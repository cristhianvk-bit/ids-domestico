#!/usr/bin/env python3
"""
Módulo de flujos – versión 1 (solo captura y agregación, sin detección todavía).

Escucha la copia del tráfico de la red (modo promiscuo / puerto espejo),
agrupa los paquetes en FLUJOS (conversaciones entre dos equipos) y guarda
únicamente sus METADATOS en flujos.csv: quién habló con quién, cuánto,
cuánto tiempo y con qué ritmo. No lee el contenido de los paquetes.

Uso:
    sudo venv/bin/python flujos.py --interfaz enp0s8
"""
import argparse
import csv
import threading
import time
from pathlib import Path

from scapy.all import IP, TCP, UDP, sniff

CARPETA = Path(__file__).parent
SALIDA = CARPETA / "flujos.csv"
COLUMNAS = ["inicio", "fin", "duracion_s", "ip_origen", "puerto_origen", "ip_destino",
            "puerto_destino", "protocolo", "paquetes_ida", "paquetes_vuelta", "bytes_ida",
            "bytes_vuelta", "tam_medio", "iat_medio_ms", "syn", "rst"]

flujos: dict = {}            # flujos activos, en memoria
candado = threading.Lock()


def clave_y_sentido(ip_o, p_o, ip_d, p_d, proto):
    """La misma conversación en ambos sentidos comparte clave."""
    a, b = (ip_o, p_o), (ip_d, p_d)
    return ((a, b, proto), True) if a <= b else ((b, a, proto), False)


def procesar(paquete) -> None:
    if IP not in paquete:
        return
    ip = paquete[IP]
    if TCP in paquete:
        proto, p_o, p_d, flags = "TCP", paquete[TCP].sport, paquete[TCP].dport, str(paquete[TCP].flags)
    elif UDP in paquete:
        proto, p_o, p_d, flags = "UDP", paquete[UDP].sport, paquete[UDP].dport, ""
    else:
        proto, p_o, p_d, flags = str(ip.proto), 0, 0, ""

    ahora, tam = float(paquete.time), len(paquete)
    clave, _ = clave_y_sentido(ip.src, p_o, ip.dst, p_d, proto)
    with candado:
        f = flujos.get(clave)
        if f is None:  # el primer paquete define quién es el "origen"
            f = flujos[clave] = dict(inicio=ahora, ultimo=ahora, origen=(ip.src, p_o), destino=(ip.dst, p_d),
                                     proto=proto, pk_ida=0, pk_vuelta=0, b_ida=0, b_vuelta=0,
                                     suma_iat=0.0, syn=0, rst=0)
        else:
            f["suma_iat"] += ahora - f["ultimo"]
            f["ultimo"] = ahora
        if (ip.src, p_o) == f["origen"]:
            f["pk_ida"] += 1; f["b_ida"] += tam
        else:
            f["pk_vuelta"] += 1; f["b_vuelta"] += tam
        if "S" in flags and "A" not in flags:
            f["syn"] += 1
        if "R" in flags:
            f["rst"] += 1


def a_fila(f) -> list:
    paquetes = f["pk_ida"] + f["pk_vuelta"]
    fecha = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
    return [fecha(f["inicio"]), fecha(f["ultimo"]), round(f["ultimo"] - f["inicio"], 3),
            f["origen"][0], f["origen"][1], f["destino"][0], f["destino"][1], f["proto"],
            f["pk_ida"], f["pk_vuelta"], f["b_ida"], f["b_vuelta"],
            round((f["b_ida"] + f["b_vuelta"]) / paquetes, 1),
            round(f["suma_iat"] / (paquetes - 1) * 1000, 2) if paquetes > 1 else 0,
            f["syn"], f["rst"]]


def exportar(todos=False, inactivo=30, activo=120) -> None:
    """Cierra los flujos inactivos (o demasiado largos) y los escribe en el CSV."""
    ahora = time.time()
    with candado:
        listos = [k for k, f in flujos.items()
                  if todos or ahora - f["ultimo"] > inactivo or ahora - f["inicio"] > activo]
        filas = [a_fila(flujos.pop(k)) for k in listos]
    if not filas:
        return
    nuevo = not SALIDA.exists()
    with open(SALIDA, "a", newline="", encoding="utf-8") as archivo:
        w = csv.writer(archivo)
        if nuevo:
            w.writerow(COLUMNAS)
        w.writerows(filas)
    for fila in filas:
        print(f"FLUJO {fila[7]:4} {fila[3]}:{fila[4]} -> {fila[5]}:{fila[6]}  "
              f"paquetes={fila[8] + fila[9]}  bytes_ida={fila[10]}  bytes_vuelta={fila[11]}")


def exportador(args) -> None:
    while True:
        time.sleep(5)
        exportar(inactivo=args.inactivo, activo=args.activo)


def main() -> None:
    p = argparse.ArgumentParser(description="Captura de flujos del IDS/IPS doméstico")
    p.add_argument("--interfaz", default="enp0s8", help="tarjeta que recibe la copia del tráfico")
    p.add_argument("--inactivo", type=int, default=30, help="segundos sin paquetes para cerrar un flujo")
    p.add_argument("--activo", type=int, default=120, help="duración máxima de un flujo antes de exportarlo")
    args = p.parse_args()

    threading.Thread(target=exportador, args=(args,), daemon=True).start()
    print(f"Capturando en {args.interfaz} (modo promiscuo). Ctrl+C para salir.")
    try:
        sniff(iface=args.interfaz, prn=procesar, store=False, promisc=True)
    except KeyboardInterrupt:
        pass
    finally:
        exportar(todos=True)
        print(f"Flujos guardados en {SALIDA}")


if __name__ == "__main__":
    main()
