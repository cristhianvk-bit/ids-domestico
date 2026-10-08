#!/usr/bin/env python3
"""
Módulo DNS – versión 1 (sumidero con listas, sin IA todavía).

Recibe las consultas DNS de la red, bloquea los dominios que están en las
listas devolviendo 0.0.0.0 (sumidero DNS) y reenvía el resto a un DNS público.
Cada consulta queda registrada en consultas.csv.

Uso:
    python3 dns_sumidero.py                 # puerto 5353 (pruebas, sin root)
    sudo venv/bin/python dns_sumidero.py --puerto 53   # puerto real de DNS
"""
import argparse
import csv
import socket
import threading
import time
import urllib.request
from pathlib import Path

from dnslib import AAAA, QTYPE, RR, A, DNSRecord

DNS_SUPERIOR = ("1.1.1.1", 53)          # a dónde se reenvían las consultas permitidas
URL_LISTA = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
CARPETA = Path(__file__).parent
LISTA_DESCARGADA = CARPETA / "lista_stevenblack.txt"
LISTA_PROPIA = CARPETA / "bloqueados.txt"
PERMITIDOS = CARPETA / "permitidos.txt"
REGISTRO = CARPETA / "consultas.csv"

bloqueados: set[str] = set()
permitidos: set[str] = set()
candado_registro = threading.Lock()


# ---------------------------------------------------------------- listas
def descargar_lista() -> None:
    """Descarga la lista de StevenBlack si no existe o tiene más de 1 día."""
    viejo = not LISTA_DESCARGADA.exists() or time.time() - LISTA_DESCARGADA.stat().st_mtime > 86400
    if viejo:
        print("Descargando lista de bloqueo de StevenBlack...")
        try:
            urllib.request.urlretrieve(URL_LISTA, LISTA_DESCARGADA)
        except Exception as e:  # sin internet: se sigue con lo que haya
            print(f"  No se pudo descargar ({e}); se usa la copia local si existe.")


def leer_archivo(ruta: Path) -> set[str]:
    """Lee dominios de un archivo tipo hosts ('0.0.0.0 dominio') o de uno por línea."""
    dominios = set()
    if not ruta.exists():
        return dominios
    for linea in ruta.read_text(encoding="utf-8", errors="ignore").splitlines():
        linea = linea.split("#")[0].strip()
        if not linea:
            continue
        partes = linea.split()
        dominio = partes[1] if len(partes) >= 2 and partes[0] in ("0.0.0.0", "127.0.0.1") else partes[0]
        if dominio not in ("localhost", "0.0.0.0", "127.0.0.1"):
            dominios.add(dominio.lower().rstrip("."))
    return dominios


def cargar_listas() -> None:
    global bloqueados, permitidos
    descargar_lista()
    bloqueados = leer_archivo(LISTA_DESCARGADA) | leer_archivo(LISTA_PROPIA)
    permitidos = leer_archivo(PERMITIDOS)
    print(f"Dominios bloqueados cargados: {len(bloqueados):,}")


def esta_bloqueado(nombre: str) -> bool:
    """Revisa el dominio y sus dominios padre (sub.malo.com -> malo.com)."""
    partes = nombre.split(".")
    candidatos = [".".join(partes[i:]) for i in range(len(partes) - 1)]
    if any(c in permitidos for c in candidatos):
        return False
    return any(c in bloqueados for c in candidatos)


# ---------------------------------------------------------------- registro
def registrar(cliente: str, dominio: str, tipo: str, accion: str, ms: float) -> None:
    nuevo = not REGISTRO.exists()
    with candado_registro, open(REGISTRO, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if nuevo:
            w.writerow(["fecha_hora", "cliente", "dominio", "tipo", "accion", "tiempo_ms"])
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cliente, dominio, tipo, accion, f"{ms:.1f}"])


# ---------------------------------------------------------------- atención
def atender(datos: bytes, cliente: tuple, servidor: socket.socket) -> None:
    inicio = time.perf_counter()
    try:
        consulta = DNSRecord.parse(datos)
    except Exception:
        return
    dominio = str(consulta.q.qname).rstrip(".").lower()
    tipo = QTYPE[consulta.q.qtype]

    if esta_bloqueado(dominio):
        respuesta = consulta.reply()
        if tipo == "A":
            respuesta.add_answer(RR(consulta.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
        elif tipo == "AAAA":
            respuesta.add_answer(RR(consulta.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
        servidor.sendto(respuesta.pack(), cliente)
        accion = "BLOQUEADO"
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(datos, DNS_SUPERIOR)
                respuesta_bytes, _ = s.recvfrom(4096)
            servidor.sendto(respuesta_bytes, cliente)
            accion = "PERMITIDO"
        except socket.timeout:
            accion = "SIN_RESPUESTA"

    ms = (time.perf_counter() - inicio) * 1000
    print(f"{accion:13} {cliente[0]:15} {tipo:5} {dominio}  ({ms:.1f} ms)")
    registrar(cliente[0], dominio, tipo, accion, ms)


def main() -> None:
    p = argparse.ArgumentParser(description="Sumidero DNS del IDS/IPS doméstico")
    p.add_argument("--puerto", type=int, default=5353)
    args = p.parse_args()

    cargar_listas()
    servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    servidor.bind(("0.0.0.0", args.puerto))
    print(f"Sumidero DNS escuchando en el puerto {args.puerto}. Ctrl+C para salir.")
    while True:
        datos, cliente = servidor.recvfrom(4096)
        threading.Thread(target=atender, args=(datos, cliente, servidor), daemon=True).start()


if __name__ == "__main__":
    main()
