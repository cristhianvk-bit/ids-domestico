#!/usr/bin/env python3
"""
Módulo DNS – versión 2 (sumidero con listas + clasificador de IA).

Recibe las consultas DNS de la red y decide en este orden:
  1. Lista blanca (permitidos.txt y permitidos_top.txt) -> se deja pasar.
  2. Listas de bloqueo -> se responde 0.0.0.0 (sumidero DNS).
  3. Clasificador de IA (modelo_dominios.joblib): si el dominio parece
     malicioso o DGA con probabilidad >= UMBRAL_IA -> se bloquea.
  4. Si nada lo bloquea, se reenvía a un DNS público (--superior). Si ese DNS es
     protector y bloquea el dominio, se registra como BLOQUEADO_SUPERIOR:
       - Cloudflare 1.1.1.2 responde 0.0.0.0 (o ::).
       - Quad9 9.9.9.9 responde NXDOMAIN sin registro SOA (un NXDOMAIN real trae
         SOA). Esto lo observamos en pruebas, no está en su documentación, por eso
         se marca como "probable".
Cada consulta queda registrada en consultas.csv.
Si el archivo del modelo no existe, funciona solo con listas (como la versión 1).

Uso:
    python3 dns_sumidero.py                 # puerto 5353 (pruebas, sin root)
    sudo venv/bin/python dns_sumidero.py --puerto 53   # puerto real de DNS
    sudo venv/bin/python dns_sumidero.py --puerto 53 --superior 9.9.9.9
"""
import argparse
import csv
import socket
import threading
import time
import urllib.request
from pathlib import Path

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord

from caracteristicas import extraer

DNS_SUPERIOR = ("1.1.1.1", 53)          # a dónde se reenvían las consultas permitidas (se cambia con --superior)
URL_LISTA = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
CARPETA = Path(__file__).parent
LISTA_DESCARGADA = CARPETA / "lista_stevenblack.txt"
LISTA_PROPIA = CARPETA / "bloqueados.txt"
PERMITIDOS = CARPETA / "permitidos.txt"
PERMITIDOS_TOP = CARPETA / "permitidos_top.txt"      # top 10.000 de Tranco (sale del notebook)
ARCHIVO_MODELO = CARPETA / "modelo_dominios.joblib"
UMBRAL_IA = 0.85            # probabilidad mínima para bloquear por IA (súbelo si hay falsos positivos)
REGISTRO = CARPETA / "consultas.csv"

bloqueados: set[str] = set()
permitidos: set[str] = set()
candado_registro = threading.Lock()
modelo = None               # se carga al inicio si existe el archivo
veredictos_ia: dict = {}    # caché: dominio -> (clase, probabilidad)


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
    permitidos = leer_archivo(PERMITIDOS) | leer_archivo(PERMITIDOS_TOP)
    print(f"Dominios bloqueados cargados: {len(bloqueados):,} | permitidos: {len(permitidos):,}")


def cargar_modelo() -> None:
    global modelo
    if not ARCHIVO_MODELO.exists():
        print("Sin modelo de IA (falta modelo_dominios.joblib): se usan solo las listas.")
        return
    import joblib
    paquete = joblib.load(ARCHIVO_MODELO)
    modelo = paquete
    modelo["modelo"].n_jobs = 1          # una consulta a la vez: más rápido sin hilos extra
    print(f"Modelo de IA cargado (entrenado el {paquete['fecha']}, umbral {UMBRAL_IA}).")


def clasificar(nombre: str):
    """Devuelve (clase, probabilidad) del dominio según el modelo, con caché."""
    if nombre in veredictos_ia:
        return veredictos_ia[nombre]
    import pandas as pd
    fila = pd.DataFrame([extraer(nombre)], columns=modelo["columnas"])
    probas = modelo["modelo"].predict_proba(fila)[0]
    clase = int(probas.argmax())
    resultado = (modelo["clases"][clase], float(probas[clase]))
    veredictos_ia[nombre] = resultado
    return resultado


def debe_clasificarse(nombre: str) -> bool:
    """Nombres que no tiene sentido pasar por la IA."""
    return "." in nombre and not nombre.endswith((".arpa", ".local", ".lan")) and modelo is not None


def decidir(nombre: str):
    """Devuelve (bloquear: bool, motivo: str). Revisa también los dominios padre."""
    partes = nombre.split(".")
    candidatos = [".".join(partes[i:]) for i in range(len(partes) - 1)]
    if any(c in permitidos for c in candidatos):
        return False, "PERMITIDO"
    if any(c in bloqueados for c in candidatos):
        return True, "BLOQUEADO_LISTA"
    if debe_clasificarse(nombre):
        clase, prob = clasificar(nombre)
        if clase != "legítimo" and prob >= UMBRAL_IA:
            return True, f"BLOQUEADO_IA({clase} {prob:.2f})"
    return False, "PERMITIDO"


def bloqueo_superior(respuesta_bytes: bytes) -> str | None:
    """Mira la respuesta del DNS superior y dice si fue un bloqueo suyo."""
    try:
        r = DNSRecord.parse(respuesta_bytes)
    except Exception:
        return None
    if any(rr.rtype in (QTYPE.A, QTYPE.AAAA) and str(rr.rdata) in ("0.0.0.0", "::") for rr in r.rr):
        return "BLOQUEADO_SUPERIOR"                 # estilo Cloudflare 1.1.1.2
    if r.header.rcode == RCODE.NXDOMAIN and not r.auth:
        return "BLOQUEADO_SUPERIOR(probable)"       # estilo Quad9: NXDOMAIN sin SOA
    return None


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

    bloquear, motivo = decidir(dominio)
    if bloquear:
        respuesta = consulta.reply()
        if tipo == "A":
            respuesta.add_answer(RR(consulta.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
        elif tipo == "AAAA":
            respuesta.add_answer(RR(consulta.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
        servidor.sendto(respuesta.pack(), cliente)
        accion = motivo
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(datos, DNS_SUPERIOR)
                respuesta_bytes, _ = s.recvfrom(4096)
            servidor.sendto(respuesta_bytes, cliente)
            accion = bloqueo_superior(respuesta_bytes) or motivo
        except socket.timeout:
            accion = "SIN_RESPUESTA"

    ms = (time.perf_counter() - inicio) * 1000
    print(f"{accion:30} {cliente[0]:15} {tipo:5} {dominio}  ({ms:.1f} ms)")
    registrar(cliente[0], dominio, tipo, accion, ms)


def main() -> None:
    p = argparse.ArgumentParser(description="Sumidero DNS del IDS/IPS doméstico")
    p.add_argument("--puerto", type=int, default=5353)
    p.add_argument("--superior", default="1.1.1.1",
                   help="DNS al que se reenvía: 1.1.1.1 (sin filtro), 1.1.1.2 (Cloudflare) o 9.9.9.9 (Quad9)")
    args = p.parse_args()

    global DNS_SUPERIOR
    DNS_SUPERIOR = (args.superior, 53)
    print(f"DNS superior: {args.superior}")

    cargar_listas()
    cargar_modelo()
    servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    servidor.bind(("0.0.0.0", args.puerto))
    print(f"Sumidero DNS escuchando en el puerto {args.puerto}. Ctrl+C para salir.")
    while True:
        datos, cliente = servidor.recvfrom(4096)
        threading.Thread(target=atender, args=(datos, cliente, servidor), daemon=True).start()


if __name__ == "__main__":
    main()
