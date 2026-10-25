"""
medir_dns_protector.py - Mide cuantos dominios maliciosos bloquea cada DNS publico (capa 2 del modulo DNS).

Compara tres servidores DNS:
  1.1.1.1  Cloudflare sin filtro (control: dice si el dominio sigue "vivo")
  1.1.1.2  Cloudflare "for Families" (bloquea malware): responde 0.0.0.0
  9.9.9.9  Quad9 (bloquea con inteligencia de amenazas): responde NXDOMAIN SIN registro SOA.
           Un NXDOMAIN real (el dominio no existe) trae el SOA de la zona en la seccion
           de autoridad. Esto lo observamos en pruebas (oct-2026); no esta en la
           documentacion de Quad9, por eso se cuenta de forma conservadora (ver abajo).
Y tambien la capa 1 del sumidero: la lista StevenBlack (que dominios ya cubria sin el DNS protector).

Fuentes (se descargan el mismo dia y se guardan en datos/dns_protector/<fecha>/ para poder citarlas):
  openphish.txt        URLs de phishing (OpenPhish, feed comunitario)
  stevenblack.txt      lista hosts de StevenBlack (la misma que usa dns_sumidero.py)
  control: muestra de datos/dns/tranco.csv (sitios normales) para medir falsas alarmas.
  URLhaus (malware): desde oct-2026 abuse.ch exige una Auth-Key gratuita (https://auth.abuse.ch/)
           y las descargas viejas /downloads/... responden 410. Por eso NO se descarga aqui: se
           usa el archivo de --urlhaus (por defecto datos/dns/urlhaus.txt) y se informa su fecha
           ("Last updated" de la cabecera). Para medir con datos del dia, baja la lista en texto
           plano desde el portal de URLhaus y pasala con --urlhaus.

Regla de conteo (la misma para los dos protectores, asi la comparacion es justa):
  "vivo"      = 1.1.1.1 devuelve al menos una IP para ese host.
  "bloqueado" = el host esta vivo y el protector NO devuelve esa respuesta normal:
                1.1.1.2 -> responde 0.0.0.0 ; 9.9.9.9 -> NXDOMAIN sin SOA.
  Los hosts muertos no cuentan (bloquear algo que ya no existe no protege a nadie).
  Ademas se informa, solo para Cloudflare, el bloqueo sobre TODOS los hosts (0.0.0.0 no es ambiguo).
  Se da el intervalo de confianza del 95 % (Wilson) porque OpenPhish trae pocos dominios.

Uso (desde la carpeta principal, consulta unos miles de dominios: tarda varios minutos):
    venv\\Scripts\\python 2_dns\\medir_dns_protector.py
    venv\\Scripts\\python 2_dns\\medir_dns_protector.py --max 200      # prueba rapida
Solo hace consultas DNS (pregunta la IP de cada nombre): NO visita ninguna pagina.
"""
import os
# --- Rutas del proyecto (no tocar): el script funciona desde cualquier carpeta ---
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATOS = os.path.join(RAIZ, "datos")
MODELOS = os.path.join(RAIZ, "modelos")
RESULTADOS = os.path.join(RAIZ, "resultados")
for _c in (DATOS, MODELOS, RESULTADOS):
    os.makedirs(_c, exist_ok=True)
import argparse
import math
import random
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import requests
from dnslib import QTYPE, RCODE, DNSRecord

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dns_comun import limpiar_host  # noqa: E402

SERVIDORES = {"1.1.1.1": "Cloudflare sin filtro", "1.1.1.2": "Cloudflare 1.1.1.2", "9.9.9.9": "Quad9"}
FUENTES = {
    "openphish.txt": "https://openphish.com/feed.txt",
    "stevenblack.txt": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}
UA = {"User-Agent": "Mozilla/5.0 (investigacion academica - tesis IDS/IPS)"}
SEMILLA = 42
CONSULTAS_POR_SEGUNDO = 15          # por servidor: suave, para no abusar de los DNS publicos


# ------------------------------------ fuentes ------------------------------------
def descargar(carpeta):
    os.makedirs(carpeta, exist_ok=True)
    for nombre, url in FUENTES.items():
        ruta = os.path.join(carpeta, nombre)
        if os.path.exists(ruta):
            print(f"- {nombre}: ya estaba descargado hoy")
            continue
        print(f"- Descargando {nombre} ... ", end="", flush=True)
        r = requests.get(url, headers=UA, timeout=120)
        r.raise_for_status()
        with open(ruta, "wb") as f:
            f.write(r.content)
        print(f"ok ({len(r.content) / 1e6:.1f} MB)")


def fecha_urlhaus(ruta):
    """Lee la linea '# Last updated: ...' de la cabecera de URLhaus (o la fecha del archivo)."""
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for _, linea in zip(range(20), f):
            if "Last updated:" in linea:
                return linea.split("Last updated:", 1)[1].strip(" #\n")
    return time.strftime("%Y-%m-%d %H:%M (fecha del archivo)", time.localtime(os.path.getmtime(ruta)))


def es_ip(h):
    return h.replace(".", "").isdigit()


def hosts_de_urls(ruta):
    hosts = set()
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for linea in f:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            h = limpiar_host(linea)
            if h and "." in h and not es_ip(h):
                hosts.add(h)
    return sorted(hosts)


def leer_stevenblack(ruta):
    dominios = set()
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for linea in f:
            partes = linea.split("#")[0].split()
            if len(partes) >= 2 and partes[0] in ("0.0.0.0", "127.0.0.1"):
                dominios.add(partes[1].lower().rstrip("."))
    return dominios


def en_lista(host, lista):
    """Igual que dns_sumidero.py: el host o cualquiera de sus dominios padre."""
    partes = host.split(".")
    return any(".".join(partes[i:]) in lista for i in range(len(partes) - 1))


def muestra(lista, n):
    return lista if len(lista) <= n else sorted(random.Random(SEMILLA).sample(lista, n))


# ------------------------------------ consultas ------------------------------------
class Ritmo:
    """Deja pasar como maximo 'qps' consultas por segundo (compartido entre hilos)."""
    def __init__(self, qps):
        self.intervalo, self.proximo, self.candado = 1 / qps, time.monotonic(), threading.Lock()

    def esperar(self):
        with self.candado:
            ahora = time.monotonic()
            espera = self.proximo - ahora
            self.proximo = max(ahora, self.proximo) + self.intervalo
        if espera > 0:
            time.sleep(espera)


def consultar(host, servidor, ritmo):
    """Devuelve (resultado, detalle). resultado: ip | 0.0.0.0 | nx_con_soa | nx_sin_soa | sin_ip | servfail | timeout"""
    try:
        pregunta = DNSRecord.question(host, "A").pack()
    except Exception:                                    # nombre invalido (p. ej. etiqueta > 63 letras)
        return "invalido", ""
    for _ in range(2):                                   # un reintento si se pierde el paquete
        ritmo.esperar()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(pregunta, (servidor, 53))
                datos, _ = s.recvfrom(4096)
            r = DNSRecord.parse(datos)
        except Exception:                                # sin respuesta o respuesta rota
            continue
        ips = [str(x.rdata) for x in r.rr if x.rtype == QTYPE.A]
        if r.header.rcode == RCODE.NXDOMAIN:
            return ("nx_con_soa" if r.auth else "nx_sin_soa"), ""
        if r.header.rcode != RCODE.NOERROR:
            return "servfail", RCODE[r.header.rcode]
        if "0.0.0.0" in ips:
            return "0.0.0.0", ""
        return ("ip" if ips else "sin_ip"), ",".join(ips[:3])
    return "timeout", ""


def consultar_todo(hosts):
    ritmos = {s: Ritmo(CONSULTAS_POR_SEGUNDO) for s in SERVIDORES}
    trabajos = [(h, s) for h in hosts for s in SERVIDORES]
    res = {}
    hechos = 0
    with ThreadPoolExecutor(max_workers=12 * len(SERVIDORES)) as ex:
        futuros = {ex.submit(consultar, h, s, ritmos[s]): (h, s) for h, s in trabajos}
        for f in futuros:
            res[futuros[f]] = f.result()
            hechos += 1
            if hechos % 600 == 0:
                print(f"  {hechos}/{len(trabajos)} consultas", flush=True)
    return res


# ------------------------------------ analisis ------------------------------------
def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0, c - m), min(1, c + m)


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / n:5.1f} % [{100 * lo:.1f}-{100 * hi:.1f}]" if n else "   -"


def main():
    global CONSULTAS_POR_SEGUNDO
    p = argparse.ArgumentParser(description="Mide el bloqueo de DNS protectores (Quad9, Cloudflare 1.1.1.2)")
    p.add_argument("--max", type=int, default=2000, help="maximo de hosts por lista maliciosa (muestra aleatoria)")
    p.add_argument("--control", type=int, default=1000, help="dominios normales de Tranco para medir falsas alarmas")
    p.add_argument("--qps", type=int, default=CONSULTAS_POR_SEGUNDO, help="consultas por segundo por servidor")
    p.add_argument("--urlhaus", default=os.path.join(DATOS, "dns", "urlhaus.txt"),
                   help="lista de URLs de URLhaus en texto plano (una URL por linea)")
    args = p.parse_args()
    CONSULTAS_POR_SEGUNDO = args.qps

    fecha = time.strftime("%Y-%m-%d")
    carpeta = os.path.join(DATOS, "dns_protector", fecha)
    print(f"Fuentes del {fecha} -> {carpeta}")
    descargar(carpeta)
    f_urlhaus = fecha_urlhaus(args.urlhaus)
    print(f"- URLhaus: {args.urlhaus} (actualizado: {f_urlhaus})")

    tranco = pd.read_csv(os.path.join(DATOS, "dns", "tranco.csv"), header=None, names=["rango", "dominio"])
    grupos = {
        "URLhaus (malware)": muestra(hosts_de_urls(args.urlhaus), args.max),
        "OpenPhish (phishing)": muestra(hosts_de_urls(os.path.join(carpeta, "openphish.txt")), args.max),
        "Tranco (normales)": muestra(sorted(tranco.dominio.astype(str).str.lower()), args.control),
    }
    stevenblack = leer_stevenblack(os.path.join(carpeta, "stevenblack.txt"))
    print(f"StevenBlack: {len(stevenblack):,} dominios")
    for g, hs in grupos.items():
        print(f"  {g:22} {len(hs):5} hosts")

    todos = sorted({h for hs in grupos.values() for h in hs})
    seg = len(todos) / CONSULTAS_POR_SEGUNDO
    print(f"\nConsultando {len(todos)} hosts x {len(SERVIDORES)} servidores (~{seg / 60:.0f} min)...")
    t0 = time.time()
    res = consultar_todo(todos)
    print(f"Listo en {(time.time() - t0) / 60:.1f} min")

    filas = []
    for g, hs in grupos.items():
        for h in hs:
            fila = {"lista": g, "host": h, "stevenblack": en_lista(h, stevenblack)}
            for s in SERVIDORES:
                fila[s], fila[f"{s}_ips"] = res[(h, s)]
            filas.append(fila)
    df = pd.DataFrame(filas)
    df["vivo"] = df["1.1.1.1"] == "ip"
    df["bloq_cf"] = df["1.1.1.2"] == "0.0.0.0"
    df["bloq_q9"] = df["9.9.9.9"] == "nx_sin_soa"
    df.to_csv(os.path.join(carpeta, "consultas.csv"), index=False)

    # ---------- tabla ----------
    lineas = [f"Medicion de DNS protectores - {fecha}",
              f"Fuentes guardadas en datos/dns_protector/{fecha}/ (muestra aleatoria, semilla {SEMILLA})",
              f"URLhaus: {os.path.relpath(args.urlhaus, RAIZ)} (actualizado: {f_urlhaus})",
              "Porcentaje bloqueado sobre los hosts VIVOS (1.1.1.1 da IP) [IC 95 % de Wilson]", ""]
    tabla = []
    cab = f"{'Lista':22} {'hosts':>6} {'vivos':>6} | {'StevenBlack':>22} | {'Cloudflare 1.1.1.2':>22} | {'Quad9 9.9.9.9':>22} | {'StevenBlack + 1.1.1.2':>22} | {'StevenBlack + Quad9':>22}"
    lineas += [cab, "-" * len(cab)]
    for g in grupos:
        d = df[df.lista == g]
        v = d[d.vivo]
        n = len(v)
        k = {"sb": v.stevenblack.sum(), "cf": v.bloq_cf.sum(), "q9": v.bloq_q9.sum(),
             "sb_cf": (v.stevenblack | v.bloq_cf).sum(), "sb_q9": (v.stevenblack | v.bloq_q9).sum()}
        lineas.append(f"{g:22} {len(d):6} {n:6} | {pct(k['sb'], n):>22} | {pct(k['cf'], n):>22} | "
                      f"{pct(k['q9'], n):>22} | {pct(k['sb_cf'], n):>22} | {pct(k['sb_q9'], n):>22}")
        tabla.append({"lista": g, "hosts": len(d), "vivos": n,
                      **{f"{c}_n": int(x) for c, x in k.items()},
                      **{f"{c}_pct": round(100 * x / n, 2) if n else None for c, x in k.items()},
                      "cf_sobre_todos_pct": round(100 * d.bloq_cf.mean(), 2) if len(d) else None})
    lineas += ["", "Cloudflare 1.1.1.2 sobre TODOS los hosts (incluye muertos; 0.0.0.0 no es ambiguo):"]
    for g in grupos:
        d = df[df.lista == g]
        lineas.append(f"  {g:22} {pct(int(d.bloq_cf.sum()), len(d))}")
    lineas += ["", "Respuestas de cada servidor (todos los hosts):"]
    for s in SERVIDORES:
        lineas.append(f"  {s:8} " + "  ".join(f"{k}={v}" for k, v in df[s].value_counts().items()))
    lineas += ["", "Nota: en Tranco, 'bloqueado' = falsa alarma (sitio normal bloqueado)."]
    if (df["1.1.1.1"] == "timeout").mean() > 0.05:
        lineas.append("AVISO: mas del 5 % de las consultas a 1.1.1.1 no respondieron; baja --qps y repite.")

    texto = "\n".join(lineas)
    print("\n" + texto)
    pd.DataFrame(tabla).to_csv(os.path.join(RESULTADOS, f"tabla_dns_protector_{fecha}.csv"), index=False)
    with open(os.path.join(RESULTADOS, f"salida_dns_protector_{fecha}.txt"), "w", encoding="utf-8") as f:
        f.write(texto + "\n")
    print(f"\nGuardado: resultados/salida_dns_protector_{fecha}.txt, resultados/tabla_dns_protector_{fecha}.csv"
          f" y el detalle en datos/dns_protector/{fecha}/consultas.csv")


if __name__ == "__main__":
    main()
