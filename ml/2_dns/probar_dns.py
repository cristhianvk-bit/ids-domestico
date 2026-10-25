"""
probar_dns_v2.py - Prueba el detector DNS v2 con dominios REALES de tu PC.

Requiere en la misma carpeta: dns_comun.py y modelo_dns_v2.pkl (lo crea entrenar_dns_v2.py).

USO:
    python probar_dns_v2.py                    lee la cache DNS de Windows (ipconfig /displaydns)
    python probar_dns_v2.py dominios.txt       un host por linea
    python probar_dns_v2.py --capturar 600     escucha tu DNS 600 s (pip install scapy, Npcap,
                                               terminal como ADMINISTRADOR)
    Agrega  --guardar  para guardar los hosts en datos/dns_real/captura_<fecha>.txt y asi usarlos
    la proxima vez que entrenes (solo si tu PC esta limpia).

Idea: tu PC casi solo hace consultas normales, asi que todo lo que salga como ALERTA o BLOQUEO
es, casi seguro, una falsa alarma. Revisa esos casos a mano.
"""
import os
# --- Rutas del proyecto (no tocar): el script funciona desde cualquier carpeta ---
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATOS = os.path.join(RAIZ, "datos")
MODELOS = os.path.join(RAIZ, "modelos")
RESULTADOS = os.path.join(RAIZ, "resultados")
for _c in (DATOS, MODELOS, RESULTADOS):
    os.makedirs(_c, exist_ok=True)
import os
import sys
import subprocess
import time

import joblib
import pandas as pd

import dns_comun as C

MODELO = os.path.join(MODELOS, "modelo_dns_v2.pkl")


# ------------------------------ obtencion de hosts ------------------------------
def hosts_de_cache_texto(texto):
    """Extrae nombres de la salida de 'ipconfig /displaydns' (cualquier idioma)."""
    salida = []
    for linea in texto.splitlines():
        if ":" not in linea:
            continue
        h = C.limpiar_host(linea.split(":", 1)[1])
        if h and "." in h and C.registrable(h):
            salida.append(h)
    return salida


def leer_cache():
    r = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True, errors="ignore")
    return hosts_de_cache_texto(r.stdout)


def leer_archivo(ruta):
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        hs = [C.limpiar_host(l) for l in f if l.strip() and not l.startswith("#")]
    return [h for h in hs if h and C.registrable(h)]


def qname_de_paquete(pkt):
    from scapy.all import DNS, DNSQR
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        q = pkt[DNSQR].qname
        h = C.limpiar_host(q.decode(errors="ignore") if isinstance(q, bytes) else q)
        return h if h and C.registrable(h) else None
    return None


def capturar(segundos):
    from scapy.all import sniff
    vistos = []

    def cb(pkt):
        h = qname_de_paquete(pkt)
        if h:
            vistos.append(h)

    print(f"Escuchando DNS durante {segundos} s... navega normal.")
    sniff(filter="udp port 53", prn=cb, store=False, timeout=segundos)
    return vistos


# ------------------------------------ programa ------------------------------------
def main():
    args = sys.argv[1:]
    guardar = "--guardar" in args
    args = [a for a in args if a != "--guardar"]

    if args[:1] == ["--capturar"]:
        hosts = capturar(int(args[1]) if len(args) > 1 else 120)
    elif args:
        hosts = leer_archivo(args[0])
    else:
        hosts = leer_cache()

    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        sys.exit("No encontre dominios. Navega un rato y repite, o pasa un archivo de hosts.")

    if guardar:
        os.makedirs(os.path.join(DATOS, "dns_real"), exist_ok=True)
        ruta = os.path.join(DATOS, "dns_real", time.strftime("captura_%Y%m%d_%H%M%S.txt"))
        with open(ruta, "w", encoding="utf-8") as f:
            f.write("\n".join(hosts))
        print(f"Hosts guardados en {ruta}")

    m = joblib.load(MODELO)
    res = detectar_y_resumir(m, hosts)
    return res


def detectar_y_resumir(m, hosts):
    df = C.detectar(m, hosts)
    df = df[df.accion != "ignorado"].copy()
    n_dom = df.dominio.nunique()
    print(f"\nHosts analizados: {len(df)}  |  dominios registrables distintos: {n_dom}")
    print(f"Umbrales: ALERTA > {m['umbral_alerta']:.3f}  (~{m['fpr_alerta']:.2%} falsas alarmas en el examen)  |  "
          f"BLOQUEO > {m['umbral_bloqueo']:.3f}  (~{m['fpr_bloqueo']:.2%})")

    print("\n=== RESULTADO (si tu PC esta limpia, ALERTA/BLOQUEO = falsa alarma) ===")
    print(df.accion.value_counts().to_string())

    df["subdominios"] = df.host.map(lambda h: max(h.count(".") - C.registrable(h).count("."), 0))
    df["alerta"] = df.accion.isin(["ALERTA", "BLOQUEO"])
    print("\n=== ¿Los subdominios disparan alarmas? (la v1 fallaba aqui) ===")
    t = df.assign(sub=pd.cut(df.subdominios, [-1, 0, 1, 2, 100], labels=["0", "1", "2", "3 o mas"])) \
          .groupby("sub", observed=True).agg(hosts=("host", "count"), alertas=("alerta", "sum"),
                                              prob_media=("prob", "mean"))
    t["tasa_alerta"] = (t.alertas / t.hosts).map("{:.1%}".format)
    t["prob_media"] = t.prob_media.round(3)
    print(t.to_string())

    marc = df[df.alerta].sort_values("prob", ascending=False)
    if len(marc):
        print("\n=== MARCADOS (revisalos a mano: casi seguro son falsos positivos) ===")
        print(marc[["host", "dominio", "prob", "accion"]].to_string(index=False,
              float_format=lambda v: f"{v:.3f}"))
    print("\n=== TOP 10 por probabilidad (sin contar los de la allowlist) ===")
    top = df[df.accion != "permitido (allowlist)"].drop_duplicates("dominio") \
            .sort_values("prob", ascending=False).head(10)
    print(top[["dominio", "prob", "accion"]].to_string(index=False, float_format=lambda v: f"{v:.3f}"))

    df.drop(columns=["alerta"]).sort_values("prob", ascending=False).to_csv(os.path.join(RESULTADOS, "resultados_dns_v2.csv"), index=False)
    print("\nGuardado: resultados_dns_v2.csv")
    return df


if __name__ == "__main__":
    main()