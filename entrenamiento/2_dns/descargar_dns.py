"""
descargar_dns.py - Descarga las fuentes de datos para el detector DNS v2 a datos/dns/

Fuentes (cada una es opcional: si alguna falla, el script sigue con las demas):
  tranco.csv           dominios NORMALES: Tranco top-1M   (https://tranco-list.eu)
  dga_chrmor.csv       DGA (25 familias) + dominios normales Alexa
                       Si lo usas en el articulo, cita: Cucchiarelli, Morbidoni, Spalazzi, Baldi (2021),
                       "Algorithmically generated malicious domain names detection based on n-grams
                       features", Expert Systems with Applications 170, 114551.
  urlhaus.txt          URLs de malware (abuse.ch URLhaus)
  openphish.txt        URLs de phishing (OpenPhish, feed comunitario)

Uso:
    pip install requests
    python 2_dns/descargar_dns.py

Tambien puedes agregar tus propias listas a mano en datos/dns/:
    malo_<nombre>.txt   un dominio o URL por linea (maliciosos)
    bueno_<nombre>.txt  un dominio por linea (normales)
"""
import os
# --- Rutas del proyecto (no tocar): el script funciona desde cualquier carpeta ---
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATOS = os.path.join(RAIZ, "datos")
MODELOS = os.path.join(RAIZ, "modelos")
RESULTADOS = os.path.join(RAIZ, "resultados")
for _c in (DATOS, MODELOS, RESULTADOS):
    os.makedirs(_c, exist_ok=True)
import io
import os
import zipfile

import requests

CARPETA = os.path.join(DATOS, "dns")
UA = {"User-Agent": "Mozilla/5.0 (investigacion academica - tesis IDS/IPS)"}
os.makedirs(CARPETA, exist_ok=True)


def bajar(url, destino, descripcion):
    print(f"- {descripcion} ... ", end="", flush=True)
    try:
        r = requests.get(url, headers=UA, timeout=120)
        r.raise_for_status()
        return r.content
    except Exception as e:
        print(f"FALLO ({type(e).__name__}: {e})")
        return None


def guardar(contenido, nombre):
    ruta = os.path.join(CARPETA, nombre)
    with open(ruta, "wb") as f:
        f.write(contenido)
    print(f"ok  ({len(contenido) / 1e6:.1f} MB) -> {ruta}")


# 1) Tranco (normales)
c = bajar("https://tranco-list.eu/top-1m.csv.zip", "tranco.csv", "Tranco top-1M (normales)")
if c:
    z = zipfile.ZipFile(io.BytesIO(c))
    guardar(z.read(z.namelist()[0]), "tranco.csv")

# 2) DGA + Alexa (repositorio de Cucchiarelli et al.)
c = bajar("https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv",
          "dga_chrmor.csv", "DGA 25 familias + Alexa (GitHub chrmor)")
if c:
    guardar(c, "dga_chrmor.csv")

# 3) URLhaus (malware)
c = bajar("https://urlhaus.abuse.ch/downloads/text/", "urlhaus.txt", "URLhaus (malware)")
if c:
    guardar(c, "urlhaus.txt")

# 4) OpenPhish (phishing) - puede cambiar o requerir cuenta; si falla no pasa nada
c = bajar("https://openphish.com/feed.txt", "openphish.txt", "OpenPhish (phishing)")
if c:
    guardar(c, "openphish.txt")

print("\nListo. Ahora (opcional) pon tus dominios reales en la carpeta datos/dns_real/ y corre:")
print("    python 2_dns/entrenar_dns.py")