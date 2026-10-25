"""
Descarga los CSV procesados de CSE-CIC-IDS2018 (carpeta "Processed Traffic Data
for ML Algorithms") desde el bucket publico de AWS, SIN necesitar AWS CLI ni cuenta.

Uso:
    pip install requests
    python 1_netflow/descargar_2018.py

- Primero lista los archivos y te muestra el tamano REAL de cada uno.
- Te pregunta antes de descargar.
- Si se corta, vuelve a correrlo: salta los archivos ya completos.

Fuente y licencia: https://registry.opendata.aws/cse-cic-ids2018
Si usas los datos debes citar el dataset y enlazar esa pagina.
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
import xml.etree.ElementTree as ET
from urllib.parse import quote

import requests

BUCKET_URL = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
PREFIJO = "Processed Traffic Data for ML Algorithms/"
CARPETA = os.path.join(DATOS, "cse-cic-ids2018")

# Si tu disco/internet van justos, pon aqui partes del nombre de los archivos
# que NO quieres bajar. Ejemplo: EXCLUIR = ["Tuesday-20-02"]  (el dia mas pesado)
# OJO: sin ese dia pierdes parte de los ejemplos de DDoS.
EXCLUIR = []

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def listar():
    """Devuelve [(key, tamano_bytes)] de los .csv del prefijo (con paginacion)."""
    archivos, token = [], None
    while True:
        params = {"list-type": "2", "prefix": PREFIJO}
        if token:
            params["continuation-token"] = token
        r = requests.get(BUCKET_URL, params=params, timeout=60)
        r.raise_for_status()
        raiz = ET.fromstring(r.content)
        for c in raiz.findall(f"{NS}Contents"):
            key = c.find(f"{NS}Key").text
            size = int(c.find(f"{NS}Size").text)
            if key.lower().endswith(".csv"):
                archivos.append((key, size))
        if raiz.findtext(f"{NS}IsTruncated") == "true":
            token = raiz.findtext(f"{NS}NextContinuationToken")
        else:
            break
    return archivos


def main():
    os.makedirs(CARPETA, exist_ok=True)
    try:
        archivos = listar()
    except Exception as e:
        print("No pude listar el bucket:", e)
        print("\nAlternativa con AWS CLI (https://aws.amazon.com/cli/):")
        print('  aws s3 sync --no-sign-request --region ca-central-1 '
              f'"s3://cse-cic-ids2018/{PREFIJO}" {CARPETA}')
        sys.exit(1)

    archivos = [(k, s) for k, s in archivos if not any(x in k for x in EXCLUIR)]
    if not archivos:
        print("No encontre CSVs. Revisa PREFIJO o usa la alternativa con AWS CLI:")
        print('  aws s3 ls --no-sign-request s3://cse-cic-ids2018/')
        sys.exit(1)

    total = sum(s for _, s in archivos)
    print(f"Archivos a bajar: {len(archivos)}  |  Tamano total: {total / 1e9:.2f} GB\n")
    for k, s in archivos:
        print(f"  {s / 1e6:9.1f} MB  {k.split('/')[-1]}")
    if input("\n¿Descargar? (s/n): ").strip().lower() != "s":
        print("Cancelado.")
        return

    for i, (key, size) in enumerate(archivos, 1):
        nombre = os.path.basename(key)
        destino = os.path.join(CARPETA, nombre)
        if os.path.exists(destino) and os.path.getsize(destino) == size:
            print(f"[{i}/{len(archivos)}] {nombre}: ya estaba completo, salto")
            continue
        url = BUCKET_URL + quote(key)
        tmp = destino + ".part"
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            bajado = 0
            with open(tmp, "wb") as f:
                for trozo in r.iter_content(chunk_size=4 * 1024 * 1024):
                    f.write(trozo)
                    bajado += len(trozo)
                    print(f"\r[{i}/{len(archivos)}] {nombre}: {bajado / size:6.1%}", end="")
        os.replace(tmp, destino)
        print(f"\r[{i}/{len(archivos)}] {nombre}: listo            ")

    print("\nTodo en la carpeta:", CARPETA)
    print("Ahora corre:  python 1_netflow/entrenar_netflow.py")


if __name__ == "__main__":
    main()