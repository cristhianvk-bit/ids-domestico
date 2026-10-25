"""
preparar_phiusiil.py - Agrega el dataset PhiUSIIL (phishing) al entrenamiento DNS.

POR QUE: con OpenPhish solo hay ~100 dominios de phishing y el modelo detecta apenas
el 7.7 % (ver resultados/salida_dns_v2.txt). PhiUSIIL tiene 100 945 URLs de phishing
y 134 850 legitimas, revisadas y publicadas en una revista cientifica.

FUENTE (citar en el articulo):
  Prasad, A. y Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered
  phishing URL detection framework based on similarity index and incremental learning.
  Computers & Security, 136, 103545. https://doi.org/10.1016/j.cose.2023.103545
  Dataset: UCI Machine Learning Repository, id 967 (licencia CC BY 4.0).

PASOS:
  1) Entra a  https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
     y pulsa "DOWNLOAD" (baja un .zip).
  2) Pon ese .zip (sin descomprimir) en la carpeta  datos/dns/
  3) python 2_dns/preparar_phiusiil.py
  4) python 2_dns/entrenar_dns.py      (detecta solo los archivos nuevos)

En PhiUSIIL la etiqueta es:  1 = legitima,  0 = phishing.
Crea:  datos/dns/malo_phiusiil.txt   (phishing)
       datos/dns/bueno_phiusiil.txt  (legitimas)
"""
import glob
import io
import os
import zipfile

import pandas as pd

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARPETA = os.path.join(RAIZ, "datos", "dns")


def leer_dataset():
    zips = [z for z in glob.glob(os.path.join(CARPETA, "*.zip")) if "phiusiil" in z.lower()]
    csvs = [c for c in glob.glob(os.path.join(CARPETA, "*.csv")) if "phiusiil" in c.lower()]
    if csvs:
        print("Leyendo", os.path.basename(csvs[0]))
        return pd.read_csv(csvs[0], low_memory=False)
    if zips:
        z = zipfile.ZipFile(zips[0])
        dentro = [n for n in z.namelist() if n.lower().endswith(".csv")]
        if not dentro:
            raise SystemExit(f"El zip {zips[0]} no tiene ningun .csv adentro.")
        print("Leyendo", dentro[0], "desde", os.path.basename(zips[0]))
        return pd.read_csv(io.BytesIO(z.read(dentro[0])), low_memory=False)
    raise SystemExit(
        "No encontre el dataset. Descarga el .zip de\n"
        "  https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset\n"
        f"y ponlo en: {CARPETA}")


def main():
    df = leer_dataset()
    cols = {c.lower().strip(): c for c in df.columns}
    if "url" not in cols or "label" not in cols:
        raise SystemExit(f"No encontre las columnas URL y label. Columnas: {list(df.columns)[:10]}...")
    url, label = cols["url"], cols["label"]
    df = df[[url, label]].dropna()

    phishing = df.loc[df[label] == 0, url].astype(str).str.strip().unique()
    legitimas = df.loc[df[label] == 1, url].astype(str).str.strip().unique()

    for nombre, datos in (("malo_phiusiil.txt", phishing), ("bueno_phiusiil.txt", legitimas)):
        ruta = os.path.join(CARPETA, nombre)
        with open(ruta, "w", encoding="utf-8") as f:
            f.write("# Fuente: PhiUSIIL (Prasad y Chandra, 2024), UCI id 967, CC BY 4.0\n")
            f.write("\n".join(datos) + "\n")
        print(f"  {nombre}: {len(datos):,} URLs")

    print("\nListo. Ahora corre:  python 2_dns/entrenar_dns.py")
    print("(el entrenamiento las reduce a dominio registrable y descarta las que choquen con Tranco)")


if __name__ == "__main__":
    main()
