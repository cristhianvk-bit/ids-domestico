"""
Descarga los 8 CSV de CIC-IDS2017 (version MachineLearningCSV) a la carpeta
datos/cic-ids2017, desde un espejo en Hugging Face.

Uso:
    pip install requests
    python 1_netflow/descargar_2017.py

Pesa ~900 MB en total. Si se corta, vuelve a correrlo: salta los archivos
que ya estan completos.
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
import requests

BASE = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/"
ARCHIVOS = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
CARPETA = os.path.join(DATOS, "cic-ids2017")
os.makedirs(CARPETA, exist_ok=True)

for i, nombre in enumerate(ARCHIVOS, 1):
    destino = os.path.join(CARPETA, nombre)
    url = BASE + nombre
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        if os.path.exists(destino) and total and os.path.getsize(destino) == total:
            print(f"[{i}/8] {nombre}: ya estaba completo, salto")
            continue
        bajado = 0
        tmp = destino + ".part"
        with open(tmp, "wb") as f:
            for trozo in r.iter_content(chunk_size=1024 * 1024):
                f.write(trozo)
                bajado += len(trozo)
                if total:
                    print(f"\r[{i}/8] {nombre}: {bajado / total:6.1%}", end="")
        os.replace(tmp, destino)
        print(f"\r[{i}/8] {nombre}: listo            ")

print("\nTodo descargado en la carpeta:", CARPETA)
print("Ahora corre:  python 1_netflow/entrenar_netflow.py")