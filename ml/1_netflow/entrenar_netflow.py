"""
PASO 6 - Modulo B (NetFlow): XGBoost con CSE-CIC-IDS2018 + validacion cruzada con 2017

Que hace (todo en un solo script):
  1) Lee los CSV de 2018 (y los de 2017 si ya los tienes) por pedazos (chunks), asi
     no revienta la memoria aunque un archivo pese varios GB.
  2) Estandariza los nombres de columnas de 2018 al formato de 2017 y se queda solo
     con las features que existen en AMBOS datasets.
  3) Mismo protocolo estricto de antes:
       - split temporal por archivo (80% inicial = entrenar, 20% final = examen)
       - tope de filas por clase SOLO en entrenamiento
       - el examen conserva la distribucion real (solo se submuestrea de forma
         uniforme, igual para todas las clases, para ahorrar memoria)
  4) Corre 4 experimentos con XGBoost (n_jobs=-1, pesos suavizados por clase):
       intra2018    : entrena y examina en 2018 (guarda modelo_netflow_2018_xgb.pkl)
       2017_a_2018  : entrena con 2017, examina con 2018 (validacion externa)
       2018_a_2017  : entrena con 2018, examina con 2017 (validacion externa)
       combinado    : entrena con 2017+2018, examina en ambos
                      (guarda modelo_netflow_combinado_xgb.pkl)
  5) Imprime classification report y matriz de confusion de cada uno, y una tabla
     resumen al final (esa tabla va al articulo).

ANTES DE CORRER:
    pip install pandas scikit-learn joblib xgboost
    python 1_netflow/descargar_2018.py  -> crea datos/cse-cic-ids2018
    (la carpeta datos/cic-ids2017 con los CSV de 2017 es opcional pero recomendada;
     sin ella solo se corre el experimento intra2018)
    python 1_netflow/entrenar_netflow.py

SI TE QUEDAS SIN MEMORIA: baja MUESTREO_TEST["2018"], MUESTREO_EXT["2018"],
CAP_TRAIN y CHUNK (mas abajo).
"""
import os
# --- Rutas del proyecto (no tocar): el script funciona desde cualquier carpeta ---
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATOS = os.path.join(RAIZ, "datos")
MODELOS = os.path.join(RAIZ, "modelos")
RESULTADOS = os.path.join(RAIZ, "resultados")
for _c in (DATOS, MODELOS, RESULTADOS):
    os.makedirs(_c, exist_ok=True)
import glob
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

# ======================= PARAMETROS (puedes tocarlos) =======================

EXCLUIR_FEATURES = ["Destination Port", "Total Length of Fwd Packets", "Subflow Fwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward"]
CARPETA_2018 = os.path.join(DATOS, "cse-cic-ids2018")
CARPETA_2017 = os.path.join(DATOS, "cic-ids2017")
EXPERIMENTOS = ["intra2018", "2017_a_2018", "2018_a_2017", "combinado"]

FRACCION_TRAIN = 0.80          # primer 80% entrena, ultimo 20% examina
SPLIT_POR_CLASE = True         # True: el corte 80/20 se hace DENTRO de cada clase y archivo.
                               # (necesario en 2018: los ataques ocurren en ventanas de tiempo y
                               #  el ultimo 20% de cada dia suele ser solo trafico normal)
CAP_TRAIN = 150_000            # tope por clase en entrenamiento (por dataset)
CAP_COMBINADO = 200_000        # tope por clase en el modelo combinado
MUESTREO_TEST = {"2017": 1.0, "2018": 0.30}   # fraccion del 20% final que se conserva
MUESTREO_EXT = {"2017": 0.50, "2018": 0.10}   # fraccion usada como examen externo
CHUNK = 400_000                # filas leidas a la vez
PESO_EXP = 0.5                 # 0 = sin pesos, 1 = pesos "balanced" completos
SIN_PUERTO = False             # True = quitar Destination Port (experimento de robustez)

EXCLUIR_CLASES = {"Otros", "Infiltration"}   # Infiltration tiene etiquetas dudosas
N_ARBOLES = 300
SEMILLA = 42
# ===========================================================================

# Nombres de columnas de 2018 -> nombres de 2017 (formato CICFlowMeter clasico)
MAPEO_2018 = {
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}


def normalizar(c):
    c = str(c).strip()
    return MAPEO_2018.get(c, c)


def categoria(etq):
    """Agrupa las etiquetas originales (2017 y 2018) en las mismas clases."""
    e = str(etq).strip().lower()
    if e in ("benign", "normal"):
        return "normal"
    if e.startswith("ddos") or e.startswith("dos"):
        return "DoS_DDoS"
    if e == "portscan":
        return "PortScan"
    if e == "bot":
        return "Botnet"
    if e in ("ftp-patator", "ssh-patator", "ftp-bruteforce", "ssh-bruteforce"):
        return "FuerzaBruta"
    if e.startswith("web attack") or e.startswith("brute force -") or e == "sql injection":
        return "WebAttack"
    if e.startswith("infil"):
        return "Infiltration"
    return "Otros"   # Heartbleed y cualquier etiqueta rara


def contar_filas(ruta):
    n = 0
    with open(ruta, "rb") as f:
        while True:
            b = f.read(1 << 24)
            if not b:
                break
            n += b.count(b"\n")
    return max(n - 1, 0)   # menos la cabecera


def contar_por_clase(ruta):
    """Primera pasada rapida: cuantas filas tiene cada clase en este archivo."""
    cnt = {}
    lector = pd.read_csv(ruta, usecols=lambda c: str(c).strip() == "Label",
                         chunksize=CHUNK, dtype=str)
    for ch in lector:
        for etq, v in ch.iloc[:, 0].value_counts().items():
            c = categoria(etq)
            cnt[c] = cnt.get(c, 0) + int(v)
    return cnt


def encabezado(ruta):
    return {normalizar(c) for c in pd.read_csv(ruta, nrows=0).columns}


def acumular(acum, tr, rng):
    """Mantiene una muestra UNIFORME de hasta CAP_TRAIN filas por clase."""
    for c, g in tr.groupby("categoria"):
        g = g.assign(_k=rng.random(len(g)).astype("float32"))
        if c in acum:
            g = pd.concat([acum[c], g], ignore_index=True)
        if len(g) > CAP_TRAIN:
            g = g.nsmallest(CAP_TRAIN, "_k")
        acum[c] = g


def cargar(carpeta, nombre, feats, necesita_ext):
    archivos = sorted(glob.glob(os.path.join(carpeta, "*.csv")))
    usar = set(feats) | {"Label"}
    rng = np.random.default_rng(SEMILLA)
    acum, tests, exts = {}, [], []
    print(f"\n=== Cargando {nombre} ({len(archivos)} archivos) ===")

    for ruta in archivos:
        t0 = time.time()
        n = contar_filas(ruta)
        corte = int(n * FRACCION_TRAIN)
        i0, leidas, saltado = 0, 0, False
        if SPLIT_POR_CLASE:
            cortes = {c: int(v * FRACCION_TRAIN) for c, v in contar_por_clase(ruta).items()}
            corrida = {}

        lector = pd.read_csv(ruta, chunksize=CHUNK, low_memory=False,
                             usecols=lambda c: normalizar(c) in usar)
        for ch in lector:
            ch.columns = [normalizar(c) for c in ch.columns]
            faltan = [c for c in feats + ["Label"] if c not in ch.columns]
            if faltan:
                print(f"  ! {os.path.basename(ruta)}: faltan columnas {faltan[:4]}... archivo saltado")
                saltado = True
                break

            idx = np.arange(i0, i0 + len(ch))
            i0 += len(ch)

            # marca de "esta fila va a entrenamiento" calculada ANTES de limpiar
            if SPLIT_POR_CLASE:
                raw = pd.Series(ch["Label"].map({u: categoria(u) for u in ch["Label"].unique()}).to_numpy())
                orden = raw.groupby(raw).cumcount().to_numpy() + raw.map(corrida).fillna(0).to_numpy()
                es_train_raw = orden < raw.map(cortes).fillna(0).to_numpy()
                for c, v in raw.value_counts().items():
                    corrida[c] = corrida.get(c, 0) + int(v)
            else:
                es_train_raw = idx < corte

            # numerico + limpieza de inf/NaN (tambien elimina cabeceras repetidas dentro del CSV)
            X = ch[feats].apply(pd.to_numeric, errors="coerce")
            X = X.replace([np.inf, -np.inf], np.nan)
            ok = X.notna().all(axis=1).to_numpy()
            if not ok.any():
                continue
            X = X[ok].astype("float32")
            lab = ch["Label"][ok]
            es_train_raw = es_train_raw[ok]

            mapa = {u: categoria(u) for u in lab.unique()}
            cat = lab.map(mapa).to_numpy()
            keep = ~np.isin(cat, list(EXCLUIR_CLASES))
            X = X[keep].copy()
            X["categoria"] = cat[keep]
            es_train = es_train_raw[keep]
            leidas += len(X)

            tr = X[es_train].drop_duplicates()
            te = X[~es_train].drop_duplicates()

            acumular(acum, tr, rng)
            f = MUESTREO_TEST[nombre]
            tests.append(te if f >= 1 else te.sample(frac=f, random_state=SEMILLA))
            if necesita_ext:
                fe = MUESTREO_EXT[nombre]
                exts.append(X if fe >= 1 else X.sample(frac=fe, random_state=SEMILLA))

        if not saltado:
            print(f"  {os.path.basename(ruta)}: {n:>9} filas leidas, {leidas:>9} utiles "
                  f"({time.time() - t0:.0f} s)")

    if not acum:
        raise SystemExit(f"No pude cargar datos validos de {carpeta}")

    train = pd.concat(acum.values(), ignore_index=True).drop(columns="_k").drop_duplicates()
    test = pd.concat(tests, ignore_index=True).drop_duplicates()
    ext = pd.concat(exts, ignore_index=True) if exts else None

    print(f"\nClases en TRAIN {nombre} (con tope):")
    print(train["categoria"].value_counts().to_string())
    print(f"\nClases en TEST {nombre} (distribucion real):")
    print(test["categoria"].value_counts().to_string())
    return {"train": train, "test": test, "ext": ext}


def entrenar_xgb(X, y_nombres):
    le = LabelEncoder().fit(sorted(set(map(str, y_nombres))))
    y = le.transform([str(v) for v in y_nombres])
    cnt = pd.Series(y).value_counts()
    w = {c: (len(y) / (len(cnt) * n)) ** PESO_EXP for c, n in cnt.items()}
    pesos = pd.Series(y).map(w).to_numpy(dtype="float32")

    modelo = XGBClassifier(
        n_estimators=N_ARBOLES, max_depth=8, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        objective="multi:softprob", tree_method="hist",
        eval_metric="mlogloss", n_jobs=-1, random_state=SEMILLA)
    t0 = time.time()
    modelo.fit(X, y, sample_weight=pesos)
    print(f"  XGBoost entrenado en {time.time() - t0:.1f} s con {len(X)} filas, "
          f"{len(le.classes_)} clases: {[str(c) for c in le.classes_]}")
    return modelo, le


def evaluar(titulo, modelo, le, X, y_nombres):
    t0 = time.time()
    pred = le.inverse_transform(modelo.predict(X)).astype(str)
    ms = (time.time() - t0) / len(X) * 1000
    y_nombres = np.asarray(y_nombres).astype(str)
    presentes = [str(c) for c in sorted(set(y_nombres))]          # clases que SI tienen examen
    todas = [str(c) for c in sorted(set(y_nombres) | set(pred))]
    conocidas = [c for c in presentes if c in {str(k) for k in le.classes_}]

    print(f"\n{'-' * 14} {titulo} {'-' * 14}")
    print(f"Filas de examen: {len(X)} | inferencia: {ms:.4f} ms por flujo")
    print(classification_report(y_nombres, pred, labels=presentes,
                                zero_division=0, digits=3))
    print("Matriz de confusion (filas=real, columnas=predicho)")
    print("Orden:", todas)
    print(confusion_matrix(y_nombres, pred, labels=todas))
    rep = classification_report(y_nombres, pred, labels=presentes,
                                zero_division=0, output_dict=True)
    # macro F1 justo: ignora clases que el modelo nunca vio al entrenar (ej. PortScan en 2018)
    rep["_macro_conocidas"] = f1_score(y_nombres, pred, labels=conocidas,
                                       average="macro", zero_division=0)
    print(f"Macro F1 solo con clases que el modelo conoce: {rep['_macro_conocidas']:.3f}")
    return rep


def fila_resumen(exp, test, rep):
    def g(clase, m):
        return rep[clase][m] if clase in rep else float("nan")
    return {"experimento": exp, "examen": test,
            "macroF1": rep["macro avg"]["f1-score"], "macroF1_conocidas": rep["_macro_conocidas"],
            "Bot_recall": g("Botnet", "recall"), "Bot_prec": g("Botnet", "precision"),
            "Bot_F1": g("Botnet", "f1-score"), "DoS_recall": g("DoS_DDoS", "recall"),
            "Web_recall": g("WebAttack", "recall")}


# ================================ PROGRAMA ================================
arch18 = sorted(glob.glob(os.path.join(CARPETA_2018, "*.csv")))
arch17 = sorted(glob.glob(os.path.join(CARPETA_2017, "*.csv")))
if not arch18 and not arch17:
    raise SystemExit("No hay CSVs. Corre primero descargar_2018.py")

hay18, hay17 = bool(arch18), bool(arch17)
cols18 = encabezado(arch18[0]) if hay18 else None
cols17 = encabezado(arch17[0]) if hay17 else None

if hay18 and hay17:
    feats = sorted((cols18 & cols17) - {"Label"})
    print(f"Features en comun 2017/2018: {len(feats)}")
    print("Solo en 2018 (descartadas):", sorted(cols18 - cols17 - {"Label"}))
    print("Solo en 2017 (descartadas):", sorted(cols17 - cols18 - {"Label"}))
else:
    feats = sorted((cols18 or cols17) - {"Label", "Timestamp"})
    print(f"Solo hay un dataset: {len(feats)} features. Los experimentos cruzados se saltaran.")

if SIN_PUERTO and "Destination Port" not in EXCLUIR_FEATURES:
    EXCLUIR_FEATURES.append("Destination Port")
quitadas = [f for f in EXCLUIR_FEATURES if f in feats]
if quitadas:
    feats = [f for f in feats if f not in quitadas]
    print(">> Experimento: features excluidas ->", quitadas)

necesita_ext = any(e in EXPERIMENTOS for e in ("2017_a_2018", "2018_a_2017"))
D18 = cargar(CARPETA_2018, "2018", feats, necesita_ext) if hay18 else None
D17 = cargar(CARPETA_2017, "2017", feats, necesita_ext) if hay17 else None

resumen = []

if "intra2018" in EXPERIMENTOS and D18:
    print("\n" + "=" * 60 + "\nEXPERIMENTO intra2018: entrena y examina en 2018\n" + "=" * 60)
    m, le = entrenar_xgb(D18["train"][feats], D18["train"]["categoria"].to_numpy())
    rep = evaluar("2018 -> 2018 (examen temporal)", m, le,
                  D18["test"][feats], D18["test"]["categoria"].to_numpy())
    resumen.append(fila_resumen("intra2018", "2018 test", rep))
    print("\nTop 10 features:")
    print(pd.Series(m.feature_importances_, index=feats)
            .sort_values(ascending=False).head(10).to_string())
    joblib.dump({"modelo": m, "columnas": feats, "clases": [str(c) for c in le.classes_],
                 "dataset": "CSE-CIC-IDS2018"}, os.path.join(MODELOS, "modelo_netflow_2018_xgb.pkl"))
    print("\nGuardado: modelo_netflow_2018_xgb.pkl")

if "2017_a_2018" in EXPERIMENTOS and D17 and D18:
    print("\n" + "=" * 60 + "\nEXPERIMENTO 2017_a_2018: validacion externa\n" + "=" * 60)
    m, le = entrenar_xgb(D17["train"][feats], D17["train"]["categoria"].to_numpy())
    rep = evaluar("2017 -> 2018 (dataset nunca visto)", m, le,
                  D18["ext"][feats], D18["ext"]["categoria"].to_numpy())
    resumen.append(fila_resumen("2017_a_2018", "2018 externo", rep))

if "2018_a_2017" in EXPERIMENTOS and D17 and D18:
    print("\n" + "=" * 60 + "\nEXPERIMENTO 2018_a_2017: validacion externa\n" + "=" * 60)
    m, le = entrenar_xgb(D18["train"][feats], D18["train"]["categoria"].to_numpy())
    rep = evaluar("2018 -> 2017 (dataset nunca visto)", m, le,
                  D17["ext"][feats], D17["ext"]["categoria"].to_numpy())
    resumen.append(fila_resumen("2018_a_2017", "2017 externo", rep))

if "combinado" in EXPERIMENTOS and D17 and D18:
    print("\n" + "=" * 60 + "\nEXPERIMENTO combinado: 2017 + 2018\n" + "=" * 60)
    comb = pd.concat([D17["train"], D18["train"]], ignore_index=True)
    comb = pd.concat([g.sample(n=min(len(g), CAP_COMBINADO), random_state=SEMILLA)
                      for _, g in comb.groupby("categoria")], ignore_index=True)
    m, le = entrenar_xgb(comb[feats], comb["categoria"].to_numpy())
    del comb
    for nom, D in (("2017", D17), ("2018", D18)):
        rep = evaluar(f"combinado -> examen {nom}", m, le,
                      D["test"][feats], D["test"]["categoria"].to_numpy())
        resumen.append(fila_resumen("combinado", f"{nom} test", rep))
    joblib.dump({"modelo": m, "columnas": feats, "clases": [str(c) for c in le.classes_],
                 "dataset": "CIC-IDS2017 + CSE-CIC-IDS2018"},
                os.path.join(MODELOS, "modelo_netflow_combinado_xgb.pkl"))
    print("\nGuardado: modelo_netflow_combinado_xgb.pkl")

# ---------------------------- TABLA RESUMEN ----------------------------
if resumen:
    print("\n" + "=" * 24 + " RESUMEN PARA EL ARTICULO " + "=" * 24)
    print("(macroF1 = promedio de las clases con ejemplos en el examen; macroF1_conocidas excluye")
    print(" ademas las clases que el modelo nunca vio al entrenar)")
    print(pd.DataFrame(resumen).round(3).to_string(index=False))