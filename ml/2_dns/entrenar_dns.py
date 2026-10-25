"""
entrenar_dns_v2.py - Modulo A (DNS) version 2: entrenamiento con evaluacion seria.

Que hace:
  1) Arma el dataset desde varias fuentes (carpeta datos/dns/) y, si existe, tu trafico real
     (carpeta datos/dns_real/). TODO se reduce al dominio registrable (steamcontent.com), igual que
     se hara en produccion.
  2) Quita dominios ambiguos (un "malicioso" que tambien esta en la lista de normales).
  3) Entrena 2 modelos distintos (XGBoost sobre features + regresion logistica sobre n-gramas de
     caracteres) y los combina.
  4) Validacion cruzada de 5 pliegues (media +- desviacion) y examen final aparte (20%).
  5) Elige los umbrales por TASA DE FALSAS ALARMAS objetivo (no por "50/50"):
       umbral_alerta  -> ~0.5% de falsos positivos
       umbral_bloqueo -> ~0.05% de falsos positivos
  6) Mide generalizacion: entrenar SIN una fuente (URLhaus, OpenPhish, DGA) y probar en ella;
     y DGA con familias que el modelo nunca vio.
  7) Prueba con tu trafico real que NO uso para entrenar (dominios nuevos).
  8) Guarda modelo_dns_v2.pkl (reentrenado con todo) listo para probar_dns_v2.py.

USO:
    pip install tldextract scikit-learn xgboost pandas numpy joblib requests
    python 2_dns/descargar_dns.py    (crea datos/dns/)
    python entrenar_dns_v2.py | Tee-Object salida_dns_v2.txt

TU TRAFICO REAL (muy recomendado): pon archivos .txt (un host por linea) o .csv (columna
"dominio" o "host") en la carpeta datos/dns_real/. Se usan asi: la mitad de los dominios nuevos entra
al entrenamiento como "normal" y la otra mitad se reserva para medir falsas alarmas reales.
Solo hazlo con trafico de una PC limpia.
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
import zlib

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, train_test_split

import dns_comun as C

# ============================ PARAMETROS ============================
CARPETA = os.path.join(DATOS, "dns")
CARPETA_REAL = os.path.join(DATOS, "dns_real")
N_TRANCO = 100_000            # dominios normales de Tranco (los mas fiables: el top)
N_ALEXA = 40_000              # normales extra del dataset de DGA
CAP_DGA_FAMILIA = 2_400       # tope de dominios por familia DGA (25 familias -> 60.000)
ALLOWLIST_TOP = 20_000        # los N dominios mas populares nunca se alertan (solo en produccion)
FPR_ALERTA = 0.005            # 0.5% de falsos positivos
FPR_BLOQUEO = 0.0005          # 0.05% de falsos positivos
PREVALENCIA = 0.01            # supuesto: 1% del trafico real seria malicioso (para precision estimada)
TEST_FRAC = 0.20
N_FOLDS = 5
HACER_LOSO = True             # evaluaciones "sin esta fuente" (tardan mas)
N_FAMILIAS_FUERA = 5
SEMILLA = 42
# ====================================================================


# ---------------------------- carga de fuentes ----------------------------
def leer_lineas(ruta):
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def leer_real():
    hosts = []
    for ruta in glob.glob(os.path.join(CARPETA_REAL, "*")):
        if ruta.lower().endswith(".csv"):
            d = pd.read_csv(ruta)
            col = next((c for c in ("dominio", "host", "domain") if c in d.columns), d.columns[0])
            hosts += d[col].astype(str).tolist()
        elif ruta.lower().endswith(".txt"):
            hosts += leer_lineas(ruta)
    return hosts


def construir_dataset():
    rng = np.random.default_rng(SEMILLA)
    partes, allow = [], []

    def agregar(dominios, label, grupo, familia=""):
        regs = [C.registrable(d) for d in dominios]
        df = pd.DataFrame({"dominio": regs, "label": label, "grupo": grupo, "familia": familia})
        df = df.dropna(subset=["dominio"]).drop_duplicates("dominio")
        print(f"  {grupo:<18} label={label}  {len(df):>8} dominios registrables")
        partes.append(df)

    print("Cargando fuentes...")
    ruta = os.path.join(CARPETA, "tranco.csv")
    if os.path.exists(ruta):
        t = pd.read_csv(ruta, names=["rank", "dominio"]).head(N_TRANCO)
        agregar(t.dominio, 0, "benigno_tranco")
        regs = [C.registrable(d) for d in t.dominio.head(ALLOWLIST_TOP * 2)]
        allow = list(dict.fromkeys(r for r in regs if r))[:ALLOWLIST_TOP]

    ruta = os.path.join(CARPETA, "dga_chrmor.csv")
    if os.path.exists(ruta):
        d = pd.read_csv(ruta, header=None, names=["tipo", "familia", "dominio"]).dropna()
        legit = d[d.tipo == "legit"].sample(n=min(N_ALEXA, (d.tipo == "legit").sum()), random_state=SEMILLA)
        agregar(legit.dominio, 0, "benigno_alexa")
        dga = d[d.tipo == "dga"]
        dga = pd.concat([g.sample(n=min(len(g), CAP_DGA_FAMILIA), random_state=SEMILLA)
                         for _, g in dga.groupby("familia")])
        regs = [C.registrable(x) for x in dga.dominio]
        df = pd.DataFrame({"dominio": regs, "label": 1, "grupo": "dga", "familia": dga.familia.values})
        df = df.dropna(subset=["dominio"]).drop_duplicates("dominio")
        print(f"  {'dga':<18} label=1  {len(df):>8} dominios registrables ({df.familia.nunique()} familias)")
        partes.append(df)

    for nombre, grupo in (("urlhaus.txt", "urlhaus"), ("openphish.txt", "openphish")):
        ruta = os.path.join(CARPETA, nombre)
        if os.path.exists(ruta):
            agregar([l for l in leer_lineas(ruta) if l.lower().startswith("http")], 1, grupo)
    for ruta in sorted(glob.glob(os.path.join(CARPETA, "malo_*.txt"))):
        agregar(leer_lineas(ruta), 1, os.path.basename(ruta)[:-4])
    for ruta in sorted(glob.glob(os.path.join(CARPETA, "bueno_*.txt"))):
        agregar(leer_lineas(ruta), 0, os.path.basename(ruta)[:-4])

    real_hosts = leer_real() if os.path.isdir(CARPETA_REAL) else []
    n_real_total = 0
    if real_hosts:
        regs = {C.registrable(h) for h in real_hosts}
        regs.discard(None)
        n_real_total = len(regs)
        agregar(sorted(regs), 0, "real")

    if not partes:
        raise SystemExit("No encontre datos. Corre primero: python descargar_dns.py")

    D = pd.concat(partes, ignore_index=True)
    D = D.sort_values("label", kind="stable")   # normales primero: ganan si hay conflicto

    # dominios ambiguos: marcados maliciosos pero tambien presentes como normales
    normales = set(D.loc[D.label == 0, "dominio"])
    amb = D[(D.label == 1) & D.dominio.isin(normales)]
    if len(amb):
        print("\nDominios 'maliciosos' que tambien estan como normales (se descartan por ambiguos):")
        print(amb.grupo.value_counts().to_string())
    D = D.drop_duplicates("dominio", keep="first").reset_index(drop=True)
    if n_real_total:
        n_nuevos = int((D.grupo == "real").sum())
        print(f"\nTrafico real: {n_real_total} dominios; {n_nuevos} son nuevos para el entrenamiento "
              f"(los otros {n_real_total - n_nuevos} ya estaban en Tranco/Alexa).")
    return D, set(allow)


def asignar_split(D):
    D["split"] = "train"
    real = D.grupo == "real"
    if real.any():
        impar = D.loc[real, "dominio"].map(lambda s: zlib.crc32(s.encode()) % 2 == 1)
        D.loc[impar[impar].index, "split"] = "real_test"
    resto = D[D.grupo != "real"]
    clave = resto.label.astype(str) + "_" + resto.grupo
    pequenos = clave.map(clave.value_counts()) < 10
    clave = clave.where(~pequenos, resto.label.astype(str) + "_otros")
    _, idx_te = train_test_split(resto.index, test_size=TEST_FRAC, stratify=clave, random_state=SEMILLA)
    D.loc[idx_te, "split"] = "test"
    return D


# ------------------------------- metricas -------------------------------
def umbral_para_fpr(y, p, fpr):
    return float(np.quantile(p[y == 0], 1 - fpr))


def tpr_fpr(y, p, thr):
    marcado = p > thr
    return float(marcado[y == 1].mean()), float(marcado[y == 0].mean())


def precision_est(tpr, fpr, prev=PREVALENCIA):
    den = tpr * prev + fpr * (1 - prev)
    return tpr * prev / den if den > 0 else float("nan")


def resumen_modelo(y, p):
    thr = umbral_para_fpr(y, p, FPR_ALERTA)
    tpr, _ = tpr_fpr(y, p, thr)
    return {"AUC": roc_auc_score(y, p), "PR_AUC": average_precision_score(y, p),
            f"TPR@FPR{FPR_ALERTA:.1%}": tpr}


def puntuar(tr, te):
    """Entrena con tr y devuelve probabilidades (xgb, lr, ens) para te."""
    m = C.entrenar_modelos(tr[C.FEATURES], tr.txt, tr.label.values, SEMILLA)
    return m, C.predecir_modelos(m, te[C.FEATURES], te.txt)


# ================================== PROGRAMA ==================================
t_ini = time.time()
D, ALLOW = construir_dataset()
D = asignar_split(D)
D = pd.concat([D, C.a_features(D.dominio)], axis=1)
D["txt"] = C.textos(D.dominio)

print("\n=== RESUMEN DEL DATASET ===")
print(D.groupby(["label", "grupo", "split"]).size().unstack(fill_value=0).to_string())

TR = D[D.split == "train"].reset_index(drop=True)
TE = D[D.split == "test"].reset_index(drop=True)
RT = D[D.split == "real_test"].reset_index(drop=True)
print(f"\ntrain={len(TR)}  test={len(TE)}  real_test={len(RT)}  "
      f"(maliciosos en train: {TR.label.mean():.1%})")

# ---------------------- 1) validacion cruzada en TRAIN ----------------------
print("\n" + "=" * 70 + f"\n1) VALIDACION CRUZADA ({N_FOLDS} pliegues)\n" + "=" * 70)
clave = TR.label.astype(str) + "_" + TR.grupo
clave = clave.where(clave.map(clave.value_counts()) >= N_FOLDS, TR.label.astype(str) + "_otros")
oof = {k: np.zeros(len(TR)) for k in ("xgb", "lr", "ens")}
filas = []
for i, (a, b) in enumerate(StratifiedKFold(N_FOLDS, shuffle=True, random_state=SEMILLA).split(TR, clave), 1):
    _, (p1, p2, p3) = puntuar(TR.iloc[a], TR.iloc[b])
    for k, p in zip(("xgb", "lr", "ens"), (p1, p2, p3)):
        oof[k][b] = p
        r = resumen_modelo(TR.label.values[b], p)
        r.update(modelo=k, pliegue=i)
        filas.append(r)
    print(f"  pliegue {i}/{N_FOLDS} listo ({time.time() - t_ini:.0f} s)")
cv = pd.DataFrame(filas)
cv_tab = cv.groupby("modelo")[["AUC", "PR_AUC", f"TPR@FPR{FPR_ALERTA:.1%}"]].agg(["mean", "std"]).round(4)
print(cv_tab.to_string())

y_tr = TR.label.values
THR_ALERTA = umbral_para_fpr(y_tr, oof["ens"], FPR_ALERTA)
THR_BLOQUEO = umbral_para_fpr(y_tr, oof["ens"], FPR_BLOQUEO)
print(f"\nUmbrales elegidos con las predicciones fuera-de-pliegue (ensamble):")
print(f"  ALERTA  (FPR~{FPR_ALERTA:.2%}): prob > {THR_ALERTA:.4f}")
print(f"  BLOQUEO (FPR~{FPR_BLOQUEO:.2%}): prob > {THR_BLOQUEO:.4f}")

# ------------------------- 2) examen final (TEST) -------------------------
print("\n" + "=" * 70 + "\n2) EXAMEN FINAL (20% que el modelo nunca vio; umbrales ya fijados)\n" + "=" * 70)
M, (p1, p2, p3) = puntuar(TR, TE)
y_te = TE.label.values
filas = []
for k, p in zip(("xgb", "lr", "ens"), (p1, p2, p3)):
    r = resumen_modelo(y_te, p)
    r["modelo"] = k
    filas.append(r)
print(pd.DataFrame(filas).set_index("modelo").round(4).to_string())

print("\nEnsamble con los umbrales fijados:")
for nombre, thr in (("ALERTA", THR_ALERTA), ("BLOQUEO", THR_BLOQUEO)):
    tpr, fpr = tpr_fpr(y_te, p3, thr)
    print(f"  {nombre:<8} detecta {tpr:6.1%} de los maliciosos | falsas alarmas {fpr:.3%} de los normales | "
          f"precision estimada con {PREVALENCIA:.0%} de maliciosos reales: {precision_est(tpr, fpr):.1%}")

print("\nPor fuente (umbral ALERTA): maliciosos -> % detectado | normales -> % de falsas alarmas")
TE["p"] = p3
tab = TE.assign(marcado=TE.p > THR_ALERTA).groupby(["label", "grupo"]).agg(
    n=("marcado", "size"), marcado=("marcado", "mean")).round(4)
print(tab.to_string())

# -------------------- 3) generalizacion a fuentes no vistas --------------------
if HACER_LOSO:
    print("\n" + "=" * 70 + "\n3) GENERALIZACION: entrenar SIN una fuente y probar en ella\n" + "=" * 70)
    print("(AUC y deteccion al 0.5% de falsas alarmas, medidos contra los normales del examen)")
    normales_te = TE[TE.label == 0]
    filas = []
    for g in [g for g in D[D.label == 1].grupo.unique() if (D.grupo == g).sum() >= 30]:
        tr_sin = TR[TR.grupo != g]
        pos = D[(D.grupo == g) & (D.split != "real_test")]
        if tr_sin.label.nunique() < 2 or tr_sin.label.sum() < 30:
            continue
        te_g = pd.concat([pos, normales_te])
        _, (_, _, pe) = puntuar(tr_sin, te_g)
        yy = te_g.label.values
        thr = umbral_para_fpr(yy, pe, FPR_ALERTA)
        filas.append({"fuente_excluida": g, "n": int(yy.sum()), "AUC": roc_auc_score(yy, pe),
                      "detecta_al_0.5%FP": tpr_fpr(yy, pe, thr)[0]})
        print(f"  sin {g}: listo ({time.time() - t_ini:.0f} s)")
    if filas:
        print(pd.DataFrame(filas).round(4).to_string(index=False))

    dga_fam = sorted(D[D.grupo == "dga"].familia.unique())
    if len(dga_fam) > N_FAMILIAS_FUERA + 3:
        fuera = [str(f) for f in np.random.default_rng(SEMILLA).choice(dga_fam, N_FAMILIAS_FUERA, replace=False)]
        print(f"\nDGA con familias NUNCA vistas (se excluyen del entrenamiento: {fuera})")
        tr_sin = TR[~TR.familia.isin(fuera)]
        pos = D[D.familia.isin(fuera)]
        te_f = pd.concat([pos, normales_te])
        _, (_, _, pe) = puntuar(tr_sin, te_f)
        yy = te_f.label.values
        thr = umbral_para_fpr(yy, pe, FPR_ALERTA)
        te_f = te_f.assign(p=pe)
        filas = [{"familia": f, "n": int((te_f.familia == f).sum()),
                  "detecta_al_0.5%FP": float((te_f[te_f.familia == f].p > thr).mean())} for f in fuera]
        print(pd.DataFrame(filas).round(4).to_string(index=False))
        print(f"  AUC conjunto: {roc_auc_score(yy, pe):.4f}")

# ---------------------- 4) tu trafico real (no usado al entrenar) ----------------------
print("\n" + "=" * 70 + "\n4) TRAFICO REAL RESERVADO (dominios nuevos, nunca usados en el entrenamiento)\n" + "=" * 70)
if len(RT):
    _, _, pr = C.predecir_modelos(M, RT[C.FEATURES], RT.txt)
    RT["p"] = pr
    sin_allow = RT[~RT.dominio.isin(ALLOW)]
    print(f"{len(RT)} dominios reservados ({len(RT) - len(sin_allow)} estan en la allowlist de produccion).")
    for nombre, thr in (("ALERTA", THR_ALERTA), ("BLOQUEO", THR_BLOQUEO)):
        a = int((RT.p > thr).sum())
        b = int((sin_allow.p > thr).sum())
        print(f"  {nombre:<8} sin allowlist: {a}/{len(RT)} marcados ({a / len(RT):.1%}) | "
              f"con allowlist: {b}/{len(RT)} ({b / len(RT):.1%})   <- todo lo marcado es falsa alarma")
    print("\nDominios reales con mayor probabilidad (revisalos a mano):")
    print(RT.sort_values("p", ascending=False).head(15)[["dominio", "p"]].to_string(index=False,
          float_format=lambda v: f"{v:.3f}"))
    if len(RT) < 200:
        print(f"\nOJO: solo {len(RT)} dominios reales reservados. Con tan pocos, el porcentaje es poco fiable;"
              f"\n     junta mas trafico (cache DNS durante varios dias) en {CARPETA_REAL}/")
else:
    print(f"No hay trafico real reservado. Pon .txt/.csv con hosts en la carpeta {CARPETA_REAL}/ "
          f"(minimo recomendado: varios cientos de dominios) y vuelve a correr.")

# ---------------------- 5) modelo final (todo el dato) ----------------------
print("\n" + "=" * 70 + "\n5) MODELO FINAL\n" + "=" * 70)
TODO = D[D.split.isin(["train", "test"])].reset_index(drop=True)
Mf = C.entrenar_modelos(TODO[C.FEATURES], TODO.txt, TODO.label.values, SEMILLA)
paquete = {"xgb": Mf["xgb"], "lr": Mf["lr"], "umbral_alerta": THR_ALERTA, "umbral_bloqueo": THR_BLOQUEO,
           "allowlist": frozenset(ALLOW), "features": C.FEATURES, "version": "dns_v2",
           "fuentes": sorted(D.grupo.unique()), "n_filas": int(len(TODO)),
           "fpr_alerta": FPR_ALERTA, "fpr_bloqueo": FPR_BLOQUEO}
joblib.dump(paquete, os.path.join(MODELOS, "modelo_dns_v2.pkl"))
print(f"Guardado: modelo_dns_v2.pkl  (entrenado con {len(TODO)} dominios, "
      f"allowlist de {len(ALLOW)} dominios populares)")
print(f"Tiempo total: {(time.time() - t_ini) / 60:.1f} min")