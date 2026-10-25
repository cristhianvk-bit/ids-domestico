"""
experimentos_dns.py - Prueba mejoras del detector DNS v2 SIN tocar el modelo oficial.

Compara, con el MISMO examen (el 20 % que entrenar_dns.py separa con la misma semilla):
  base   : igual que el modelo oficial (todas las fuentes, n-gramas de 1 a 3 letras)
  D1     : entrenado solo para DGA (sin URLhaus ni OpenPhish en el entrenamiento)
  D2     : n-gramas de 1 a 5 letras y mas vocabulario
  D1+D2  : las dos cosas juntas
Y para D3 (allowlist mas grande) mide las falsas alarmas en sitios normales poco populares
(Tranco puestos 100.001 a 1.000.000, que ningun modelo vio al entrenar).

Metricas sobre DGA vs normales del examen (lo que el modelo puede detectar por el nombre):
  AUC, deteccion al 0,5 % y al 0,05 % de falsas alarmas, DGA de familias nunca vistas.

Uso (desde la carpeta principal):
    venv\\Scripts\\python 2_dns\\experimentos_dns.py | Tee-Object resultados\\salida_experimentos_dns.txt
No guarda ni reemplaza ningun .pkl.
"""
import os
# --- Rutas del proyecto (no tocar): el script funciona desde cualquier carpeta ---
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATOS = os.path.join(RAIZ, "datos")
MODELOS = os.path.join(RAIZ, "modelos")
RESULTADOS = os.path.join(RAIZ, "resultados")
for _c in (DATOS, MODELOS, RESULTADOS):
    os.makedirs(_c, exist_ok=True)
import sys
import time

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns_comun as C  # noqa: E402

# Mismos parametros que entrenar_dns.py, para que el examen sea identico
CARPETA = os.path.join(DATOS, "dns")
N_TRANCO, N_ALEXA, CAP_DGA_FAMILIA = 100_000, 40_000, 2_400
TEST_FRAC, SEMILLA, N_FAMILIAS_FUERA = 0.20, 42, 5
N_TRANCO_COLA = 20_000                 # muestra de Tranco 100.001-1.000.000 para falsas alarmas


def leer_lineas(ruta):
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def construir_dataset():
    """Copia de entrenar_dns.construir_dataset (sin trafico real ni listas propias)."""
    partes = []

    def agregar(dominios, label, grupo, familia=""):
        regs = [C.registrable(d) for d in dominios]
        df = pd.DataFrame({"dominio": regs, "label": label, "grupo": grupo, "familia": familia})
        partes.append(df.dropna(subset=["dominio"]).drop_duplicates("dominio"))

    t = pd.read_csv(os.path.join(CARPETA, "tranco.csv"), names=["rank", "dominio"]).head(N_TRANCO)
    agregar(t.dominio, 0, "benigno_tranco")
    d = pd.read_csv(os.path.join(CARPETA, "dga_chrmor.csv"), header=None, names=["tipo", "familia", "dominio"]).dropna()
    legit = d[d.tipo == "legit"].sample(n=min(N_ALEXA, (d.tipo == "legit").sum()), random_state=SEMILLA)
    agregar(legit.dominio, 0, "benigno_alexa")
    dga = d[d.tipo == "dga"]
    dga = pd.concat([g.sample(n=min(len(g), CAP_DGA_FAMILIA), random_state=SEMILLA) for _, g in dga.groupby("familia")])
    df = pd.DataFrame({"dominio": [C.registrable(x) for x in dga.dominio], "label": 1, "grupo": "dga",
                       "familia": dga.familia.values})
    partes.append(df.dropna(subset=["dominio"]).drop_duplicates("dominio"))
    for nombre, grupo in (("urlhaus.txt", "urlhaus"), ("openphish.txt", "openphish")):
        agregar([l for l in leer_lineas(os.path.join(CARPETA, nombre)) if l.lower().startswith("http")], 1, grupo)
    D = pd.concat(partes, ignore_index=True).sort_values("label", kind="stable")
    return D.drop_duplicates("dominio", keep="first").reset_index(drop=True)


def asignar_split(D):
    D["split"] = "train"
    clave = D.label.astype(str) + "_" + D.grupo
    clave = clave.where(clave.map(clave.value_counts()) >= 10, D.label.astype(str) + "_otros")
    _, idx_te = train_test_split(D.index, test_size=TEST_FRAC, stratify=clave, random_state=SEMILLA)
    D.loc[idx_te, "split"] = "test"
    return D


def nuevo_lr(ngramas, max_feat, min_df):
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=ngramas, min_df=min_df,
                                  max_features=max_feat, sublinear_tf=True, dtype=np.float32)),
        ("clf", LogisticRegression(C=4.0, max_iter=600, random_state=SEMILLA)),
    ])


VARIANTES = {
    "base":  dict(solo_dga=False, ngramas=(1, 3), max_feat=60_000, min_df=5),
    "D1":    dict(solo_dga=True,  ngramas=(1, 3), max_feat=60_000, min_df=5),
    "D2":    dict(solo_dga=False, ngramas=(1, 5), max_feat=300_000, min_df=3),
    "D1+D2": dict(solo_dga=True,  ngramas=(1, 5), max_feat=300_000, min_df=3),
}


def entrenar(tr, v):
    if v["solo_dga"]:
        tr = tr[tr.grupo.isin(["dga", "benigno_tranco", "benigno_alexa"])]
    xgb = C.nuevo_xgb(SEMILLA).fit(tr[C.FEATURES], tr.label.values)
    lr = nuevo_lr(v["ngramas"], v["max_feat"], v["min_df"]).fit(list(tr.txt), tr.label.values)
    return xgb, lr


def predecir(m, df):
    xgb, lr = m
    return (xgb.predict_proba(df[C.FEATURES])[:, 1] + lr.predict_proba(list(df.txt))[:, 1]) / 2


def deteccion(y, p, fpr):
    thr = np.quantile(p[y == 0], 1 - fpr)
    return float((p[y == 1] > thr).mean()), thr


def main():
    t0 = time.time()
    print("Cargando datos (mismas fuentes y semilla que entrenar_dns.py)...")
    D = asignar_split(construir_dataset())
    D = pd.concat([D, C.a_features(D.dominio)], axis=1)
    D["txt"] = C.textos(D.dominio)
    TR, TE = D[D.split == "train"], D[D.split == "test"]
    ex = TE[TE.grupo.isin(["dga", "benigno_tranco", "benigno_alexa"])]          # examen DGA vs normales
    print(f"train={len(TR)}  examen DGA vs normales={len(ex)} ({int(ex.label.sum())} DGA)")

    # normales poco populares que nadie vio: Tranco 100.001 - 1.000.000
    t = pd.read_csv(os.path.join(CARPETA, "tranco.csv"), names=["rank", "dominio"])
    vistos = set(D.dominio)
    cola = [r for r in (C.registrable(x) for x in t.dominio.iloc[N_TRANCO:]) if r and r not in vistos]
    cola = sorted(set(cola))
    cola = pd.Series(cola).sample(n=min(N_TRANCO_COLA, len(cola)), random_state=SEMILLA).tolist()
    COLA = pd.concat([pd.DataFrame({"dominio": cola}), C.a_features(cola)], axis=1)
    COLA["txt"] = C.textos(cola)

    fuera = [str(f) for f in np.random.default_rng(SEMILLA).choice(
        sorted(D[D.grupo == "dga"].familia.unique()), N_FAMILIAS_FUERA, replace=False)]
    normales_te = TE[TE.label == 0]

    filas, por_familia = [], {}
    for nombre, v in VARIANTES.items():
        m = entrenar(TR, v)
        y, p = ex.label.values, predecir(m, ex)
        d05, thr05 = deteccion(y, p, 0.005)
        d005, thr005 = deteccion(y, p, 0.0005)
        pu = predecir(m, TE[TE.grupo == "urlhaus"])
        pp = predecir(m, TE[TE.grupo == "openphish"])
        pc = predecir(m, COLA)
        # familias nunca vistas (se reentrena sin ellas)
        mf = entrenar(TR[~TR.familia.isin(fuera)], v)
        te_f = pd.concat([D[D.familia.isin(fuera)], normales_te])
        pf = predecir(mf, te_f)
        thr_f = np.quantile(pf[te_f.label.values == 0], 1 - 0.005)
        por_familia[nombre] = {f: float((pf[(te_f.familia == f).values] > thr_f).mean()) for f in fuera}
        filas.append({
            "variante": nombre, "AUC": roc_auc_score(y, p),
            "DGA_al_0,5%FP": d05, "DGA_al_0,05%FP": d005,
            "URLhaus_det": float((pu > thr05).mean()), "OpenPhish_det": float((pp > thr05).mean()),
            "FP_Tranco_cola_0,5%": float((pc > thr05).mean()), "FP_Tranco_cola_0,05%": float((pc > thr005).mean()),
            "AUC_familias_nuevas": roc_auc_score(te_f.label.values, pf),
        })
        print(f"  {nombre:6} listo ({time.time() - t0:.0f} s)", flush=True)

    tab = pd.DataFrame(filas).set_index("variante")
    pct = [c for c in tab.columns if not c.startswith("AUC")]
    print("\n" + "=" * 100)
    print("RESULTADOS (umbrales fijados con los normales del examen; URLhaus/OpenPhish/Tranco-cola al umbral 0,5 %)")
    print("=" * 100)
    salida = tab.copy()
    salida[pct] = (salida[pct] * 100).round(2)
    salida[[c for c in tab.columns if c.startswith("AUC")]] = tab[[c for c in tab.columns if c.startswith("AUC")]].round(4)
    print(salida.to_string())
    print(f"\nTranco-cola = {len(COLA)} sitios normales de los puestos 100.001-1.000.000 (no vistos al entrenar):")
    print("su % marcado es la tasa de falsas alarmas fuera de la muestra de entrenamiento.")
    print(f"\nDeteccion de familias DGA nunca vistas al 0,5 % de falsas alarmas ({', '.join(fuera)}):")
    print((pd.DataFrame(por_familia) * 100).round(1).to_string())
    print(f"\nTiempo total: {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
