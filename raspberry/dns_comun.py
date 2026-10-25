"""
dns_comun.py - Codigo COMPARTIDO del detector DNS v2.

Entrenamiento (entrenar_dns_v2.py) y uso (probar_dns_v2.py) importan ESTE mismo archivo,
asi el dominio se transforma exactamente igual en ambos lados. El desajuste entre como se
preparaban los datos al entrenar y como llegaban en la red real fue lo que hizo fallar la v1.

Idea central: el modelo juzga el DOMINIO REGISTRABLE (nombre + sufijo publico), no el host
completo. cache4-eze1.steamcontent.com -> steamcontent.com ; www.bbc.co.uk -> bbc.co.uk
Asi normales y maliciosos se ven en el mismo formato y desaparece el atajo "tiene subdominios".

Requisitos: pip install tldextract scikit-learn xgboost pandas numpy joblib
"""
import math
from collections import Counter

import numpy as np
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

# Lista de sufijos publicos incluida en el paquete: no necesita internet.
_EXT = tldextract.TLDExtract(suffix_list_urls=())


# ------------------------------ dominio registrable ------------------------------
def limpiar_host(h):
    """Acepta host o URL ('http://a.b.com:8080/x?y') y devuelve el host en minusculas."""
    h = str(h).strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if h.startswith("["):          # IPv6 literal
        return None
    h = h.split(":", 1)[0].strip(".")
    return h or None


def registrable(host):
    """'cache4.steamcontent.com' -> 'steamcontent.com'. None si es IP, local o invalido."""
    h = limpiar_host(host)
    if not h or "." not in h or len(h) > 253:
        return None
    r = _EXT(h)
    if not r.domain or not r.suffix or r.suffix.endswith("arpa"):   # IPs, locales y DNS inverso
        return None
    return f"{r.domain}.{r.suffix}"


# ----------------------------------- features -----------------------------------
FEATURES = ["len_sld", "ent_sld", "ratio_vocales", "ratio_digitos", "n_guiones",
            "racha_cons", "racha_dig", "unicos", "transiciones", "frac_max",
            "ratio_hex", "suffix_len", "n_suffix", "empieza_digito", "es_xn"]


def _feat(reg):
    sld, _, suf = reg.partition(".")
    n = max(len(sld), 1)
    cnt = Counter(sld)
    letras = [c for c in sld if c.isalpha()]
    vocales = sum(c in "aeiou" for c in letras)
    rc = mc = rd = md = 0
    for c in sld:
        if c.isalpha() and c not in "aeiou":
            rc += 1
            mc = max(mc, rc)
        else:
            rc = 0
        if c.isdigit():
            rd += 1
            md = max(md, rd)
        else:
            rd = 0
    trans = sum(1 for a, b in zip(sld, sld[1:])
                if (a.isalpha() and b.isdigit()) or (a.isdigit() and b.isalpha()))
    ent = -sum(v / n * math.log2(v / n) for v in cnt.values())
    return [len(sld), ent, vocales / max(len(letras), 1),
            sum(c.isdigit() for c in sld) / n, sld.count("-"),
            mc, md, len(cnt) / n, trans / n, max(cnt.values()) / n if cnt else 0.0,
            sum(c in "0123456789abcdef" for c in sld) / n,
            len(suf), suf.count(".") + 1,
            float(sld[:1].isdigit()), float(sld.startswith("xn--"))]


def a_features(regs):
    return pd.DataFrame([_feat(r) for r in regs], columns=FEATURES, dtype="float32")


def textos(regs):
    """Texto para el modelo de n-gramas de caracteres (con marcas de inicio y fin)."""
    return ["^" + r.partition(".")[0] + "$" for r in regs]


# ------------------------------------ modelos ------------------------------------
def nuevo_xgb(semilla=42):
    return XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08, subsample=0.8,
        colsample_bytree=0.8, tree_method="hist", eval_metric="logloss",
        n_jobs=-1, random_state=semilla)


def nuevo_lr(semilla=42):
    # Mejora D2 (oct-2026, ver experimentos_dns.py): n-gramas de 1 a 5 letras y mas vocabulario.
    # Antes: ngram_range=(1, 3), min_df=5, max_features=60000.
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(1, 5), min_df=3,
                                  max_features=300000, sublinear_tf=True, dtype=np.float32)),
        ("clf", LogisticRegression(C=4.0, max_iter=600, random_state=semilla)),
    ])


def entrenar_modelos(X, txt, y, semilla=42):
    """Dos modelos distintos: XGBoost sobre features + regresion logistica sobre n-gramas."""
    return {"xgb": nuevo_xgb(semilla).fit(X, y), "lr": nuevo_lr(semilla).fit(list(txt), y)}


def predecir_modelos(m, X, txt):
    p1 = m["xgb"].predict_proba(X)[:, 1]
    p2 = m["lr"].predict_proba(list(txt))[:, 1]
    return p1, p2, (p1 + p2) / 2          # el ensamble promedia ambos


# ------------------------------- uso en produccion -------------------------------
def detectar(m, hosts):
    """m = dict cargado de modelo_dns_v2.pkl. Devuelve host, dominio, prob y accion."""
    hosts = list(hosts)
    regs = [registrable(h) for h in hosts]
    unicos = sorted({r for r in regs if r})
    prob = {}
    if unicos:
        _, _, p = predecir_modelos(m, a_features(unicos), textos(unicos))
        prob = dict(zip(unicos, p))
    filas = []
    for h, r in zip(hosts, regs):
        if r is None:
            filas.append((h, None, np.nan, "ignorado"))
            continue
        p = float(prob[r])
        if r in m["allowlist"]:
            acc = "permitido (allowlist)"
        elif p > m["umbral_bloqueo"]:
            acc = "BLOQUEO"
        elif p > m["umbral_alerta"]:
            acc = "ALERTA"
        else:
            acc = "ok"
        filas.append((h, r, p, acc))
    return pd.DataFrame(filas, columns=["host", "dominio", "prob", "accion"])