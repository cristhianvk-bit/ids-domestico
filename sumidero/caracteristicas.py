"""
Características léxicas de un nombre de dominio.

Este archivo lo usan DOS lados y debe ser idéntico en ambos:
  - el notebook de Colab (para entrenar el modelo)
  - dns_sumidero.py en la pi (para clasificar en tiempo real)
Si cambias algo aquí, hay que volver a entrenar el modelo.
"""
import math
from collections import Counter

# Sufijos de dos partes comunes (para encontrar el "nombre principal" del dominio)
SUFIJOS_DOBLES = {
    "com.bo", "gob.bo", "edu.bo", "org.bo", "net.bo", "int.bo", "mil.bo", "tv.bo",
    "com.ar", "gob.ar", "com.br", "gov.br", "com.mx", "gob.mx", "com.pe", "gob.pe",
    "com.co", "gov.co", "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "co.in",
    "com.cn", "com.es", "co.za", "com.tr", "co.kr",
}
# Dominios de nivel superior baratos o gratuitos muy usados en abuso
TLD_RIESGOSOS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "buzz", "click", "link", "work",
    "rest", "fit", "cam", "loan", "zip", "mov", "support", "live", "online", "site", "shop",
}
# Palabras señuelo típicas de phishing (inglés y español)
SENUELOS = (
    "login", "logon", "signin", "verify", "verif", "secure", "security", "account", "update",
    "confirm", "billing", "wallet", "support", "password", "bank", "paypal", "apple", "icloud",
    "microsoft", "office", "outlook", "netflix", "amazon", "facebook", "instagram", "whatsapp",
    "banco", "cuenta", "clave", "verifica", "seguridad", "acceso", "pago", "tarjeta",
)
VOCALES = set("aeiou")

COLUMNAS = [
    "largo_total", "largo_principal", "num_etiquetas", "largo_subdominio",
    "prop_digitos", "num_guiones", "entropia", "prop_vocales", "max_consonantes",
    "prop_unicos", "tld_riesgoso", "tiene_senuelo", "prop_hex", "cambios_letra_digito",
]


def partir(dominio: str):
    """Devuelve (subdominio, nombre_principal, tld)."""
    d = dominio.lower().strip(".")
    if d.startswith("www."):
        d = d[4:]
    etiquetas = d.split(".")
    if len(etiquetas) >= 3 and ".".join(etiquetas[-2:]) in SUFIJOS_DOBLES:
        tld = ".".join(etiquetas[-2:])
        principal = etiquetas[-3]
        sub = ".".join(etiquetas[:-3])
    elif len(etiquetas) >= 2:
        tld = etiquetas[-1]
        principal = etiquetas[-2]
        sub = ".".join(etiquetas[:-2])
    else:
        tld, principal, sub = "", d, ""
    return sub, principal, tld


def entropia(texto: str) -> float:
    if not texto:
        return 0.0
    n = len(texto)
    return -sum(c / n * math.log2(c / n) for c in Counter(texto).values())


def extraer(dominio: str) -> list:
    """Convierte un dominio en una lista de números (en el orden de COLUMNAS)."""
    d = dominio.lower().strip(".")
    sub, principal, tld = partir(d)
    letras = [c for c in principal if c.isalpha()]
    max_cons = actual = 0
    for c in principal:
        if c.isalpha() and c not in VOCALES:
            actual += 1
            max_cons = max(max_cons, actual)
        else:
            actual = 0
    cambios = sum(1 for a, b in zip(principal, principal[1:]) if a.isdigit() != b.isdigit())
    n = max(len(principal), 1)
    return [
        len(d),
        len(principal),
        d.count(".") + 1,
        len(sub),
        sum(c.isdigit() for c in principal) / n,
        d.count("-"),
        entropia(principal),
        sum(c in VOCALES for c in letras) / max(len(letras), 1),
        max_cons,
        len(set(principal)) / n,
        int(tld.split(".")[-1] in TLD_RIESGOSOS),
        int(any(s in d for s in SENUELOS)),
        sum(c in "0123456789abcdef" for c in principal) / n,
        cambios,
    ]
