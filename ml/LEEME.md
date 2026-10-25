# ML del IDS/IPS doméstico

Entrenamiento de los dos modelos del proyecto:

- **NetFlow:** XGBoost que clasifica flujos de red.
- **DNS:** XGBoost + regresión logística que detecta dominios maliciosos.

## Estructura

```
ML - movil/
├── LEEME.md                 ← este archivo
├── requirements.txt         ← librerías a instalar
├── ordenar_carpetas.bat     ← se usa UNA vez para ordenar lo viejo
│
├── 1_netflow/
│   ├── descargar_2017.py    ← baja CIC-IDS2017        → datos/cic-ids2017/
│   ├── descargar_2018.py    ← baja CSE-CIC-IDS2018    → datos/cse-cic-ids2018/
│   ├── entrenar_netflow.py  ← entrena y evalúa (4 experimentos) → modelos/
│   └── evaluar_csv.py       ← clasifica un CSV exportado por CICFlowMeter
│
├── 2_dns/
│   ├── dns_comun.py         ← fórmulas compartidas (entrenar y usar = idénticas)
│   ├── descargar_dns.py     ← baja Tranco, DGA, URLhaus y OpenPhish → datos/dns/
│   ├── preparar_phiusiil.py ← (MEJORA) agrega 100 945 URLs de phishing de UCI
│   ├── entrenar_dns.py      ← entrena y evalúa → modelos/modelo_dns_v2.pkl
│   └── probar_dns.py        ← prueba el modelo con dominios reales de tu PC
│
├── datos/                   ← datasets (NO se suben a GitHub)
├── modelos/                 ← .pkl actuales (anteriores/ = versiones viejas)
├── resultados/              ← salidas de los entrenamientos (van al artículo)
└── _historial_lukas/        ← respaldo de los scripts originales, sin tocar
```

## Modelos oficiales (`modelos/`)

| Archivo | Qué hace | Resultado (ver `resultados/`) |
|---|---|---|
| `modelo_dns_v2.pkl` | Ensamble XGBoost + regresión logística sobre el dominio registrable. Umbrales: ALERTA > 0,626, BLOQUEO > 0,898. | AUC 0,963; detecta 69 % de DGA con 0,44 % de falsas alarmas |
| `modelo_netflow_combinado_xgb.pkl` | XGBoost de 6 clases (normal, DoS_DDoS, FuerzaBruta, PortScan, Botnet, WebAttack), entrenado con 2017 + 2018 sin `Destination Port` (experimento B). | F1 macro 0,80; entre datasets 0,19–0,25 |
| `modelo_netflow_2018_xgb.pkl` | Igual, pero entrenado solo con CSE-CIC-IDS2018 (para las pruebas de generalización). | F1 macro 0,80 en 2018 |

Se abren con `joblib.load()` y **solo con las mismas versiones con que se guardaron**: `scikit-learn==1.9.1` y `xgboost==3.4.1` (ya fijadas en `requirements.txt`).
Cada `.pkl` es un diccionario con el modelo, las columnas y las clases. Abre únicamente `.pkl` de este repositorio: un `.pkl` de origen desconocido puede ejecutar código al cargarse.

## Instalación (una sola vez)

1. Instala **Python 3.13** desde https://www.python.org/downloads/ y marca la casilla **"Add python.exe to PATH"**.
2. Abre esta carpeta, escribe `cmd` en la barra de dirección del Explorador y pulsa Enter.
3. Crea el entorno virtual e instala las librerías:

   ```
   py -3.13 -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

Cada vez que abras una terminal nueva, activa el entorno con `venv\Scripts\activate`. Sabrás que está activo porque aparece `(venv)` al inicio de la línea.

## Ejecución (siempre desde la carpeta principal)

| Qué | Comando | Tiempo aprox. |
|---|---|---|
| Bajar datos NetFlow | `python 1_netflow\descargar_2017.py` y `python 1_netflow\descargar_2018.py` | ya están bajados |
| Entrenar NetFlow | `python 1_netflow\entrenar_netflow.py > resultados\salida_netflow.txt` | 20–40 min |
| Bajar datos DNS | `python 2_dns\descargar_dns.py` | 1–2 min |
| Agregar PhiUSIIL | `python 2_dns\preparar_phiusiil.py` (después de bajar el zip de UCI) | 1 min |
| Entrenar DNS | `python 2_dns\entrenar_dns.py > resultados\salida_dns.txt` | 1–3 min |
| Probar DNS real | `python 2_dns\probar_dns.py --guardar` | 1 min |

## Fuentes de datos (para citar en el artículo)

| Dataset | Uso | Referencia |
|---|---|---|
| CIC-IDS2017 | NetFlow | Sharafaldin, Habibi Lashkari y Ghorbani (2018), ICISSP |
| CSE-CIC-IDS2018 | NetFlow | CSE y CIC (2018), registry.opendata.aws/cse-cic-ids2018 |
| Tranco | DNS (normales) | Le Pochat et al. (2019), NDSS |
| DGA (25 familias) | DNS (DGA) | Cucchiarelli et al. (2021), *Expert Systems with Applications*, 170, 114551 |
| URLhaus / OpenPhish | DNS (malware / phishing) | abuse.ch / OpenPhish: listas en vivo, **anotar la fecha de descarga** |
| PhiUSIIL | DNS (phishing) | Prasad y Chandra (2024), *Computers & Security*, 136, 103545 |
