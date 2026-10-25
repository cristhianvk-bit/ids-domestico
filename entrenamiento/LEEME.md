# ML del IDS/IPS doméstico

Entrenamiento de los dos modelos del proyecto:

- **NetFlow:** XGBoost que clasifica flujos de red.
- **DNS:** XGBoost + regresión logística que detecta dominios maliciosos.

## Estructura

```
entrenamiento/
├── LEEME.md                 ← este archivo
├── requirements.txt         ← librerías a instalar
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
│   ├── experimentos_dns.py  ← compara mejoras sin tocar el modelo (de aquí salió D1+D2)
│   ├── medir_dns_protector.py ← mide cuánto bloquean Cloudflare 1.1.1.2 y Quad9
│   └── probar_dns.py        ← prueba el modelo con dominios reales de tu PC
│
├── antiguo/                 ← notebook del primer clasificador de dominios (superado por 2_dns/)
├── resultados/              ← salidas de los entrenamientos (van al artículo)
│
├── datos/                   ← datasets (se crean al descargar; NO se suben a GitHub)
└── modelos/                 ← aquí guardan los scripts los .pkl nuevos (NO se suben)
```

Los modelos que usa el sistema están en [`../modelos_oficiales/`](../modelos_oficiales/).
Si vuelves a entrenar y el modelo nuevo es mejor, cópialo de `modelos/` a `../modelos_oficiales/`.

**Modelo DNS actual (25/10/2026):** versión `dns_v2_d1d2`. Se entrena solo para DGA (URLhaus y OpenPhish
quedan solo para el examen) y usa n-gramas de 1 a 5 letras. Detecta el 74,3 % de los DGA con 0,44 % de
falsas alarmas (antes 69,5 %). Comparación completa en `resultados/salida_experimentos_dns.txt`; la salida
del modelo anterior está en `resultados/salida_dns_base_2026-10-15.txt`.

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
