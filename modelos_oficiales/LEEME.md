# Modelos oficiales

Los dos modelos de machine learning que usa el sistema, uno por módulo.

| Archivo | Módulo | Qué hace | Resultado (ver `../entrenamiento/resultados/`) |
|---|---|---|---|
| `modelo_dns_v2.pkl` | DNS | Mira el **nombre del dominio** y detecta dominios generados por malware (DGA). Ensamble de XGBoost (15 características del nombre) y regresión logística (n-gramas de 1 a 5 letras) sobre el dominio registrable. Versión `dns_v2_d1d2` (25/10/2026). | Detecta el **74,3 %** de los DGA con **0,44 %** de falsas alarmas (umbral ALERTA) y el 45,9 % con 0,04 % (umbral BLOQUEO). AUC 0,981 (DGA vs normales). |
| `modelo_netflow_combinado_xgb.pkl` | Flujos | Mira los **metadatos de cada conexión** y la clasifica en 6 clases: normal, DoS_DDoS, FuerzaBruta, PortScan, Botnet y WebAttack. XGBoost con 72 columnas estilo CICFlowMeter, sin `Destination Port` (experimento B). Entrenado con CIC-IDS2017 + CSE-CIC-IDS2018. | F1 macro **0,80** dentro de los datasets. Entre datasets distintos baja a 0,19–0,25: hay que validarlo en el laboratorio. |

## Qué contiene cada archivo

Cada `.pkl` es un diccionario que se abre con `joblib.load()`:

- `modelo_dns_v2.pkl`: `xgb`, `lr`, `umbral_alerta` (0,589), `umbral_bloqueo` (0,909), `allowlist`
  (los 20 000 dominios más populares de Tranco), `features`, `version`. Para usarlo hace falta `dns_comun.py`
  (está en `../raspberry/` y en `../entrenamiento/2_dns/`, es el mismo archivo): `dns_comun.detectar(modelo, hosts)`.
- `modelo_netflow_combinado_xgb.pkl`: `modelo`, `columnas` (las 72 que espera, en orden), `clases`, `dataset`.

## Versiones necesarias

Solo abren con las mismas versiones con que se guardaron: **`scikit-learn==1.9.1`** y **`xgboost==3.4.1`**
(en la Raspberry, `xgboost-cpu==3.4.1`). Ya están fijadas en los `requirements.txt`.

Abre únicamente `.pkl` de este repositorio: un `.pkl` de origen desconocido puede ejecutar código al cargarse.

## Lo que el modelo DNS NO detecta

Por el nombre del dominio no se distingue el phishing (7,7 %) ni el malware (1,6 %): esos dominios imitan a los
normales. Eso lo cubren las listas de bloqueo y el DNS protector (`dns_sumidero.py --superior 1.1.1.2`), que en
nuestra medición bloqueó el 80,1 % del phishing activo de OpenPhish.
