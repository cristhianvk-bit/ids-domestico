# ids-domestico

Sistema IDS/IPS doméstico gestionado por app móvil: machine learning, captura pasiva y Raspberry Pi
para detectar anomalías de tráfico y prevenir el acceso a dominios maliciosos.
Sin inspección profunda de paquetes (DPI) y sin descifrar HTTPS: solo se usan nombres de dominio y metadatos de flujos.

## Carpetas

| Carpeta | Qué contiene |
|---|---|
| [`modelos_oficiales/`](modelos_oficiales/) | Los 2 modelos de ML del sistema: `modelo_dns_v2.pkl` (dominios DGA) y `modelo_netflow_combinado_xgb.pkl` (flujos). Qué detecta cada uno y cómo abrirlos: [`LEEME`](modelos_oficiales/LEEME.md). |
| [`raspberry/`](raspberry/) | Todo lo que se instala en la Raspberry Pi: sumidero DNS, captura y clasificación de flujos, respuesta activa. Instalación y uso: [`LEEME`](raspberry/LEEME.md). |
| [`router/`](router/) | Lo que se instala en el router: reglas nftables para que la Raspberry pueda bloquear IPs, y la configuración de referencia del laboratorio: [`LEEME`](router/LEEME.md). |
| [`entrenamiento/`](entrenamiento/) | Scripts para descargar los datasets, entrenar y evaluar los modelos, experimentos y resultados citados en el artículo: [`LEEME`](entrenamiento/LEEME.md). |

## Resumen de cómo protege

| Capa | Dónde | Qué atrapa |
|---|---|---|
| Listas de bloqueo (StevenBlack) | `raspberry/dns_sumidero.py` | Dominios peligrosos ya conocidos |
| DNS protector (`--superior 1.1.1.2` o `9.9.9.9`) | `raspberry/dns_sumidero.py` | Phishing y malware reportados (Cloudflare 1.1.1.2 bloqueó el 80,1 % del phishing activo de OpenPhish) |
| Modelo DNS | `modelos_oficiales/modelo_dns_v2.pkl` | Dominios generados por malware (DGA): 74,3 % con 0,44 % de falsas alarmas |
| Modelo de flujos | `modelos_oficiales/modelo_netflow_combinado_xgb.pkl` | DoS, fuerza bruta, escaneo, botnet y ataques web por metadatos de conexión |

Los datasets no se suben: se descargan con los scripts de `entrenamiento/`.
La primera versión del código de ML la hizo Lukas (repo `sassan225/Machine-Learning-IDS-IPS`).
