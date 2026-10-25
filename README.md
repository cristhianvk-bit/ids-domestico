# ids-domestico

Sistema IDS/IPS doméstico gestionado por app móvil: machine learning, captura pasiva y Raspberry Pi
para detectar anomalías de tráfico y prevenir el acceso a dominios maliciosos.
Sin inspección profunda de paquetes (DPI) y sin descifrar HTTPS: solo se usan nombres de dominio y metadatos de flujos.

## Carpetas

| Carpeta | Qué contiene |
|---|---|
| [`sumidero/`](sumidero/) | Lo que corre en la Raspberry Pi (o en la VM `pi` del laboratorio): sumidero DNS, captura de flujos y respuesta activa. |
| [`ml/`](ml/) | Entrenamiento y evaluación de los modelos de machine learning (dominios DNS y flujos tipo NetFlow), más la medición de DNS protectores. Ver [`ml/LEEME.md`](ml/LEEME.md). |

### `sumidero/`

| Archivo | Qué hace |
|---|---|
| `dns_sumidero.py` | Sumidero DNS: lista blanca → listas de bloqueo (StevenBlack + `bloqueados.txt`) → clasificador de IA → reenvío al DNS superior. Registra cada consulta en `consultas.csv`. |
| `caracteristicas.py`, `entrenar_modelo_dominios.ipynb` | Versión temprana del clasificador de dominios que usa hoy el sumidero (el modelo v2 está en `ml/2_dns/`). |
| `flujos.py` | Captura de flujos con scapy → `flujos.csv`. |
| `flujos_cic.py` | Flujos con columnas estilo CIC (cicflowmeter) clasificados con el modelo XGBoost de `ml/1_netflow/`. |
| `respuesta.py`, `router_ids.nft` | Respuesta activa: TCP RST y bloqueo temporal de IP en el router (SSH + nftables). |

Uso (desde la carpeta `sumidero/`):

```bash
sudo venv/bin/python dns_sumidero.py --puerto 53                       # reenvía a 1.1.1.1
sudo venv/bin/python dns_sumidero.py --puerto 53 --superior 1.1.1.2    # DNS protector de Cloudflare
sudo venv/bin/python dns_sumidero.py --puerto 53 --superior 9.9.9.9    # Quad9
```

Con un DNS protector, lo que ese servidor bloquea queda registrado como `BLOQUEADO_SUPERIOR`.

### `ml/`

- `1_netflow/`: descarga de CIC-IDS2017 y CSE-CIC-IDS2018, entrenamiento y evaluación del clasificador de flujos.
- `2_dns/`: detector de dominios v2 (ensamble XGBoost + regresión logística sobre el dominio registrable)
  y `medir_dns_protector.py` (cuánto bloquean Cloudflare 1.1.1.2 y Quad9).
- `resultados/`: salidas de los experimentos citadas en el artículo.

Los datasets y los modelos entrenados (`.pkl`) no se suben: se regeneran con los scripts.
La primera versión del código de ML la hizo Lukas (repo `sassan225/Machine-Learning-IDS-IPS`).
