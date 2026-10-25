# Raspberry Pi (o VM `pi` del laboratorio)

Todo lo que se instala en la Raspberry Pi.

| Archivo | Qué hace |
|---|---|
| `dns_sumidero.py` | Sumidero DNS: lista blanca → listas de bloqueo (StevenBlack + `bloqueados.txt`) → clasificador de IA → reenvío al DNS superior (`--superior`). Registra cada consulta en `consultas.csv`. |
| `bloqueados.txt`, `permitidos.txt` | Listas propias (un dominio por línea). |
| `dns_comun.py` | Preparación del dominio para el modelo DNS v2 (dominio registrable, características y n-gramas). Debe ser **idéntico** a `../entrenamiento/2_dns/dns_comun.py`. |
| `caracteristicas.py` | Características del clasificador antiguo que todavía usa `dns_sumidero.py` (se quita al conectar el modelo v2). |
| `flujos.py` | Captura de flujos con scapy (16 columnas propias) → `flujos.csv`. |
| `flujos_cic.py` | Flujos con columnas estilo CIC (cicflowmeter 0.5.0, con dos arreglos) clasificados con el modelo de flujos. |
| `respuesta.py`, `router_ids.nft` | Respuesta activa: TCP RST y bloqueo temporal de IP en el router (SSH con llave + nftables). |

## Instalación (Debian / Raspberry Pi OS)

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
mkdir -p modelos
cp ../modelos_oficiales/*.pkl modelos/
```

## Uso

```bash
sudo venv/bin/python dns_sumidero.py --puerto 53                       # reenvía a 1.1.1.1
sudo venv/bin/python dns_sumidero.py --puerto 53 --superior 1.1.1.2    # DNS protector de Cloudflare
sudo venv/bin/python flujos_cic.py --interfaz enp0s8 --modelo modelos/modelo_netflow_combinado_xgb.pkl
```

Con un DNS protector, lo que ese servidor bloquea queda registrado como `BLOQUEADO_SUPERIOR`.
En Windows el puerto 5353 está ocupado por mDNS; para pruebas usa otro, por ejemplo `--puerto 15353`.

## Pendiente

- `dns_sumidero.py` todavía busca el modelo antiguo `modelo_dominios.joblib`; si no lo encuentra funciona
  solo con listas. Falta conectarlo a `modelo_dns_v2.pkl` (con `dns_comun.py` y sus umbrales).
- `flujos_cic.py` usa por defecto `modelos/modelo_netflow_xgb.pkl` (el antiguo); hasta conectarlo, pásale
  el oficial con `--modelo` como en el ejemplo de arriba.
