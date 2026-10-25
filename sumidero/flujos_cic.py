#!/usr/bin/env python3
"""
Módulo de flujos – versión 2 (con la IA de Lukas).

Qué hace:
  1. Escucha el tráfico de la red (o lee un archivo .pcap).
  2. Arma los flujos con CICFlowMeter, la MISMA familia de herramienta con la
     que se hizo el dataset CIC-IDS2017, así salen las 78 columnas que pide
     el modelo de Lukas.
  3. Le pasa cada flujo al modelo XGBoost (modelo_netflow_xgb.pkl) y este
     dice: normal, DoS_DDoS, PortScan, FuerzaBruta, Botnet o WebAttack.
  4. Muestra una ALERTA si no es normal y guarda todo en flujos_cic.csv.

Uso (en la VM pi):
  sudo venv/bin/python flujos_cic.py --interfaz enp0s8          # en vivo
  venv/bin/python flujos_cic.py --pcap captura.pcap              # desde archivo

Dos arreglos que hace este script (comprobados con pruebas):
  - CICFlowMeter en Python (v0.5.0) contaba el primer paquete de cada flujo
    dos veces. Se corrige abajo.
  - CICFlowMeter en Python da los tiempos en SEGUNDOS, pero el dataset
    CIC-IDS2017 (con el que Lukas entrenó) está en MICROSEGUNDOS.
    Se multiplican por 1 000 000 antes de pasarlos al modelo.
"""
import argparse
import csv
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import cicflowmeter.flow as cic_flow
from cicflowmeter.flow_session import FlowSession

CARPETA = Path(__file__).parent
MODELO_POR_DEFECTO = CARPETA / "modelos" / "modelo_netflow_xgb.pkl"
SALIDA = CARPETA / "flujos_cic.csv"

# --- Arreglo 1: el primer paquete se contaba dos veces -----------------------
_init_original = cic_flow.Flow.__init__


def _init_corregido(self, paquete, direccion):
    _init_original(self, paquete, direccion)
    self.packets = []  # add_packet() lo vuelve a agregar justo después


cic_flow.Flow.__init__ = _init_corregido

# --- Nombre en el modelo de Lukas (CIC-IDS2017)  ->  nombre en CICFlowMeter ---
MAPA = {
    "Destination Port": "dst_port", "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts", "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts", "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max", "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean", "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max", "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean", "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_byts_s", "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean", "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max", "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot", "Fwd IAT Mean": "fwd_iat_mean", "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max", "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_tot", "Bwd IAT Mean": "bwd_iat_mean", "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max", "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags", "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags", "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Length": "fwd_header_len", "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s", "Bwd Packets/s": "bwd_pkts_s",
    "Min Packet Length": "pkt_len_min", "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean", "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "FIN Flag Count": "fin_flag_cnt", "SYN Flag Count": "syn_flag_cnt", "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt", "ACK Flag Count": "ack_flag_cnt", "URG Flag Count": "urg_flag_cnt",
    "CWE Flag Count": "cwr_flag_count",  # en el dataset original se llama mal "CWE"; es CWR
    "ECE Flag Count": "ece_flag_cnt", "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",
    "Avg Fwd Segment Size": "fwd_seg_size_avg", "Avg Bwd Segment Size": "bwd_seg_size_avg",
    "Fwd Header Length.1": "fwd_header_len",  # columna repetida en el dataset original
    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg", "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg", "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts", "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Packets": "subflow_bwd_pkts", "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts", "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts", "min_seg_size_forward": "fwd_seg_size_min",
    "Active Mean": "active_mean", "Active Std": "active_std",
    "Active Max": "active_max", "Active Min": "active_min",
    "Idle Mean": "idle_mean", "Idle Std": "idle_std", "Idle Max": "idle_max", "Idle Min": "idle_min",
}

# --- Arreglo 2: columnas de tiempo, de segundos a microsegundos ---------------
COLUMNAS_TIEMPO = [c for c in MAPA if c.startswith(
    ("Flow Duration", "Flow IAT", "Fwd IAT", "Bwd IAT", "Active", "Idle"))]

COLUMNAS_CSV = ["fecha_hora", "ip_origen", "puerto_origen", "ip_destino", "puerto_destino",
                "protocolo", "paquetes_ida", "paquetes_vuelta", "duracion_s",
                "prediccion", "confianza"]


class Clasificador:
    """Recibe cada flujo terminado, lo pasa por la IA, muestra y guarda."""

    def __init__(self, ruta_modelo, salida):
        paquete = joblib.load(ruta_modelo)
        self.modelo = paquete["modelo"]
        self.columnas = paquete["columnas"]
        self.clases = np.array([str(c) for c in paquete["clases"]])
        faltan = [c for c in self.columnas if c not in MAPA]
        if faltan:
            raise SystemExit(f"El modelo pide columnas que no sé calcular: {faltan}")
        self.salida = salida
        if not salida.exists():
            with open(salida, "w", newline="") as f:
                csv.writer(f).writerow(COLUMNAS_CSV)
        print(f"IA cargada: {len(self.columnas)} columnas, clases = {list(self.clases)}")

    def write(self, flujo: dict):  # CICFlowMeter llama a write() por cada flujo
        fila = {c: flujo.get(MAPA[c], 0) for c in self.columnas}
        X = pd.DataFrame([fila]).apply(pd.to_numeric, errors="coerce")
        X = X.replace([np.inf, -np.inf], 0).fillna(0)
        X[COLUMNAS_TIEMPO] = X[COLUMNAS_TIEMPO] * 1_000_000

        prob = self.modelo.predict_proba(X)[0]
        clase = self.clases[prob.argmax()]
        confianza = float(prob.max())

        datos = [datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 flujo["src_ip"], flujo["src_port"], flujo["dst_ip"], flujo["dst_port"],
                 {6: "TCP", 17: "UDP"}.get(flujo["protocol"], flujo["protocol"]),
                 flujo["tot_fwd_pkts"], flujo["tot_bwd_pkts"],
                 round(float(flujo["flow_duration"]), 3), clase, round(confianza, 2)]
        with open(self.salida, "a", newline="") as f:
            csv.writer(f).writerow(datos)

        texto = (f"{datos[1]}:{datos[2]} -> {datos[3]}:{datos[4]} {datos[5]} "
                 f"pk={datos[6]}/{datos[7]} -> {clase} ({confianza:.0%})")
        print(("🚨 ALERTA  " if clase != "normal" else "   ok     ") + texto)


def main():
    p = argparse.ArgumentParser(description="Flujos + IA de Lukas (CIC-IDS2017)")
    origen = p.add_mutually_exclusive_group(required=True)
    origen.add_argument("--interfaz", help="ej. enp0s8 (captura en vivo, requiere sudo)")
    origen.add_argument("--pcap", help="archivo .pcap para probar sin red")
    p.add_argument("--modelo", default=str(MODELO_POR_DEFECTO))
    args = p.parse_args()

    clasificador = Clasificador(args.modelo, SALIDA)
    sesion = FlowSession(output_mode="csv", output="/dev/null")
    sesion.output_writer = clasificador  # en vez de escribir el CSV de CIC, clasificamos

    if args.pcap:
        from scapy.all import PcapReader
        with PcapReader(args.pcap) as lector:
            for paquete in lector:
                sesion.process(paquete)
        sesion.flush_flows()
        return

    from scapy.all import AsyncSniffer
    print(f"Escuchando en {args.interfaz}... (Ctrl+C para parar)")
    sniffer = AsyncSniffer(iface=args.interfaz, prn=sesion.process, store=False,
                           filter="ip and (tcp or udp)", promisc=True)
    sniffer.start()
    try:
        while True:
            time.sleep(5)
            sesion.garbage_collect(time.time())  # saca los flujos que ya terminaron
    except KeyboardInterrupt:
        sniffer.stop()
        sesion.flush_flows()
        print("\nListo. Resultados en", SALIDA.name)


if __name__ == "__main__":
    main()
