#!/usr/bin/env python3
"""
Motor de respuesta del IDS/IPS doméstico.

Dos acciones:
  1. cortar_flujo(): corta una conexión TCP en curso enviando paquetes de
     reinicio (TCP RST) a los dos extremos. No necesita estar "en medio":
     basta con conocer los números de secuencia, que salen de la copia del tráfico.
  2. bloquear_en_router(): le pide al router (por SSH) que bloquee una IP
     durante unos minutos. Simula la "interfaz de administración del router"
     que menciona el artículo.
"""
import subprocess

from scapy.all import IP, TCP, Ether, sendp

ROUTER_IP = "192.168.50.1"
ROUTER_USUARIO = "root"
MINUTOS_BLOQUEO = 10
IPS_PROTEGIDAS = {"192.168.50.1", "192.168.50.2"}   # nunca se bloquean (router y pi)


def cortar_flujo(clave: tuple, f: dict, interfaz: str) -> bool:
    """Envía TCP RST a ambos extremos de un flujo TCP. Devuelve True si pudo."""
    a, pa, b, pb, proto = clave
    seq_a = f.get("seq_ida", f.get("ack_vuelta"))      # próxima secuencia de A
    seq_b = f.get("seq_vuelta", f.get("ack_ida"))      # próxima secuencia de B
    if proto != "TCP" or "mac_a" not in f or seq_a is None:
        return False
    # Hacia B, haciéndose pasar por A (con el siguiente número de secuencia de A)
    rst_a_b = Ether(src=f["mac_a"], dst=f["mac_b"]) / IP(src=a, dst=b) / \
        TCP(sport=pa, dport=pb, flags="R", seq=seq_a)
    paquetes = [rst_a_b]
    # Hacia A, haciéndose pasar por B
    if seq_b is not None:
        paquetes.append(Ether(src=f["mac_b"], dst=f["mac_a"]) / IP(src=b, dst=a) /
                        TCP(sport=pb, dport=pa, flags="R", seq=seq_b))
    for _ in range(3):              # se repite por si el otro extremo avanzó la secuencia
        sendp(paquetes, iface=interfaz, verbose=False)
    return True


def bloquear_en_router(ip: str, minutos: int = MINUTOS_BLOQUEO) -> bool:
    """Agrega la IP al conjunto 'bloqueados' del router durante X minutos."""
    if ip in IPS_PROTEGIDAS:
        return False
    comando = f"nft add element inet ids bloqueados {{ {ip} timeout {minutos}m }}"
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
             f"{ROUTER_USUARIO}@{ROUTER_IP}", comando],
            capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            print(f"   (el router no aceptó el bloqueo: {r.stderr.strip()})")
        return r.returncode == 0
    except Exception as e:
        print(f"   (no se pudo conectar al router: {e})")
        return False
