# Router (VM `router` del laboratorio)

Lo que se instala en el router. La Raspberry no reemplaza al router: el router sigue dando Internet y DHCP,
y solo recibe órdenes de bloqueo desde la Raspberry.

| Archivo | Qué hace |
|---|---|
| `router_ids.nft` | Crea en nftables la tabla `inet ids` con el conjunto `bloqueados`. Las IPs que la Raspberry mande bloquear se quedan sin acceso durante el tiempo indicado y luego se liberan solas. |

La orden de bloqueo la envía `../raspberry/respuesta.py` (función `bloquear_en_router()`) por SSH:

```bash
nft add element inet ids bloqueados { 192.168.50.X timeout 10m }
```

## Instalación en el router

1. Agrega el contenido de `router_ids.nft` **al final** de `/etc/nftables.conf` y recarga:

   ```bash
   sudo sh -c 'cat router_ids.nft >> /etc/nftables.conf'
   sudo nft -f /etc/nftables.conf
   sudo nft list set inet ids bloqueados      # debe mostrar el conjunto vacío
   ```

2. Permite que la Raspberry entre por SSH **con llave** (sin contraseña), porque `respuesta.py` usa
   `ssh -o BatchMode=yes root@192.168.50.1`. En la **Raspberry**:

   ```bash
   ssh-keygen -t ed25519            # si todavía no tiene llave
   ssh-copy-id root@192.168.50.1
   ssh -o BatchMode=yes root@192.168.50.1 'nft list set inet ids bloqueados'
   ```

   Si prefieres no usar `root`, crea un usuario con permiso solo para `nft` y cambia `ROUTER_USUARIO`
   en `respuesta.py`.

3. Prueba manual (bloquea una IP del laboratorio 1 minuto):

   ```bash
   sudo nft add element inet ids bloqueados { 192.168.50.50 timeout 1m }
   sudo nft list set inet ids bloqueados
   ```

`respuesta.py` nunca bloquea al router (192.168.50.1) ni a la Raspberry (192.168.50.2).

## Configuración de referencia del laboratorio (VirtualBox)

- Red interna `redcasa`: `192.168.50.0/24`.
- `enp0s3` en NAT (salida a Internet) y `enp0s8` con `192.168.50.1`.
- `ip_forward` activado y *masquerade* con nftables para que los clientes salgan a Internet.
- DHCP con dnsmasq, sin servidor DNS propio (`port=0`) y entregando como DNS a la Raspberry (`192.168.50.2`),
  para que todas las consultas pasen por el sumidero.

En una casa real, el equivalente es configurar en el router del proveedor el DNS que entrega por DHCP
(la IP de la Raspberry) y, si el router lo permite, el puerto espejo para el módulo de flujos.
