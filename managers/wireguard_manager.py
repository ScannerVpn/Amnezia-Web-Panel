import logging
from .ssh_manager import SSHManager


def _parse_wg_dump(output: str) -> dict:
    result = {}
    for line in output.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub_key = parts[1]
        if not pub_key or pub_key == "(none)":
            continue
        try:
            last_seen = int(parts[5]) if parts[5] and parts[5] != "0" else None
            rx = int(parts[6]) if parts[6].isdigit() else 0
            tx = int(parts[7]) if parts[7].isdigit() else 0
            result[pub_key] = {"rx": rx, "tx": tx, "last_seen": last_seen}
        except (ValueError, IndexError):
            pass
    return result

logger = logging.getLogger(__name__)

WG_CONF = "/etc/wireguard/wg0.conf"


def _gen_keypair_on_server(ssh: SSHManager) -> tuple[str, str]:
    out, _, _ = ssh.run_sudo("wg genkey")
    priv = out.strip()
    out2, _, _ = ssh.run_sudo(f"echo '{priv}' | wg pubkey")
    pub = out2.strip()
    return priv, pub


def _gen_psk_on_server(ssh: SSHManager) -> str:
    out, _, _ = ssh.run_sudo("wg genpsk")
    return out.strip()


class WireGuardManager:
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh

    def is_installed(self) -> bool:
        _, _, code = self.ssh.run_sudo("wg show wg0 2>/dev/null")
        return code == 0

    def install(self, port: int = 51820, subnet: str = "10.8.0.0/24",
                dns: str = "1.1.1.1", progress=None) -> dict:
        def log(msg):
            if progress:
                progress(msg)

        log("Installing WireGuard packages...")
        script = f"""\
#!/bin/bash
set -e
apt-get update -qq
apt-get install -y wireguard wireguard-tools iproute2 iptables
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
mkdir -p /etc/wireguard
"""
        self.ssh.run_sudo_script(script, 300)

        log("Generating WireGuard key pair...")
        priv_key, pub_key = _gen_keypair_on_server(self.ssh)
        iface = self._detect_iface()
        network = subnet.rsplit(".", 1)[0]
        server_ip = network + ".1"

        log("Writing WireGuard configuration...")
        conf = (
            f"[Interface]\n"
            f"Address = {server_ip}/24\n"
            f"ListenPort = {port}\n"
            f"PrivateKey = {priv_key}\n"
            f"\n"
            f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
            f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n"
        )
        self.ssh.upload_sudo_file(conf, WG_CONF)

        log("Starting WireGuard service...")
        self.ssh.run_sudo("systemctl enable wg-quick@wg0 && systemctl start wg-quick@wg0")

        log(f"Opening firewall port {port}/udp...")
        self.ssh.open_port(port, "udp")

        log("WireGuard installed successfully!")
        return {
            "server_private_key": priv_key,
            "server_public_key": pub_key,
            "port": port,
            "subnet": subnet,
            "dns": dns,
        }

    def uninstall(self):
        self.ssh.run_sudo("systemctl stop wg-quick@wg0 2>/dev/null || true")
        self.ssh.run_sudo("systemctl disable wg-quick@wg0 2>/dev/null || true")
        self.ssh.run_sudo(f"rm -f {WG_CONF}")

    def add_client(self, server_pub_key: str, client_ip: str, client_name: str) -> dict:
        priv_key, pub_key = _gen_keypair_on_server(self.ssh)
        psk = _gen_psk_on_server(self.ssh)

        peer = (
            f"\n[Peer]\n"
            f"# {client_name}\n"
            f"PublicKey = {pub_key}\n"
            f"PresharedKey = {psk}\n"
            f"AllowedIPs = {client_ip}/32\n"
        )
        conf = self._read_conf()
        self._write_conf(conf + peer)
        self.ssh.run_sudo("wg addconf wg0 <(wg-quick strip /etc/wireguard/wg0.conf) 2>/dev/null || systemctl restart wg-quick@wg0")

        return {
            "private_key": priv_key,
            "public_key": pub_key,
            "preshared_key": psk,
            "ip": client_ip,
        }

    def remove_client(self, public_key: str):
        conf = self._read_conf()
        new_conf = self._remove_peer(conf, public_key)
        self._write_conf(new_conf)
        self.ssh.run_sudo(f"wg set wg0 peer {public_key} remove 2>/dev/null || true")

    def toggle_client(self, public_key: str, enabled: bool):
        conf = self._read_conf()
        if enabled:
            conf = conf.replace(f"#PublicKey = {public_key}", f"PublicKey = {public_key}")
        else:
            conf = conf.replace(f"PublicKey = {public_key}", f"#PublicKey = {public_key}")
        self._write_conf(conf)

    def get_traffic(self) -> dict:
        out, _, code = self.ssh.run_sudo("wg show all dump 2>/dev/null")
        if code != 0 or not out.strip():
            return {}
        return _parse_wg_dump(out)

    def get_live_peers(self) -> list[str]:
        out, _, _ = self.ssh.run_sudo("wg show all dump 2>/dev/null")
        return list(_parse_wg_dump(out).keys())

    def build_client_conf(self, client: dict, server: dict) -> str:
        return (
            f"[Interface]\n"
            f"PrivateKey = {client['private_key']}\n"
            f"Address = {client['ip']}/32\n"
            f"DNS = {server.get('dns', '1.1.1.1')}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {server['server_public_key']}\n"
            f"PresharedKey = {client['preshared_key']}\n"
            f"Endpoint = {server['host']}:{server['port']}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"PersistentKeepalive = 25\n"
        )

    def _detect_iface(self) -> str:
        out, _, _ = self.ssh.run_sudo("ip route | grep default | awk '{print $5}' | head -1")
        return out.strip() or "eth0"

    def _read_conf(self) -> str:
        return self.ssh.download_file(WG_CONF)

    def _write_conf(self, content: str):
        self.ssh.upload_sudo_file(content, WG_CONF)

    def _remove_peer(self, conf: str, public_key: str) -> str:
        lines = conf.split("\n")
        result = []
        in_peer = False
        skip = False
        for line in lines:
            if line.strip() == "[Peer]":
                in_peer = True
                skip = False
                peer_lines = [line]
                continue
            if in_peer:
                if line.strip().startswith("["):
                    if not skip:
                        result.extend(peer_lines)
                    in_peer = False
                    peer_lines = []
                    result.append(line)
                    continue
                peer_lines.append(line)
                if f"PublicKey = {public_key}" in line:
                    skip = True
                continue
            result.append(line)
        if in_peer and not skip:
            result.extend(peer_lines)
        return "\n".join(result)
