import logging
import shlex
from .ssh_manager import SSHManager
from utils import parse_wg_dump

logger = logging.getLogger(__name__)

WG_CONF = "/etc/wireguard/wg0.conf"


def _gen_keypair_locally() -> tuple[str, str]:
    """Generate WireGuard keypair locally using cryptography library — same
    approach as AWG. Avoids leaking private key through server shell."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return (
        base64.b64encode(priv_bytes).decode(),
        base64.b64encode(pub_bytes).decode(),
    )


def _gen_psk_locally() -> str:
    import base64, secrets
    return base64.b64encode(secrets.token_bytes(32)).decode()


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
        script = """\
#!/bin/bash
set -e
apt-get update -qq
apt-get install -y wireguard wireguard-tools iproute2 iptables
sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || \\
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
mkdir -p /etc/wireguard
"""
        self.ssh.run_sudo_script(script, 300)

        log("Generating WireGuard key pair locally (not on server)...")
        priv_key, pub_key = _gen_keypair_locally()
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
            f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; "
            f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
            f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n"
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
        priv_key, pub_key = _gen_keypair_locally()
        psk = _gen_psk_locally()

        peer = (
            f"\n[Peer]\n"
            f"# {client_name}\n"
            f"PublicKey = {pub_key}\n"
            f"PresharedKey = {psk}\n"
            f"AllowedIPs = {client_ip}/32\n"
        )
        conf = self._read_conf()
        self._write_conf(conf + peer)
        self.ssh.run_sudo(
            "wg addconf wg0 <(wg-quick strip /etc/wireguard/wg0.conf) 2>/dev/null || "
            "systemctl restart wg-quick@wg0"
        )

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
        # Remove from live interface (safe — quoted)
        self.ssh.run_sudo(
            f"wg set wg0 peer {shlex.quote(public_key)} remove 2>/dev/null || true"
        )

    def toggle_client(self, public_key: str, enabled: bool):
        """Toggle peer's live state. Disabled = remove from live interface.
        Enabled = re-add from config file (syncconf)."""
        if enabled:
            self.ssh.run_sudo(
                "wg syncconf wg0 <(wg-quick strip /etc/wireguard/wg0.conf) 2>/dev/null"
            )
        else:
            self.ssh.run_sudo(
                f"wg set wg0 peer {shlex.quote(public_key)} remove 2>/dev/null || true"
            )

    def get_traffic(self) -> dict:
        out, _, code = self.ssh.run_sudo("wg show all dump 2>/dev/null")
        if code != 0 or not out.strip():
            return {}
        return parse_wg_dump(out)

    def get_live_peers(self) -> list[str]:
        out, _, _ = self.ssh.run_sudo("wg show all dump 2>/dev/null")
        return list(parse_wg_dump(out).keys())

    def build_client_conf(self, client: dict, server: dict) -> str:
        # Per-client overrides (new in v2.1)
        dns = client.get("dns") or server.get("dns", "1.1.1.1")
        mtu = client.get("mtu")
        keepalive = client.get("persistent_keepalive", 25)
        allowed_ips = client.get("allowed_ips", "0.0.0.0/0, ::/0")

        lines = [
            "[Interface]",
            f"PrivateKey = {client['private_key']}",
            f"Address = {client['ip']}/32",
            f"DNS = {dns}",
        ]
        if mtu:
            lines.append(f"MTU = {mtu}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {server['server_public_key']}",
            f"PresharedKey = {client['preshared_key']}",
            f"Endpoint = {server['host']}:{server['port']}",
            f"AllowedIPs = {allowed_ips}",
            f"PersistentKeepalive = {keepalive}",
        ]
        return "\n".join(lines) + "\n"

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
        peer_lines: list[str] = []
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
