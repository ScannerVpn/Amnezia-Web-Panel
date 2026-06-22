import secrets
import struct
import logging
from typing import Optional
from .ssh_manager import SSHManager
from utils import parse_wg_dump

logger = logging.getLogger(__name__)

AWG_DIR = "/opt/amnezia/awg"
AWG_CONTAINER = "amnezia-awg"
AWG_CONF = f"{AWG_DIR}/wg0.conf"


AWG_DOCKERFILE = """\
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \\
    apt-get install -y software-properties-common curl iproute2 iptables kmod && \\
    add-apt-repository ppa:amnezia/ppa && \\
    apt-get update && \\
    apt-get install -y amneziawg amneziawg-tools && \\
    rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
VOLUME /etc/amnezia/awg
ENTRYPOINT ["/entrypoint.sh"]
"""

AWG_ENTRYPOINT = """\
#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
modprobe amneziawg 2>/dev/null || true
awg-quick up /etc/amnezia/awg/wg0.conf
tail -f /dev/null
"""

DOCKER_INSTALL_SCRIPT = """\
#!/bin/bash
set -e
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | bash
fi
"""


def _gen_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return (
        base64.b64encode(priv_bytes).decode(),
        base64.b64encode(pub_bytes).decode(),
    )


def _gen_psk() -> str:
    import base64
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _rand_awg_params() -> dict:
    return {
        "Jc": secrets.randbelow(6) + 3,
        "Jmin": secrets.randbelow(20) + 30,
        "Jmax": secrets.randbelow(30) + 60,
        "S1": secrets.randbelow(20),
        "S2": secrets.randbelow(20),
        "H1": secrets.randbits(32),
        "H2": secrets.randbits(32),
        "H3": secrets.randbits(32),
        "H4": secrets.randbits(32),
    }


class AWGManager:
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh

    def _exec(self, cmd: str, timeout: int = 120):
        return self.ssh.run_sudo(cmd, timeout)

    def _docker_exec(self, cmd: str, timeout: int = 60):
        return self._exec(f"docker exec {AWG_CONTAINER} {cmd}", timeout)

    def install_docker(self):
        self._exec("bash -c '" + DOCKER_INSTALL_SCRIPT.replace("'", "'\\''") + "'", 300)

    def is_installed(self) -> bool:
        out, _, code = self._exec(f"docker inspect --format='{{{{.State.Running}}}}' {AWG_CONTAINER} 2>/dev/null")
        return code == 0 and "true" in out.lower()

    def install(self, port: int = 51820, subnet: str = "10.8.1.0/24",
                dns: str = "1.1.1.1", progress=None) -> dict:
        def log(msg):
            if progress:
                progress(msg)

        log("Installing Docker on server...")
        self.install_docker()

        log("Creating AmneziaWG directory...")
        self._exec(f"mkdir -p {AWG_DIR}")

        log("Generating WireGuard keys...")
        priv_key, pub_key = _gen_keypair()
        params = _rand_awg_params()

        iface = self._detect_iface()
        conf = self._build_server_conf(priv_key, port, subnet, dns, iface, params)

        log("Uploading AmneziaWG configuration...")
        self.ssh.upload_sudo_file(conf, AWG_CONF)
        self.ssh.upload_sudo_file(AWG_DOCKERFILE, f"{AWG_DIR}/Dockerfile")
        self.ssh.upload_sudo_file(AWG_ENTRYPOINT, f"{AWG_DIR}/entrypoint.sh")
        self._exec(f"chmod +x {AWG_DIR}/entrypoint.sh")

        log("Removing old container (if any)...")
        self._exec(f"docker rm -f {AWG_CONTAINER} 2>/dev/null || true")

        log("Building AmneziaWG Docker container (3-5 min)...")
        self._exec(f"docker build -t {AWG_CONTAINER} {AWG_DIR}", timeout=600)

        log("Starting AmneziaWG container...")
        self._exec(
            f"docker run -d --name {AWG_CONTAINER} --privileged --net=host "
            f"--restart=unless-stopped "
            f"-v {AWG_DIR}:/etc/amnezia/awg "
            f"{AWG_CONTAINER}",
        )

        log(f"Opening firewall port {port}/udp...")
        self.ssh.open_port(port, "udp")

        log("AmneziaWG installed successfully!")
        return {
            "server_private_key": priv_key,
            "server_public_key": pub_key,
            "port": port,
            "subnet": subnet,
            "dns": dns,
            "awg_params": params,
        }

    def uninstall(self):
        self._exec(f"docker rm -f {AWG_CONTAINER} 2>/dev/null || true")
        self._exec(f"rm -rf {AWG_DIR}")

    def add_client(self, server_conf: dict, client_name: str, client_ip: str) -> dict:
        priv_key, pub_key = _gen_keypair()
        psk = _gen_psk()

        peer_block = (
            f"\n[Peer]\n"
            f"# {client_name}\n"
            f"PublicKey = {pub_key}\n"
            f"PresharedKey = {psk}\n"
            f"AllowedIPs = {client_ip}/32\n"
        )

        current = self._read_conf()
        self._write_conf(current + peer_block)
        self._sync()

        return {
            "private_key": priv_key,
            "public_key": pub_key,
            "preshared_key": psk,
            "ip": client_ip,
        }

    def remove_client(self, public_key: str):
        conf = self._read_conf()
        new_conf = self._remove_peer_from_conf(conf, public_key)
        self._write_conf(new_conf)
        self._sync()

    def _remove_peer_from_conf(self, conf: str, public_key: str) -> str:
        sections = []
        current = []
        for line in conf.split("\n"):
            if line.strip().startswith("[") and current:
                sections.append("\n".join(current))
                current = [line]
            else:
                current.append(line)
        if current:
            sections.append("\n".join(current))

        result = []
        for section in sections:
            if "[Peer]" in section and f"PublicKey = {public_key}" in section:
                continue
            result.append(section)
        return "\n".join(result)

    def toggle_client(self, public_key: str, enabled: bool):
        conf = self._read_conf()
        if enabled:
            conf = conf.replace(f"#PublicKey = {public_key}", f"PublicKey = {public_key}")
        else:
            conf = conf.replace(f"PublicKey = {public_key}", f"#PublicKey = {public_key}")
        self._write_conf(conf)
        self._sync()

    def get_traffic(self) -> dict:
        # Try docker container first, fall back to native
        out, _, code = self._docker_exec("awg show all dump")
        if code != 0:
            out, _, code = self.ssh.run_sudo("awg show all dump 2>/dev/null || wg show all dump 2>/dev/null")
        if code != 0 or not out.strip():
            return {}
        return parse_wg_dump(out)

    def get_live_peers(self) -> list[str]:
        out, _, code = self._docker_exec("awg show all dump")
        if code != 0:
            out, _, _ = self.ssh.run_sudo("awg show all dump 2>/dev/null || wg show all dump 2>/dev/null")
        return list(parse_wg_dump(out).keys())

    def _detect_iface(self) -> str:
        out, _, _ = self._exec("ip route | grep default | awk '{print $5}' | head -1")
        return out.strip() or "eth0"

    def _build_server_conf(self, priv_key, port, subnet, dns, iface, params) -> str:
        network = subnet.rsplit(".", 1)[0]
        server_ip = network + ".1"
        return (
            f"[Interface]\n"
            f"Address = {server_ip}/24\n"
            f"ListenPort = {port}\n"
            f"PrivateKey = {priv_key}\n"
            f"DNS = {dns}\n"
            f"Jc = {params['Jc']}\n"
            f"Jmin = {params['Jmin']}\n"
            f"Jmax = {params['Jmax']}\n"
            f"S1 = {params['S1']}\n"
            f"S2 = {params['S2']}\n"
            f"H1 = {params['H1']}\n"
            f"H2 = {params['H2']}\n"
            f"H3 = {params['H3']}\n"
            f"H4 = {params['H4']}\n"
            f"\n"
            f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
            f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n"
        )

    def build_client_conf(self, client: dict, server: dict) -> str:
        params = server.get("awg_params", {})
        return (
            f"[Interface]\n"
            f"PrivateKey = {client['private_key']}\n"
            f"Address = {client['ip']}/32\n"
            f"DNS = {server.get('dns', '1.1.1.1')}\n"
            f"Jc = {params.get('Jc', 4)}\n"
            f"Jmin = {params.get('Jmin', 40)}\n"
            f"Jmax = {params.get('Jmax', 70)}\n"
            f"S1 = {params.get('S1', 0)}\n"
            f"S2 = {params.get('S2', 0)}\n"
            f"H1 = {params.get('H1', 1)}\n"
            f"H2 = {params.get('H2', 2)}\n"
            f"H3 = {params.get('H3', 3)}\n"
            f"H4 = {params.get('H4', 4)}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {server['server_public_key']}\n"
            f"PresharedKey = {client['preshared_key']}\n"
            f"Endpoint = {server['host']}:{server['port']}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"PersistentKeepalive = 25\n"
        )

    def _read_conf(self) -> str:
        return self.ssh.download_file(AWG_CONF)

    def _write_conf(self, content: str):
        self.ssh.upload_sudo_file(content, AWG_CONF)

    def _sync(self):
        self._docker_exec("awg syncconf wg0 <(awg-quick strip /etc/amnezia/awg/wg0.conf)")
