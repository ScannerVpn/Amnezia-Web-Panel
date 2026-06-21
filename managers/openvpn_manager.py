import logging
import secrets
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)

OVPN_DIR = "/opt/amnezia/openvpn"
OVPN_CONTAINER = "amnezia-openvpn"

OVPN_DOCKERFILE = """\
FROM kylemanna/openvpn:latest
RUN apk add --no-cache bash
"""

INSTALL_SCRIPT = """\
#!/bin/bash
set -e
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | bash
fi
mkdir -p {ovpn_dir}
docker rm -f {container} 2>/dev/null || true
docker volume create --name={container}-data 2>/dev/null || true

HOST_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{{print $1}}')
docker run -v {container}-data:/etc/openvpn --rm kylemanna/openvpn \\
    ovpn_genconfig -u udp://${{HOST_IP}}:{port} -n {dns}
docker run -v {container}-data:/etc/openvpn --rm -it kylemanna/openvpn \\
    ovpn_initpki nopass <<'EOF'
amnezia-vpn
EOF
"""


class OpenVPNManager:
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh

    def is_installed(self) -> bool:
        out, _, code = self.ssh.run_sudo(
            f"docker inspect --format='{{{{.State.Running}}}}' {OVPN_CONTAINER} 2>/dev/null"
        )
        return code == 0 and "true" in out.lower()

    def install(self, port: int = 1194, dns: str = "1.1.1.1") -> dict:
        host_ip = self._get_host_ip()

        setup_script = f"""\
#!/bin/bash
set -e
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | bash
fi
mkdir -p {OVPN_DIR}
docker rm -f {OVPN_CONTAINER} 2>/dev/null || true
docker volume create {OVPN_CONTAINER}-data 2>/dev/null || true
docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm kylemanna/openvpn \\
    ovpn_genconfig -u udp://{host_ip}:{port} -n {dns}
echo 'amnezia-vpn' | docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm -i kylemanna/openvpn \\
    ovpn_initpki nopass
docker run -d \\
    --name {OVPN_CONTAINER} \\
    --cap-add=NET_ADMIN \\
    -p {port}:{port}/udp \\
    --restart=unless-stopped \\
    -v {OVPN_CONTAINER}-data:/etc/openvpn \\
    kylemanna/openvpn
"""
        self.ssh.run_sudo_script(setup_script, 600)

        return {
            "port": port,
            "dns": dns,
            "host": host_ip,
        }

    def uninstall(self):
        self.ssh.run_sudo(f"docker rm -f {OVPN_CONTAINER} 2>/dev/null || true")
        self.ssh.run_sudo(f"docker volume rm {OVPN_CONTAINER}-data 2>/dev/null || true")

    def add_client(self, client_name: str) -> dict:
        safe_name = client_name.replace(" ", "_").replace("/", "_")
        script = f"""\
#!/bin/bash
set -e
echo 'yes' | docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm -i kylemanna/openvpn \\
    easyrsa build-client-full {safe_name} nopass
"""
        self.ssh.run_sudo_script(script, 120)

        ovpn_out, _, _ = self.ssh.run_sudo(
            f"docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm kylemanna/openvpn "
            f"ovpn_getclient {safe_name}"
        )
        return {"name": client_name, "safe_name": safe_name, "config": ovpn_out}

    def remove_client(self, safe_name: str):
        script = f"""\
#!/bin/bash
set -e
echo 'yes' | docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm -i kylemanna/openvpn \\
    easyrsa revoke {safe_name}
docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm kylemanna/openvpn \\
    easyrsa gen-crl
docker exec {OVPN_CONTAINER} kill -HUP 1
"""
        self.ssh.run_sudo_script(script, 120)

    def get_client_config(self, safe_name: str) -> str:
        out, _, _ = self.ssh.run_sudo(
            f"docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm kylemanna/openvpn "
            f"ovpn_getclient {safe_name}"
        )
        return out

    def _get_host_ip(self) -> str:
        out, _, _ = self.ssh.run_sudo("curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'")
        return out.strip()
