import logging
import re
import secrets
from .ssh_manager import SSHManager, _validate_path_component

logger = logging.getLogger(__name__)

OVPN_DIR = "/opt/amnezia/openvpn"
OVPN_CONTAINER = "amnezia-openvpn"

OVPN_DOCKERFILE = """\
FROM kylemanna/openvpn:latest
RUN apk add --no-cache bash
"""


def _safe_client_name(name: str) -> str:
    """Convert a user-supplied client name into a filesystem-safe, shell-safe name.
    Allows only [a-zA-Z0-9._-] and raises if the result is empty."""
    name = (name or "").strip()
    # Replace common separators with underscore
    name = re.sub(r"[\s/\\]+", "_", name)
    # Drop any char outside the safe set
    name = re.sub(r"[^a-zA-Z0-9._-]", "", name)
    if not name:
        # Fallback to random if nothing left
        name = f"user_{secrets.token_hex(4)}"
    # Cap length (EasyRSA client names can be long, but we cap for sanity)
    if len(name) > 64:
        name = name[:64]
    return name


class OpenVPNManager:
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh

    def is_installed(self) -> bool:
        out, _, code = self.ssh.run_sudo(
            f"docker inspect --format='{{{{.State.Running}}}}' {OVPN_CONTAINER} 2>/dev/null"
        )
        return code == 0 and out.strip().lower() == "true"

    def install(self, port: int = 1194, dns: str = "1.1.1.1", progress=None) -> dict:
        # Validate inputs
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("Invalid port")
        # dns must look like an IP or hostname (basic check)
        if not re.match(r"^[a-zA-Z0-9.\-]+$", dns):
            raise ValueError("Invalid DNS")

        host_ip = self._get_host_ip()
        # Generate a strong random PKI password (NOT hardcoded "amnezia-vpn")
        pki_password = secrets.token_urlsafe(24)

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
echo '{pki_password}' | docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm -i kylemanna/openvpn \\
    ovpn_initpki nopass
docker run -d \\
    --name {OVPN_CONTAINER} \\
    --cap-add=NET_ADMIN \\
    -p {port}:{port}/udp \\
    --restart=unless-stopped \\
    -v {OVPN_CONTAINER}-data:/etc/openvpn \\
    kylemanna/openvpn
"""
        if progress:
            progress("Installing Docker and OpenVPN container (5-10 min)...")
        self.ssh.run_sudo_script(setup_script, 600)
        if progress:
            progress(f"Opening firewall port {port}/udp...")
        self.ssh.open_port(port, "udp")
        if progress:
            progress("OpenVPN installed successfully!")

        return {
            "port": port,
            "dns": dns,
            "host": host_ip,
            "pki_password": pki_password,
        }

    def uninstall(self):
        self.ssh.run_sudo(f"docker rm -f {OVPN_CONTAINER} 2>/dev/null || true")
        self.ssh.run_sudo(f"docker volume rm {OVPN_CONTAINER}-data 2>/dev/null || true")

    def add_client(self, client_name: str) -> dict:
        safe_name = _safe_client_name(client_name)
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
        # Validate before use
        safe_name = _safe_client_name(safe_name)
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
        safe_name = _safe_client_name(safe_name)
        out, _, _ = self.ssh.run_sudo(
            f"docker run -v {OVPN_CONTAINER}-data:/etc/openvpn --rm kylemanna/openvpn "
            f"ovpn_getclient {safe_name}"
        )
        return out

    def _get_host_ip(self) -> str:
        out, _, _ = self.ssh.run_sudo(
            "curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'"
        )
        return out.strip()
