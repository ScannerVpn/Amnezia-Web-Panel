import json
import secrets
import logging
import uuid
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)

XRAY_CONF = "/usr/local/etc/xray/config.json"
XRAY_SERVICE = "xray"

INSTALL_SCRIPT = """\
#!/bin/bash
set -e
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl enable xray
"""


class XrayManager:
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh

    def is_installed(self) -> bool:
        _, _, code = self.ssh.run_sudo("systemctl is-active --quiet xray 2>/dev/null")
        return code == 0

    def install(self, port: int = 443, dest_domain: str = "www.microsoft.com") -> dict:
        self.ssh.run_sudo_script(INSTALL_SCRIPT, 300)

        priv_key, pub_key, short_id = self._gen_reality_keys()

        config = self._build_config(port, priv_key, pub_key, short_id, dest_domain)
        self.ssh.upload_sudo_file(json.dumps(config, indent=2), XRAY_CONF)
        self.ssh.run_sudo("systemctl restart xray")

        return {
            "port": port,
            "private_key": priv_key,
            "public_key": pub_key,
            "short_id": short_id,
            "dest_domain": dest_domain,
            "clients": [],
        }

    def uninstall(self):
        self.ssh.run_sudo("systemctl stop xray 2>/dev/null || true")
        self.ssh.run_sudo("bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ remove 2>/dev/null || true")

    def add_client(self, client_name: str) -> dict:
        client_id = str(uuid.uuid4())
        config = self._read_config()

        config["inbounds"][0]["settings"]["clients"].append({
            "id": client_id,
            "email": client_name,
        })
        self._write_config(config)
        self.ssh.run_sudo("systemctl restart xray")

        return {"id": client_id, "name": client_name}

    def remove_client(self, client_id: str):
        config = self._read_config()
        config["inbounds"][0]["settings"]["clients"] = [
            c for c in config["inbounds"][0]["settings"]["clients"]
            if c["id"] != client_id
        ]
        self._write_config(config)
        self.ssh.run_sudo("systemctl restart xray")

    def build_client_url(self, client: dict, server: dict) -> str:
        host = server["host"]
        port = server.get("port", 443)
        pub_key = server["public_key"]
        short_id = server["short_id"]
        dest = server.get("dest_domain", "www.microsoft.com")
        client_id = client["id"]
        name = client["name"]

        return (
            f"vless://{client_id}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={pub_key}"
            f"&fp=chrome&sni={dest}&sid={short_id}"
            f"&spx=%2F&flow=xtls-rprx-vision"
            f"#{name}"
        )

    def get_traffic(self) -> dict:
        out, _, code = self.ssh.run_sudo(
            "xray api statsquery --server=127.0.0.1:10085 2>/dev/null || true"
        )
        return {}

    def _gen_reality_keys(self) -> tuple[str, str, str]:
        out, _, _ = self.ssh.run_sudo("xray x25519 2>/dev/null")
        priv_key = ""
        pub_key = ""
        for line in out.split("\n"):
            if "Private key:" in line:
                priv_key = line.split(":", 1)[1].strip()
            elif "Public key:" in line:
                pub_key = line.split(":", 1)[1].strip()
        short_id = secrets.token_hex(8)
        return priv_key, pub_key, short_id

    def _build_config(self, port, priv_key, pub_key, short_id, dest_domain) -> dict:
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": f"{dest_domain}:443",
                            "xver": 0,
                            "serverNames": [dest_domain],
                            "privateKey": priv_key,
                            "shortIds": [short_id, ""],
                        },
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                    },
                }
            ],
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                ],
            },
        }

    def _read_config(self) -> dict:
        content = self.ssh.download_file(XRAY_CONF)
        return json.loads(content)

    def _write_config(self, config: dict):
        self.ssh.upload_sudo_file(json.dumps(config, indent=2), XRAY_CONF)
