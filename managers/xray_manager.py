import json
import secrets
import logging
import uuid
import base64
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)

XRAY_CONF = "/usr/local/etc/xray/config.json"
XRAY_CERT = "/usr/local/etc/xray/cert.pem"
XRAY_KEY  = "/usr/local/etc/xray/key.pem"
XRAY_BIN  = "/usr/local/bin/xray"

INSTALL_SCRIPT = """\
#!/bin/bash
set -e
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl enable xray
"""

GEN_CERT_SCRIPT = f"""\
#!/bin/bash
set -e
mkdir -p /usr/local/etc/xray
if [ ! -f {XRAY_CERT} ]; then
    openssl req -x509 -newkey rsa:2048 \\
        -keyout {XRAY_KEY} \\
        -out {XRAY_CERT} \\
        -days 3650 -nodes -subj '/CN=xray-panel' 2>/dev/null
    chmod 600 {XRAY_KEY} {XRAY_CERT}
fi
"""

INBOUND_LABELS = {
    "vless-reality": "VLESS + XTLS-Reality",
    "vless-ws":      "VLESS + WebSocket",
    "vless-grpc":    "VLESS + gRPC",
    "vmess-ws":      "VMess + WebSocket",
    "trojan-tcp":    "Trojan + TLS",
    "shadowsocks":   "Shadowsocks 2022",
}

# Map panel protocol key → Xray inbound type
PROTO_TO_ITYPE = {
    "xray":         "vless-reality",
    "xray_ws":      "vless-ws",
    "xray_grpc":    "vless-grpc",
    "xray_vmess":   "vmess-ws",
    "xray_trojan":  "trojan-tcp",
    "xray_ss":      "shadowsocks",
}


class XrayManager:
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh

    def is_xray_installed(self) -> bool:
        if self.ssh is None:
            return False
        _, _, code = self.ssh.run_sudo(f"test -f {XRAY_BIN}")
        return code == 0

    def ensure_installed(self):
        if not self.is_xray_installed():
            self.ssh.run_sudo_script(INSTALL_SCRIPT, 300)
        self.ssh.run_sudo_script(GEN_CERT_SCRIPT, 30)
        if not self._config_exists():
            self._write_config(self._base_config())

    def add_inbound(self, inbound_type: str, port: int, **kwargs) -> dict:
        self.ensure_installed()
        config = self._read_config()
        inbound_id = str(uuid.uuid4())

        inbound, extra = self._build_inbound(inbound_type, port, inbound_id, **kwargs)
        config["inbounds"].append(inbound)
        self._write_config(config)
        self.ssh.run_sudo("systemctl restart xray")

        return {
            "id": inbound_id,
            "type": inbound_type,
            "label": INBOUND_LABELS.get(inbound_type, inbound_type),
            "port": port,
            **extra,
        }

    def remove_inbound(self, inbound_id: str):
        try:
            config = self._read_config()
            config["inbounds"] = [ib for ib in config["inbounds"] if ib.get("tag") != inbound_id]
            self._write_config(config)
            self.ssh.run_sudo("systemctl restart xray")
        except Exception:
            pass

    def uninstall(self):
        self.ssh.run_sudo("systemctl stop xray 2>/dev/null || true")
        self.ssh.run_sudo(
            'bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove 2>/dev/null || true'
        )

    def add_client(self, inbound_id: str, inbound_type: str, client_name: str) -> dict:
        config = self._read_config()
        client_id = str(uuid.uuid4())

        for ib in config["inbounds"]:
            if ib.get("tag") != inbound_id:
                continue

            if inbound_type in ("shadowsocks",):
                password = secrets.token_urlsafe(16)
                ib["settings"]["clients"].append({
                    "password": password,
                    "email": client_name,
                })
                self._write_config(config)
                self.ssh.run_sudo("systemctl restart xray")
                return {"id": client_id, "name": client_name, "password": password}

            elif inbound_type == "trojan-tcp":
                password = secrets.token_urlsafe(16)
                ib["settings"]["clients"].append({
                    "password": password,
                    "email": client_name,
                })
                self._write_config(config)
                self.ssh.run_sudo("systemctl restart xray")
                return {"id": client_id, "name": client_name, "password": password}

            else:
                flow = "xtls-rprx-vision" if inbound_type == "vless-reality" else ""
                entry = {"id": client_id, "email": client_name}
                if flow:
                    entry["flow"] = flow
                ib["settings"]["clients"].append(entry)
                self._write_config(config)
                self.ssh.run_sudo("systemctl restart xray")
                return {"id": client_id, "name": client_name}

        raise ValueError(f"Inbound {inbound_id} not found in config")

    def remove_client(self, inbound_id: str, inbound_type: str, client_identifier: str):
        config = self._read_config()
        for ib in config["inbounds"]:
            if ib.get("tag") != inbound_id:
                continue
            if inbound_type in ("shadowsocks", "trojan-tcp"):
                ib["settings"]["clients"] = [
                    c for c in ib["settings"]["clients"]
                    if c.get("password") != client_identifier
                ]
            else:
                ib["settings"]["clients"] = [
                    c for c in ib["settings"]["clients"]
                    if c.get("id") != client_identifier
                ]
            break
        self._write_config(config)
        self.ssh.run_sudo("systemctl restart xray")

    def build_client_url(self, client: dict, inbound: dict, server_host: str) -> str:
        itype = inbound.get("type", "vless-reality")
        port  = inbound.get("port", 443)
        name  = client.get("name", "client")

        if itype == "vless-reality":
            pub_key  = inbound.get("public_key", "")
            short_id = inbound.get("short_id", "")
            dest     = inbound.get("dest_domain", "www.microsoft.com")
            cid      = client.get("xray_id", "")
            return (
                f"vless://{cid}@{server_host}:{port}"
                f"?type=tcp&security=reality&pbk={pub_key}"
                f"&fp=chrome&sni={dest}&sid={short_id}"
                f"&spx=%2F&flow=xtls-rprx-vision#{name}"
            )

        elif itype == "vless-ws":
            path = inbound.get("path", "/vless")
            cid  = client.get("xray_id", "")
            return (
                f"vless://{cid}@{server_host}:{port}"
                f"?type=ws&path={path}&security=tls&allowInsecure=1#{name}"
            )

        elif itype == "vless-grpc":
            svc = inbound.get("service_name", "grpc")
            cid = client.get("xray_id", "")
            return (
                f"vless://{cid}@{server_host}:{port}"
                f"?type=grpc&serviceName={svc}&security=tls&allowInsecure=1#{name}"
            )

        elif itype == "vmess-ws":
            path = inbound.get("path", "/vmess")
            cid  = client.get("xray_id", "")
            obj  = {
                "v": "2", "ps": name, "add": server_host,
                "port": str(port), "id": cid, "aid": "0",
                "net": "ws", "type": "none", "host": "",
                "path": path, "tls": "tls",
            }
            return f"vmess://{base64.b64encode(json.dumps(obj).encode()).decode()}"

        elif itype == "trojan-tcp":
            password = client.get("password", "")
            return f"trojan://{password}@{server_host}:{port}?security=tls&allowInsecure=1#{name}"

        elif itype == "shadowsocks":
            password = client.get("password", "")
            method   = "2022-blake3-aes-128-gcm"
            srv_pass = inbound.get("server_password", "")
            # SS2022 format: ss://method:serverpw:userpw@host:port
            combo = base64.b64encode(f"{method}:{srv_pass}:{password}".encode()).decode()
            return f"ss://{combo}@{server_host}:{port}#{name}"

        return ""

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_inbound(self, itype: str, port: int, tag: str, **kwargs) -> tuple[dict, dict]:

        tls_stream = lambda net, **extra: {
            "network": net,
            "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": XRAY_CERT, "keyFile": XRAY_KEY}]},
            **extra,
        }

        if itype == "vless-reality":
            priv, pub, sid = self._gen_reality_keys()
            dest = kwargs.get("dest_domain", "www.microsoft.com")
            return (
                {
                    "tag": tag, "port": port, "protocol": "vless",
                    "settings": {"clients": [], "decryption": "none"},
                    "streamSettings": {
                        "network": "tcp", "security": "reality",
                        "realitySettings": {
                            "show": False, "dest": f"{dest}:443", "xver": 0,
                            "serverNames": [dest], "privateKey": priv,
                            "shortIds": [sid, ""],
                        },
                    },
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
                },
                {"private_key": priv, "public_key": pub, "short_id": sid, "dest_domain": dest},
            )

        elif itype == "vless-ws":
            path = kwargs.get("path", "/vless")
            return (
                {
                    "tag": tag, "port": port, "protocol": "vless",
                    "settings": {"clients": [], "decryption": "none"},
                    "streamSettings": tls_stream("ws", wsSettings={"path": path}),
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {"path": path},
            )

        elif itype == "vless-grpc":
            svc = kwargs.get("service_name", "grpc")
            return (
                {
                    "tag": tag, "port": port, "protocol": "vless",
                    "settings": {"clients": [], "decryption": "none"},
                    "streamSettings": tls_stream("grpc", grpcSettings={"serviceName": svc}),
                },
                {"service_name": svc},
            )

        elif itype == "vmess-ws":
            path = kwargs.get("path", "/vmess")
            return (
                {
                    "tag": tag, "port": port, "protocol": "vmess",
                    "settings": {"clients": []},
                    "streamSettings": tls_stream("ws", wsSettings={"path": path}),
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {"path": path},
            )

        elif itype == "trojan-tcp":
            return (
                {
                    "tag": tag, "port": port, "protocol": "trojan",
                    "settings": {"clients": []},
                    "streamSettings": tls_stream("tcp"),
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {},
            )

        elif itype == "shadowsocks":
            srv_pass = secrets.token_urlsafe(16)
            return (
                {
                    "tag": tag, "port": port, "protocol": "shadowsocks",
                    "settings": {
                        "method": "2022-blake3-aes-128-gcm",
                        "password": srv_pass,
                        "clients": [],
                        "network": "tcp,udp",
                    },
                    "streamSettings": {"network": "tcp"},
                },
                {"server_password": srv_pass},
            )

        raise ValueError(f"Unknown inbound type: {itype}")

    def _gen_reality_keys(self) -> tuple[str, str, str]:
        out, _, _ = self.ssh.run_sudo("xray x25519 2>/dev/null")
        priv = pub = ""
        for line in out.split("\n"):
            if "Private key:" in line:
                priv = line.split(":", 1)[1].strip()
            elif "Public key:" in line:
                pub = line.split(":", 1)[1].strip()
        return priv, pub, secrets.token_hex(8)

    def _base_config(self) -> dict:
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}],
            },
        }

    def _config_exists(self) -> bool:
        return self.ssh.file_exists(XRAY_CONF)

    def _read_config(self) -> dict:
        return json.loads(self.ssh.download_file(XRAY_CONF))

    def _write_config(self, cfg: dict):
        self.ssh.upload_sudo_file(json.dumps(cfg, indent=2), XRAY_CONF)
