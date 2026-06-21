import asyncio
import base64
import io
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import bcrypt
import qrcode
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import (
    HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from managers.ssh_manager import SSHManager
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager
from managers.xray_manager import XrayManager, PROTO_TO_ITYPE
from managers.openvpn_manager import OpenVPNManager

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VERSION = "1.1.0"
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_FILE = DATA_DIR / "data.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_LOCK = asyncio.Lock()

app = FastAPI(title="Amnezia Web Panel", version=VERSION)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=86400 * 7)

# All protocols including Xray sub-types
ALL_PROTOCOLS = ["awg", "wireguard", "xray", "xray_ws", "xray_grpc", "xray_vmess", "xray_trojan", "xray_ss", "openvpn"]
XRAY_PROTOCOLS = {"xray", "xray_ws", "xray_grpc", "xray_vmess", "xray_trojan", "xray_ss"}


# ─── Data helpers ─────────────────────────────────────────────────────────────

def _default_data() -> dict:
    pw = os.getenv("ADMIN_PASSWORD", "admin")
    pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    return {
        "panel": {
            "admin_username": os.getenv("ADMIN_USERNAME", "admin"),
            "admin_password_hash": pw_hash,
            "version": VERSION,
        },
        "servers": {},
    }


async def load_data() -> dict:
    if not DATA_FILE.exists():
        data = _default_data()
        await save_data(data)
        return data
    async with DATA_LOCK:
        return json.loads(DATA_FILE.read_text())


async def save_data(data: dict):
    async with DATA_LOCK:
        DATA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def bytes_to_human(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _make_ssh(server: dict) -> SSHManager:
    return SSHManager(
        host=server["host"],
        port=server.get("ssh_port", 22),
        username=server["username"],
        password=base64.b64decode(server.get("password_b64", "")).decode() if server.get("password_b64") else None,
        key_data=server.get("ssh_key"),
    )


def _ensure_protocols(server: dict):
    """Make sure server dict has all protocol keys (for old data)."""
    if "protocols" not in server:
        server["protocols"] = {}
    if "clients" not in server:
        server["clients"] = {}
    for p in ALL_PROTOCOLS:
        server["protocols"].setdefault(p, {"installed": False})
        server["clients"].setdefault(p, {})


# ─── Auth ─────────────────────────────────────────────────────────────────────

def require_auth(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=302, headers={"Location": "/login"})


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def render(request: Request, template: str, **ctx):
    return templates.TemplateResponse(
        template,
        {"request": request, "version": VERSION, "bytes_to_human": bytes_to_human, **ctx},
    )


# ─── WireGuard dump helpers ────────────────────────────────────────────────────

def _parse_wg_dump(output: str) -> list[str]:
    peers = []
    for line in output.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) >= 5 and parts[1] not in ("(none)", ""):
            peers.append(parts[1])
    return peers


def _parse_wg_conf_peers(conf: str) -> list[str]:
    return [
        line.split("=", 1)[1].strip()
        for line in conf.split("\n")
        if line.strip().startswith("PublicKey")
    ]


# ─── Login / Logout ───────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return render(request, "login.html")


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    data = await load_data()
    panel = data["panel"]
    if username == panel["admin_username"] and bcrypt.checkpw(
        password.encode(), panel["admin_password_hash"].encode()
    ):
        request.session["authenticated"] = True
        return RedirectResponse("/", status_code=302)
    return render(request, "login.html", error="Wrong username or password")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    for s in data["servers"].values():
        _ensure_protocols(s)
    return render(request, "index.html", servers=list(data["servers"].values()))


# ─── Server CRUD ──────────────────────────────────────────────────────────────

@app.get("/server/{server_id}", response_class=HTMLResponse)
async def server_detail(request: Request, server_id: str):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)
    return render(request, "server.html", server=server)


@app.post("/api/servers")
async def add_server(request: Request):
    require_auth(request)
    body = await request.json()

    server_id = str(uuid.uuid4())
    pw_b64 = base64.b64encode(body.get("password", "").encode()).decode() if body.get("password") else ""

    server: dict = {
        "id": server_id,
        "name": body.get("name", body["host"]),
        "host": body["host"],
        "ssh_port": int(body.get("ssh_port", 22)),
        "username": body.get("username", "root"),
        "password_b64": pw_b64,
        "ssh_key": body.get("ssh_key", ""),
        "created_at": now_iso(),
        "protocols": {p: {"installed": False} for p in ALL_PROTOCOLS},
        "clients":   {p: {} for p in ALL_PROTOCOLS},
    }

    ssh = _make_ssh(server)
    result = ssh.test_connection()
    if not result["success"]:
        return JSONResponse({"success": False, "error": result.get("error", "Connection failed")})

    data = await load_data()
    data["servers"][server_id] = server
    await save_data(data)
    return JSONResponse({"success": True, "server_id": server_id})


@app.delete("/api/servers/{server_id}")
async def delete_server(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    if server_id not in data["servers"]:
        raise HTTPException(404)
    del data["servers"][server_id]
    await save_data(data)
    return JSONResponse({"success": True})


@app.post("/api/servers/{server_id}/ping")
async def ping_server(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    return JSONResponse(_make_ssh(server).ping())


@app.post("/api/servers/{server_id}/reboot")
async def reboot_server(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    ssh = _make_ssh(server)
    try:
        with ssh:
            ssh.run_sudo("reboot || shutdown -r now &")
    except Exception:
        pass
    return JSONResponse({"success": True})


@app.put("/api/servers/{server_id}")
async def update_server(request: Request, server_id: str):
    require_auth(request)
    body = await request.json()
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    server["name"] = body.get("name", server["name"])
    if body.get("password"):
        server["password_b64"] = base64.b64encode(body["password"].encode()).decode()
    if body.get("ssh_key"):
        server["ssh_key"] = body["ssh_key"]
    await save_data(data)
    return JSONResponse({"success": True})


# ─── Protocol Install / Uninstall ─────────────────────────────────────────────

@app.post("/api/servers/{server_id}/protocols/{protocol}/install")
async def install_protocol(request: Request, server_id: str, protocol: str):
    require_auth(request)
    body = await request.json()

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)

    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol == "awg":
                mgr = AWGManager(ssh)
                result = mgr.install(
                    port=int(body.get("port", 51820)),
                    subnet=body.get("subnet", "10.8.1.0/24"),
                    dns=body.get("dns", "1.1.1.1"),
                )
                server["protocols"]["awg"] = {"installed": True, **result, "host": server["host"]}

            elif protocol == "wireguard":
                mgr = WireGuardManager(ssh)
                result = mgr.install(
                    port=int(body.get("port", 51820)),
                    subnet=body.get("subnet", "10.8.0.0/24"),
                    dns=body.get("dns", "1.1.1.1"),
                )
                server["protocols"]["wireguard"] = {"installed": True, **result, "host": server["host"]}

            elif protocol in XRAY_PROTOCOLS:
                itype = PROTO_TO_ITYPE[protocol]
                mgr = XrayManager(ssh)
                extra_kwargs = {}
                if itype == "vless-reality":
                    extra_kwargs["dest_domain"] = body.get("dest_domain", "www.microsoft.com")
                elif itype in ("vless-ws", "vmess-ws"):
                    extra_kwargs["path"] = body.get("path", f"/{itype.split('-')[0]}")
                elif itype == "vless-grpc":
                    extra_kwargs["service_name"] = body.get("service_name", "grpc")

                inbound = mgr.add_inbound(itype, int(body.get("port", _default_port(protocol))), **extra_kwargs)
                server["protocols"][protocol] = {"installed": True, "host": server["host"], **inbound}

            elif protocol == "openvpn":
                mgr = OpenVPNManager(ssh)
                result = mgr.install(
                    port=int(body.get("port", 1194)),
                    dns=body.get("dns", "1.1.1.1"),
                )
                server["protocols"]["openvpn"] = {"installed": True, **result, "host": server["host"]}

            else:
                raise HTTPException(400, f"Unknown protocol: {protocol}")

    except Exception as e:
        logger.exception("Install error")
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True})


def _default_port(protocol: str) -> int:
    defaults = {
        "xray": 443, "xray_ws": 8443, "xray_grpc": 8444,
        "xray_vmess": 8080, "xray_trojan": 443, "xray_ss": 54321,
    }
    return defaults.get(protocol, 443)


@app.post("/api/servers/{server_id}/protocols/{protocol}/uninstall")
async def uninstall_protocol(request: Request, server_id: str, protocol: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol == "awg":
                AWGManager(ssh).uninstall()
            elif protocol == "wireguard":
                WireGuardManager(ssh).uninstall()
            elif protocol in XRAY_PROTOCOLS:
                inbound_id = server["protocols"][protocol].get("id", "")
                mgr = XrayManager(ssh)
                if inbound_id:
                    mgr.remove_inbound(inbound_id)
                # Only remove Xray service if no other xray protocol is installed after this
                remaining = [
                    k for k, v in server["protocols"].items()
                    if k in XRAY_PROTOCOLS and k != protocol and v.get("installed")
                ]
                if not remaining:
                    mgr.uninstall()
            elif protocol == "openvpn":
                OpenVPNManager(ssh).uninstall()
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    server["protocols"][protocol] = {"installed": False}
    server["clients"][protocol] = {}
    await save_data(data)
    return JSONResponse({"success": True})


# ─── Client Management ────────────────────────────────────────────────────────

def _next_ip(proto_conf: dict, clients: dict) -> str:
    subnet = proto_conf.get("subnet", "10.8.1.0/24")
    base = subnet.rsplit(".", 1)[0]
    used = {c["ip"] for c in clients.values() if c.get("ip")}
    for i in range(2, 254):
        ip = f"{base}.{i}"
        if ip not in used:
            return ip
    raise ValueError("IP pool exhausted")


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients")
async def add_client(request: Request, server_id: str, protocol: str):
    require_auth(request)
    body = await request.json()
    client_name = body.get("name", f"user_{secrets.token_hex(3)}")

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)

    if not server["protocols"][protocol].get("installed"):
        return JSONResponse({"success": False, "error": "Protocol not installed"})

    proto_conf = server["protocols"][protocol]
    clients = server["clients"].setdefault(protocol, {})
    client_id = str(uuid.uuid4())

    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol == "awg":
                client_ip = body.get("ip") or _next_ip(proto_conf, clients)
                keys = AWGManager(ssh).add_client(proto_conf, client_name, client_ip)
                clients[client_id] = _wg_client(client_id, client_name, client_ip, keys, body)

            elif protocol == "wireguard":
                client_ip = body.get("ip") or _next_ip(proto_conf, clients)
                keys = WireGuardManager(ssh).add_client(proto_conf["server_public_key"], client_ip, client_name)
                clients[client_id] = _wg_client(client_id, client_name, client_ip, keys, body)

            elif protocol in XRAY_PROTOCOLS:
                itype      = PROTO_TO_ITYPE[protocol]
                inbound_id = proto_conf["id"]
                info = XrayManager(ssh).add_client(inbound_id, itype, client_name)
                clients[client_id] = {
                    "id": client_id, "name": client_name,
                    "xray_id": info.get("id", ""),
                    "password": info.get("password", ""),
                    "inbound_id": inbound_id, "inbound_type": itype,
                    "enabled": True, "source": "panel", "created_at": now_iso(),
                    "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
                    "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
                }

            elif protocol == "openvpn":
                info = OpenVPNManager(ssh).add_client(client_name)
                clients[client_id] = {
                    "id": client_id, "name": client_name,
                    "safe_name": client_name.replace(" ", "_"),
                    "enabled": True, "source": "panel", "created_at": now_iso(),
                    "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
                    "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
                    "ovpn_config": info.get("config", ""),
                }

    except Exception as e:
        logger.exception("Add client error")
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "client_id": client_id})


def _wg_client(client_id, name, ip, keys, body):
    return {
        "id": client_id, "name": name, "ip": ip,
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
        "preshared_key": keys["preshared_key"],
        "enabled": True, "source": "panel", "created_at": now_iso(),
        "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
    }


@app.delete("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}")
async def remove_client(request: Request, server_id: str, protocol: str, client_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404)

    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol == "awg":
                AWGManager(ssh).remove_client(client["public_key"])
            elif protocol == "wireguard":
                WireGuardManager(ssh).remove_client(client["public_key"])
            elif protocol in XRAY_PROTOCOLS:
                itype = PROTO_TO_ITYPE[protocol]
                ident = client.get("password") if itype in ("shadowsocks", "trojan-tcp") else client.get("xray_id", "")
                XrayManager(ssh).remove_client(client["inbound_id"], itype, ident)
            elif protocol == "openvpn":
                OpenVPNManager(ssh).remove_client(client.get("safe_name", client["name"]))
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    del server["clients"][protocol][client_id]
    await save_data(data)
    return JSONResponse({"success": True})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}/toggle")
async def toggle_client(request: Request, server_id: str, protocol: str, client_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404)

    enabled = not client["enabled"]
    if protocol in ("awg", "wireguard"):
        ssh = _make_ssh(server)
        try:
            with ssh:
                if protocol == "awg":
                    AWGManager(ssh).toggle_client(client["public_key"], enabled)
                else:
                    WireGuardManager(ssh).toggle_client(client["public_key"], enabled)
        except Exception as e:
            return JSONResponse({"success": False, "error": str(e)})

    client["enabled"] = enabled
    await save_data(data)
    return JSONResponse({"success": True, "enabled": enabled})


# ─── Config / QR ──────────────────────────────────────────────────────────────

@app.get("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}/config")
async def get_client_config(request: Request, server_id: str, protocol: str, client_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404)

    proto_conf = server["protocols"][protocol]

    if protocol == "awg":
        text = AWGManager(None).build_client_conf(client, {**proto_conf, "host": server["host"]})
        fname = f"awg_{client['name']}.conf"
    elif protocol == "wireguard":
        text = WireGuardManager(None).build_client_conf(client, {**proto_conf, "host": server["host"]})
        fname = f"wg_{client['name']}.conf"
    elif protocol in XRAY_PROTOCOLS:
        itype = PROTO_TO_ITYPE[protocol]
        text = XrayManager(None).build_client_url(client, {**proto_conf, "type": itype}, server["host"])
        fname = f"xray_{protocol}_{client['name']}.txt"
    elif protocol == "openvpn":
        text = client.get("ovpn_config", "")
        fname = f"{client['name']}.ovpn"
    else:
        raise HTTPException(400)

    return Response(
        content=text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}/qr")
async def get_client_qr(request: Request, server_id: str, protocol: str, client_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404)

    proto_conf = server["protocols"][protocol]

    if protocol == "awg":
        text = AWGManager(None).build_client_conf(client, {**proto_conf, "host": server["host"]})
    elif protocol == "wireguard":
        text = WireGuardManager(None).build_client_conf(client, {**proto_conf, "host": server["host"]})
    elif protocol in XRAY_PROTOCOLS:
        itype = PROTO_TO_ITYPE[protocol]
        text = XrayManager(None).build_client_url(client, {**proto_conf, "type": itype}, server["host"])
    else:
        raise HTTPException(400, "QR not supported for this protocol")

    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ─── Traffic Sync ─────────────────────────────────────────────────────────────

@app.post("/api/servers/{server_id}/sync-traffic")
async def sync_traffic(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    ssh = _make_ssh(server)
    try:
        with ssh:
            for proto in ["awg", "wireguard"]:
                if not server["protocols"].get(proto, {}).get("installed"):
                    continue
                traffic = AWGManager(ssh).get_traffic() if proto == "awg" else WireGuardManager(ssh).get_traffic()
                for client in server["clients"].get(proto, {}).values():
                    t = traffic.get(client.get("public_key", ""))
                    if t:
                        client["traffic_rx"] = t["rx"]
                        client["traffic_tx"] = t["tx"]
                        if t["last_seen"]:
                            client["last_seen"] = datetime.fromtimestamp(t["last_seen"], tz=timezone.utc).isoformat()
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True})


# ─── Detect External (Amnezia App) Configs ────────────────────────────────────

@app.post("/api/servers/{server_id}/detect-external")
async def detect_external_clients(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    # Collect all public keys we already know
    known_keys: set[str] = set()
    for proto_clients in server["clients"].values():
        for c in proto_clients.values():
            if isinstance(c, dict) and c.get("public_key"):
                known_keys.add(c["public_key"])

    detected: dict[str, list[str]] = {}

    ssh = _make_ssh(server)
    try:
        with ssh:
            # 1. Native WireGuard dump
            out, _, code = ssh.run_sudo("wg show all dump 2>/dev/null")
            if code == 0:
                new_peers = [p for p in _parse_wg_dump(out) if p not in known_keys]
                if new_peers:
                    detected["wireguard"] = new_peers

            # 2. Amnezia config files (installed by Amnezia desktop app)
            for conf_path in ["/opt/amnezia/awg/wg0.conf", "/opt/amnezia/wireguard/wg0.conf"]:
                try:
                    conf = ssh.download_file(conf_path)
                    new_peers = [p for p in _parse_wg_conf_peers(conf) if p not in known_keys]
                    if new_peers:
                        detected.setdefault("awg", []).extend(new_peers)
                except Exception:
                    pass

            # 3. Docker containers (any amnezia/wg related containers)
            out, _, _ = ssh.run_sudo("docker ps --format '{{.Names}}' 2>/dev/null")
            for container in out.strip().split("\n"):
                container = container.strip()
                if not container:
                    continue
                if not any(k in container.lower() for k in ["awg", "wireguard", "amnezia", "wg"]):
                    continue
                for cmd in ["awg show all dump", "wg show all dump"]:
                    out2, _, rc = ssh.run_sudo(f"docker exec {container} {cmd} 2>/dev/null")
                    if rc == 0 and out2.strip():
                        new_peers = [p for p in _parse_wg_dump(out2) if p not in known_keys]
                        if new_peers:
                            detected.setdefault("awg", []).extend(new_peers)
                        break

    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    # Deduplicate
    for k in detected:
        detected[k] = list(dict.fromkeys(detected[k]))

    total = sum(len(v) for v in detected.values())
    return JSONResponse({"success": True, "external": detected, "total": total})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/{public_key}/import")
async def import_external_client(request: Request, server_id: str, protocol: str, public_key: str):
    require_auth(request)
    body = await request.json()
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    client_id = str(uuid.uuid4())
    server["clients"].setdefault(protocol, {})[client_id] = {
        "id": client_id,
        "name": body.get("name", f"External ({public_key[:8]})"),
        "public_key": public_key,
        "private_key": "", "preshared_key": "",
        "ip": body.get("ip", ""),
        "enabled": True, "source": "amnezia_app", "created_at": now_iso(),
        "traffic_limit_bytes": 0, "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
    }
    await save_data(data)
    return JSONResponse({"success": True, "client_id": client_id})


# ─── Settings ─────────────────────────────────────────────────────────────────

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    return render(request, "settings.html", panel=data["panel"])


@app.post("/api/settings/password")
async def change_password(request: Request):
    require_auth(request)
    body = await request.json()
    data = await load_data()

    if not bcrypt.checkpw(body.get("current_password", "").encode(), data["panel"]["admin_password_hash"].encode()):
        return JSONResponse({"success": False, "error": "Current password is incorrect"})

    new_pw = body.get("new_password", "")
    if len(new_pw) < 8:
        return JSONResponse({"success": False, "error": "Password must be at least 8 characters"})

    data["panel"]["admin_password_hash"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    await save_data(data)
    return JSONResponse({"success": True})


# ─── Background traffic sync ──────────────────────────────────────────────────

async def _auto_sync():
    while True:
        await asyncio.sleep(600)
        try:
            data = await load_data()
            for server in list(data["servers"].values()):
                ssh = _make_ssh(server)
                try:
                    with ssh:
                        for proto in ["awg", "wireguard"]:
                            if not server["protocols"].get(proto, {}).get("installed"):
                                continue
                            traffic = (AWGManager(ssh) if proto == "awg" else WireGuardManager(ssh)).get_traffic()
                            for client in server["clients"].get(proto, {}).values():
                                t = traffic.get(client.get("public_key", ""))
                                if t:
                                    client["traffic_rx"] = t["rx"]
                                    client["traffic_tx"] = t["tx"]
                                    if t["last_seen"]:
                                        client["last_seen"] = datetime.fromtimestamp(t["last_seen"], tz=timezone.utc).isoformat()
                except Exception:
                    pass
            await save_data(data)
        except Exception:
            pass


@app.on_event("startup")
async def startup():
    asyncio.create_task(_auto_sync())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PANEL_PORT", 54325)), reload=False)
