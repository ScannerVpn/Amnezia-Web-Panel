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
import qrcode.image.svg
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import (
    HTMLResponse, JSONResponse, RedirectResponse,
    Response, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from managers.ssh_manager import SSHManager
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager
from managers.xray_manager import XrayManager
from managers.openvpn_manager import OpenVPNManager

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VERSION = "1.0.0"
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_FILE = DATA_DIR / "data.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_LOCK = asyncio.Lock()

app = FastAPI(title="Amnezia Web Panel", version=VERSION)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=86400 * 7)


# ─── Data helpers ────────────────────────────────────────────────────────────

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


# ─── Auth ─────────────────────────────────────────────────────────────────────

def require_auth(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=302, headers={"Location": "/login"})


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


# ─── Template helpers ─────────────────────────────────────────────────────────

def render(request: Request, template: str, **ctx):
    return templates.TemplateResponse(
        template,
        {"request": request, "version": VERSION, "bytes_to_human": bytes_to_human, **ctx},
    )


# ─── Routes: Auth ─────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return render(request, "login.html")


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    data = await load_data()
    panel = data["panel"]
    if username == panel["admin_username"] and bcrypt.checkpw(
        password.encode(), panel["admin_password_hash"].encode()
    ):
        request.session["authenticated"] = True
        request.session["username"] = username
        return RedirectResponse("/", status_code=302)
    return render(request, "login.html", error="نام کاربری یا رمز عبور اشتباه است")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ─── Routes: Dashboard ────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    return render(request, "index.html", servers=list(data["servers"].values()))


# ─── Routes: Server Management ────────────────────────────────────────────────

@app.get("/server/{server_id}", response_class=HTMLResponse)
async def server_detail(request: Request, server_id: str):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    return render(request, "server.html", server=server)


@app.post("/api/servers")
async def add_server(request: Request):
    require_auth(request)
    body = await request.json()

    server_id = str(uuid.uuid4())
    password_b64 = base64.b64encode(body.get("password", "").encode()).decode() if body.get("password") else ""

    server = {
        "id": server_id,
        "name": body.get("name", body["host"]),
        "host": body["host"],
        "ssh_port": int(body.get("ssh_port", 22)),
        "username": body.get("username", "root"),
        "password_b64": password_b64,
        "ssh_key": body.get("ssh_key", ""),
        "created_at": now_iso(),
        "protocols": {
            "awg": {"installed": False},
            "wireguard": {"installed": False},
            "xray": {"installed": False},
            "openvpn": {"installed": False},
        },
        "clients": {
            "awg": {},
            "wireguard": {},
            "xray": {},
            "openvpn": {},
        },
    }

    ssh = _make_ssh(server)
    result = ssh.test_connection()
    if not result["success"]:
        return JSONResponse({"success": False, "error": result.get("error", "Connection failed")})

    data = await load_data()
    data["servers"][server_id] = server
    await save_data(data)

    return JSONResponse({"success": True, "server_id": server_id, "info": result.get("info", "")})


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
    ssh = _make_ssh(server)
    result = ssh.ping()
    return JSONResponse(result)


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


# ─── Routes: Protocol Management ─────────────────────────────────────────────

@app.post("/api/servers/{server_id}/protocols/{protocol}/install")
async def install_protocol(request: Request, server_id: str, protocol: str):
    require_auth(request)
    body = await request.json()

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

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
                server["protocols"]["awg"] = {
                    "installed": True,
                    **result,
                    "host": server["host"],
                }

            elif protocol == "wireguard":
                mgr = WireGuardManager(ssh)
                result = mgr.install(
                    port=int(body.get("port", 51820)),
                    subnet=body.get("subnet", "10.8.0.0/24"),
                    dns=body.get("dns", "1.1.1.1"),
                )
                server["protocols"]["wireguard"] = {
                    "installed": True,
                    **result,
                    "host": server["host"],
                }

            elif protocol == "xray":
                mgr = XrayManager(ssh)
                result = mgr.install(
                    port=int(body.get("port", 443)),
                    dest_domain=body.get("dest_domain", "www.microsoft.com"),
                )
                server["protocols"]["xray"] = {
                    "installed": True,
                    **result,
                    "host": server["host"],
                }

            elif protocol == "openvpn":
                mgr = OpenVPNManager(ssh)
                result = mgr.install(
                    port=int(body.get("port", 1194)),
                    dns=body.get("dns", "1.1.1.1"),
                )
                server["protocols"]["openvpn"] = {
                    "installed": True,
                    **result,
                    "host": server["host"],
                }
            else:
                raise HTTPException(400, f"Unknown protocol: {protocol}")

    except Exception as e:
        logger.exception("Install error")
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "protocol": protocol})


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
            elif protocol == "xray":
                XrayManager(ssh).uninstall()
            elif protocol == "openvpn":
                OpenVPNManager(ssh).uninstall()

    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    server["protocols"][protocol] = {"installed": False}
    server["clients"][protocol] = {}
    await save_data(data)
    return JSONResponse({"success": True})


# ─── Routes: Client Management ───────────────────────────────────────────────

def _next_ip(protocol_conf: dict, clients: dict) -> str:
    subnet = protocol_conf.get("subnet", "10.8.1.0/24")
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
    if not server["protocols"][protocol].get("installed"):
        return JSONResponse({"success": False, "error": "Protocol not installed"})

    proto_conf = server["protocols"][protocol]
    clients = server["clients"].setdefault(protocol, {})
    client_id = str(uuid.uuid4())

    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol in ("awg", "wireguard"):
                client_ip = body.get("ip") or _next_ip(proto_conf, clients)
                if protocol == "awg":
                    keys = AWGManager(ssh).add_client(proto_conf, client_name, client_ip)
                else:
                    keys = WireGuardManager(ssh).add_client(
                        proto_conf["server_public_key"], client_ip, client_name
                    )
                clients[client_id] = {
                    "id": client_id,
                    "name": client_name,
                    "ip": client_ip,
                    "public_key": keys["public_key"],
                    "private_key": keys["private_key"],
                    "preshared_key": keys["preshared_key"],
                    "enabled": True,
                    "source": "panel",
                    "created_at": now_iso(),
                    "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
                    "traffic_rx": 0,
                    "traffic_tx": 0,
                    "last_seen": None,
                }

            elif protocol == "xray":
                info = XrayManager(ssh).add_client(client_name)
                clients[client_id] = {
                    "id": client_id,
                    "name": client_name,
                    "xray_id": info["id"],
                    "enabled": True,
                    "source": "panel",
                    "created_at": now_iso(),
                    "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
                    "traffic_rx": 0,
                    "traffic_tx": 0,
                    "last_seen": None,
                }

            elif protocol == "openvpn":
                safe_name = client_name.replace(" ", "_")
                info = OpenVPNManager(ssh).add_client(client_name)
                clients[client_id] = {
                    "id": client_id,
                    "name": client_name,
                    "safe_name": safe_name,
                    "enabled": True,
                    "source": "panel",
                    "created_at": now_iso(),
                    "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
                    "traffic_rx": 0,
                    "traffic_tx": 0,
                    "last_seen": None,
                    "ovpn_config": info.get("config", ""),
                }

    except Exception as e:
        logger.exception("Add client error")
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "client_id": client_id})


@app.delete("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}")
async def remove_client(request: Request, server_id: str, protocol: str, client_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol == "awg":
                AWGManager(ssh).remove_client(client["public_key"])
            elif protocol == "wireguard":
                WireGuardManager(ssh).remove_client(client["public_key"])
            elif protocol == "xray":
                XrayManager(ssh).remove_client(client["xray_id"])
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
    ssh = _make_ssh(server)
    try:
        with ssh:
            if protocol == "awg":
                AWGManager(ssh).toggle_client(client["public_key"], enabled)
            elif protocol == "wireguard":
                WireGuardManager(ssh).toggle_client(client["public_key"], enabled)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    client["enabled"] = enabled
    await save_data(data)
    return JSONResponse({"success": True, "enabled": enabled})


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
        config_text = AWGManager(None).build_client_conf(client, {**proto_conf, "host": server["host"]})
        filename = f"awg_{client['name']}.conf"
    elif protocol == "wireguard":
        config_text = WireGuardManager(None).build_client_conf(client, {**proto_conf, "host": server["host"]})
        filename = f"wg_{client['name']}.conf"
    elif protocol == "xray":
        config_text = XrayManager(None).build_client_url(client, {**proto_conf, "host": server["host"]})
        filename = f"xray_{client['name']}.txt"
    elif protocol == "openvpn":
        config_text = client.get("ovpn_config", "")
        filename = f"{client['name']}.ovpn"
    else:
        raise HTTPException(400)

    return Response(
        content=config_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
    elif protocol == "xray":
        text = XrayManager(None).build_client_url(client, {**proto_conf, "host": server["host"]})
    else:
        raise HTTPException(400, "QR not supported for this protocol")

    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ─── Routes: Traffic Sync ─────────────────────────────────────────────────────

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
            for protocol in ["awg", "wireguard"]:
                if not server["protocols"][protocol].get("installed"):
                    continue
                if protocol == "awg":
                    traffic = AWGManager(ssh).get_traffic()
                else:
                    traffic = WireGuardManager(ssh).get_traffic()

                for client in server["clients"].get(protocol, {}).values():
                    pub_key = client.get("public_key", "")
                    if pub_key in traffic:
                        t = traffic[pub_key]
                        client["traffic_rx"] = t["rx"]
                        client["traffic_tx"] = t["tx"]
                        if t["last_seen"]:
                            client["last_seen"] = datetime.fromtimestamp(
                                t["last_seen"], tz=timezone.utc
                            ).isoformat()
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True})


@app.post("/api/servers/{server_id}/detect-external")
async def detect_external_clients(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    external = {}
    ssh = _make_ssh(server)
    try:
        with ssh:
            for protocol in ["awg", "wireguard"]:
                if not server["protocols"][protocol].get("installed"):
                    continue
                if protocol == "awg":
                    live_peers = AWGManager(ssh).get_live_peers()
                else:
                    live_peers = WireGuardManager(ssh).get_live_peers()

                known_keys = {
                    c["public_key"]
                    for c in server["clients"].get(protocol, {}).values()
                    if c.get("public_key")
                }
                ext_peers = [p for p in live_peers if p and p not in known_keys]
                if ext_peers:
                    external[protocol] = ext_peers
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    return JSONResponse({"success": True, "external": external})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/{public_key}/import")
async def import_external_client(
    request: Request, server_id: str, protocol: str, public_key: str
):
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
        "private_key": "",
        "preshared_key": "",
        "ip": body.get("ip", ""),
        "enabled": True,
        "source": "amnezia_app",
        "created_at": now_iso(),
        "traffic_limit_bytes": 0,
        "traffic_rx": 0,
        "traffic_tx": 0,
        "last_seen": None,
    }
    await save_data(data)
    return JSONResponse({"success": True, "client_id": client_id})


# ─── Routes: Settings ─────────────────────────────────────────────────────────

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

    current = body.get("current_password", "")
    new_pw = body.get("new_password", "")

    if not bcrypt.checkpw(current.encode(), data["panel"]["admin_password_hash"].encode()):
        return JSONResponse({"success": False, "error": "رمز عبور فعلی اشتباه است"})

    if len(new_pw) < 8:
        return JSONResponse({"success": False, "error": "رمز عبور باید حداقل ۸ کاراکتر باشد"})

    data["panel"]["admin_password_hash"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    await save_data(data)
    return JSONResponse({"success": True})


# ─── Background task: auto traffic sync ──────────────────────────────────────

async def _auto_sync():
    while True:
        await asyncio.sleep(600)
        try:
            data = await load_data()
            for server in list(data["servers"].values()):
                ssh = _make_ssh(server)
                try:
                    with ssh:
                        for protocol in ["awg", "wireguard"]:
                            if not server["protocols"][protocol].get("installed"):
                                continue
                            if protocol == "awg":
                                traffic = AWGManager(ssh).get_traffic()
                            else:
                                traffic = WireGuardManager(ssh).get_traffic()
                            for client in server["clients"].get(protocol, {}).values():
                                pub_key = client.get("public_key", "")
                                if pub_key in traffic:
                                    t = traffic[pub_key]
                                    client["traffic_rx"] = t["rx"]
                                    client["traffic_tx"] = t["tx"]
                                    if t["last_seen"]:
                                        client["last_seen"] = datetime.fromtimestamp(
                                            t["last_seen"], tz=timezone.utc
                                        ).isoformat()
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
