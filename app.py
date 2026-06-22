import asyncio
import base64
import csv
import io
import json
import logging
import os
import secrets
import signal
import subprocess
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

import bcrypt
import qrcode
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import (
    HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.middleware.sessions import SessionMiddleware

from managers.ssh_manager import SSHManager
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager
from managers.xray_manager import XrayManager, PROTO_TO_ITYPE
from managers.openvpn_manager import OpenVPNManager
from models import (
    AddServerRequest, InstallProtocolRequest, AddClientRequest,
    BulkCreateRequest, UpdateClientRequest, ImportExternalRequest,
    ChangePasswordRequest,
)
from utils import parse_wg_dump
import crypto

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VERSION = "2.0.0"
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_FILE = DATA_DIR / "data.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_LOCK = asyncio.Lock()
INSTALL_TASKS: dict[str, dict] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 300  # 5 minutes


@asynccontextmanager
async def lifespan(application: FastAPI):
    asyncio.create_task(_auto_sync())
    yield


app = FastAPI(title="Amnezia Web Panel", version=VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    secret_file = DATA_DIR / ".secret_key"
    if secret_file.exists():
        SECRET_KEY = secret_file.read_text().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        secret_file.write_text(SECRET_KEY)
        os.chmod(secret_file, 0o600)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=86400 * 30)

ALL_PROTOCOLS = ["awg", "wireguard", "xray", "xray_ws", "xray_grpc", "xray_vmess", "xray_trojan", "xray_ss", "openvpn"]
XRAY_PROTOCOLS = {"xray", "xray_ws", "xray_grpc", "xray_vmess", "xray_trojan", "xray_ss"}
SUPPORTED_LANGS = ["en", "fa", "ru", "zh"]

# ── Translations ──────────────────────────────────────────────────────────────
TRANSLATIONS: dict[str, dict] = {}
for _lang in SUPPORTED_LANGS:
    _p = Path(f"translations/{_lang}.json")
    TRANSLATIONS[_lang] = json.loads(_p.read_text(encoding="utf-8")) if _p.exists() else {}


def get_t(request: Request) -> dict:
    lang = request.session.get("lang", "en")
    return TRANSLATIONS.get(lang, TRANSLATIONS.get("en", {}))


def get_lang(request: Request) -> str:
    return request.session.get("lang", "en")


# ── Data helpers ──────────────────────────────────────────────────────────────

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
    try:
        async with DATA_LOCK:
            return json.loads(DATA_FILE.read_text())
    except json.JSONDecodeError as e:
        logger.error("Failed to parse data.json: %s", e)
        data = _default_data()
        await save_data(data)
        return data
    except Exception as e:
        logger.exception("Failed to load data")
        raise


async def save_data(data: dict):
    async with DATA_LOCK:
        try:
            DATA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.exception("Failed to save data")
            raise


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def bytes_to_human(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _make_ssh(server: dict) -> SSHManager:
    password = None
    pw_raw = server.get("password_b64", "")
    if pw_raw:
        try:
            password = crypto.decrypt(pw_raw)
        except Exception:
            # Fallback: try base64 decode for legacy data
            import base64 as _b64
            try:
                password = _b64.b64decode(pw_raw).decode()
            except Exception:
                password = ""
    return SSHManager(
        host=server["host"],
        port=server.get("ssh_port", 22),
        username=server["username"],
        password=password,
        key_data=server.get("ssh_key"),
    )


def _ensure_protocols(server: dict):
    server.setdefault("protocols", {})
    server.setdefault("clients", {})
    for p in ALL_PROTOCOLS:
        server["protocols"].setdefault(p, {"installed": False})
        server["clients"].setdefault(p, {})


def _default_port(protocol: str) -> int:
    return {"xray": 443, "xray_ws": 8443, "xray_grpc": 8444,
            "xray_vmess": 8080, "xray_trojan": 443, "xray_ss": 54321}.get(protocol, 443)


def _task_log(task_id: str, msg: str) -> None:
    if task_id in INSTALL_TASKS:
        INSTALL_TASKS[task_id]["logs"].append(msg)


# ── Auth ──────────────────────────────────────────────────────────────────────

def require_auth(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(302, headers={"Location": "/login"})


def is_auth(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


_BCP47 = {"en": "en", "fa": "fa", "ru": "ru", "zh": "zh-Hans"}


def render(request: Request, tpl: str, **ctx):
    lang = get_lang(request)
    t = get_t(request)
    is_rtl = t.get("dir", "ltr") == "rtl"
    return templates.TemplateResponse(tpl, {
        "request": request, "version": VERSION,
        "bytes_to_human": bytes_to_human,
        "now_iso": now_iso,
        "t": t, "lang": lang, "is_rtl": is_rtl,
        "bcp47_lang": _BCP47.get(lang, "en"),
        "supported_langs": SUPPORTED_LANGS,
        "lang_names": {l: TRANSLATIONS.get(l, {}).get("lang_name", l.upper()) for l in SUPPORTED_LANGS},
        **ctx
    })


# ── WG dump helpers ───────────────────────────────────────────────────────────

def _parse_wg_conf_peers(conf: str) -> list[str]:
    return [l.split("=", 1)[1].strip() for l in conf.split("\n")
            if l.strip().startswith("PublicKey")]


# ── Language ──────────────────────────────────────────────────────────────────

@app.get("/api/language/{lang}")
async def switch_language(request: Request, lang: str):
    if lang in SUPPORTED_LANGS:
        request.session["lang"] = lang
    ref = request.headers.get("referer", "/")
    return RedirectResponse(ref, status_code=302)


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_auth(request):
        return RedirectResponse("/", status_code=302)
    return render(request, "login.html")


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Rate limiting: clean old attempts and check limit
    LOGIN_ATTEMPTS[client_ip] = [t for t in LOGIN_ATTEMPTS[client_ip] if now - t < LOGIN_WINDOW]
    if len(LOGIN_ATTEMPTS[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        return render(request, "login.html", error=True, 
                      message="Too many login attempts. Please try again later.")
    
    data = await load_data()
    panel = data["panel"]
    if username == panel["admin_username"] and bcrypt.checkpw(
        password.encode(), panel["admin_password_hash"].encode()
    ):
        LOGIN_ATTEMPTS.pop(client_ip, None)
        request.session["authenticated"] = True
        return RedirectResponse("/", status_code=302)
    
    LOGIN_ATTEMPTS[client_ip].append(now)
    return render(request, "login.html", error=True)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_auth(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    servers = list(data["servers"].values())
    for s in servers:
        _ensure_protocols(s)

    # Compute quick stats
    total_users = sum(
        sum(len(pc) for pc in s["clients"].values())
        for s in servers
    )
    active_protos = sum(
        sum(1 for v in s["protocols"].values() if v.get("installed"))
        for s in servers
    )
    return render(request, "index.html", servers=servers,
                  total_users=total_users, active_protos=active_protos)


# ── Server routes ─────────────────────────────────────────────────────────────

@app.get("/server/{server_id}", response_class=HTMLResponse)
async def server_detail(request: Request, server_id: str):
    if not is_auth(request):
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
    try:
        body = AddServerRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=422)
    sid = str(uuid.uuid4())
    pw_encrypted = crypto.encrypt(body.password) if body.password else ""
    server = {
        "id": sid, "name": body.name or body.host,
        "host": body.host, "ssh_port": body.ssh_port,
        "username": body.username,
        "password_b64": pw_encrypted, "ssh_key": body.ssh_key,
        "created_at": now_iso(),
        "protocols": {p: {"installed": False} for p in ALL_PROTOCOLS},
        "clients":   {p: {} for p in ALL_PROTOCOLS},
    }
    result = _make_ssh(server).test_connection()
    if not result["success"]:
        return JSONResponse({"success": False, "error": result.get("error", "Connection failed")})
    data = await load_data()
    data["servers"][sid] = server
    await save_data(data)
    return JSONResponse({"success": True, "server_id": sid})


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
    try:
        with _make_ssh(server) as ssh:
            ssh.run_sudo("reboot || shutdown -r now &")
    except Exception:
        pass
    return JSONResponse({"success": True})


# ── Task system ───────────────────────────────────────────────────────────────

@app.get("/api/tasks/{task_id}")
async def get_task(request: Request, task_id: str):
    require_auth(request)
    task = INSTALL_TASKS.get(task_id)
    if not task:
        raise HTTPException(404)
    return JSONResponse(task)


async def _run_install_bg(task_id: str, server_id: str, protocol: str, body: dict):
    def log(msg: str):
        _task_log(task_id, msg)
    loop = asyncio.get_event_loop()
    try:
        data = await load_data()
        server = data["servers"].get(server_id)
        if not server:
            raise ValueError("Server not found")
        _ensure_protocols(server)

        def do_install():
            ssh = _make_ssh(server)
            with ssh:
                if protocol == "awg":
                    return AWGManager(ssh).install(
                        port=int(body.get("port", 51820)),
                        subnet=body.get("subnet", "10.8.1.0/24"),
                        dns=body.get("dns", "1.1.1.1"),
                        progress=log,
                    )
                elif protocol == "wireguard":
                    return WireGuardManager(ssh).install(
                        port=int(body.get("port", 51820)),
                        subnet=body.get("subnet", "10.8.0.0/24"),
                        dns=body.get("dns", "1.1.1.1"),
                        progress=log,
                    )
                elif protocol in XRAY_PROTOCOLS:
                    itype = PROTO_TO_ITYPE[protocol]
                    extra: dict = {}
                    if itype == "vless-reality":
                        extra["dest_domain"] = body.get("dest_domain", "www.microsoft.com")
                    elif itype in ("vless-ws", "vmess-ws"):
                        extra["path"] = body.get("path", f"/{itype.split('-')[0]}")
                    elif itype == "vless-grpc":
                        extra["service_name"] = body.get("service_name", "grpc")
                    return XrayManager(ssh).add_inbound(
                        itype, int(body.get("port", _default_port(protocol))),
                        progress=log, **extra
                    )
                elif protocol == "openvpn":
                    return OpenVPNManager(ssh).install(
                        port=int(body.get("port", 1194)),
                        dns=body.get("dns", "1.1.1.1"),
                        progress=log,
                    )
                raise ValueError(f"Unknown protocol: {protocol}")

        result = await loop.run_in_executor(None, do_install)
        server["protocols"][protocol] = {"installed": True, "host": server["host"], **result}
        await save_data(data)
        INSTALL_TASKS[task_id].update({"done": True, "success": True})
    except Exception as e:
        logger.exception("Install task failed")
        INSTALL_TASKS[task_id].update({"done": True, "success": False, "error": str(e)})


@app.post("/api/servers/{server_id}/protocols/{protocol}/install")
async def install_protocol(request: Request, server_id: str, protocol: str):
    require_auth(request)
    body = await request.json()
    task_id = str(uuid.uuid4())
    INSTALL_TASKS[task_id] = {"status": "running", "logs": [], "done": False, "success": None}
    asyncio.create_task(_run_install_bg(task_id, server_id, protocol, body))
    return JSONResponse({"success": True, "task_id": task_id})


@app.post("/api/servers/{server_id}/protocols/{protocol}/uninstall")
async def uninstall_protocol(request: Request, server_id: str, protocol: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    try:
        with _make_ssh(server) as ssh:
            if protocol == "awg":
                AWGManager(ssh).uninstall()
            elif protocol == "wireguard":
                WireGuardManager(ssh).uninstall()
            elif protocol in XRAY_PROTOCOLS:
                inbound_id = server["protocols"][protocol].get("id", "")
                mgr = XrayManager(ssh)
                if inbound_id:
                    mgr.remove_inbound(inbound_id)
                remaining = [k for k, v in server["protocols"].items()
                             if k in XRAY_PROTOCOLS and k != protocol and v.get("installed")]
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


# ── Client management ─────────────────────────────────────────────────────────

def _next_ip(proto_conf: dict, clients: dict) -> str:
    subnet = proto_conf.get("subnet", "10.8.1.0/24")
    parts = subnet.split("/")
    base_parts = parts[0].rsplit(".", 1)[0]
    cidr = int(parts[1]) if len(parts) > 1 else 24
    max_hosts = 2 ** (32 - cidr) - 2
    used = {c["ip"] for c in clients.values() if c.get("ip")}
    for i in range(2, min(max_hosts + 2, 254)):
        ip = f"{base_parts}.{i}"
        if ip not in used:
            return ip
    raise ValueError("IP pool exhausted")


def _wg_client(cid, name, ip, keys, body, expires_at=None):
    return {
        "id": cid, "name": name, "ip": ip,
        "email": body.get("email", ""),
        "notes": body.get("notes", ""),
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
        "preshared_key": keys["preshared_key"],
        "enabled": True, "source": "panel", "created_at": now_iso(),
        "expires_at": expires_at,
        "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
    }


def _compute_expires_at(body: dict) -> str | None:
    """Compute expires_at from body fields."""
    if body.get("expires_at"):
        return body["expires_at"]
    validity_days = int(body.get("validity_days", 0))
    if validity_days > 0:
        return (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat()
    return None


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients")
async def add_client(request: Request, server_id: str, protocol: str):
    require_auth(request)
    try:
        body = AddClientRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=422)
    client_name = body.name or f"user_{secrets.token_hex(3)}"

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)

    if not server["protocols"][protocol].get("installed"):
        return JSONResponse({"success": False, "error": "Protocol not installed"})

    proto_conf = server["protocols"][protocol]
    clients = server["clients"].setdefault(protocol, {})
    cid = str(uuid.uuid4())
    expires_at = _compute_expires_at(body.dict())

    try:
        with _make_ssh(server) as ssh:
            if protocol == "awg":
                ip = body.ip or _next_ip(proto_conf, clients)
                keys = AWGManager(ssh).add_client(proto_conf, client_name, ip)
                clients[cid] = _wg_client(cid, client_name, ip, keys, body.dict(), expires_at)

            elif protocol == "wireguard":
                ip = body.ip or _next_ip(proto_conf, clients)
                keys = WireGuardManager(ssh).add_client(proto_conf["server_public_key"], ip, client_name)
                clients[cid] = _wg_client(cid, client_name, ip, keys, body.dict(), expires_at)

            elif protocol in XRAY_PROTOCOLS:
                itype = PROTO_TO_ITYPE[protocol]
                info = XrayManager(ssh).add_client(proto_conf["id"], itype, client_name)
                clients[cid] = {
                    "id": cid, "name": client_name,
                    "email": body.email, "notes": body.notes,
                    "xray_id": info.get("id", ""), "password": info.get("password", ""),
                    "inbound_id": proto_conf["id"], "inbound_type": itype,
                    "enabled": True, "source": "panel", "created_at": now_iso(),
                    "expires_at": expires_at,
                    "traffic_limit_bytes": body.traffic_limit_gb * 1024 ** 3,
                    "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
                }

            elif protocol == "openvpn":
                info = OpenVPNManager(ssh).add_client(client_name)
                clients[cid] = {
                    "id": cid, "name": client_name,
                    "email": body.email, "notes": body.notes,
                    "safe_name": client_name.replace(" ", "_"),
                    "enabled": True, "source": "panel", "created_at": now_iso(),
                    "expires_at": expires_at,
                    "traffic_limit_bytes": body.traffic_limit_gb * 1024 ** 3,
                    "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
                    "ovpn_config": info.get("config", ""),
                }

    except Exception as e:
        logger.exception("Add client error")
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "client_id": cid})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/bulk")
async def bulk_create_clients(request: Request, server_id: str, protocol: str):
    require_auth(request)
    body = await request.json()
    count = min(int(body.get("count", 1)), 100)
    prefix = body.get("prefix", "user")

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)
    if not server["protocols"][protocol].get("installed"):
        return JSONResponse({"success": False, "error": "Protocol not installed"})

    created = []
    errors = []
    proto_conf = server["protocols"][protocol]
    clients = server["clients"].setdefault(protocol, {})
    expires_at = _compute_expires_at(body)

    try:
        with _make_ssh(server) as ssh:
            for i in range(1, count + 1):
                cid = str(uuid.uuid4())
                name = f"{prefix}{i}"
                try:
                    if protocol == "awg":
                        ip = _next_ip(proto_conf, clients)
                        keys = AWGManager(ssh).add_client(proto_conf, name, ip)
                        clients[cid] = _wg_client(cid, name, ip, keys, body, expires_at)
                    elif protocol == "wireguard":
                        ip = _next_ip(proto_conf, clients)
                        keys = WireGuardManager(ssh).add_client(proto_conf["server_public_key"], ip, name)
                        clients[cid] = _wg_client(cid, name, ip, keys, body, expires_at)
                    elif protocol in XRAY_PROTOCOLS:
                        itype = PROTO_TO_ITYPE[protocol]
                        info = XrayManager(ssh).add_client(proto_conf["id"], itype, name)
                        clients[cid] = {
                            "id": cid, "name": name, "email": "", "notes": "",
                            "xray_id": info.get("id", ""), "password": info.get("password", ""),
                            "inbound_id": proto_conf["id"], "inbound_type": itype,
                            "enabled": True, "source": "panel", "created_at": now_iso(),
                            "expires_at": expires_at,
                            "traffic_limit_bytes": int(body.get("traffic_limit_gb", 0)) * 1024 ** 3,
                            "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
                        }
                    created.append(name)
                except Exception as e:
                    errors.append(f"{name}: {e}")
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "created": len(created), "errors": errors})


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

    try:
        with _make_ssh(server) as ssh:
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
        try:
            with _make_ssh(server) as ssh:
                if protocol == "awg":
                    AWGManager(ssh).toggle_client(client["public_key"], enabled)
                else:
                    WireGuardManager(ssh).toggle_client(client["public_key"], enabled)
        except Exception as e:
            return JSONResponse({"success": False, "error": str(e)})

    client["enabled"] = enabled
    await save_data(data)
    return JSONResponse({"success": True, "enabled": enabled})


@app.put("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}")
async def update_client(request: Request, server_id: str, protocol: str, client_id: str):
    """Update client metadata: name, notes, email, expires_at, traffic_limit_bytes."""
    require_auth(request)
    body = await request.json()
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404)

    if "name" in body:
        client["name"] = body["name"]
    if "notes" in body:
        client["notes"] = body["notes"]
    if "email" in body:
        client["email"] = body["email"]
    if "expires_at" in body:
        client["expires_at"] = body["expires_at"] or None
    if "traffic_limit_gb" in body:
        client["traffic_limit_bytes"] = int(body["traffic_limit_gb"]) * 1024 ** 3

    await save_data(data)
    return JSONResponse({"success": True})


# ── Config & QR ───────────────────────────────────────────────────────────────

def _build_config_text(client: dict, protocol: str, proto_conf: dict, server_host: str) -> str | None:
    if protocol == "awg":
        if not client.get("private_key"):
            return None
        return AWGManager(None).build_client_conf(client, {**proto_conf, "host": server_host})
    elif protocol == "wireguard":
        if not client.get("private_key"):
            return None
        return WireGuardManager(None).build_client_conf(client, {**proto_conf, "host": server_host})
    elif protocol in XRAY_PROTOCOLS:
        itype = PROTO_TO_ITYPE[protocol]
        return XrayManager(None).build_client_url(client, {**proto_conf, "type": itype}, server_host)
    elif protocol == "openvpn":
        return client.get("ovpn_config")
    return None


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

    text = _build_config_text(client, protocol, server["protocols"].get(protocol, {}), server["host"])
    if text is None:
        return JSONResponse({"success": False, "error": "Config not available for Amnezia App clients"}, status_code=422)

    ext = {"awg": "conf", "wireguard": "conf", "openvpn": "ovpn"}.get(protocol, "txt")
    fname = f"{protocol}_{client['name']}.{ext}"
    return Response(content=text, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


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

    text = _build_config_text(client, protocol, server["protocols"].get(protocol, {}), server["host"])
    if text is None:
        raise HTTPException(422, "QR not available")

    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/servers/{server_id}/protocols/{protocol}/clients/export")
async def export_clients(request: Request, server_id: str, protocol: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    clients = server["clients"].get(protocol, {})
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=[
        "name", "email", "notes", "ip", "enabled", "source",
        "created_at", "expires_at",
        "traffic_limit_gb", "traffic_rx_mb", "traffic_tx_mb", "last_seen"
    ])
    writer.writeheader()
    for c in clients.values():
        writer.writerow({
            "name": c.get("name", ""),
            "email": c.get("email", ""),
            "notes": c.get("notes", ""),
            "ip": c.get("ip", ""),
            "enabled": c.get("enabled", True),
            "source": c.get("source", ""),
            "created_at": c.get("created_at", "")[:10],
            "expires_at": (c.get("expires_at") or "")[:10],
            "traffic_limit_gb": round(c.get("traffic_limit_bytes", 0) / 1024**3, 2),
            "traffic_rx_mb": round(c.get("traffic_rx", 0) / 1024**2, 2),
            "traffic_tx_mb": round(c.get("traffic_tx", 0) / 1024**2, 2),
            "last_seen": (c.get("last_seen") or "")[:10],
        })

    fname = f"{server['name']}_{protocol}_users.csv"
    return Response(content=out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ── Traffic sync ──────────────────────────────────────────────────────────────

def _collect_traffic_from_server(ssh: 'SSHManager') -> dict:
    """Collect WireGuard/AmneziaWG traffic from native and Docker sources."""
    all_traffic: dict = {}

    # 1. Native wg/awg
    out, _, code = ssh.run_sudo("wg show all dump 2>/dev/null")
    if code == 0 and out.strip():
        all_traffic.update(parse_wg_dump(out))

    # 2. Docker containers
    out2, _, _ = ssh.run_sudo("docker ps --format '{{.Names}}' 2>/dev/null")
    for cname in out2.strip().split("\n"):
        cname = cname.strip()
        if not cname:
            continue
        if any(k in cname.lower() for k in ["awg", "wireguard", "amnezia", "wg"]):
            for cmd in ["awg show all dump", "wg show all dump"]:
                out3, _, rc = ssh.run_sudo(f"docker exec {cname} {cmd} 2>/dev/null")
                if rc == 0 and out3.strip():
                    all_traffic.update(parse_wg_dump(out3))
                    break

    return all_traffic


def _apply_traffic_to_clients(server: dict, all_traffic: dict) -> bool:
    """Apply traffic data to WG/AWG clients. Returns True if any changes."""
    changed = False
    for proto in ["awg", "wireguard"]:
        for client in server["clients"].get(proto, {}).values():
            t = all_traffic.get(client.get("public_key", ""))
            if t:
                client["traffic_rx"] = t["rx"]
                client["traffic_tx"] = t["tx"]
                if t["last_seen"]:
                    client["last_seen"] = datetime.fromtimestamp(
                        t["last_seen"], tz=timezone.utc
                    ).isoformat()
                changed = True
    return changed


@app.post("/api/servers/{server_id}/sync-traffic")
async def sync_traffic(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    try:
        with _make_ssh(server) as ssh:
            all_traffic = _collect_traffic_from_server(ssh)
            _apply_traffic_to_clients(server, all_traffic)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True})


# ── Detect external Amnezia configs ───────────────────────────────────────────

@app.post("/api/servers/{server_id}/detect-external")
async def detect_external(request: Request, server_id: str):
    require_auth(request)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)

    known_keys: set[str] = set()
    for pc in server["clients"].values():
        for c in pc.values():
            if isinstance(c, dict) and c.get("public_key"):
                known_keys.add(c["public_key"])

    detected: dict[str, list[str]] = {}

    try:
        with _make_ssh(server) as ssh:
            # Native wg
            out, _, code = ssh.run_sudo("wg show all dump 2>/dev/null")
            if code == 0:
                new = [p for p in parse_wg_dump(out) if p not in known_keys]
                if new:
                    detected["wireguard"] = new

            # Amnezia config files
            for path in ["/opt/amnezia/awg/wg0.conf", "/opt/amnezia/wireguard/wg0.conf"]:
                try:
                    new = [p for p in _parse_wg_conf_peers(ssh.download_file(path)) if p not in known_keys]
                    if new:
                        detected.setdefault("awg", []).extend(new)
                except Exception:
                    pass

            # Docker containers
            out2, _, _ = ssh.run_sudo("docker ps --format '{{.Names}}' 2>/dev/null")
            for cname in out2.strip().split("\n"):
                cname = cname.strip()
                if not cname or not any(k in cname.lower() for k in ["awg", "wireguard", "amnezia", "wg"]):
                    continue
                for cmd in ["awg show all dump", "wg show all dump"]:
                    out3, _, rc = ssh.run_sudo(f"docker exec {cname} {cmd} 2>/dev/null")
                    if rc == 0 and out3.strip():
                        new = [p for p in parse_wg_dump(out3) if p not in known_keys]
                        if new:
                            detected.setdefault("awg", []).extend(new)
                        break
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    for k in detected:
        detected[k] = list(dict.fromkeys(detected[k]))

    return JSONResponse({"success": True, "external": detected,
                         "total": sum(len(v) for v in detected.values())})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/{public_key}/import")
async def import_external(request: Request, server_id: str, protocol: str, public_key: str):
    require_auth(request)
    body = await request.json()
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)
    cid = str(uuid.uuid4())
    server["clients"].setdefault(protocol, {})[cid] = {
        "id": cid,
        "name": body.get("name", f"Amnezia ({public_key[:8]})"),
        "email": "", "notes": "",
        "public_key": public_key,
        "private_key": "", "preshared_key": "", "ip": "",
        "enabled": True, "source": "amnezia_app", "created_at": now_iso(),
        "expires_at": None, "traffic_limit_bytes": 0,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
    }
    await save_data(data)
    return JSONResponse({"success": True, "client_id": cid})


# ── Settings ──────────────────────────────────────────────────────────────────

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    if not is_auth(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    return render(request, "settings.html", panel=data["panel"])


@app.post("/api/settings/password")
async def change_password(request: Request):
    require_auth(request)
    try:
        body = ChangePasswordRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=422)
    data = await load_data()
    if not bcrypt.checkpw(body.current_password.encode(),
                          data["panel"]["admin_password_hash"].encode()):
        return JSONResponse({"success": False, "error": "Current password is incorrect"})
    data["panel"]["admin_password_hash"] = bcrypt.hashpw(body.new_password.encode(), bcrypt.gensalt()).decode()
    await save_data(data)
    return JSONResponse({"success": True})


# ── Self-update ───────────────────────────────────────────────────────────────

@app.post("/api/update")
async def update_panel(request: Request):
    require_auth(request)
    try:
        result = subprocess.run(["git", "-C", "/app", "pull"],
                                capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return JSONResponse({"success": False, "error": result.stderr.strip() or "git pull failed"})
        output = result.stdout.strip()
        if "Already up to date" in output:
            return JSONResponse({"success": True, "message": "Already up to date.", "restarting": False})

        needs_rebuild = "requirements.txt" in output

        async def _restart():
            await asyncio.sleep(2)
            os.kill(os.getpid(), signal.SIGTERM)

        asyncio.create_task(_restart())
        msg = output
        if needs_rebuild:
            msg += "\n\n⚠️  requirements.txt changed. Run: docker compose up -d --build"

        return JSONResponse({"success": True, "message": msg,
                             "restarting": not needs_rebuild, "needs_rebuild": needs_rebuild})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})


@app.get("/api/version")
async def get_version(request: Request):
    require_auth(request)
    try:
        r = subprocess.run(["git", "-C", "/app", "log", "-1", "--format=%h %s"],
                           capture_output=True, text=True, timeout=10)
        commit = r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:
        commit = "unknown"
    return JSONResponse({"version": VERSION, "commit": commit})


# ── Background: traffic sync + expiry enforcement ─────────────────────────────

async def _auto_sync():
    while True:
        await asyncio.sleep(600)
        try:
            data = await load_data()
            now = datetime.now(timezone.utc)
            changed = False

            for server in list(data["servers"].values()):
                ssh = _make_ssh(server)
                try:
                    with ssh:
                        all_traffic = _collect_traffic_from_server(ssh)
                        if _apply_traffic_to_clients(server, all_traffic):
                            changed = True

                        # Expiry enforcement
                        for proto in ALL_PROTOCOLS:
                            for client in server["clients"].get(proto, {}).values():
                                if client.get("expires_at") and client.get("enabled"):
                                    try:
                                        exp = datetime.fromisoformat(client["expires_at"])
                                        if exp.tzinfo is None:
                                            exp = exp.replace(tzinfo=timezone.utc)
                                        if now > exp:
                                            client["enabled"] = False
                                            changed = True
                                    except ValueError:
                                        pass

                except Exception:
                    pass

            if changed:
                await save_data(data)
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PANEL_PORT", 54325)), reload=False)
