"""Amnezia Web Panel — main FastAPI application (v2.1)."""
import asyncio
import base64
import csv
import io
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import time
import uuid
from collections import defaultdict, OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

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
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from managers.ssh_manager import SSHManager
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager
from managers.xray_manager import XrayManager, PROTO_TO_ITYPE
from managers.openvpn_manager import OpenVPNManager
from models import (
    AddServerRequest, UpdateServerRequest, InstallProtocolRequest, AddClientRequest,
    BulkCreateRequest, UpdateClientRequest, ImportExternalRequest,
    ChangePasswordRequest,
)
from utils import parse_wg_dump
import crypto

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VERSION = "2.1.0"
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_FILE = DATA_DIR / "data.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_LOCK = asyncio.Lock()
INSTALL_TASKS: "OrderedDict[str, dict]" = OrderedDict()
INSTALL_TASK_TTL = 3600  # 1 hour

LOGIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 300  # 5 minutes

API_RATE_LIMIT = 60  # requests per minute per IP
API_RATE_WINDOW = 60
API_RATE_HITS: dict[str, list[float]] = defaultdict(list)

MAX_BODY_SIZE = 64 * 1024  # 64 KB max request body

# Regex for validating WireGuard public keys (base64, 32 bytes)
_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan / startup
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(application: FastAPI):
    asyncio.create_task(_auto_sync())
    asyncio.create_task(_cleanup_tasks_bg())
    yield


app = FastAPI(title="Amnezia Web Panel", version=VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    secret_file = DATA_DIR / ".secret_key"
    if secret_file.exists():
        try:
            SECRET_KEY = secret_file.read_text().strip()
        except PermissionError:
            logger.warning(
                "Cannot read %s (permission denied). Regenerating. "
                "Run on host: sudo chown -R 1000:1000 data/",
                secret_file,
            )
            try:
                os.unlink(secret_file)
            except PermissionError:
                logger.error(
                    "Cannot remove %s — run: sudo chown -R 1000:1000 data/",
                    secret_file,
                )
                raise
            SECRET_KEY = secrets.token_hex(32)
            secret_file.write_text(SECRET_KEY)
            try:
                os.chmod(secret_file, 0o600)
            except OSError:
                pass
    else:
        SECRET_KEY = secrets.token_hex(32)
        secret_file.write_text(SECRET_KEY)
        try:
            os.chmod(secret_file, 0o600)
        except OSError:
            pass

# ──────────────────────────────────────────────────────────────────────────────
# Middlewares: security headers + body size limit + rate limit + CSRF + session
# IMPORTANT: in Starlette, the LAST added middleware runs FIRST (outermost).
# We need SessionMiddleware to be outermost so request.session is available
# to all inner middlewares (CSRF, rate limit, etc.).
# So: add custom middlewares FIRST, then SessionMiddleware LAST.
# ──────────────────────────────────────────────────────────────────────────────



# ──────────────────────────────────────────────────────────────────────────────
# Middlewares: security headers + body size limit + CSRF
# ──────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add common security headers to every response."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        # CSP: allow inline (for templates) + self + data: images (QR codes)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject bodies larger than MAX_BODY_SIZE to prevent DoS."""
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_BODY_SIZE:
            return JSONResponse(
                {"success": False, "error": "Request body too large"},
                status_code=413,
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limit on /api/* endpoints.
    - Allows API_RATE_LIMIT requests per API_RATE_WINDOW seconds.
    - Exempts /api/tasks/{id} polling (uses higher separate budget) and static/login.
    - Returns 429 with Retry-After header when exceeded."""
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)

        # Identify client (IP, plus session id if available for behind-proxy accuracy)
        client_ip = request.client.host if request.client else "unknown"
        # Honor X-Forwarded-For if present (behind reverse proxy)
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            client_ip = fwd.split(",")[0].strip()

        # Polling endpoints get a separate, more generous budget
        if path.startswith("/api/tasks/"):
            limit = 120
            window = 60
            key = f"task:{client_ip}"
        else:
            limit = API_RATE_LIMIT
            window = API_RATE_WINDOW
            key = f"api:{client_ip}"

        now = time.time()
        hits = API_RATE_HITS[key]
        # Drop expired
        API_RATE_HITS[key] = [t for t in hits if now - t < window]
        if len(API_RATE_HITS[key]) >= limit:
            retry_after = int(window - (now - min(API_RATE_HITS[key])))
            return JSONResponse(
                {"success": False, "error": "Rate limit exceeded. Try again later."},
                status_code=429,
                headers={"Retry-After": str(max(retry_after, 1))},
            )
        API_RATE_HITS[key].append(now)
        # Periodic cleanup of stale keys (every ~1000 requests)
        if len(API_RATE_HITS) > 10000:
            stale = [k for k, v in API_RATE_HITS.items()
                     if not v or now - v[-1] > max(window, API_RATE_WINDOW) * 2]
            for k in stale:
                API_RATE_HITS.pop(k, None)

        return await call_next(request)



class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit CSRF protection.
    - On GET, ensures a csrf_token is in the session (used by templates).
    - On POST/PUT/DELETE to /api/*, validates X-CSRF-Token header against session.
    - /login is exempted (uses its own session + rate limit protection).
    """

    EXEMPT_PATHS = {"/login", "/logout", "/api/language"}

    async def dispatch(self, request: Request, call_next):
        # Ensure session has a csrf_token (for templates to use)
        session = request.session
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

        # Verify CSRF on state-changing requests to /api/*
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            path = request.url.path
            if path.startswith("/api/") and path not in self.EXEMPT_PATHS:
                session_token = session.get("csrf_token")
                header_token = request.headers.get("X-CSRF-Token")
                if not session_token or not header_token or session_token != header_token:
                    return JSONResponse(
                        {"success": False, "error": "CSRF validation failed"},
                        status_code=403,
                    )

        return await call_next(request)



app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=86400 * 30)



# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

ALL_PROTOCOLS = [
    "awg", "wireguard",
    "xray", "xray_ws", "xray_grpc", "xray_vmess", "xray_trojan", "xray_ss",
    "openvpn",
]
XRAY_PROTOCOLS = {"xray", "xray_ws", "xray_grpc", "xray_vmess", "xray_trojan", "xray_ss"}
SUPPORTED_LANGS = ["en", "fa", "ru", "zh"]

# ──────────────────────────────────────────────────────────────────────────────
# Translations
# ──────────────────────────────────────────────────────────────────────────────

TRANSLATIONS: dict[str, dict] = {}
for _lang in SUPPORTED_LANGS:
    _p = Path(f"translations/{_lang}.json")
    TRANSLATIONS[_lang] = json.loads(_p.read_text(encoding="utf-8")) if _p.exists() else {}


def get_t(request: Request) -> dict:
    lang = request.session.get("lang", "en")
    return TRANSLATIONS.get(lang, TRANSLATIONS.get("en", {}))


def get_lang(request: Request) -> str:
    return request.session.get("lang", "en")


# ──────────────────────────────────────────────────────────────────────────────
# Data helpers
# ──────────────────────────────────────────────────────────────────────────────

def _default_data() -> dict:
    # Fail-fast: do NOT default to "admin" password in production
    pw = os.getenv("ADMIN_PASSWORD")
    if not pw:
        # First-run with no env: generate random + log it once
        pw = secrets.token_urlsafe(12)
        logger.warning(
            "No ADMIN_PASSWORD set — generated random password: %s "
            "(set ADMIN_PASSWORD env var to override)", pw
        )
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
        # Backup corrupt file then start fresh
        backup = DATA_FILE.with_suffix(".json.corrupt")
        try:
            DATA_FILE.rename(backup)
            logger.warning("Backed up corrupt data.json to %s", backup)
        except Exception:
            pass
        data = _default_data()
        await save_data(data)
        return data
    except Exception:
        logger.exception("Failed to load data")
        raise


async def save_data(data: dict):
    async with DATA_LOCK:
        try:
            # Atomic write: temp file + rename
            tmp = DATA_FILE.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
            tmp.replace(DATA_FILE)
        except Exception:
            logger.exception("Failed to save data")
            raise


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def bytes_to_human(n: int) -> str:
    n = float(n or 0)
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
            # Legacy base64 fallback (warn, but allow)
            import base64 as _b64
            try:
                password = _b64.b64decode(pw_raw).decode()
                logger.warning("Server %s uses legacy base64 password — re-save to upgrade",
                               server.get("id"))
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


def _cleanup_old_tasks() -> None:
    """Remove INSTALL_TASKS entries older than INSTALL_TASK_TTL."""
    cutoff = time.time() - INSTALL_TASK_TTL
    to_remove = [
        tid for tid, t in INSTALL_TASKS.items()
        if t.get("done") and t.get("finished_at", 0) < cutoff
    ]
    for tid in to_remove:
        INSTALL_TASKS.pop(tid, None)
    if to_remove:
        logger.info("Cleaned up %d old install tasks", len(to_remove))


# ──────────────────────────────────────────────────────────────────────────────
# Auth
# ──────────────────────────────────────────────────────────────────────────────

def require_auth(request: Request):
    """For API endpoints — return 401 JSON instead of 302 redirect."""
    if not request.session.get("authenticated"):
        raise HTTPException(401, detail="Not authenticated")


def require_auth_html(request: Request):
    """For HTML page routes — redirect to /login."""
    if not request.session.get("authenticated"):
        return RedirectResponse("/login", status_code=302)
    return None


def is_auth(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


_BCP47 = {"en": "en", "fa": "fa", "ru": "ru", "zh": "zh-Hans"}


def render(request: Request, tpl: str, **ctx):
    lang = get_lang(request)
    t = get_t(request)
    is_rtl = t.get("dir", "ltr") == "rtl"
    csrf_token = request.session.get("csrf_token", "")
    return templates.TemplateResponse(tpl, {
        "request": request, "version": VERSION,
        "bytes_to_human": bytes_to_human,
        "now_iso": now_iso,
        "t": t, "lang": lang, "is_rtl": is_rtl,
        "bcp47_lang": _BCP47.get(lang, "en"),
        "supported_langs": SUPPORTED_LANGS,
        "lang_names": {l: TRANSLATIONS.get(l, {}).get("lang_name", l.upper())
                       for l in SUPPORTED_LANGS},
        "csrf_token": csrf_token,
        **ctx
    })


# ──────────────────────────────────────────────────────────────────────────────
# WG helpers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_wg_conf_peers(conf: str) -> list[str]:
    return [l.split("=", 1)[1].strip() for l in conf.split("\n")
            if l.strip().startswith("PublicKey")]


# ──────────────────────────────────────────────────────────────────────────────
# Language
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/language/{lang}")
async def switch_language(request: Request, lang: str):
    if lang in SUPPORTED_LANGS:
        request.session["lang"] = lang
    ref = request.headers.get("referer", "/")
    return RedirectResponse(ref, status_code=302)


# ──────────────────────────────────────────────────────────────────────────────
# Auth routes
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_auth(request):
        return RedirectResponse("/", status_code=302)
    return render(request, "login.html")


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    LOGIN_ATTEMPTS[client_ip] = [
        t for t in LOGIN_ATTEMPTS[client_ip] if now - t < LOGIN_WINDOW
    ]
    if len(LOGIN_ATTEMPTS[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        retry = int(LOGIN_WINDOW - (now - min(LOGIN_ATTEMPTS[client_ip])))
        return render(request, "login.html",
                      error=f"Too many login attempts. Try again in {retry}s.")

    data = await load_data()
    panel = data["panel"]
    if username == panel["admin_username"] and bcrypt.checkpw(
        password.encode(), panel["admin_password_hash"].encode()
    ):
        LOGIN_ATTEMPTS.pop(client_ip, None)
        request.session["authenticated"] = True
        # Issue CSRF token
        if "csrf_token" not in request.session:
            request.session["csrf_token"] = secrets.token_urlsafe(32)
        return RedirectResponse("/", status_code=302)

    LOGIN_ATTEMPTS[client_ip].append(now)
    return render(request, "login.html", error="Wrong username or password")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_auth(request):
        return RedirectResponse("/login", status_code=302)
    data = await load_data()
    servers = list(data["servers"].values())
    for s in servers:
        _ensure_protocols(s)

    total_users = sum(
        sum(len(pc) for pc in s["clients"].values())
        for s in servers
    )
    active_protos = sum(
        sum(1 for v in s["protocols"].values() if v.get("installed"))
        for s in servers
    )
    total_traffic = sum(
        c.get("traffic_rx", 0) + c.get("traffic_tx", 0)
        for s in servers
        for pc in s["clients"].values()
        for c in pc.values()
        if isinstance(c, dict)
    )
    return render(request, "index.html", servers=servers,
                  total_users=total_users, active_protos=active_protos,
                  total_traffic=total_traffic)


# ──────────────────────────────────────────────────────────────────────────────
# Server routes
# ──────────────────────────────────────────────────────────────────────────────

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
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)
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


@app.put("/api/servers/{server_id}")
async def update_server(request: Request, server_id: str):
    require_auth(request)
    try:
        body = UpdateServerRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    if body.name is not None:
        server["name"] = body.name
    if body.password:
        server["password_b64"] = crypto.encrypt(body.password)
    if body.ssh_key is not None:
        server["ssh_key"] = body.ssh_key
    await save_data(data)
    return JSONResponse({"success": True})


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
    except Exception as e:
        logger.warning("Reboot failed for %s: %s", server_id, e)
    return JSONResponse({"success": True})


# ──────────────────────────────────────────────────────────────────────────────
# Task system
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/tasks/{task_id}")
async def get_task(request: Request, task_id: str):
    require_auth(request)
    task = INSTALL_TASKS.get(task_id)
    if not task:
        raise HTTPException(404)
    return JSONResponse(task)


async def _run_install_bg(task_id: str, server_id: str, protocol: str, body_dict: dict):
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
                        port=int(body_dict.get("port", 51820)),
                        subnet=body_dict.get("subnet", "10.8.1.0/24"),
                        dns=body_dict.get("dns", "1.1.1.1"),
                        progress=log,
                    )
                elif protocol == "wireguard":
                    return WireGuardManager(ssh).install(
                        port=int(body_dict.get("port", 51820)),
                        subnet=body_dict.get("subnet", "10.8.0.0/24"),
                        dns=body_dict.get("dns", "1.1.1.1"),
                        progress=log,
                    )
                elif protocol in XRAY_PROTOCOLS:
                    itype = PROTO_TO_ITYPE[protocol]
                    extra: dict = {}
                    if itype == "vless-reality":
                        extra["dest_domain"] = body_dict.get("dest_domain", "www.microsoft.com")
                    elif itype in ("vless-ws", "vmess-ws"):
                        extra["path"] = body_dict.get("path", f"/{itype.split('-')[0]}")
                    elif itype == "vless-grpc":
                        extra["service_name"] = body_dict.get("service_name", "grpc")
                    return XrayManager(ssh).add_inbound(
                        itype, int(body_dict.get("port", _default_port(protocol))),
                        progress=log, **extra
                    )
                elif protocol == "openvpn":
                    return OpenVPNManager(ssh).install(
                        port=int(body_dict.get("port", 1194)),
                        dns=body_dict.get("dns", "1.1.1.1"),
                        progress=log,
                    )
                raise ValueError(f"Unknown protocol: {protocol}")

        result = await loop.run_in_executor(None, do_install)
        server["protocols"][protocol] = {"installed": True, "host": server["host"], **result}
        await save_data(data)
        INSTALL_TASKS[task_id].update(
            {"done": True, "success": True, "finished_at": time.time()}
        )
    except Exception as e:
        logger.exception("Install task failed")
        INSTALL_TASKS[task_id].update(
            {"done": True, "success": False, "error": str(e), "finished_at": time.time()}
        )


@app.post("/api/servers/{server_id}/protocols/{protocol}/install")
async def install_protocol(request: Request, server_id: str, protocol: str):
    require_auth(request)
    if protocol not in ALL_PROTOCOLS:
        return JSONResponse({"success": False, "error": "Unknown protocol"}, status_code=400)
    try:
        body = InstallProtocolRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)

    task_id = str(uuid.uuid4())
    INSTALL_TASKS[task_id] = {
        "status": "running", "logs": [], "done": False, "success": None,
        "started_at": time.time(),
    }
    asyncio.create_task(_run_install_bg(task_id, server_id, protocol, body.model_dump()))
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


# ──────────────────────────────────────────────────────────────────────────────
# Client management
# ──────────────────────────────────────────────────────────────────────────────

def _next_ip(proto_conf: dict, clients: dict) -> str:
    subnet = proto_conf.get("subnet", "10.8.1.0/24")
    parts = subnet.split("/")
    base_parts = parts[0].rsplit(".", 1)[0]
    cidr = int(parts[1]) if len(parts) > 1 else 24
    max_hosts = 2 ** (32 - cidr) - 2
    used = {c["ip"] for c in clients.values() if c.get("ip")}
    upper = min(max_hosts + 2, 254) if cidr >= 24 else max_hosts + 2
    for i in range(2, upper):
        ip = f"{base_parts}.{i}"
        if ip not in used:
            return ip
    raise ValueError("IP pool exhausted")


def _compute_expires_at(body) -> str | None:
    expires_at = getattr(body, "expires_at", None)
    if expires_at:
        return expires_at
    validity_days = getattr(body, "validity_days", 0) or 0
    if validity_days > 0:
        return (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat()
    return None


def _wg_client(cid, name, ip, keys, body, expires_at=None):
    return {
        "id": cid, "name": name, "ip": ip,
        "email": getattr(body, "email", "") or "",
        "notes": getattr(body, "notes", "") or "",
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
        "preshared_key": keys["preshared_key"],
        "enabled": True, "source": "panel", "created_at": now_iso(),
        "expires_at": expires_at,
        "traffic_limit_bytes": int(getattr(body, "traffic_limit_gb", 0) or 0) * 1024 ** 3,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
        # Per-client overrides (v2.1)
        "dns": getattr(body, "dns", None),
        "mtu": getattr(body, "mtu", None),
        "persistent_keepalive": getattr(body, "persistent_keepalive", None),
        "allowed_ips": getattr(body, "allowed_ips", None),
    }


def _xray_client(cid, name, body, info, proto_conf, itype, expires_at=None):
    return {
        "id": cid, "name": name,
        "email": getattr(body, "email", "") or "",
        "notes": getattr(body, "notes", "") or "",
        "xray_id": info.get("id", ""), "password": info.get("password", ""),
        "inbound_id": proto_conf["id"], "inbound_type": itype,
        "enabled": True, "source": "panel", "created_at": now_iso(),
        "expires_at": expires_at,
        "traffic_limit_bytes": int(getattr(body, "traffic_limit_gb", 0) or 0) * 1024 ** 3,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
    }


def _openvpn_client(cid, name, body, info, expires_at=None):
    return {
        "id": cid, "name": name,
        "email": getattr(body, "email", "") or "",
        "notes": getattr(body, "notes", "") or "",
        "safe_name": info.get("safe_name", name.replace(" ", "_")),
        "enabled": True, "source": "panel", "created_at": now_iso(),
        "expires_at": expires_at,
        "traffic_limit_bytes": int(getattr(body, "traffic_limit_gb", 0) or 0) * 1024 ** 3,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
        "ovpn_config": info.get("config", ""),
    }


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients")
async def add_client(request: Request, server_id: str, protocol: str):
    require_auth(request)
    try:
        body = AddClientRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)
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
    expires_at = _compute_expires_at(body)

    try:
        with _make_ssh(server) as ssh:
            if protocol == "awg":
                ip = body.ip or _next_ip(proto_conf, clients)
                keys = AWGManager(ssh).add_client(proto_conf, client_name, ip)
                clients[cid] = _wg_client(cid, client_name, ip, keys, body, expires_at)

            elif protocol == "wireguard":
                ip = body.ip or _next_ip(proto_conf, clients)
                keys = WireGuardManager(ssh).add_client(
                    proto_conf["server_public_key"], ip, client_name
                )
                clients[cid] = _wg_client(cid, client_name, ip, keys, body, expires_at)

            elif protocol in XRAY_PROTOCOLS:
                itype = PROTO_TO_ITYPE[protocol]
                info = XrayManager(ssh).add_client(proto_conf["id"], itype, client_name)
                clients[cid] = _xray_client(cid, client_name, body, info, proto_conf, itype, expires_at)

            elif protocol == "openvpn":
                info = OpenVPNManager(ssh).add_client(client_name)
                clients[cid] = _openvpn_client(cid, client_name, body, info, expires_at)

    except Exception as e:
        logger.exception("Add client error")
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "client_id": cid})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/bulk")
async def bulk_create_clients(request: Request, server_id: str, protocol: str):
    require_auth(request)
    try:
        body = BulkCreateRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)

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
            for i in range(1, body.count + 1):
                cid = str(uuid.uuid4())
                name = f"{body.prefix}{i}"
                try:
                    if protocol == "awg":
                        ip = _next_ip(proto_conf, clients)
                        keys = AWGManager(ssh).add_client(proto_conf, name, ip)
                        clients[cid] = _wg_client(cid, name, ip, keys, body, expires_at)
                    elif protocol == "wireguard":
                        ip = _next_ip(proto_conf, clients)
                        keys = WireGuardManager(ssh).add_client(
                            proto_conf["server_public_key"], ip, name
                        )
                        clients[cid] = _wg_client(cid, name, ip, keys, body, expires_at)
                    elif protocol in XRAY_PROTOCOLS:
                        itype = PROTO_TO_ITYPE[protocol]
                        info = XrayManager(ssh).add_client(proto_conf["id"], itype, name)
                        clients[cid] = _xray_client(cid, name, body, info, proto_conf, itype, expires_at)
                    elif protocol == "openvpn":
                        info = OpenVPNManager(ssh).add_client(name)
                        clients[cid] = _openvpn_client(cid, name, body, info, expires_at)
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
                ident = (client.get("password") if itype in ("shadowsocks", "trojan-tcp")
                         else client.get("xray_id", ""))
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
    """Update client metadata: name, notes, email, expires_at, traffic_limit,
    per-client overrides (dns, mtu, keepalive, allowed_ips), reset_traffic, extend_days."""
    require_auth(request)
    try:
        body = UpdateClientRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    client = server["clients"].get(protocol, {}).get(client_id)
    if not client:
        raise HTTPException(404)

    if body.name is not None:
        client["name"] = body.name
    if body.notes is not None:
        client["notes"] = body.notes
    if body.email is not None:
        client["email"] = body.email
    if body.expires_at is not None:
        client["expires_at"] = body.expires_at or None
    if body.traffic_limit_gb is not None:
        client["traffic_limit_bytes"] = int(body.traffic_limit_gb) * 1024 ** 3
    # Per-client overrides
    if body.dns is not None:
        client["dns"] = body.dns or None
    if body.mtu is not None:
        client["mtu"] = body.mtu
    if body.persistent_keepalive is not None:
        client["persistent_keepalive"] = body.persistent_keepalive
    if body.allowed_ips is not None:
        client["allowed_ips"] = body.allowed_ips or None
    # Reset traffic counter
    if body.reset_traffic:
        client["traffic_rx"] = 0
        client["traffic_tx"] = 0
        client["last_seen"] = None
    # Extend expiry
    if body.extend_days and body.extend_days > 0:
        current = client.get("expires_at")
        if current:
            try:
                base = datetime.fromisoformat(current.replace("Z", "+00:00"))
                if base.tzinfo is None:
                    base = base.replace(tzinfo=timezone.utc)
            except ValueError:
                base = datetime.now(timezone.utc)
        else:
            base = datetime.now(timezone.utc)
        client["expires_at"] = (base + timedelta(days=body.extend_days)).isoformat()

    await save_data(data)
    return JSONResponse({"success": True, "client": client})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/{client_id}/clone")
async def clone_client(request: Request, server_id: str, protocol: str, client_id: str):
    """Clone an existing client — copies all settings, generates new keys/credentials."""
    require_auth(request)
    try:
        body = AddClientRequest(**(await request.json()))
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    src = server["clients"].get(protocol, {}).get(client_id)
    if not src:
        raise HTTPException(404)

    proto_conf = server["protocols"][protocol]
    clients = server["clients"].setdefault(protocol, {})
    cid = str(uuid.uuid4())
    new_name = body.name or f"{src['name']}_copy"
    expires_at = _compute_expires_at(body)
    # Inherit source's overrides if not specified
    if not body.dns and src.get("dns"):
        body.dns = src["dns"]
    if not body.mtu and src.get("mtu"):
        body.mtu = src["mtu"]
    if body.persistent_keepalive is None and src.get("persistent_keepalive"):
        body.persistent_keepalive = src["persistent_keepalive"]
    if not body.allowed_ips and src.get("allowed_ips"):
        body.allowed_ips = src["allowed_ips"]

    try:
        with _make_ssh(server) as ssh:
            if protocol == "awg":
                ip = body.ip or _next_ip(proto_conf, clients)
                keys = AWGManager(ssh).add_client(proto_conf, new_name, ip)
                clients[cid] = _wg_client(cid, new_name, ip, keys, body, expires_at)
            elif protocol == "wireguard":
                ip = body.ip or _next_ip(proto_conf, clients)
                keys = WireGuardManager(ssh).add_client(
                    proto_conf["server_public_key"], ip, new_name
                )
                clients[cid] = _wg_client(cid, new_name, ip, keys, body, expires_at)
            elif protocol in XRAY_PROTOCOLS:
                itype = PROTO_TO_ITYPE[protocol]
                info = XrayManager(ssh).add_client(proto_conf["id"], itype, new_name)
                clients[cid] = _xray_client(cid, new_name, body, info, proto_conf, itype, expires_at)
            elif protocol == "openvpn":
                info = OpenVPNManager(ssh).add_client(new_name)
                clients[cid] = _openvpn_client(cid, new_name, body, info, expires_at)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "client_id": cid})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/bulk-delete")
async def bulk_delete_clients(request: Request, server_id: str, protocol: str):
    """Delete multiple clients by id list."""
    require_auth(request)
    body = await request.json()
    ids = body.get("ids", [])
    if not isinstance(ids, list) or len(ids) > 500:
        return JSONResponse({"success": False, "error": "Invalid ids list"}, status_code=422)

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    clients = server["clients"].get(protocol, {})
    deleted = 0
    errors = []
    try:
        with _make_ssh(server) as ssh:
            for cid in ids:
                client = clients.get(cid)
                if not client:
                    continue
                try:
                    if protocol == "awg":
                        AWGManager(ssh).remove_client(client["public_key"])
                    elif protocol == "wireguard":
                        WireGuardManager(ssh).remove_client(client["public_key"])
                    elif protocol in XRAY_PROTOCOLS:
                        itype = PROTO_TO_ITYPE[protocol]
                        ident = (client.get("password") if itype in ("shadowsocks", "trojan-tcp")
                                 else client.get("xray_id", ""))
                        XrayManager(ssh).remove_client(client["inbound_id"], itype, ident)
                    elif protocol == "openvpn":
                        OpenVPNManager(ssh).remove_client(client.get("safe_name", client["name"]))
                    del clients[cid]
                    deleted += 1
                except Exception as e:
                    errors.append(f"{client.get('name')}: {e}")
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    await save_data(data)
    return JSONResponse({"success": True, "deleted": deleted, "errors": errors})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/bulk-toggle")
async def bulk_toggle_clients(request: Request, server_id: str, protocol: str):
    """Toggle multiple clients. Body: {ids: [...], enabled: true|false}."""
    require_auth(request)
    body = await request.json()
    ids = body.get("ids", [])
    target_enabled = bool(body.get("enabled"))
    if not isinstance(ids, list) or len(ids) > 500:
        return JSONResponse({"success": False, "error": "Invalid ids list"}, status_code=422)

    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    clients = server["clients"].get(protocol, {})
    toggled = 0
    errors = []
    if protocol in ("awg", "wireguard"):
        try:
            with _make_ssh(server) as ssh:
                for cid in ids:
                    client = clients.get(cid)
                    if not client or client["enabled"] == target_enabled:
                        continue
                    try:
                        if protocol == "awg":
                            AWGManager(ssh).toggle_client(client["public_key"], target_enabled)
                        else:
                            WireGuardManager(ssh).toggle_client(client["public_key"], target_enabled)
                        client["enabled"] = target_enabled
                        toggled += 1
                    except Exception as e:
                        errors.append(f"{client.get('name')}: {e}")
        except Exception as e:
            return JSONResponse({"success": False, "error": str(e)})
    else:
        # Xray/OpenVPN: just update flag (no live toggle)
        for cid in ids:
            client = clients.get(cid)
            if client:
                client["enabled"] = target_enabled
                toggled += 1

    await save_data(data)
    return JSONResponse({"success": True, "toggled": toggled, "errors": errors})


# ──────────────────────────────────────────────────────────────────────────────
# Config & QR
# ──────────────────────────────────────────────────────────────────────────────

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
        return JSONResponse(
            {"success": False, "error": "Config not available for Amnezia App clients"},
            status_code=422,
        )

    ext = {"awg": "conf", "wireguard": "conf", "openvpn": "ovpn"}.get(protocol, "txt")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", client.get("name", "client"))
    fname = f"{protocol}_{safe_name}.{ext}"
    return Response(
        content=text, media_type="text/plain; charset=utf-8",
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
        "traffic_limit_gb", "traffic_rx_mb", "traffic_tx_mb", "last_seen",
        "dns", "mtu", "persistent_keepalive", "allowed_ips",
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
            "created_at": (c.get("created_at") or "")[:10],
            "expires_at": (c.get("expires_at") or "")[:10],
            "traffic_limit_gb": round(c.get("traffic_limit_bytes", 0) / 1024**3, 2),
            "traffic_rx_mb": round(c.get("traffic_rx", 0) / 1024**2, 2),
            "traffic_tx_mb": round(c.get("traffic_tx", 0) / 1024**2, 2),
            "last_seen": (c.get("last_seen") or "")[:10],
            "dns": c.get("dns", "") or "",
            "mtu": c.get("mtu", "") or "",
            "persistent_keepalive": c.get("persistent_keepalive", "") or "",
            "allowed_ips": c.get("allowed_ips", "") or "",
        })

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", server["name"])[:32]
    fname = f"{safe_name}_{protocol}_users.csv"
    return Response(
        content=out.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Traffic sync
# ──────────────────────────────────────────────────────────────────────────────

def _collect_traffic_from_server(ssh: SSHManager) -> dict:
    all_traffic: dict = {}
    out, _, code = ssh.run_sudo("wg show all dump 2>/dev/null")
    if code == 0 and out.strip():
        all_traffic.update(parse_wg_dump(out))

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


# ──────────────────────────────────────────────────────────────────────────────
# Detect external Amnezia configs
# ──────────────────────────────────────────────────────────────────────────────

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

    detected: dict[str, list[str]] = {"awg": [], "wireguard": []}

    try:
        with _make_ssh(server) as ssh:
            # Native wg → wireguard
            out, _, code = ssh.run_sudo("wg show all dump 2>/dev/null")
            if code == 0 and out.strip():
                new = [p for p in parse_wg_dump(out) if p not in known_keys]
                if new:
                    detected["wireguard"].extend(new)

            # Amnezia config files (path-keyed, NOT all dumped into awg)
            for path, proto in [
                ("/opt/amnezia/awg/wg0.conf", "awg"),
                ("/opt/amnezia/wireguard/wg0.conf", "wireguard"),
            ]:
                try:
                    peers = _parse_wg_conf_peers(ssh.download_file(path))
                    new = [p for p in peers if p not in known_keys and p not in detected[proto]]
                    if new:
                        detected[proto].extend(new)
                except Exception:
                    pass

            # Docker containers: AWG container → awg, anything else → wireguard
            out2, _, _ = ssh.run_sudo("docker ps --format '{{.Names}}' 2>/dev/null")
            for cname in out2.strip().split("\n"):
                cname = cname.strip()
                if not cname:
                    continue
                low = cname.lower()
                if "awg" in low or "amnezia" in low:
                    target_proto = "awg"
                elif "wireguard" in low or low.endswith("wg") or "wg" in low:
                    target_proto = "wireguard"
                else:
                    continue
                for cmd in ["awg show all dump", "wg show all dump"]:
                    out3, _, rc = ssh.run_sudo(f"docker exec {cname} {cmd} 2>/dev/null")
                    if rc == 0 and out3.strip():
                        new = [p for p in parse_wg_dump(out3)
                               if p not in known_keys and p not in detected[target_proto]]
                        if new:
                            detected[target_proto].extend(new)
                        break
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

    # Dedupe
    for k in detected:
        detected[k] = list(dict.fromkeys(detected[k]))
    # Drop empty buckets
    detected = {k: v for k, v in detected.items() if v}

    return JSONResponse({"success": True, "external": detected,
                         "total": sum(len(v) for v in detected.values())})


@app.post("/api/servers/{server_id}/protocols/{protocol}/clients/{public_key}/import")
async def import_external(request: Request, server_id: str, protocol: str, public_key: str):
    require_auth(request)
    # Validate public_key format (base64-encoded 32-byte key)
    if not _PUBKEY_RE.match(public_key):
        return JSONResponse(
            {"success": False, "error": "Invalid public key format"}, status_code=422
        )
    try:
        body = ImportExternalRequest(**await request.json())
    except ValidationError as e:
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)
    data = await load_data()
    server = data["servers"].get(server_id)
    if not server:
        raise HTTPException(404)
    _ensure_protocols(server)
    cid = str(uuid.uuid4())
    server["clients"].setdefault(protocol, {})[cid] = {
        "id": cid,
        "name": body.name or f"Amnezia ({public_key[:8]})",
        "email": "", "notes": "",
        "public_key": public_key,
        "private_key": "", "preshared_key": "", "ip": "",
        "enabled": True, "source": "amnezia_app", "created_at": now_iso(),
        "expires_at": None, "traffic_limit_bytes": 0,
        "traffic_rx": 0, "traffic_tx": 0, "last_seen": None,
    }
    await save_data(data)
    return JSONResponse({"success": True, "client_id": cid})


# ──────────────────────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────────────────────

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
        return JSONResponse({"success": False, "error": e.errors()}, status_code=422)
    data = await load_data()
    if not bcrypt.checkpw(body.current_password.encode(),
                          data["panel"]["admin_password_hash"].encode()):
        return JSONResponse({"success": False, "error": "Current password is incorrect"})
    data["panel"]["admin_password_hash"] = bcrypt.hashpw(
        body.new_password.encode(), bcrypt.gensalt()
    ).decode()
    await save_data(data)
    return JSONResponse({"success": True})


# ──────────────────────────────────────────────────────────────────────────────
# Self-update (with remote URL verification)
# ──────────────────────────────────────────────────────────────────────────────

EXPECTED_REPO = "github.com/ScannerVpn/Amnezia-Web-Panel"


@app.post("/api/update")
async def update_panel(request: Request):
    require_auth(request)
    try:
        # Verify remote URL before pulling
        chk = subprocess.run(
            ["git", "-C", "/app", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
        )
        if chk.returncode != 0 or EXPECTED_REPO not in chk.stdout:
            return JSONResponse({
                "success": False,
                "error": f"Refusing to update: remote URL is not {EXPECTED_REPO}",
            })

        result = subprocess.run(
            ["git", "-C", "/app", "pull"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return JSONResponse(
                {"success": False, "error": result.stderr.strip() or "git pull failed"}
            )
        output = result.stdout.strip()
        if "Already up to date" in output:
            return JSONResponse(
                {"success": True, "message": "Already up to date.", "restarting": False}
            )

        needs_rebuild = "requirements.txt" in output or "Dockerfile" in output

        async def _restart():
            await asyncio.sleep(2)
            os.kill(os.getpid(), signal.SIGTERM)

        asyncio.create_task(_restart())
        msg = output
        if needs_rebuild:
            msg += "\n\nrequirements.txt or Dockerfile changed. Run: docker compose up -d --build"

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


# ──────────────────────────────────────────────────────────────────────────────
# Background: traffic sync + expiry enforcement + task cleanup
# ──────────────────────────────────────────────────────────────────────────────

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
                                        exp = datetime.fromisoformat(
                                            client["expires_at"].replace("Z", "+00:00")
                                        )
                                        if exp.tzinfo is None:
                                            exp = exp.replace(tzinfo=timezone.utc)
                                        if now > exp:
                                            client["enabled"] = False
                                            changed = True
                                            logger.info(
                                                "Disabled expired client %s on %s/%s",
                                                client.get("name"), server.get("name"), proto
                                            )
                                    except ValueError as e:
                                        logger.warning("Bad expires_at for %s: %s",
                                                       client.get("name"), e)

                except Exception as e:
                    logger.warning(
                        "Auto-sync failed for server %s: %s", server.get("name"), e
                    )

            if changed:
                await save_data(data)
        except Exception as e:
            logger.exception("Auto-sync loop crashed: %s", e)


async def _cleanup_tasks_bg():
    """Periodically clean up old INSTALL_TASKS entries."""
    while True:
        await asyncio.sleep(600)
        try:
            _cleanup_old_tasks()
        except Exception as e:
            logger.warning("Task cleanup failed: %s", e)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PANEL_PORT", 54325)),
        reload=False,
    )
