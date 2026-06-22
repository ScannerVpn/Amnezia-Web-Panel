"""Pydantic models for request validation across all Amnezia Web Panel endpoints."""
import re
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
from typing import Optional


# ── Common validators ────────────────────────────────────────────────────────

_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")
_SAFE_NAME_RE = re.compile(r"^[^\n\r\t<>\"'&]+$", re.UNICODE)  # broad unicode, block dangerous chars
_PORT_RANGE = (1, 65535)


def _validate_port(v: int) -> int:
    if not isinstance(v, int):
        raise ValueError("Port must be an integer")
    if not (_PORT_RANGE[0] <= v <= _PORT_RANGE[1]):
        raise ValueError(f"Port must be in range {_PORT_RANGE[0]}-{_PORT_RANGE[1]}")
    return v


def _validate_host(v: str) -> str:
    v = (v or "").strip()
    if not v:
        raise ValueError("Host is required")
    # Allow IPv4, hostname, or domain
    if _IPV4_RE.match(v):
        parts = [int(p) for p in v.split(".")]
        if any(p > 255 for p in parts):
            raise ValueError("Invalid IPv4 address")
    elif _HOSTNAME_RE.match(v) and len(v) <= 253:
        pass
    else:
        raise ValueError("Invalid host (must be IP or hostname)")
    return v


def _validate_subnet(v: str) -> str:
    v = (v or "").strip()
    if not v:
        raise ValueError("Subnet is required")
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", v):
        raise ValueError("Invalid subnet format (e.g. 10.8.0.0/24)")
    return v


def _validate_dns(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return "1.1.1.1"
    if _IPV4_RE.match(v) or _HOSTNAME_RE.match(v):
        return v
    raise ValueError("Invalid DNS (must be IP or hostname)")


# ── Server ───────────────────────────────────────────────────────────────────

class AddServerRequest(BaseModel):
    name: str = Field(default="", max_length=128)
    host: str = Field(..., min_length=1, max_length=253)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", max_length=64)
    password: str = Field(default="", max_length=512)
    ssh_key: str = Field(default="")

    @field_validator("host")
    @classmethod
    def _v_host(cls, v): return _validate_host(v)

    @field_validator("name")
    @classmethod
    def _v_name(cls, v):
        v = (v or "").strip()
        return v


class UpdateServerRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=128)
    password: Optional[str] = Field(default=None, max_length=512)
    ssh_key: Optional[str] = Field(default=None)


# ── Protocol install ─────────────────────────────────────────────────────────

class InstallProtocolRequest(BaseModel):
    port: int = Field(default=0, ge=0, le=65535)
    subnet: str = Field(default="")
    dns: str = Field(default="1.1.1.1")
    dest_domain: str = Field(default="www.microsoft.com")
    path: str = Field(default="")
    service_name: str = Field(default="grpc")

    @field_validator("subnet")
    @classmethod
    def _v_subnet(cls, v):
        return v if not v else _validate_subnet(v)

    @field_validator("dns")
    @classmethod
    def _v_dns(cls, v): return _validate_dns(v)

    @field_validator("dest_domain")
    @classmethod
    def _v_dest(cls, v):
        v = (v or "").strip()
        if not _HOSTNAME_RE.match(v):
            raise ValueError("Invalid dest_domain")
        return v

    @field_validator("path")
    @classmethod
    def _v_path(cls, v):
        v = (v or "").strip()
        if v and not re.match(r"^/[A-Za-z0-9._\-/]*$", v):
            raise ValueError("Invalid path (must start with /)")
        return v

    @field_validator("service_name")
    @classmethod
    def _v_svc(cls, v):
        v = (v or "").strip()
        if v and not re.match(r"^[A-Za-z0-9._\-]+$", v):
            raise ValueError("Invalid service name")
        return v


# ── Clients ──────────────────────────────────────────────────────────────────

class AddClientRequest(BaseModel):
    name: str = Field(default="", max_length=128)
    email: str = Field(default="", max_length=256)
    notes: str = Field(default="", max_length=1024)
    traffic_limit_gb: int = Field(default=0, ge=0, le=10240)
    validity_days: int = Field(default=0, ge=0, le=3650)
    expires_at: Optional[str] = None
    ip: Optional[str] = None
    # New per-client overrides (v2.1)
    dns: Optional[str] = None
    mtu: Optional[int] = Field(default=None, ge=576, le=9000)
    persistent_keepalive: Optional[int] = Field(default=None, ge=0, le=65535)
    allowed_ips: Optional[str] = None

    @field_validator("ip")
    @classmethod
    def _v_ip(cls, v):
        if v and not _IPV4_RE.match(v):
            raise ValueError("Invalid IPv4 address")
        return v

    @field_validator("expires_at")
    @classmethod
    def _v_expires(cls, v):
        if v:
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("Invalid expires_at format (use ISO 8601)")
        return v

    @field_validator("dns")
    @classmethod
    def _v_dns_opt(cls, v):
        if v:
            return _validate_dns(v)
        return v

    @field_validator("allowed_ips")
    @classmethod
    def _v_allowed(cls, v):
        if v and not re.match(r"^[0-9./, :]+$", v):
            raise ValueError("Invalid AllowedIPs")
        return v


class BulkCreateRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=100)
    prefix: str = Field(default="user", max_length=32)
    traffic_limit_gb: int = Field(default=0, ge=0, le=10240)
    validity_days: int = Field(default=0, ge=0, le=3650)
    expires_at: Optional[str] = None
    # New optional per-batch defaults
    dns: Optional[str] = None
    mtu: Optional[int] = Field(default=None, ge=576, le=9000)
    persistent_keepalive: Optional[int] = Field(default=None, ge=0, le=65535)
    allowed_ips: Optional[str] = None

    @field_validator("prefix")
    @classmethod
    def _v_prefix(cls, v):
        v = (v or "").strip()
        if not re.match(r"^[A-Za-z0-9._\-]+$", v):
            raise ValueError("Prefix must be alphanumeric with . _ -")
        return v

    @field_validator("expires_at")
    @classmethod
    def _v_expires(cls, v):
        if v:
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("Invalid expires_at (ISO 8601)")
        return v


class UpdateClientRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=128)
    email: Optional[str] = Field(default=None, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=1024)
    expires_at: Optional[str] = None
    traffic_limit_gb: Optional[int] = Field(default=None, ge=0, le=10240)
    # New editable fields (v2.1)
    dns: Optional[str] = None
    mtu: Optional[int] = Field(default=None, ge=576, le=9000)
    persistent_keepalive: Optional[int] = Field(default=None, ge=0, le=65535)
    allowed_ips: Optional[str] = None
    reset_traffic: Optional[bool] = False
    extend_days: Optional[int] = Field(default=None, ge=0, le=3650)

    @field_validator("expires_at")
    @classmethod
    def _v_expires(cls, v):
        if v:
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("Invalid expires_at (ISO 8601)")
        return v


class ImportExternalRequest(BaseModel):
    name: str = Field(default="Amnezia", max_length=128)


# ── Auth ─────────────────────────────────────────────────────────────────────

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=256)
