from pydantic import BaseModel, Field
from typing import Optional


class AddServerRequest(BaseModel):
    name: str = Field(default="")
    host: str
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root")
    password: str = Field(default="")
    ssh_key: str = Field(default="")


class InstallProtocolRequest(BaseModel):
    port: int = Field(default=0, ge=1, le=65535)
    subnet: str = Field(default="")
    dns: str = Field(default="1.1.1.1")
    dest_domain: str = Field(default="www.microsoft.com")
    path: str = Field(default="")
    service_name: str = Field(default="grpc")


class AddClientRequest(BaseModel):
    name: str = Field(default="")
    email: str = Field(default="")
    notes: str = Field(default="")
    traffic_limit_gb: int = Field(default=0, ge=0)
    validity_days: int = Field(default=0, ge=0)
    expires_at: Optional[str] = None
    ip: Optional[str] = None


class BulkCreateRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=100)
    prefix: str = Field(default="user")
    traffic_limit_gb: int = Field(default=0, ge=0)
    validity_days: int = Field(default=0, ge=0)
    expires_at: Optional[str] = None


class UpdateClientRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    notes: Optional[str] = None
    expires_at: Optional[str] = None
    traffic_limit_gb: Optional[int] = Field(default=None, ge=0)


class ImportExternalRequest(BaseModel):
    name: str = Field(default="Amnezia")


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)
