from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class Role(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    VIEWER = "viewer"
    USER = "user"


ROLE_HIERARCHY = {
    Role.SUPERADMIN: 4,
    Role.ADMIN: 3,
    Role.VIEWER: 2,
    Role.USER: 1,
}


PERMISSIONS: dict[str, set[Role]] = {
    "panel.users.read": {Role.SUPERADMIN},
    "panel.users.write": {Role.SUPERADMIN},
    "mail.read": {Role.SUPERADMIN, Role.ADMIN, Role.VIEWER},
    "mail.write": {Role.SUPERADMIN, Role.ADMIN},
    "antispam.read": {Role.SUPERADMIN, Role.ADMIN, Role.VIEWER},
    "antispam.write": {Role.SUPERADMIN, Role.ADMIN},
    "antispam.self": {Role.USER},
    "logs.read": {Role.SUPERADMIN, Role.ADMIN, Role.VIEWER},
    "services.read": {Role.SUPERADMIN, Role.ADMIN, Role.VIEWER},
    "services.restart": {Role.SUPERADMIN, Role.ADMIN},
    "quarantine.read": {Role.SUPERADMIN, Role.ADMIN, Role.VIEWER, Role.USER},
    "quarantine.write": {Role.SUPERADMIN, Role.ADMIN},
    "quarantine.self": {Role.USER},
    "queue.read": {Role.SUPERADMIN, Role.ADMIN},
    "queue.write": {Role.SUPERADMIN, Role.ADMIN},
    "forwarding.self": {Role.USER},
}


def role_has_permission(role: Role, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission, set())
    return role in allowed


class PanelConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    secret_key: str
    token_expire_hours: int = 12
    mail_domain: str = "company.ru"


class DatabaseConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 3306
    user: str
    password: str
    database: str


class PathsConfig(BaseModel):
    wblist_script: str
    greylisting_script: str
    spamassassin_config: str
    maillog: str
    iredapd_log: str
    dovecot_log: str
    messages_log: str


class LogCollectorConfig(BaseModel):
    enabled: bool = True
    poll_interval_seconds: int = 5
    retention_days: int = 90


class AmavisdConfig(BaseModel):
    release_host: str = "127.0.0.1"
    release_port: int = 9998


class AppConfig(BaseModel):
    panel: PanelConfig
    database: DatabaseConfig
    vmail_database: DatabaseConfig
    amavisd_database: DatabaseConfig
    amavisd: AmavisdConfig = Field(default_factory=AmavisdConfig)
    paths: PathsConfig
    services: list[str] = Field(default_factory=list)
    log_collector: LogCollectorConfig = Field(default_factory=LogCollectorConfig)


def _find_config_path() -> Path:
    for path in (
        Path(__file__).resolve().parents[2] / "config.yaml",
        Path("/etc/mailpanel/config.yaml"),
        Path("config.yaml"),
    ):
        if path.exists():
            return path
    raise FileNotFoundError("config.yaml not found. Copy config.example.yaml to config.yaml")


@lru_cache
def get_config() -> AppConfig:
    with _find_config_path().open("r", encoding="utf-8") as handle:
        raw: dict[str, Any] = yaml.safe_load(handle) or {}
    return AppConfig.model_validate(raw)
