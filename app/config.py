import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.errors import StartupError


def _raw(name):
    if name not in os.environ:
        return None
    return os.environ[name].strip()


def _required(name, default):
    value = _raw(name)
    if value is None:
        return default
    if not value:
        raise StartupError(f"{name} is empty.")
    return value


def _flag(name, default):
    value = _raw(name)
    if value is None:
        return default
    if not value:
        raise StartupError(f"{name} is empty.")
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise StartupError(f"{name} must be 0 or 1. Got: {value}")


@dataclass
class Config:
    tz_name: str
    host: str
    port: int
    data_dir: Path
    secret_path: Path
    base_url: str
    cookie_secure: bool
    trusted_proxies: frozenset

    @property
    def cookie_name(self):
        if self.cookie_secure:
            return "__Host-session"
        return "session"

    @classmethod
    def from_env(cls):
        port_raw = _required("PORT", "4189")
        try:
            port = int(port_raw)
        except ValueError as exc:
            raise StartupError(f"PORT must be an integer from 1 to 65535. Got: {port_raw}") from exc
        if not 1 <= port <= 65535:
            raise StartupError(f"PORT must be an integer from 1 to 65535. Got: {port_raw}")

        trusted = []
        for item in os.environ.get("TRUSTED_PROXIES", "").split(","):
            item = item.strip()
            if not item:
                continue
            try:
                trusted.append(ipaddress.ip_address(item).compressed)
            except ValueError as exc:
                raise StartupError(f"TRUSTED_PROXIES has an invalid address: {item}") from exc

        base = _required("SIMPLELOGIN_BASE_URL", "https://app.simplelogin.io").rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise StartupError(f"SIMPLELOGIN_BASE_URL must be an http or https URL. Got: {base}")
        tz_name = os.environ.get("TZ", "").strip() or "Etc/UTC"
        return cls(
            tz_name=tz_name,
            host=_required("HOST", "0.0.0.0"),
            port=port,
            data_dir=Path(_required("DATA_DIR", "./data")),
            secret_path=Path(_required("SECRET_PATH", "./secret")),
            base_url=base,
            cookie_secure=_flag("COOKIE_SECURE", True),
            trusted_proxies=frozenset(trusted),
        )
