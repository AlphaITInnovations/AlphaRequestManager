# File: alpharequestmanager/config.py
from __future__ import annotations

import dataclasses
import os
import json
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from alpharequestmanager import database as db
from alpharequestmanager.logger import logger


# ---------------------------
# Helpers
# ---------------------------

def _coerce_int(v: Any, *, default: int) -> int:
    if v is None:
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        v = v.strip()
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
        try:
            return int(float(v))
        except ValueError:
            pass
    raise ValueError(f"Cannot coerce {v!r} to int")

def _coerce_scope(v: Any, *, default: List[str]) -> List[str]:
    # NOTE: generic string-list coercion; used for SCOPE + COMPANIES
    if v is None:
        return list(default)
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
        return parts or list(default)
    raise ValueError(f"Cannot coerce {v!r} to List[str]")

def _env(key: str) -> Optional[str]:
    v = os.getenv(key)
    return v if v not in ("", None) else None

def _env_json(key: str) -> Optional[Any]:
    raw = _env(key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw


# ---------------------------
# Defaults (nur Fallback/Seeding)
# ---------------------------

_DEFAULTS: Dict[str, Any] = {
    "SECRET_KEY": "",
    "CLIENT_ID": "",
    "CLIENT_SECRET": "",
    "TENANT_ID": "",
    "REDIRECT_URI": "",
    "SCOPE": ["User.Read", "Mail.Send"],
    "ADMIN_GROUP_ID": "",
    "TICKET_MAIL": "",
    "SESSION_TIMEOUT": 15 * 60,
    "NINJA_POLL_INTERVAL": 5 * 60,  # 5 Minuten in Sekunden
    "NINJA_TOKEN": {},              # JSON-Feld
    # Neu: Firmenliste (Fallback, wird durch ENV/DB überschrieben)
    "COMPANIES": [
        "AlphaConsult KG",
        "Alpha-Med KG",
        "AlphaConsult Premium KG",
    ],
}

_SEED_FROM_ENV: Dict[str, Any] = {
    "SECRET_KEY": _env("SECRET_KEY"),
    "CLIENT_ID": _env("CLIENT_ID"),
    "CLIENT_SECRET": _env("CLIENT_SECRET"),
    "TENANT_ID": _env("TENANT_ID"),
    "REDIRECT_URI": _env("REDIRECT_URI"),
    "SCOPE": _env_json("SCOPE"),
    "ADMIN_GROUP_ID": _env("ADMIN_GROUP_ID"),
    "TICKET_MAIL": _env("TICKET_MAIL"),
    "SESSION_TIMEOUT": _env("SESSION_TIMEOUT"),
    "NINJA_POLL_INTERVAL": _env("NINJA_POLL_INTERVAL"),
    "NINJA_TOKEN": _env_json("NINJA_TOKEN"),
    # Neu: erlaubt JSON (z.B. ["A","B"]) oder CSV ("A,B")
    "COMPANIES": _env_json("COMPANIES"),
}


# ---------------------------
# Dataclass mit Properties
# ---------------------------

@dataclass
class Settings:
    SECRET_KEY: str
    CLIENT_ID: str
    CLIENT_SECRET: str
    TENANT_ID: str
    REDIRECT_URI: str
    SCOPE: List[str]
    ADMIN_GROUP_ID: str
    TICKET_MAIL: str
    SESSION_TIMEOUT: int
    NINJA_POLL_INTERVAL: int
    NINJA_TOKEN: Any
    COMPANIES: List[str]

    _AUTHORITY_override: Optional[str] = field(default=None, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    @property
    def AUTHORITY(self) -> str:
        if self._AUTHORITY_override:
            return self._AUTHORITY_override
        return f"https://login.microsoftonline.com/{self.TENANT_ID}"

    @AUTHORITY.setter
    def AUTHORITY(self, value: str) -> None:
        with self._lock:
            self._AUTHORITY_override = str(value)

    def as_safe_dict(self) -> Dict[str, Any]:
        return {
            "SECRET_KEY": "***",
            "CLIENT_ID": self.CLIENT_ID,
            "CLIENT_SECRET": "***",
            "TENANT_ID": self.TENANT_ID,
            "AUTHORITY": self.AUTHORITY,
            "REDIRECT_URI": self.REDIRECT_URI,
            "SCOPE": list(self.SCOPE),
            "ADMIN_GROUP_ID": self.ADMIN_GROUP_ID,
            "TICKET_MAIL": self.TICKET_MAIL,
            "SESSION_TIMEOUT": self.SESSION_TIMEOUT,
            "NINJA_POLL_INTERVAL": self.NINJA_POLL_INTERVAL,
            "NINJA_TOKEN": list(self.NINJA_TOKEN.keys()) if isinstance(self.NINJA_TOKEN, dict) else "***",
            "COMPANIES": list(self.COMPANIES),
        }

    def update(self, **fields: Any) -> None:
        with self._lock:
            allowed = {
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "SCOPE", "ADMIN_GROUP_ID", "TICKET_MAIL",
                "SESSION_TIMEOUT", "AUTHORITY",
                "NINJA_POLL_INTERVAL", "NINJA_TOKEN", "COMPANIES",
            }
            unknown = set(fields) - allowed
            if unknown:
                raise AttributeError(f"Unknown setting(s): {', '.join(sorted(unknown))}")

            if "SESSION_TIMEOUT" in fields:
                fields["SESSION_TIMEOUT"] = _coerce_int(fields["SESSION_TIMEOUT"], default=self.SESSION_TIMEOUT)
            if "NINJA_POLL_INTERVAL" in fields:
                fields["NINJA_POLL_INTERVAL"] = _coerce_int(fields["NINJA_POLL_INTERVAL"], default=self.NINJA_POLL_INTERVAL)
            if "SCOPE" in fields:
                fields["SCOPE"] = _coerce_scope(fields["SCOPE"], default=self.SCOPE)
            if "COMPANIES" in fields:
                fields["COMPANIES"] = _coerce_scope(fields["COMPANIES"], default=self.COMPANIES)
            if "NINJA_TOKEN" in fields and fields["NINJA_TOKEN"] is not None:
                if isinstance(fields["NINJA_TOKEN"], str):
                    try:
                        fields["NINJA_TOKEN"] = json.loads(fields["NINJA_TOKEN"])
                    except Exception:
                        pass

            string_keys = {"SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                           "REDIRECT_URI", "ADMIN_GROUP_ID", "TICKET_MAIL"}
            for k in list(fields.keys()):
                if k in string_keys and fields[k] is not None:
                    fields[k] = str(fields[k])
            if "AUTHORITY" in fields and fields["AUTHORITY"] is not None:
                fields["AUTHORITY"] = str(fields["AUTHORITY"])

            if "AUTHORITY" in fields:
                self.AUTHORITY = fields.pop("AUTHORITY")

            for k, v in fields.items():
                setattr(self, k, v)

            to_persist: Dict[str, Any] = {}
            for key in [
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "SCOPE", "ADMIN_GROUP_ID", "TICKET_MAIL",
                "SESSION_TIMEOUT", "NINJA_POLL_INTERVAL", "NINJA_TOKEN", "COMPANIES",
            ]:
                if key in fields:
                    to_persist[key] = getattr(self, key)

            if self._AUTHORITY_override is not None:
                to_persist["AUTHORITY"] = self._AUTHORITY_override
            elif "TENANT_ID" in fields:
                to_persist["AUTHORITY"] = self.AUTHORITY

            for k, v in to_persist.items():
                db.settings_set(k, v)

            redacted = {k: ("***" if "SECRET" in k else v) for k, v in to_persist.items()}
            logger.info("Config updated: %s", redacted)

    @classmethod
    def load_from_db(cls) -> "Settings":
        db.init_db()

        seed_pairs: Dict[str, Any] = {}
        for k, default_val in _DEFAULTS.items():
            existing = db.settings_get(k, None)
            if existing is None:
                seed_val = _SEED_FROM_ENV.get(k)
                seed_pairs[k] = seed_val if seed_val is not None else default_val

        if db.settings_get("AUTHORITY", None) is None:
            tenant = seed_pairs.get("TENANT_ID", db.settings_get("TENANT_ID", _DEFAULTS["TENANT_ID"]))
            seed_pairs["AUTHORITY"] = f"https://login.microsoftonline.com/{tenant}"

        if seed_pairs:
            db.settings_init_defaults(seed_pairs)

        raw: Dict[str, Any] = db.settings_all()

        def _get_or_default(key: str) -> Any:
            return raw.get(key, _DEFAULTS[key])

        try:
            return cls(
                SECRET_KEY       = str(_get_or_default("SECRET_KEY")),
                CLIENT_ID        = str(_get_or_default("CLIENT_ID")),
                CLIENT_SECRET    = str(_get_or_default("CLIENT_SECRET")),
                TENANT_ID        = str(_get_or_default("TENANT_ID")),
                REDIRECT_URI     = str(_get_or_default("REDIRECT_URI")),
                SCOPE            = _coerce_scope(_get_or_default("SCOPE"), default=_DEFAULTS["SCOPE"]),
                ADMIN_GROUP_ID   = str(_get_or_default("ADMIN_GROUP_ID")),
                TICKET_MAIL      = str(_get_or_default("TICKET_MAIL")),
                SESSION_TIMEOUT  = _coerce_int(_get_or_default("SESSION_TIMEOUT"), default=_DEFAULTS["SESSION_TIMEOUT"]),
                NINJA_POLL_INTERVAL = _coerce_int(_get_or_default("NINJA_POLL_INTERVAL"), default=_DEFAULTS["NINJA_POLL_INTERVAL"]),
                NINJA_TOKEN      = _get_or_default("NINJA_TOKEN"),
                COMPANIES        = _coerce_scope(_get_or_default("COMPANIES"), default=_DEFAULTS["COMPANIES"]),
            )
        except Exception as e:
            logger.exception("Failed to load settings from DB, falling back to defaults. Error: %s", e)
            return cls(
                SECRET_KEY       = str(_DEFAULTS["SECRET_KEY"]),
                CLIENT_ID        = str(_DEFAULTS["CLIENT_ID"]),
                CLIENT_SECRET    = str(_DEFAULTS["CLIENT_SECRET"]),
                TENANT_ID        = str(_DEFAULTS["TENANT_ID"]),
                REDIRECT_URI     = str(_DEFAULTS["REDIRECT_URI"]),
                SCOPE            = list(_DEFAULTS["SCOPE"]),
                ADMIN_GROUP_ID   = str(_DEFAULTS["ADMIN_GROUP_ID"]),
                TICKET_MAIL      = str(_DEFAULTS["TICKET_MAIL"]),
                SESSION_TIMEOUT  = int(_DEFAULTS["SESSION_TIMEOUT"]),
                NINJA_POLL_INTERVAL = int(_DEFAULTS["NINJA_POLL_INTERVAL"]),
                NINJA_TOKEN      = dict(_DEFAULTS["NINJA_TOKEN"]),
                COMPANIES        = list(_DEFAULTS["COMPANIES"]),
            )


# ---------------------------
# Singleton-Instanz + Public API
# ---------------------------

cfg: Settings = Settings.load_from_db()

def reload_settings() -> None:
    global cfg
    new_cfg = Settings.load_from_db()
    with cfg._lock:
        for f in dataclasses.fields(Settings):
            if f.name in ("_lock", "_AUTHORITY_override"):
                continue
            setattr(cfg, f.name, getattr(new_cfg, f.name))
        cfg._AUTHORITY_override = new_cfg._AUTHORITY_override
    logger.info("Config reloaded (safe): %s", cfg.as_safe_dict())


def get_companies() -> List[str]:
    """Zentrale Lesefunktion für Firmenliste (DB‑gestützt via Settings).
    Warum: hält Aufrufer vom Settings-Objekt entkoppelt und erleichtert spätere Änderungen.
    """
    return list(cfg.COMPANIES)

# ---------------------------
# FastAPI/Starlette Convenience
# ---------------------------

def fastapi_settings_dep() -> Settings:
    return cfg


def get_companies() -> list[str]:
    return cfg.COMPANIES


def set_companies(com: list[str]):
    cfg.update(COMPANIES=com)