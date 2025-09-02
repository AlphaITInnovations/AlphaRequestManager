# File: alpharequestmanager/config.py
from __future__ import annotations

import dataclasses
import json
import threading
from dataclasses import dataclass, field
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
    # Neu: Firmenliste (Fallback, wird durch DB überschrieben)
    "COMPANIES": [
        "AlphaConsult KG",
        "Alpha-Med KG",
        "AlphaConsult Premium KG",
    ],
    # NEU: Ninja OAuth Felder (Defaults sind leer, da tenant-/systemabhängig)
    "NINJA_CLIENT_ID": "",
    "NINJA_CLIENT_SECRET": "",
    "NINJA_REDIRECT_URI": "",
    "NINJA_AUTH_URL": "",
    "NINJA_TOKEN_URL": "",
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

    # NEU: Ninja OAuth Felder
    NINJA_CLIENT_ID: str
    NINJA_CLIENT_SECRET: str
    NINJA_REDIRECT_URI: str
    NINJA_AUTH_URL: str
    NINJA_TOKEN_URL: str

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
        # Wichtig: Secrets maskieren
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
            # Ninja Felder
            "NINJA_CLIENT_ID": self.NINJA_CLIENT_ID,
            "NINJA_CLIENT_SECRET": "***",
            "NINJA_REDIRECT_URI": self.NINJA_REDIRECT_URI,
            "NINJA_AUTH_URL": self.NINJA_AUTH_URL,
            "NINJA_TOKEN_URL": self.NINJA_TOKEN_URL,
        }

    def update(self, **fields: Any) -> None:
        with self._lock:
            allowed = {
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "SCOPE", "ADMIN_GROUP_ID", "TICKET_MAIL",
                "SESSION_TIMEOUT", "AUTHORITY",
                "NINJA_POLL_INTERVAL", "NINJA_TOKEN", "COMPANIES",
                # Ninja Felder
                "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET", "NINJA_REDIRECT_URI",
                "NINJA_AUTH_URL", "NINJA_TOKEN_URL",
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
                        # why: tolerieren, falls bereits dict-ähnlicher String, aber kein JSON
                        pass

            string_keys = {
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "ADMIN_GROUP_ID", "TICKET_MAIL",
                # Ninja Felder als Strings
                "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET", "NINJA_REDIRECT_URI",
                "NINJA_AUTH_URL", "NINJA_TOKEN_URL",
            }
            for k in list(fields.keys()):
                if k in string_keys and fields[k] is not None:
                    fields[k] = str(fields[k])
            if "AUTHORITY" in fields and fields["AUTHORITY"] is not None:
                fields["AUTHORITY"] = str(fields["AUTHORITY"])  # stored via override

            # AUTHORITY setter getrennt behandeln (setzt Override)
            if "AUTHORITY" in fields:
                self.AUTHORITY = fields.pop("AUTHORITY")

            # In-Memory aktualisieren
            for k, v in fields.items():
                setattr(self, k, v)

            # Persistenz-Vorbereitung
            to_persist: Dict[str, Any] = {}
            for key in [
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "SCOPE", "ADMIN_GROUP_ID", "TICKET_MAIL",
                "SESSION_TIMEOUT", "NINJA_POLL_INTERVAL", "NINJA_TOKEN", "COMPANIES",
                # Ninja Felder
                "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET", "NINJA_REDIRECT_URI",
                "NINJA_AUTH_URL", "NINJA_TOKEN_URL",
            ]:
                if key in fields:
                    to_persist[key] = getattr(self, key)

            # AUTHORITY optional mitpersistieren
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

        # Seed: NUR Defaults in DB schreiben, falls Keys fehlen (kein ENV mehr)
        seed_pairs: Dict[str, Any] = {}
        for k, default_val in _DEFAULTS.items():
            if db.settings_get(k, None) is None:
                seed_pairs[k] = default_val

        # AUTHORITY initial aus TENANT_ID ableiten, falls fehlt
        if db.settings_get("AUTHORITY", None) is None:
            tenant = db.settings_get("TENANT_ID", _DEFAULTS["TENANT_ID"]) or ""
            seed_pairs["AUTHORITY"] = f"https://login.microsoftonline.com/{tenant}"

        if seed_pairs:
            db.settings_init_defaults(seed_pairs)

        raw: Dict[str, Any] = db.settings_all()

        def _get_or_default(key: str) -> Any:
            return raw.get(key, _DEFAULTS[key])

        try:
            settings = cls(
                SECRET_KEY          = str(_get_or_default("SECRET_KEY")),
                CLIENT_ID           = str(_get_or_default("CLIENT_ID")),
                CLIENT_SECRET       = str(_get_or_default("CLIENT_SECRET")),
                TENANT_ID           = str(_get_or_default("TENANT_ID")),
                REDIRECT_URI        = str(_get_or_default("REDIRECT_URI")),
                SCOPE               = _coerce_scope(_get_or_default("SCOPE"), default=_DEFAULTS["SCOPE"]),
                ADMIN_GROUP_ID      = str(_get_or_default("ADMIN_GROUP_ID")),
                TICKET_MAIL         = str(_get_or_default("TICKET_MAIL")),
                SESSION_TIMEOUT     = _coerce_int(_get_or_default("SESSION_TIMEOUT"), default=_DEFAULTS["SESSION_TIMEOUT"]),
                NINJA_POLL_INTERVAL = _coerce_int(_get_or_default("NINJA_POLL_INTERVAL"), default=_DEFAULTS["NINJA_POLL_INTERVAL"]),
                NINJA_TOKEN         = _get_or_default("NINJA_TOKEN"),
                COMPANIES           = _coerce_scope(_get_or_default("COMPANIES"), default=_DEFAULTS["COMPANIES"]),
                # Ninja Felder
                NINJA_CLIENT_ID     = str(_get_or_default("NINJA_CLIENT_ID")),
                NINJA_CLIENT_SECRET = str(_get_or_default("NINJA_CLIENT_SECRET")),
                NINJA_REDIRECT_URI  = str(_get_or_default("NINJA_REDIRECT_URI")),
                NINJA_AUTH_URL      = str(_get_or_default("NINJA_AUTH_URL")),
                NINJA_TOKEN_URL     = str(_get_or_default("NINJA_TOKEN_URL")),
            )

            # AUTHORITY-Override aus DB übernehmen, falls vorhanden
            authority_from_db = raw.get("AUTHORITY")
            if authority_from_db:
                settings._AUTHORITY_override = str(authority_from_db)

            return settings

        except Exception as e:
            logger.exception("Failed to load settings from DB, falling back to defaults. Error: %s", e)
            settings = cls(
                SECRET_KEY          = str(_DEFAULTS["SECRET_KEY"]),
                CLIENT_ID           = str(_DEFAULTS["CLIENT_ID"]),
                CLIENT_SECRET       = str(_DEFAULTS["CLIENT_SECRET"]),
                TENANT_ID           = str(_DEFAULTS["TENANT_ID"]),
                REDIRECT_URI        = str(_DEFAULTS["REDIRECT_URI"]),
                SCOPE               = list(_DEFAULTS["SCOPE"]),
                ADMIN_GROUP_ID      = str(_DEFAULTS["ADMIN_GROUP_ID"]),
                TICKET_MAIL         = str(_DEFAULTS["TICKET_MAIL"]),
                SESSION_TIMEOUT     = int(_DEFAULTS["SESSION_TIMEOUT"]),
                NINJA_POLL_INTERVAL = int(_DEFAULTS["NINJA_POLL_INTERVAL"]),
                NINJA_TOKEN         = dict(_DEFAULTS["NINJA_TOKEN"]),
                COMPANIES           = list(_DEFAULTS["COMPANIES"]),
                # Ninja Felder
                NINJA_CLIENT_ID     = str(_DEFAULTS["NINJA_CLIENT_ID"]),
                NINJA_CLIENT_SECRET = str(_DEFAULTS["NINJA_CLIENT_SECRET"]),
                NINJA_REDIRECT_URI  = str(_DEFAULTS["NINJA_REDIRECT_URI"]),
                NINJA_AUTH_URL      = str(_DEFAULTS["NINJA_AUTH_URL"]),
                NINJA_TOKEN_URL     = str(_DEFAULTS["NINJA_TOKEN_URL"]),
            )
            return settings


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


# ---------------------------
# Convenience API
# ---------------------------

def fastapi_settings_dep() -> Settings:
    return cfg


def get_companies() -> List[str]:
    return list(cfg.COMPANIES)


def set_companies(com: List[str]) -> None:
    cfg.update(COMPANIES=com)
