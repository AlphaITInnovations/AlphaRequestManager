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
        # evtl. float-artig
        try:
            return int(float(v))
        except ValueError:
            pass
    raise ValueError(f"Cannot coerce {v!r} to int")

def _coerce_scope(v: Any, *, default: List[str]) -> List[str]:
    if v is None:
        return list(default)
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str):
        # z. B. "User.Read,Mail.Send"
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
        return raw  # fallback: plain string


# ---------------------------
# Defaults (nur Fallback/Seeding)
# ---------------------------

_DEFAULTS: Dict[str, Any] = {
    "SECRET_KEY": "",
    "CLIENT_ID": "",
    "CLIENT_SECRET": "",
    "TENANT_ID": "",
    # AUTHORITY wird dynamisch aus TENANT_ID abgeleitet
    "REDIRECT_URI": "",
    "SCOPE": ["User.Read", "Mail.Send"],
    "ADMIN_GROUP_ID": "",
    "TICKET_MAIL": "",
    "SESSION_TIMEOUT": 15 * 60,
}

# ENV-Overrides für Initial-Seeding (einmalig, wenn Key in DB fehlt)
# Beispiel: setze im Deployment SECRET_KEY, CLIENT_SECRET etc. als ENV.
_SEED_FROM_ENV: Dict[str, Any] = {
    "SECRET_KEY": _env("SECRET_KEY"),
    "CLIENT_ID": _env("CLIENT_ID"),
    "CLIENT_SECRET": _env("CLIENT_SECRET"),
    "TENANT_ID": _env("TENANT_ID"),
    "REDIRECT_URI": _env("REDIRECT_URI"),
    "SCOPE": _env_json("SCOPE"),            # darf JSON oder CSV sein
    "ADMIN_GROUP_ID": _env("ADMIN_GROUP_ID"),
    "TICKET_MAIL": _env("TICKET_MAIL"),
    "SESSION_TIMEOUT": _env("SESSION_TIMEOUT"),
}


# ---------------------------
# Dataclass mit Properties (Autocomplete!)
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

    # AUTHORITY ist abgeleitet, kann aber explizit überschrieben werden (falls nötig)
    _AUTHORITY_override: Optional[str] = field(default=None, repr=False)

    # interne Synchronisation
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    # ---------- Properties ----------

    @property
    def AUTHORITY(self) -> str:
        if self._AUTHORITY_override:
            return self._AUTHORITY_override
        return f"https://login.microsoftonline.com/{self.TENANT_ID}"

    @AUTHORITY.setter
    def AUTHORITY(self, value: str) -> None:
        # Wenn explizit gesetzt, behalten wir den Override
        with self._lock:
            self._AUTHORITY_override = str(value)

    # ---------- Public API ----------

    def as_safe_dict(self) -> Dict[str, Any]:
        """
        Für Logging/Debug/Frontend: nur „öffentliche“ Werte,
        Secrets geschwärzt, keine deepcopy/asdict (vermeidet RLock-Problem).
        """
        return {
            "SECRET_KEY": "***",                       # redacted
            "CLIENT_ID": self.CLIENT_ID,
            "CLIENT_SECRET": "***",                    # redacted
            "TENANT_ID": self.TENANT_ID,
            "AUTHORITY": self.AUTHORITY,               # abgeleitet oder Override
            "REDIRECT_URI": self.REDIRECT_URI,
            "SCOPE": list(self.SCOPE),
            "ADMIN_GROUP_ID": self.ADMIN_GROUP_ID,
            "TICKET_MAIL": self.TICKET_MAIL,
            "SESSION_TIMEOUT": self.SESSION_TIMEOUT,
        }

    # in alpharequestmanager/config.py -> innerhalb der Dataclass Settings

    def update(self, **fields: Any) -> None:
        """
        Laufende Updates + Persistenz:
            cfg.update(SESSION_TIMEOUT=1200)
            cfg.update(TENANT_ID="abcd-1234")  # AUTHORITY zieht automatisch mit (sofern kein Override gesetzt)
            cfg.update(AUTHORITY="https://login.microsoftonline.com/custom")  # expliziter Override
        """
        with self._lock:
            # --- Validierung: nur bekannte Keys erlauben ---
            allowed = {
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "SCOPE", "ADMIN_GROUP_ID", "TICKET_MAIL",
                "SESSION_TIMEOUT", "AUTHORITY"
            }
            unknown = set(fields) - allowed
            if unknown:
                raise AttributeError(f"Unknown setting(s): {', '.join(sorted(unknown))}")

            # --- Coercion/Normalisierung ---
            # Typ-sichere Felder
            if "SESSION_TIMEOUT" in fields:
                fields["SESSION_TIMEOUT"] = _coerce_int(fields["SESSION_TIMEOUT"], default=self.SESSION_TIMEOUT)
            if "SCOPE" in fields:
                fields["SCOPE"] = _coerce_scope(fields["SCOPE"], default=self.SCOPE)

            # Reine String-Felder immer zu str() normalisieren (z. B. EmailStr/AnyUrl von Pydantic)
            string_keys = {"SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                           "REDIRECT_URI", "ADMIN_GROUP_ID", "TICKET_MAIL"}
            for k in list(fields.keys()):
                if k in string_keys and fields[k] is not None:
                    fields[k] = str(fields[k])
            if "AUTHORITY" in fields and fields["AUTHORITY"] is not None:
                fields["AUTHORITY"] = str(fields["AUTHORITY"])

            # --- In-Memory aktualisieren ---
            # AUTHORITY: spezieller Fall – Setter setzt Override
            if "AUTHORITY" in fields:
                self.AUTHORITY = fields.pop("AUTHORITY")

            # Restliche Felder direkt setzen
            for k, v in fields.items():
                setattr(self, k, v)

            # --- Persistenz vorbereiten ---
            to_persist: Dict[str, Any] = {}
            # Basiskonfiguration schreiben, aber nur geänderte Keys
            for key in [
                "SECRET_KEY", "CLIENT_ID", "CLIENT_SECRET", "TENANT_ID",
                "REDIRECT_URI", "SCOPE", "ADMIN_GROUP_ID", "TICKET_MAIL",
                "SESSION_TIMEOUT"
            ]:
                if key in fields:
                    to_persist[key] = getattr(self, key)

            # AUTHORITY-Strategie:
            #  - Wenn Override aktiv → AUTHORITY explizit speichern
            #  - Sonst, falls TENANT_ID geändert wurde → abgeleitete AUTHORITY mitschreiben
            if self._AUTHORITY_override is not None:
                to_persist["AUTHORITY"] = self._AUTHORITY_override
            elif "TENANT_ID" in fields:
                to_persist["AUTHORITY"] = self.AUTHORITY

            # --- In DB speichern ---
            for k, v in to_persist.items():
                db.settings_set(k, v)

            # --- Logging (Secrets geschwärzt) ---
            redacted = {k: ("***" if "SECRET" in k else v) for k, v in to_persist.items()}
            logger.info("Config updated: %s", redacted)

    # ---------- Klassmethoden ----------

    @classmethod
    def load_from_db(cls) -> "Settings":
        """
        Lädt Settings aus DB, seedet fehlende Keys aus ENV/Defaults (einmalig).
        """
        db.init_db()

        # 1) Seed fehlende Keys (ENV > Defaults)
        seed_pairs: Dict[str, Any] = {}
        for k, default_val in _DEFAULTS.items():
            existing = db.settings_get(k, None)
            if existing is None:
                seed_val = _SEED_FROM_ENV.get(k)
                seed_pairs[k] = seed_val if seed_val is not None else default_val

        # AUTHORITY konsistent seed’en (falls fehlt)
        if db.settings_get("AUTHORITY", None) is None:
            tenant = seed_pairs.get("TENANT_ID", db.settings_get("TENANT_ID", _DEFAULTS["TENANT_ID"]))
            seed_pairs["AUTHORITY"] = f"https://login.microsoftonline.com/{tenant}"

        if seed_pairs:
            db.settings_init_defaults(seed_pairs)

        # 2) Alle lesen + coerces
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
            )
        except Exception as e:
            logger.exception("Failed to load settings from DB, falling back to defaults. Error: %s", e)
            # harte Fallbacks, damit App überhaupt startet
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
            )


# ---------------------------
# Singleton-Instanz + Public API
# ---------------------------

# Eine einzige live-Instanz -> überall importierbar, Autocomplete auf Attributen
cfg: Settings = Settings.load_from_db()

def reload_settings() -> None:
    """
    Lädt Settings vollständig neu aus der DB und aktualisiert die Singleton-Instanz IN PLACE,
    ohne deepcopy/asdict (damit kein RLock-Fehler).
    """
    global cfg
    new_cfg = Settings.load_from_db()
    with cfg._lock:
        # Alle Dataclass-Felder (ohne _lock / _AUTHORITY_override) kopieren
        for f in dataclasses.fields(Settings):
            if f.name in ("_lock", "_AUTHORITY_override"):
                continue
            setattr(cfg, f.name, getattr(new_cfg, f.name))
        # Override separat übernehmen
        cfg._AUTHORITY_override = new_cfg._AUTHORITY_override
    logger.info("Config reloaded (safe): %s", cfg.as_safe_dict())


# ---------------------------
# FastAPI/Starlette Convenience
# ---------------------------

def fastapi_settings_dep() -> Settings:
    """
    Dependency, falls du in Endpoints typisierte Settings willst:
        from fastapi import Depends
        from alpharequestmanager.config import fastapi_settings_dep

        @app.get("/health")
        def health(cfg: Settings = Depends(fastapi_settings_dep)):
            return {"authority": cfg.AUTHORITY}
    """
    return cfg
