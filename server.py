# server.py — session/token robust fix for MS OAuth redirect-loop
# Goal: avoid redirect loops by keeping the session cookie tiny and stable,
# move tokens server-side, and use safe cookie attributes.

import json
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import time
import uuid

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from httpx import HTTPStatusError
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse
from starlette.status import HTTP_302_FOUND
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel, Field, AnyUrl, EmailStr, field_validator
from contextlib import asynccontextmanager

from alpharequestmanager import graph, database, ninja_api, ninja_sync
from alpharequestmanager.database import update_ticket
from alpharequestmanager.graph import get_user_profile, send_mail
from alpharequestmanager.config import cfg as config
from alpharequestmanager.auth import initiate_auth_flow, acquire_token_by_auth_code
from alpharequestmanager.dependencies import get_current_user
from alpharequestmanager.logger import logger
from alpharequestmanager.manager import RequestManager
from alpharequestmanager.models import RequestStatus, TicketType

from html import escape  # add near other imports
from typing import Any

from collections import Counter, defaultdict
from typing import Optional
from fastapi import Query
from datetime import datetime
import json as _json

RUNTIME_SESSION_TIMEOUT = config.SESSION_TIMEOUT

# -------------------------------
# Lightweight server-side token store (in-memory)
# -------------------------------

class TokenStore:
    """Server-side token storage to keep cookies small.
    For production, replace with Redis or a DB.
    """
    def __init__(self) -> None:
        self._db: Dict[str, Dict[str, Any]] = {}

    def put(self, sid: str, tokens: Dict[str, Any]) -> None:
        self._db[sid] = {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
            # naive expiry; prefer token's real expires_in/exp claim
            "expires_at": time.time() + 3500,
        }

    def get(self, sid: str) -> Optional[Dict[str, Any]]:
        data = self._db.get(sid)
        if not data:
            return None
        return data

    def delete(self, sid: str) -> None:
        self._db.pop(sid, None)


TOKENS = TokenStore()


def ensure_sid(session: dict) -> str:
    sid = session.get("sid")
    if not sid:
        sid = uuid.uuid4().hex
        session["sid"] = sid
    return sid


def rotate_sid(session: dict) -> str:
    """Generate a fresh SID on login to prevent session fixation.
    Removes any server-side tokens bound to the old SID.
    """
    old = session.get("sid")
    new = uuid.uuid4().hex
    session["sid"] = new
    if old:
        TOKENS.delete(old)
    return new


def approx_cookie_size_bytes(session: dict) -> int:
    try:
        raw = json.dumps(session, separators=(",", ":"))
        return len(raw.encode("utf-8"))
    except Exception:
        return -1


def get_access_token_from_store(request: Request) -> Optional[str]:
    sid = request.session.get("sid")
    if not sid:
        return None
    rec = TOKENS.get(sid)
    if not rec:
        return None
    # optional: refresh here when expired
    return rec.get("access_token")


# -------------------------------
# App
# -------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=ninja_sync.start_polling, daemon=True)
    thread.start()
    yield


app = FastAPI(lifespan=lifespan)

# IMPORTANT: Keep cookie first‑party and small; Lax fits OAuth top-level redirects
app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    session_cookie="app_session",
    same_site="lax",  # was "none"; Lax avoids some browser drops
    https_only=True,   # keep True on HTTPS; set via env if you need HTTP for local dev
    max_age=config.SESSION_TIMEOUT,
    # domain=config.COOKIE_DOMAIN if you add it to cfg
    path="/",
)


templates = Jinja2Templates(directory="alpharequestmanager/templates")
templates.env.globals['SESSION_TIMEOUT'] = RUNTIME_SESSION_TIMEOUT

manager = RequestManager()

app.mount("/static", StaticFiles(directory="alpharequestmanager/static"), name="static")


# -------------------------------
# LOGIN & AUTH
# -------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/start-auth")
async def start_auth(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)
    auth_url = initiate_auth_flow(request)
    return RedirectResponse(auth_url)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        logger.info("➡️ Session vor Token-Abruf: %s", dict(request.session))

        flow = request.session.get("auth_flow")
        if not flow:
            raise HTTPException(status_code=400, detail="OAuth Flow fehlt")

        result = acquire_token_by_auth_code(request)
        logger.info("🔁 Token Result keys: %s", list(result.keys()) if isinstance(result, dict) else type(result))

        if not result or "access_token" not in result:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Tokenfehler"})

        id_claims = result.get("id_token_claims", {}) or {}
        logger.info("🪪 ID Claims keys: %s", list(id_claims.keys()))

        # Keep only essentials in the cookie
        infos = {}
        try:
            infos = await get_user_profile(result["access_token"])  # don't stuff this into the cookie
        except Exception:
            logger.exception("Graph-Call fehlgeschlagen")

        user_payload = {
            "id": id_claims.get("oid") or id_claims.get("sub"),
            "displayName": id_claims.get("name") or infos.get("displayName"),
            "email": id_claims.get("preferred_username") or id_claims.get("email") or infos.get("mail"),
            "is_admin": config.ADMIN_GROUP_ID in (id_claims.get("groups", []) or []),
            # keep templates happy; small fields only
            "phone": (infos or {}).get("phone"),
            "mobile": (infos or {}).get("mobile"),
            "company": (infos or {}).get("company"),
            "position": (infos or {}).get("position"),
            "address": ((infos or {}).get("address") or {}),
        }

        # Rotate SID on successful login and store tokens server-side
        sid = rotate_sid(request.session)
        TOKENS.put(sid, result)

        request.session.update({
            "user": user_payload,
            "last_activity": int(time.time()),
        })
        request.session.pop("auth_flow", None)

        # Guard: if cookie would be too big, shrink it to bare minimum
        size = approx_cookie_size_bytes(request.session)
        if size < 0 or size > 3000:  # keep well below browser limits
            logger.warning("Session cookie too large (%s bytes). Shrinking payload.", size)
            request.session.clear()
            request.session["sid"] = sid
            request.session["user"] = user_payload
            request.session["last_activity"] = int(time.time())

        logger.info("✅ Session nach Schreiben: %s", dict(request.session))
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)

    except Exception as e:
        logger.exception("Login fehlgeschlagen")
        return templates.TemplateResponse("login.html", {"request": request, "error": str(e)})


# -------------------------------
# DASHBOARD & TICKETS
# -------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(get_current_user)):
    raw = manager.list_tickets(owner_id=user["id"])
    orders = [
        {
            "id": t.id,
            "type": t.title,
            "date": t.created_at.strftime("%d.%m.%Y"),
            "status": t.status.value,
            "comment": t.comment,
            "description": t.description,
        } for t in raw
    ]
    companies = config.COMPANIES
    is_admin = user.get("is_admin", False)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "orders": orders,
            "is_admin": is_admin,
            "companies_json": companies
        }
    )


@app.post("/tickets")
async def create_ticket(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    user: dict = Depends(get_current_user)
):
    desc_obj = json.loads(description)
    data = desc_obj.get("data", {})
    ticket_type = desc_obj.get("ticketType")
    user_mail = user["email"]
    """
    description_plain = description + format_user_info_plain(user)
    description_html = f"<p>{description}</p>" + format_user_info_html(user)
    description_obj = {
        "public": True,
        "body": description_plain,
        "htmlBody": description_html
    }
    """

    description_obj = make_ninja_description(desc_obj, user)

    ticket = None
    if ticket_type == "Hardwarebestellung":
        ticket = ninja_api.create_ticket_hardware(description=description_obj, requester_mail=user_mail)
    elif ticket_type == "EDV-Zugang sperren":
        ticket = ninja_api.create_ticket_edv_sperren(description=description_obj, requester_mail=user_mail)
    elif ticket_type == "EDV-Zugang beantragen":
        arbeitsbeginn_ts = None
        if "arbeitsbeginn" in data and data["arbeitsbeginn"]:
            dt = datetime.fromisoformat(data["arbeitsbeginn"])
            arbeitsbeginn_ts = int(dt.timestamp())

        info_text = "Bitte die Daten links im Ticket prüfen und anschließend freigeben"
        edv_desc = _desc_with_user_info(info_text, user)

        datev_user = data.get("datev")
        if datev_user:
            datev_user=True
        else:
            datev_user=False

        elo_user = data.get("elo")
        if elo_user:
            elo_user=True
        else:
            elo_user=False

        ticket = ninja_api.create_ticket_edv_beantragen(
            description=edv_desc,
            vorname=data.get("vorname", ""),
            nachname=data.get("nachname", ""),
            firma=data.get("firma", ""),
            arbeitsbeginn=arbeitsbeginn_ts,
            titel=data.get("titel", ""),
            strasse=data.get("strasse", ""),
            ort=data.get("ort", ""),
            plz=data.get("plz", ""),
            handy=data.get("handy", ""),
            telefon=data.get("telefon", ""),
            fax=data.get("fax", ""),
            niederlassung=data.get("niederlassung", ""),
            kostenstelle=data.get("kostenstelle", ""),
            kommentar=data.get("kommentar", ""),
            requester_mail=user_mail,
            checkbox_datev_user=datev_user,
            checkbox_elo_user=elo_user,
        )
    elif ticket_type == "Niederlassung anmelden":
        ticket = ninja_api.create_ticket_niederlassung_anmelden(description=description_obj, requester_mail=user_mail)
    elif ticket_type == "Niederlassung umziehen":
        ticket = ninja_api.create_ticket_niederlassung_umziehen(description=description_obj, requester_mail=user_mail)
    elif ticket_type == "Niederlassung schließen":
        ticket = ninja_api.create_ticket_niederlassung_schließen(description=description_obj, requester_mail=user_mail)

    if not ticket or "id" not in ticket:
        raise HTTPException(status_code=500, detail="Ticket konnte in Ninja nicht erstellt werden")

    ninja_id = ticket["id"]

    ticket_id = manager.submit_ticket(
        title=title,
        description=description,
        owner_id=user["id"],
        owner_name=user["displayName"],
        owner_info=json.dumps(user, ensure_ascii=False)
    )
    manager.set_ninja_metadata(ticket_id, ninja_id)

    logger.info("✅ Ticket erstellt: Lokale ID %s / Ninja ID %s für %s", ticket_id, ninja_id, user_mail)
    return RedirectResponse(url="/dashboard", status_code=HTTP_302_FOUND)


@app.get("/logout")
async def logout(request: Request):
    user_email = request.session.get("user", {}).get("email")
    sid = request.session.get("sid")
    if sid:
        TOKENS.delete(sid)
    request.session.clear()
    logger.info("User logged out: %s", user_email)
    return RedirectResponse("/login", status_code=HTTP_302_FOUND)


# -------------------------------
# ADMIN-PRÜFUNG
# -------------------------------

@app.get("/pruefung", response_class=HTMLResponse)
async def pruefung(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)

    items = []
    for t in manager.list_all_tickets():
        try:
            description_parsed = json.loads(t.description)
        except Exception as e:
            print(f"Fehler beim Parsen der Ticketbeschreibung (ID {t.id}):", e)
            description_parsed = {}

        item = {
            "id": t.id,
            "type": t.title,
            "date": t.created_at.strftime("%d.%m.%Y"),
            "creator": t.owner_name,
            "status": t.status.value,
            "description": description_parsed,
            "owner_info": json.loads(t.owner_info) if t.owner_info else None,
            "ninja_metadata": json.loads(t.ninja_metadata) if t.ninja_metadata else None

        }
        items.append(item)

    items_json = json.dumps(items, ensure_ascii=False)
    return templates.TemplateResponse(
        "pruefung.html",
        {"request": request, "user": user, "items_json": items_json, "is_admin": user.get("is_admin")}
    )


@app.post("/pruefung/approve")
async def approve_ticket(
    request: Request,
    ticket_id: int = Form(...),
    comment: str = Form(""),
    description_json: str = Form(""),
    user: dict = Depends(get_current_user)
):
    if description_json.strip():
        try:
            description_data = json.loads(description_json)
            update_ticket(ticket_id, description=json.dumps(description_data, ensure_ascii=False))
        except Exception as e:
            print(f"Fehler beim Parsen/Speichern der Beschreibung (ID {ticket_id}):", e)

    update_ticket(ticket_id, status=RequestStatus.approved)
    manager.set_comment(ticket_id, comment)
    logger.info("Ticket approved: %s by admin %s", ticket_id, user["displayName"])

    # Use server-side token store
    access_token = get_access_token_from_store(request)

    # TODO: use access_token with Graph if needed
    # ticketType handling omitted for brevity as in original code

    return RedirectResponse("/pruefung", status_code=HTTP_302_FOUND)


@app.post("/pruefung/reject")
async def reject_ticket(
    ticket_id: int = Form(...),
    comment: str = Form(""),
    description_json: str = Form(""),
    user: dict = Depends(get_current_user)
):
    if description_json.strip():
        try:
            description_data = json.loads(description_json)
            update_ticket(ticket_id, description=json.dumps(description_data, ensure_ascii=False))
        except Exception as e:
            print(f"Fehler beim Parsen/Speichern der Beschreibung (ID {ticket_id}):", e)

    update_ticket(ticket_id, status=RequestStatus.rejected)
    manager.set_comment(ticket_id, comment)
    logger.info("Ticket rejected: %s by admin %s", ticket_id, user["displayName"])
    return RedirectResponse("/pruefung", status_code=HTTP_302_FOUND)



def _user_can_delete_ticket(user: dict, ticket_id: int) -> bool:
    """Erlaubt Löschen für Admins oder Besitzer des Tickets.
    Warum: verhindert, dass Nutzer fremde Tickets löschen.
    """
    if user.get("is_admin", False):
        return True
    try:
        owned = database.list_tickets_by_owner(user["id"]) # minimaler Check ohne Extra-DB-Funktion
    except Exception:
        logger.exception("Konnte Tickets des Users nicht laden")
        return False
    return any(t.id == ticket_id for t in owned)



@app.post("/tickets/{ticket_id}/delete")
async def delete_ticket_form(ticket_id: int, user: dict = Depends(get_current_user)):
    if not _user_can_delete_ticket(user, ticket_id):
        raise HTTPException(status_code=403, detail="Kein Zugriff auf dieses Ticket")
    ok = database.delete_ticket(ticket_id)

    if not ok:
        raise HTTPException(status_code=404, detail="Ticket nicht gefunden")


    logger.info("Ticket gelöscht: id=%s von %s", ticket_id, user.get("email"))
    target = "/pruefung" if user.get("is_admin", False) else "/dashboard"
    return RedirectResponse(url=target, status_code=HTTP_302_FOUND)

# -------------------------------
# DEBUG / SESSION TESTING
# -------------------------------

@app.get("/test-session")
def test_session(request: Request):
    request.session["foo"] = "bar"
    return {"msg": "Session gesetzt"}


@app.get("/check-session")
def check_session(request: Request):
    return {"foo": request.session.get("foo")}


@app.get("/debug-session")
def debug_session(request: Request):
    size = approx_cookie_size_bytes(dict(request.session))
    return {
        "session_raw": request.session,
        "user": request.session.get("user"),
        "sid": request.session.get("sid"),
        "cookie_size_bytes_estimate": size,
        "has_server_token": bool(get_access_token_from_store(request)),
    }


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/login")

"""
@app.post("/send-mail")
async def send_mail_endpoint(
    request: Request,
    subject: str = Body(...),
    content: str = Body(...),
    user: dict = Depends(get_current_user),
):
    access_token = get_access_token_from_store(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Access token missing")

    try:
        await send_mail(access_token, subject, content)
    except HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    return {"status": "sent"}
"""

# -----------------
# Admin Settings Panel
# --------------------

# ✨ Neu: Helfer für Admin-Only

def require_admin(user: dict):
    if not user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")


class SettingsUpdate(BaseModel):
    SECRET_KEY: Optional[str] = Field(None, min_length=8)
    CLIENT_ID: Optional[str] = Field(None, min_length=1)
    CLIENT_SECRET: Optional[str] = Field(None, min_length=1)
    TENANT_ID: Optional[str] = Field(None, min_length=1)
    AUTHORITY: Optional[AnyUrl] = None
    REDIRECT_URI: Optional[AnyUrl] = None
    SCOPE: Optional[list[str]] = None
    ADMIN_GROUP_ID: Optional[str] = None
    TICKET_MAIL: Optional[EmailStr] = None
    SESSION_TIMEOUT: Optional[int] = Field(None, ge=60, le=24*60*60)

    @field_validator("SCOPE", mode="before")
    @classmethod
    def coerce_scope(cls, v):
        if v is None:
            return v
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            parts = [p.strip() for p in v.split(",") if p.strip()]
            return parts
        raise ValueError("SCOPE must be list[str] or CSV string")


@app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings_page(request: Request, user: dict = Depends(get_current_user)):
    require_admin(user)
    safe = config.as_safe_dict()
    return templates.TemplateResponse(
        "admin_settings.html",
        {"request": request, "user": user, "settings": safe, "is_admin": user.get("is_admin")}
    )


@app.get("/api/admin/settings")
async def api_get_settings(user: dict = Depends(get_current_user)):
    require_admin(user)
    safe = config.as_safe_dict()
    safe["runtime_session_timeout"] = RUNTIME_SESSION_TIMEOUT
    return safe


@app.put("/api/admin/settings")
async def api_update_settings(payload: SettingsUpdate, user: dict = Depends(get_current_user)):
    require_admin(user)

    changes = json.loads(payload.model_dump_json(exclude_unset=True))

    if not changes:
        return {"ok": True, "settings": config.as_safe_dict()}

    try:
        config.update(**changes)
    except Exception as e:
        logger.exception("Settings update failed")
        raise HTTPException(status_code=400, detail=str(e))

    templates.env.globals['SESSION_TIMEOUT'] = config.SESSION_TIMEOUT

    restart_required = (
        "SESSION_TIMEOUT" in changes
        and int(changes["SESSION_TIMEOUT"]) != int(RUNTIME_SESSION_TIMEOUT)
    ) if 'RUNTIME_SESSION_TIMEOUT' in globals() else False

    return {
        "ok": True,
        "settings": config.as_safe_dict(),
        "runtime_session_timeout": globals().get("RUNTIME_SESSION_TIMEOUT"),
        "restart_required": restart_required,
        "note": "Änderungen an SESSION_TIMEOUT werden erst nach Neustart wirksam." if restart_required else None,
    }


@app.get("/api/orders", response_class=JSONResponse)
async def api_orders(user: dict = Depends(get_current_user)):
    raw = manager.list_tickets(owner_id=user["id"])
    orders = [
        {
            "id": t.id,
            "type": t.title,
            "date": t.created_at.strftime("%d.%m.%Y"),
            "status": t.status.value,
            "comment": t.comment,
            "description": t.description,
        }
        for t in raw
    ]
    return orders



class CompaniesPayload(BaseModel):
    companies: list[str]

class CompaniesResponse(BaseModel):
    companies: list[str]
    count: int

def _normalize_companies(items: list[str]) -> list[str]:
    """Trim + de-duplicate (case-insensitive)."""

    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        name = str(raw).strip()
        if not name:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out



@app.get("/api/companies", response_model=CompaniesResponse)
async def api_get_companies(user: dict = Depends(get_current_user)):
    # Lesen für alle eingeloggten User erlaubt
    items = list(config.COMPANIES)
    return CompaniesResponse(companies=items, count=len(items))



@app.put("/api/companies", response_model=CompaniesResponse)
async def api_set_companies(payload: CompaniesPayload, user: dict = Depends(get_current_user)):
    # Schreiben nur für Admins
    require_admin(user)
    items = _normalize_companies(payload.companies)
    if not items:
        raise HTTPException(status_code=422, detail="companies must contain at least one non-empty string")
    try:
        config.update(COMPANIES=items)
    except Exception as e:
        logger.exception("Failed to update COMPANIES: %s", e)
        raise HTTPException(status_code=500, detail="failed to persist companies") from e
    items = list(config.COMPANIES)
    return CompaniesResponse(companies=items, count=len(items))



# -------------------------------
# Helpers to format user info (unchanged)
# -------------------------------

def format_user_info_plain(user: dict) -> str:
    address = user.get("address", {})
    return (
        "\n\n---\n"
        f"Erstellt von: {user.get('displayName')} ({user.get('email')})\n"
        f"Firma: {user.get('company')}\n"
        f"Position: {user.get('position')}\n"
        f"Telefon: {user.get('phone') or '-'}\n"
        f"Mobil: {user.get('mobile') or '-'}\n"
        f"Adresse: {address.get('street', '-')}, {address.get('zip', '')} {address.get('city', '')}\n"
        "---\n"
    )


def format_user_info_html(user: dict) -> str:
    address = user.get("address", {})
    return (
        "<hr>"
        f"<p><b>Erstellt von:</b> {user.get('displayName')} ({user.get('email')})<br>"
        f"<b>Firma:</b> {user.get('company')}<br>"
        f"<b>Position:</b> {user.get('position')}<br>"
        f"<b>Telefon:</b> {user.get('phone') or '-'}<br>"
        f"<b>Mobil:</b> {user.get('mobile') or '-'}<br>"
        f"<b>Adresse:</b> {address.get('street', '-')}, {address.get('zip', '')} {address.get('city', '')}</p>"
        "<hr>"
    )



def _humanize(key: str) -> str:
    key = str(key).replace("_", " ").replace("-", " ")
    return key[:1].upper() + key[1:]


def _is_bool_map(d: dict) -> bool:
    return d and all(isinstance(v, bool) for v in d.values())


def _prune_false(obj: Any) -> Any:
    if isinstance(obj, dict):
        # whole section skip if explicitly marked benoetigt=False
        if obj.get("benoetigt") is False:
            return {}
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if v is False:
                continue
            pv = _prune_false(v)

            if isinstance(pv, dict) and not pv:
                continue
            if isinstance(pv, list) and not pv:
                continue
            out[k] = pv
        return out
    if isinstance(obj, list):
        out: list[Any] = []
        for v in obj:
            if v is False:
                continue
            pv = _prune_false(v)
            if isinstance(pv, dict) and not pv:
                continue
            if isinstance(pv, list) and not pv:
                continue
            out.append(pv)
        return out
    return obj


def _fmt_plain(obj: Any, level: int = 0) -> list[str]:
    indent = "  " * level
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            label = _humanize(k)
            if isinstance(v, dict):
                if not v:
                    continue
                if _is_bool_map(v):
                    trues = [ _humanize(xk) for xk, xv in v.items() if xv is True ]
                    if trues:
                        out.append(f"{indent}{label}: {', '.join(trues)}")
                    continue
                out.append(f"{indent}{label}:")
                out.extend(_fmt_plain(v, level + 1))
            elif isinstance(v, list):
                if not v:
                    continue
                out.append(f"{indent}{label}:")
                out.extend(_fmt_plain(v, level + 1))
            else:
                out.append(f"{indent}{label}: {v if v not in (None, '') else '-'}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                if not item:
                    continue
                out.append(f"{indent}-")
                out.extend(_fmt_plain(item, level + 1))
            else:
                out.append(f"{indent}- {item if item not in (None, '') else '-'}")
    else:
        out.append(f"{indent}{obj if obj not in (None, '') else '-'}")
    return out


def _fmt_html(obj: Any) -> str:
    def render(node: Any) -> str:
        if isinstance(node, dict):
            items = []
            for k, v in node.items():
                if isinstance(v, (dict, list)) and not v:
                    continue
                label = escape(_humanize(k))
                if isinstance(v, dict):
                    if _is_bool_map(v):
                        trues = [ escape(_humanize(xk)) for xk, xv in v.items() if xv is True ]
                        if trues:
                            items.append(f"<li><strong>{label}:</strong> {', '.join(trues)}</li>")
                        continue
                    items.append(f"<li><strong>{label}</strong>{render(v)}</li>")
                elif isinstance(v, list):
                    items.append(f"<li><strong>{label}</strong>{render(v)}</li>")
                else:
                    val = '-' if v in (None, '') else escape(str(v))
                    items.append(f"<li><strong>{label}:</strong> {val}</li>")
            return f"<ul>{''.join(items)}</ul>"
        if isinstance(node, list):
            items = []
            for v in node:
                if isinstance(v, (dict, list)):
                    if not v:
                        continue
                    items.append(f"<li>{render(v)}</li>")
                else:
                    items.append(f"<li>{'-' if v in (None, '') else escape(str(v))}</li>")
            return f"<ul>{''.join(items)}</ul>"
        return f"<span>{'-' if node in (None, '') else escape(str(node))}</span>"

    return render(obj)


def make_ninja_description(payload: str | dict, user: dict) -> dict:
    # parse input
    if isinstance(payload, dict):
        src = payload
    elif isinstance(payload, str):
        try:
            src = json.loads(payload)
        except Exception:
            src = {"text": payload}
    else:
        src = {"text": str(payload)}

    ticket_type = src.get("ticketType")
    data = src.get("data", src)

    # prune
    data = _prune_false(data)

    # Plain
    lines: list[str] = []
    if ticket_type:
        lines.append(f"{ticket_type}")
        lines.append("")
    if isinstance(data, (dict, list)) and data:
        lines.extend(_fmt_plain(data))
        lines.append("")
    lines.append("---")
    lines.append("Nutzerangaben:")
    lines.append(format_user_info_plain(user).strip())
    body = "\n".join(lines)

    # HTML
    parts: list[str] = []
    if ticket_type:
        parts.append(f"<h3>{escape(str(ticket_type))}</h3>")
    if isinstance(data, (dict, list)) and data:
        parts.append(_fmt_html(data))
    parts.append(format_user_info_html(user))
    html = "".join(parts)

    return {"public": True, "body": body, "htmlBody": html}





def _desc_with_user_info(text: str, user: dict) -> dict:
    """Kleiner Helper: Baut NinjaOne-Description (Plain + HTML) und hängt User-Info an.
    Warum: Sonderfall EDV-Zugang beantragen nutzt bisher nur einen Hinweistext.
    """
    body = f"{text}\n\n" + format_user_info_plain(user)
    html = f"<p>{escape(text)}</p>" + format_user_info_html(user)
    return {"public": True, "body": body, "htmlBody": html}


# ANALYTICS PAGE
def _parse_iso_dt(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try: return datetime.fromisoformat(s)
    except Exception: return None


def _date_key(dt: datetime) -> str:
    return dt.date().isoformat()

def _safe_ticket_type(title: str, description: str) -> str:
    try:
        o = _json.loads(description)
        t = o.get("ticketType")
        if isinstance(t, str) and t.strip():
            return t.strip()
    except Exception:
        pass
    return title or "Unbekannt"


def _parse_range(date_from: Optional[str], date_to: Optional[str]) -> tuple[Optional[datetime], Optional[datetime]]:
    df = _parse_iso_dt(date_from)
    dt = _parse_iso_dt(date_to)

    if df and 'T' not in (date_from or ''):
        df = df.replace(hour=0, minute=0, second=0, microsecond=0)

    if dt and 'T' not in (date_to or ''):
        dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)

    return df, dt


# (3) Seite /analytics
@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)

    return templates.TemplateResponse(
        "analytics.html",
        {"request": request, "user": user, "is_admin": user.get("is_admin", False)}
    )


@app.get("/api/analytics/overview")
async def api_analytics_overview(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    df, dt = _parse_range(date_from, date_to)

    by_type: Counter[str] = Counter()
    by_date: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    total = 0

    for t in manager.list_all_tickets():
        created: datetime = t.created_at
        if df and created < df:
            continue
        if dt and created > dt:
            continue
        total += 1

        # Typ
        try:
            o = _json.loads(t.description)
            ttype = o.get("ticketType") if isinstance(o, dict) else None
            if not (isinstance(ttype, str) and ttype.strip()):
                ttype = t.title or "Unbekannt"
        except Exception:
            ttype = t.title or "Unbekannt"
        by_type[str(ttype)] += 1

        # Datum
        date_key = created.date().isoformat()
        by_date[date_key] += 1

        # Status
        st = getattr(t.status, "value", None) or str(t.status)
        by_status[str(st)] += 1

    # ✅ Datumsliste vollständig ergänzen (auch mit count = 0)
    def _date_range(start: datetime, end: datetime) -> list[str]:
        if not start or not end:
            return sorted(by_date.keys())
        delta = (end.date() - start.date()).days
        return [(start.date() + timedelta(days=i)).isoformat() for i in range(delta + 1)]

    date_range = _date_range(df, dt)
    by_date_rows = [{"date": d, "count": by_date.get(d, 0)} for d in date_range]

    # Status-Sortierung
    order = ["pending", "approved", "rejected"]
    by_status_rows = sorted(by_status.items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order else 99))

    return {
        "total_tickets": total,
        "by_type": [{"type": k, "count": v} for k, v in by_type.most_common()],
        "by_date": by_date_rows,
        "by_status": [{"status": k, "count": v} for k, v in by_status_rows],
    }



@app.get("/api/analytics/hardware/top")
async def api_analytics_hardware_top(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(10, ge=1, le=100),
):
    df, dt = _parse_range(date_from, date_to)
    counts: Counter[str] = Counter()

    for t in manager.list_all_tickets():
        created: datetime = t.created_at
        if df and created < df:
            continue
        if dt and created > dt:
            continue
        # nur Hardwarebestellung
        try:
            o = _json.loads(t.description)
        except Exception:
            continue
        if not isinstance(o, dict) or o.get("ticketType") != "Hardwarebestellung":
            continue
        data = o.get("data", {}) if isinstance(o, dict) else {}
        if isinstance(data, dict):
            artikel = data.get("Artikel", {})
            if isinstance(artikel, dict):
                for name, flag in artikel.items():
                    if flag is True:
                        counts[str(name)] += 1
            mon = data.get("Monitor")
            if isinstance(mon, dict) and mon.get("benoetigt") is True:
                try:
                    qty = int(mon.get("Anzahl") or 1)
                except Exception:
                    qty = 1
                counts["Monitor"] += max(qty, 1)

    return [{"item": k, "quantity": v} for k, v in counts.most_common(limit)]