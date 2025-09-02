# server.py — session/token robust fix for MS OAuth redirect-loop
# Goal: avoid redirect loops by keeping the session cookie tiny and stable,
# move tokens server-side, and use safe cookie attributes.

import json
import threading
from datetime import datetime
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

    description_plain = description + format_user_info_plain(user)
    description_html = f"<p>{description}</p>" + format_user_info_html(user)
    description_obj = {
        "public": True,
        "body": description_plain,
        "htmlBody": description_html
    }

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
        ticket = ninja_api.create_ticket_edv_beantragen(
            description="Bitte die Daten links im Ticket prüfen und anschließend freigeben",
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

