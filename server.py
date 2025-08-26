import json
import threading
from datetime import datetime
from typing import Optional

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

RUNTIME_SESSION_TIMEOUT = config.SESSION_TIMEOUT  # <- „eingefrorener“ Wert bei Start


import time

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    thread = threading.Thread(target=ninja_sync.start_polling, daemon=True)
    thread.start()

    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    session_cookie="session",
    same_site="lax",
    https_only=True,
    max_age=config.SESSION_TIMEOUT,
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
    """Zeigt Login-Seite mit Button."""
    if request.session.get("user"):
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/start-auth")
async def start_auth(request: Request):
    """Startet den Auth-Code-Flow, wenn Button gedrückt wird."""
    if request.session.get("user"):
        return RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)
    auth_url = initiate_auth_flow(request)
    return RedirectResponse(auth_url)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        flow = request.session.get("auth_flow")
        if not flow:
            raise HTTPException(status_code=400, detail="OAuth Flow fehlt")

        result = acquire_token_by_auth_code(request)

        logger.info("🔁 Callback-Ergebnis: %s", result)

        if not result or "access_token" not in result:
            return templates.TemplateResponse(
                "login.html", {
                    "request": request,
                    "error": result.get("error_description", "Tokenfehler")
                }
            )

        id_claims = result.get("id_token_claims", {})
        is_admin = config.ADMIN_GROUP_ID in id_claims.get("groups", [])
        infos = await get_user_profile(result["access_token"])

        #print("infos")
        #print(infos)


        request.session["user"] = {
            "id": id_claims.get("oid"),
            "displayName": id_claims.get("name"),
            "email": id_claims.get("preferred_username"),
            "is_admin": is_admin,
            "phone": infos.get("phone"),
            "mobile": infos.get("mobile"),
            "company": infos.get("company"),
            "position": infos.get("position"),
            "address": infos.get("address"),
        }

        #print(request.session["user"])
        request.session["access_token"] = result["access_token"]
        request.session["last_activity"] = time.time()
        request.session.pop("auth_flow", None)

        #logger.info("✅ Benutzer in Session gespeichert: %s", result.get("id_token_claims"))
        logger.info("✅ Benutzer in Session gespeichert: %s", request.session["user"])


        # ✅ DANN redirect-Response erzeugen
        response = RedirectResponse("/dashboard", status_code=HTTP_302_FOUND)
        return response

    except Exception as e:
        logger.exception("Login fehlgeschlagen:")
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": str(e)}
        )


# -------------------------------
# DASHBOARD & TICKETS
# -------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(get_current_user)):
    #print(user)
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
    companies = database.get_companies()
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

    # Beschreibung inkl. User-Infos formatieren
    description_plain = description + format_user_info_plain(user)
    description_html = f"<p>{description}</p>" + format_user_info_html(user)
    description_obj = {
        "public": True,
        "body": description_plain,
        "htmlBody": description_html
    }

    # 1. Zuerst in Ninja erstellen
    ticket = None
    if ticket_type == "Neue Hardwarebestellung":
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

    # Fehler abfangen
    if not ticket or "id" not in ticket:
        raise HTTPException(status_code=500, detail="Ticket konnte in Ninja nicht erstellt werden")

    ninja_id = ticket["id"]

    # 2. Nur wenn Ninja erfolgreich war → in lokale DB
    ticket_id = manager.submit_ticket(
        title=title,
        description=description,  # hier lieber das Original-JSON speichern
        owner_id=user["id"],
        owner_name=user["displayName"],
        owner_info=json.dumps(user, ensure_ascii=False)
    )
    manager.set_ninja_metadata(ticket_id, ninja_id)

    logger.info("✅ Ticket erstellt: Lokale ID %s / Ninja ID %s für %s", ticket_id, ninja_id, user_mail)
    return RedirectResponse(url="/dashboard", status_code=HTTP_302_FOUND)


@app.get("/logout")
async def logout(request: Request):
    user = request.session.get("user", {}).get("email")
    request.session.clear()
    logger.info("User logged out: %s", user)
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
        # Versuche, das description JSON-Objekt direkt zu laden
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
            "description": description_parsed,  # bereits geparst
            "owner_info": json.loads(t.owner_info) if t.owner_info else None
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
    # Beschreibung aktualisieren, falls mitgesendet
    if description_json.strip():
        try:
            description_data = json.loads(description_json)
            update_ticket(ticket_id, description=json.dumps(description_data, ensure_ascii=False))
        except Exception as e:
            print(f"Fehler beim Parsen/Speichern der Beschreibung (ID {ticket_id}):", e)

    # Status + Kommentar setzen
    update_ticket(ticket_id, status=RequestStatus.approved)
    manager.set_comment(ticket_id, comment)
    logger.info("Ticket approved: %s by admin %s", ticket_id, user["displayName"])

    ticketType = description_data["ticketType"]
    access_token = request.session.get("access_token")

    if ticketType == TicketType.zugangSperren:
        #Erstellung eines Tickets zur Abmeldung des Mitarbeiters (Name und Startdatum reichen).
        #await send_mail(access_token, "Benutzer sperren", "")
        pass
    elif ticketType == TicketType.zugangBeantragen:
        #Erstellung einer XML-Datei für JUWI.
        #Ticket-Erstellung in Ninja mit allen notwendigen Informationen und kurzer Aufforderung „Bitte User anlegen lassen“.
        pass
    elif ticketType == TicketType.niederlassungAnmeldung:
        #Erstellung eines Tickets mit allen relevanten Informationen
        pass
    elif ticketType == TicketType.niederlassungUmzug:
        #Erstellung eines Tickets mit allen relevanten Informationen
        pass
    elif ticketType == TicketType.niederlassungAbmeldung:
        #Erstellung eines Tickets mit allen relevanten Informationen
        pass
    elif ticketType == TicketType.hardware:
        #Erstellung eines Tickets mit allen relevanten Informationen.
        pass



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
    return {
        "session_raw": request.session,
        "user": request.session.get("user")
    }


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/login")

@app.post("/send-mail")
async def send_mail_endpoint(
    request: Request,
    subject: str = Body(...),
    content: str = Body(...),
    user: dict = Depends(get_current_user),
):
    access_token = request.session.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Access token missing")

    try:
        await send_mail(access_token, subject, content)
    except HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    return {"status": "sent"}


#-----------------
#Admin Setting Panel
#--------------------

# ✨ Neu: Helfer für Admin-Only
def require_admin(user: dict):
    if not user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")


class SettingsUpdate(BaseModel):
    SECRET_KEY: Optional[str] = Field(None, min_length=8)
    CLIENT_ID: Optional[str] = Field(None, min_length=1)
    CLIENT_SECRET: Optional[str] = Field(None, min_length=1)
    TENANT_ID: Optional[str] = Field(None, min_length=1)
    AUTHORITY: Optional[AnyUrl] = None         # erlaubt expliziten Override
    REDIRECT_URI: Optional[AnyUrl] = None
    SCOPE: Optional[list[str]] = None          # Liste oder CSV (siehe Validator)
    ADMIN_GROUP_ID: Optional[str] = None
    TICKET_MAIL: Optional[EmailStr] = None
    SESSION_TIMEOUT: Optional[int] = Field(None, ge=60, le=24*60*60)  # 1min .. 24h

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
    # Sichere Anzeige (Secrets maskiert)
    safe = config.as_safe_dict()
    return templates.TemplateResponse(
        "admin_settings.html",
        {"request": request, "user": user, "settings": safe, "is_admin": user.get("is_admin")}
    )

@app.get("/api/admin/settings")
async def api_get_settings(user: dict = Depends(get_current_user)):
    require_admin(user)
    safe = config.as_safe_dict()
    safe["runtime_session_timeout"] = RUNTIME_SESSION_TIMEOUT  # neu
    return safe

@app.put("/api/admin/settings")
async def api_update_settings(payload: SettingsUpdate, user: dict = Depends(get_current_user)):
    require_admin(user)

    # Wichtig: JSON-kompatible Struktur erzeugen (Urls/EmailStr -> str, etc.)
    changes = json.loads(payload.model_dump_json(exclude_unset=True))  # <= entscheidend

    if not changes:
        return {"ok": True, "settings": config.as_safe_dict()}

    try:
        config.update(**changes)
    except Exception as e:
        logger.exception("Settings update failed")
        raise HTTPException(status_code=400, detail=str(e))

    templates.env.globals['SESSION_TIMEOUT'] = config.SESSION_TIMEOUT

    # Falls du das "Neustart nötig" Flag nutzt:
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
