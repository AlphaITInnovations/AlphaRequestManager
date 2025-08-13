import json

from fastapi import FastAPI, Request, Form, Depends, HTTPException, Body
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from httpx import HTTPStatusError
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND
from fastapi.staticfiles import StaticFiles

from alpharequestmanager import graph, database
from alpharequestmanager.graph import get_user_profile, send_mail

from alpharequestmanager.config import SECRET_KEY, ADMIN_GROUP_ID
from alpharequestmanager.auth import initiate_auth_flow, acquire_token_by_auth_code
from alpharequestmanager.dependencies import get_current_user
from alpharequestmanager.logger import logger
from alpharequestmanager.manager import RequestManager
from alpharequestmanager.models import RequestStatus

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    same_site="lax",
    https_only=True,
    max_age=86400,
    path="/",
)

templates = Jinja2Templates(directory="alpharequestmanager/templates")
manager = RequestManager()

app.mount("/static", StaticFiles(directory="alpharequestmanager/static"), name="static")

# -------------------------------
# LOGIN & AUTH
# -------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Zeigt Login-Seite mit Button."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/start-auth")
async def start_auth(request: Request):
    """Startet den Auth-Code-Flow, wenn Button gedrückt wird."""
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
        is_admin = ADMIN_GROUP_ID in id_claims.get("groups", [])
        infos = await get_user_profile(result["access_token"])

        print("infos")
        print(infos)


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

        print(request.session["user"])
        request.session["access_token"] = result["access_token"]
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
    ticket = manager.submit_ticket(
        title=title,
        description=description,
        owner_id=user["id"],
        owner_name=user["displayName"],
        owner_info=json.dumps(user, ensure_ascii=False)  # alle user-details als JSON speichern
    )

    #MAIL Versand
    data = json.loads(description)
    ticket_type = data.get("ticketType")
    subject = "Neuer Request: " + ticket_type + " von " + user["displayName"]

    await graph.send_mail(request.session.get("access_token"), subject, description)
    logger.info("Mail send: " + subject)


    logger.info("Ticket erstellt: %s für %s", ticket.id, ticket.owner_name)
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
    ticket_id: int = Form(...),
    comment: str = Form(""),
    user: dict = Depends(get_current_user)
):
    manager.update_status(ticket_id, status=RequestStatus.approved)
    manager.set_comment(ticket_id, comment)
    return RedirectResponse("/pruefung", status_code=HTTP_302_FOUND)


@app.post("/pruefung/reject")
async def reject_ticket(
    ticket_id: int = Form(...),
    comment: str = Form(""),
    user: dict = Depends(get_current_user)
):
    manager.update_status(ticket_id, status=RequestStatus.rejected)
    manager.set_comment(ticket_id, comment)
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