import http.server
import socketserver
import webbrowser
from typing import Optional

import requests
import urllib.parse
import threading
import time
import json
from alpharequestmanager.config import cfg as config
import time
from datetime import datetime

from alpharequestmanager.logger import logger

# =========================
# Konfiguration
# =========================
CLIENT_ID = "xpwBmeH2At_yjUVQIZuPP4rCSXE"
CLIENT_SECRET = "vwj3ZhA_QBBN1D4exZ0s8X43hZxYep7X8kuyPkQT0GR95-J-dUZaWA"
REDIRECT_URI = "http://localhost:9090"
AUTH_URL = f"https://eu.ninjarmm.com/ws/oauth/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=monitoring%20management%20control%20offline_access&state=STATE"
TOKEN_URL = "https://eu.ninjarmm.com/ws/oauth/token"



# =========================
# Funktion: Auth Code holen
# =========================
def get_auth_code():
    auth_code = None

    class OAuthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal auth_code
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)

            if "code" in params:
                auth_code = params["code"][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<h1>NinjaOne Authorization Code</h1><p>Code empfangen. Fenster kann geschlossen werden.</p>"
                )
                threading.Thread(target=httpd.shutdown, daemon=True).start()
            else:
                self.send_response(400)
                self.end_headers()

    with socketserver.TCPServer(("localhost", 9090), OAuthHandler) as httpd:
        print(f"Starte Browser: {AUTH_URL}")
        webbrowser.open(AUTH_URL)
        httpd.serve_forever()

    if not auth_code:
        raise Exception("Kein Authorization Code erhalten!")

    return auth_code



# =========================
# Token Management
# =========================
def save_token(token_info):
    token_info["expires_at"] = int(time.time()) + int(token_info.get("expires_in", 0))
    config.update(NINJA_TOKEN=token_info)

def load_token():
    return config.NINJA_TOKEN

def get_new_token():
    code = get_auth_code()
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    resp = requests.post(TOKEN_URL, data=data)
    resp.raise_for_status()
    token_info = resp.json()
    save_token(token_info)
    return token_info

def refresh_token(refresh_token_value):
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token_value,
    }
    resp = requests.post(TOKEN_URL, data=data)
    resp.raise_for_status()
    token_info = resp.json()
    save_token(token_info)
    print("Access Token refresh erfolgreich")
    return token_info

def get_valid_token():
    token_info = load_token()
    if token_info:
        # Falls Access Token noch gültig
        if "expires_at" in token_info and time.time() < token_info["expires_at"]:
            return token_info
        # Versuche Refresh Token
        if "refresh_token" in token_info:
            try:
                print("Access Token abgelaufen – versuche Refresh...")
                return refresh_token(token_info["refresh_token"])
            except Exception as e:
                print("Refresh fehlgeschlagen:", e)
    # Neuer Flow
    print("Kein gültiges Token – starte neuen Auth Flow...")
    return get_new_token()

def get_access_token():
    token_info = get_valid_token()
    return token_info["access_token"]



#API Request
def _api_request(method: str, endpoint: str, access_token: str = None, **kwargs):
    url = f"https://eu.ninjarmm.com{endpoint}"
    headers = kwargs.pop("headers", {})
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    resp = requests.request(method, url, headers=headers, **kwargs)
    if resp.status_code >= 400:
        print(f"Fehler bei {method} {url}: {resp.status_code} {resp.text}")
        resp.raise_for_status()
    if resp.text.strip():
        return resp.json()
    return None



def test_connection():
    """
    Testet die Verbindung zur NinjaOne API über den Organizations-Endpoint.
    """
    try:
        access_token = get_access_token()
        orgs = _api_request("GET", "/api/v2/organizations", access_token)
        logger.info("✅ API-Verbindung erfolgreich")
        return True
    except Exception as e:
        logger.error(f"❌ API-Verbindung fehlgeschlagen: {e}")
        return False




# =========================
# Funktion: Ticket erstellen
# =========================
def __create_ticket(access_token, ticket_data):
    url = "https://eu.ninjarmm.com/api/v2/ticketing/ticket"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    resp = requests.post(url, headers=headers, json=ticket_data)
    if resp.status_code >= 400:
        print("Fehler beim Ticket erstellen:", resp.status_code, resp.text)
        resp.raise_for_status()
    return resp.json()

def get_ticket(ticket_id):
    access_token = get_access_token()
    """
    Holt ein einzelnes Ticket aus NinjaOne per Ticket-ID.
    """
    url = f"https://eu.ninjarmm.com/api/v2/ticketing/ticket/{ticket_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    resp = requests.get(url, headers=headers)
    if resp.status_code >= 400:
        print("Fehler beim Abrufen des Tickets:", resp.status_code, resp.text)
        resp.raise_for_status()
    return resp.json()

def update_ticket(access_token, ticket_id, update_data):
    """
    Aktualisiert ein Ticket in NinjaOne.
    :param access_token: gültiges Bearer Token
    :param ticket_id: ID des Tickets
    :param update_data: dict mit den Feldern, die aktualisiert werden sollen
    """
    url = f"https://eu.ninjarmm.com/api/v2/ticketing/ticket/{ticket_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    resp = requests.put(url, headers=headers, json=update_data)
    if resp.status_code >= 400:
        print("Fehler beim Ticket-Update:", resp.status_code, resp.text)
        resp.raise_for_status()
    return resp.json()

def add_ticket_comment(access_token, ticket_id, body, public=True, html_body=None):
    """
    Fügt einem Ticket einen Kommentar hinzu (ohne Dateien).
    Gibt JSON zurück, falls vorhanden – ansonsten None.
    """
    url = f"https://eu.ninjarmm.com/api/v2/ticketing/ticket/{ticket_id}/comment"
    headers = {"Authorization": f"Bearer {access_token}"}

    comment_obj = {
        "public": public,
        "body": body,
        "htmlBody": html_body or f"<p>{body}</p>"
    }

    multipart_data = {
        "comment": (None, json.dumps(comment_obj), "application/json")
    }

    resp = requests.post(url, headers=headers, files=multipart_data)

    if resp.status_code >= 400:
        print("Fehler beim Hinzufügen des Kommentars:", resp.status_code, resp.text)
        resp.raise_for_status()

    # Manche Endpoints geben keinen JSON-Body zurück
    if resp.text.strip():
        return resp.json()
    else:
        return {"status": resp.status_code, "message": "Kommentar erfolgreich hinzugefügt"}


def create_ticket(
    client_id: int,
    form_id: int,
    subject: str,
    description: str | dict,   # <- hier auch dict erlauben
    requester_mail: Optional[str] = None,
    attributes: Optional[list[dict[str, object]]] = None,
    status: int = 1000,
):
    access_token = get_access_token()
    requester_uid = None
    if requester_mail:
        requester_uid = find_requester_uid_by_email(access_token, requester_mail)

    ticket: dict[str, object] = {
        "clientId": client_id,
        "ticketFormId": form_id,
        "subject": subject,
        "status": status,
    }

    # Falls description schon ein dict ist (mit body/htmlBody), direkt übernehmen
    if isinstance(description, dict):
        ticket["description"] = description
    else:
        ticket["description"] = {
            "public": True,
            "body": description,
            "htmlBody": f"<p>{description}</p>"
        }

    if requester_uid:
        ticket["requesterUid"] = requester_uid
    if attributes:
        ticket["attributes"] = attributes

    return __create_ticket(access_token, ticket)





def create_ticket_edv_beantragen(
    client_id=2,
    description="",
    requester_mail=None,
    vorname="",
    nachname="",
    firma="AlphaConsult KG",
    arbeitsbeginn=None,
    titel="",
    strasse="",
    ort="",
    plz="",
    handy="",
    telefon="",
    fax="",
    niederlassung="",
    kostenstelle="",
    kommentar="",
):
    arbeitsbeginn_val = None
    if isinstance(arbeitsbeginn, datetime):
        arbeitsbeginn_val = int(time.mktime(arbeitsbeginn.timetuple()))
    elif isinstance(arbeitsbeginn, int):
        arbeitsbeginn_val = arbeitsbeginn

    attributes = [
        {"attributeId": 203, "value": vorname},
        {"attributeId": 204, "value": nachname},
        {"attributeId": 205, "value": firma},
        {"attributeId": 206, "value": arbeitsbeginn_val},
        {"attributeId": 207, "value": titel},
        {"attributeId": 216, "value": strasse},
        {"attributeId": 209, "value": ort},
        {"attributeId": 210, "value": plz},
        {"attributeId": 211, "value": handy},
        {"attributeId": 212, "value": telefon},
        {"attributeId": 213, "value": fax},
        {"attributeId": 214, "value": niederlassung},
        {"attributeId": 215, "value": kostenstelle},
        {"attributeId": 202, "value": kommentar},
    ]

    return create_ticket(
        client_id=client_id,
        form_id=9,
        subject="EDV-Zugang beantragen",
        description=description,
        requester_mail=requester_mail,
        attributes=attributes,
    )



def create_ticket_hardware(client_id=2, description="", requester_mail=None):
    return create_ticket(
        client_id=client_id,
        form_id=10,
        subject="Neue Hardwarebestellung",
        description=description,
        requester_mail=requester_mail,
    )



def create_ticket_edv_sperren(client_id=2, description="", requester_mail=None):
    return create_ticket(
        client_id=client_id,
        form_id=8,
        subject="EDV Zugang sperren",
        description=description,
        requester_mail=requester_mail,
    )



def create_ticket_niederlassung_anmelden(client_id=2, description="", requester_mail=None):
    return create_ticket(
        client_id=client_id,
        form_id=11,
        subject="Niederlassung anmelden",
        description=description,
        requester_mail=requester_mail,
    )



def create_ticket_niederlassung_umziehen(client_id=2, description="", requester_mail=None):
    return create_ticket(
        client_id=client_id,
        form_id=12,
        subject="Niederlassung umziehen",
        description=description,
        requester_mail=requester_mail,
    )



def create_ticket_niederlassung_schließen(client_id=2, description="", requester_mail=None):
    return create_ticket(
        client_id=client_id,
        form_id=13,
        subject="Niederlassung schließen",
        description=description,
        requester_mail=requester_mail,
    )


def is_alpha_request_approved(ticket_id: int) -> bool | None:
    """
    Prüft im Ticket-Log, ob das Attribut 'AlphaRequest Status' zuletzt
    auf 'Erledigt✅' oder 'Abgelehnt ❌' gesetzt wurde.
    """
    access_token = get_access_token()
    entries = _api_request(
        "GET",
        f"/v2/ticketing/ticket/{ticket_id}/log-entry?pageSize=50",
        access_token
    )
    if not entries:
        return None

    # neuesten Eintrag mit Attribut-Änderung suchen
    for entry in sorted(entries, key=lambda e: e.get("createTime", 0), reverse=True):
        attrs = entry.get("changeDiff", {}).get("attributeValues", [])
        if not attrs:
            continue

        # Nur Attribute mit ID 201 (= AlphaRequest Status)
        for attr in attrs:
            attr_id = attr.get("attributeId", {}).get("id")
            if attr_id == 201:
                new_val = attr.get("new", "")
                if "Erledigt" in new_val:
                    return True
                if "Abgelehnt" in new_val:
                    return False
                return None

    return None




def find_requester_uid_by_email(access_token, email):
    url = "https://eu.ninjarmm.com/api/v2/users"  # oder contacts
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    users = resp.json()
    for u in users:
        if u.get("email", "").lower() == email.lower():
            return u["uid"]
    return None



def get_alpha_request_comment(ticket: dict) -> str | None:
    """
    Holt den Wert des Attributs 'AlphaRequest Kommentar' (id=202) aus einem Ninja-Ticket.
    """
    for attr in ticket.get("attributeValues", []):
        if attr.get("attributeId") == 202:   # int vergleichen!
            return attr.get("value")
    return None




if __name__ == "__main__":

    print(get_alpha_request_comment(get_ticket(6147)))
    #test_connection()

    """
    ticket = create_ticket_edv_beantragen(
        description="Bitte neuen EDV-Zugang für Mitarbeiter erstellen",
        vorname="Max",  # Vorname
        nachname="Schneider",  # Nachname
        firma="AlphaConsult KG",  # Firma (Dropdown-Wert aus NinjaOne)
        arbeitsbeginn=1760090400,  # Arbeitsbeginn als Unix-Timestamp (10.10.2025)
        titel="Herr",
        strasse="Musterstraße 12",
        ort="Musterstadt",
        plz="12345",
        handy="017612345678",
        telefon="0301234567",
        fax="0307654321",
        niederlassung="Berlin",
        kostenstelle="KST-4711",
        kommentar="",

    )
    """

