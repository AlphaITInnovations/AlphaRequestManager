import http.server
import socketserver
import webbrowser
import requests
import urllib.parse
import threading
import time
import json
from alpharequestmanager.config import cfg as config

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
    subject="AlphaRequest Ticket",
    clientId=2,
    ticketFormId=8,
    description="",
    status="1000"
):
    """
    creates ticket and returns ticket id
    """
    access_token = get_access_token()
    new_ticket = {
        "clientId": clientId,
        "ticketFormId": ticketFormId,
        "subject": subject,
        "description": {
            "public": True,
            "body": description,
            "htmlBody": f"<p>{description}</p>"
        },
        "status": status,
    }
    return __create_ticket(access_token, new_ticket)



if __name__ == "__main__":
    create_ticket(description="Test Ticket")
    #save_token({"access_token": "123", "expires_in": 3600})
    #print("DB-Wert:", config.settings_get("NINJA_TOKEN", None))
"""
    ticket_response = create_ticket(new_ticket)
    id = ticket_response["id"]
    #print(ticket_response["id"])
    #print(get_ticket(ticket_response["id"]))
    comment_response = add_ticket_comment(
        get_access_token(),
        ticket_id=id,
        body="Test-Kommentar aus Python",
        public=True
    )

    print("Antwort:", comment_response)
"""