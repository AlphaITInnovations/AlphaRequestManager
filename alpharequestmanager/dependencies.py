# File: alpharequestmanager/dependencies.py

from fastapi import Request, HTTPException, status

def get_current_user(request: Request) -> dict:
    """
    Liest den aktuell eingeloggten Benutzer aus der Session.
    Wirft 401, wenn keine gültige Session oder kein Benutzer vorhanden ist.
    """
    user = request.session.get("user")
    print("🔍 Aktueller Benutzer in Session:", user)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nicht eingeloggt oder Session abgelaufen."
        )

    return user
