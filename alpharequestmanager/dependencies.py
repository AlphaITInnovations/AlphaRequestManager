
from __future__ import annotations

import time

from fastapi import HTTPException, Request, status

from alpharequestmanager.config import cfg as config


def get_current_user(request: Request) -> dict:
    """Gibt den aktuell eingeloggten Benutzer zurück.
    Neben der reinen Existenzprüfung wird ein Inaktivitäts-Timeout
    berücksichtigt. Liegt die letzte Aktivität länger als ``SESSION_TIMEOUT``
    Sekunden zurück, wird die Session geleert und eine ``HTTPException`` mit
    Status ``401`` ausgelöst.
    """


    user = request.session.get("user")
    print("🔍 Aktueller Benutzer in Session:", user)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )

        # Timeout-Logik: Session löschen, wenn die letzte Aktivität zu lange her ist
    now = time.time()
    last_activity = request.session.get("last_activity")
    if last_activity and (now - last_activity) > config.SESSION_TIMEOUT:
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )

    # Aktuelle Aktivität speichern, um das Timeout fortlaufend zu erneuern
    request.session["last_activity"] = now

    return user
