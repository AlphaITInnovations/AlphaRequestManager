# alpharequestmanager/dependencies.py — hardened get_current_user (idle-timeout)

from typing import Dict
import time
from fastapi import Request, HTTPException, status
from alpharequestmanager.config import cfg as config
from alpharequestmanager.logger import logger

# Min-interval to reduce Set-Cookie churn
SAFE_UPDATE_INTERVAL = 60  # seconds


def get_current_user(request: Request) -> Dict:
    session = request.session
    user = session.get("user")
    now = int(time.time())
    last_activity_raw = session.get("last_activity")

    # Masked diagnostics (no raw cookies/tokens in logs)
    try:
        cookie_len = sum((len(k) + len(v)) for k, v in request.cookies.items())
    except Exception:
        cookie_len = -1
    logger.info(
        "🔍 session_keys=%s sid=%s last=%s now=%s cookie_len=%s",
        list(session.keys()), session.get("sid"), last_activity_raw, now, cookie_len,
    )

    if not user:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})

    try:
        last_activity = int(last_activity_raw) if last_activity_raw is not None else 0
    except Exception:
        last_activity = 0

    # First touch: set last_activity and continue
    if last_activity == 0:
        session["last_activity"] = now
        return user

    # Idle timeout
    if now - last_activity > int(config.SESSION_TIMEOUT):
        sid = session.get("sid")
        # Best-effort revoke of server-side tokens if server exposes a store
        try:
            token_store = getattr(request.app.state, "token_store", None)
            if sid and token_store:
                token_store.delete(sid)
        except Exception:
            logger.exception("token revoke failed for sid=%s", sid)
        session.clear()
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})

    # Reduce cookie rewrites: only bump once per SAFE_UPDATE_INTERVAL
    if now - last_activity >= SAFE_UPDATE_INTERVAL:
        session["last_activity"] = now

    return user
