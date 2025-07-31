# alpharequestmanager/auth.py

from msal import ConfidentialClientApplication
from fastapi import Request
from alpharequestmanager.config import CLIENT_ID, CLIENT_SECRET, TENANT_ID, REDIRECT_URI, SCOPE

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = SCOPE

def build_msal_app():
    return ConfidentialClientApplication(
        client_id=CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )

def initiate_auth_flow(request: Request):
    app = build_msal_app()
    flow = app.initiate_auth_code_flow(
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    request.session["auth_flow"] = flow
    return flow["auth_uri"]

def acquire_token_by_auth_code(request: Request):
    app = build_msal_app()
    flow = request.session.get("auth_flow")
    if not flow:
        raise ValueError("OAuth Flow fehlt in Session")

    # Fix: QueryParams → dict
    return app.acquire_token_by_auth_code_flow(flow, dict(request.query_params))