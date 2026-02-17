import msal
from .config import AUTHORITY, CLIENT_ID, CLIENT_SECRET, SCOPES, REDIRECT_URI

def build_msal_app():
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )

def get_auth_url(state: str):
    app = build_msal_app()
    return app.get_authorization_request_url(
        SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI,
    )

def acquire_token_by_authorization_code(code: str):
    app = build_msal_app()
    result = app.acquire_token_by_authorization_code(
        code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    return result