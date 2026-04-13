"""
app.py — SAML 2.0 Service Provider (SP) with Session Management + SLO
=======================================================================

OVERVIEW
--------
This module extends the base SAML SP implementation with:
  1. Signed session cookie issued after successful ACS validation
  2. GET /auth/me — auth check endpoint for the frontend
  3. GET /logout  — local logout (clears cookie only)
  4. GET /slo     — SP-initiated Single Logout (tells the IdP to end the SSO session)
  5. POST /slo    — IdP-initiated Single Logout (IdP tells us to end our session)

SESSION DESIGN
--------------
  After ACS validation, we issue a signed cookie using itsdangerous.URLSafeTimedSerializer.
  The cookie is:
    - HttpOnly  → JS cannot read it (XSS protection)
    - Secure    → HTTPS only
    - SameSite=lax → CSRF protection for browser navigations
    - Signed    → tamper-evident (secret key in SESSION_SECRET env var)

  The cookie payload stores:
    - user_id       → the NameID from the SAML assertion
    - session_index → the IdP's session ID (required for SLO LogoutRequest)
    - name_id       → the NameID value again (required in SLO LogoutRequest XML)
    - session_expiry → when the IdP session expires (informational)

SINGLE LOGOUT (SLO) FLOWS
--------------------------
  SP-initiated (user clicks logout in our app):
    Browser → GET /slo
      → SP builds LogoutRequest XML with SessionIndex + NameID
      → SP DEFLATE-compresses + Base64-encodes + URL-encodes
      → SP clears the local session cookie
      → Browser is redirected to IdP SLO endpoint with ?SAMLRequest=...
      → IdP ends its session + redirects back to SP's SLO endpoint with ?SAMLResponse=...
      → SP receives GET /slo?SAMLResponse=... and redirects to frontend

  IdP-initiated (user logged out from another app in the SSO network):
    IdP → POST /slo (SAMLRequest form field)
      → SP decodes the LogoutRequest
      → SP clears the local session cookie
      → SP sends LogoutResponse back to IdP
      → IdP confirms logout complete

ENVIRONMENT VARIABLES REQUIRED
-------------------------------
  IDAM_SSO_URL      — IdP Single Sign-On URL
  IDAM_SLO_URL      — IdP Single Logout URL (from metadata SingleLogoutService HTTP-POST)
  ISSUER            — This SP's entity ID
  ACS_URL           — This SP's ACS URL
  FRONTEND_REDIRECT — Frontend base URL
  IDP_CERT          — Raw base64 X.509 certificate from IdP metadata
  SESSION_SECRET    — Long random secret for signing cookies (openssl rand -hex 32)

DEPENDENCIES
------------
  pip install fastapi uvicorn python-multipart lxml xmlsec cryptography itsdangerous
"""

import os
import base64
import zlib
import uuid
import logging
from datetime import datetime, timezone
from urllib.parse import quote, unquote

import xmlsec
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

# =============================================================================
# LOGGING SETUP
# =============================================================================
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("saml_sp")

# =============================================================================
# STARTUP VALIDATION
# =============================================================================
REQUIRED_ENV_VARS = [
    "IDAM_SSO_URL", "IDAM_SLO_URL", "ISSUER",
    "ACS_URL", "FRONTEND_REDIRECT", "IDP_CERT", "SESSION_SECRET",
]
missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing:
    logger.critical("Missing required environment variables: %s", ", ".join(missing))
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

logger.info("All required environment variables are present.")

# =============================================================================
# CONFIGURATION
# =============================================================================
IDAM_SSO_URL      = os.getenv("IDAM_SSO_URL")        # IdP SSO endpoint
IDAM_SLO_URL      = os.getenv("IDAM_SLO_URL")        # IdP SLO endpoint (from metadata)
ISSUER            = os.getenv("ISSUER")                # SP entity ID
ACS_URL           = os.getenv("ACS_URL")               # SP ACS URL
FRONTEND_REDIRECT = os.getenv("FRONTEND_REDIRECT")    # Frontend base URL
SESSION_SECRET    = os.getenv("SESSION_SECRET")        # Cookie signing secret
IDP_CERT_B64      = os.getenv("IDP_CERT", "").replace("\n", "").replace(" ", "").strip()

# Session cookie lifetime — 8 hours to match IdP's SessionNotOnOrAfter
SESSION_MAX_AGE = 28800

logger.debug(
    "Config — ISSUER=%s | ACS_URL=%s | IDAM_SSO_URL=%s | IDAM_SLO_URL=%s",
    ISSUER, ACS_URL, IDAM_SSO_URL, IDAM_SLO_URL,
)

# =============================================================================
# SESSION SERIALIZER
# Itsdangerous signs the cookie payload with SESSION_SECRET.
# If anyone tampers with the cookie value, BadSignature is raised on load.
# max_age is enforced at load time — expired cookies raise SignatureExpired.
# =============================================================================
serializer = URLSafeTimedSerializer(SESSION_SECRET)

# =============================================================================
# XML NAMESPACE MAP
# =============================================================================
NS = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds":     "http://www.w3.org/2000/09/xmldsig#",
}

# =============================================================================
# IDP PUBLIC KEY LOADING
# =============================================================================

def load_idp_public_key() -> xmlsec.Key:
    """
    Converts the raw base64 X.509 certificate from IdP metadata into an
    xmlsec Key object used for XML signature verification.
    """
    logger.info("Loading IdP public key from IDP_CERT env var...")
    try:
        cert_der = base64.b64decode(IDP_CERT_B64)
        logger.debug("Decoded IDP_CERT: %d bytes (DER)", len(cert_der))

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        logger.debug(
            "Certificate subject: %s | valid until: %s",
            cert.subject.rfc4514_string(),
            cert.not_valid_after_utc,
        )

        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM)
        logger.info("IdP public key loaded successfully.")
        return key
    except Exception as exc:
        logger.critical("Failed to load IdP public key: %s", exc, exc_info=True)
        raise


IDP_KEY = load_idp_public_key()

# =============================================================================
# FASTAPI APP
# =============================================================================
app = FastAPI(title="SAML SP", description="SAML 2.0 SP with session management and SLO")

# =============================================================================
# SESSION HELPERS
# =============================================================================

def create_session_cookie(response: RedirectResponse, claims: dict) -> None:
    """
    Serializes the user's session claims into a signed cookie and sets it
    on the response object.

    The cookie payload contains everything needed for:
      - Auth check (/auth/me)  → user_id
      - SLO LogoutRequest      → session_index, name_id

    Cookie flags:
      httponly=True  — JS cannot access the cookie (prevents XSS token theft)
      secure=True    — Cookie is only sent over HTTPS
      samesite="lax" — Cookie is sent on top-level navigations but not cross-site
                       POSTs (CSRF protection). "strict" would break the IdP POST-back.
    """
    session_data = {
        "user_id":        claims["user_id"],
        "name_id":        claims["user_id"],   # NameID needed verbatim in LogoutRequest
        "session_index":  claims["session_index"],
        "session_expiry": claims["session_expiry"],
    }
    cookie_value = serializer.dumps(session_data)
    logger.debug("Created session cookie for user_id=%s session_index=%s",
                 claims["user_id"], claims["session_index"])

    response.set_cookie(
        key="saml_session",
        value=cookie_value,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
    )


def get_session(request: Request) -> dict | None:
    """
    Reads and validates the signed session cookie from the incoming request.

    Returns the session dict if the cookie is present, valid, and not expired.
    Returns None in all other cases (missing, tampered, expired).

    The itsdangerous serializer verifies both:
      - The HMAC signature (tamper detection)
      - The cookie age (expiry — max_age=SESSION_MAX_AGE seconds)
    """
    cookie = request.cookies.get("saml_session")
    if not cookie:
        logger.debug("No saml_session cookie found in request.")
        return None

    try:
        data = serializer.loads(cookie, max_age=SESSION_MAX_AGE)
        logger.debug("Session cookie valid for user_id=%s", data.get("user_id"))
        return data
    except SignatureExpired:
        logger.info("Session cookie has expired.")
        return None
    except BadSignature:
        logger.warning("Session cookie signature is invalid — possible tampering attempt.")
        return None


def clear_session_cookie(response) -> None:
    """
    Clears the session cookie by deleting it from the browser.
    delete_cookie() sets the cookie with an empty value and max_age=0,
    which instructs the browser to remove it immediately.
    """
    response.delete_cookie("saml_session", httponly=True, secure=True, samesite="lax")
    logger.debug("Session cookie cleared.")

# =============================================================================
# SAML HELPERS — AuthnRequest + LogoutRequest encoding
# =============================================================================

def deflate_and_base64(xml: str) -> str:
    """
    DEFLATE-compresses (raw, no zlib header) and Base64-encodes an XML string.
    Required by both HTTP-Redirect AuthnRequest and LogoutRequest bindings.
    wbits=-15 = raw DEFLATE without zlib wrapper (SAML spec requirement).
    """
    logger.debug("DEFLATE-compressing XML (%d chars)...", len(xml))
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    encoded = base64.b64encode(compressed).decode("utf-8")
    logger.debug("Compressed result: %d chars", len(encoded))
    return encoded


def build_authn_request(request_id: str, issue_instant: str) -> str:
    """Builds the SAML 2.0 AuthnRequest XML string."""
    return (
        f'<saml2p:AuthnRequest '
        f'ID="{request_id}" '
        f'Version="2.0" '
        f'IssueInstant="{issue_instant}" '
        f'Destination="{IDAM_SSO_URL}" '
        f'AssertionConsumerServiceURL="{ACS_URL}" '
        f'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<saml2:Issuer>{ISSUER}</saml2:Issuer>'
        f'</saml2p:AuthnRequest>'
    )


def build_logout_request(request_id: str, issue_instant: str,
                          name_id: str, session_index: str) -> str:
    """
    Builds a SAML 2.0 LogoutRequest XML string for SP-initiated SLO.

    Key elements:
      NameID        — Identifies the user whose session is being terminated.
                      Must match the NameID from the original SAMLResponse exactly.
      SessionIndex  — The IdP's session identifier from the AuthnStatement.
                      Without this, the IdP may not know which session to end.
      Destination   — The IdP's SLO endpoint URL (from metadata).

    The LogoutRequest is sent via HTTP-Redirect binding (same as AuthnRequest):
    DEFLATE → Base64 → URL-encode → append to IdP SLO URL as ?SAMLRequest=...
    """
    return (
        f'<saml2p:LogoutRequest '
        f'ID="{request_id}" '
        f'Version="2.0" '
        f'IssueInstant="{issue_instant}" '
        f'Destination="{IDAM_SLO_URL}" '
        f'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<saml2:Issuer>{ISSUER}</saml2:Issuer>'
        f'<saml2:NameID '
        f'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">'
        f'{name_id}'
        f'</saml2:NameID>'
        f'<saml2p:SessionIndex>{session_index}</saml2p:SessionIndex>'
        f'</saml2p:LogoutRequest>'
    )


def build_logout_response(request_id: str, issue_instant: str,
                           in_response_to: str) -> str:
    """
    Builds a SAML 2.0 LogoutResponse XML for IdP-initiated SLO.

    When the IdP sends us a LogoutRequest (user logged out from another app),
    we must respond with a LogoutResponse confirming we've ended our session.

    in_response_to — the ID from the IdP's LogoutRequest, echoed back.
    Status Success  — tells the IdP our session was successfully terminated.
    """
    return (
        f'<saml2p:LogoutResponse '
        f'ID="{request_id}" '
        f'Version="2.0" '
        f'IssueInstant="{issue_instant}" '
        f'Destination="{IDAM_SLO_URL}" '
        f'InResponseTo="{in_response_to}" '
        f'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<saml2:Issuer>{ISSUER}</saml2:Issuer>'
        f'<saml2p:Status>'
        f'<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        f'</saml2p:Status>'
        f'</saml2p:LogoutResponse>'
    )

# =============================================================================
# SAML RESPONSE VALIDATION HELPERS
# =============================================================================

def verify_saml_signature(root: etree._Element) -> bool:
    """
    Verifies the XML digital signature on the SAML Assertion element.

    Critical step: xmlsec.tree.add_ids(assertion, ["ID"]) must be called before
    ctx.verify() so xmlsec can resolve the <ds:Reference URI="#..."> pointer to
    the Assertion. Without this, verification always fails with "failed to verify".
    """
    logger.debug("Starting XML signature verification on Assertion...")

    assertion = root.find(".//saml2:Assertion", NS)
    if assertion is None:
        logger.error("No <saml2:Assertion> element found.")
        raise ValueError("No Assertion element found in SAML response")

    logger.debug("Found Assertion element with ID=%s", assertion.get("ID"))

    signature_node = xmlsec.tree.find_node(assertion, xmlsec.Node.SIGNATURE)
    if signature_node is None:
        logger.error("No <ds:Signature> found inside the Assertion.")
        raise ValueError("No Signature found in Assertion")

    # Register ID attribute so xmlsec can resolve URI="#..." reference
    xmlsec.tree.add_ids(assertion, ["ID"])
    logger.debug("Registered 'ID' attribute for URI reference resolution.")

    ctx = xmlsec.SignatureContext()
    ctx.key = IDP_KEY
    ctx.verify(signature_node)

    logger.info("XML signature verification PASSED.")
    return True


def parse_dt(s: str) -> datetime | None:
    """Parse xs:dateTime string (with or without milliseconds) to UTC datetime."""
    if s is None:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def parse_saml_assertion(root: etree._Element) -> dict:
    """
    Extracts all claims from the verified SAML Assertion and validates the
    assertion time window (NotBefore / NotOnOrAfter).

    Returns a dict with user_id, session_index, session_expiry, and time window values.
    Raises ValueError if the assertion is expired or not yet valid.
    """
    logger.debug("Parsing SAML Assertion claims...")

    assertion = root.find(".//saml2:Assertion", NS)
    if assertion is None:
        raise ValueError("No Assertion found in SAMLResponse")

    name_id_el = assertion.find(".//saml2:NameID", NS)
    name_id    = name_id_el.text.strip() if (name_id_el is not None and name_id_el.text) else None
    logger.info("Extracted NameID: %s | Format: %s",
                name_id, name_id_el.get("Format") if name_id_el is not None else "N/A")

    authn_stmt  = assertion.find(".//saml2:AuthnStatement", NS)
    session_idx = authn_stmt.get("SessionIndex")        if authn_stmt is not None else None
    session_exp = authn_stmt.get("SessionNotOnOrAfter") if authn_stmt is not None else None
    logger.debug("SessionIndex=%s | SessionNotOnOrAfter=%s", session_idx, session_exp)

    conditions   = assertion.find("saml2:Conditions", NS)
    not_before   = conditions.get("NotBefore")   if conditions is not None else None
    not_on_after = conditions.get("NotOnOrAfter") if conditions is not None else None
    logger.debug("Assertion window: NotBefore=%s | NotOnOrAfter=%s", not_before, not_on_after)

    now = datetime.now(timezone.utc)
    if not_before   and now < parse_dt(not_before):
        raise ValueError(f"Assertion not yet valid (NotBefore: {not_before})")
    if not_on_after and now >= parse_dt(not_on_after):
        raise ValueError(f"Assertion has expired (NotOnOrAfter: {not_on_after})")

    logger.info("Assertion time window is valid.")
    return {
        "user_id":        name_id,
        "session_index":  session_idx,
        "session_expiry": session_exp,
        "not_before":     not_before,
        "not_on_after":   not_on_after,
    }

# =============================================================================
# ROUTES
# =============================================================================

# -----------------------------------------------------------------------------
# /login — SP-initiated SSO
# -----------------------------------------------------------------------------
@app.get("/login", summary="Initiate SAML SSO login")
def login():
    """
    Builds a SAML AuthnRequest and redirects the browser to the IdP for authentication.
    Uses HTTP-Redirect binding: AuthnRequest is DEFLATE-compressed, Base64-encoded,
    URL-encoded, and sent as a ?SAMLRequest= query parameter.
    """
    logger.info("=== GET /login — Initiating SAML AuthnRequest ===")

    request_id    = "_" + str(uuid.uuid4())
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.debug("AuthnRequest ID=%s | IssueInstant=%s", request_id, issue_instant)

    xml         = build_authn_request(request_id, issue_instant)
    encoded     = deflate_and_base64(xml)
    url_encoded = quote(encoded, safe="")

    redirect_url = f"{IDAM_SSO_URL}?SAMLRequest={url_encoded}"
    logger.info("Redirecting to IdP: %s", IDAM_SSO_URL)
    return RedirectResponse(redirect_url)


# -----------------------------------------------------------------------------
# /acs — Assertion Consumer Service
# -----------------------------------------------------------------------------
@app.post("/acs", summary="Receive SAMLResponse from IdP after authentication")
async def acs(request: Request):
    """
    Receives the SAMLResponse POST from the IdP, validates it, and issues a
    signed session cookie. Then 303-redirects the browser to the frontend.

    Flow:
      1. Decode the base64 SAMLResponse
      2. Verify the XML digital signature
      3. Validate the assertion time window
      4. Extract claims (NameID, SessionIndex, etc.)
      5. Set a signed HttpOnly session cookie
      6. 303-redirect to the frontend (converts IdP POST → browser GET)
    """
    logger.info("=== POST /acs — Received SAMLResponse ===")

    form = await request.form()
    raw  = form.get("SAMLResponse")
    if not raw:
        logger.error("No SAMLResponse in POST body. Keys: %s", list(form.keys()))
        return HTMLResponse("Missing SAMLResponse", status_code=400)

    logger.debug("Raw SAMLResponse: %d chars", len(raw))

    # Restore '+' characters that HTTP form encoding may have converted to spaces
    clean = raw.replace(" ", "+").strip()

    try:
        decoded_bytes = base64.b64decode(clean)
        saml_xml      = decoded_bytes.decode("utf-8")
        logger.debug("Decoded %d bytes of XML", len(saml_xml))
    except Exception as exc:
        logger.error("Base64 decode failed: %s", exc, exc_info=True)
        return HTMLResponse(f"Base64 decode failed: {exc}", status_code=400)

    logger.debug("SAMLResponse XML:\n%s", saml_xml)  # remove in production (PII)

    try:
        root = etree.fromstring(saml_xml.encode("utf-8"))
    except etree.XMLSyntaxError as exc:
        logger.error("XML parse error: %s", exc)
        return HTMLResponse(f"Invalid XML: {exc}", status_code=400)

    logger.info("SAMLResponse ID=%s | InResponseTo=%s | Destination=%s",
                root.get("ID"), root.get("InResponseTo"), root.get("Destination"))

    # Check IdP status
    status_el = root.find(".//saml2p:StatusCode", NS)
    if status_el is not None:
        status_val = status_el.get("Value", "")
        logger.info("IdP Status: %s", status_val)
        if "Success" not in status_val:
            return HTMLResponse(f"IdP returned non-success: {status_val}", status_code=401)

    # Verify signature
    try:
        verify_saml_signature(root)
    except (xmlsec.Error, ValueError) as exc:
        logger.error("Signature verification FAILED: %s", exc, exc_info=True)
        return HTMLResponse(f"Signature verification failed: {exc}", status_code=401)

    # Parse and validate assertion
    try:
        claims = parse_saml_assertion(root)
    except ValueError as exc:
        logger.error("Assertion validation FAILED: %s", exc, exc_info=True)
        return HTMLResponse(f"Assertion validation failed: {exc}", status_code=401)

    user_id = claims["user_id"]
    if not user_id:
        return HTMLResponse("NameID missing in assertion", status_code=401)

    logger.info("Auth SUCCESS — user_id=%s | session_index=%s | session_expiry=%s",
                claims["user_id"], claims["session_index"], claims["session_expiry"])

    # Issue session cookie and redirect to frontend
    response = RedirectResponse(FRONTEND_REDIRECT, status_code=303)
    create_session_cookie(response, claims)
    return response


# -----------------------------------------------------------------------------
# /auth/me — Auth check
# -----------------------------------------------------------------------------
@app.get("/auth/me", summary="Check if the current user is authenticated")
def auth_me(request: Request):
    """
    Auth check endpoint called by the frontend on every page load.

    Returns 200 + user info if the session cookie is present, valid, and not expired.
    Returns 401 if the user is not authenticated (no cookie, expired, or tampered).

    Frontend usage:
      const res = await fetch("/api/auth/me", { credentials: "include" });
      if (res.status === 401) window.location.href = "/api/login";
      const { user_id } = await res.json();

    WHY credentials: "include"?
    Fetch does not send cookies cross-origin by default. Since the frontend
    and backend may be on different ports during development, credentials: "include"
    is required. In production (same domain), it still doesn't hurt.
    """
    logger.debug("GET /auth/me — checking session cookie")

    session = get_session(request)
    if not session:
        logger.info("/auth/me — not authenticated (no valid session)")
        return JSONResponse({"authenticated": False}, status_code=401)

    logger.info("/auth/me — authenticated as user_id=%s", session.get("user_id"))
    return JSONResponse({
        "authenticated":   True,
        "user_id":         session["user_id"],
        "session_expiry":  session.get("session_expiry"),
    })


# -----------------------------------------------------------------------------
# /logout — Local logout (cookie only, no SLO)
# -----------------------------------------------------------------------------
@app.get("/logout", summary="Local logout — clears session cookie only")
def logout(request: Request):
    """
    Local logout — clears the SP's session cookie without notifying the IdP.

    Use this only if you do NOT need SLO (e.g. during development or if the
    IdP's SLO endpoint is unreliable). The user's IdP session remains active,
    meaning they can re-authenticate without entering credentials again.

    For full SSO logout, use /slo instead.
    """
    logger.info("=== GET /logout — Local logout ===")

    session = get_session(request)
    if session:
        logger.info("Logging out user_id=%s (local only, IdP session preserved)",
                    session.get("user_id"))
    else:
        logger.info("Logout called with no active session — clearing cookie anyway.")

    response = RedirectResponse(FRONTEND_REDIRECT, status_code=303)
    clear_session_cookie(response)
    return response


# -----------------------------------------------------------------------------
# /slo — Single Logout (SP-initiated + IdP-initiated)
# -----------------------------------------------------------------------------
@app.get("/slo", summary="Single Logout — SP-initiated or IdP SLO response receiver")
def slo_get(request: Request):
    """
    Handles two distinct scenarios on GET /slo:

    SCENARIO A — SP-initiated SLO (user clicked logout in our app):
      No query params → build LogoutRequest → redirect to IdP SLO endpoint.
      The local session cookie is cleared BEFORE the redirect so even if the
      IdP redirect fails, the user is logged out locally.

    SCENARIO B — IdP returns SAMLResponse after completing SLO:
      Query param ?SAMLResponse=... is present → IdP has finished SLO.
      We just redirect to the frontend (session was already cleared in Scenario A).

    SAML SLO HTTP-Redirect binding flow:
      SP → GET {IDAM_SLO_URL}?SAMLRequest={encoded_logout_request}
      IdP ends session → GET /slo?SAMLResponse={encoded_logout_response}
    """
    logger.info("=== GET /slo ===")

    # --- Scenario B: IdP has completed SLO and sent us a SAMLResponse ---
    saml_response_encoded = request.query_params.get("SAMLResponse")
    if saml_response_encoded:
        logger.info("Received SAMLResponse from IdP after SLO — logout complete.")
        # At this point our session cookie was already cleared in Scenario A.
        # We just redirect to the frontend.
        return RedirectResponse(FRONTEND_REDIRECT, status_code=303)

    # --- Scenario A: SP-initiated SLO — user clicked logout ---
    session = get_session(request)
    if not session:
        # No session — nothing to log out. Just go home.
        logger.info("SLO requested but no active session found. Redirecting to frontend.")
        return RedirectResponse(FRONTEND_REDIRECT, status_code=303)

    user_id       = session.get("user_id")
    name_id       = session.get("name_id", user_id)
    session_index = session.get("session_index")

    logger.info("SP-initiated SLO for user_id=%s | session_index=%s", user_id, session_index)

    # Build the LogoutRequest XML
    request_id    = "_" + str(uuid.uuid4())
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logout_request_xml = build_logout_request(request_id, issue_instant, name_id, session_index)
    logger.debug("LogoutRequest XML: %s", logout_request_xml)

    # Encode for HTTP-Redirect binding (same as AuthnRequest)
    encoded     = deflate_and_base64(logout_request_xml)
    url_encoded = quote(encoded, safe="")

    idp_slo_url = f"{IDAM_SLO_URL}?SAMLRequest={url_encoded}"
    logger.info("Redirecting to IdP SLO endpoint: %s", IDAM_SLO_URL)

    # Clear the local session cookie BEFORE redirecting to IdP.
    # This ensures the user is logged out locally even if the IdP redirect fails.
    response = RedirectResponse(idp_slo_url, status_code=303)
    clear_session_cookie(response)
    return response


@app.post("/slo", summary="IdP-initiated Single Logout — receive LogoutRequest from IdP")
async def slo_post(request: Request):
    """
    IdP-initiated SLO — the IdP tells us to end our session.

    This happens when a user logs out from ANOTHER application in the same
    SSO network. The IdP sends a LogoutRequest to all SPs that have active
    sessions for that user.

    Flow:
      IdP → POST /slo (SAMLRequest form field containing LogoutRequest XML)
        → SP decodes the LogoutRequest
        → SP extracts the InResponseTo ID from the LogoutRequest
        → SP clears local session cookie
        → SP builds LogoutResponse and redirects to IdP SLO endpoint

    WHY REDIRECT WITH LogoutResponse instead of POST?
    The SAML SLO HTTP-Redirect binding is simpler to implement than HTTP-POST
    for the LogoutResponse. We use the same DEFLATE → Base64 → URL-encode
    approach as the AuthnRequest.
    """
    logger.info("=== POST /slo — IdP-initiated SLO LogoutRequest received ===")

    form = await request.form()
    raw  = form.get("SAMLRequest")

    if not raw:
        logger.error("No SAMLRequest in POST body. Keys: %s", list(form.keys()))
        return HTMLResponse("Missing SAMLRequest", status_code=400)

    # Decode the LogoutRequest
    try:
        clean         = raw.replace(" ", "+").strip()
        decoded_bytes = base64.b64decode(clean)
        logout_xml    = decoded_bytes.decode("utf-8")
        logger.debug("Decoded LogoutRequest XML:\n%s", logout_xml)
    except Exception as exc:
        logger.error("Failed to decode LogoutRequest: %s", exc)
        return HTMLResponse(f"Failed to decode SAMLRequest: {exc}", status_code=400)

    # Parse the LogoutRequest to get the ID (needed for InResponseTo)
    try:
        root           = etree.fromstring(logout_xml.encode("utf-8"))
        logout_req_id  = root.get("ID", "_unknown")
        name_id_el     = root.find(".//saml2:NameID", NS)
        name_id        = name_id_el.text.strip() if (name_id_el is not None and name_id_el.text) else "unknown"
        logger.info("IdP LogoutRequest ID=%s | NameID=%s", logout_req_id, name_id)
    except etree.XMLSyntaxError as exc:
        logger.error("Failed to parse LogoutRequest XML: %s", exc)
        return HTMLResponse(f"Invalid LogoutRequest XML: {exc}", status_code=400)

    # Clear the local session regardless of whether we find a session cookie.
    # The IdP is authoritative — if it says logout, we comply.
    logger.info("Clearing local session for NameID=%s (IdP-initiated SLO)", name_id)

    # Build LogoutResponse to send back to the IdP
    response_id   = "_" + str(uuid.uuid4())
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logout_response_xml = build_logout_response(response_id, issue_instant, logout_req_id)
    logger.debug("LogoutResponse XML: %s", logout_response_xml)

    # Encode for HTTP-Redirect binding
    encoded     = deflate_and_base64(logout_response_xml)
    url_encoded = quote(encoded, safe="")

    idp_slo_url  = f"{IDAM_SLO_URL}?SAMLResponse={url_encoded}"
    logger.info("Sending LogoutResponse to IdP SLO endpoint: %s", IDAM_SLO_URL)

    # Clear session cookie and redirect to IdP with LogoutResponse
    response = RedirectResponse(idp_slo_url, status_code=303)
    clear_session_cookie(response)
    return response