import os
import base64
import zlib
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, unquote_plus
from xml.etree import ElementTree as ET

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse

REQUIRED_ENV_VARS = ["IDAM_SSO_URL", "ISSUER", "ACS_URL", "FRONTEND_REDIRECT"]
missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

app = FastAPI()

IDAM_SSO_URL = os.getenv("IDAM_SSO_URL")
ISSUER = os.getenv("ISSUER")
ACS_URL = os.getenv("ACS_URL")
FRONTEND_REDIRECT = os.getenv("FRONTEND_REDIRECT")


def deflate_and_base64(xml: str) -> str:
    """DEFLATE compress (raw, no zlib header) then Base64 encode."""
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    return base64.b64encode(compressed).decode("utf-8")


def build_authn_request(request_id: str, issue_instant: str) -> str:
    """Build the SAML AuthnRequest XML — no leading whitespace."""
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


@app.get("/login")
def login():
    request_id = "_" + str(uuid.uuid4())

    # FIX 2: Use Z-suffix format, matching Java's ISO_INSTANT
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    saml_request_xml = build_authn_request(request_id, issue_instant)
    encoded = deflate_and_base64(saml_request_xml)

    # FIX 1: URL-encode the Base64 string so +, /, = are safely transmitted
    url_encoded = quote(encoded, safe="")

    redirect_url = f"{IDAM_SSO_URL}?SAMLRequest={url_encoded}"
    return RedirectResponse(redirect_url)


@app.post("/acs")
async def acs(request: Request):
    form = await request.form()
    saml_response_raw = form.get("SAMLResponse")

    if not saml_response_raw:
        return HTMLResponse("No SAMLResponse in POST body", status_code=400)

    # FIX 5: Spaces may replace + during form transport — restore them
    saml_response_clean = saml_response_raw.replace(" ", "+").strip()

    try:
        decoded_bytes = base64.b64decode(saml_response_clean)
        saml_xml = decoded_bytes.decode("utf-8")
    except Exception as e:
        return HTMLResponse(f"Failed to decode SAMLResponse: {e}", status_code=400)

    print("SAML RESPONSE:\n", saml_xml)

    try:
        root = ET.fromstring(saml_xml)
    except ET.ParseError as e:
        return HTMLResponse(f"Invalid XML in SAMLResponse: {e}", status_code=400)

    namespace = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
    name_id_el = root.find(".//saml2:NameID", namespace)

    if name_id_el is None or not name_id_el.text:
        return HTMLResponse("Login failed: NameID not found in SAML response", status_code=401)

    user_id = name_id_el.text
    return RedirectResponse(f"{FRONTEND_REDIRECT}/?user={user_id}", status_code=303)