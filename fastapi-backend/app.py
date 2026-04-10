import os
import base64
import zlib
import uuid
import textwrap
from datetime import datetime, timezone
from urllib.parse import quote
from xml.etree import ElementTree as ET

import xmlsec
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse

REQUIRED_ENV_VARS = ["IDAM_SSO_URL", "ISSUER", "ACS_URL", "FRONTEND_REDIRECT", "IDP_CERT"]
missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

app = FastAPI()

IDAM_SSO_URL     = os.getenv("IDAM_SSO_URL")
ISSUER           = os.getenv("ISSUER")
ACS_URL          = os.getenv("ACS_URL")
IDP_CERT = os.getenv("IDP_CERT")
FRONTEND_REDIRECT = os.getenv("FRONTEND_REDIRECT")

IDP_CERT_B64 = os.getenv("IDP_CERT", "").replace("\n", "").replace(" ", "").strip()

def load_idp_public_key():
    """Convert the raw base64 cert from metadata into an xmlsec-compatible key."""
    cert_der = base64.b64decode(IDP_CERT_B64)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    # xmlsec needs a PEM file-like object
    cert_pem = cert.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM
    )
    return xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM)

IDP_KEY = load_idp_public_key()

NS = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds":     "http://www.w3.org/2000/09/xmldsig#",
}

def verify_saml_signature(root: etree._Element) -> bool:
    """
    Verify the XML digital signature on the Assertion (or Response).
    Returns True if valid, raises on failure.
    """
    # Try to find a Signature node — prefer the one on the Assertion
    signature_node = root.find(".//ds:Signature", NS)
    if signature_node is None:
        raise ValueError("No Signature element found in SAML response")

    ctx = xmlsec.SignatureContext()
    ctx.key = IDP_KEY
    ctx.verify(signature_node)   # raises xmlsec.Error if invalid
    return True

def parse_saml_assertion(root: etree._Element) -> dict:
    """Extract all useful fields from the verified assertion."""
    assertion = root.find(".//saml2:Assertion", NS)
    if assertion is None:
        raise ValueError("No Assertion found")

    name_id_el = assertion.find(".//saml2:NameID", NS)
    name_id    = name_id_el.text.strip() if name_id_el is not None else None

    authn_stmt  = assertion.find(".//saml2:AuthnStatement", NS)
    session_idx = authn_stmt.get("SessionIndex") if authn_stmt is not None else None
    session_exp = authn_stmt.get("SessionNotOnOrAfter") if authn_stmt is not None else None

    conditions   = assertion.find("saml2:Conditions", NS)
    not_before   = conditions.get("NotBefore")   if conditions is not None else None
    not_on_after = conditions.get("NotOnOrAfter") if conditions is not None else None

    # Validate time window
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"

    def parse_dt(s):
        if s is None:
            return None
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    if not_before and now < parse_dt(not_before):
        raise ValueError(f"Assertion not yet valid (NotBefore: {not_before})")
    if not_on_after and now > parse_dt(not_on_after):
        raise ValueError(f"Assertion has expired (NotOnOrAfter: {not_on_after})")

    return {
        "user_id":       name_id,
        "session_index": session_idx,
        "session_expiry": session_exp,
        "not_before":    not_before,
        "not_on_after":  not_on_after,
    }


# ── Login ──────────────────────────────────────────────────────────────────────

def deflate_and_base64(xml: str) -> str:
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    return base64.b64encode(compressed).decode("utf-8")

@app.get("/login")
def login():
    request_id     = "_" + str(uuid.uuid4())
    issue_instant  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    saml_request   = (
        f'<saml2p:AuthnRequest '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{IDAM_SSO_URL}" AssertionConsumerServiceURL="{ACS_URL}" '
        f'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<saml2:Issuer>{ISSUER}</saml2:Issuer>'
        f'</saml2p:AuthnRequest>'
    )
    encoded      = deflate_and_base64(saml_request)
    url_encoded  = quote(encoded, safe="")
    return RedirectResponse(f"{IDAM_SSO_URL}?SAMLRequest={url_encoded}")


# ── ACS ────────────────────────────────────────────────────────────────────────

@app.post("/acs")
async def acs(request: Request):
    form = await request.form()
    raw  = form.get("SAMLResponse")
    if not raw:
        return HTMLResponse("Missing SAMLResponse", status_code=400)

    try:
        decoded_bytes = base64.b64decode(raw.replace(" ", "+").strip())
        saml_xml      = decoded_bytes.decode("utf-8")
    except Exception as e:
        return HTMLResponse(f"Base64 decode failed: {e}", status_code=400)

    try:
        root = etree.fromstring(saml_xml.encode("utf-8"))
    except etree.XMLSyntaxError as e:
        return HTMLResponse(f"XML parse failed: {e}", status_code=400)

    # 1. Verify signature
    try:
        verify_saml_signature(root)
    except Exception as e:
        return HTMLResponse(f"Signature verification failed: {e}", status_code=401)

    # 2. Parse and time-validate the assertion
    try:
        claims = parse_saml_assertion(root)
    except ValueError as e:
        return HTMLResponse(f"Assertion validation failed: {e}", status_code=401)

    user_id = claims["user_id"]
    if not user_id:
        return HTMLResponse("NameID missing", status_code=401)

    # 303 = See Other — browser re-issues as GET (fixes the 405 you saw)
    return RedirectResponse(
        f"{FRONTEND_REDIRECT}/?user={user_id}",
        status_code=303
    )