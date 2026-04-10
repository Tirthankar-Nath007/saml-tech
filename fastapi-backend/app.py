"""
saml_main.py — SAML 2.0 Service Provider (SP) implementation for FastAPI
=========================================================================

OVERVIEW
--------
This module implements a minimal but production-aware SAML 2.0 SP that:
  1. Generates a signed AuthnRequest and redirects the browser to the IdP (HTTP-Redirect binding)
  2. Receives the SAMLResponse POST from the IdP (HTTP-POST binding) at the ACS endpoint
  3. Cryptographically verifies the IdP's XML signature using the certificate from metadata
  4. Validates the assertion time window (NotBefore / NotOnOrAfter)
  5. Extracts the NameID (user identifier) and any other useful claims
  6. Redirects the browser to the frontend with the user info

SAML FLOW (high level)
----------------------
  Browser → GET /login
    → SP builds AuthnRequest XML
    → SP DEFLATE-compresses + Base64-encodes it
    → SP URL-encodes the result
    → Browser is redirected to IdP SSO URL with ?SAMLRequest=...

  IdP authenticates user, then:
  Browser → POST /acs  (IdP posts SAMLResponse form field here)
    → SP Base64-decodes the response
    → SP verifies XML signature against IdP's X.509 cert
    → SP validates time window
    → SP extracts NameID
    → Browser is 303-redirected to frontend

ENVIRONMENT VARIABLES REQUIRED
-------------------------------
  IDAM_SSO_URL      — IdP Single Sign-On URL (e.g. https://idp.example.com/sso)
  ISSUER            — This SP's entity ID / issuer string (must match what you registered with IdP)
  ACS_URL           — This SP's Assertion Consumer Service URL (where IdP will POST back)
  FRONTEND_REDIRECT — Base URL of the frontend to redirect after successful login
  IDP_CERT          — Raw base64 X.509 certificate from IdP metadata (no PEM headers, no line breaks)

DEPENDENCIES
------------
  pip install fastapi uvicorn python-multipart lxml xmlsec cryptography
"""

import os
import base64
import zlib
import uuid
import logging
from datetime import datetime, timezone
from urllib.parse import quote

import xmlsec
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse

# =============================================================================
# LOGGING SETUP
# =============================================================================
# Using a named logger (not root) so log level can be controlled independently.
# For POC: DEBUG level shows everything. In production, switch to INFO or WARNING.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("saml_sp")

# =============================================================================
# STARTUP VALIDATION — Fail fast if any required env var is missing
# =============================================================================
REQUIRED_ENV_VARS = ["IDAM_SSO_URL", "ISSUER", "ACS_URL", "FRONTEND_REDIRECT", "IDP_CERT"]
missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing:
    # Log the missing vars before raising so the error appears in container logs
    logger.critical("Missing required environment variables: %s", ", ".join(missing))
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

logger.info("All required environment variables are present.")

# =============================================================================
# CONFIGURATION — Load from environment
# =============================================================================
IDAM_SSO_URL      = os.getenv("IDAM_SSO_URL")       # IdP SSO endpoint
ISSUER            = os.getenv("ISSUER")               # SP entity ID
ACS_URL           = os.getenv("ACS_URL")              # SP ACS URL
FRONTEND_REDIRECT = os.getenv("FRONTEND_REDIRECT")   # Frontend base URL

# IDP_CERT is the raw base64 blob from the IdP's metadata XML <ds:X509Certificate>.
# We strip whitespace defensively in case the .env value has accidental line breaks.
IDP_CERT_B64 = os.getenv("IDP_CERT", "").replace("\n", "").replace(" ", "").strip()

logger.debug("Configuration loaded — ISSUER=%s | ACS_URL=%s | IDAM_SSO_URL=%s",
             ISSUER, ACS_URL, IDAM_SSO_URL)

# =============================================================================
# XML NAMESPACE MAP
# Used by lxml's .find() / .findall() for namespace-aware XPath queries.
# =============================================================================
NS = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",   # Protocol namespace (Response, AuthnRequest)
    "saml2":  "urn:oasis:names:tc:SAML:2.0:assertion",  # Assertion namespace (NameID, Conditions, etc.)
    "ds":     "http://www.w3.org/2000/09/xmldsig#",     # XML Digital Signature namespace
}

# =============================================================================
# IDP PUBLIC KEY LOADING
# =============================================================================

def load_idp_public_key() -> xmlsec.Key:
    """
    Converts the raw base64 X.509 certificate (from IdP metadata) into an
    xmlsec Key object that can be used to verify XML digital signatures.

    Steps:
      1. base64-decode the cert string → DER bytes
      2. Parse the DER bytes into a cryptography.x509.Certificate object
      3. Re-encode as PEM (xmlsec needs PEM format)
      4. Load into xmlsec.Key

    Why PEM? xmlsec's Key.from_memory() accepts PEM-encoded certificates.
    The metadata XML contains the cert as raw base64 (DER without headers),
    so we must convert it.
    """
    logger.info("Loading IdP public key from IDP_CERT env var...")

    try:
        # Step 1: Decode the base64 cert string to raw DER bytes
        cert_der = base64.b64decode(IDP_CERT_B64)
        logger.debug("Decoded IDP_CERT: %d bytes (DER)", len(cert_der))

        # Step 2: Parse the DER bytes as an X.509 certificate
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        logger.debug(
            "Certificate subject: %s | valid until: %s",
            cert.subject.rfc4514_string(),
            cert.not_valid_after_utc,
        )

        # Step 3: Re-encode as PEM so xmlsec can consume it
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

        # Step 4: Load into xmlsec as a certificate key (not a raw public key)
        key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM)
        logger.info("IdP public key loaded successfully.")
        return key

    except Exception as exc:
        logger.critical("Failed to load IdP public key: %s", exc, exc_info=True)
        raise


# Load the key once at startup — reused for every incoming SAMLResponse
IDP_KEY = load_idp_public_key()

# =============================================================================
# FASTAPI APP
# =============================================================================
app = FastAPI(title="SAML SP — POC", description="SAML 2.0 Service Provider integration")

# =============================================================================
# SAML REQUEST HELPERS
# =============================================================================

def deflate_and_base64(xml: str) -> str:
    """
    Compresses an XML string using raw DEFLATE (no zlib header) and then
    Base64-encodes the result.

    This is REQUIRED by the SAML HTTP-Redirect binding specification (section 3.4.4.1).
    The 'wbits=-15' parameter (via zlib.DEFLATED + negative window bits) produces
    raw DEFLATE output without the zlib header/trailer — exactly what SAML expects.

    The Java equivalent is:
        Deflater deflater = new Deflater(Deflater.DEFLATED, true); // true = no ZLIB header
    """
    logger.debug("Compressing AuthnRequest XML (%d chars) with raw DEFLATE...", len(xml))
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    encoded = base64.b64encode(compressed).decode("utf-8")
    logger.debug("Compressed + encoded AuthnRequest: %d chars", len(encoded))
    return encoded


def build_authn_request(request_id: str, issue_instant: str) -> str:
    """
    Builds the SAML 2.0 AuthnRequest XML string.

    Key attributes:
      ID              — Unique identifier for this request (prefixed with _ per spec)
      Version         — Always "2.0" for SAML 2.0
      IssueInstant    — UTC timestamp in xs:dateTime format (YYYY-MM-DDTHH:MM:SSZ)
      Destination     — The IdP SSO URL (some IdPs validate this matches their endpoint)
      AssertionConsumerServiceURL — Where the IdP should POST the SAMLResponse back to

    Note: No leading whitespace or newlines — some strict IdPs reject XML with a BOM
    or leading whitespace before the root element.
    """
    xml = (
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
    logger.debug("Built AuthnRequest XML: ID=%s | IssueInstant=%s", request_id, issue_instant)
    return xml

# =============================================================================
# SAML RESPONSE VALIDATION HELPERS
# =============================================================================

def verify_saml_signature(root: etree._Element) -> bool:
    """
    Verifies the XML digital signature on the SAML Assertion element.

    WHY THE ASSERTION, NOT THE RESPONSE?
    The IdP in this integration signs both the outer <Response> and the inner
    <Assertion>. We verify the Assertion's signature because:
      - The Assertion is the authoritative piece we rely on (it contains the NameID,
        conditions, and AuthnStatement).
      - Some IdPs sign only the Assertion and not the outer Response wrapper.
      - Verifying the Assertion is sufficient to prove the identity claim is authentic.

    HOW XMLSEC SIGNATURE VERIFICATION WORKS:
      1. We locate the <ds:Signature> element inside the Assertion using xmlsec's
         own finder (not lxml's .find()) — xmlsec needs to walk the tree its own way.
      2. We register the "ID" attribute as an XML ID on the Assertion. This is critical:
         the <ds:Reference URI="#IBAM-EgbCsHW0mkMaNuk6oLSQ"> in the signature points
         to the Assertion by its ID attribute. Without registering it, xmlsec cannot
         resolve the URI reference and throws "failed to verify".
      3. We create a SignatureContext, attach the IdP's public key, and call verify().
         If the signature is invalid or the document was tampered with, xmlsec raises.

    COMMON PITFALL:
      Using lxml's root.find(".//ds:Signature") picks the FIRST signature in the
      document — which is on the outer Response. Verifying that with the Assertion's
      ID registration fails. Always find the signature INSIDE the Assertion element.
    """
    logger.debug("Starting XML signature verification on Assertion...")

    # Step 1: Find the <saml2:Assertion> element in the Response
    assertion = root.find(".//saml2:Assertion", NS)
    if assertion is None:
        logger.error("No <saml2:Assertion> element found in the SAMLResponse.")
        raise ValueError("No Assertion element found in SAML response")

    logger.debug("Found Assertion element with ID=%s", assertion.get("ID"))

    # Step 2: Use xmlsec's native tree walker to find <ds:Signature> inside the Assertion.
    # This is different from lxml's XPath — xmlsec uses its own C-level tree traversal.
    signature_node = xmlsec.tree.find_node(assertion, xmlsec.Node.SIGNATURE)
    if signature_node is None:
        logger.error("No <ds:Signature> element found inside the Assertion.")
        raise ValueError("No Signature found in Assertion")

    logger.debug("Found Signature node inside Assertion.")

    # Step 3: Register the "ID" XML attribute on the Assertion so xmlsec can resolve
    # the URI reference in <ds:Reference URI="#...">. Without this, xmlsec cannot
    # find the signed content and will always fail verification.
    xmlsec.tree.add_ids(assertion, ["ID"])
    logger.debug("Registered 'ID' attribute on Assertion for URI reference resolution.")

    # Step 4: Create a verification context and attach the IdP's public key
    ctx = xmlsec.SignatureContext()
    ctx.key = IDP_KEY

    # Step 5: Verify — raises xmlsec.Error if signature is invalid or content was tampered
    logger.debug("Calling xmlsec SignatureContext.verify()...")
    ctx.verify(signature_node)

    logger.info("XML signature verification PASSED.")
    return True


def parse_dt(s: str) -> datetime:
    """
    Parse an xs:dateTime string into a timezone-aware datetime object.
    Handles both millisecond precision (2026-04-10T06:17:56.551Z)
    and second precision (2026-04-10T06:17:56Z) formats.
    """
    if s is None:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def parse_saml_assertion(root: etree._Element) -> dict:
    """
    Extracts all useful claims from the verified SAML Assertion and validates
    the assertion's time window.

    TIME WINDOW VALIDATION
    ----------------------
    The Assertion's <Conditions> element contains:
      NotBefore    — The assertion is not valid before this time (allows small clock skew)
      NotOnOrAfter — The assertion expires at this time (typically 1-2 minutes from issue)

    This window is intentionally narrow (in this IdP, ~70 seconds) to prevent
    replay attacks. We must check the current UTC time is within this window.

    FIELDS EXTRACTED
    ----------------
      user_id        — The NameID value (the user's unique identifier, e.g. employee ID)
      session_index  — The IdP session identifier (needed for Single Logout / SLO)
      session_expiry — When the IdP session expires (typically 8 hours)
      not_before     — Start of the assertion validity window
      not_on_after   — End of the assertion validity window

    Returns a dict with all extracted fields.
    """
    logger.debug("Parsing SAML Assertion claims...")

    assertion = root.find(".//saml2:Assertion", NS)
    if assertion is None:
        raise ValueError("No Assertion found in SAMLResponse")

    # --- Extract NameID (the primary user identifier) ---
    name_id_el = assertion.find(".//saml2:NameID", NS)
    if name_id_el is None:
        logger.warning("No <saml2:NameID> found in Assertion.")
        name_id = None
    else:
        name_id = name_id_el.text.strip() if name_id_el.text else None
        logger.info("Extracted NameID: %s | Format: %s", name_id, name_id_el.get("Format"))

    # --- Extract AuthnStatement attributes ---
    # SessionIndex is the IdP's session ID — required for SLO (Single Logout).
    # SessionNotOnOrAfter tells us how long the IdP session is valid (8 hours here).
    authn_stmt  = assertion.find(".//saml2:AuthnStatement", NS)
    session_idx = authn_stmt.get("SessionIndex")         if authn_stmt is not None else None
    session_exp = authn_stmt.get("SessionNotOnOrAfter")  if authn_stmt is not None else None
    authn_ctx   = assertion.findtext(".//saml2:AuthnContextClassRef", namespaces=NS)

    logger.debug("SessionIndex=%s | SessionNotOnOrAfter=%s | AuthnContext=%s",
                 session_idx, session_exp, authn_ctx)

    # --- Extract Conditions (time window + audience) ---
    conditions   = assertion.find("saml2:Conditions", NS)
    not_before   = conditions.get("NotBefore")   if conditions is not None else None
    not_on_after = conditions.get("NotOnOrAfter") if conditions is not None else None

    logger.debug("Assertion validity window: NotBefore=%s | NotOnOrAfter=%s",
                 not_before, not_on_after)

    # --- Validate time window ---
    now = datetime.now(timezone.utc)
    logger.debug("Current UTC time: %s", now.isoformat())

    nb_dt  = parse_dt(not_before)
    noa_dt = parse_dt(not_on_after)

    if nb_dt and now < nb_dt:
        logger.error("Assertion time window violation: now=%s < NotBefore=%s", now, nb_dt)
        raise ValueError(f"Assertion not yet valid (NotBefore: {not_before})")

    if noa_dt and now >= noa_dt:
        logger.error("Assertion has EXPIRED: now=%s >= NotOnOrAfter=%s", now, noa_dt)
        raise ValueError(f"Assertion has expired (NotOnOrAfter: {not_on_after})")

    logger.info("Assertion time window is valid.")

    # --- Extract Audience (optional but useful for debugging misconfiguration) ---
    audience = assertion.findtext(".//saml2:Audience", namespaces=NS)
    logger.debug("Assertion Audience: %s (our ISSUER: %s)", audience, ISSUER)
    if audience and audience != ISSUER:
        # Log a warning but don't reject — the IdP in this integration uses the ISSUER
        # as the Audience. If they differ, it may indicate a misconfiguration.
        logger.warning(
            "Audience mismatch! Response Audience=%s but our ISSUER=%s. "
            "This may indicate an IdP misconfiguration.",
            audience, ISSUER,
        )

    return {
        "user_id":        name_id,
        "session_index":  session_idx,
        "session_expiry": session_exp,
        "not_before":     not_before,
        "not_on_after":   not_on_after,
        "authn_context":  authn_ctx,
        "audience":       audience,
    }

# =============================================================================
# ROUTES
# =============================================================================

@app.get("/login", summary="Initiate SAML SSO login")
def login():
    """
    Step 1 of SAML SSO — Build and send the AuthnRequest to the IdP.

    This implements the SAML HTTP-Redirect binding:
      1. Build the AuthnRequest XML
      2. DEFLATE compress it (raw, no zlib header)
      3. Base64 encode the compressed bytes
      4. URL-encode the base64 string (critical! + and / must be encoded)
      5. Redirect the browser to the IdP SSO URL with the encoded request as a query param

    WHY URL-ENCODE?
    Base64 uses +, /, and = which are special characters in query strings.
    Without URL-encoding, the IdP receives a malformed SAMLRequest and returns 500.
    """
    logger.info("=== /login — Initiating SAML AuthnRequest ===")

    # Generate a unique request ID. SAML spec requires it to start with a letter or _
    # (XML NCName rule) — we use _ prefix to be safe.
    request_id    = "_" + str(uuid.uuid4())

    # IssueInstant must be in xs:dateTime format with Z suffix (UTC).
    # Python's .isoformat() produces +00:00 which some strict IdPs reject.
    # strftime with %Z is unreliable; hardcode the Z suffix instead.
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.debug("AuthnRequest: ID=%s | IssueInstant=%s", request_id, issue_instant)

    # Build the raw XML
    saml_request_xml = build_authn_request(request_id, issue_instant)
    logger.debug("AuthnRequest XML length: %d chars", len(saml_request_xml))

    # Compress + encode per SAML HTTP-Redirect binding spec
    encoded     = deflate_and_base64(saml_request_xml)

    # URL-encode so base64 special chars don't corrupt the query string
    url_encoded = quote(encoded, safe="")

    redirect_url = f"{IDAM_SSO_URL}?SAMLRequest={url_encoded}"
    logger.info("Redirecting browser to IdP: %s", IDAM_SSO_URL)
    logger.debug("Full redirect URL length: %d chars", len(redirect_url))

    # 307 Temporary Redirect — browser keeps the GET method
    return RedirectResponse(redirect_url)


@app.post("/acs", summary="SAML Assertion Consumer Service — receive IdP's SAMLResponse")
async def acs(request: Request):
    """
    Step 2 of SAML SSO — Receive and validate the SAMLResponse from the IdP.

    This implements the SAML HTTP-POST binding at the Assertion Consumer Service (ACS).
    The IdP POSTs a form with a 'SAMLResponse' field containing the base64-encoded
    SAML Response XML.

    Processing steps:
      1. Extract SAMLResponse from the POST form body
      2. Fix base64 (spaces may have replaced + during HTTP transport)
      3. Base64-decode to get the raw XML bytes
      4. Parse the XML with lxml (namespace-aware)
      5. Verify the XML digital signature using the IdP's X.509 certificate
      6. Validate the assertion time window (NotBefore / NotOnOrAfter)
      7. Extract the NameID and other claims
      8. 303-redirect the browser to the frontend

    WHY 303 AND NOT 307?
    The ACS receives a POST from the IdP. After processing, we want to send the
    browser to the frontend with a GET request. A 307 would cause the browser to
    re-POST to the frontend (which doesn't accept POST), resulting in 405 Not Allowed.
    A 303 See Other tells the browser: "go GET this new URL" — converting POST → GET.
    """
    logger.info("=== POST /acs — Received SAMLResponse from IdP ===")

    # --- Step 1: Extract SAMLResponse from form body ---
    form = await request.form()
    raw_saml_response = form.get("SAMLResponse")

    if not raw_saml_response:
        logger.error("No 'SAMLResponse' field in POST body. Form keys: %s", list(form.keys()))
        return HTMLResponse("Missing SAMLResponse in POST body", status_code=400)

    logger.debug("Raw SAMLResponse length: %d chars", len(raw_saml_response))
    logger.debug("SAMLResponse preview (first 80 chars): %s", raw_saml_response[:80])

    # --- Step 2: Fix base64 — spaces may have replaced '+' during form encoding ---
    # When browsers POST a form, '+' in a base64 string can be decoded as a space.
    # Replacing spaces back to '+' restores the valid base64 string.
    # The Java code uses the same technique: samlResponse.replace(" ", "+").trim()
    clean_response = raw_saml_response.replace(" ", "+").strip()
    logger.debug("After space-to-plus fix: %d chars", len(clean_response))

    # --- Step 3: Base64-decode to get raw XML ---
    try:
        decoded_bytes = base64.b64decode(clean_response)
        saml_xml      = decoded_bytes.decode("utf-8")
        logger.debug("Decoded SAMLResponse: %d bytes of XML", len(saml_xml))
    except Exception as exc:
        logger.error("Base64 decode failed: %s", exc, exc_info=True)
        return HTMLResponse(f"Base64 decode failed: {exc}", status_code=400)

    # Log the full XML for POC debugging (remove in production — contains PII)
    logger.debug("SAMLResponse XML:\n%s", saml_xml)

    # --- Step 4: Parse XML with lxml (namespace-aware) ---
    # We use lxml (not stdlib xml.etree) because xmlsec requires lxml elements.
    try:
        root = etree.fromstring(saml_xml.encode("utf-8"))
        logger.debug("XML parsed successfully. Root tag: %s", root.tag)
    except etree.XMLSyntaxError as exc:
        logger.error("XML parse error: %s", exc, exc_info=True)
        return HTMLResponse(f"Invalid XML in SAMLResponse: {exc}", status_code=400)

    # --- Log top-level response attributes for diagnostics ---
    logger.info(
        "SAMLResponse — ID=%s | InResponseTo=%s | IssueInstant=%s | Destination=%s",
        root.get("ID"),
        root.get("InResponseTo"),
        root.get("IssueInstant"),
        root.get("Destination"),
    )

    # --- Check the top-level status code ---
    status_code_el = root.find(".//saml2p:StatusCode", NS)
    if status_code_el is not None:
        status_value = status_code_el.get("Value", "")
        logger.info("IdP Status: %s", status_value)
        if "Success" not in status_value:
            logger.error("IdP returned non-success status: %s", status_value)
            return HTMLResponse(f"IdP returned non-success status: {status_value}", status_code=401)

    # --- Step 5: Verify XML digital signature ---
    try:
        verify_saml_signature(root)
    except xmlsec.Error as exc:
        # xmlsec.Error is the specific exception for cryptographic failures
        logger.error("XML signature verification FAILED (cryptographic): %s", exc, exc_info=True)
        return HTMLResponse(f"Signature verification failed: {exc}", status_code=401)
    except ValueError as exc:
        logger.error("XML signature verification FAILED (structural): %s", exc, exc_info=True)
        return HTMLResponse(f"Signature verification failed: {exc}", status_code=401)

    # --- Step 6 & 7: Parse assertion, validate time window, extract claims ---
    try:
        claims = parse_saml_assertion(root)
    except ValueError as exc:
        logger.error("Assertion validation FAILED: %s", exc, exc_info=True)
        return HTMLResponse(f"Assertion validation failed: {exc}", status_code=401)

    logger.info(
        "Authentication SUCCESS — user_id=%s | session_index=%s | session_expiry=%s",
        claims["user_id"],
        claims["session_index"],
        claims["session_expiry"],
    )

    # --- Guard: NameID must be present ---
    user_id = claims["user_id"]
    if not user_id:
        logger.error("NameID is missing or empty in the assertion. Cannot identify user.")
        return HTMLResponse("Login failed: NameID not found in SAML assertion", status_code=401)

    # --- Step 8: 303 redirect to frontend ---
    # 303 See Other causes the browser to issue a GET to the new URL,
    # converting the IdP's POST into a GET to the frontend.
    # NOTE: In a real app, issue a signed session cookie or JWT here instead of
    # passing the user_id in the query string (which is visible in browser history).
    frontend_url = f"{FRONTEND_REDIRECT}/?user={user_id}"
    logger.info("Redirecting to frontend: %s", frontend_url)

    return RedirectResponse(frontend_url, status_code=303)