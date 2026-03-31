import os
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
import base64, zlib, uuid
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

REQUIRED_ENV_VARS = ["IDAM_SSO_URL", "ISSUER", "ACS_URL", "FRONTEND_REDIRECT"]

missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

app = FastAPI()

IDAM_SSO_URL = os.getenv("IDAM_SSO_URL")
ISSUER = os.getenv("ISSUER")
ACS_URL = os.getenv("ACS_URL")
FRONTEND_REDIRECT = os.getenv("FRONTEND_REDIRECT")

def deflate_and_base64(xml: str):
    compressor = zlib.compressobj(wbits=-15)
    compressed = compressor.compress(xml.encode()) + compressor.flush()
    return base64.b64encode(compressed).decode()

@app.get("/login")
def login():
    request_id = "_" + str(uuid.uuid4())
    issue_instant = datetime.now(timezone.utc).isoformat()

    saml_request = f"""
    <saml2p:AuthnRequest
        ID="{request_id}"
        Version="2.0"
        IssueInstant="{issue_instant}"
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
        AssertionConsumerServiceURL="{ACS_URL}">
        <saml2:Issuer>{ISSUER}</saml2:Issuer>
    </saml2p:AuthnRequest>
    """

    encoded = deflate_and_base64(saml_request)

    redirect_url = f"{IDAM_SSO_URL}?SAMLRequest={encoded}"

    return RedirectResponse(redirect_url)

@app.post("/acs")
async def acs(request: Request):
    form = await request.form()
    saml_response = form.get("SAMLResponse")

    decoded = base64.b64decode(saml_response)
    xml = decoded.decode()

    print("SAML RESPONSE:\n", xml)

    root = ET.fromstring(xml)
    namespace = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}

    name_id = root.find(".//saml2:NameID", namespace)

    if name_id is None:
        return HTMLResponse("Login failed")

    user_id = name_id.text

    return RedirectResponse(f"{FRONTEND_REDIRECT}/?user={user_id}")