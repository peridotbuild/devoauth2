import random
import string
import json
import os

import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from jwcrypto import jwk, jwt

app = FastAPI()

with open(
    os.path.join(os.path.dirname(__file__), "data", "jwk_private.json"),
    "r",
) as f:
    _jwk_key = jwk.JWK(**json.load(f))

with open(
    os.path.join(
        os.path.dirname(__file__),
        "data",
        "jwks.json",
    ),
    "r",
) as f:
    _jwks = json.load(f)

VALID_TOKEN = "demotoken"
USERINFO = {
    "sub": "demo",
    "email": "demo@example.com",
    "full_name": "Demo Person",
    "given_name": "Demo",
    "family_name": "Person",
    "preferred_username": "demo",
    "groups": []
    if not os.getenv("DEVOAUTH2_GROUPS")
    else os.getenv("DEVOAUTH2_GROUPS").split(","),
}


@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    return {
        "issuer": "http://localhost:6644/",
        "authorization_endpoint": "http://localhost:6644/auth",
        "token_endpoint": "http://localhost:6644/token",
        "jwks_uri": "http://localhost:6644/jwks",
        "userinfo_endpoint": "http://localhost:6644/userinfo",
    }


@app.get("/auth")
async def auth(redirect_uri: str):
    # Doesn't really matter but let's just do random
    random_code = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return RedirectResponse(f"{redirect_uri}?code={random_code}")


@app.post("/token")
async def token():
    claims = {**USERINFO, "iss": "http://localhost:6644/"}

    t = jwt.JWT(
        header={"alg": "RS256"},
        claims=claims,
    )

    t.make_signed_token(_jwk_key)

    return {
        "access_token": VALID_TOKEN,
        "token_type": "bearer",
        "id_token": t.serialize(),
    }


@app.get("/jwks")
async def jwks():
    return _jwks


@app.get("/userinfo")
async def userinfo(request: Request):
    # First verify that there is an Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="No Authorization header")

    # Then verify that it is a Bearer token
    auth_type, auth_token = auth_header.split(" ")
    if not auth_type or auth_type.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not a bearer token")

    # Then verify that the token is valid
    if auth_token != VALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")

    return USERINFO


def main():
    uvicorn.run("devoauth2.main:app", port=6644)


if __name__ == "__main__":
    main()
