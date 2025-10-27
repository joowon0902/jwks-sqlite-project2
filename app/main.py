from contextlib import asynccontextmanager
import time
from typing import Optional
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import jwt

from .config import ALGORITHM, ISSUER, AUDIENCE
from .db import get_conn, init_db, get_one_key, get_all_valid_keys
from .crypto_utils import private_pem_to_key, jwk_from_private_pem
from .key_manager import bootstrap_keys
from .models import AuthRequest, JWKS


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = get_conn()
    init_db(conn)
    conn.close()
    bootstrap_keys()
    yield


app = FastAPI(title="JWKS with SQLite", version="2.0", lifespan=lifespan)
security = HTTPBasic(auto_error=False)


@app.post("/auth")
async def issue_token(
    request: Request,
    body: Optional[AuthRequest] = None,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    username = None
    if credentials and credentials.username:
        username = credentials.username
    elif body and body.username:
        username = body.username

    if not username:
        raise HTTPException(status_code=400, detail="username required via Basic or JSON")

    expired = request.query_params.get("expired") is not None
    now = int(time.time())

    conn = get_conn()
    row = get_one_key(conn, expired=expired, now_ts=now)
    conn.close()
    if not row:
        raise HTTPException(status_code=500, detail="no suitable key found")

    priv = private_pem_to_key(row["key"])
    claims = {
        "sub": username,
        "iat": now,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now - 60 if expired else now + 3600,
    }

    token = jwt.encode(
        claims,
        priv,
        algorithm=ALGORITHM,
        headers={"kid": str(row["kid"])},
    )

    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept or request.query_params.get("json") is not None:
        return JSONResponse({"access_token": token, "token_type": "bearer"})
    return PlainTextResponse(token)


@app.get("/.well-known/jwks.json", response_model=JWKS)
async def jwks():
    now = int(time.time())
    conn = get_conn()
    rows = get_all_valid_keys(conn, now_ts=now)
    conn.close()

    keys = [jwk_from_private_pem(r["key"], r["kid"]) for r in rows]
    return JWKS(keys=keys)
