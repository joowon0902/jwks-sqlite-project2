from contextlib import asynccontextmanager
import time
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import jwt

from .config import ALGORITHM, ISSUER, AUDIENCE
from .db import get_conn, init_db, get_one_key, get_all_valid_keys
from .crypto_utils import private_pem_to_key, jwk_from_private_pem
from .key_manager import bootstrap_keys
from .models import AuthRequest, TokenResponse, JWKS


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 앱 시작 시 DB 스키마 초기화 및 키 시드
    conn = get_conn()
    init_db(conn)
    conn.close()
    bootstrap_keys()
    yield
    # 종료 시 필요한 정리 작업이 있으면 여기서 처리


app = FastAPI(title="JWKS with SQLite", version="2.0", lifespan=lifespan)
security = HTTPBasic(auto_error=False)  # Basic 미제공 시에도 401 대신 통과


@app.post("/auth", response_model=TokenResponse)
async def issue_token(
    request: Request,
    body: Optional[AuthRequest] = None,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    # Basic 또는 JSON 바디 중 하나로 username을 받음
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

    priv = private_pem_to_key(row["key"])  # PEM 문자열을 로드해 key 객체로
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
    return TokenResponse(access_token=token)


@app.get("/.well-known/jwks.json", response_model=JWKS)
async def jwks():
    now = int(time.time())
    conn = get_conn()
    rows = get_all_valid_keys(conn, now_ts=now)
    conn.close()

    keys = [jwk_from_private_pem(r["key"], r["kid"]) for r in rows]
    return JWKS(keys=keys)
