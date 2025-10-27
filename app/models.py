from pydantic import BaseModel
from typing import Optional

class AuthRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class JWKS(BaseModel):
    keys: list
