from fastapi.testclient import TestClient
from app.main import app

def test_auth_and_jwks():
    c = TestClient(app)
    r = c.post("/auth", auth=("userABC","password123"))
    assert r.status_code == 200
    r2 = c.get("/.well-known/jwks.json")
    assert r2.status_code == 200
    assert "keys" in r2.json()
