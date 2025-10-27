from fastapi.testclient import TestClient
from app.main import app
import base64

def _basic_headers(u="userABC", p="password123"):
    token = base64.b64encode(f"{u}:{p}".encode()).decode()
    return {"Authorization": f"Basic {token}"}

def test_jwks_has_keys():
    c = TestClient(app)
    r = c.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data and len(data["keys"]) >= 1
    k = data["keys"][0]
    for f in ["kty","alg","use","kid","n","e"]:
        assert f in k

def test_auth_basic_and_json_body():
    c = TestClient(app)
    # Basic
    r1 = c.post("/auth", headers=_basic_headers())
    assert r1.status_code == 200 and "access_token" in r1.json()
    # JSON
    r2 = c.post("/auth", json={"username":"userABC","password":"password123"})
    assert r2.status_code == 200 and "access_token" in r2.json()

def test_auth_expired_param():
    c = TestClient(app)
    r = c.post("/auth?expired=1", headers=_basic_headers())
    assert r.status_code == 200 and "access_token" in r.json()
