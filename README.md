# JWKS Server with SQLite — Project 2

This extends my Project 1 JWKS server to persist RSA private keys in SQLite, sign JWTs via POST /auth, and serve JWK Set via GET /.well-known/jwks.json. All SQL uses parameterized queries.


**Language**: Python 3.11

**Framework**: FastAPI with Uvicorn ASGI server

**Database**: SQLite 3

**Dependencies**: listed in requirements.txt (fastapi, uvicorn, python-jose, pytest, coverage, sqlite3)

**Platform Tested**: Windows 11 (64-bit)

## How to run

python -m venv .venv

. .venv/Scripts/activate

pip install -r requirements.txt

python -m uvicorn app.main:app

Server runs on http://127.0.0.1:8000

## Endpoints

POST /auth  
- Accepts either HTTP Basic or JSON body  
- JSON example  
  {"username":"userABC","password":"password123"}  
- Optional query parameter expired to sign with an expired key  
- Response  
  {"access_token":"<JWT>", "token_type":"bearer"}

GET /.well-known/jwks.json  
- Returns all non expired keys as JWKS  
- Each JWK has kty, alg, use, kid, n, e

## Database

File name  
totally_not_my_privateKeys.db

Schema
CREATE TABLE IF NOT EXISTS keys(
  kid INTEGER PRIMARY KEY AUTOINCREMENT,
  key BLOB NOT NULL,
  exp INTEGER NOT NULL
)

Keys are stored as PEM strings. On first run the app seeds one expired key and one valid key.

## Security

- Only parameterized SQLite queries  
- No string concatenation in SQL  
- JWT header includes kid that maps to SQLite kid

## Tests and coverage

pytest -q  
coverage run -m pytest  
coverage report  
coverage html

My run  
- Tests passed 6  
- Total coverage 94 percent

## Screenshots

- JWKS browser view  screenshots/jwks_json.png  
- Auth token result  screenshots/auth_token.png  
- Coverage report  screenshots/coverage.png  
- Gradebot table  screenshots/gradebot.png

## Notes

- The DB file is created in the working directory so the provided test client can find it  
- favicon 404 from browser requests is expected and harmless
