import os, tempfile, time, sqlite3
from app import config
from app.db import get_conn, init_db, insert_key, get_one_key, get_all_valid_keys
from app.key_manager import bootstrap_keys
from app.crypto_utils import generate_rsa_keypair, jwk_from_private_pem

def test_db_bootstrap_and_queries(monkeypatch):
    fd, path = tempfile.mkstemp(prefix="jwks_cov_", suffix=".db")
    os.close(fd)
    monkeypatch.setattr(config, "DB_FILE", __import__("pathlib").Path(path))

    conn = get_conn()
    init_db(conn)
    conn.close()

    bootstrap_keys()

    conn = get_conn()
    now = int(time.time())

    row_valid = get_one_key(conn, expired=False, now_ts=now)
    assert row_valid is not None and row_valid["exp"] > now

    row_exp = get_one_key(conn, expired=True, now_ts=now)
    assert row_exp is not None and row_exp["exp"] <= now

    all_valid = list(get_all_valid_keys(conn, now_ts=now))
    assert len(all_valid) >= 1
    conn.close()

    jwk = jwk_from_private_pem(row_valid["key"], row_valid["kid"])
    for f in ["kty","alg","use","kid","n","e"]:
        assert f in jwk

    os.remove(path)

def test_manual_insert_key_and_select(monkeypatch):
    fd, path = tempfile.mkstemp(prefix="jwks_cov2_", suffix=".db")
    os.close(fd)
    monkeypatch.setattr(config, "DB_FILE", __import__("pathlib").Path(path))

    conn = get_conn()
    init_db(conn)

    priv_pem, _ = generate_rsa_keypair()
    now = int(time.time())

    kid1 = insert_key(conn, priv_pem.decode(), now - 5)
    kid2 = insert_key(conn, priv_pem.decode(), now + 3600)

    row_v = get_one_key(conn, expired=False, now_ts=now)
    row_e = get_one_key(conn, expired=True, now_ts=now)
    assert str(row_v["kid"]) == str(kid2)
    assert str(row_e["kid"]) == str(kid1)
    conn.close()
    os.remove(path)
