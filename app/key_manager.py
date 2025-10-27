import time
from .db import get_conn, init_db, insert_key, get_all_valid_keys
from .crypto_utils import generate_rsa_keypair

def bootstrap_keys():
    conn = get_conn()
    init_db(conn)
    now = int(time.time())
    valid = list(get_all_valid_keys(conn, now))
    if valid:
        conn.close()
        return
    priv_expired, _ = generate_rsa_keypair()
    insert_key(conn, priv_expired.decode(), now - 10)
    priv_valid, _ = generate_rsa_keypair()
    insert_key(conn, priv_valid.decode(), now + 3600)
    conn.close()
