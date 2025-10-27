import sqlite3
from pathlib import Path
from typing import Iterable, Optional
from . import config

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS keys("
    "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
    "key BLOB NOT NULL,"
    "exp INTEGER NOT NULL)"
)

def get_conn() -> sqlite3.Connection:
    config.DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_FILE.as_posix(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn: Optional[sqlite3.Connection] = None) -> None:
    close_later = False
    if conn is None:
        conn = get_conn()
        close_later = True
    try:
        conn.execute(SCHEMA)
        conn.commit()
    finally:
        if close_later:
            conn.close()

def insert_key(conn: sqlite3.Connection, pem: str, exp: int) -> int:
    cur = conn.execute("INSERT INTO keys(key, exp) VALUES(?, ?)", (pem, exp))
    conn.commit()
    return int(cur.lastrowid)

def get_one_key(conn: sqlite3.Connection, expired: bool, now_ts: int):
    q = ("SELECT * FROM keys WHERE exp <= ? ORDER BY exp DESC, kid DESC LIMIT 1"
         if expired else
         "SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC, kid ASC LIMIT 1")
    cur = conn.execute(q, (now_ts,))
    return cur.fetchone()

def get_all_valid_keys(conn: sqlite3.Connection, now_ts: int) -> Iterable[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC", (now_ts,))
    return cur.fetchall()
