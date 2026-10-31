# db.py
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DB_PATH = Path(__file__).parent / "phishguard.db"


def _conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with closing(_conn()) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                url           TEXT UNIQUE NOT NULL,
                host          TEXT,
                risk          REAL,
                verdict       TEXT,
                deep          INTEGER,
                details       TEXT,
                first_seen    REAL,
                scanned_at    REAL,
                last_seen     REAL,
                times_checked INTEGER DEFAULT 1
            )""")
        c.commit()


def normalize(url: str) -> str:
    """Same URL, different typing (trailing slash, host case, #fragment) -> one DB key."""
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    p = urlsplit(u)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/"), p.query, ""))


def get_scan(url: str):
    with closing(_conn()) as c:
        r = c.execute("SELECT * FROM scans WHERE url = ?", (url,)).fetchone()
    return dict(r) if r else None


def save_scan(url, host, risk, verdict, deep, details: dict) -> int:
    now = time.time()
    with closing(_conn()) as c:
        c.execute("""
            INSERT INTO scans (url, host, risk, verdict, deep, details,
                               first_seen, scanned_at, last_seen, times_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(url) DO UPDATE SET
                host = excluded.host, risk = excluded.risk, verdict = excluded.verdict,
                deep = excluded.deep, details = excluded.details,
                scanned_at = excluded.scanned_at, last_seen = excluded.last_seen,
                times_checked = scans.times_checked + 1
        """, (url, host, risk, verdict, int(deep), json.dumps(details), now, now, now))
        c.commit()
        return c.execute("SELECT id FROM scans WHERE url = ?", (url,)).fetchone()["id"]


def bump_scan(scan_id: int):
    with closing(_conn()) as c:
        c.execute("UPDATE scans SET times_checked = times_checked + 1, last_seen = ? WHERE id = ?",
                  (time.time(), scan_id))
        c.commit()


def get_scans_by_ids(ids):
    if not ids:
        return []
    with closing(_conn()) as c:
        q = ",".join("?" * len(ids))
        rows = {r["id"]: dict(r) for r in
                c.execute(f"SELECT * FROM scans WHERE id IN ({q})", list(ids)).fetchall()}
    return [rows[i] for i in ids if i in rows]      # recent-first order bachao


def db_stats():
    with closing(_conn()) as c:
        r = c.execute("SELECT COUNT(*) AS n, "
                      "COALESCE(SUM(risk >= 60), 0) AS risky, "
                      "COALESCE(SUM(times_checked), 0) AS checks FROM scans").fetchone()
    return {"total": r["n"], "risky": int(r["risky"]), "checks": int(r["checks"])}