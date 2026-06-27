import hashlib
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote, urlsplit


def default_output_dir() -> Path:
    root = os.environ.get("XDG_DATA_HOME")
    if root:
        return Path(root) / "oobmap" / "output"
    return Path.home() / ".local" / "share" / "oobmap" / "output"


def target_id(request, force_ssl: bool) -> str:
    scheme = "https" if force_ssl else "http"
    host = request.host
    target = request.target
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        scheme = parsed.scheme
        host = parsed.netloc or host
        path = parsed.path or "/"
    else:
        parsed = urlsplit(target)
        path = parsed.path or "/"
    digest = hashlib.sha1(f"{request.method} {scheme}://{host}{path}".encode()).hexdigest()[:10]
    safe = quote(host, safe="._-")
    return f"{safe}_{digest}"


def fingerprint(*parts: str) -> str:
    raw = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


class SessionStore:
    def __init__(self, output_dir, request, force_ssl: bool, flush: bool = False):
        self.root = Path(output_dir) if output_dir else default_output_dir()
        self.target = target_id(request, force_ssl)
        self.dir = self.root / self.target
        self.path = self.dir / "session.sqlite"

        if flush and self.dir.exists():
            shutil.rmtree(self.dir)

        self.dir.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kv (
              namespace TEXT NOT NULL,
              key TEXT NOT NULL,
              value TEXT NOT NULL,
              updated_at REAL NOT NULL,
              PRIMARY KEY(namespace, key)
            );

            CREATE TABLE IF NOT EXISTS extractions (
              id TEXT PRIMARY KEY,
              dbms TEXT NOT NULL,
              place TEXT NOT NULL,
              param TEXT NOT NULL,
              expression TEXT NOT NULL,
              alphabet TEXT NOT NULL,
              value TEXT NOT NULL,
              completed INTEGER NOT NULL DEFAULT 0,
              updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS checks (
              id TEXT PRIMARY KEY,
              dbms TEXT NOT NULL,
              place TEXT NOT NULL,
              param TEXT NOT NULL,
              status TEXT NOT NULL,
              updated_at REAL NOT NULL
            );
            """
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

    def set_kv(self, namespace: str, key: str, value):
        self.conn.execute(
            "REPLACE INTO kv(namespace,key,value,updated_at) VALUES(?,?,?,?)",
            (namespace, key, json.dumps(value), time.time()),
        )
        self.conn.commit()

    def get_kv(self, namespace: str, key: str):
        row = self.conn.execute(
            "SELECT value FROM kv WHERE namespace=? AND key=?",
            (namespace, key),
        ).fetchone()
        return json.loads(row["value"]) if row else None

    def extraction_id(self, dbms: str, place: str, param: str, expression: str, alphabet: str) -> str:
        return fingerprint(self.target, dbms, place, param, expression, alphabet)

    def get_extraction(self, extraction_id: str):
        row = self.conn.execute(
            "SELECT * FROM extractions WHERE id=?",
            (extraction_id,),
        ).fetchone()
        return dict(row) if row else None

    def save_extraction(
        self,
        extraction_id: str,
        dbms: str,
        place: str,
        param: str,
        expression: str,
        alphabet: str,
        value: str,
        completed: bool,
    ):
        self.conn.execute(
            """
            REPLACE INTO extractions
              (id, dbms, place, param, expression, alphabet, value, completed, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                extraction_id,
                dbms,
                place,
                param,
                expression,
                alphabet,
                value,
                int(completed),
                time.time(),
            ),
        )
        self.conn.commit()

    def check_id(self, dbms: str, place: str, param: str) -> str:
        return fingerprint(self.target, dbms, place, param)

    def save_check(self, check_id: str, dbms: str, place: str, param: str, status: str):
        self.conn.execute(
            "REPLACE INTO checks(id,dbms,place,param,status,updated_at) VALUES(?,?,?,?,?,?)",
            (check_id, dbms, place, param, status, time.time()),
        )
        self.conn.commit()

    def catalog_key(self, dbms: str, database: str | None, kind: str, table: str | None = None) -> str:
        return fingerprint(self.target, dbms, database or "", kind, table or "")

    def get_catalog(self, dbms: str, database: str | None, kind: str, table: str | None = None):
        return self.get_kv("catalog", self.catalog_key(dbms, database, kind, table))

    def save_catalog(self, dbms: str, database: str | None, kind: str, values, table: str | None = None):
        self.set_kv("catalog", self.catalog_key(dbms, database, kind, table), values)
