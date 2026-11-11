"""Thin portable DB layer.

Design notes
------------
* Every identifier is a TEXT UUID, every timestamp an ISO-8601 UTC string, so the
  *same* DDL runs on SQLite and PostgreSQL (see ``migrations/001_init.sql``).
* One writer connection guarded by a re-entrant lock keeps ``BEGIN IMMEDIATE``
  semantics without cross-thread surprises; SQLite in WAL mode sustains the
  board/SSE read load of a single-operator deployment.
* The database is the single source of truth for project/task/queue state. No
  worker holds state in memory that cannot be rebuilt from these tables.
"""
from __future__ import annotations

import contextlib
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .config import settings

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_plus(seconds: float) -> str:
    from datetime import timedelta

    return (
        (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )


class Row(dict):
    """dict row that also supports attribute access (a.column)."""

    def __getattr__(self, item: str) -> Any:
        try:
            return self[item]
        except KeyError as exc:  # pragma: no cover - defensive
            raise AttributeError(item) from exc


class Database:
    def __init__(self, url: str | None = None) -> None:
        self.url = url or settings.db_url
        self.is_postgres = self.url.startswith("postgres")
        self._lock = threading.RLock()
        self._conn = None
        self._depth = 0
        self._connect()

    # -- connection --------------------------------------------------------
    def _connect(self) -> None:
        if self.is_postgres:  # pragma: no cover - no PostgreSQL on this host
            import psycopg  # type: ignore

            self._conn = psycopg.connect(self.url.replace("postgresql+psycopg://", "postgresql://"), autocommit=True)
            self._conn.row_factory = None
            self._param = "%s"
        else:
            path = self.url.replace("sqlite:///", "")
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30, isolation_level=None)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._param = "?"

    def _adapt(self, sql: str) -> str:
        return sql if self._param == "?" else sql.replace("?", "%s")

    # -- primitives --------------------------------------------------------
    def execute(self, sql: str, params: Sequence[Any] | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(self._adapt(sql), tuple(params or ()))
            if self.is_postgres:  # pragma: no cover
                try:
                    cur.close()
                except Exception:  # noqa: BLE001
                    pass
            return getattr(cur, "rowcount", -1)

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self._lock:
            self._conn.executemany(self._adapt(sql), [tuple(r) for r in rows])

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[Row]:
        with self._lock:
            cur = self._conn.execute(self._adapt(sql), tuple(params or ()))
            rows = cur.fetchall()
            keys = [d[0] for d in (cur.description or [])]
        return [Row(dict(zip(keys, r))) for r in rows]

    def one(self, sql: str, params: Sequence[Any] | None = None) -> Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: Sequence[Any] | None = None, default: Any = None) -> Any:
        row = self.one(sql, params)
        if not row:
            return default
        return next(iter(row.values()))

    @contextlib.contextmanager
    def tx(self) -> Iterator["Database"]:
        """Serialisable write transaction (nested calls join the outer one)."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE" if not self.is_postgres else "BEGIN")
            self._depth += 1
            try:
                yield self
                self._depth -= 1
                if outer:
                    self._conn.commit()
            except Exception:
                self._depth -= 1
                if outer:
                    self._conn.rollback()
                raise

    # -- helpers -----------------------------------------------------------
    def alloc_seq(self, name: str) -> int:
        """Monotonic counter usable as an ordering key on both dialects."""
        with self.tx():
            self.execute("INSERT INTO counters(name, value) VALUES(?, 0) ON CONFLICT(name) DO NOTHING", (name,))
            self.execute("UPDATE counters SET value = value + 1 WHERE name = ?", (name,))
            value = self.scalar("SELECT value FROM counters WHERE name = ?", (name,), 0)
        return int(value)

    def migrate(self) -> list[str]:
        applied: list[str] = []
        self.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "  name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        done = {r["name"] for r in self.query("SELECT name FROM schema_migrations")}
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if path.name in done:
                continue
            sql = path.read_text(encoding="utf-8")
            for stmt in _split_statements(sql):
                self.execute(stmt)
            self.execute(
                "INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)", (path.name, utcnow())
            )
            applied.append(path.name)
        return applied


def _split_statements(sql: str) -> list[str]:
    """Split a migration file into statements.

    A trigger body contains `;` characters that do not end the statement, so once a
    CREATE TRIGGER is opened the splitter waits for a line that is exactly `END;`
    instead of stopping at the first trailing semicolon.
    """
    out: list[str] = []
    buf: list[str] = []
    in_trigger = False
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") or not stripped:
            continue
        buf.append(line)
        head = "\n".join(buf).lstrip().upper()
        if not in_trigger and head.startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if stripped.upper() == "END;":
                stmt = "\n".join(buf).strip().rstrip(";").strip()
                if stmt:
                    out.append(stmt)
                buf = []
                in_trigger = False
            continue
        if stripped.endswith(";"):
            stmt = "\n".join(buf).strip().rstrip(";").strip()
            if stmt:
                out.append(stmt)
            buf = []
    tail = "\n".join(buf).strip().rstrip(";").strip()
    if tail:
        out.append(tail)
    return out


db = Database()
