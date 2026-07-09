"""SQLite-backed usage tracking for NetGuard.

Schema:
  apps(id, name, match_kind, match_value, cgroup_name, created_at)
  samples(id, app_id, ts, rx_bytes, tx_bytes)   -- rx_bytes/tx_bytes are deltas since previous sample
  caps(app_id, cap_kind, limit_mb, period, rate_kbps, sched_start, sched_end, enabled)
  events(id, app_id, ts, kind, detail)          -- blocked/unblocked/cap_hit/etc, for audit trail
"""
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta

from netguard.common.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    match_kind TEXT NOT NULL,      -- 'process_name' | 'desktop_file' | 'path'
    match_value TEXT NOT NULL UNIQUE,
    cgroup_name TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_app_ts ON samples(app_id, ts);

CREATE TABLE IF NOT EXISTS caps (
    app_id INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    cap_kind TEXT NOT NULL DEFAULT 'none',   -- 'none' | 'daily_mb' | 'session_mb'
    limit_mb REAL,
    rate_kbps REAL,                          -- optional sustained bandwidth throttle
    sched_start TEXT,                        -- 'HH:MM' allowed-window start, NULL = all day
    sched_end TEXT,                          -- 'HH:MM' allowed-window end
    blocked INTEGER NOT NULL DEFAULT 0,      -- manual/enforced block flag
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)


def add_app(name, match_kind, match_value, cgroup_name):
    with connect() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO apps(name, match_kind, match_value, cgroup_name, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, match_kind, match_value, cgroup_name, time.time()),
        )
        if cur.lastrowid:
            conn.execute(
                "INSERT OR IGNORE INTO caps(app_id, cap_kind, enabled) VALUES (?, 'none', 1)",
                (cur.lastrowid,),
            )
            return cur.lastrowid
        row = conn.execute("SELECT id FROM apps WHERE match_value = ?", (match_value,)).fetchone()
        return row["id"]


def remove_app(app_id):
    with connect() as conn:
        conn.execute("DELETE FROM apps WHERE id = ?", (app_id,))


def list_apps():
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM apps ORDER BY name")]


def get_app(app_id):
    with connect() as conn:
        r = conn.execute("SELECT * FROM apps WHERE id = ?", (app_id,)).fetchone()
        return dict(r) if r else None


def record_sample(app_id, rx_bytes, tx_bytes, ts=None):
    with connect() as conn:
        conn.execute(
            "INSERT INTO samples(app_id, ts, rx_bytes, tx_bytes) VALUES (?, ?, ?, ?)",
            (app_id, ts or time.time(), rx_bytes, tx_bytes),
        )


def set_cap(app_id, cap_kind, limit_mb=None, rate_kbps=None,
            sched_start=None, sched_end=None, enabled=True):
    with connect() as conn:
        conn.execute(
            "UPDATE caps SET cap_kind=?, limit_mb=?, rate_kbps=?, sched_start=?, sched_end=?, enabled=? "
            "WHERE app_id=?",
            (cap_kind, limit_mb, rate_kbps, sched_start, sched_end, int(enabled), app_id),
        )


def set_blocked(app_id, blocked: bool):
    with connect() as conn:
        conn.execute("UPDATE caps SET blocked=? WHERE app_id=?", (int(blocked), app_id))


def get_cap(app_id):
    with connect() as conn:
        r = conn.execute("SELECT * FROM caps WHERE app_id = ?", (app_id,)).fetchone()
        return dict(r) if r else None


def list_caps():
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM caps")]


def log_event(app_id, kind, detail=""):
    with connect() as conn:
        conn.execute(
            "INSERT INTO events(app_id, ts, kind, detail) VALUES (?, ?, ?, ?)",
            (app_id, time.time(), kind, detail),
        )


# --- Usage queries -----------------------------------------------------

def _range_bounds(period: str, custom_start=None, custom_end=None):
    now = datetime.now()
    if period == "today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif period == "yesterday":
        start = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
    elif period == "last_3h":
        start = now - timedelta(hours=3)
        end = now
    elif period == "week":
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif period == "custom":
        start, end = custom_start, custom_end
    else:
        raise ValueError(f"unknown period: {period}")
    return start.timestamp(), end.timestamp()


def usage_for_app(app_id, period="today", custom_start=None, custom_end=None):
    start_ts, end_ts = _range_bounds(period, custom_start, custom_end)
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(rx_bytes),0) rx, COALESCE(SUM(tx_bytes),0) tx "
            "FROM samples WHERE app_id=? AND ts>=? AND ts<?",
            (app_id, start_ts, end_ts),
        ).fetchone()
        return {"rx_bytes": row["rx"], "tx_bytes": row["tx"], "total_bytes": row["rx"] + row["tx"]}


def usage_total(period="today", custom_start=None, custom_end=None):
    start_ts, end_ts = _range_bounds(period, custom_start, custom_end)
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(rx_bytes),0) rx, COALESCE(SUM(tx_bytes),0) tx "
            "FROM samples WHERE ts>=? AND ts<?",
            (start_ts, end_ts),
        ).fetchone()
        return {"rx_bytes": row["rx"], "tx_bytes": row["tx"], "total_bytes": row["rx"] + row["tx"]}


def usage_by_app(period="today", custom_start=None, custom_end=None):
    start_ts, end_ts = _range_bounds(period, custom_start, custom_end)
    with connect() as conn:
        rows = conn.execute(
            "SELECT a.id, a.name, COALESCE(SUM(s.rx_bytes),0) rx, COALESCE(SUM(s.tx_bytes),0) tx "
            "FROM apps a LEFT JOIN samples s ON s.app_id=a.id AND s.ts>=? AND s.ts<? "
            "GROUP BY a.id ORDER BY (rx+tx) DESC",
            (start_ts, end_ts),
        ).fetchall()
        return [
            {"app_id": r["id"], "name": r["name"], "rx_bytes": r["rx"], "tx_bytes": r["tx"],
             "total_bytes": r["rx"] + r["tx"]}
            for r in rows
        ]


def session_usage_bytes(app_id, since_ts):
    """Usage since a given timestamp (e.g. app/session start) for session-based caps."""
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(rx_bytes),0) rx, COALESCE(SUM(tx_bytes),0) tx "
            "FROM samples WHERE app_id=? AND ts>=?",
            (app_id, since_ts),
        ).fetchone()
        return row["rx"] + row["tx"]


def prune_old_samples(max_age_days=90):
    cutoff = time.time() - max_age_days * 86400
    with connect() as conn:
        conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
