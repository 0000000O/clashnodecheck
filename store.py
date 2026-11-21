"""SQLite 存储：每次批量测试是一个 run，每个节点的每次结果是一行 result。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time

COLUMNS = [
    "ip", "host", "ip_type", "isp", "org", "asn", "bot_ratio", "domain", "registry",
    "is_dc", "threat", "proxy_status", "score", "country", "country_code", "flag",
    "region", "city", "latlon", "timezone", "continent",
    "gemini_level", "gemini_region", "gemini_web", "gemini_api", "gemini_risk", "gemini_latency_ms",
    "yt_translate_status", "yt_translate_code", "yt_translate_detail", "yt_translate_ms",
]
INT_COLUMNS = {"score", "gemini_latency_ms", "yt_translate_code", "yt_translate_ms"}

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    finished_at REAL,
    total INTEGER DEFAULT 0,
    ok INTEGER DEFAULT 0,
    fail INTEGER DEFAULT 0,
    note TEXT
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    node TEXT NOT NULL,
    tested_at REAL NOT NULL,
    ok INTEGER NOT NULL,
    error TEXT,
    delay_ms INTEGER,
    latency_ms INTEGER,
    {", ".join(c + (" INTEGER" if c in INT_COLUMNS else " TEXT") for c in COLUMNS)},
    fields_json TEXT,
    geo_json TEXT,
    gemini_json TEXT,
    yt_translate_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_node ON results(node, tested_at);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_ip ON results(ip);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self):
        existing = {r["name"] for r in self._db.execute("PRAGMA table_info(results)").fetchall()}
        wanted = [
            *((c, "INTEGER" if c in INT_COLUMNS else "TEXT") for c in COLUMNS),
            ("gemini_json", "TEXT"),
            ("yt_translate_json", "TEXT"),
        ]
        for col, col_type in wanted:
            if col not in existing:
                self._db.execute(f"ALTER TABLE results ADD COLUMN {col} {col_type}")

    def _rows(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def _exec(self, sql, args=()):
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.lastrowid

    # ---- runs
    def start_run(self, total: int, note: str = "") -> int:
        return self._exec("INSERT INTO runs(started_at,total,note) VALUES(?,?,?)",
                          (time.time(), total, note))

    def finish_run(self, run_id: int, ok: int, fail: int, note: str | None = None):
        self._exec("UPDATE runs SET finished_at=?, ok=?, fail=?, note=COALESCE(?,note) WHERE id=?",
                   (time.time(), ok, fail, note, run_id))

    def runs(self, limit=100):
        return self._rows("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))

    def delete_run(self, run_id: int):
        self._exec("DELETE FROM results WHERE run_id=?", (run_id,))
        self._exec("DELETE FROM runs WHERE id=?", (run_id,))

    # ---- results
    def add_result(self, run_id: int | None, node: str, data: dict, delay_ms: int | None):
        cols = ["run_id", "node", "tested_at", "ok", "error", "delay_ms", "latency_ms",
                *COLUMNS, "fields_json", "geo_json", "gemini_json", "yt_translate_json"]
        vals = [run_id, node, time.time(), 1 if data.get("ok") else 0, data.get("error"),
                delay_ms, data.get("latency_ms"), *[data.get(c) for c in COLUMNS],
                json.dumps(data.get("fields") or {}, ensure_ascii=False),
                json.dumps(data.get("geo"), ensure_ascii=False) if data.get("geo") else None,
                json.dumps(data.get("gemini_detail"), ensure_ascii=False) if data.get("gemini_detail") else None,
                json.dumps(data.get("yt_translate_extra"), ensure_ascii=False) if data.get("yt_translate_extra") else None]
        return self._exec(f"INSERT INTO results({','.join(cols)}) VALUES({','.join('?' * len(cols))})", vals)

    def results_of_run(self, run_id: int):
        return self._rows("SELECT * FROM results WHERE run_id=? ORDER BY id", (run_id,))

    def latest_per_node(self):
        """每个节点最近一次结果，并附带「上一次成功的 IP」用来标记 IP 变化。"""
        rows = self._rows("""
            SELECT r.* FROM results r
            JOIN (SELECT node, MAX(id) AS mid FROM results GROUP BY node) m ON r.id = m.mid
        """)
        prev = self._rows("""
            SELECT node, ip FROM (
                SELECT node, ip, ROW_NUMBER() OVER (PARTITION BY node ORDER BY id DESC) AS rn
                FROM results WHERE ok=1
            ) WHERE rn = 2
        """)
        prev_ip = {p["node"]: p["ip"] for p in prev}
        counts = {r["node"]: r for r in self._rows("""
            SELECT node, COUNT(*) AS tests, SUM(ok) AS oks, COUNT(DISTINCT ip) AS ips
            FROM results GROUP BY node""")}
        for r in rows:
            r["prev_ip"] = prev_ip.get(r["node"])
            c = counts.get(r["node"], {})
            r["tests"], r["oks"], r["distinct_ips"] = c.get("tests"), c.get("oks"), c.get("ips")
        return rows

    def history(self, node: str, limit=500):
        return self._rows("SELECT * FROM results WHERE node=? ORDER BY id DESC LIMIT ?", (node, limit))

    def ip_lookup(self, ip: str):
        return self._rows("SELECT * FROM results WHERE ip=? ORDER BY id DESC", (ip,))

    def all_results(self, run_id: int | None = None):
        if run_id:
            return self.results_of_run(run_id)
        return self._rows("SELECT * FROM results ORDER BY id")
