from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backend.config.schema import ClientOverride, ExperimentConfig
from backend.experiments.records import delete_run, restore_run


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "experiments.sqlite3"
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
                    config TEXT NOT NULL, metrics TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    cancel_requested INTEGER NOT NULL DEFAULT 0, error TEXT, pid INTEGER
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL, type TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_run ON events(run_id, seq);
            """)
            if 'deleted_at' not in {row['name'] for row in db.execute('PRAGMA table_info(runs)')}:
                db.execute('ALTER TABLE runs ADD COLUMN deleted_at TEXT')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def decode(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        item = dict(row)
        item["config"] = json.loads(item["config"])
        item["config"].setdefault("model", "lr")
        item["metrics"] = json.loads(item["metrics"])
        item["cancel_requested"] = bool(item["cancel_requested"])
        return item

    def create(self, config: ExperimentConfig) -> dict:
        rid, timestamp = uuid.uuid4().hex, now()
        snapshot = config.model_dump()
        overrides = {client.id: client for client in config.clients}
        snapshot["clients"] = [overrides.get(f"client-{i:02d}", ClientOverride(id=f"client-{i:02d}")).model_dump()
                               for i in range(config.client_count)]
        with self.connect() as db:
            db.execute("INSERT INTO runs(id,name,status,config,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                       (rid, config.name, "queued", json.dumps(snapshot, ensure_ascii=False), timestamp, timestamp))
        self.emit(rid, "run_created", {"name": config.name, "backend": config.backend})
        return self.get(rid)

    def get(self, rid: str) -> dict | None:
        with self.connect() as db:
            return self.decode(db.execute("SELECT * FROM runs WHERE id=? AND deleted_at IS NULL", (rid,)).fetchone())

    def list(self) -> list[dict]:
        with self.connect() as db:
            return [self.decode(row) for row in db.execute("SELECT * FROM runs WHERE deleted_at IS NULL ORDER BY created_at DESC")]

    def delete(self, rid: str) -> bool:
        return delete_run(self, rid)

    def restore(self, rid: str) -> dict | None:
        return restore_run(self, rid)

    def update(self, rid: str, **fields) -> None:
        allowed = {"status", "metrics", "cancel_requested", "error", "pid"}
        if not fields or not set(fields).issubset(allowed):
            raise ValueError("Invalid run update")
        if "metrics" in fields:
            fields["metrics"] = json.dumps(fields["metrics"], allow_nan=False)
        fields["updated_at"] = now()
        with self.connect() as db:
            db.execute(f"UPDATE runs SET {','.join(f'{key}=?' for key in fields)} WHERE id=?", (*fields.values(), rid))

    def emit(self, rid: str, kind: str, payload: dict, active_only: bool = False) -> dict | None:
        timestamp = now()
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        with self.connect() as db:
            if active_only:
                cursor = db.execute("INSERT INTO events(run_id,timestamp,type,payload) SELECT ?,?,?,? "
                                    "WHERE EXISTS(SELECT 1 FROM runs WHERE id=? AND status IN ('running','cancelling'))",
                                    (rid, timestamp, kind, encoded, rid))
                if not cursor.rowcount:
                    return None
            else:
                cursor = db.execute("INSERT INTO events(run_id,timestamp,type,payload) VALUES(?,?,?,?)",
                                    (rid, timestamp, kind, encoded))
            seq = cursor.lastrowid
        return {"schema_version": "1.0", "run_id": rid, "seq": seq,
                "timestamp": timestamp, "type": kind, "payload": payload}

    def events(self, rid: str, after: int = 0, limit: int = 20000) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM events WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?", (rid, after, limit))
            return [{**dict(row), "schema_version": "1.0", "payload": json.loads(row["payload"])} for row in rows]

    def cancelled(self, rid: str) -> bool:
        run = self.get(rid)
        return run is None or run["cancel_requested"]

    def cancel(self, rid: str) -> dict | None:
        with self.connect() as db:
            cursor = db.execute("UPDATE runs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'cancelling' END, "
                                "cancel_requested=1,updated_at=? WHERE id=? AND status IN ('queued','running')", (now(), rid))
        if cursor.rowcount:
            self.emit(rid, "cancel_requested", {})
        return self.get(rid)

    def start(self, rid: str) -> bool:
        with self.connect() as db:
            cursor = db.execute("UPDATE runs SET status='running',updated_at=? WHERE id=? AND status='queued' AND cancel_requested=0", (now(), rid))
            return bool(cursor.rowcount)

    def finish(self, rid: str, error: str | None = None) -> str | None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT status,cancel_requested FROM runs WHERE id=?", (rid,)).fetchone()
            if run is None or run["status"] not in {"queued", "running", "cancelling"}:
                return None
            status = "failed" if error is not None else "cancelled" if run["cancel_requested"] else "completed"
            db.execute("UPDATE runs SET status=?,error=?,updated_at=? WHERE id=?", (status, error, now(), rid))
            return status

    def record_metrics(self, rid: str, payload: dict) -> None:
        with self.connect() as db:
            db.execute("UPDATE runs SET metrics=?,updated_at=? WHERE id=? AND status IN ('running','cancelling')",
                       (json.dumps(payload, allow_nan=False), now(), rid))

    def recover(self) -> None:
        for run in self.list():
            if run["status"] in {"queued", "running", "cancelling"}:
                with self.connect() as db:
                    cursor = db.execute("UPDATE runs SET status='interrupted',cancel_requested=1,error=?,updated_at=? "
                                        "WHERE id=? AND status IN ('queued','running','cancelling')",
                                        ("服务重启中断了该任务，请从配置创建新实验", now(), run["id"]))
                if cursor.rowcount:
                    self.emit(run["id"], "run_interrupted", {"reason": "service_restart"})
