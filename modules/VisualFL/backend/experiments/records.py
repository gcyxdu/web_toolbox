"""Recoverable removal of finished experiment records."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.experiments.store import Store


def delete_run(store: Store, rid: str) -> bool:
    from backend.experiments.store import now
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT status FROM runs WHERE id=? AND deleted_at IS NULL', (rid,)).fetchone()
        if row is None:
            return False
        if row['status'] in {'queued', 'running', 'cancelling'}:
            raise ValueError('运行中的实验不可删除，请先停止训练')
        db.execute('UPDATE runs SET deleted_at=?,updated_at=? WHERE id=?', (now(), now(), rid))
    return True


def restore_run(store: Store, rid: str) -> dict | None:
    with store.connect() as db:
        cursor = db.execute('UPDATE runs SET deleted_at=NULL WHERE id=? AND deleted_at IS NOT NULL', (rid,))
    return store.get(rid) if cursor.rowcount else None
