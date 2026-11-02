from __future__ import annotations

import argparse
import traceback

from backend.engines import get_engine
from backend.config.schema import ExperimentConfig
from backend.experiments.store import Store


def execute(data_root: str, run_id: str) -> None:
    store = Store(data_root)
    run = store.get(run_id)
    if run is None or not store.start(run_id):
        return
    store.emit(run_id, "run_started", {})

    def emit(kind: str, payload: dict) -> None:
        accepted = store.emit(run_id, kind, payload, active_only=True)
        if accepted and kind == "round_completed":
            store.record_metrics(run_id, payload)

    try:
        config = ExperimentConfig.model_validate(run["config"])
        get_engine(config.backend).run(config, emit, lambda: store.cancelled(run_id))
        status = store.finish(run_id)
        if status:
            store.emit(run_id, f"run_{status}", {})
    except Exception as exc:
        traceback.print_exc()
        if store.finish(run_id, error=str(exc)):
            store.emit(run_id, "run_failed", {"error": str(exc), "stage": "training"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--run-id", required=True)
    options = parser.parse_args()
    execute(options.data_root, options.run_id)
