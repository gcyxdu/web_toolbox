from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

from backend.experiments.store import Store


class JobManager:
    def __init__(self, store: Store):
        self.store = store
        self.processes: dict[str, subprocess.Popen] = {}
        self.lock = threading.Lock()

    def launch(self, rid: str) -> None:
        with self.lock:
            if len(self.processes) >= 2:
                raise RuntimeError("最多同时运行 2 个实验，请等待当前任务结束")
            run_dir = self.store.root / "runs" / rid
            run_dir.mkdir(parents=True, exist_ok=True)
            env = {**os.environ, "PYTHONIOENCODING": "utf-8", "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1"}
            try:
                with (run_dir / "worker.log").open("w", encoding="utf-8") as log:
                    process = subprocess.Popen(
                        [sys.executable, "-m", "backend.experiments.worker", "--data-root", str(self.store.root), "--run-id", rid],
                        cwd=Path(__file__).resolve().parents[2], env=env, stdout=log, stderr=subprocess.STDOUT,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except OSError as exc:
                self.store.update(rid, status="failed", error=str(exc))
                raise RuntimeError("训练进程无法启动") from exc
            self.processes[rid] = process
            self.store.update(rid, pid=process.pid)
        threading.Thread(target=self._watch, args=(rid, process), daemon=True).start()

    def _watch(self, rid: str, process: subprocess.Popen) -> None:
        code = process.wait()
        run = self.store.get(rid)
        if run and run["status"] in {"queued", "running", "cancelling"}:
            status = "cancelled" if run["cancel_requested"] else "failed"
            message = None if status == "cancelled" else f"训练进程退出 ({code})，请查看 worker.log"
            final = self.store.finish(rid, error=message)
            if final:
                self.store.emit(rid, f"run_{final}", {"exit_code": code, "error": message})
        with self.lock:
            self.processes.pop(rid, None)

    def shutdown(self) -> None:
        with self.lock:
            processes = list(self.processes.items())
        for rid, _ in processes:
            self.store.cancel(rid)
        for rid, process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                self.store.update(rid, status="interrupted", error="服务关闭，训练进程已停止")
