from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config.methods import ATTACKS, DEFENSES
from backend.config.models import MODELS
from backend.datasets.partition import prepare_data
from backend.engines import ENGINES
from backend.experiments.jobs import JobManager
from backend.config.schema import ExperimentConfig
from backend.experiments.store import Store
from backend.system.info import get_system_info
from backend.datasets.catalog import DATASETS, inspect_dataset


def scenarios() -> list[dict]:
    return [
        {"id": "baseline", "title": "正常联邦训练", "description": "观察数据异构下的收敛过程", "config": {
            "name": "Digits / 基线实验", "attack": "None", "defense": "Mean"}},
        {"id": "poison", "title": "模型投毒", "description": "观察恶意更新对聚合结果的影响", "config": {
            "name": "Gaussian / 更新投毒", "attack": "Gaussian", "attack_start": 5, "defense": "Mean",
            "clients": [{"id": "client-02", "malicious": True}, {"id": "client-07", "malicious": True}]}},
        {"id": "robust", "title": "鲁棒聚合", "description": "相同投毒场景下使用范数裁剪", "config": {
            "name": "Gaussian / Norm clipping", "attack": "Gaussian", "attack_start": 5, "defense": "NormClipping",
            "clients": [{"id": "client-02", "malicious": True}, {"id": "client-07", "malicious": True}]}},
        {"id": "backdoor", "title": "后门攻击", "description": "同时观察干净准确率与后门成功率", "config": {
            "name": "BadNets / 后门实验", "attack": "BadNets", "defense": "Mean",
            "clients": [{"id": "client-02", "malicious": True}, {"id": "client-07", "malicious": True}]}},
        {"id": "layersift", "title": "LayerSift", "description": "固定层投影与 Multi-Krum 筛选（明文在线算法）", "config": {
            "name": "LayerSift / MNIST", "dataset": "MNIST", "model": "LeNet5", "test_size": 1 / 7,
            "algorithm": "FedAvg", "client_count": 12, "attack": "Gaussian", "attack_start": 5,
            "defense": "LayerSift", "defense_params": {"byzantine_ratio": 0.2},
            "clients": [{"id": "client-02", "malicious": True}, {"id": "client-07", "malicious": True}]}}
    ]


def create_app(data_root: Path | str | None = None, launch_jobs: bool = True) -> FastAPI:
    root = data_root or os.getenv("VISUALFL_DATA_DIR", str(Path(__file__).resolve().parents[1] / "data"))
    store = Store(root)
    manager = JobManager(store)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if launch_jobs:
            store.recover()
        yield
        if launch_jobs:
            manager.shutdown()

    app = FastAPI(title="VisualFL", version="0.1.0", lifespan=lifespan)
    app.state.store = store

    def require_run(rid: str) -> dict:
        run = store.get(rid)
        if run is None:
            raise HTTPException(404, "实验不存在")
        return run

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "VisualFL", "training": "real"}

    @app.get("/api/system")
    def system():
        return get_system_info()

    @app.get("/api/catalog")
    def catalog():
        return {"attacks": [{"id": key, **value} for key, value in ATTACKS.items()],
                "defenses": [{"id": key, **value} for key, value in DEFENSES.items()],
                "backends": [engine.availability() for engine in ENGINES.values()],
                "models": MODELS, "datasets": list(DATASETS.values()), "config_schema": ExperimentConfig.model_json_schema()}

    @app.get('/api/datasets/{name}')
    def dataset_details(name: str, seed: int = Query(42, ge=0, le=2147483647),
                        test_size: float = Query(.2, ge=.1, le=.4)):
        if name not in DATASETS:
            raise HTTPException(404, '数据集不存在')
        return inspect_dataset(name, seed, test_size)

    @app.get("/api/scenarios")
    def get_scenarios():
        return scenarios()

    @app.post("/api/preview")
    def preview(config: ExperimentConfig):
        return prepare_data(config).describe(config.resolve_clients())

    @app.get("/api/runs")
    def list_runs():
        return store.list()

    @app.post("/api/runs", status_code=201)
    def create_run(config: ExperimentConfig):
        if config.backend != 'flpoison':
            try:
                config = ExperimentConfig.model_validate({**config.model_dump(), 'backend': 'flpoison'})
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
        availability = ENGINES[config.backend].availability()
        if not availability["available"]:
            raise HTTPException(422, availability.get("reason", "后端暂不可用"))
        run = store.create(config)
        if launch_jobs:
            try:
                manager.launch(run["id"])
            except RuntimeError as exc:
                store.update(run["id"], status="failed", error=str(exc))
                raise HTTPException(409, str(exc)) from exc
        return run

    @app.get("/api/runs/{rid}")
    def get_run(rid: str):
        return require_run(rid)

    @app.delete('/api/runs/{rid}')
    def delete_record(rid: str):
        try:
            deleted = store.delete(rid)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        if not deleted:
            raise HTTPException(404, '实验不存在')
        return {'id': rid, 'deleted': True}

    @app.post('/api/runs/{rid}/restore')
    def restore_record(rid: str):
        restored = store.restore(rid)
        if restored is None:
            raise HTTPException(404, '可恢复的实验不存在')
        return restored

    @app.get("/api/runs/{rid}/events")
    def events(rid: str, after: int = Query(0, ge=0), limit: int = Query(20000, ge=1, le=20000)):
        require_run(rid)
        return store.events(rid, after, limit)

    @app.post("/api/runs/{rid}/cancel")
    def cancel(rid: str):
        require_run(rid)
        return store.cancel(rid)

    @app.get("/api/runs/{rid}/export")
    def export(rid: str):
        run = require_run(rid)
        return JSONResponse({"format": "visualfl.run.v1", "run": run, "events": store.events(rid)},
                            headers={"Content-Disposition": f'attachment; filename="visualfl-{rid[:8]}.json"'})

    @app.websocket("/api/runs/{rid}/stream")
    async def stream(websocket: WebSocket, rid: str, after: int = 0):
        await websocket.accept()
        if store.get(rid) is None:
            await websocket.close(code=1008, reason="Unknown run")
            return
        try:
            while True:
                batch = store.events(rid, max(0, after), 500)
                if batch:
                    await websocket.send_json(batch)
                    after = batch[-1]["seq"]
                if store.get(rid)["status"] not in {"queued", "running", "cancelling"} and not batch:
                    await websocket.close()
                    return
                await asyncio.sleep(0.3)
        except WebSocketDisconnect:
            pass

    dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
