"""Offline real federated softmax training, with independently implemented attacks.

This engine is not FLPoison. Its normalized model-delta interface and source are
recorded in each run; the optional native adapter uses the upstream classes.
"""
from __future__ import annotations

import time

import numpy as np

from backend.datasets.partition import add_trigger, prepare_data
from backend.config.schema import ExperimentConfig
from backend.engines.base import Cancelled, Emit


def probabilities(x: np.ndarray, weights: np.ndarray) -> np.ndarray:
    logits = x @ weights[:-1] + weights[-1]
    logits -= logits.max(axis=1, keepdims=True)
    exp = np.exp(logits)
    return exp / exp.sum(axis=1, keepdims=True)


def evaluate(x: np.ndarray, y: np.ndarray, weights: np.ndarray) -> tuple[float, float]:
    probs = probabilities(x, weights)
    return float(np.mean(probs.argmax(axis=1) == y)), float(-np.log(np.maximum(probs[np.arange(len(y)), y], 1e-12)).mean())


def aggregate(updates: np.ndarray, method: str, params: dict) -> tuple[np.ndarray, list[dict]]:
    norms = np.linalg.norm(updates, axis=1)
    diag = [{"update_norm": float(n)} for n in norms]
    if method == "Mean":
        result = updates.mean(axis=0)
        for d in diag:
            d["weight"] = 1 / len(updates)
    elif method == "Median":
        result = np.median(updates, axis=0)
    elif method == "TrimmedMean":
        cut = int(float(params["beta"]) * len(updates))
        ordered = np.sort(updates, axis=0)
        result = ordered[cut:len(updates) - cut].mean(axis=0)
    elif method == "NormClipping":
        scales = np.minimum(1., float(params["norm_threshold"]) / np.maximum(norms, 1e-12))
        result = (updates * scales[:, None]).mean(axis=0)
        for d, scale in zip(diag, scales):
            d["clip_ratio"] = float(scale)
            d["clipped_norm"] = d["update_norm"] * float(scale)
    elif method == "Krum":
        neighbors = len(updates) - int(params["byzantine_budget"]) - 2
        distances = np.sum((updates[:, None] - updates[None, :]) ** 2, axis=2)
        np.fill_diagonal(distances, np.inf)
        scores = np.sort(distances, axis=1)[:, :neighbors].sum(axis=1)
        selected = int(scores.argmin())
        result = updates[selected]
        for i, d in enumerate(diag):
            d.update(score=float(scores[i]), selected=i == selected)
    else:
        raise ValueError(f"未注册聚合方法: {method}")
    return result, diag


class NumpyEngine:
    @staticmethod
    def availability() -> dict:
        return {"id": "numpy", "name": "本地轻量引擎", "available": True,
                "description": "真实训练 / NumPy Softmax / 离线 Digits",
                "algorithms": ["FedAvg", "FedSGD"], "source": "visualfl.numpy.v1"}

    def run(self, config: ExperimentConfig, emit: Emit, cancelled: Cancelled) -> None:
        data = prepare_data(config)
        clients = config.resolve_clients()
        emit("data_prepared", data.describe(clients))
        emit("engine_ready", {"backend": "numpy", "source": "visualfl.numpy.v1", "update_kind": "model_delta",
                              "aggregation_weighting": "equal", "local_training_unit": "minibatch_step",
                              "numpy_version": np.__version__, "partition_hash": data.partition_hash})
        weights = np.random.default_rng(config.seed + 1).normal(0, 0.01, (data.train_x.shape[1] + 1, data.classes))
        sampling = np.random.default_rng(config.seed + 101)
        for round_index in range(1, config.rounds + 1):
            if cancelled():
                return
            started = time.perf_counter()
            selected = sorted(sampling.choice(config.client_count, config.participants, replace=False).tolist())
            emit("round_started", {"round": round_index, "client_ids": [clients[i]["id"] for i in selected]})
            updates, active_ids = [], []
            for i in selected:
                if cancelled():
                    return
                client = clients[i]
                emit("client_started", {"round": round_index, "client_id": client["id"]})
                local_started = time.perf_counter()
                local = weights.copy()
                partition = data.partitions[i]
                train_rng = np.random.default_rng(config.seed + round_index * 1000 + i)
                attack_rng = np.random.default_rng(config.seed + round_index * 10000 + i + 999)
                active = client["malicious"] and config.attack != "None" and round_index >= config.attack_start and (
                    config.attack_end is None or round_index <= config.attack_end)
                params = client["attack_params"]
                losses = []
                for _ in range(client["local_steps"]):
                    if cancelled():
                        return
                    batch = train_rng.choice(partition, min(config.batch_size, len(partition)), replace=False)
                    bx, by = data.train_x[batch].copy(), data.train_y[batch].copy()
                    if active and config.attack == "BadNets":
                        poison_count = int(len(by) * params["poisoning_ratio"])
                        poisoned = attack_rng.choice(len(by), poison_count, replace=False)
                        bx[poisoned] = add_trigger(bx[poisoned], int(params["trigger_size"]))
                        by[poisoned] = int(params["target_label"])
                    probs = probabilities(bx, local)
                    losses.append(float(-np.log(np.maximum(probs[np.arange(len(by)), by], 1e-12)).mean()))
                    residual = probs.copy()
                    residual[np.arange(len(by)), by] -= 1
                    local[:-1] -= client["learning_rate"] * (bx.T @ residual / len(by))
                    local[-1] -= client["learning_rate"] * residual.mean(axis=0)
                update = (local - weights).ravel()
                original_norm = float(np.linalg.norm(update))
                if active and config.attack == "Gaussian":
                    update = attack_rng.normal(params["noise_mean"], params["noise_std"], update.shape)
                elif active and config.attack == "SignFlipping":
                    update = -update
                if active:
                    active_ids.append(client["id"])
                updates.append(update)
                emit("client_completed", {"round": round_index, "client_id": client["id"], "samples": len(partition),
                                          "learning_rate": client["learning_rate"], "local_steps": client["local_steps"],
                                          "train_loss": float(np.mean(losses)), "update_norm": float(np.linalg.norm(update)),
                                          "original_norm": original_norm, "attack_active": active,
                                          "duration_ms": (time.perf_counter() - local_started) * 1000})
            if cancelled():
                return
            emit("aggregation_started", {"round": round_index, "method": config.defense})
            delta, diagnostics = aggregate(np.asarray(updates), config.defense, config.defense_settings())
            weights += delta.reshape(weights.shape)
            if not np.isfinite(weights).all():
                raise RuntimeError("更新出现非有限数值，请降低学习率或攻击强度")
            emit("aggregation_completed", {"round": round_index, "method": config.defense,
                                           "clients": [{"client_id": clients[i]["id"], **d} for i, d in zip(selected, diagnostics)]})
            accuracy, loss = evaluate(data.test_x, data.test_y, weights)
            metrics: dict = {"round": round_index, "accuracy": accuracy, "loss": loss,
                             "duration_ms": (time.perf_counter() - started) * 1000,
                             "attack_count": len(active_ids), "participants": len(selected), "source": "measured"}
            if config.attack == "BadNets":
                params = {**clients[0]["attack_params"]}
                # Each malicious group can have a distinct target; report each, and a sample-count weighted total.
                signatures = {(int(c["attack_params"]["target_label"]), int(c["attack_params"]["trigger_size"]))
                              for c in clients if c["malicious"]}
                groups = []
                for target, size in sorted(signatures):
                    eligible = data.test_y != target
                    predictions = probabilities(add_trigger(data.test_x[eligible], size), weights).argmax(axis=1)
                    success, total = int(np.sum(predictions == target)), int(np.sum(eligible))
                    groups.append({"target": target, "trigger_size": size, "success": success, "total": total,
                                   "asr": success / total})
                if groups:
                    metrics["asr_groups"] = groups
                    metrics["asr"] = sum(g["success"] for g in groups) / sum(g["total"] for g in groups)
                    metrics["asr_definition"] = "per-target triggered test, excludes original target class; pooled across groups"
            emit("round_completed", metrics)
