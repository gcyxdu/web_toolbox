from __future__ import annotations

import copy
import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.config.methods import defaults, validate_params
from backend.config.models import LAYERSIFT_LAYERS
from backend.datasets.catalog import DATASETS


class ClientOverride(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    id: str = Field(pattern=r"^client-\d{2}$")
    learning_rate: float | None = Field(default=None, ge=0.001, le=1)
    local_steps: int | None = Field(default=None, ge=1, le=50)
    malicious: bool = False
    attack_params: dict[str, float | int] = Field(default_factory=dict)


class ExperimentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    name: str = Field(default="联邦学习实验", min_length=1, max_length=80)
    backend: Literal["numpy", "flpoison"] = "flpoison"
    dataset: Literal["CIFAR10", "CIFAR100", "MNIST", "Digits", "Iris", "Wine"] = "Digits"
    model: Literal["lr", "LeNet5", "ResNet20", "ResNet18", "ResNet50"] = "lr"
    test_size: float = Field(default=0.2, ge=0.1, le=0.4)
    algorithm: Literal["FedAvg", "FedSGD", "FedOpt"] = "FedAvg"
    client_count: int = Field(default=12, ge=2, le=40)
    participation: float = Field(default=1, ge=0.2, le=1)
    rounds: int = Field(default=20, ge=1, le=200)
    local_steps: int = Field(default=10, ge=1, le=50)
    learning_rate: float = Field(default=0.1, ge=0.001, le=1)
    batch_size: int = Field(default=32, ge=8, le=256)
    distribution: Literal["iid", "dirichlet"] = "dirichlet"
    alpha: float = Field(default=0.7, ge=0.05, le=100)
    seed: int = Field(default=42, ge=0, le=2147483647)
    attack: Literal["None", "Gaussian", "SignFlipping", "BadNets"] = "None"
    attack_start: int = Field(default=1, ge=1, le=200)
    attack_end: int | None = Field(default=None, ge=1, le=200)
    attack_params: dict[str, float | int] = Field(default_factory=dict)
    defense: Literal["Mean", "Median", "TrimmedMean", "NormClipping", "Krum", "LayerSift"] = "Mean"
    defense_params: dict[str, float | int] = Field(default_factory=dict)
    clients: list[ClientOverride] = Field(default_factory=list, max_length=40)

    @property
    def participants(self) -> int:
        return max(2, math.ceil(self.client_count * self.participation))

    @model_validator(mode="after")
    def coherent(self) -> "ExperimentConfig":
        metadata = DATASETS[self.dataset]
        if self.model != 'lr' and metadata['kind'] != 'image':
            raise ValueError('卷积模型仅支持图像数据集')
        if self.backend == 'numpy' and self.model != 'lr':
            raise ValueError('卷积模型需要内置 PyTorch 引擎')
        if self.dataset in {'CIFAR10','CIFAR100'}:self.test_size=1/6
        if self.dataset == "MNIST":
            self.test_size = 1 / 7
        max_clients = min(40, (metadata['samples'] - math.ceil(metadata['samples'] * self.test_size)) // 8)
        if self.client_count > max_clients:
            raise ValueError(f"当前训练数据最多支持 {max_clients} 个客户端（每个至少 8 个样本）")
        if self.attack == "BadNets" and not metadata['backdoor']:
            raise ValueError("BadNets 图像触发器仅适用于图像数据集")
        ids = [c.id for c in self.clients]
        if len(ids) != len(set(ids)):
            raise ValueError("客户端 ID 不可重复")
        if any(int(cid.split("-")[1]) >= self.client_count for cid in ids):
            raise ValueError("客户端 ID 超出当前数量")
        validate_params("attack", self.attack, self.attack_params)
        validate_params("defense", self.defense, self.defense_params)
        for client in self.clients:
            validate_params("attack", self.attack, client.attack_params)
        if self.attack == 'BadNets':
            for params in [self.attack_params]+[c.attack_params for c in self.clients]:
                label=params.get('target_label',self.attack_params.get('target_label',0))
                if label >= metadata['classes']:raise ValueError('目标类别超出数据集类别范围')
        if self.attack_end is not None and self.attack_end < self.attack_start:
            raise ValueError("攻击结束轮次不能早于开始轮次")
        if self.defense == "Krum":
            budget = self.defense_params.get("byzantine_budget", 1)
            if self.participants <= 2 * budget + 2:
                raise ValueError("Krum 要求当轮参与客户端数 n > 2f + 2，请调整参与比例或数量上界")
        if self.defense == "LayerSift":
            if self.backend != "flpoison" or self.model not in LAYERSIFT_LAYERS:
                raise ValueError("LayerSift 需要 PyTorch 引擎及 LeNet-5、ResNet-18 或 ResNet-20 模型")
            budget = math.floor(self.participants * self.defense_settings()["byzantine_ratio"])
            if self.participants <= 2 * budget + 2:
                raise ValueError(f"LayerSift / Multi-Krum 要求 n > 2f + 2；当前 n={self.participants}、f={budget}，请增加参与客户端或降低比例上界")
        if self.backend == "numpy" and self.algorithm == "FedOpt":
            raise ValueError("轻量引擎支持 FedAvg 和 FedSGD，FedOpt 请使用内置 PyTorch 引擎")
        if self.backend == "flpoison" and self.defense == "TrimmedMean":
            if int(self.defense_params.get("beta", 0.1) * self.participants) == 0:
                raise ValueError("TrimmedMean 要求每侧至少裁剪一个更新，请提高 beta 或参与数量")
        return self

    def resolve_clients(self) -> list[dict]:
        overrides = {c.id: c for c in self.clients}
        resolved = []
        for i in range(self.client_count):
            cid = f"client-{i:02d}"
            override = overrides.get(cid)
            params = {**defaults("attack", self.attack), **self.attack_params}
            if override:
                params.update(override.attack_params)
            resolved.append({
                "id": cid,
                "learning_rate": override.learning_rate if override and override.learning_rate is not None else self.learning_rate,
                "local_steps": (override.local_steps if override and override.local_steps is not None else self.local_steps)
                if self.algorithm != "FedSGD" else 1,
                "malicious": bool(override and override.malicious),
                "attack_params": copy.deepcopy(params),
            })
        return resolved

    def defense_settings(self) -> dict:
        return {**defaults("defense", self.defense), **self.defense_params}
