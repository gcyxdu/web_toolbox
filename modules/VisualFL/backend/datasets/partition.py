from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from backend.config.schema import ExperimentConfig
from backend.datasets.catalog import DATASETS, load_dataset, split_indices


@dataclass
class FederatedData:
    train_x: np.ndarray
    test_x: np.ndarray
    train_y: np.ndarray
    test_y: np.ndarray
    partitions: list[np.ndarray]
    partition_hash: str
    dataset: str = "Digits"
    classes: int = 10

    def describe(self, clients: list[dict]) -> dict:
        return {"dataset": self.dataset, "train_samples": len(self.train_y), "test_samples": len(self.test_y),
                "partition_hash": self.partition_hash, "feature_count": self.train_x.shape[1], "classes": self.classes,
                "partition_indices": [part.tolist() for part in self.partitions],
                "clients": [{**client, "samples": len(part),
                             "histogram": np.bincount(self.train_y[part], minlength=self.classes).tolist()}
                            for client, part in zip(clients, self.partitions)]}


def prepare_data(config: ExperimentConfig) -> FederatedData:
    raw = load_dataset(config.dataset)
    classes = DATASETS[config.dataset]['classes']
    x = np.asarray(raw.data) if DATASETS[config.dataset].get("pixel_max") == 255 else np.asarray(raw.data, dtype=np.float64)
    y = np.asarray(raw.target, dtype=np.int64)
    train, test = split_indices(config.dataset, y, config.seed, config.test_size)
    train_x, test_x, train_y, test_y = x[train], x[test], y[train], y[test]
    if DATASETS[config.dataset].get('pixel_max') == 255:
        train_x = train_x.astype(np.float32) / 255.0
        test_x = test_x.astype(np.float32) / 255.0
    elif config.dataset == 'Digits':
        train_x, test_x = train_x / 16.0, test_x / 16.0
    else:
        scaler = StandardScaler().fit(train_x)
        train_x, test_x = scaler.transform(train_x), scaler.transform(test_x)
    rng = np.random.default_rng(config.seed)
    if config.distribution == "iid":
        partitions = [p.copy() for p in np.array_split(rng.permutation(len(train_y)), config.client_count)]
    else:
        groups: list[list[int]] = [[] for _ in range(config.client_count)]
        for label in range(classes):
            indices = rng.permutation(np.flatnonzero(train_y == label))
            counts = rng.multinomial(len(indices), rng.dirichlet([config.alpha] * config.client_count))
            for group, part in zip(groups, np.split(indices, np.cumsum(counts)[:-1])):
                group.extend(part.tolist())
        # Enforce a documented minimum by moving existing indices, never duplicating data.
        for group in groups:
            while len(group) < 8:
                donor = max(groups, key=len)
                group.append(donor.pop())
        partitions = [rng.permutation(group) for group in groups]
    digest = hashlib.sha256()
    for part in partitions:
        digest.update(np.asarray(part, dtype="<i8").tobytes())
        digest.update(b"|")
    return FederatedData(train_x, test_x, train_y, test_y, partitions, digest.hexdigest(), config.dataset, classes)


def add_trigger(x: np.ndarray, size: int) -> np.ndarray:
    channels = 3 if x.shape[1] == 3072 else 1
    side = int(np.sqrt(x.shape[1] // channels))
    if side * side * channels != x.shape[1] or not 1 <= size <= side:
        raise ValueError("触发器要求方形图像及有效尺寸")
    triggered = x.copy().reshape(-1, channels, side, side)
    triggered[:, :, side - size:, side - size:] = 1.0
    return triggered.reshape(x.shape)
