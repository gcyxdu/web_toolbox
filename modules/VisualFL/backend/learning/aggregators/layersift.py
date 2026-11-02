"""Fixed-layer LayerSift online algorithm in plaintext arithmetic.

Implements critical-layer extraction, Rademacher JL compression, orthogonal
rotation and Multi-Krum selection. No secret sharing or secure MPC is performed.
The complete uploaded updates, never their projections, form the final mean.
"""
from __future__ import annotations

import math
from collections.abc import Callable
from typing import TYPE_CHECKING

import numpy as np

from backend.config.models import LAYERSIFT_DIMENSIONS, LAYERSIFT_LAYERS
from backend.learning.aggregators import aggregator_registry
from backend.learning.aggregators.aggregatorbase import AggregatorBase

if TYPE_CHECKING:
    from types import SimpleNamespace
    from torch.nn import Module


class LayerSiftCancelled(Exception):
    """Stop projection between blocks when the experiment is cancelled."""


def layer_layout(model: Module, name: str) -> tuple[list[slice], dict]:
    """Match selected parameters to the floating state_dict vector, including BN offsets."""
    if name not in LAYERSIFT_LAYERS:
        raise ValueError(f"LayerSift 没有 {name} 的固定层配置")
    parameters = dict(model.named_parameters())
    offsets = {}
    offset = 0
    for key, tensor in model.state_dict().items():
        if tensor.is_floating_point():
            offsets[key] = slice(offset, offset + tensor.numel())
            offset += tensor.numel()
    slices = []
    layers = []
    for label, prefix in LAYERSIFT_LAYERS[name]:
        keys = [key for key in offsets if key in parameters and key.startswith(prefix + '.')]
        if not keys:
            raise ValueError(f"LayerSift 固定层 {label} 对应的模块 {prefix} 不存在")
        count = sum(offsets[key].stop - offsets[key].start for key in keys)
        slices.extend(offsets[key] for key in keys)
        layers.append({'label': label, 'module': prefix, 'parameters': count})
    selected = sum(layer['parameters'] for layer in layers)
    return slices, {'layers': layers, 'selected_dimensions': selected,
                    'full_dimensions': offset, 'parameter_ratio': selected / offset}


def project_layers(values: np.ndarray, dimension: int, seed: int, round_index: int,
                   cancelled: Callable[[], bool] = lambda: False) -> np.ndarray:
    """Fresh round-specific dense signs, generated in blocks to bound matrix memory.

Seeds are reproducible experiment seeds, not cryptographic secrets. Projection
is called only after uploads have been collected. Float64 limits score error.
"""
    public_rng = np.random.default_rng(np.random.SeedSequence([seed, round_index, 1701]))
    projected = np.zeros((len(values), dimension), dtype=np.float64)
    for start in range(0, values.shape[1], 2048):
        if cancelled():
            raise LayerSiftCancelled()
        block = values[:, start:start + 2048]
        signs = public_rng.integers(0, 2, (block.shape[1], dimension), dtype=np.int8)
        signs = signs.astype(np.float64) * 2 - 1
        projected += block @ signs
    projected /= math.sqrt(dimension)
    if cancelled():
        raise LayerSiftCancelled()
    rotation_rng = np.random.default_rng(np.random.SeedSequence([seed, round_index, 1702]))
    rotation, triangular = np.linalg.qr(rotation_rng.standard_normal((dimension, dimension)))
    diagonal_signs = np.where(np.diag(triangular) < 0, -1.0, 1.0)
    rotation *= diagonal_signs  # Positive R diagonal, as in the manuscript.
    if cancelled():
        raise LayerSiftCancelled()
    return projected @ rotation


def multi_krum(values: np.ndarray, budget: int) -> tuple[np.ndarray, np.ndarray]:
    """Score with n-f-2 other neighbors and retain the n-f-2 lowest scores."""
    n = len(values)
    if budget < 0 or n <= 2 * budget + 2:
        raise ValueError(f"Multi-Krum 要求 n > 2f + 2，当前 n={n}、f={budget}")
    centered = values - values.mean(axis=0)
    norms = np.einsum('ij,ij->i', centered, centered)
    distances = np.maximum(norms[:, None] + norms[None, :] - 2 * centered @ centered.T, 0)
    np.fill_diagonal(distances, np.inf)
    neighbors = n - budget - 2
    scores = np.sort(distances, axis=1)[:, :neighbors].sum(axis=1)
    chosen = np.argsort(scores, kind='stable')[:neighbors]
    return chosen, scores


@aggregator_registry
class LayerSift(AggregatorBase):
    def __init__(self, args: SimpleNamespace, **kwargs: object) -> None:
        super().__init__(args)
        self.default_defense_params = {'byzantine_ratio': 0.2}
        self.update_and_set_attr()
        self.dimension = LAYERSIFT_DIMENSIONS[args.dataset]
        self.layout: tuple[list[slice], dict] | None = None
        self.last_diagnostics: dict = {}

    def aggregate(self, updates: np.ndarray, **kwargs: object) -> np.ndarray:
        vectors = np.asarray(updates)
        if vectors.ndim != 2 or not np.isfinite(vectors).all():
            raise ValueError("LayerSift 需要有限的二维客户端更新")
        if self.layout is None:
            self.layout = layer_layout(kwargs['last_global_model'], self.args.model)
        slices, metadata = self.layout
        if vectors.shape[1] != metadata['full_dimensions']:
            raise ValueError("LayerSift 更新维度与模型不一致")
        n = len(vectors)
        budget = math.floor(n * self.byzantine_ratio)
        if n <= 2 * budget + 2:
            raise ValueError(f"LayerSift / Multi-Krum 的参与人数不足：n={n}，f={budget}")
        # Extract deltas for detection. Full uploaded objects retain their
        # algorithm-specific semantics when returned to FedAvg/FedSGD/FedOpt.
        selected_layers = np.concatenate([vectors[:, part] for part in slices], axis=1).astype(np.float64)
        if self.args.algorithm == 'FedAvg':
            global_vector = np.asarray(kwargs['global_weights_vec'])
            selected_layers -= np.concatenate([global_vector[part] for part in slices])
        round_index = int(kwargs['global_epoch']) + 1
        projected = project_layers(selected_layers, self.dimension, self.args.seed, round_index,
                                   kwargs.get('cancelled', lambda: False))
        if not np.isfinite(projected).all():
            raise ValueError("LayerSift 投影出现非有限值")
        chosen, scores = multi_krum(projected, budget)
        retained = set(chosen.tolist())
        self.last_diagnostics = {
            **metadata, 'mode': 'plaintext', 'implementation': 'layersift.fixed.v1',
            'selector': 'Multi-Krum', 'projection_dimension': self.dimension,
            'byzantine_budget': budget, 'byzantine_ratio': float(self.byzantine_ratio),
            'selected_count': len(chosen), 'participant_count': n, 'round': round_index,
            'projection_seed': int(self.args.seed),
            'clients': [{'selected': i in retained, 'score': float(scores[i]),
                         'weight': 1 / len(chosen) if i in retained else 0.0} for i in range(n)],
        }
        return vectors[chosen].mean(axis=0, dtype=np.float64).astype(vectors.dtype)
