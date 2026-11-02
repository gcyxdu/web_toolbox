"""Engine registration boundary. Only trusted local entries are loadable."""
from __future__ import annotations

from backend.engines.numpy_engine import NumpyEngine
from backend.engines.flpoison_engine import FlpoisonEngine

ENGINES = {"numpy": NumpyEngine, "flpoison": FlpoisonEngine}


def get_engine(name: str):
    try:
        return ENGINES[name]()
    except KeyError as exc:
        raise ValueError(f"未知训练后端: {name}") from exc
