from __future__ import annotations

from typing import Callable, Protocol

from backend.config.schema import ExperimentConfig

Emit = Callable[[str, dict], None]
Cancelled = Callable[[], bool]


class Engine(Protocol):
    def run(self, config: ExperimentConfig, emit: Emit, cancelled: Cancelled) -> None: ...
