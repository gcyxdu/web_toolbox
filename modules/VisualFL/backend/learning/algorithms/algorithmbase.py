# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/fl/algorithms/algorithmbase.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

from abc import ABC, abstractmethod


class AlgorithmBase(ABC):
    def __init__(self, args, model, optimizer):
        self.args = args
        self.model = model  # same address with the model in the client or server
        # self.optimizer = optimizer

    @abstractmethod
    def init_local_epochs(self):
        pass

    @abstractmethod
    def get_local_update(self, *nouse):
        pass

    @abstractmethod
    def update(self, aggregated_update, *nouse):
        pass
