# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/fl/algorithms/fedsgd.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

from backend.learning.models.model_utils import model2vec, vec2model
from backend.learning.models.model_utils import model2vec
from .algorithmbase import AlgorithmBase
from backend.learning.algorithms import algorithm_registry


@algorithm_registry
class FedSGD(AlgorithmBase):
    def __init__(self, args, model, optimizer=None):
        super().__init__(args, model, optimizer)

    # for client
    def init_local_epochs(self):
        return 1

    def get_local_update(self, **kwargs):
        global_weights_vec = kwargs['global_weights_vec']
        update = model2vec(self.model) - global_weights_vec
        return update

    # for server
    def update(self, aggregated_update, **kwargs):
        global_weights_vec = kwargs['global_weights_vec']
        global_w = global_weights_vec + aggregated_update
        vec2model(global_w, self.model)
        return model2vec(self.model)
