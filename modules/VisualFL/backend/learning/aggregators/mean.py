# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/aggregators/mean.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

from backend.learning.aggregators.aggregatorbase import AggregatorBase
import numpy as np
from backend.learning.aggregators import aggregator_registry


@aggregator_registry
class Mean(AggregatorBase):
    def __init__(self, args, **kwargs):
        super().__init__(args)

    def aggregate(self, updates, **kwargs):
        return np.mean(updates, axis=0)
