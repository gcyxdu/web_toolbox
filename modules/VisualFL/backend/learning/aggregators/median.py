# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/aggregators/median.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

from backend.learning.aggregators.aggregatorbase import AggregatorBase
import numpy as np

from backend.learning.aggregators import aggregator_registry


@aggregator_registry
class Median(AggregatorBase):
    """
    [Byzantine-robust distributed learning: Towards optimal statistical rates](https://proceedings.mlr.press/v80/yin18a.html) - ICML'18
    Coordinated Median computes the median of the updates coordinate-wisely.
    """

    def __init__(self, args, **kwargs):
        super().__init__(args)

    def aggregate(self, updates, **kwargs):
        return np.median(updates, axis=0)
