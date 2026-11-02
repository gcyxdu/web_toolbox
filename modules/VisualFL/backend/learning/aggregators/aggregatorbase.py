# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/aggregators/aggregatorbase.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

class AggregatorBase():
    """Base class of aggregators.
    """

    def __init__(self, args, **kwargs):
        self.args = args

    def update_and_set_attr(self):
        """
        update the aggregator parameters if given, otherwise use the default aggregator parameters
        """
        new_defense_params = self.args.defense_params
        self.defense_params = self.default_defense_params
        # update default attack params with new defense_params
        if new_defense_params:
            self.defense_params.update(new_defense_params)
        # set the attack parameters as the class attributes
        for key, value in self.defense_params.items():
            setattr(self, key, value)

    def aggregate(self, updates, **kwargs):
        """Aggregate the inputs/clients' updates, and return the aggregated result.
        updates: 2d numpy array with the [rows, columns] as [clients, updates].
        """
        raise NotImplementedError
