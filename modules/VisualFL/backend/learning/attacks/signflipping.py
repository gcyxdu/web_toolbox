# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/attackers/signflipping.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

from backend.learning.client import Client
from backend.learning.utils import actor
from backend.learning.attacks.pbases.mpbase import MPBase
from backend.learning.attacks import attacker_registry


@attacker_registry
@actor('attacker', 'model_poisoning', 'non_omniscient')
class SignFlipping(MPBase, Client):
    """
    [Asynchronous Byzantine machine learning (the case of SGD)](http://proceedings.mlr.press/v80/damaskinos18a/damaskinos18a.pdf) - ICML '18
    reverse the sign of the update
    """

    def __init__(self, args, worker_id, train_dataset, test_dataset):
        Client.__init__(self, args, worker_id, train_dataset, test_dataset)

    def non_omniscient(self):
        return - self.update
