# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/attackers/pbases/dpbase.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Keep poisoning loaders/schedules; omit unrelated external dataset evaluation.

import torch
from .pbase import PBase
from ...utils import frac_or_int_to_int

class DPBase(PBase):
    """
    this is a base class for all data poisoning attacker classes
    """

    def define_synthesizer(self):
        """
        define the trigger, self.synthesizer, and other data poisoning-related variables in here.
        """
        raise NotImplementedError

    def get_dataloader(self, dataset, train_flag, poison_epochs=None):
        """
        data poisoning attacker may choose 
        1. train or test
        2. poisoning or not poisoning
            3. if do poisoning, poisoning specific epochs or all epochs 

        args: poisoning_epoch is used to specify the epoch for poisoning, default is None
        """
        dataloader = torch.utils.data.DataLoader(
            dataset, batch_size=self.args.batch_size, shuffle=train_flag, num_workers=self.args.num_workers, pin_memory=True)

        # compatability with the non-poisoining calls
        poison_epochs = False if poison_epochs is None else poison_epochs
        if isinstance(poison_epochs, bool):
            # poisoning all epoch
            def poisoning_epoch(_): return poison_epochs
        elif isinstance(poison_epochs, list):
            # poisoning specific epochs in poison_indicator list
            def poisoning_epoch(x): return x in poison_epochs

        while True:  # train mode for infinite loop with training epoch as the outer
            for images, targets in dataloader:
                if poisoning_epoch(self.global_epoch):
                    yield self.synthesizer.backdoor_batch(images, targets, train=train_flag, worker_id=self.worker_id)
                else:
                    # print(f"global_epoch {self.global_epoch}, no poisoning")
                    yield images, targets

            if not train_flag:
                # test mode for test dataset
                break

    def generate_poison_epochs(self, attack_strategy, epochs, single_epoch, poison_frequency, attack_start_epoch=None):
        """
        generate the poisoning epochs based on the strategy, ['single-shot', 'fixed-frequency','continuous']
        """
        if attack_strategy == "continuous":
            return list(range(attack_start_epoch, epochs)) if attack_start_epoch is not None else True
        if attack_strategy == "single-shot":
            assert isinstance(
                single_epoch, int), "single_epoch should be an integer"
            return [single_epoch]
        elif attack_strategy == "fixed-frequency":
            poison_frequency = frac_or_int_to_int(poison_frequency, epochs)
            return list(range(0, epochs, poison_frequency))
        else:
            raise ValueError("attack strategy not supported")

