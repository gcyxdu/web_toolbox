# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/attackers/pbases/pbase.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.



class PBase():
    def update_and_set_attr(self):
        """
        update the attack parameters if given, otherwise use the default attack parameters
        """
        new_attack_params = self.args.attack_params
        self.attack_params = self.default_attack_params
        # update default attack params with new attack_params
        if new_attack_params:
            self.attack_params.update(
                new_attack_params)
        # set the attack parameters as the class attributes
        for key, value in self.attack_params.items():
            setattr(self, key, value)
