# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/global_utils.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

def actor(category, *attributes):
    """class decorator for categorizing attackers, data poisoners (backdoor, others), and model poisoners (omniscient, non_omniscient, others)
    """
    def decorator(cls):
        # key is the actor, value is the attributes of the actor
        categories = {"benign": ['always', 'temporary'],
                      "attacker": ['data_poisoning', 'model_poisoning', "non_omniscient", "omniscient"]}

        if not set(attributes).issubset(set(categories[category])):
            raise ValueError(
                "Invalid sub-category. Please change or add the sub-category.")
        cls._category = category
        cls._attributes = attributes
        # change __init__ method to realize it in objects
        original_init = cls.__init__

        def new_init(self, *args, **kwargs):
            # Check if the object has already been decorated to avoid redundant decoration due to inheritance.
            # When attacker init, one class, two different object (attacker, super init)
            if not hasattr(self, "_decorated"):
                self.category = cls._category
                self.attributes = cls._attributes
                # Mark self object as decorated to prevent re-decoration on inherited classes
                self._decorated = True
            original_init(self, *args, **kwargs)

        cls.__init__ = new_init
        return cls
    return decorator


class Register(dict):
    """Register class is a dict class with 2 functions: 1. serve as the registry 2. register the callable object, function, to this registry
    """

    def __init__(self, *args, **kwargs):
        # init the dict class, so that it can be used as a normal dict
        super().__init__(*args, **kwargs)

    def __call__(self, target):
        def register_item(name, func):
            self[name] = func
            return func

        # if target is a string, return a function to receive the callable object. @register('name')
        if isinstance(target, str):
            ret_func = (lambda x: register_item(target, x))
        # if target is a callable object, then register it, and return it, @register
        elif callable(target):
            ret_func = register_item(target.__name__, target)
        return ret_func


def avg_value(x):
    return sum(x) / len(x)


def frac_or_int_to_int(frac_or_int, total_num):
    return int(frac_or_int) if frac_or_int >= 1 else int(frac_or_int * total_num)
