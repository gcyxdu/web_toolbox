"""Explicit algorithm registry; add trusted local methods here."""
from ..utils import Register
algorithm_registry = Register()
from .fedavg import FedAvg
from .fedsgd import FedSGD
from .fedopt import FedOpt

def get_algorithm_handler(name: str):
    return algorithm_registry[name]
