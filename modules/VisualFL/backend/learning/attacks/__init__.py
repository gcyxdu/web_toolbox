"""Explicit attack registry."""
from ..utils import Register
attacker_registry = Register()
from .gaussian import Gaussian
from .signflipping import SignFlipping
from .badnets import BadNets

def get_attacker_handler(name: str):
    return attacker_registry[name]
