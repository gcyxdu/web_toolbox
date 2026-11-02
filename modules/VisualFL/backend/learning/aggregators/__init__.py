"""Explicit aggregation registry."""
from ..utils import Register
aggregator_registry = Register()
from .mean import Mean
from .median import Median
from .trimmedmean import TrimmedMean
from .normclipping import NormClipping
from .krum import Krum
from .layersift import LayerSift

def get_aggregator(name: str):
    return aggregator_registry[name]
