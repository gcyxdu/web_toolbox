"""Select a CUDA device only after a real kernel succeeds, otherwise use CPU."""
from functools import lru_cache


@lru_cache(maxsize=1)
def training_device() -> str:
    import torch

    if torch.cuda.is_available():
        for index in range(torch.cuda.device_count()):
            device = f"cuda:{index}"
            try:
                probe = torch.ones((2, 2), device=device)
                probe.matmul(probe).sum().item()
                return device
            except (RuntimeError, AssertionError):
                continue
    return "cpu"
