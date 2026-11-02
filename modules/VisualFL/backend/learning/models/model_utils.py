# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/fl/models/model_utils.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.

from copy import deepcopy
import numpy as np
import torch

def vec2model(vector, model, plus=False, ignorebn=False):
    """
    in-place modification of model's parameters
    Convert a 1d-numpy array back into a model
    """
    curr_idx = 0
    model_state_dict = model.state_dict()
    device = next(model.parameters()).device
    dtype = next(model.parameters()).dtype

    for key, value in model_state_dict.items():
        if not value.is_floating_point():
            continue
        if ignorebn:
            if any(substring in key for substring in ['running_mean', 'running_var', 'num_batches_tracked']):
                continue
        numel = value.numel()
        param_tensor = torch.from_numpy(
            vector[curr_idx:curr_idx + numel].reshape(value.shape)).to(device=device, dtype=dtype)

        if plus:
            value.copy_(value + param_tensor)  # in-place addition
        else:
            value.copy_(param_tensor)  # in-place assignment
        if key.endswith("running_var"):
            value.clamp_(min=1e-5)
        curr_idx += numel


def model2vec(model):
    """
    convert the model's state dict to a 1d numpy array
    """
    return state2vec(model.state_dict())


def add_vec2model(vector, model_template):
    """
    Add the state dict vector-form (pseudo) gradient to the model's parameters and return a new model
    """
    tmp_model = deepcopy(model_template)
    vec2model(vector, tmp_model, plus=True)
    return tmp_model


def state2vec(model_state_dict, ignorebn=False, numpy_flg=False):
    """
    Convert a state dict to a concatenated 1D numpy array.
    """
    # Collect all the tensors first
    if numpy_flg:
        arrays = [
            value.flatten()
            for name, value in model_state_dict.items()
            if np.issubdtype(value.dtype,np.floating) and (True if not ignorebn else all(substring not in name for substring in ['running_mean', 'running_var', 'num_batches_tracked']))
        ]
    else:
        arrays = [
            i.detach().cpu().numpy().flatten()
            for name, i in model_state_dict.items()
            if i.is_floating_point() and (True if not ignorebn else all(substring not in name for substring in ['running_mean', 'running_var', 'num_batches_tracked']))
        ]

    # Concatenate the list of arrays at once
    return np.concatenate(arrays)
