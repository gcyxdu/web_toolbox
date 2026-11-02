# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/fl/models/regression.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Namespaced imports; retained selected components only.


import torch.nn as nn
from backend.learning.models import model_registry


@model_registry
class lr(nn.Module):
    """logistic regression model"""
    def __init__(self, input_dim=32*32, num_classes=10):
        super().__init__()
        self.input_dim, self.num_classes = input_dim, num_classes
        self.linear = nn.Linear(input_dim, num_classes)
        nn.init.normal_(self.linear.weight, mean=0.0, std=0.02)

    def forward(self, xb):
        # flatten the image to vector for linear
        xb = xb.reshape(-1, self.input_dim)
        outputs = self.linear(xb)
        return outputs
