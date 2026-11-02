# Source notice

Selected components are derived from FLPoison by its original authors:
https://github.com/vio1etus/FLPoison

Revision: `2e9a9d41e9cbe991b88505324fada5e8ac47fad3`. Original license: GPL-2.0, included in `LICENSE`.
Modified for VisualFL on 2026-10-29. File origins and original SHA-256 hashes are in `sources.json`.

Changes: package-local imports; explicit registries; keep only selected methods; remove external dataset/image/timing dependencies; replace pixel normalization with equivalent PyTorch operations; fix the FedAvg-to-delta branch before norm clipping. Unchanged math, defaults and behavior are otherwise retained, including the upstream FedOpt definition and Krum score convention.

The platform owns offline data, scheduling, structured events and task storage. These are distinct from the copied method implementations. No external checkout or `FLPOISON_ROOT` is used at runtime.

Classic image model extension (2026-10-29): independently implemented LeNet-style and ResNet networks from published architectures; ResNet18/50 use small-image 3x3 stems (ResNet50 stride in the 3x3 bottleneck convolution). Tiny 8x8 inputs are resized to32x32. Floating BatchNorm buffers join model vectors; integer counters are excluded, and running variance is bounded below when loading attacked vectors. Algorithm returns reflect loaded model state. Sequential clients share one network object with separate SGD optimizers (momentum0), and evaluation/ASR use cancellable batches.
