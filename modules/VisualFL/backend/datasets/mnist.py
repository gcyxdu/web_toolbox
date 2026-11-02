"""Bundled, checksum-verified original MNIST IDX files (no network at runtime)."""
import gzip
import hashlib
import json
import struct
from pathlib import Path

import numpy as np
from sklearn.utils import Bunch


def load_mnist():
    root = Path(__file__).resolve().parents[1] / 'assets' / 'mnist'
    manifest = json.loads((root / 'sources.json').read_text())
    arrays = {}
    for entry in manifest['files']:
        blob = (root / entry['file']).read_bytes()
        if hashlib.md5(blob).hexdigest() != entry['md5']:
            raise ValueError(f"MNIST 数据校验失败：{entry['file']}")
        decoded = gzip.decompress(blob)
        magic, count = struct.unpack('>II', decoded[:8])
        if magic == 2051:
            rows, cols = struct.unpack('>II', decoded[8:16])
            if (rows, cols) != (28, 28) or len(decoded) != 16 + count * 784:
                raise ValueError('MNIST 图像格式不正确')
            array = np.frombuffer(decoded, dtype=np.uint8, offset=16).reshape(count, 784)
        elif magic == 2049 and len(decoded) == 8 + count:
            array = np.frombuffer(decoded, dtype=np.uint8, offset=8)
        else:
            raise ValueError('MNIST IDX 格式不正确')
        arrays[entry['file']] = array
    x = np.concatenate([arrays['train-images-idx3-ubyte.gz'], arrays['t10k-images-idx3-ubyte.gz']])
    y = np.concatenate([arrays['train-labels-idx1-ubyte.gz'], arrays['t10k-labels-idx1-ubyte.gz']])
    if x.shape != (70000, 784) or y.shape != (70000,) or y.max() > 9:
        raise ValueError('MNIST 数据数量或标签不正确')
    return Bunch(data=x, target=y, target_names=np.arange(10),
                 feature_names=[f'pixel_{i}' for i in range(784)])
