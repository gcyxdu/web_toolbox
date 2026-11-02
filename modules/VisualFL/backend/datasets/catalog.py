"""Offline dataset catalog and honest sample inspection."""
from functools import lru_cache

import numpy as np
from sklearn.datasets import load_digits, load_iris, load_wine
from sklearn.model_selection import train_test_split
from backend.datasets.mnist import load_mnist
from backend.datasets.cifar import load_cifar

DATASETS = {
    **{name:{'id':name,'name':f'{name.replace("CIFAR","CIFAR-")} · 彩色图像','samples':60000,
             'features':3072,'classes':classes,'kind':'image','shape':[32,32],'channels':3,'pixel_max':255,
             'backdoor':True,'train_samples':50000,'test_samples':10000,
             'source':'CIFAR / Alex Krizhevsky, Vinod Nair, Geoffrey Hinton（官方划分 / UofT CIFAR 镜像，无损本地数据包）'}
       for name,classes in [('CIFAR10',10),('CIFAR100',100)]},
    "MNIST": {"id": "MNIST", "name": "MNIST · 手写数字", "samples": 70000, "features": 784, "classes": 10,
              "kind": "image", "shape": [28, 28], "pixel_max": 255, "backdoor": True,
              "source": "MNIST / Yann LeCun, Corinna Cortes, Christopher J.C. Burges（内置原始数据，官方 60000 / 10000 划分）"},
    "Digits": {"id": "Digits", "name": "Digits · 手写数字", "samples": 1797, "features": 64, "classes": 10,
               "kind": "image", "shape": [8, 8], "backdoor": True, "source": "sklearn.datasets.load_digits"},
    "Iris": {"id": "Iris", "name": "Iris · 鸢尾花", "samples": 150, "features": 4, "classes": 3,
             "kind": "table", "shape": [4], "backdoor": False, "source": "sklearn.datasets.load_iris"},
    "Wine": {"id": "Wine", "name": "Wine · 葡萄酒", "samples": 178, "features": 13, "classes": 3,
             "kind": "table", "shape": [13], "backdoor": False, "source": "sklearn.datasets.load_wine"},
}


@lru_cache(maxsize=6)
def load_dataset(name: str):
    if name in {'CIFAR10','CIFAR100'}:return load_cifar(name)
    return {"MNIST": load_mnist, "Digits": load_digits, "Iris": load_iris, "Wine": load_wine}[name]()


def split_indices(name: str, labels: np.ndarray, seed: int, test_size: float):
    if name in {'CIFAR10','CIFAR100'}:
        return np.arange(50000),np.arange(50000,60000)
    if name == 'MNIST':
        return np.arange(60000), np.arange(60000, 70000)
    return train_test_split(np.arange(len(labels)), test_size=test_size, random_state=seed, stratify=labels)


def inspect_dataset(name: str, seed: int, test_size: float) -> dict:
    raw = load_dataset(name)
    labels = np.asarray(raw.target, dtype=np.int64)
    train, test = split_indices(name, labels, seed, test_size)
    rng = np.random.default_rng(seed)
    chosen = [int(rng.choice(np.flatnonzero(labels == label))) for label in np.linspace(0, DATASETS[name]["classes"]-1, min(12,DATASETS[name]["classes"]),dtype=int)]
    remaining = np.setdiff1d(np.arange(len(labels)), chosen)
    chosen += rng.choice(remaining, min(12 - len(chosen), len(remaining)), replace=False).tolist()
    return {**DATASETS[name], "channels": DATASETS[name].get("channels",1), "class_names": [str(item) for item in raw.target_names],
            "feature_names": [str(item) for item in raw.feature_names],
            "train_samples": len(train), "test_samples": len(test),
            "train_histogram": np.bincount(labels[train]).tolist(),
            "test_histogram": np.bincount(labels[test]).tolist(),
            "examples": [{"index": i, "label": int(labels[i]), "split": "train" if i in train else "test",
                          "values": np.asarray(raw.data[i], dtype=float).tolist()} for i in chosen]}
