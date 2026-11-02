"""Load verified CIFAR binary archives directly, without pickle or extraction."""
import hashlib
import json
import tarfile
from pathlib import Path
import numpy as np
from sklearn.utils import Bunch

SPECS={
 'CIFAR10':('cifar-10-binary.tar.gz','c32a1d4ab5d03f1284b67883e8d87530','cifar-10-batches-bin',3073),
 'CIFAR100':('cifar-100-binary.tar.gz','03b5dce01913d631647c71ecec9e9cb8','cifar-100-binary',3074),
}

def load_cifar(name):
    root=Path(__file__).resolve().parents[1]/'assets'/'cifar'
    mirror=root/'mirror-manifest.json'
    if mirror.exists():
        entry=next(item for item in json.loads(mirror.read_text()) if item['id']==name)
        path=root/entry['file']
        with path.open('rb') as f:
            if hashlib.file_digest(f,'sha256').hexdigest()!=entry['sha256']:raise ValueError(f'{name} 数据校验失败')
        with np.load(path,allow_pickle=False) as packed:
            x=packed['data'];y=packed['target'];names=packed['class_names'].tolist()
        if x.shape!=(60000,3072) or y.shape!=(60000,) or len(names)!=(10 if name=='CIFAR10' else 100):
            raise ValueError('CIFAR 数据格式不正确')
        return Bunch(data=x,target=y,target_names=names,feature_names=[])

    filename,md5,folder,row_size=SPECS[name]
    path=Path(__file__).resolve().parents[1]/'assets'/'cifar'/filename
    if not path.exists():raise ValueError(f'{name} 数据文件缺失，请从项目备份恢复 backend/assets/cifar 中的数据包和来源清单')
    with path.open('rb') as f:
        if hashlib.file_digest(f,'md5').hexdigest()!=md5:raise ValueError(f'{name} 数据校验失败')
    train_names=[f'data_batch_{i}.bin' for i in range(1,6)] if name=='CIFAR10' else ['train.bin']
    test_name='test_batch.bin' if name=='CIFAR10' else 'test.bin'
    images=[];labels=[]
    with tarfile.open(path,'r:gz') as archive:
        for member in train_names+[test_name]:
            content=archive.extractfile(f'{folder}/{member}').read()
            rows=np.frombuffer(content,dtype=np.uint8).reshape(-1,row_size)
            images.append(rows[:,-3072:])
            labels.append(rows[:,row_size-3073])
        metadata='batches.meta.txt' if name=='CIFAR10' else 'fine_label_names.txt'
        names=archive.extractfile(f'{folder}/{metadata}').read().decode().splitlines()
    x=np.concatenate(images);y=np.concatenate(labels)
    if x.shape!=(60000,3072) or len(names)!=(10 if name=='CIFAR10' else 100):raise ValueError('CIFAR 格式不正确')
    return Bunch(data=x,target=y,target_names=names,feature_names=[])
