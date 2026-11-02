"""Explicit model compatibility, without importing training dependencies."""
IMAGE_DATASETS=['MNIST','Digits','CIFAR10','CIFAR100']

# Fixed presets from the manuscript's critical-layer table, mapped to classic.py.
# Prefixes identify entire Conv/Linear modules (weight and bias, when present).
LAYERSIFT_LAYERS = {
    'LeNet5': [('C1', 'features.0'), ('FC3', 'classifier.5')],
    'ResNet20': [('L2.0C1', 'stages.3.body.0'), ('FC', 'classifier'),
                 ('C1', 'stem.0'), ('L2.0C2', 'stages.3.body.3')],
    'ResNet18': [('C1', 'stem.0'), ('FC', 'classifier'),
                 ('L3.0C1', 'stages.4.body.0'), ('L2.0C1', 'stages.2.body.0')],
}
LAYERSIFT_DIMENSIONS = {'MNIST': 128, 'Digits': 128, 'CIFAR10': 512, 'CIFAR100': 512}
MODELS=[
 {'id':'lr','name':'线性分类器','datasets':IMAGE_DATASETS+['Iris','Wine'],'description':'单层线性分类器；保留原有实验兼容性。'},
 {'id':'LeNet5','name':'LeNet-5','datasets':IMAGE_DATASETS,'description':'6/16 卷积通道，120/84 全连接；MNIST 补边到 32×32。'},
 {'id':'ResNet20','name':'ResNet-20','datasets':IMAGE_DATASETS,'description':'CIFAR 版：3×3 卷积，16/32/64 通道，每阶段 3 个残差块。'},
 {'id':'ResNet18','name':'ResNet-18','datasets':IMAGE_DATASETS,'description':'2/2/2/2 基本残差块；3×3 小图像输入层，无初始最大池化；8×8 输入缩放至 32×32。'},
 {'id':'ResNet50','name':'ResNet-50','datasets':IMAGE_DATASETS,'description':'3/4/6/3 瓶颈残差块；3×3 小图像输入层，无初始最大池化；8×8 输入缩放至 32×32。'},
]
