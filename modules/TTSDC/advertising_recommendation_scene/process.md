# 云场景中隐私保护的高效加权范围集采样系统

本文档介绍如何配置和运行适配SecretFlow框架的云场景中隐私保护的高效加权范围集采样系统。

## 1. 目录结构

```
advertising_recommendation_scene/
├── BuildingBlocks				# 加权范围采样系统的基础组件
│   ├── __init__.py
│   ├── alias.py				# Alias采样算法实现，包括了明文和密文下的两种形式
│   ├── alias_class.py			# 明文和密文下Alias数据结构定义
│   ├── ase.py					# 三方加法秘密共享结构体及相关算法的实现
│   ├── data_processing.py		# 完成数据预处理任务，读取和写入文件
│   ├── private_algorithms.py	# 定义了保护加权范围采样隐私的相关算法
│   ├── three_pss.py			# 传统的三方秘密共享方案算法
│   └── util.py					# 完成明文场景下的类型转化和距离计算
├── EPWS						# 实现隐私保护的高效加权范围采样系统的核心算法
│   ├── __init__.py
│   ├── bst_cipher.py			# 定义了密文状态下的二叉搜索树及其搜索方法
│   ├── bst_plain.py			# 定义了明文状态下的二叉搜索树及其构造方法
│   └── key.py					# 定义了密钥类用于服务器间的安全交互
├── Test						# 实现系统的对比及测试
│   ├── __init__.py
│   ├── comparison.py			# 实现当前方案与其他加密方式计算性能对比
│   └── evaluation.py			# 实现当前方案不同环节在不同参数下的性能评估
├── cleanData.txt				# 数据文件，包含清洗后的数据集
└── result.txt					# 运行评估代码得到的性能评估结果
```

### 核心文件说明

+ **ase.py**：实现了三方秘密共享，为整个方案提供基础的数据加密、运算与随机性支持。与传统的三方秘密共享方案不同，ase.py中的秘密共享每方只持有一份的秘密份额，三方持有的份额在不泄露原值的前提下完成加、减、乘等运算。
+ **bst_plain.py**：实现明文下二叉搜索树的构建。云服务场景下数据持有者将数据发送到服务器之前将其构建为二叉搜索树的形式，便于实现后续在密文场景上高效且隐私保护的加权范围集采样。
+ **bst_cipher.py**：作为方案的核心执行体实现对明文二叉搜索树的加密、密文二叉树的搜索以及最终采样，实现范围过滤、加权抽样、结果验证的全流程。
+ **evaluation.py**：实现了本项目方案在不同环节的性能评估，评估了数据外包、查询请求加密、查询处理三个环节在不同参数下的所需时间以及数据大小或通信量。
+ **comparison.py**：实现核心方案与其他加密算法的计算性能对比，在加解密以及计算等环节将本项目方案与传统三方秘密共享和Paillier同态加密进行性能对比。

## 2. 环境配置

在运行项目之前首先完成环境配置工作，主要完成SecretFlow框架的安装，在SecretFlow官网给出的环境要求为

+ Python：3.10
+ pip: >= 19.3
+ OS: CentOS 7, Ubuntu 20.04
+ CPU/Memory: 推荐最低配置为8核16G

当前SecretFlow框架主要提供了四种安装方法：

### 方式1：从pypi：

SecretFlow框架的安装包已发布到PyPi，Python版本若不为3.10，可以用conda构建一个虚拟环境，输入如下指令安装SecretFlow：

```bash
conda create -n sf python=3.10
conda activate sf
pip install -U secretflow
```

### 方式2：通过docker

通过SecretFlow发布的docker image安装SecretFlow：

```bash
docker run -it secretflow/secretflow-anolis8:latest
```

### 方式3：通过源码

通过源码安装可以从Github上下载SecretFlow的源码并创建Python虚拟环境，安装构建出来的wheel文件完成SecretFlow的安装

```bash
git clone https://github.com/secretflow/secretflow.git
cd secretflow

conda create -n secretflow python=3.10
conda activate secretflow
python -m build --wheel
pip install dist/*.whl
```

### 方式4：通过WSL

SecretFlow框架当前并不支持Windows的安装，在Windows系统使用SecretFlow需要在WSL(Windows Subsystem for Linux)上进行安装。

首先在Windows上遵循[中文指南](https://learn.microsoft.com/zh-cn/windows/wsl/install)或[英文指南](https://learn.microsoft.com/en-us/windows/wsl/install)安装WSL2，其中GNU/Linux推荐使用Ubuntu，并在WSL2中安装anaconda用来构造虚拟环境，之后创建虚拟环境并激活，使用pip安装SecretFlow即可正常使用。

```bash
conda create -n sf python=3.10
conda activate sf
pip install -U secretflow
```

上述安装过程完成后，在Python中输入以下命令检查是否能够正常导入SecretFlow，如果没有报错则说明成功安装SecretFlow框架，能够正常完成后续的代码运行工作。

```python
import secretflow as sf
```

## 3. 项目启动

完成相关环境的配置后，执行下面的命令进入项目目录并运行测试文件evaluation.py。

```bash
cd SetSampling
python -m Test.evaluation
```

运行evaluation.py文件后，测试将注意评估数据外包、查询请求加密以及查询处理场景下不同参数对性能的影响，性能的评估使用执行所需的时间以及执行过程中所需的数据大小或通信量作为依据，以不同数据集大小*n*下数据外包的性能评估为例，得到如图所示的评估结果。

![](https://raw.githubusercontent.com/AsyncKurisu/TyporaPicture/master/images/20251125213309.png)

comparison.py在计算性能的对比中，选择与传统秘密共享和Paillier同态加密进行加解密和计算性能对比，其中将秘密共享的秘密分割和恢复对应Paillier的加解密，此外还测试了加法、标量乘和密文乘法上的表现。运行下面的命令，最终得到如图所示的结果。

```bash
cd SetSampling
python -m Test.comparison
```

<img src="https://raw.githubusercontent.com/AsyncKurisu/TyporaPicture/master/images/20251125213639.png" style="zoom:67%;" />