# 隐私保护相似性查询项目使用指南

本文档介绍如何配置和运行适配SecretFlow框架的高效隐私保护相似性查询系统

# 1. 目录结构

```
ehealthcare_query_scene/
├── EEGEyeState.txt     	# EEG数据集
├── aes.py  				# 实现查询过程中验证环节的AES加解密
├── data.py					# 实现数据集的读取
├── kdpb_class.py			# 定义了构造k-d-PB树过程中使用到的相关类
├── kdpb_tree.py			# 完成k-d-PB树的构造过程
├── kdpb_tree_cipher.py		# 加密k-d-PB树并完成查询过程中的过滤和验证
├── main_eeg.py				# 使用真实的EEG数据集进行方案的性能测试
├── main_synthetic.py		# 使用随机数模拟的数据集进行方案的性能测试
├── naive_query.py			# 
├── naive_query_paillier.py # 使用Paillier完成的常规查询方案用作对比方案
├── paillier.py				# 封装Paillier算法接口的类实现加密和查询过程中的同态计算
├── requirements.txt		# 运行项目所需的依赖
├── util_cipher.py			# 完成密文场景下的相关协议计算
└── util_plain.py			# 完成明文场景下的类型转化和距离计算
```

## 核心文件说明

### paillier.py

代码基于SecretFlow框架下的[HEU加法同态加密库](https://www.secretflow.org.cn/zh-CN/docs/heu/main/)进行构建，相较于SecretFlow中的HEU单元，HEU加法同态加密库作为其底层实现显得更为自由，能够更好地解决HEU单元不具备编程能力执行函数以及复杂结构体在逻辑单元间传递加密的问题。HEU加法同态加密库定义了Plaintext（明文）以及Ciphertext（密文）三种可操作对象并实现了在三种对象间进行转换的加解密和编码解码接口，此外还实现了Paillier等高效的同态加密算法的实现，用于完成高效地加法同态计算。因此，本方案的实现使用HEU库中提供的Paillier加解密以及同态计算接口完成相应的操作。

![](https://raw.githubusercontent.com/AsyncKurisu/TyporaPicture/master/images/20251125173701.png)

HEU加法同态库通过构造encryptor、evaluator以及decryptor对象完成同态加解密操作，基本使用如下所示：
```python
from heu import phe

kit = phe.setup(phe.SchemaType.ZPaillier, 2048)
encryptor = kit.encryptor()
evaluator = kit.evaluator()
decryptor = kit.decryptor()

c1 = encryptor.encrypt_raw(3)
c2 = encryptor.encrypt_raw(5)
evaluator.add_inplace(c1, c2)  # c1 += c2

decryptor.decrypt_raw(c1)  # output 8
```

paillier.py对HEU加法同态库中的算法接口进行进一步封装，将encryptor、evaluator以及decryptor对象包裹在类的内部，只向外暴露实现方案所必需的算法接口，同时对于方案中涉及密文下乘法的计算，通过生成随机数和多次的同态加密以及加法实现密文乘法逻辑。

### main_eeg.py

main_eeg.py使用真实的EEG数据集进行性能测试，该数据集包含了14980个没有属性值的14维的真实医学脑电图记录，为进行性能评估，为每条记录附加4个维度，在这个合成的数据集上进行性能测试。实现测试的文件除了main_eeg.py以外还有main_synthetic.py，区别在于main_syhthetic.py使用随机数生成的模拟数据集进行性能测试。两部分代码共测试了不同参数对于数据库加密、token生成以及相似性查询性能的影响，为简便起见，将main_synthetic.py的main函数添加到main_eeg.py的main函数中，从而能够仅运行main_eeg.py文件就简便地完成所有的测试内容。

## 2. 环境配置

在运行项目之前首先完成项目的环境配置工作，其中HEU加法同态加密库要求为

+ Python：3.9-3.11
+ OS：Centos 7 / Ubuntu 18.04+ / macOS 12.0+ (macOS Monterey+)

HEU加法同态加密库的安装具体来说分为通过pip安装和通过源码安装两种方式

### 通过Pip安装

HEU的安装包被发布到了PyPi，可在终端通过pip工具安装HEU。

```bash
pip install sf-heu
```

### 从源码安装

如果需要使用最新测试版本，可以从[源码链接](https://github.com/secretflow/heu)下载并进行编译安装。具体的依赖工具包括：

+ Bazelisk
+ nasm (x86架构)
+ GCC >= 11

具体安装步骤在终端输入以下命令完成编译和安装工作。

```bash
git clone --recursive https://github.com/secretflow/heu.git
cd heu
sh build_wheel_entrypoint.sh
```

安装完成后，建议执行以下命令检查 HEU 是否工作正常，上述命令，如果没有任何输出，则说明安装成功。

```bash
python -c "from heu import phe"
```

安装完成HEU后，安装运行整个项目所需的依赖，项目使用的所有依赖写入到requirements.txt文件中，可执行如下命令一次性安装全部依赖，以确保项目能够正常运行。

```bash
pip install -r requirements.txt
```

## 3. 项目启动

完成相关环境的配置后，执行下面的命令进入项目目录并运行测试文件main_eeg.py。

```bash
cd DataSharing
python main_eeg.py
```

运行main_eeg.py文件后将依次执行main_eeg.py和main_synthetic.py中定义的使用不同参数进行的对数据库加密、token生成以及相似性查询的性能测试，并与Paillier使用常规查询方案的实现进行性能对比，在终端上得到类似如图所示时间以毫秒为单位进行表示的结果。以真实EEG数据集下不同的参数*n*和*d*下相似性查询的性能评估为例，运行main_eeg.py得到前三行代表使用k-d-PB树进行相似性的方案所需的时间，后三行代表使用Paillier的常规方案相似性查询所需的时间。

![](https://raw.githubusercontent.com/AsyncKurisu/TyporaPicture/master/images/20251125204354.png)