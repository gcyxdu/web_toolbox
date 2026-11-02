# 隐私保护朴素贝叶斯分类项目使用指南

本文档介绍如何配置和运行基于同态加密的隐私保护朴素贝叶斯分类系统。

## 一、目录结构

```
target/
├── ciphertext-naive-bayesian/    # 密文版本（使用同态加密）
│   ├── data/                     # 数据集目录
│   │   ├── MC1.csv              # 医疗中心1的训练数据
│   │   ├── MC2.csv              # 医疗中心2的训练数据
│   │   ├── MC3.csv              # 医疗中心3的训练数据
│   │   └── Users.csv            # 用户查询数据（测试集）
│   └── src/                     # 源代码目录
│       ├── __init__.py
│       └── com/                 # 核心模块
│           ├── __init__.py
│           ├── DataProcessor.py      # 数据处理模块
│           ├── Encrypter.py          # 同态加密器（HEU ZPaillier）
│           ├── MedicalCenters.py     # 医疗中心类
│           ├── EhealthcareProvider.py # 电子医疗提供商类
│           ├── Users.py              # 用户类
│           ├── Query.py              # 查询处理模块
│           └── Prediction.py         # 预测主程序
│
├── plain-naive-bayesian/        # 明文版本（用于对比）
│   ├── data/                    # 数据集目录
│   │   ├── MC1.csv
│   │   ├── MC2.csv
│   │   ├── MC3.csv
│   │   └── Users.csv
│   └── src/                     # 源代码目录
│       ├── __init__.py
│       └── prediction/          # 预测模块
│           ├── __init__.py
│           ├── DataProcessor.py      # 数据处理模块
│           ├── MedicalCenters.py     # 医疗中心类
│           ├── EhealthcareProvider.py # 电子医疗提供商类
│           ├── Users.py              # 用户类
│           └── Prediction.py         # 预测主程序
│
├── process.md                   # 本文件，项目使用指南
└── bak.md                       # 参考文档

tools/                           # 工具目录
├── prepare_dataset.py           # 数据集准备和切分工具
├── xls_to_csv.py               # Excel转CSV工具
├── credit_default.csv          # 转换后的信用卡违约数据集
└── default of credit card clients.xls  # 原始Excel数据集
```

### 文件说明

#### 核心Python文件

**密文版本 (ciphertext-naive-bayesian)**：
- **Prediction.py**: 主程序文件，实现使用HEU ZPaillier同态加密的安全朴素贝叶斯分类
- **Encrypter.py**: 同态加密器，使用SecretFlow-HEU的ZPaillier算法
- **DataProcessor.py**: 数据处理模块，包含特征提取、向量扩展、概率计算等功能
- **MedicalCenters.py**: 医疗中心类，负责本地训练数据的加密处理
- **EhealthcareProvider.py**: 电子医疗提供商类，负责聚合加密统计信息并生成预测模型
- **Users.py**: 用户类，负责生成加密查询请求
- **Query.py**: 查询处理模块，实现隐私保护的查询加密和解密

**明文版本 (plain-naive-bayesian)**：
- **Prediction.py**: 主程序文件，实现明文版本的朴素贝叶斯分类（用于性能对比）
- **DataProcessor.py**: 数据处理模块（不涉及加密）
- **MedicalCenters.py**: 医疗中心类（明文统计）
- **EhealthcareProvider.py**: 电子医疗提供商类（明文聚合）
- **Users.py**: 用户类（明文查询）

#### 数据集文件

- **data/**: 包含训练和测试数据集
  - **MC1.csv, MC2.csv, MC3.csv**: 三个医疗中心的训练数据（已离散化）
  - **Users.csv**: 用户查询数据（测试集）
  - 数据格式：每行23个特征列 + 1个标签列（2=正常，4=违约）

#### 工具脚本

- **prepare_dataset.py**: 将原始金融数据集转换为项目所需格式
  - 支持等宽分箱离散化
  - 自动切分训练集和测试集
  - 支持标签映射（0/1 → 2/4）
- **xls_to_csv.py**: 将Excel文件转换为CSV格式

---

## 二、运行程序前提工作

本项目依赖于 [SecretFlow-HEU](https://www.secretflow.org.cn/docs/heu/latest/)，这是一个基于同态加密的隐私计算框架。HEU（Homomorphic Encryption Unit）提供了多种同态加密算法实现，本项目使用 ZPaillier 算法进行隐私保护计算。

### 2.1 关于 ZPaillier 算法

**ZPaillier** 是 SecretFlow-HEU 中实现的一种同态加密方案，基于 Paillier 加密算法的改进版本。ZPaillier 具有以下特点：

- **加法同态性**：支持对密文进行加法运算，即 `Enc(a) + Enc(b) = Enc(a + b)`，无需解密即可进行密文加法计算
- **标量乘法**：支持密文与标量的乘法运算，即 `k * Enc(a) = Enc(k * a)`
- **安全性**：基于大整数分解难题（RSA 问题），提供较高的安全性保障
- **性能优化**：相比标准 Paillier，ZPaillier 在保持安全性的同时进行了性能优化
- **适用场景**：特别适合需要保护数据隐私的机器学习场景，如联邦学习、安全聚合等

在本项目中，ZPaillier 用于：
- 加密各医疗中心的训练统计信息（NX, NY, NZ, ND, NL）
- 在加密状态下聚合多个医疗中心的数据
- 保护用户查询请求和预测结果的隐私

更多关于 ZPaillier 的技术细节，请参考 [SecretFlow-HEU 算法选择文档](https://www.secretflow.org.cn/zh-CN/docs/heu/v0.6.0b0/getting_started/algo_choice)。

#### 2.1.1 ZPaillier 快速开始示例

以下是一个简单的 ZPaillier 使用示例，展示基本的加密、同态加法和解密操作：

```python
from heu import phe

# 1. 初始化 ZPaillier 加密系统
# 参数：SchemaType.ZPaillier 指定使用 ZPaillier 算法，1024 是密钥长度（位）
kit = phe.setup(phe.SchemaType.ZPaillier, 1024)

# 2. 创建加密器、评估器和解密器
encryptor = kit.encryptor()  # 用于加密数据
evaluator = kit.evaluator()  # 用于同态运算
decryptor = kit.decryptor()  # 用于解密数据

# 3. 加密两个整数
a = 10
b = 20
ciphertext_a = encryptor.encrypt_raw(a)
ciphertext_b = encryptor.encrypt_raw(b)

# 4. 同态加法：在密文状态下计算 a + b
ciphertext_sum = evaluator.add(ciphertext_a, ciphertext_b)

# 5. 解密结果
result = decryptor.decrypt_raw(ciphertext_sum)
print(f"{a} + {b} = {result}")  # 输出: 10 + 20 = 30

# 6. 标量乘法：在密文状态下计算 k * a
k = 5
ciphertext_scaled = evaluator.mul(ciphertext_a, k)
result_scaled = decryptor.decrypt_raw(ciphertext_scaled)
print(f"{k} * {a} = {result_scaled}")  # 输出: 5 * 10 = 50
```

这个示例展示了 ZPaillier 的核心功能：可以在不解密的情况下对密文进行加法和标量乘法运算，这正是本项目所需的核心能力。

### 2.2 系统要求

- **Python**: Python 3.8 或更高版本
- **操作系统**: Linux, macOS, 或 Windows
- **内存**: 建议至少 4GB RAM
- **CPU**: 支持 64 位架构

### 2.3 安装 SecretFlow-HEU

#### 方法一：使用 pip 安装（推荐）

使用 pip 直接安装 SecretFlow-HEU：

```bash
pip install secretflow-heu
```

如果需要安装特定版本：

```bash
pip install secretflow-heu==0.6.0b0
```

#### 方法二：从源码安装

如果需要从源码安装或使用最新开发版本：

```bash
git clone https://github.com/secretflow/heu.git
cd heu
pip install -e .
```

### 2.4 验证 HEU 安装

安装完成后，验证 HEU 是否正确安装：

```bash
python -c "import heu; print('HEU library found')"
```

或者在 Python 中验证 ZPaillier 相关功能：

```python
from heu import phe

# 创建 ZPaillier 密钥对
kit = phe.setup(phe.SchemaType.ZPaillier, 1024)
encryptor = kit.encryptor()
decryptor = kit.decryptor()

# 测试加密和解密
plaintext = 42
ciphertext = encryptor.encrypt_raw(plaintext)
decrypted = decryptor.decrypt_raw(ciphertext)

print(f"Original: {plaintext}, Decrypted: {decrypted}")
assert plaintext == decrypted
print("HEU ZPaillier imported and working successfully")
```

如果上述代码能够正常运行并输出 "HEU ZPaillier imported and working successfully"，说明安装成功。

### 2.5 安装其他依赖

安装项目所需的其他 Python 库：

```bash
pip install pandas numpy
```

### 2.6 准备数据集

#### 2.6.1 下载原始数据集

从 UCI 机器学习仓库下载信用卡违约数据集：
- 数据集名称：Default of Credit Card Clients
- 下载地址：https://archive.ics.uci.edu/ml/datasets/default+of+credit+card+clients

或者使用项目中 `tools/` 目录下的 `default of credit card clients.xls` 文件。

#### 2.6.2 转换和准备数据

1. **将 Excel 转换为 CSV**（如果使用 Excel 文件）：
   ```bash
   cd tools
   python xls_to_csv.py --source "default of credit card clients.xls" --output credit_default.csv
   ```

2. **切分数据集**：
   ```bash
   python prepare_dataset.py --source credit_default.csv --bins 10 --label-mode 24 --users-ratio 0.3 --mc-ratios 0.33,0.33,0.34 --write-to both
   ```

   参数说明：
   - `--source`: 输入CSV文件路径
   - `--bins`: 每个特征的分箱数量（默认10）
   - `--label-mode`: 标签映射模式（24表示0→2, 1→4）
   - `--users-ratio`: 测试集比例（默认0.3）
   - `--mc-ratios`: 三个医疗中心的数据比例（默认0.33,0.33,0.34）
   - `--write-to`: 写入目标（both/ciphertext/plain）

3. **验证数据文件**：
   数据文件会自动生成到 `target/ciphertext-naive-bayesian/data/` 和 `target/plain-naive-bayesian/data/` 目录。

### 2.7 Python 标准库依赖

本项目使用 Python 标准库，通常已随 Python 安装包含：
- `sys` - 系统相关功能
- `os` - 操作系统接口
- `time` - 时间相关功能
- `math` - 数学函数
- `random` - 随机数生成
- `csv` - CSV文件处理

这些库通常不需要额外安装，但如果遇到导入错误，请检查 Python 版本（需要 Python 3.8 或更高版本）。

### 2.8 验证环境准备

在运行主程序之前，可以通过以下步骤验证环境是否准备就绪：

1. **检查 Python 版本**：
   ```bash
   python --version
   ```
   应该显示 Python 3.8 或更高版本。

2. **验证 HEU ZPaillier 导入**：
   ```bash
   python -c "from heu import phe; kit = phe.setup(phe.SchemaType.ZPaillier, 1024); print('HEU ZPaillier imported successfully')"
   ```

3. **检查项目文件**：
   ```bash
   cd target/ciphertext-naive-bayesian
   ls -la src/com/*.py
   ```
   应该能看到所有核心模块文件。

4. **检查数据文件**：
   ```bash
   ls -la data/*.csv
   ```
   应该能看到 MC1.csv, MC2.csv, MC3.csv, Users.csv 四个文件。

---

## 三、运行程序

完成上述前提工作后，可以按照以下步骤运行程序：

### 3.1 运行密文版本（同态加密）

进入密文版本目录并运行主程序：

```bash
cd target/ciphertext-naive-bayesian
python src/com/Prediction.py
```

### 3.2 运行明文版本（对比）

进入明文版本目录并运行主程序：

```bash
cd target/plain-naive-bayesian
python src/prediction/Prediction.py
```

### 3.3 程序输出

程序运行后会输出：
- 加密算法参数信息
- 各医疗中心的本地训练数据（密文/明文）
- 聚合统计信息
- 查询请求和响应信息
- 计算成本（加密时间、聚合时间、查询时间等）
- 实际标签和预测结果
- 准确率统计

### 3.4 程序流程说明

**密文版本执行的主要步骤**：
1. 初始化HEU ZPaillier加密器（生成公钥和私钥）
2. 各医疗中心读取本地训练数据
3. 对训练数据进行特征提取和向量扩展
4. 计算本地统计信息（NX, NY, NZ, ND, NL）
5. 使用同态加密对统计信息进行加密
6. 电子医疗提供商聚合加密统计信息
7. 解密密文并计算朴素贝叶斯概率
8. 生成预测向量（加密形式）
9. 用户生成加密查询请求
10. 执行加密查询并返回加密结果
11. 用户解密查询结果
12. 计算预测准确率

**明文版本执行的主要步骤**：
1. 各医疗中心读取本地训练数据
2. 计算本地统计信息
3. 电子医疗提供商聚合统计信息
4. 计算朴素贝叶斯概率
5. 用户生成查询请求
6. 执行查询并返回结果
7. 计算预测准确率

### 3.5 注意事项

- 确保在运行程序前已完成所有前提工作
- 首次运行可能需要较长时间进行初始化（特别是加密版本）
- 密文版本的运行时间会比明文版本长很多（由于同态加密计算开销）
- 如果遇到内存不足，可以尝试使用较小的数据集
- 数据文件路径是硬编码的，确保数据文件在正确的目录下

### 3.6 性能对比

运行两个版本后，可以对比：
- **计算时间**：明文版本 vs 密文版本
- **准确率**：两个版本的预测准确率应该相同
- **通信开销**：密文版本的通信数据大小

---

## 四、Fork 仓库并提交代码更改

本教程介绍如何 Fork 原始仓库，在本地进行修改，然后通过 Pull Request (PR) 的方式提交代码更改。

### 4.1 准备工作

在开始之前，确保：
- 已安装 Git（检查：`git --version`）
- 已创建 GitHub 账号
- 已访问原始仓库：https://github.com/secretflow/TTSDC

### 4.2 Fork 仓库

1. **访问原始仓库**：
   在浏览器中打开 https://github.com/secretflow/TTSDC

2. **Fork 仓库**：
   - 点击页面右上角的 "Fork" 按钮
   - 选择你的 GitHub 账号作为 Fork 的目标
   - 等待 Fork 完成，你将在你的账号下看到 `TTSDC` 仓库

### 4.3 克隆 Fork 的仓库到本地

1. **获取 Fork 仓库的 URL**：
   在你的 Fork 仓库页面，点击绿色的 "Code" 按钮，复制 HTTPS URL（例如：`https://github.com/yourusername/TTSDC.git`）

2. **克隆仓库**：
   ```bash
   git clone https://github.com/yourusername/TTSDC.git
   cd TTSDC
   ```

3. **添加上游仓库**（原始仓库）：
   ```bash
   git remote add upstream https://github.com/secretflow/TTSDC.git
   ```

4. **验证远程仓库配置**：
   ```bash
   git remote -v
   ```
   应该显示：
   - `origin`：指向你的 Fork 仓库
   - `upstream`：指向原始仓库

### 4.4 创建新分支

在开始修改代码之前，创建一个新的分支：

```bash
git checkout -b your-feature-branch
```

> **建议**：使用描述性的分支名称，例如 `fix-bug-description` 或 `add-new-feature`

### 4.5 修改代码

1. **进行代码修改**：
   使用你喜欢的编辑器修改代码文件

2. **查看更改**：
   ```bash
   git status
   git diff
   ```

### 4.6 提交更改

1. **添加更改的文件**：
   ```bash
   git add <file-name>
   # 或添加所有更改
   git add .
   ```

2. **提交更改**：
   ```bash
   git commit -m "描述你的更改内容"
   ```
   
   > **建议**：提交信息应该清晰描述你做了什么更改，例如：
   > - `fix: 修复数据处理的bug`
   > - `feat: 添加新的加密功能`
   > - `docs: 更新文档说明`

### 4.7 保持分支与上游同步

在推送之前，确保你的分支是最新的：

1. **获取上游仓库的最新更改**：
   ```bash
   git fetch upstream
   ```

2. **合并上游的 main 分支**（如果需要）：
   ```bash
   git checkout main
   git merge upstream/main
   git checkout your-feature-branch
   git merge main
   ```

### 4.8 推送到你的 Fork 仓库

```bash
git push origin your-feature-branch
```

> **注意**：首次推送可能需要输入 GitHub 用户名和密码（或访问令牌）。
> 
> 如果使用 HTTPS 方式，GitHub 已不再支持密码认证，需要使用 Personal Access Token (PAT)。
> 创建 PAT：GitHub Settings -> Developer settings -> Personal access tokens -> Generate new token

### 4.9 创建 Pull Request

1. **访问你的 Fork 仓库**：
   在浏览器中打开 `https://github.com/yourusername/TTSDC`

2. **创建 Pull Request**：
   - 你会看到一条提示信息，显示你刚刚推送的分支
   - 点击 "Compare & pull request" 按钮
   - 或者点击 "Pull requests" 标签页，然后点击 "New pull request"

3. **填写 PR 信息**：
   - **标题**：简洁描述你的更改
   - **描述**：详细说明你做了什么更改、为什么做这些更改、以及如何测试
   - 检查更改的文件列表是否正确

4. **提交 PR**：
   - 点击 "Create pull request" 按钮
   - 等待仓库维护者审查你的 PR

### 4.10 后续操作

1. **响应审查意见**：
   - 如果维护者要求修改，在你的分支上进行修改
   - 提交新的更改：
     ```bash
     git add .
     git commit -m "根据审查意见进行修改"
     git push origin your-feature-branch
     ```
   - PR 会自动更新，无需创建新的 PR

2. **同步上游更改**：
   如果上游仓库有新的提交，保持你的分支同步：
   ```bash
   git fetch upstream
   git checkout your-feature-branch
   git merge upstream/main
   git push origin your-feature-branch
   ```

3. **等待 PR 合并**：
   - 维护者审查通过后，会将你的 PR 合并到主仓库
   - 合并后，你可以删除本地和远程的分支：
     ```bash
     git checkout main
     git branch -d your-feature-branch
     git push origin --delete your-feature-branch
     ```

4. **更新本地主分支**：
   ```bash
   git checkout main
   git pull upstream main
   ```
