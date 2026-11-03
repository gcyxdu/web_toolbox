# PythonVersion 项目使用指南

本文档介绍如何配置和运行 Python 版本的隐私保护决策树推理系统。

## 一、目录结构

```
PythonVersion/
├── __pycache__/              # Python缓存目录
├── bfs_dectree.py            # 决策树类实现文件
├── examples.py               # SEAL加密示例辅助函数
├── main.py                   # 主程序文件，实现安全决策树推理
├── test_converted_modules.py # 模块转换测试脚本
├── process.md                # 本文件，目录结构说明
└── UCI_dectrees/            # UCI数据集目录
    ├── boston                # 波士顿数据集决策树文件
    ├── boston.png            # 波士顿数据集决策树可视化图片
    ├── breast                # 乳腺癌数据集决策树文件
    ├── breast.png            # 乳腺癌数据集决策树可视化图片
    ├── decision_tree         # 决策树相关文件
    ├── diabetes              # 糖尿病数据集决策树文件
    ├── digits                # 手写数字数据集决策树文件
    ├── digits.png            # 手写数字数据集决策树可视化图片
    ├── iris                  # 鸢尾花数据集决策树文件
    ├── iris.png              # 鸢尾花数据集决策树可视化图片
    ├── linnerud              # Linnerud数据集决策树文件
    ├── test.py               # 测试脚本，用于可视化决策树
    ├── wine                  # 葡萄酒数据集决策树文件
    └── wine.png              # 葡萄酒数据集决策树可视化图片
```

### 文件说明

#### 核心Python文件

- **main.py**: 主程序文件，实现了使用SEAL-Python进行安全决策树推理的完整流程
- **bfs_dectree.py**: 决策树类实现，包含从scikit-learn生成的决策树读取和处理功能
- **examples.py**: SEAL加密示例的辅助函数，提供打印、格式化等工具函数
- **test_converted_modules.py**: 用于测试转换后的模块功能是否正常

#### 数据集文件

- **UCI_dectrees/**: 包含多个UCI机器学习数据集的决策树模型文件
  - 支持的数据集：wine（葡萄酒）、iris（鸢尾花）、breast（乳腺癌）、digits（手写数字）、diabetes（糖尿病）、linnerud、boston（波士顿房价）
  - 每个数据集通常包含决策树文件（文本格式）和可视化图片（PNG格式）
  - **test.py**: 用于读取决策树文件并使用Graphviz和matplotlib进行可视化

#### 缓存目录

- **__pycache__/**: Python自动生成的字节码缓存目录，包含编译后的.pyc文件

---

## 二、运行程序前提工作

本项目依赖于 [Microsoft SEAL-Python](https://github.com/Huelse/SEAL-Python)，这是一个 Microsoft SEAL 同态加密库的 Python 绑定。以下是在 Linux 系统下的安装步骤。

### 2.1 系统要求

- **编译器**：Clang++ (>= 10.0) 或 GNU G++ (>= 9.4)
- **构建工具**：CMake (>= 3.16)
- **Python**：Python 3.x

### 2.2 安装系统依赖

首先安装必要的系统工具和开发库：

```bash
sudo apt-get install git build-essential cmake python3 python3-dev python3-pip
```

### 2.3 克隆 SEAL-Python 仓库

获取 SEAL-Python 源代码：

```bash
git clone https://github.com/Huelse/SEAL-Python.git
cd SEAL-Python
```

### 2.4 安装 Python 依赖

安装所需的 Python 包：

```bash
pip3 install numpy pybind11
```

### 2.5 初始化子模块

初始化 SEAL 和 pybind11 子模块：

```bash
git submodule update --init --recursive
```

> **注意**：如果需要在开发模式下获取最新版本的子模块，可以使用：
> ```bash
> git submodule update --remote
> ```

### 2.6 构建 SEAL 库

进入 SEAL 目录并构建库（禁用 msgsl、zlib 和 zstandard 压缩以简化构建）：

```bash
cd SEAL
cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build build
cd ..
```

### 2.7 编译 Python 绑定

运行 setup.py 编译 Python 扩展模块，生成的动态库将位于当前目录：

```bash
python3 setup.py build_ext -i
```

### 2.8 验证安装

运行示例程序测试安装是否成功：

```bash
cp seal.*.so examples
cd examples
python3 4_bgv_basics.py
```

如果示例程序能够正常运行，说明 SEAL-Python 安装成功。

### 2.9 验证 SEAL-Python 安装

安装完成后，需要验证 SEAL-Python 是否正确安装并可以正常使用：

1. **检查是否已安装 SEAL 库**：
   ```bash
   # 检查 pip list 中是否包含 seal 相关库
   pip3 list | grep -i seal
   ```
   
   或者直接在 Python 中检查：
   ```bash
   python3 -c "import seal; print('SEAL library found')" 2>/dev/null && echo "SEAL is installed" || echo "SEAL is not installed"
   ```

2. **如果 SEAL 库已存在，验证导入**：
   如果上述命令显示 SEAL 库已安装，执行验证导入：
   ```bash
   python3 -c "from seal import *; print('SEAL-Python imported successfully')"
   ```
   
   如果成功输出 "SEAL-Python imported successfully"，说明安装正确，可以继续下一步。

3. **如果 SEAL 库不存在，需要重新安装**：

### 2.10 检查数据文件

确保 `UCI_dectrees/` 目录中存在所需的决策树文件：

```bash
cd PythonVersion
ls -la UCI_dectrees/
```

应该能看到以下文件：
- `wine` - 葡萄酒数据集决策树
- `iris` - 鸢尾花数据集决策树
- `breast` - 乳腺癌数据集决策树
- `digits` - 手写数字数据集决策树
- `diabetes` - 糖尿病数据集决策树
- `linnerud` - Linnerud 数据集决策树
- `boston` - 波士顿房价数据集决策树

如果缺少任何数据集，则该数据集标号我们不能指定程序去运行

### 2.11 Python 标准库依赖

本项目使用 Python 标准库，通常已随 Python 安装包含：
- `sys` - 系统相关功能
- `os` - 操作系统接口
- `time` - 时间相关功能
- `math` - 数学函数
- `random` - 随机数生成
- `typing` - 类型提示支持
- `collections` - 集合数据类型
- `re` - 正则表达式

这些库通常不需要额外安装，但如果遇到导入错误，请检查 Python 版本（需要 Python 3.6 或更高版本）。

### 2.12 验证环境准备

在运行主程序之前，可以通过以下步骤验证环境是否准备就绪：

1. **检查 Python 版本**：
   ```bash
   python3 --version
   ```
   应该显示 Python 3.6 或更高版本。

2. **验证 SEAL-Python 导入**：
   ```bash
   python3 -c "from seal import *; print('SEAL imported successfully')"
   ```

3. **检查项目文件**：
   ```bash
   cd PythonVersion
   ls -la *.py
   ```
   应该能看到 `main.py`、`bfs_dectree.py`、`examples.py` 等文件。

4. **检查数据文件**：
   ```bash
   ls -la UCI_dectrees/* | grep -v ".png"
   ```
   应该能看到所有决策树文件。

---

## 三、运行程序

完成上述前提工作后，可以按照以下步骤运行程序：

### 3.1 运行主程序

进入项目目录并运行主程序：

```bash
cd PythonVersion
python3 main.py <dataset_index>
```

其中 `<dataset_index>` 是数据集索引（0-6），例如：

```bash
# 运行葡萄酒数据集
python3 main.py 0

# 运行鸢尾花数据集
python3 main.py 1

# 运行乳腺癌数据集
python3 main.py 2
```

### 3.2 程序输出

程序运行后会输出：
- 数据集名称
- 使用的方案（交互式或非交互式）
- 决策树处理信息
- 加密推理结果
- 最终预测结果

### 3.3 程序流程说明

程序执行的主要步骤：
1. 读取决策树模型文件
2. 初始化客户端和服务端的加密系统
3. 客户端加密输入特征向量
4. 执行安全特征选择
5. 执行安全比较操作
6. 计算路径权重和
7. 客户端解密并输出最终结果

### 3.4 注意事项

- 确保在运行程序前已完成所有前提工作
- 首次运行可能需要较长时间进行初始化
- 如果遇到内存不足，可以尝试使用较小的数据集（如 iris）
- 程序使用固定随机种子（1234）以确保结果可复现

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
   > - `fix: 修复决策树推理的bug`
   > - `feat: 添加新的数据集支持`
   > - `docs: 更新使用文档`

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

