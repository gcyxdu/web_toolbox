# VisualFL

本地联邦学习实验台。浏览器负责配置与可视化，Python 服务管理实验，独立训练进程执行模型训练、攻击、聚合和评估。

## 技术组成

| 部分    | 使用的技术                          | 在项目中的作用                                         |
| ----- | ------------------------------ | ----------------------------------------------- |
| 前端    | React 19、TypeScript、Vite 8     | 页面、交互、类型检查和前端构建                                 |
| 界面组件  | Radix UI Themes、Phosphor Icons | 表单、弹窗、按钮和图标                                     |
| 拓扑    | React Flow（`@xyflow/react`）    | 客户端与服务器节点、连线、拖动和缩放                              |
| 图表    | Apache ECharts 6               | 准确率、测试损失、ASR 与实验对比曲线                            |
| 后端    | Python 3.12、FastAPI、Uvicorn    | HTTP API、网页文件服务和任务管理                            |
| 模型训练  | PyTorch 2.6.0                  | 模型、本地更新、评估与 CUDA / CPU 计算                       |
| 数据处理  | NumPy、scikit-learn             | 数据预处理、客户端划分和内置小数据集                              |
| 数据库   | SQLite，Python 内置 `sqlite3` 驱动  | 保存实验配置、状态、指标与事件，文件位于 `data/experiments.sqlite3` |
| 环境与依赖 | Conda、pip、npm                  | 独立 Python 环境、Python 包和前端依赖管理                    |

数据库无需单独安装。生产模式由一个 Python 服务同时提供网页和 API；训练在独立的 Python 子进程中执行。前端通过 HTTP 增量轮询读取训练事件。图片数据集保存为本地文件，实验记录保存到 SQLite。

## 1. 安装基础软件

以下步骤适用于 Windows 10/11 x64。已经安装对应软件的步骤可以跳过。

### 1.1 安装 Conda

Conda 用于创建独立的 Python 环境。已有 Anaconda 或 Miniconda 时直接使用；没有时：

1. 从 [Miniconda 官方下载目录](https://repo.anaconda.com/miniconda/) 下载 `Miniconda3-latest-Windows-x86_64.exe`。
2. 运行安装程序，选择当前用户安装（Just Me），记住安装目录，完成安装。
3. 从开始菜单打开 **Anaconda Prompt / Miniconda Prompt**，检查 Conda，并初始化 PowerShell：

```powershell
conda --version
conda init powershell
```

4. 关闭终端，重新打开 PowerShell，执行 `conda --version`。能显示版本号即可。

如果开始菜单提供 **Anaconda PowerShell Prompt**，也可以直接使用该终端。项目会单独创建 Python 3.12 环境，无需另装 Python，也无需修改 Conda 基础环境的 Python 版本。

### 1.2 安装 Node.js 和 npm

Node.js 用于构建网页，npm 用于安装前端依赖。**安装 Node.js 时会一并安装 npm，无需单独下载 npm。**

1. 打开 [Node.js 官方下载页](https://nodejs.org/en/download)。
2. 选择 **24.x、Windows、x64、Installer（.msi）**。项目按 Node.js 24 使用，不必跟随网页默认版本升级。
3. 运行安装程序，保留 **npm package manager** 和 **Add to PATH**，完成安装。
4. 关闭并重新打开 PowerShell，检查：

```powershell
node --version
npm.cmd --version
```

`node` 应显示 `v24.x.x`，npm 应显示版本号。使用 `npm.cmd` 可以避免 PowerShell 将命令解析为 `npm.ps1`。安装方式也可参阅 [npm 官方说明](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/)。

## 2. 准备项目

将项目完整复制或解压到一个目录。以下以 `W:\联邦学习\VisualFL` 为例，其他位置替换为实际路径。

在 PowerShell 中进入项目根目录：

```powershell
cd "VisualFL"
Test-Path .\visualfl.ps1
Test-Path .\frontend\package-lock.json
Test-Path .\backend\learning\client.py
```

三条检查都应返回 `True`。保留 `backend/assets` 中的数据集文件和来源清单。

## 3. 安装项目依赖

先查看设备检测与安装方案（这一步不下载）：

```powershell
.\visualfl.ps1 plan
```

然后安装：

```powershell
.\visualfl.ps1 setup
```

安装脚本依次完成：

1. 根据 `environment.yml` 创建独立的 `visualfl` Conda 环境，固定 Python 3.12。
2. 安装 `requirements.txt` 中固定版本的 Python 包，并检查依赖兼容性。
3. 根据 `frontend/package-lock.json` 执行 npm 锁定安装。

默认镜像为清华 Conda、阿里云 PyPI / PyTorch wheels、npmmirror，不修改全局镜像配置。

PyTorch 固定为 2.6.0。脚本根据 NVIDIA 显卡和驱动选择 cu118 或 CPU 包；运行时通过 CUDA 运算检测选择训练设备。无需另装完整 CUDA Toolkit。

需要强制 CPU 时执行：

```powershell
.\visualfl.ps1 setup -TorchVariant cpu
```

已有前端依赖、只需安装 Python 包时执行：

```powershell
.\visualfl.ps1 setup -SkipFrontend
```

## 4. 启动项目

在项目根目录运行：

```powershell
.\visualfl.ps1
```

脚本检查 TypeScript、构建前端，然后启动 Python 服务。终端保持打开，在浏览器访问 **http://127.0.0.1:8000** 

在页面中新建实验、配置参数并启动。训练设备可在侧栏“本机配置”查看。

已有前端构建且没有修改前端代码时，可以跳过构建：

```powershell
.\visualfl.ps1 -NoBuild
```

8000 端口被占用时：

```powershell
.\visualfl.ps1 -Port 8001
```

访问地址改为 `http://127.0.0.1:8001`。

停止前先等待或取消训练，再回到服务终端按 **Ctrl+C**。

选择“方法库 → LayerSift → 配置实验”即可使用固定层默认配置。支持 LeNet-5、ResNet-18、ResNet-20；MNIST 默认投影到 128 维，CIFAR 默认 512 维，使用 Multi-Krum 筛选后对完整更新等权聚合。恶意比例上界默认 0.2，与真实客户端角色独立设置。当前实现为明文在线算法，不包含离线选层或双服务器隐私协议。

## 5. 项目结构

```text
VisualFL/
├── README.md                   安装、启动、技术组成与项目结构
├── visualfl.ps1                安装 / 启动 / 设备检测的统一入口
├── environment.yml             Conda 环境名、Python 版本与镜像
├── requirements.txt            Python 固定版本依赖
├── backend/                    Python 服务与训练代码
│   ├── app.py                  FastAPI 入口、API 路由、前端静态文件服务
│   ├── config/                 实验配置与方法目录
│   │   ├── schema.py          配置定义、参数校验与客户端覆盖解析
│   │   ├── methods.py         攻击和聚合方法的参数、说明与默认值
│   │   └── models.py          模型名称与适用数据集
│   ├── datasets/               数据加载与客户端划分
│   │   ├── catalog.py         数据集目录、统一加载与样本预览
│   │   ├── partition.py       预处理、训练测试切分与客户端划分
│   │   ├── mnist.py           MNIST 文件加载和校验
│   │   └── cifar.py           CIFAR 文件加载和校验
│   ├── experiments/            实验记录与任务管理
│   │   ├── store.py           SQLite 存储、事件序号与状态更新
│   │   ├── records.py         实验记录软删除与恢复
│   │   ├── jobs.py            训练子进程启动、取消与退出管理
│   │   └── worker.py          单次实验的进程入口
│   ├── system/                 硬件与运行环境
│   │   ├── device.py          CUDA 运算探测与设备选择
│   │   └── info.py            CPU、内存、GPU 与软件版本信息
│   ├── engines/                训练流程与工作台事件的适配层
│   │   ├── base.py             引擎接口
│   │   ├── flpoison_engine.py  主 PyTorch 引擎，串起数据、方法与评估
│   │   └── numpy_engine.py     轻量线性模型对照与历史兼容
│   ├── learning/               模型训练与联邦学习方法实现
│   │   ├── client.py           客户端本地训练与上传对象
│   │   ├── server.py           收集更新、聚合与全局模型更新
│   │   ├── worker.py           批次训练、评估和优化器操作
│   │   ├── models/            线性分类器、LeNet、ResNet 和参数转换
│   │   ├── algorithms/        FedAvg、FedSGD、FedOpt
│   │   ├── attacks/           Gaussian、SignFlipping、BadNets 与触发器
│   │   ├── aggregators/       LayerSift、Mean、Median、TrimmedMean、NormClipping、Krum
│   │   │   └── layersift.py   固定层提取、两阶段投影、Multi-Krum 筛选和完整更新聚合
│   │   └── NOTICE.md / LICENSE / sources.json  代码来源与许可证
│   └── assets/                 离线数据及其来源、校验信息
│       ├── mnist/              MNIST 压缩 IDX 文件
│       └── cifar/              CIFAR-10 / CIFAR-100 NPZ 与类别元数据
├── frontend/                   React 前端
│   ├── index.html              网页入口与标签页标题
│   ├── public/favicon.svg      标签页与侧栏品牌图标
│   ├── package.json            npm 依赖与开发 / 构建命令
│   ├── package-lock.json       npm 依赖锁定文件
│   ├── vite.config.ts          开发服务、API 代理与构建配置
│   ├── tsconfig.json           TypeScript 检查配置
│   ├── src/
│   │   ├── main.tsx            挂载应用和主题
│   │   ├── App.tsx             侧栏、页面切换与全局交互
│   │   ├── api.ts              HTTP 请求与错误处理
│   │   ├── types.ts            配置、实验、事件与指标的数据类型
│   │   ├── config.ts           默认配置、客户端覆盖与事件投影
│   │   ├── hooks/              服务连接、草稿、训练事件与回放状态
│   │   ├── pages/              实验台、实验记录、对比分析、方法库
│   │   ├── components/
│   │   │   ├── topology/      客户端 / 服务端节点、连线、布局和缩放
│   │   │   ├── inspector/     训练、数据、攻防和单节点配置面板
│   │   │   ├── forms/         通用参数输入控件
│   │   │   ├── metrics/       指标曲线、配色与事件日志
│   │   │   ├── datasets/      样本与类别分布弹窗
│   │   │   ├── layout/        导航侧栏与本机配置弹窗
│   │   │   ├── workbench/     实验操作工具栏与回放控制
│   │   │   └── icons/         导航及良性 / 恶意客户端图标
│   │   ├── styles.css          样式加载入口
│   │   ├── styles/             各区域及响应式样式
│   │   └── assets/             图标资源与许可证
│   ├── node_modules/           npm 安装生成，可重新安装
│   └── dist/                   构建生成，供 Python 服务提供网页
└── data/                       本机实验数据，按运行生成
    ├── experiments.sqlite3     实验配置、状态、指标和事件
    └── runs/<run_id>/worker.log  训练进程日志
```


`app.py` 接收请求，`experiments` 管理记录和训练进程，`engines` 调用 `learning` 执行训练；`datasets` 提供数据，`system` 选择计算设备，前端读取事件并更新拓扑和曲线。
