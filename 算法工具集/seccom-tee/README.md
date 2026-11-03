# seccom-tee

> 面向 Intel SGX 与 TrustZone/iTrustee 风格可信执行环境的多模块安全计算实验仓库  
> A multi-module secure computing repository for Intel SGX and TrustZone/iTrustee-style Trusted Execution Environments.

---

**项目来源：西安电子科技大学**

---

## 项目简介 / Overview

`seccom-tee` 是一个围绕可信执行环境（TEE）展开的研究型代码仓库，聚焦于安全计算、密码学实验以及平台迁移验证。当前仓库主要覆盖以下方向：

`seccom-tee` is a research-oriented repository for Trusted Execution Environment (TEE) experimentation, with a focus on secure computing, cryptographic prototypes, and platform migration work. The repository currently covers the following areas:

- 多方安全计算（MPC）
- CKKS / TCKKS 风格密文计算
- 神经网络激活函数的安全执行
- TEE 辅助的密码协议实验
- GmSSL 与 TLCP 相关移植、裁剪和优化工作

- secure multi-party computation (MPC)
- CKKS / TCKKS-style encrypted computation
- secure execution of neural network activation functions
- TEE-assisted cryptographic protocol experiments
- GmSSL- and TLCP-related adaptation, pruning, and optimization work

本仓库并非单一应用，而是由多个相对独立的子项目组成。大多数模块拥有各自的构建脚本、运行前提、输入数据和部署流程。

This repository is not a single monolithic application. Instead, it is organized as a collection of relatively independent subprojects, each with its own build scripts, runtime assumptions, input data, and deployment flow.

## 项目定位 / Project Positioning

`seccom-tee` 当前更接近研究验证型或工程实验型代码库，而非产品化项目。适用场景包括：

`seccom-tee` is currently closer to a research or engineering validation repository than a productized software project. It is best suited for:

- TEE 相关算法实验与原型验证
- SGX 与 TrustZone 之间的平台迁移与适配
- 安全计算方案的性能测试与对比
- 面向具体模块的复现、重构与增量改造

- TEE-related algorithm experiments and prototyping
- migration and adaptation work between SGX and TrustZone
- performance evaluation and comparison of secure computing schemes
- reproduction, refactoring, and incremental improvement of individual modules

如果你计划在新的环境中使用本仓库，通常需要先完成本地路径适配、SDK 配置以及模块级构建验证。

If you plan to use this repository in a new environment, expect to perform local path adaptation, SDK configuration, and module-level build verification first.

## 仓库结构 / Repository Layout

```text
seccom-tee/
|-- SGX/
|   |-- activation_function/
|   |-- cryptographic_protocol/
|   |-- MPC/
|   |-- MPC_Add/
|   |-- NNT/
|   |-- RMT_B/
|   |-- RMT_M/
|   |-- RMT_V/
|   `-- TCKKS_Optimization/
`-- Trustzone/
    |-- CA/
    |-- TA/
    `-- script/
```

### 顶层目录说明 / Top-Level Directories

| 路径 / Path | 说明 / Description |
| --- | --- |
| `SGX/` | 基于 Intel SGX 的实现与实验代码 / Intel SGX-based implementations and experiment code |
| `Trustzone/CA/` | 运行于普通世界的 Client Application（CA）/ Client Applications (CA) running in the normal world |
| `Trustzone/TA/` | 运行于安全世界的 Trusted Application（TA）/ Trusted Applications (TA) running in the secure world |
| `Trustzone/script/` | 测试数据生成与辅助脚本 / Helper scripts for test data generation |

## 模块分类 / Module Families

仓库中的模块大致可以归纳为以下几类：

The modules in this repository can be broadly grouped into the following categories:

| 类别 / Category | 代表目录 / Representative Directories | 说明 / Description |
| --- | --- | --- |
| 激活函数 / Activation Functions | `SGX/activation_function/`、`Trustzone/CA/activation_function/`、`Trustzone/TA/activate_function/`、`Trustzone/TA/activate_function_contrast/` | 在 TEE 场景下实现 ReLU、Sigmoid、Softmax 等激活函数的安全执行或对比实验 / Secure execution or comparison experiments for activation functions such as ReLU, Sigmoid, and Softmax in TEE-based workflows |
| 密码协议 / Cryptographic Protocols | `SGX/cryptographic_protocol/`、`Trustzone/CA/cryptographic_protocol/`、`Trustzone/TA/cryptographic_protocol/` | 面向 TEE 的密码协议流程验证与实验实现 / TEE-oriented protocol validation and experimental implementations |
| 多方安全计算 / MPC | `SGX/MPC/`、`SGX/MPC_Add/`、`Trustzone/CA/MPC/`、`Trustzone/CA/MPC_Add/`、`Trustzone/TA/MPC/`、`Trustzone/TA/MPC_add_tkks/` | 多方安全计算实验，以及偏向安全加法的实现分支 / Multi-party computation experiments, including secure-addition-oriented branches |
| CKKS / TCKKS | `SGX/TCKKS_Optimization/`、`Trustzone/CA/TCKKS/`、`Trustzone/TA/TCKKS/`、`Trustzone/TA/TCKKS_Optimization/` | 面向 CKKS / TCKKS 风格密文计算的实验与优化版本 / Experimental and optimized implementations for CKKS / TCKKS-style encrypted computation |
| GmSSL / TLCP | `Trustzone/CA/gmssl/`、`Trustzone/TA/gmssl/`、`Trustzone/TA/gmssl_optimized/`、`Trustzone/TA/gmssl_tlcp/`、`Trustzone/TA/gmssl_tlcp_optimized/` | GmSSL 与 TLCP 相关算法在 TEE 环境中的移植、裁剪与优化 / Porting, trimming, and optimization of GmSSL- and TLCP-related components in TEE environments |
| 任务型实验 / Task-Specific Experiments | `SGX/NNT/`、`SGX/RMT_B/`、`SGX/RMT_M/`、`SGX/RMT_V/`、`Trustzone/CA/NNT/`、`Trustzone/CA/RMT_B/`、`Trustzone/CA/RMT_M/`、`Trustzone/CA/RMT_V/`、`Trustzone/TA/NNT/`、`Trustzone/TA/RMT_B/`、`Trustzone/TA/RMT_M/`、`Trustzone/TA/RMT_V/` | 面向特定任务、数据集或性能评测场景的实验模块 / Experimental modules for specific tasks, datasets, or performance evaluation scenarios |

## 平台组织方式 / Platform Organization

### SGX 模块 / SGX Modules

大多数 SGX 模块都具有较强的独立性，通常包含：

Most SGX modules are relatively self-contained and typically include:

- 模块级 `Makefile`
- `sgx_u.mk`、`sgx_t.mk` 等 SGX 构建脚本
- enclave 侧源码与相关生成产物

- a module-level `Makefile`
- SGX build scripts such as `sgx_u.mk` and `sgx_t.mk`
- enclave-side source code and related generated artifacts

典型构建输出包括：

Typical build outputs include:

- `app`
- `enclave.so` / `TestEnclave.so`
- `enclave.signed.so` / `TestEnclave.signed.so`

### TrustZone 模块 / TrustZone Modules

TrustZone 部分采用常见的普通世界 / 安全世界拆分方式：

The TrustZone portion follows the common split between the normal world and the secure world:

- `CA/`：运行于普通世界的客户端程序
- `TA/`：运行于安全世界的可信应用

- `CA/`: client-side applications running in the normal world
- `TA/`: trusted applications running in the secure world

在许多 TrustZone 模块中：

In many TrustZone modules:

- `CA/<module>/cloud/` 是客户端侧 CMake 工程目录
- `TA/<module>/cloud/` 是 TA 的构建、签名与部署目录
- `manifest.txt`、`config.mk`、`config_cloud.ini` 等文件用于控制打包与部署行为

- `CA/<module>/cloud/` is the client-side CMake project directory
- `TA/<module>/cloud/` is the TA build, signing, and deployment directory
- files such as `manifest.txt`, `config.mk`, and `config_cloud.ini` are used to control packaging and deployment behavior

典型构建输出包括：

Typical build outputs include:

- `libcombine.so`
- 签名后的 `.sec` 部署包 / signed `.sec` deployment packages

## 环境依赖 / Environment Requirements

仓库没有统一的顶层初始化脚本。根据目标平台与模块不同，通常需要具备以下环境中的部分或全部：

The repository does not provide a unified top-level bootstrap script. Depending on the target platform and selected module, you will typically need some or all of the following:

- `gcc` / `g++`
- `make`
- `cmake`
- `python3`
- Intel SGX SDK 及相关运行时 / Intel SGX SDK and related runtime components
- Intel SGX SSL 或兼容的密码库依赖 / Intel SGX SSL or compatible cryptographic dependencies
- Huawei iTrustee SDK，或兼容 GlobalPlatform 风格的 TEE 构建环境 / Huawei iTrustee SDK, or a compatible GlobalPlatform-style TEE build environment

### 环境说明 / Environment Notes

- 大多数模块默认面向 Linux 环境进行构建与运行。  
  Most modules are designed to be built and run in Linux environments.
- 部分源码与构建脚本包含环境相关的绝对路径。  
  Some source files and build scripts contain environment-specific absolute paths.
- 某些模块默认依赖预生成输入文件、特定 SDK 安装路径或诸如 `/data/` 的部署目录。  
  Some modules assume pre-generated input files, specific SDK installation paths, or deployment directories such as `/data/`.

## 构建方式 / Build Instructions

本仓库按模块分别构建。

This repository is built on a per-module basis.

### 构建 SGX 模块 / Build an SGX Module

```bash
cd SGX/<module>
make
```

部分模块会在主 `Makefile` 中进一步调用 enclave 侧与非可信侧的子构建脚本。

Some modules delegate additional enclave-side and untrusted-side steps through the top-level `Makefile`.

### 构建 TrustZone CA 模块 / Build a TrustZone CA Module

```bash
cd Trustzone/CA/<module>/cloud
mkdir -p build
cd build
cmake ..
make
```

### 构建 TrustZone TA 模块 / Build a TrustZone TA Module

```bash
cd Trustzone/TA/<module>/cloud
mkdir -p build
cd build
cmake ..
make
```

部分 TA 模块还提供 `install.sh`，用于重建并将生成的 `.sec` 文件复制到部署目录。

Some TA modules also provide an `install.sh` script to rebuild the target and copy the generated `.sec` package into a deployment directory.

## 测试数据生成 / Test Data Generation

`Trustzone/script/` 目录提供了一组用于生成测试输入的辅助脚本，例如：

The `Trustzone/script/` directory contains helper scripts for generating test inputs, including:

- `create_tckks_data.py`
- `create_mpc_data.py`
- `create_mpc_add_data.py`
- `create_crypto_protocol_data.py`
- `create_active_function_data.py`

这些脚本既可用于准备实验输入，也有助于理解相关模块所需的数据格式。

These scripts are useful both for preparing experimental inputs and for understanding the expected data format of the corresponding modules.

## 建议使用流程 / Recommended Workflow

如果你是第一次接触本仓库，建议按照以下顺序开始：

If you are new to this repository, the following workflow is recommended:

1. 确定目标平台：`SGX` 或 `Trustzone`。  
   Choose the target platform: `SGX` or `Trustzone`.
2. 选择一个具体模块，例如 `TCKKS_Optimization`、`MPC_Add` 或激活函数相关模块。  
   Select a concrete module, such as `TCKKS_Optimization`, `MPC_Add`, or an activation-function-related module.
3. 阅读该模块目录下的 `Makefile`、`CMakeLists.txt`、局部说明文档与入口源码。  
   Review the local `Makefile`, `CMakeLists.txt`, module-specific documentation, and entry-point source files.
4. 根据本机环境调整绝对路径、SDK 路径与输入数据路径。  
   Adapt absolute paths, SDK locations, and input-data paths to your local environment.
5. 先完成一个模块的端到端构建与验证，再扩展到其他模块。  
   Build and validate one module end-to-end before expanding to additional modules.

## 模块文档 / Module Documentation

部分子目录已经包含模块级说明文档，例如：

Some subdirectories already contain module-level documentation, for example:

- `SGX/MPC_Add/README.md`
- `SGX/MPC/修改说明.md`
- `Trustzone/CA/TCKKS/readme.md`
- `Trustzone/CA/MPC/readme.md`
- `Trustzone/CA/MPC_Add/readme.md`
- `Trustzone/CA/gmssl/readme.md`

这些文档的结构和语言风格尚未完全统一，因此本 README 主要承担仓库级导航说明的角色。

The structure and language of these documents are not yet fully unified, so this top-level README is intended primarily as repository-wide guidance.

## 许可证与第三方依赖 / License and Third-Party Dependencies

本仓库包含对外部 SDK、工具链和密码库的依赖。在公开发布或二次分发之前，建议重点核对：

This repository depends on external SDKs, toolchains, and cryptographic libraries. Before public release or redistribution, it is recommended to review:

- 第三方依赖的许可证状态 / the license status of third-party dependencies
- SDK 的再分发限制 / SDK redistribution constraints
- 仓库整体的开源许可策略 / the repository-wide open-source licensing strategy

当前仓库尚未包含统一的 `LICENSE` 文件。如果该项目后续计划作为开源仓库发布，建议补充明确的许可证文件，并同步检查相关第三方组件的许可边界。

The repository does not currently include a top-level `LICENSE` file. If the project is intended for open-source distribution, adding a clear license file and reviewing the licensing boundaries of related third-party components is strongly recommended.
