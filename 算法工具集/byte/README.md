# Secure Transformer Inference Toolkits

本目录包含四个面向隐私保护 Transformer 推理的协议工具集，覆盖从基础安全协议、固定区间混合近似、宽范围增强近似，到 Transformer 非线性算子的完整测试链路。

项目采用二方秘密分享和 TEE 辅助的安全计算结构。输入、输出和中间结果默认以加性秘密分享形式存在；TEE 主要用于随机掩码、辅助补偿项和近似计算所需的安全辅助材料；网络通信中传输的是 masked message，而不是明文输入。

## 目录结构

```text
byte/
├── 1.basic_protocols/
├── 2.base_hybrid_approx/
├── 3.plus_hybrid_approx/
└── 4.nonlinear_functions/
```

四个目录按协议层级组织：

1. `1.basic_protocols`：基础安全协议。
2. `2.base_hybrid_approx`：固定区间混合近似函数。
3. `3.plus_hybrid_approx`：宽范围输入增强混合近似函数。
4. `4.nonlinear_functions`：Transformer 上层非线性算子。

## 工具集说明

### 1.basic_protocols

基础安全协议测试模块，包含：

- SMP：安全二输入乘法协议。
- 3SMP：安全三输入乘法协议。
- ODReLU：隐藏符号门生成协议。
- ReLU：由 ODReLU 和 SMP 组合得到的安全 ReLU。

该工具集是其他三个工具集的底层依赖，主要验证分享态乘法、三输入乘法、比较门和 ReLU 组合的正确性与通信调度。

工程实现包含 `base` 和 `dualport` 两类形态：

- `base`：基础单通道版本，强调协议代数和单向传输逻辑。
- `dualport`：在 `base` 基础上使用双网络通道拆分通信负载，降低双向通信阻塞。

### 2.base_hybrid_approx

固定区间混合近似工具集，包含：

- Sigmoid base
- Tanh base
- Erf base
- Exp base
- Inv base
- InvSqrt base

该工具集假设输入已经落在对应函数的拟合区间内，主要解决“如何在分享态下高效计算局部非线性函数近似”的问题。

核心思想是将函数写成低阶多项式项和三角基项的组合，通过随机掩码打开 `d = x + t`，再基于 `x = d - t` 的展开和三角差角公式完成安全近似。

### 3.plus_hybrid_approx

宽范围混合近似工具集，包含：

- Sigmoid+
- Tanh+
- Erf+
- Exp+
- Inv+
- InvSqrt+

该工具集用于处理真实 Transformer 推理中更宽的输入范围。与 base 版本不同，plus 版本在局部近似外加入比较、分段、饱和、clipping、mux 或 Newton refinement。

典型逻辑包括：

- bounded 函数：左饱和区 / 中间 base 区 / 右饱和区。
- Exp：clipping 或分段近似。
- Inv 和 InvSqrt：steep/flat 分段初值 + Newton 迭代。

所有 gate、候选值和选择结果均保持为秘密分享形式。

### 4.nonlinear_functions

Transformer 非线性函数组合测试模块，包含：

- GeLU
- LayerNorm
- Softmax

该工具集不再只测试单个数学函数，而是把基础协议、base/plus 近似协议组合为 Transformer 中真实使用的非线性模块。

典型依赖关系：

- GeLU：Erf/Erf+ + SMP。
- LayerNorm：平方、均值、方差、InvSqrt+、归一化乘法。
- Softmax：clipping、Exp/Exp+、行求和、Inv+、归一化乘法。

## 运行方式

每个工具集均采用 `party0` 和 `party1` 两方程序。运行时需要打开两个终端。

以 `1.basic_protocols` 为例：

终端 1：

```sh
cd 1.basic_protocols/party1
./1.sh
```

终端 2：

```sh
cd 1.basic_protocols/party0
./1.sh
```

其他工具集运行方式相同，只需替换目录名：

```sh
cd 2.base_hybrid_approx/party1
./1.sh
```

```sh
cd 2.base_hybrid_approx/party0
./1.sh
```

建议先启动 `party1`，再启动 `party0`。各目录中的 `./1.sh` 会编译并运行默认测试。直接运行 `./app` 通常会执行当前工具集的默认测试；已有的 `--test-*` 参数或宏定义可用于单项测试。

## 测试项配置

每个工具集的默认测试项由两侧代码中的 `define.h` 控制。修改测试范围时，需要同时检查 `party0` 和 `party1` 的配置文件，保证两方启用的测试项一致：

```text
1.basic_protocols/party0/App/define/define.h
1.basic_protocols/party1/App/define/define.h

2.base_hybrid_approx/party0/App/define/define.h
2.base_hybrid_approx/party1/App/define/define.h

3.plus_hybrid_approx/party0/App/define/define.h
3.plus_hybrid_approx/party1/App/define/define.h

4.nonlinear_functions/party0/App/define/define.h
4.nonlinear_functions/party1/App/define/define.h
```

通常做法是通过注释或取消注释宏定义来切换测试项。例如：

- 启用全部默认测试。
- 只测试某一个基础协议。
- 只测试某一个 base/plus 近似函数。
- 只测试 GeLU、LayerNorm 或 Softmax 中的某一项。

修改 `define.h` 后，需要重新运行对应目录下的 `./1.sh`，让两侧程序重新编译并使用新的宏配置。若 `party0` 和 `party1` 启用的测试项不一致，可能出现连接等待、收发顺序错位或测试结果异常。

## 技术文档

每个工具集目录下均包含独立技术说明文档：

```text
1.basic_protocols/TECHNICAL_NOTES.pdf

2.base_hybrid_approx/TECHNICAL_NOTES.pdf

3.plus_hybrid_approx/TECHNICAL_NOTES.pdf

4.nonlinear_functions/TECHNICAL_NOTES.pdf
```

技术说明通常包含：

1. 技术方案原理
2. 逻辑推导
3. 详细理论解释
4. 算法框架图
5. 数据流程图
6. 运行方式
