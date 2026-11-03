# Two-Party Secret Sharing Comparison

## 1. 功能简介

本模块实现了一个基于**加法秘密共享（Additive Secret Sharing）**和**布尔秘密共享（Boolean Secret Sharing）**的两方安全比较协议，用于判断两个秘密值是否满足 **`x < y`**，运算环为 **Z_(2^l)**。

其中：
- `l` 为比特长度 `bitlen`
- `bitlen` 的取值范围为 `[1, 64]`

该实现支持以下功能：

- 将某一方的私有输入秘密共享给两方；
- 在共享态下计算两个秘密值的大小关系；
- 先计算 `x - y` 的算术 share，再通过进位链逻辑完成比较；
- 使用布尔 AND 协议实现比较过程中的关键布尔运算；
- 使用 B2A 将最终布尔比较结果转换为算术 share；
- 将比较结果恢复为明文并返回给双方。

---

## 2. 协议原理

对于秘密值 `x` 和 `y`，双方分别持有它们的加法 share：

`x = x0 + x1 (mod 2^l)`

`y = y0 + y1 (mod 2^l)`

协议目标是在不泄露 `x` 和 `y` 明文的前提下，得到比较结果：

`z = [x < y]`

其中：
- `z = 1` 表示 `x < y`
- `z = 0` 表示 `x >= y`

### 2.1 输入共享

若某一方持有私有输入 `x`，则该方随机生成一个值 `r`，并计算：

`other = x - r (mod 2^l)`

随后：
- 自己保留 `r`
- 将 `other` 发送给另一方

这样两方共同持有 `x` 的加法秘密共享。

对于 `y` 也采用相同方式进行共享。

### 2.2 差值计算

比较协议首先在算术 share 上计算：

`a = x - y (mod 2^l)`

由于 `x` 和 `y` 都是加法 share，因此双方可以直接对本地 share 做减法，得到 `a` 的加法 share。

这一部分不需要额外通信。

### 2.3 基于进位链的比较

在得到 `a = x - y` 的 share 后，协议按位处理该结果，并根据进位链逻辑逐步计算最终比较位。

核心思路是：

- 将 `a` 的各比特拆分为布尔 share；
- 从低位到高位递推计算进位信息；
- 每一步递推中都需要安全布尔 AND；
- 最终由最高位相关结果得到比较输出位。

因此，该比较协议的核心可以概括为：

- 先计算 `(x - y)` 的算术 share；
- 再利用布尔 AND 和进位链逻辑提取比较结果；
- 最后将布尔结果转换回算术 share。

### 2.4 Boolean AND

进位链中的关键操作是布尔 AND。

对于两个异或 share 的比特 `x` 和 `y`，协议使用**布尔 Beaver Triple**完成安全 AND 计算，其中 triple 满足：

`c = a & b`

协议先生成布尔 triple，再在线阶段打开：

`d = x XOR a`

`e = y XOR b`

然后由双方各自本地计算输出 share。

为了生成 triple 中的交叉项，实现中使用了基于 OT 的 bit 乘法 share。

### 2.5 B2A 转换

比较协议得到的最终结果是一个布尔 share，即两方异或 share 形式的 bit。

为了让输出能够继续参与算术协议，模块进一步执行 **B2A（Boolean-to-Arithmetic）** 转换，将该布尔 share 转换为环 `Z_(2^l)` 上的算术 share。

转换后，双方得到：

`z = z0 + z1 (mod 2^l)`

其中 `z` 只可能为 `0` 或 `1`。

### 2.6 结果恢复

设结果 share 为：

`z = z0 + z1 (mod 2^l)`

双方交换各自持有的 share，并相加即可恢复明文比较结果。

---

## 3. 模块结构

本实现包含以下五个核心部分：

### 3.1 `types.h`

该文件定义了比较协议中使用的基础数据结构和环上工具函数。

主要包括：

- `ArithShare`  
  表示算术秘密共享值，包含：
  - `value`：当前参与方持有的 share 数值
  - `bitlen`：该 share 所属环的比特长度

- `BoolShare`  
  表示单比特布尔秘密共享，采用异或 share 语义。

- `BoolWordShare`  
  表示多比特布尔秘密共享，底层使用一个 `uint64_t` 保存多个异或 share bit。

此外，该文件还提供了：
- `RingMask(bitlen)`
- `AddMod(a, b, bitlen)`
- `SubMod(a, b, bitlen)`
- `GetBit(v, idx)`

这些函数用于处理环 `Z_(2^l)` 上的运算和按位访问。

### 3.2 `OtHelper`

`OtHelper` 是比较协议中的 OT 基础组件，用于封装消息 OT 的发送和接收逻辑。

主要职责包括：

- 初始化两方 Base OT；
- 基于 IKNP OT Extension 扩展出批量 OT key；
- 通过 pad 掩码方式实现 `uint64_t` 消息 OT；
- 支持两个通信方向：
  - `0 -> 1`
  - `1 -> 0`

该模块为后续的：
- 布尔 AND
- B2A 转换

提供统一的 OT 能力支持。

### 3.3 `BooleanAnd`

`BooleanAnd` 模块用于在布尔 share 上实现安全 AND。

其输入和输出都遵循异或 share 语义，即：

- 输入是两方分别持有的 bit share；
- 输出仍然是两方分别持有的 bit share；
- 两方异或后得到真实的 AND 结果。

该模块内部主要包括：

- `Xor`  
  计算两个布尔 share 的异或；

- `XorConst`  
  计算布尔 share 与公开常量 bit 的异或；

- `And`  
  实现安全布尔 AND；

- `GenTriple`  
  生成布尔 Beaver Triple；

- `OtMulBitShare`  
  基于 OT 生成 bit 乘法 share。

该模块是整个比较协议中最关键的布尔计算组件之一。

### 3.4 `B2AConverter`

`B2AConverter` 模块用于将布尔 share 转换为算术 share。

主要支持两种转换：

- `ConvertBit`  
  将单比特 `BoolShare` 转换为算术 share；

- `ConvertWord`  
  将多比特 `BoolWordShare` 转换为算术 share。

其中比较协议最终只需要将一个结果 bit 转换为算术 share，因此 `ConvertBit` 是比较流程中的核心接口。

该模块同样依赖 `OtHelper` 实现 OT 支持。

### 3.5 `TwoPartySSCompare`

`TwoPartySSCompare` 是比较协议的核心类，负责组织完整的两方安全比较流程。

主要成员包括：

- `lctx_`：YACL 通信上下文，用于两方消息收发
- `bitlen_`：运算环比特长度
- `mask_`：对应 `bitlen_` 的掩码，用于实现模 `2^l` 运算
- `and_`：布尔 AND 协议组件
- `b2a_`：B2A 转换组件

该类对外提供以下核心能力：

- `ShareInput`  
  将输入共享给两方；

- `RevealToAll`  
  将算术 share 恢复为明文；

- `LessThan`  
  执行安全比较，返回结果的算术 share。

## 4. 核心功能模块介绍

### 4.1 环上基础与布尔基础

比较协议中首先依赖 `types.h` 提供的基础运算和数据表示。

其中包括：

- `RingMask(bitlen)`  
  生成对应 bit 长度的掩码；

- `AddMod(a, b, bitlen)`  
  计算模 `2^l` 加法；

- `SubMod(a, b, bitlen)`  
  计算模 `2^l` 减法；

- `GetBit(v, idx)`  
  获取一个整数在指定位置上的比特值。

这些函数用于保证算术 share 始终工作在 `Z_(2^l)` 环上，同时支持比较协议中的逐位处理逻辑。

### 4.2 `OtHelper`

`OtHelper` 模块用于封装比较协议中的消息 OT 能力。

特点：

- 在初始化阶段完成 Base OT 的建立；
- 支持两个方向的 OT 通信：
  - `0 -> 1`
  - `1 -> 0`
- 基于 IKNP OT Extension 扩展出批量 OT key；
- 使用 pad 掩码方式实现 `uint64_t` 消息 OT；
- 为布尔 AND 和 B2A 提供统一的底层 OT 支持。

该模块的核心接口包括：

- `SendU64`  
  由 sender 发送两组候选消息；

- `RecvU64`  
  由 receiver 根据选择比特接收对应消息。

### 4.3 `BooleanAnd`

`BooleanAnd` 模块用于在布尔 share 上实现安全 AND。

特点：

- 输入和输出都采用异或 share 语义；
- 支持基础布尔异或操作；
- 使用布尔 Beaver Triple 完成安全 AND；
- Triple 中的交叉项通过 OT 生成；
- 在线阶段通过打开 `d` 和 `e` 完成最终计算。

该模块主要包括以下功能：

- `Xor`  
  计算两个布尔 share 的异或；

- `XorConst`  
  计算布尔 share 与公开常量 bit 的异或；

- `And`  
  实现安全布尔 AND，是进位链计算中的核心接口；

- `GenTriple`  
  生成布尔 Beaver Triple；

- `OtMulBitShare`  
  使用 OT 生成 bit 乘法的本地 share。

该模块是整个比较协议中最关键的布尔计算组件之一。

### 4.4 `B2AConverter`

`B2AConverter` 模块用于将布尔 share 转换为算术 share。

特点：

- 支持单比特布尔 share 转算术 share；
- 支持多比特布尔 word share 转算术 share；
- 底层依赖 `OtHelper` 提供的 OT 能力；
- 输出结果落在 `Z_(2^l)` 环上。

该模块主要包括以下功能：

- `ConvertBit`  
  将单比特 `BoolShare` 转换为算术 share；

- `ConvertWord`  
  将多比特 `BoolWordShare` 转换为算术 share。

其中比较协议最终只需要输出一个结果 bit，因此 `ConvertBit` 是比较流程中的核心接口。

### 4.5 `ShareInput`

该函数用于将某一方持有的私有输入转换为两方加法秘密共享。

特点：

- 双方都需要调用该函数；
- 只有输入拥有方真正提供明文输入；
- 非拥有方只负责接收 share；
- 最终双方分别得到一个 `ArithShare`。

该过程与前面的加法、乘法模块一致，是比较协议的输入准备阶段。

### 4.6 `RevealToAll`

该函数用于将算术 share 恢复为明文，并将结果返回给双方。

特点：

- 双方都需要调用；
- 双方交换各自持有的 share；
- 本地求和后得到最终结果。

对于比较协议而言，该函数主要用于恢复最终比较结果 `z`。

### 4.7 `LessThan`

该函数用于执行安全比较，是整个比较协议的核心接口。

特点：

- 输入为两个算术 share：`x` 和 `y`；
- 首先本地计算 `a = x - y` 的 share；
- 然后按位构造布尔 share；
- 通过进位链递推逐步计算比较结果位；
- 在递推过程中多次调用 `BooleanAnd::And`；
- 最终通过 `B2AConverter::ConvertBit` 将结果 bit 转为算术 share。

其整体流程可以概括为：

- 先计算 `(x - y)` 的算术 share；
- 再提取各比特并构造 `w_k`、`p_k`、`q_k`；
- 从低位到高位递推计算进位链状态 `c_k`；
- 最后由最高位相关结果得到比较输出位；
- 将该布尔结果转换为算术 share 作为最终输出。

该函数最终返回：

- `1` 的算术 share，表示 `x < y`
- `0` 的算术 share，表示 `x >= y`

### 4.8 辅助函数

比较协议中还实现了若干辅助函数，用于支持通信和一致性检查。

主要包括：

- `CheckTwoPartyOrThrow()`  
  检查当前协议环境是否合法，例如：
  - 当前协议是否确实为两方协议；
  - `bitlen` 是否在合法范围内；
  - 通信上下文是否有效。

- `PackU64()` / `UnpackU64()`  
  用于 `uint64_t` 与 `yacl::Buffer` 之间的序列化和反序列化，便于网络传输。

- `Pack2Bits()` / `Unpack2Bits()`  
  用于打包和解包两个布尔值，主要服务于布尔 AND 在线阶段打开 `d` 和 `e` 的过程。

这些辅助函数不直接实现比较逻辑，但为整个协议的稳定执行提供了必要支持。