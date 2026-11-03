# Two-Party Secret Sharing Multiplication

## 1. 功能简介

本模块实现了一个基于**加法秘密共享（Additive Secret Sharing）**的两方安全乘法协议，运算环为 **Z_(2^l)**。

其中：
- `l` 为比特长度 `bitlen`
- `bitlen` 的取值范围为 `[1, 64]`

该实现支持以下功能：

- 将某一方的私有输入秘密共享给两方；
- 在共享态下对两个秘密值进行乘法运算；
- 使用 Beaver Triple 完成在线乘法计算；
- 使用 OT 生成 Beaver Triple 中所需的乘法相关项；
- 将乘法结果恢复为明文并返回给双方；
- 支持不同 bit 长度下的模 `2^l` 运算。

---

## 2. 协议原理

对于秘密值 `x`，将其拆分为两个 share：

`x = x0 + x1 (mod 2^l)`

其中：
- Party 0 持有 `x0`
- Party 1 持有 `x1`

单独任意一方都无法恢复 `x`，只有双方将 share 相加才能得到原值。

### 2.1 输入共享

若某一方持有私有输入 `x`，则该方随机生成一个值 `r`，并计算：

`other = x - r (mod 2^l)`

随后：
- 自己保留 `r`
- 将 `other` 发送给另一方

这样两方共同持有 `x` 的加法秘密共享。

### 2.2 共享态乘法

对于共享值 `x` 和 `y`，本模块使用 Beaver Triple：

`(a, b, c)`，其中 `c = a * b (mod 2^l)`

双方先分别计算：

`d = x - a`

`e = y - b`

然后将 `d` 和 `e` 恢复为明文，并结合本地持有的 triple share 计算结果 share。

因此，共享态下的乘法被转化为：
- 一次 Beaver Triple 生成；
- 一次在线打开 `d` 和 `e`；
- 若干次本地模加和模乘。

### 2.3 OT 生成乘法相关项

为了生成 Beaver Triple，本实现使用基于 OT 的方法计算交叉乘法项。

核心思想是：
- 一方作为 sender，持有一个乘数；
- 另一方作为 receiver，持有另一个乘数；
- receiver 按照自己输入的各比特作为选择位；
- sender 构造两组消息并通过消息 OT 发送；
- 双方最终分别得到一个 share，两个 share 相加后等于乘积值。

该实现内部使用：
- Base OT
- IKNP OT Extension
- 基于 pad 的消息掩码传输

从而高效生成 Beaver Triple 中所需的乘法相关项。

### 2.4 结果恢复

设结果 share 为：

`z = z0 + z1 (mod 2^l)`

双方交换各自持有的 share，并相加即可恢复明文结果。

---

## 3. 模块结构

本实现包含以下三个核心部分：

### 3.1 `ArithShare`

用于表示一个算术秘密共享值，包含：

- `value`：当前参与方持有的 share 数值
- `bitlen`：该 share 所属环的比特长度

该结构用于表示普通输入 share 和乘法结果 share。

### 3.2 `BeaverTripleShare`

用于表示 Beaver Triple 的本地 share，包含：

- `a`：当前参与方持有的 `a` 的 share
- `b`：当前参与方持有的 `b` 的 share
- `c`：当前参与方持有的 `c` 的 share，其中 `c = a * b (mod 2^l)`
- `bitlen`：该 triple 所属环的比特长度

该结构是共享态乘法的核心辅助数据结构。

### 3.3 `TwoPartySSMul`

协议核心类，封装了两方安全乘法协议的主要逻辑。

主要成员包括：

- `lctx_`：YACL 通信上下文，用于两方消息收发
- `bitlen_`：运算环比特长度
- `mask_`：对应 `bitlen_` 的掩码，用于实现模 `2^l` 运算
- `base_ot_ready_`：标记 Base OT 是否已经初始化
- `base_recv_*` / `base_send_*`：两种通信方向下使用的 Base OT 存储

---

## 4. 核心功能模块介绍

### 4.1 环上基础运算

类中提供了多个基础函数用于环上运算：

- `RingMask(bitlen)`  
  生成对应 bit 长度的掩码；

- `AddMod(a, b, bitlen)`  
  计算模 `2^l` 加法；

- `SubMod(a, b, bitlen)`  
  计算模 `2^l` 减法；

- `MulMod(a, b)`  
  计算模 `2^l` 乘法。

这些函数用于保证所有数值始终落在 `Z_(2^l)` 环内。

### 4.2 `ShareInput`

该函数用于将某一方持有的私有输入转换为两方加法秘密共享。

特点：

- 双方都需要调用该函数；
- 只有输入拥有方真正提供明文输入；
- 非拥有方只负责接收 share；
- 最终双方分别得到一个 `ArithShare`。

### 4.3 `Mul`

该函数用于在共享态下执行乘法。

特点：

- 先生成一组 Beaver Triple；
- 再打开 `d = x - a` 和 `e = y - b`；
- 最后基于 Beaver 公式计算结果 share；
- 返回结果 `ArithShare`。

这是整个模块最核心的在线计算接口。

### 4.4 `RevealToAll`

该函数用于将共享值恢复为明文，并将结果返回给双方。

特点：

- 双方都需要调用；
- 双方交换各自持有的 share；
- 本地求和后得到最终结果。

### 4.5 Beaver Triple 生成

该模块通过 `GenBeaverTriple()` 生成一组 Beaver Triple share。

特点：

- 每一方先随机生成本地的 `a_i` 和 `b_i`；
- 本地先计算 `a_i * b_i`；
- 再通过两次 OT-mul 生成交叉项 share；
- 最终合成 `c_i`，满足 `c = a * b (mod 2^l)`。

该部分是连接 OT 与在线乘法的关键模块。

### 4.6 OT 相关模块

模块中实现了若干 OT 相关函数，用于支撑乘法 share 的生成：

- `SetupBaseOtsOnce()`  
  初始化 Base OT，仅执行一次；

- `DerivePad64()`  
  从 OT key 派生 64 位 pad；

- `MessageOtSendU64()` / `MessageOtRecvU64()`  
  基于 IKNP 扩展实现 `uint64_t` 消息 OT；

- `OtMulShare()`  
  基于 OT 生成乘法结果的本地 share。

这些函数共同实现了从 Base OT 到消息 OT，再到乘法 share 生成的完整流程。
