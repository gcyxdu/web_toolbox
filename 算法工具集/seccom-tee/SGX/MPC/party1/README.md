# TEE MPC

本项目包含TEE辅助的MPC求和、求积、求商、相似度计算、数值比较、多方数据求标准差、方差、皮尔逊相关系数、距离相关系数、排序、数据分箱等功能，对于每种功能的具体数据输入以及参数解释均在下方详细说明中给出。

## 项目结构
* APP
    * define：用于指定当前参与方为Party0或Party1
    * examples：用处存放函数测试代码
    * src
        * `basicSockets`：用于Socket通信使用
        * `func`：主要的计算协议实现，后续新增计算功能可放入该文件
        * `tools`：通用工具
* Enclave
    * define：用于指定当前参与方为Party0或Party1，需与APP中定义相同
    * utils：用于存放伪随机数生成函数代码
    * `Enclave.cpp`：程序生成随机数并向REE分发
    * `Enclave.edl`：TEE与REE互相调用的接口函数声明


## 环境配置

* SGX1.0

* gcc  9.4.0

* cmake 3.16.3

上述环境配置为测试配置。

## 程序部署

分别将项目目录下的`party0`和`party1`文件部署在参与方1和参与方2出，也可再本地启动两个进行进行模拟。请确保两方在`define.cpp`中定义的`currentParty`变量取值分别为`PARTY0`和`PARTY1`

如有配置IP地址和端口号的需求，请在`initializeCommunication()`函数中设置IP地址和端口号。

## 程序初始化

程序初始化需要执行两个步骤：

1. 调用`enclaveInitCSPRNG(global_eid)`，传入创建的SGX Enclave ID，系统将使用Enclave内的随机数种子对Enclave内的随机数生成器状态进行初始化；
2. 调用`initializeCommunication()`建立两方间的通信

为简化程序实现，本程序还需要调用`initialSGXEnclaveID(global_eid)`初始化全局变量`enclave_id`。

## 程序计算

### 求和

函数声明：`void funcAddMPC(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：x的秘密共享份额
* `const uint64_t *y`：y的秘密共享份额
* `uint64_t *z`：加法计算结果的秘密共享份额
* `int32_t size`：输入数据的个数

使用示例：

```c++
uint64_t x[]{23, 452, (uint64_t)-128, 57, 65};
uint64_t y[]{(uint64_t)-1287, 257, 345, 75, (uint64_t)-789};
uint64_t z[5];
funcAddMPC(x, y, z, 5);
```

### 求积

函数声明：`void funcMulMPC(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：x的秘密共享份额
* `const uint64_t *y`：y的秘密共享份额
* `uint64_t *z`：乘法计算结果的秘密共享份额
* `int32_t size`：输入数据的个数

使用示例：

参与方0：

```c++
uint64_t x[]{23, 452, (uint64_t)-128, 57, 65};
uint64_t y[]{(uint64_t)-1287, 257, 345, 75, (uint64_t)-789};
uint64_t z[5];
funcMulMPC(x, y, z, 5);
```

参与方1：

```c++
uint64_t x[]{232, (uint64_t)-52, 1235, 75, 852};
uint64_t y[]{3521, 856, 5, (uint64_t)-150, 158};
uint64_t z[5];
funcMulMPC(x, y, z, 5);
```

### 求商

函数声明：`void funcCommonDiv(const uint64_t *x, const uint64_t *y, uint64_t *q, int32_t size)`

参数含义：

* `const uint64_t *x`：x的秘密共享份额
* `const uint64_t *y`：y的秘密共享份额
* `uint64_t *q`：x / y计算结果的秘密共享份额
* `int32_t size`：输入数据的个数

使用示例：

参与方0：

```c++
uint64_t x[]{25876, 43653, (uint64_t)(-57872), 36, 64};
uint64_t y[]{12, 75, 56, 18, (uint64_t)-65};
uint64_t z[5];
funcCommonDiv(x, y, z, 5);    
```

参与方1：

```c++
uint64_t x[]{25, 43, (uint64_t)(-57), 36862, 64157};
uint64_t y[]{12, 75, 56, 18, (uint64_t)-65};
uint64_t z[5];
funcCommonDiv(x, y, z, 5);
```

### 相似度计算

函数声明：`void funcEuclidDistance(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：包含size个数据的向量
* `const uint64_t *y`：包含size个数据的向量
* `uint64_t *z`：向量x与向量y的欧氏距离计算结果
* `int32_t size`：x，y的大小

使用示例：

参与方0：

```c++
uint64_t x[]{87, 50, (uint64_t)-100, 253, 231};
uint64_t y[]{40, 100, 800, 3, (uint64_t)-200};
uint64_t z;
funcEuclidDistance(x, y, &z, 5);
```

参与方1：

```c++
uint64_t x[]{13, 150, 400, 147, 269};
uint64_t y[]{360, 400, (uint64_t)-200, 697, 1000};
uint64_t z;
funcEuclidDistance(x, y, &z, 5);
```

### 数值比较

函数声明：`void funcSecretCompare(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：x的秘密共享份额
* `const uint64_t *y`：y的秘密共享份额
* `uint64_t *z`：x与y的比较结果的秘密共享份额
* `int32_t size`：输入数据的个数

使用示例：

参与方0：

```c++
uint64_t x[]{25, 43, (uint64_t)(-57), 36, 64};
uint64_t y[]{12, 75, 56, 18, (uint64_t)-65};
uint64_t z[5];
funcSecretCompare(x, y, z, 5);
```

参与方1：

```
uint64_t x[]{15, uint64_t(-13), 157, uint64_t(-63), 12};
uint64_t y[]{18, uint64_t(-112), 56, uint64_t(-200), 179};
uint64_t z[5];
funcSecretCompare(x, y, z, 5);
```

### 多方数据求标准差

### 方差

函数声明：`void funcVariance(const uint64_t *x, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：列表X
* `uint64_t *z`：方差计算结果
* `int32_t size`：输入数据的个数

使用示例：

参与方0：

```c++
uint64_t x[]{200, 400, 600};
uint64_t z;
funcVariance(x, &z, 3);
```

参与方1：

```c++
uint64_t x[]{800, 1000};
uint64_t z;
funcVariance(x, &z, 2);
```

### 皮尔逊相关系数

函数声明：`void funcPearson(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：包含size个数据的向量
* `const uint64_t *y`：包含size个数据的向量
* `uint64_t *z`：向量x与向量y的皮尔逊相关系数计算结果
* `int32_t size`：x，y的大小

使用示例：

参与方0：

```c++
uint64_t x[]{5, 15, 20, 10, 25, 10};
uint64_t y[]{15, 30, 40, 10, 5, 6};
uint64_t z;
funcPearson(x, y, &z, 5);
```

参与方1：

```c++
uint64_t x[]{5, 5, 10, 30, 25, 4};
uint64_t y[]{5, 10, 20, 70, 5, 20};
uint64_t z;
funcPearson(x, y, &z, 5);
```

### 距离相关系数

函数声明：`void funcDistCorr(const uint64_t *A, const uint64_t *B, const uint64_t *dcovAA, const uint64_t *dcovBB, uint64_t *res, int32_t size)`

参数含义：

* `const uint64_t *A`：预处理后矩阵A
* `const uint64_t *B`：预处理后矩阵B
* `const uint64_t *dcovAA`：预处理后向量dcovAA
* `const uint64_t *dcovBB`：预处理后向量dcovBB
* `uint64_t *res`：距离相关系数计算结果秘密共享份额
* `int32_t size`：矩阵A、B的尺寸为size*size

使用示例：

参与方0：

```c++
uint64_t A[]{
    18446744073709551568,
    18446744073709551600,
    8,
    24,
    32,
    18446744073709551600,
    18446744073709551592,
    0,
    16,
    24,
    8,
    0,
    18446744073709551600,
    0,
    8,
    24,
    16,
    0,
    18446744073709551592,
    18446744073709551600,
    32,
    24,
    8,
    18446744073709551600,
    18446744073709551568,
};
uint64_t B[]{
    18446744073709551452,
    12,
    36,
    52,
    60,
    12,
    18446744073709551584,
    18446744073709551608,
    8,
    16,
    36,
    18446744073709551608,
    18446744073709551592,
    18446744073709551608,
    0,
    52,
    8,
    18446744073709551608,
    18446744073709551584,
    18446744073709551592,
    60,
    16,
    0,
    18446744073709551592,
    18446744073709551560,
};

uint64_t dcovAA = 22 * 5;
uint64_t dcovBB = 45 * 5;

uint64_t res;

funcDistCorr(A, B, &dcovAA, &dcovBB, &res, 5);
```

参与方1：

```c++
uint64_t A[25];
uint64_t B[25];
for (size_t i = 0; i < 25; i++)
{
    A[i] = 0;
    B[i] = 0;
}
uint64_t dcovAA = 0;
uint64_t dcovBB = 0;
uint64_t res;
funcDistCorr(A, B, &dcovAA, &dcovBB, &res, 5);

cout << "距离相关系数计算结果分片为： " << res << endl;
```



### 排序

函数声明：`void funcSecretSort(const uint64_t *x, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：需要排序的数组的秘密共享份额
* `const uint64_t *z`：排序后结果的秘密共享份额
* `int32_t size`：数组中元素的个数

使用示例：

参与方0：

```c++
uint64_t x[]{54, 365, 25, 35, 75};
uint64_t z[5];
funcSecretSort(x, z, 5);
```

参与方1：

```c++
uint64_t x[]{89, 23, 14, 756, 32};
uint64_t z[5];
funcSecretSort(x, z, 5);
```

### 数据分箱

函数声明：`void funcDataBin(const uint64_t *x, uint64_t *z, int32_t size)`

参数含义：

* `const uint64_t *x`：需要进行数据分箱的数组的秘密共享份额
* `const uint64_t *z`：数据分箱后结果的秘密共享份额
* `int32_t size`：数组中元素的个数

使用示例：

参与方0：

```c++
uint64_t x[]{54, 365, 25, 35, 75};
uint64_t z[5];
funcDataBin(x, z, 5);
```

参与方1：

```c++
uint64_t x[]{89, 23, 14, 756, 32};
uint64_t z[5];
funcDataBin(x, z, 5);
```

## 程序测试

程序在`example.h`中声明了用于测试的函数
具体说明如下：

`testAddFunction()`：加法功能测试
`testAddPerformance()`： 加法性能测试

`testMulFunction()`：乘法功能测试
`testMulPerformance()`：乘法性能测试

`testDivFunction()`：除法功能测试
`testDivPerformance()`：除法性能测试

`testEculidDistanceFunction()`：欧氏距离计算功能测试
`testEculidDistancePerformance()`：欧氏距离计算性能测试

`testCompareFunction()`： 数值比较功能测试
`testComparePerformance()`：数值比较性能测试

`testVarianceFunction()`：多方数据求方差功能测试
`testVariancePerformance()`：多方数据求方差性能测试

`testPearsonFunction()`：皮尔逊相关系数功能测试 
`testPearsonPerformance()`：皮尔逊相关系数性能测试

`testDistCorCoeffFunction()`：距离相关系数功能测试
`testDistCorCoeffPerformance()`：距离相关系数性能测试

`testSortFunction()`：排序功能测试
`testSortPerformance()`：排序性能测试

`testDataBinFunction()`：数据分箱功能测试
`testDataBinPerformance()`：数据分箱性能测试

## 程序扩展
### 自定义函数计算
在`func.h`中声明函数，在`func.cpp`中定义相关函数即可。
本地环境下，在`party0`下运行`update.sh`会将相关代码同步至`party1`，在分布式环境下请确保相关函数代码更新至`party1`。

### 更改随机数生成算法
当前`Encalve`中采用的随机数生成算法为**Spritz**，该算法是一种密码学安全的随机数生成算法，如果您希望更换其他随机数生成算法，可将算法相关代码添加到`Enclave/utils`中，并在`Enclave.cpp`中修改`enclaveInitCSPRNG()`和`getSecureRandom()`函数实现。