#pragma once

#include <vector>
#include "basicSockets.h"
#include "tools.h"

using std::vector;

extern BSNet *bsnet_server;
extern BSNet *bsnet_cli;

/**
 * 给线程设置姓名
 * */
void setThreadName(const std::string& name);
/**
 * 获取线程名
 * */
std::string getThreadName();
/**
 * 初始化通信函数 host: 服务器地址 port: 服务器端口号
 */
void initializeCommunication(const char *host, unsigned int port);

/**
 * 初始化通信函数，传入端口号来创建BSNet对象并开始监听
 */
void initializeCommunication(unsigned int port);

/**
 * 初始化随机数生成器
 */
void initializeRandGen(const uint64_t &seed);

/**
 * 生成随机数序列并存储到数组r中，序列长度为len
 */
void generateRand(uint64_t *r, int32_t len);

/**
 * 生成指定长度的随机数，并将其添加到给定的数组中
 */
void generateRand(vector<uint64_t> &vec, int32_t len);

/**
 * 将秘密共享的数据右移power位
 */
void funcTruncate2PC(uint64_t *a, uint64_t power, size_t size);

/**
 * 乘法计算，将x，y相乘的计算结果保存在z中
 */
void funcMulMPC(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size);

/**
 * 矩阵乘法计算，将a，b相乘的计算结果保存在c中
 */
void funcMatrixMul(size_t rows, size_t common_dim, size_t columns,
				   const uint64_t *a, const uint64_t *b, uint64_t *c);

/**
 * 计算（X，Y）间的欧几里得距离，计算结果保存在z中
 */
void funcEuclidDistance(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size);

/**
 * 计算秘密共享份额a的RELU函数的导数并存储到数据z中
 */
void funcDeRELUMPC(const uint64_t *a, uint64_t *b, int32_t size);

/**
 * 计算秘密共享份额a的RELU函数的值并存储到数据z中
 */
void funcRelu(const uint64_t *a, uint64_t *z, int32_t size);

/**
 * MSBA2B协议，对于输入的秘密共享份额a，计算其原始值的最高比特位并转换为布尔共享存储至z中
 */
void funcMSBA2B(const uint64_t *a, uint64_t *b, int32_t size);

/**
 * 比较秘密共享份额x和秘密共享份额y的大小，将结果存储在z中
 */
void funcSecretCompare(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size);

/**
 * 计算除法的系数（RELU（1）->1, RELU(0)->-1）
 */
void calDivCoeff(const uint64_t *x, uint64_t *z, int32_t size);

/**
 * 计算秘密共享份额x除以秘密共享份额y，并将计算结果存储至q中, 并将计算结果存储至q中，要求x >= 0, y > 0
 */
void funcDiv(const uint64_t *x, const uint64_t *y, uint64_t *q, int32_t size);

/**
 * 通用除法，可以计算任意正负的除数/被除数
 */
void funcCommonDiv(const uint64_t *x, const uint64_t *y, uint64_t *q, int32_t size);

/**
 * 计算Array(x)的方差并将结果存储到z中
 */
void funcVariance(const uint64_t *x, uint64_t *z, int32_t size);

/**
 * 计算Array(x,y)的协方差并将结果存储到z中
 */
void funcCovariance(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size);

/**
 * 计算x，y间的皮尔逊相关系数并将结果存储到z中
 */
void funcPearson(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size);

/**
 * A，B，dcovAA，dcovBB为数据预处理后的数据，进一步计算距离相关系数并存储在res中
 */
void funcDistCorr(const uint64_t *A, const uint64_t *B, const uint64_t *dcovAA, const uint64_t *dcovBB, uint64_t *res, int32_t size);

/**
 * 数据分箱比较
 */
bool databinCompare(const uint64_t *x, const uint64_t *y, uint64_t *z);

/**
 * 自定义sort函数中的比较规则
 */
bool sortCompare(const uint64_t &x, const uint64_t &y);

/**
 * 快速排序
 */
int64_t partitionData(uint64_t *A, int64_t start, int64_t end);

void quicksortSharingData(uint64_t *A, int64_t start, int64_t end);

/**
 * 排序
 */
void funcSecretSort(const uint64_t *x, uint64_t *z, int32_t size);

/**
 * 数据分箱
 */
void funcDataBin(const uint64_t *x, uint64_t *z, int32_t size);

/**
 * 对数据进行左移
 */
void funcFixedPointShift(double *input, uint64_t *output, size_t power, int32_t size);

/**
 * 对数据进行右移截断
 */
void funcTruncate2PC(uint64_t *a, size_t power, int32_t size);

/**
 * 将浮点数据方法后转换为整数
 */
void funcFixedPointShift(uint64_t *input, uint64_t *output, size_t power, int32_t size);

/**
 * 实现一方输入a, 一方输入b型compare
 */
void truncateCompare(uint64_t *a, uint64_t *res, int32_t size);