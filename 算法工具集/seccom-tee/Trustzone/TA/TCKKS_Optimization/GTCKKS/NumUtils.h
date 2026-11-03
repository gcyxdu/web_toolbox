#ifndef NUM_UTILS_H
#define NUM_UTILS_H

#include <stdint.h>
#include "SpritzCipher.h"
#include "stddef.h"


// 用于生成高斯噪声样本
void samplesGauss(uint64_t **e, size_t ploy_modulus_degree, double stdev, uint64_t qmod);

// 获取给定数字 a 的第 k 位
long bit(long a, long k);

// 生成私钥的函数
void samplesHWT(uint64_t **s, size_t ploy_modulus_degree, const long h, uint64_t qmod);

// 生成随机 01 系数的函数
void samplesZO(uint64_t **r, size_t ploy_modulus_degree, uint64_t qmod);

// 生成公钥的函数
void samplesUniform2(uint64_t **a, size_t ploy_modulus_degree, uint64_t qmod);

#endif
