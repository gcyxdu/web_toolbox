#pragma once

#include <iostream>
#include <stdint.h>
#include <cwchar>

// 矩阵乘法
void matrixMulEigen(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c);