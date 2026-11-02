#ifndef MATRIX_MUL_EIGEN_H
#define MATRIX_MUL_EIGEN_H

#include <stdint.h>  // 用于 uint64_t
#include <wchar.h>   // 只保留必要的头文件

// 矩阵乘法
void matrixMulEigen(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c);

#endif // MATRIX_MUL_EIGEN_H
