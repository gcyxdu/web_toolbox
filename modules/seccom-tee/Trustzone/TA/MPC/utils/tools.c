#include "tools.h"

// 矩阵乘法计算
void matrixMulEigen(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c)
{
    uint64_t left_matrix_row_major[rows * common_dim];
    uint64_t right_matrix_col_major[common_dim * columns];
    size_t offset = 0;

    // 将 a 矩阵转换为行主序列
    for (size_t i = 0; i < rows; i++)
    {
        offset = i * common_dim;
        for (size_t j = 0; j < common_dim; j++)
        {
            left_matrix_row_major[offset + j] = a[offset + j];
        }
    }

    // 将 b 矩阵转换为列主序列
    for (size_t i = 0; i < common_dim; i++)
    {
        offset = i * columns;
        for (size_t j = 0; j < columns; j++)
        {
            right_matrix_col_major[j * common_dim + i] = b[offset + j];
        }
    }

    // 矩阵乘法计算
    uint64_t ra, rb, rc;
    uint64_t cumu_ele;
    for (size_t r = 0; r < rows; r++)
    {
        ra = r * common_dim;
        rc = r * columns;
        for (size_t col = 0; col < columns; col++)
        {
            rb = col * common_dim;
            cumu_ele = 0;
            for (size_t com = 0; com < common_dim; com++)
            {
                cumu_ele += left_matrix_row_major[ra + com] * right_matrix_col_major[rb + com];
            }
            c[rc + col] = cumu_ele;
        }
    }
}
