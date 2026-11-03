#include "tools.h"

// 矩阵乘法计算
void matrixMulEigen(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c)
{

    uint64_t left_matrix_row_major[rows * common_dim];
    uint64_t right_matrix_col_major[common_dim * columns];
    size_t offset = 0;

    for (int i = 0; i < rows; i++)
    {
        offset = i * common_dim;
        for (int j = 0; j < common_dim; j++)
        {
            left_matrix_row_major[offset + j] = a[offset + j];
        }
    }

    for (int i = 0; i < common_dim; i++)
    {
        offset = i * columns;
        for (int j = 0; j < columns; j++)
        {
            right_matrix_col_major[j * common_dim + i] = b[offset + j];
        }
    }

    uint64_t ra, rb, rc;
    uint64_t cumu_ele;
    for (int r = 0; r < rows; r++)
    {
        ra = r * common_dim;
        rc = r * columns;
        for (int col = 0; col < columns; col++)
        {
            rb = col * common_dim;
            cumu_ele = 0;
            for (int com = 0; com < common_dim; com++)
            {
                cumu_ele += left_matrix_row_major[ra + com] * right_matrix_col_major[rb + com];
            }
            c[rc + col] = cumu_ele;
        }
    }
}
