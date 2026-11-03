#pragma once

#include <iostream>
#include <stdint.h>
#include <cwchar>


void matrixMulPlain(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c);