#ifndef STRINGUTILS_H
#define STRINGUTILS_H

#include <stdint.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

void printf_vector_int64_t(int64_t* value, size_t size);
void printf_vector_double(double* value, size_t size);
void printf_ploy_int64_t(int64_t* value, size_t ploy_modulus_degree);
void printf_ploy_uint64_t(uint64_t* value, size_t ploy_modulus_degree);

#ifdef __cplusplus
}
#endif

#endif // STRINGUTILS_H
