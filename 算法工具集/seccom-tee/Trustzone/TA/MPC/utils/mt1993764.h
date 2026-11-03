#ifndef MT1993764_H
#define MT1993764_H
#include <stdint.h>

void init_genrand64(uint64_t seed);

void init_by_array64(uint64_t init_key[], uint64_t key_length);

uint64_t genrand64_uint64(void);

int64_t genrand64_int63(void);
#endif