#ifndef ENCLAVE_H
#define ENCLAVE_H

#include <stdint.h>

void printf(const char* fmt, ...);
void generate_consistent_random_64(uint64_t* array, uint64_t count, uint64_t seed);

#endif
