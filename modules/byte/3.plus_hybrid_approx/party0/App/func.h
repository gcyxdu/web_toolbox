#ifndef FUNC_H
#define FUNC_H

#include <cstdint>
#include "calculate/basicSockets.h"
#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX
#include <sys/time.h>
#include <mutex>
#include <condition_variable>
#include <complex>
#include <iostream>
#include <vector>
#include <random> 
#include <atomic>  
#include "App.h"
#include "base_secure_protocols.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include <future>
#include <chrono>
#include <thread>
#include <cstdint>
void generate_consistent_random_64(uint64_t* array, uint64_t count, uint64_t seed) ;

void generateRandomArrayApp(int* array, int size, unsigned int seed, int max_val = 50);
void arrayAdd(int* result, const int* a, const int* b, int size);
void arraySubtract(int* result, const int* a, const int* b, int size);
int secureModApp(int value, int modulus = 1000);
void arrayModAdd(int* result, const int* a, const int* b, int size, int modulus = 1000);
void arrayModSub(int* result, const int* a, const int* b, int size, int modulus = 1000);
void arrayModMul(int* result, const int* a, const int* b, int size, int modulus = 1000);


void generateRandomArray(int* array, int size, unsigned int seed, int max_val = 50);
void generateRandomArrayUint(uint32_t* array, uint32_t size, uint32_t seed, uint32_t max_val = 50);


void arrayModAddUint(uint32_t* result, const uint32_t* a, const uint32_t* b, uint32_t size, uint32_t modulus);
void arrayModSubUint(uint32_t* result, const uint32_t* a, const uint32_t* b, uint32_t size, uint32_t modulus);
void arrayModMulUint(uint32_t* result, const uint32_t* a, const uint32_t* b, uint32_t size, uint32_t modulus);


int32_t secureMod(int64_t value, int32_t modulus);






void generate_sparse_patch_fixed(int* original, int* share, int* b_mask, int m, int fixed_n, int seed_offset);


void print_patch_with_highlight(const int* patch, int size, const int* b_mask);


void arrayAdd_64(uint64_t* result, const uint64_t* a, const uint64_t* b, int size);
void arraySubtract_64(uint64_t* result, const uint64_t* a, const uint64_t* b, int size);


uint64_t* applyMapping_64(const uint64_t* input, int input_len, const uint64_t* mapping, int mapping_len);


void generateRandomArray_64(uint64_t* array, int size, int seed);


void generate_sparse_neuron_fixed_64(uint64_t* original, uint64_t* share, uint64_t* b_mask, 
                                   int m, int fixed_n, int seed_offset);


void generate_sparse_neuron_fixed_csp1_64(uint64_t* original, uint64_t* share, uint64_t* b_mask, 
                                        int m, int fixed_n, int seed_offset);


extern sgx_enclave_id_t global_eid;
extern sgx_enclave_id_t global_eid0;
extern sgx_enclave_id_t global_eid1;

#endif 