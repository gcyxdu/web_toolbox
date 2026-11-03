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
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "func.h"
#include "base_secure_protocols.h"
#include "calculate/basicSockets.h"  
#include <future>
#include <chrono>
#include <thread>
#include <cstdint>


void generateRandomArrayApp(int* array, int size, unsigned int seed, int max_val ) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(1, max_val);
    
    
    for (int i = 0; i < size; i++) {
        array[i] = dis(gen);
    }
    
    
    std::cout << "最后生成的数组为：";
    for (int i = 0; i < size; i++) {
        if (i > 0) {  
            std::cout << ", ";
        }
        std::cout << array[i];
    }
    std::cout << std::endl;  
}


void arrayAdd(int* result, const int* a, const int* b, int size) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] + b[i];
    }
}


void arraySubtract(int* result, const int* a, const int* b, int size) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] - b[i];
    }
}


int secureModApp(int value, int modulus ) {
    int result = value % modulus;
    if (result < 0) result += modulus;
    return result;
}


void arrayModAdd(int* result, const int* a, const int* b, int size, int modulus ) {
    for (int i = 0; i < size; i++) {
        result[i] = secureModApp(a[i] + b[i], modulus);
    }
}


void arrayModSub(int* result, const int* a, const int* b, int size, int modulus ) {
    for (int i = 0; i < size; i++) {
        result[i] = secureModApp(a[i] - b[i], modulus);
    }
}


void arrayModMul(int* result, const int* a, const int* b, int size, int modulus ) {
    for (int i = 0; i < size; i++) {
        result[i] = secureModApp(a[i] * b[i], modulus);
    }
}

#include <random>


void generateRandomArray(int* array, int size, unsigned int seed, int max_val ) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(1, max_val);
    
    for (int i = 0; i < size; i++) {
        array[i] = dis(gen);
    }
    std::cout << "最后生成的数组为：";
    for (int i = 0; i < size; i++) {
        if (i > 0) {  
            std::cout << ", ";
        }
        std::cout << array[i];
    }
    std::cout << std::endl;  
}


void generateRandomArrayUint(uint32_t* array, uint32_t size, uint32_t seed, uint32_t max_val) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint32_t> dis(1, max_val);
    
    for (uint32_t i = 0; i < size; i++) {
        array[i] = dis(gen);
    }

}


void arrayModAddUint(uint32_t* result, const uint32_t* a, const uint32_t* b, uint32_t size, uint32_t modulus) {
    for (uint32_t i = 0; i < size; i++) {
        result[i] = (a[i] + b[i]) % modulus;
    }
}


void arrayModSubUint(uint32_t* result, const uint32_t* a, const uint32_t* b, uint32_t size, uint32_t modulus) {
    for (uint32_t i = 0; i < size; i++) {
        result[i] = (a[i] + modulus - b[i]) % modulus;
    }
}


void arrayModMulUint(uint32_t* result, const uint32_t* a, const uint32_t* b, uint32_t size, uint32_t modulus) {
    for (uint32_t i = 0; i < size; i++) {
        result[i] = (a[i] * b[i]) % modulus;
    }
}



uint64_t secure_smp_multiply(uint32_t a, uint32_t b, uint32_t L) {
    return (uint64_t)a * b;
}


uint64_t secure_smp_multiply_fixed(uint32_t a, uint32_t b, uint32_t s, uint32_t L) {
    
    uint64_t product = (uint64_t)a * b;
    
    product = product >> s;
    return product % L;
}


uint32_t secureModUint(int64_t value, uint32_t L) {
    int64_t mod = value % L;
    if (mod < 0) mod += L;
    return (uint32_t)mod;
}

int32_t secureModFixedRange(int64_t value, uint32_t modulus) {
    int64_t half_mod = modulus / 2;
    int64_t result = value % modulus;
    
    
    if (result > half_mod) {
        result -= modulus;
    } else if (result < -half_mod) {
        result += modulus;
    }
    
    return (int32_t)result;
}
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>


#define TIMER_START(name) auto start_##name = std::chrono::high_resolution_clock::now()
#define TIMER_END(name, msg) \
    do { \
        auto end_##name = std::chrono::high_resolution_clock::now(); \
        auto dur_##name = std::chrono::duration_cast<std::chrono::microseconds>(end_##name - start_##name).count(); \
        printf("[CSP1] %s: %ld us\n", msg, dur_##name); \
    } while(0)


void arrayAdd_64(uint64_t* result, const uint64_t* a, const uint64_t* b, int size) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] + b[i];
    }
}

void arraySubtract_64(uint64_t* result, const uint64_t* a, const uint64_t* b, int size) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] - b[i];
    }
}


uint64_t* applyMapping_64(const uint64_t* input, int input_len, const uint64_t* mapping, int mapping_len) {
    uint64_t* result = new uint64_t[mapping_len]();
    for (int i = 0; i < input_len; i++) {
        if (mapping[i] > 0) {
            int target_idx = mapping[i] - 1;
            if (target_idx < mapping_len) {
                result[target_idx] += input[i];
            }
        }
    }
    return result;
}


void generateRandomArray_64(uint64_t* array, int size, int seed) {
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<uint64_t> dis(0, 100);
    
    for (int i = 0; i < size; i++) {
        array[i] = dis(gen);
    }
}

void generate_sparse_neuron_fixed_64(uint64_t* original, uint64_t* share, uint64_t* b_mask, 
                                   int m, int fixed_n, int seed_offset) {
    
    memset(original, 0, m * sizeof(uint64_t));
    memset(b_mask, 0, m * sizeof(uint64_t));
    
    std::mt19937_64 gen(1000 + seed_offset);
    std::uniform_int_distribution<uint64_t> value_dis(10, 100);
    
    
    std::vector<int> positions(m);
    for (int i = 0; i < m; i++) {
        positions[i] = i;
    }
    
    
    for (int i = m - 1; i > 0; i--) {
        int j = gen() % (i + 1);
        std::swap(positions[i], positions[j]);
    }
    
    
    for (int i = 0; i < fixed_n; i++) {
        int pos = positions[i];
        b_mask[pos] = 1;
        original[pos] = value_dis(gen);
    }
    
    
    std::mt19937_64 share_gen(2000 + seed_offset);
    std::uniform_int_distribution<uint64_t> share_dis(1, 50);
    
    for (int i = 0; i < m; i++) {
        if (b_mask[i]) {
            share[i] = original[i] - share_dis(share_gen);
        } else {
            share[i] = 0;
        }
    }
}


void generate_sparse_neuron_fixed_csp1_64(uint64_t* original, uint64_t* share, uint64_t* b_mask, 
                                        int m, int fixed_n, int seed_offset) {
    
    memset(original, 0, m * sizeof(uint64_t));
    memset(b_mask, 0, m * sizeof(uint64_t));
    
    std::mt19937_64 gen(1000 + seed_offset);
    std::uniform_int_distribution<uint64_t> value_dis(10, 100);
    
    
    std::vector<int> positions(m);
    for (int i = 0; i < m; i++) {
        positions[i] = i;
    }
    
    
    for (int i = m - 1; i > 0; i--) {
        int j = gen() % (i + 1);
        std::swap(positions[i], positions[j]);
    }
    
    
    for (int i = 0; i < fixed_n; i++) {
        int pos = positions[i];
        b_mask[pos] = 1;
        original[pos] = value_dis(gen);
    }
    
    
    std::mt19937_64 share_gen(2000 + seed_offset);
    std::uniform_int_distribution<uint64_t> share_dis(1, 50);
    
    for (int i = 0; i < m; i++) {
        if (b_mask[i]) {
            
            
            share[i] = share_dis(share_gen); 
        } else {
            share[i] = 0;
        }
    }
}
