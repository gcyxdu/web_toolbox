
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <random>
#include "Enclave.h"
#include "Enclave_t.h"
#include "sgx_trts.h"

using namespace std;


#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif



static inline uint64_t enc_trunc(uint64_t v, int s) {
    if (v < (1ULL << 63)) return v >> s;
    uint64_t c = (uint64_t)0 - v;
    return (uint64_t)0 - (c >> s);
}

static inline uint64_t enc_trunc_product(uint64_t a, uint64_t b, int s) {
    __int128 product =
        static_cast<__int128>(static_cast<int64_t>(a)) *
        static_cast<__int128>(static_cast<int64_t>(b));
    __int128 magnitude = (product < 0) ? -product : product;
    __int128 shifted = magnitude >> s;
    if (product < 0) shifted = -shifted;
    return static_cast<uint64_t>(static_cast<int64_t>(shifted));
}

void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}



static uint64_t* smp_a_array_64 = nullptr;
static uint64_t* smp_b_array_64 = nullptr;  
static uint64_t* smp_r0_array_64 = nullptr;
static uint64_t smp_vector_size_64 = 0;

void ecall_smp_reset_64() {
    if (smp_a_array_64) delete[] smp_a_array_64;
    if (smp_b_array_64) delete[] smp_b_array_64;
    if (smp_r0_array_64) delete[] smp_r0_array_64;
    
    smp_a_array_64 = nullptr;
    smp_b_array_64 = nullptr;
    smp_r0_array_64 = nullptr;
    smp_vector_size_64 = 0;
}


void ecall_smp_gen_ab_r0_64(uint64_t seed, uint64_t count) {
    
    ecall_smp_reset_64();
    
    
    
    if (count > 1024 * 1024 * 100) return; 

    smp_a_array_64 = new uint64_t[count];
    smp_b_array_64 = new uint64_t[count];
    smp_r0_array_64 = new uint64_t[count];
    smp_vector_size_64 = count;
    
    
    
    generate_consistent_random_64(smp_a_array_64, count, seed);     
    generate_consistent_random_64(smp_b_array_64, count, seed + 1); 
    generate_consistent_random_64(smp_r0_array_64, count, seed + 2); 
}

void ecall_smp_tee1_computation_64(uint64_t count, const uint64_t* x1_plus_r1, 
                                  const uint64_t* y1_plus_r2, uint64_t* result) {
    if (!smp_a_array_64 || !smp_b_array_64 || !smp_r0_array_64) {
        printf("错误: 64位SMP协议未初始化\n");
        return;
    }
    
    for (uint64_t i = 0; i < count; i++) {
        
        __int128 term1 = (__int128)smp_b_array_64[i] * x1_plus_r1[i];
        __int128 term2 = (__int128)smp_a_array_64[i] * y1_plus_r2[i];
        __int128 computation = -term1 - term2 + smp_r0_array_64[i];
        
        
        result[i] = (uint64_t)computation;
    }
    
}



static uint64_t* smp3_a_array_64 = nullptr;
static uint64_t* smp3_b_array_64 = nullptr;
static uint64_t* smp3_c_array_64 = nullptr;
static uint64_t* smp3_r0_array_64 = nullptr;

static uint64_t* smp3_m3_array_64 = nullptr; 

static uint64_t smp3_vector_size_64 = 0;


void ecall_3smp_reset_64() {
    if (smp3_a_array_64) delete[] smp3_a_array_64;
    if (smp3_b_array_64) delete[] smp3_b_array_64;
    if (smp3_c_array_64) delete[] smp3_c_array_64;
    if (smp3_r0_array_64) delete[] smp3_r0_array_64;
    if (smp3_m3_array_64) delete[] smp3_m3_array_64;
    
    smp3_a_array_64 = nullptr;
    smp3_b_array_64 = nullptr;
    smp3_c_array_64 = nullptr;
    smp3_r0_array_64 = nullptr;
    smp3_m3_array_64 = nullptr;
    smp3_vector_size_64 = 0;
}

void ecall_3smp_gen_abc_r0_64(uint64_t seed, uint64_t count) {
    ecall_3smp_reset_64();
    if (count > 1024 * 1024 * 100) return; 

    smp3_a_array_64 = new uint64_t[count];
    smp3_b_array_64 = new uint64_t[count];
    smp3_c_array_64 = new uint64_t[count];
    smp3_r0_array_64 = new uint64_t[count];
    smp3_vector_size_64 = count;
    
    generate_consistent_random_64(smp3_a_array_64, count, seed);
    generate_consistent_random_64(smp3_b_array_64, count, seed + 1);
    generate_consistent_random_64(smp3_c_array_64, count, seed + 2);
    generate_consistent_random_64(smp3_r0_array_64, count, seed + 3);
}

void ecall_3smp_tee1_compute_m3_64(uint64_t count,
                                 const uint64_t* x1_plus_r1, 
                                 const uint64_t* y1_plus_r2, 
                                 const uint64_t* w1_plus_r3) {
    
    if (!smp3_a_array_64 || !smp3_b_array_64 || !smp3_c_array_64) return;

    
    if (smp3_m3_array_64) delete[] smp3_m3_array_64;
    smp3_m3_array_64 = new uint64_t[count];

    using uint128_t = unsigned __int128;
    
    for (uint64_t i = 0; i < count; i++) {
        
        
        smp3_m3_array_64[i] = (uint64_t)(
            (uint128_t)smp3_a_array_64[i] * smp3_b_array_64[i] * w1_plus_r3[i] + 
            (uint128_t)smp3_a_array_64[i] * smp3_c_array_64[i] * y1_plus_r2[i] + 
            (uint128_t)smp3_b_array_64[i] * smp3_c_array_64[i] * x1_plus_r1[i]
        );
    }
}

void ecall_3smp_tee1_compute_m4_64(uint64_t count,
                                 const uint64_t* U, 
                                 const uint64_t* V, 
                                 const uint64_t* W, 
                                 uint64_t* final_result) { 
                                 
    if (!smp3_a_array_64 || !smp3_b_array_64 || !smp3_c_array_64 || !smp3_m3_array_64) return;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t m4 = 0 - (
            smp3_a_array_64[i] * U[i] + 
            smp3_b_array_64[i] * V[i] + 
            smp3_c_array_64[i] * W[i]
        );
        
        final_result[i] = smp3_m3_array_64[i] + m4 + smp3_r0_array_64[i];
    }

    delete[] smp3_m3_array_64;
    smp3_m3_array_64 = nullptr;
}


void ecall_cleanup() {

    
    ecall_smp_reset_64();
    
    
    ecall_3smp_reset_64();
    
    
    ecall_odrelu_reset_uint64();
    
}




static uint64_t* odrelu_a_array_uint64 = nullptr;
static uint64_t* odrelu_b_array_uint64 = nullptr;
static uint64_t* odrelu_r0_array_uint64 = nullptr;
static uint64_t* odrelu_r1_array_uint64 = nullptr;
static uint64_t* odrelu_v_array_uint64 = nullptr;
static uint64_t odrelu_vector_size_uint64 = 0;


void ecall_odrelu_reset_uint64() {
    if (odrelu_a_array_uint64) { delete[] odrelu_a_array_uint64; odrelu_a_array_uint64 = nullptr; }
    if (odrelu_b_array_uint64) { delete[] odrelu_b_array_uint64; odrelu_b_array_uint64 = nullptr; }
    if (odrelu_r0_array_uint64) { delete[] odrelu_r0_array_uint64; odrelu_r0_array_uint64 = nullptr; }
    if (odrelu_r1_array_uint64) { delete[] odrelu_r1_array_uint64; odrelu_r1_array_uint64 = nullptr; }
    if (odrelu_v_array_uint64) { delete[] odrelu_v_array_uint64; odrelu_v_array_uint64 = nullptr; }
    odrelu_vector_size_uint64 = 0;
}


void ecall_odrelu_gen_shared_randomness_final_uint64(uint64_t seed, uint64_t vector_size, uint64_t xi) {
    
    
    ecall_odrelu_reset_uint64();
    if (vector_size > 1024 * 1024 * 100) return; 

    odrelu_a_array_uint64 = new uint64_t[vector_size];
    odrelu_b_array_uint64 = new uint64_t[vector_size];
    odrelu_r0_array_uint64 = new uint64_t[vector_size];
    odrelu_r1_array_uint64 = new uint64_t[vector_size];
    odrelu_v_array_uint64 = new uint64_t[vector_size];
    odrelu_vector_size_uint64 = vector_size;

    
    uint64_t gen_size = vector_size * 5;
    uint64_t* raw_rand = new uint64_t[gen_size];
    
    generate_consistent_random_64(raw_rand, gen_size, seed);
    
    uint64_t two_xi = 2 * xi;

    
    for (uint64_t i = 0; i < vector_size; i++) {
        uint64_t r_sign = raw_rand[5*i + 0];
        uint64_t r_val1 = raw_rand[5*i + 1];
        uint64_t r_val2 = raw_rand[5*i + 2];
        uint64_t r_r0   = raw_rand[5*i + 3];
        uint64_t r_r1   = raw_rand[5*i + 4];

        bool is_positive = (r_sign % 2 == 0);
        
        
        uint64_t v1 = (r_val1 % (two_xi - 1)) + 1;
        uint64_t v2 = (r_val2 % (two_xi - 1)) + 1;
        
        while (v1 == v2) { 
            v2 = (v2 + 1) % (two_xi - 1) + 1; 
        }

        uint64_t abs_a = (v1 > v2) ? v1 : v2;
        uint64_t abs_b = (v1 > v2) ? v2 : v1;

        if (is_positive) {
            odrelu_a_array_uint64[i] = abs_a;
            odrelu_b_array_uint64[i] = abs_b;
            odrelu_v_array_uint64[i] = 0; 
        } else {
            odrelu_a_array_uint64[i] = 0 - abs_a;
            odrelu_b_array_uint64[i] = 0 - abs_b;
            odrelu_v_array_uint64[i] = 1;
        }
        
        odrelu_r0_array_uint64[i] = r_r0;
        odrelu_r1_array_uint64[i] = r_r1;
    }

    delete[] raw_rand;
}

void ecall_odrelu_tee1_step1_uint64(uint64_t vector_size, const uint64_t* x1_minus_r2, uint64_t* result) {
    if (!odrelu_a_array_uint64 || !odrelu_r0_array_uint64) return;

    for (uint64_t i = 0; i < vector_size; i++) {
        
        uint64_t temp = odrelu_a_array_uint64[i ] * x1_minus_r2[i]; 
        result[i] = temp - odrelu_r0_array_uint64[i ];
    }
}

void ecall_odrelu_tee1_step2_uint64(uint64_t vector_size, const uint64_t* z_plus_r3, uint64_t* result) {
    if (!odrelu_r1_array_uint64 || !odrelu_v_array_uint64) return;
    
    for (uint64_t i = 0; i < vector_size; i++) {
        if (odrelu_v_array_uint64[i] == 0) {
            result[i] = z_plus_r3[i] + odrelu_r1_array_uint64[i];
        } else {
            result[i] = 1ULL - z_plus_r3[i] + odrelu_r1_array_uint64[i];
        }
    }
}

void ecall_odrelu_get_stored_values_uint64(uint64_t vector_size, uint64_t* a, uint64_t* b, uint64_t* r0, uint64_t* r1, uint64_t* v) {
    if (!odrelu_a_array_uint64 || !odrelu_b_array_uint64 || !odrelu_r0_array_uint64 || !odrelu_r1_array_uint64 || !odrelu_v_array_uint64) {
        return;
    }
    
    uint64_t copy_size = (vector_size < odrelu_vector_size_uint64) ? vector_size : odrelu_vector_size_uint64;
    for (uint64_t i = 0; i < copy_size; i++) {
        a[i] = odrelu_a_array_uint64[i];
        b[i] = odrelu_b_array_uint64[i];
        r0[i] = odrelu_r0_array_uint64[i];
        r1[i] = odrelu_r1_array_uint64[i];
        v[i] = odrelu_v_array_uint64[i];
    }
}




static uint64_t* odrelu2_a_array_uint64 = nullptr;
static uint64_t* odrelu2_b_array_uint64 = nullptr;
static uint64_t* odrelu2_r0_array_uint64 = nullptr;
static uint64_t* odrelu2_r1_array_uint64 = nullptr;
static uint64_t* odrelu2_v_array_uint64 = nullptr;
static uint64_t odrelu2_vector_size_uint64 = 0;

void ecall_odrelu_reset_uint64_v2() {
    if (odrelu2_a_array_uint64) { delete[] odrelu2_a_array_uint64; odrelu2_a_array_uint64 = nullptr; }
    if (odrelu2_b_array_uint64) { delete[] odrelu2_b_array_uint64; odrelu2_b_array_uint64 = nullptr; }
    if (odrelu2_r0_array_uint64) { delete[] odrelu2_r0_array_uint64; odrelu2_r0_array_uint64 = nullptr; }
    if (odrelu2_r1_array_uint64) { delete[] odrelu2_r1_array_uint64; odrelu2_r1_array_uint64 = nullptr; }
    if (odrelu2_v_array_uint64) { delete[] odrelu2_v_array_uint64; odrelu2_v_array_uint64 = nullptr; }
    odrelu2_vector_size_uint64 = 0;
}

void ecall_odrelu_gen_shared_randomness_final_uint64_v2(uint64_t seed, uint64_t vector_size, uint64_t xi) {
    ecall_odrelu_reset_uint64_v2();
    if (vector_size > 1024 * 1024 * 100) return;

    odrelu2_a_array_uint64 = new uint64_t[vector_size];
    odrelu2_b_array_uint64 = new uint64_t[vector_size];
    odrelu2_r0_array_uint64 = new uint64_t[vector_size];
    odrelu2_r1_array_uint64 = new uint64_t[vector_size];
    odrelu2_v_array_uint64 = new uint64_t[vector_size];
    odrelu2_vector_size_uint64 = vector_size;

    uint64_t gen_size = vector_size * 5;
    uint64_t* raw_rand = new uint64_t[gen_size];
    generate_consistent_random_64(raw_rand, gen_size, seed);

    uint64_t two_xi = 2 * xi;

    for (uint64_t i = 0; i < vector_size; i++) {
        uint64_t r_sign = raw_rand[5*i + 0];
        uint64_t r_val1 = raw_rand[5*i + 1];
        uint64_t r_val2 = raw_rand[5*i + 2];
        uint64_t r_r0   = raw_rand[5*i + 3];
        uint64_t r_r1   = raw_rand[5*i + 4];

        bool is_positive = (r_sign % 2 == 0);

        uint64_t v1 = (r_val1 % (two_xi - 1)) + 1;
        uint64_t v2 = (r_val2 % (two_xi - 1)) + 1;

        while (v1 == v2) {
            v2 = (v2 + 1) % (two_xi - 1) + 1;
        }

        uint64_t abs_a = (v1 > v2) ? v1 : v2;
        uint64_t abs_b = (v1 > v2) ? v2 : v1;

        if (is_positive) {
            odrelu2_a_array_uint64[i] = abs_a;
            odrelu2_b_array_uint64[i] = abs_b;
            odrelu2_v_array_uint64[i] = 0;
        } else {
            odrelu2_a_array_uint64[i] = 0 - abs_a;
            odrelu2_b_array_uint64[i] = 0 - abs_b;
            odrelu2_v_array_uint64[i] = 1;
        }

        odrelu2_r0_array_uint64[i] = r_r0;
        odrelu2_r1_array_uint64[i] = r_r1;
    }

    delete[] raw_rand;
}

void ecall_odrelu_tee1_step1_uint64_v2(uint64_t vector_size, const uint64_t* x1_minus_r2, uint64_t* result) {
    if (!odrelu2_a_array_uint64 || !odrelu2_r0_array_uint64) return;

    for (uint64_t i = 0; i < vector_size; i++) {
        uint64_t temp = odrelu2_a_array_uint64[i] * x1_minus_r2[i];
        result[i] = temp - odrelu2_r0_array_uint64[i];
    }
}

void ecall_odrelu_tee1_step2_uint64_v2(uint64_t vector_size, const uint64_t* z_plus_r3, uint64_t* result) {
    if (!odrelu2_r1_array_uint64 || !odrelu2_v_array_uint64) return;

    for (uint64_t i = 0; i < vector_size; i++) {
        if (odrelu2_v_array_uint64[i] == 0) {
            result[i] = z_plus_r3[i] + odrelu2_r1_array_uint64[i];
        } else {
            result[i] = 1ULL - z_plus_r3[i] + odrelu2_r1_array_uint64[i];
        }
    }
}

void generate_consistent_random_64(uint64_t* array, uint64_t count, uint64_t seed) {
    uint64_t state = seed;
    const uint64_t MULTIPLIER = 6364136223846793005ULL;
    const uint64_t INCREMENT = 1442695040888963407ULL;

    for (uint64_t i = 0; i < count; i++) {
        state = state * MULTIPLIER + INCREMENT;
        array[i] = state;
        if (array[i] == 0) array[i] = 1; 
    }
}
