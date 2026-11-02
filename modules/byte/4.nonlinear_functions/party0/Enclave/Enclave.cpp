#define EIGEN_DONT_VECTORIZE
#define EIGEN_DISABLE_UNALIGNED_ARRAY_ASSERT
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <random>
#include "Enclave.h"
#include "Enclave_t.h"
#include <cstdio>
#include "sgx_trts.h"


#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif

namespace std {
    
    int rand() {
        unsigned int val;
        
        sgx_status_t status = sgx_read_rand((unsigned char*)&val, sizeof(val));
        if (status != SGX_SUCCESS) {
            return 0; 
        }
        
        return (int)(val % (RAND_MAX + 1)); 
    }

    
    void srand(unsigned int seed) {
        (void)seed; 
    }
}
using namespace std;
#include <sstream>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#include <string>
#include <sstream>


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

void ecall_smp_tee1_computation_64(uint64_t count, uint64_t start_idx, const uint64_t* x1_plus_r1, const uint64_t* y1_plus_r2, uint64_t* result) {
    for (uint64_t i = 0; i < count; i++) {
        
        __int128 term1 = (__int128)smp_b_array_64[i] * x1_plus_r1[i];
        __int128 term2 = (__int128)smp_a_array_64[i] * y1_plus_r2[i];
        __int128 computation = -term1 - term2 + smp_r0_array_64[i];
        
        
        result[i] = (uint64_t)computation;
    }
    
}

static uint64_t* sq_a_array_64 = nullptr;       
static uint64_t* sq_r0_array_64 = nullptr;      
static uint64_t sq_vector_size_64 = 0;


void ecall_square_reset_64() {
    if (sq_a_array_64) delete[] sq_a_array_64;
    if (sq_r0_array_64) delete[] sq_r0_array_64;
    
    sq_a_array_64 = nullptr;
    sq_r0_array_64 = nullptr;
    sq_vector_size_64 = 0;
}


void ecall_square_gen_a_r0_64(uint64_t seed, uint64_t count) {
    
    ecall_square_reset_64();
    
    
    if (count == 0 || count > 1024 * 1024 * 100) { 
        ocall_print_string("[ENCLAVE] Invalid vector size for square protocol\n");
        return;
    }

    
    try {
        sq_a_array_64 = new uint64_t[count];
        sq_r0_array_64 = new uint64_t[count];
        sq_vector_size_64 = count;
    } catch (const std::bad_alloc& e) {
        ocall_print_string("[ENCLAVE] Memory allocation failed for square protocol\n");
        ecall_square_reset_64();
        return;
    }
    
    
    generate_consistent_random_64(sq_a_array_64, count, seed);     
    generate_consistent_random_64(sq_r0_array_64, count, seed + 1); 
}
void ecall_sq_tee1_computation_64(uint64_t count, uint64_t start_idx, const uint64_t* x1_plus_r1, uint64_t* result) {

    for (uint64_t i = 0; i < count; i++) {
        
        __int128 two_a = (__int128)2 * sq_a_array_64[i];
        __int128 term = two_a * x1_plus_r1[i];
        __int128 computation = -term + sq_r0_array_64[i];
        
        
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
    if (count > smp3_vector_size_64) return;

    
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
                                     
    if (!smp3_a_array_64 || !smp3_b_array_64 || !smp3_c_array_64 || !smp3_r0_array_64 || !smp3_m3_array_64) return;
    if (count > smp3_vector_size_64) return;

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


static uint64_t* cube_opt_a_array = nullptr;
static uint64_t* cube_opt_r0_array = nullptr;
static uint64_t* cube_opt_m3_buffer = nullptr; 

static uint64_t cube_opt_vector_size = 0;


void ecall_cube_opt_reset_64() {
    if (cube_opt_a_array) delete[] cube_opt_a_array;
    if (cube_opt_r0_array) delete[] cube_opt_r0_array;
    if (cube_opt_m3_buffer) delete[] cube_opt_m3_buffer;
    
    cube_opt_a_array = nullptr;
    cube_opt_r0_array = nullptr;
    cube_opt_m3_buffer = nullptr;
    cube_opt_vector_size = 0;
}


void ecall_cube_opt_gen_params_64(uint64_t seed, uint64_t count) {
    
    ecall_cube_opt_reset_64();
    
    
    if (count > 1024 * 1024 * 100) return; 
    cube_opt_a_array = new uint64_t[count];
    cube_opt_r0_array = new uint64_t[count];
    cube_opt_vector_size = count;
    
    
    generate_consistent_random_64(cube_opt_a_array, count, seed);     
    generate_consistent_random_64(cube_opt_r0_array, count, seed + 1); 
}




void ecall_cube_opt_step1_m3_64(uint64_t count, const uint64_t* x_plus_r1) {
    
    if (!cube_opt_a_array) return;
    if (count > cube_opt_vector_size) return;

    
    if (cube_opt_m3_buffer) delete[] cube_opt_m3_buffer;
    cube_opt_m3_buffer = new uint64_t[count];

    for (uint64_t i = 0; i < count; i++) {
        
        uint64_t a = cube_opt_a_array[i];
        uint64_t a2 = a * a;
        uint64_t coeff = 3 * a2; 

        
        cube_opt_m3_buffer[i] = coeff * x_plus_r1[i];
    }
}




void ecall_cube_opt_step2_final_64(uint64_t count,
                                   const uint64_t* V, 
                                   uint64_t* final_result) {
                                     
    if (!cube_opt_a_array || !cube_opt_r0_array || !cube_opt_m3_buffer) return;
    if (count > cube_opt_vector_size) return;

    for (uint64_t i = 0; i < count; i++) {
        
        uint64_t a = cube_opt_a_array[i];
        uint64_t coeff = 3 * a;
        
        
        uint64_t m4 = 0 - (coeff * V[i]);
        
        
        final_result[i] = cube_opt_m3_buffer[i] + m4 + cube_opt_r0_array[i];
    }
    
    
    delete[] cube_opt_m3_buffer;
    cube_opt_m3_buffer = nullptr;
}


static uint64_t* xy2_a_array = nullptr;
static uint64_t* xy2_b_array = nullptr;
static uint64_t* xy2_r0_array = nullptr;
static uint64_t* xy2_mlin_buffer = nullptr; 

static uint64_t xy2_vector_size = 0;

void ecall_xy2_opt_reset_64() {
    if (xy2_a_array) delete[] xy2_a_array;
    if (xy2_b_array) delete[] xy2_b_array;
    if (xy2_r0_array) delete[] xy2_r0_array;
    if (xy2_mlin_buffer) delete[] xy2_mlin_buffer;
    
    xy2_a_array = nullptr; xy2_b_array = nullptr;
    xy2_r0_array = nullptr; xy2_mlin_buffer = nullptr;
    xy2_vector_size = 0;
}


void ecall_xy2_opt_gen_params_64(uint64_t seed, uint64_t count) {
    ecall_xy2_opt_reset_64();
    if (count > 1024 * 1024 * 100) return; 
    
    xy2_a_array = new uint64_t[count];
    xy2_b_array = new uint64_t[count];
    xy2_r0_array = new uint64_t[count];
    xy2_vector_size = count;
    
    
    generate_consistent_random_64(xy2_a_array, count, seed);
    generate_consistent_random_64(xy2_b_array, count, seed + 1);
    generate_consistent_random_64(xy2_r0_array, count, seed + 2);
}


void ecall_xy2_opt_step1_64(uint64_t count, const uint64_t* x_plus_r1, const uint64_t* y_plus_r2) {
    if (!xy2_a_array) return;
    if (count > xy2_vector_size) return;

    if (xy2_mlin_buffer) delete[] xy2_mlin_buffer;
    xy2_mlin_buffer = new uint64_t[count];

    for (uint64_t i = 0; i < count; i++) {
        uint64_t a = xy2_a_array[i];
        uint64_t b = xy2_b_array[i];
        uint64_t b2 = b * b;
        uint64_t ab2 = 2 * a * b; 

        
        xy2_mlin_buffer[i] = (b2 * x_plus_r1[i]) + (ab2 * y_plus_r2[i]);
    }
}


void ecall_xy2_opt_step2_final_64(uint64_t count, 
                                  const uint64_t* V_xy, 
                                  const uint64_t* V_yy, 
                                  uint64_t* final_result) {
    if (!xy2_a_array || !xy2_mlin_buffer) return;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t a = xy2_a_array[i];
        uint64_t b = xy2_b_array[i];
        uint64_t b2_coeff = 2 * b;

        
        uint64_t m_quad = 0 - (b2_coeff * V_xy[i]) - (a * V_yy[i]);
        
        
        final_result[i] = xy2_mlin_buffer[i] + m_quad + xy2_r0_array[i];
    }
    delete[] xy2_mlin_buffer; xy2_mlin_buffer = nullptr;
}



static uint64_t* odrelu_a_array_uint64 = nullptr;
static uint64_t* odrelu_b_array_uint64 = nullptr;
static uint64_t* odrelu_r0_array_uint64 = nullptr;
static uint64_t* odrelu_r1_array_uint64 = nullptr;
static uint64_t* odrelu_v_array_uint64 = nullptr;
static uint64_t odrelu_vector_size_uint64 = 0;
static const uint64_t ODRELU_L_UINT64 = UINT64_MAX;

void ecall_odrelu_reset_uint64() {
    if (odrelu_a_array_uint64) delete[] odrelu_a_array_uint64;
    if (odrelu_b_array_uint64) delete[] odrelu_b_array_uint64;
    if (odrelu_r0_array_uint64) delete[] odrelu_r0_array_uint64;
    if (odrelu_r1_array_uint64) delete[] odrelu_r1_array_uint64;
    if (odrelu_v_array_uint64) delete[] odrelu_v_array_uint64;
    
    odrelu_a_array_uint64 = nullptr;
    odrelu_b_array_uint64 = nullptr;
    odrelu_r0_array_uint64 = nullptr;
    odrelu_r1_array_uint64 = nullptr;
    odrelu_v_array_uint64 = nullptr;
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





static uint64_t* odrelu2_a_array_uint64  = nullptr;
static uint64_t* odrelu2_b_array_uint64  = nullptr;
static uint64_t* odrelu2_r0_array_uint64 = nullptr;
static uint64_t* odrelu2_r1_array_uint64 = nullptr;
static uint64_t* odrelu2_v_array_uint64  = nullptr;
static uint64_t  odrelu2_vector_size_uint64 = 0;

void ecall_odrelu_reset_uint64_v2() {
    if (odrelu2_a_array_uint64)  delete[] odrelu2_a_array_uint64;
    if (odrelu2_b_array_uint64)  delete[] odrelu2_b_array_uint64;
    if (odrelu2_r0_array_uint64) delete[] odrelu2_r0_array_uint64;
    if (odrelu2_r1_array_uint64) delete[] odrelu2_r1_array_uint64;
    if (odrelu2_v_array_uint64)  delete[] odrelu2_v_array_uint64;
    odrelu2_a_array_uint64  = nullptr;
    odrelu2_b_array_uint64  = nullptr;
    odrelu2_r0_array_uint64 = nullptr;
    odrelu2_r1_array_uint64 = nullptr;
    odrelu2_v_array_uint64  = nullptr;
    odrelu2_vector_size_uint64 = 0;
}

void ecall_odrelu_gen_shared_randomness_final_uint64_v2(uint64_t seed, uint64_t vector_size, uint64_t xi) {
    ecall_odrelu_reset_uint64_v2();
    if (vector_size > 1024 * 1024 * 100) return;

    odrelu2_a_array_uint64  = new uint64_t[vector_size];
    odrelu2_b_array_uint64  = new uint64_t[vector_size];
    odrelu2_r0_array_uint64 = new uint64_t[vector_size];
    odrelu2_r1_array_uint64 = new uint64_t[vector_size];
    odrelu2_v_array_uint64  = new uint64_t[vector_size];
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
        while (v1 == v2) { v2 = (v2 + 1) % (two_xi - 1) + 1; }

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
        result[i] = odrelu2_a_array_uint64[i] * x1_minus_r2[i] - odrelu2_r0_array_uint64[i];
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


void generateRandomArray_64(uint64_t* array, int size, int seed) {
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<uint64_t> dis(0, 100);
    
    for (int i = 0; i < size; i++) {
        array[i] = dis(gen);
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





static std::vector<uint64_t> g_batch_A;
static std::vector<uint64_t> g_batch_B;
static std::vector<uint64_t> g_batch_R0;

#include <algorithm> 


#define BLOCK_SIZE 32 


static void mat_mul_acc(const uint64_t* A, const uint64_t* B, uint64_t* C, int m, int k, int n) {
    
    
    
    for (int i0 = 0; i0 < m; i0 += BLOCK_SIZE) {
        for (int p0 = 0; p0 < k; p0 += BLOCK_SIZE) {
            for (int j0 = 0; j0 < n; j0 += BLOCK_SIZE) {
                
                
                int i_max = std::min(i0 + BLOCK_SIZE, m);
                int p_max = std::min(p0 + BLOCK_SIZE, k);
                int j_max = std::min(j0 + BLOCK_SIZE, n);

                
                for (int i = i0; i < i_max; i++) {
                    for (int p = p0; p < p_max; p++) {
                        
                        
                        uint64_t val_A = A[i * k + p]; 
                        
                        
                        
                        #pragma unroll 
                        for (int j = j0; j < j_max; j++) {
                            C[i * n + j] += val_A * B[p * n + j];
                        }
                    }
                }
            }
        }
    }
}


static void mat_mul_acc_naive(const uint64_t* A, const uint64_t* B, uint64_t* C, int m, int k, int n) {
    
    for (int i = 0; i < m; i++) {
        
        for (int p = 0; p < k; p++) {
            
            uint64_t val_A = A[i * k + p];
            
            
            for (int j = 0; j < n; j++) {
                
                C[i * n + j] += val_A * B[p * n + j];
            }
        }
    }
}

void ecall_matrix_batch_init(uint64_t seedT, int m, int k, int n, int count) {
    size_t sz_A = (size_t)m * k * count;
    size_t sz_B = (size_t)k * n * count;
    size_t sz_R0 = (size_t)m * n * count;

    g_batch_A.resize(sz_A);
    g_batch_B.resize(sz_B);
    g_batch_R0.resize(sz_R0);

    generate_consistent_random_64(g_batch_A.data(), sz_A, seedT);
    generate_consistent_random_64(g_batch_B.data(), sz_B, seedT + 1);
    generate_consistent_random_64(g_batch_R0.data(), sz_R0, seedT + 2);
}


void ecall_matrix_batch_compute(
    int m, int k, int n, int count,
    const uint64_t* X_batch, size_t len_x,
    const uint64_t* Y_batch, size_t len_y,
    uint64_t* Tout_batch, size_t len_z
) {
    size_t stride_X = (size_t)m * k;
    size_t stride_Y = (size_t)k * n;
    size_t stride_Z = (size_t)m * n;

    
    for (int i = 0; i < count; i++) {
        
        const uint64_t* cur_X = X_batch + i * stride_X;
        const uint64_t* cur_Y = Y_batch + i * stride_Y;
        const uint64_t* cur_A = g_batch_A.data() + i * stride_X;
        const uint64_t* cur_B = g_batch_B.data() + i * stride_Y;
        const uint64_t* cur_R0 = g_batch_R0.data() + i * stride_Z;
        uint64_t* cur_Tout = Tout_batch + i * stride_Z;

        
        std::vector<uint64_t> Term1(stride_Z, 0);
        mat_mul_acc(cur_X, cur_B, Term1.data(), m, k, n);

        
        std::vector<uint64_t> Term2(stride_Z, 0);
        mat_mul_acc(cur_A, cur_Y, Term2.data(), m, k, n);

        
        for (size_t j = 0; j < stride_Z; j++) {
            cur_Tout[j] = cur_R0[j] - Term1[j] - Term2[j];
        }
    }
}
static const uint64_t SEED_A0 = 12345;
static const uint64_t SEED_A1 = 67890;
static const uint64_t SEED_B0 = 9999;
static const uint64_t SEED_B1 = 8888;
static const uint64_t SEED_COMMON = 55555; 
void ecall_tee0_master_compute(
    int m, int k, int n, int count,
    uint64_t* batch_C0, size_t len_C  
) {
    size_t sz_A = (size_t)m * k;
    size_t sz_B = (size_t)k * n;
    size_t sz_C = (size_t)m * n;

    
    if (len_C < sz_C * count * sizeof(uint64_t)) {
        return; 
    }

    
    size_t num_elements_C = len_C / sizeof(uint64_t);

    std::vector<uint64_t> A_full(sz_A);
    std::vector<uint64_t> B_full(sz_B);
    std::vector<uint64_t> Temp_Share(std::max(sz_A, sz_B)); 
    std::vector<uint64_t> C_real(sz_C);

    
    
    generate_consistent_random_64(batch_C0, num_elements_C, SEED_COMMON);

    for (int b = 0; b < count; b++) {
        
        generate_consistent_random_64(A_full.data(), sz_A, SEED_A0 + b);
        generate_consistent_random_64(Temp_Share.data(), sz_A, SEED_A1 + b);
        for(size_t i=0; i<sz_A; i++) A_full[i] += Temp_Share[i];

        
        generate_consistent_random_64(B_full.data(), sz_B, SEED_B0 + b);
        generate_consistent_random_64(Temp_Share.data(), sz_B, SEED_B1 + b);
        for(size_t i=0; i<sz_B; i++) B_full[i] += Temp_Share[i];

        
        std::fill(C_real.begin(), C_real.end(), 0); 
        mat_mul_acc(A_full.data(), B_full.data(), C_real.data(), m, k, n);

        
        
        uint64_t* ptr_C0 = batch_C0 + b * sz_C; 
        for(size_t i=0; i<sz_C; i++) {
            ptr_C0[i] = C_real[i] - ptr_C0[i]; 
        }
    }
}


static const uint64_t SEED_T0 = 12345;
static const uint64_t SEED_T1 = 67890;
static const uint64_t SEED_U0 = 9999;
static const uint64_t SEED_V0 = 8888;


void generate_and_map_random(uint64_t* target_buf, uint64_t count, uint64_t seed, uint64_t scale, int bound_coeff) {
    uint64_t state = seed;
    const uint64_t MULTIPLIER = 6364136223846793005ULL;
    const uint64_t INCREMENT = 1442695040888963407ULL;
    uint64_t range_width = (uint64_t)bound_coeff * scale * 2;
    uint64_t offset = (uint64_t)bound_coeff * scale;

    for (uint64_t i = 0; i < count; i++) {
        state = state * MULTIPLIER + INCREMENT;
        uint64_t raw_val = state;
        if (raw_val == 0) raw_val = 1;
        uint64_t mod_val = raw_val % range_width;
        int64_t signed_val = (int64_t)mod_val - (int64_t)offset;
        target_buf[i] = (uint64_t)signed_val; 
    }
}

void ecall_csp0_generate_shares(
    int size, int b_len, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv
) {
    
    generate_and_map_random(u0_buf, len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(v0_buf, len_uv, SEED_V0, scale_factor, 1);
}
void ecall_csp0_generate_sigmoid_shares_internal(
    int size, 
    int k1, 
    int k2, 
    uint64_t scale_factor,
    uint64_t* u0_buf, 
    uint64_t* v0_buf, 
    int len_uv
) {
    
    
    generate_and_map_random(u0_buf, len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(v0_buf, len_uv, SEED_V0, scale_factor, 1);
}





static const uint64_t sigmoid_B_0_6[] = { 
    595794, 18446744073709455121ULL, 131565, 18446744073709474133ULL, 68443, 18446744073709496503ULL 
};
static const uint64_t sigmoid_B_0_12[] = { 
    595794, 18446744073709455121ULL, 131565, 18446744073709474133ULL, 68443, 18446744073709496503ULL,
    47800, 18446744073709509944ULL, 37073, 18446744073709513667ULL, 30323, 18446744073709519218ULL
};


static const uint64_t sigmoid_B_1_1[] = { 307931 };
static const uint64_t sigmoid_B_1_4[] = { 260979, 70911, 19960, 6224 };
static const uint64_t sigmoid_B_1_5[] = { 262598, 70102, 20500, 5819, 1805 };
static const uint64_t sigmoid_B_1_6[] = { 262128, 70336, 20343, 5937, 1711, 516 };
static const uint64_t sigmoid_B_1_12[] = { 
    262243, 70279, 20381, 5908, 1733, 497, 150, 40, 14, 3, 2, 18446744073709551615ULL 
};


static const uint64_t sigmoid_B_2_1[] = { 861074 };
static const uint64_t sigmoid_B_2_6[] = { 230511, 74197, 19245, 6373, 1505, 623 };
static const uint64_t sigmoid_B_2_12[] = { 
    260771, 70462, 20328, 5930, 1722, 503, 146, 43, 12, 4, 1, 0 
};
static const uint64_t sigmoid_B_3_12[] = {
    17197, 18446744073707959095ULL, 18446744073708743198ULL, 2077890,
    18446744073707410011ULL, 1700399, 18446744073708472140ULL, 574725,
    18446744073709304346ULL, 85052, 18446744073709530860ULL, 3136
};


const uint64_t* get_internal_sigmoid_b(int k1, int k2) {
    if (k1 == 0) {
        if (k2 == 6) return sigmoid_B_0_6;
        if (k2 == 12) return sigmoid_B_0_12;
    } else if (k1 == 1) {
        if (k2 == 1) return sigmoid_B_1_1;
        if (k2 == 4) return sigmoid_B_1_4;
        if (k2 == 5) return sigmoid_B_1_5;
        if (k2 == 6) return sigmoid_B_1_6;
        if (k2 == 12) return sigmoid_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 1) return sigmoid_B_2_1;
        if (k2 == 6) return sigmoid_B_2_6;
        if (k2 == 12) return sigmoid_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return sigmoid_B_3_12;
    }
    return sigmoid_B_1_6; 
}

static double get_internal_sigmoid_L_const(int k1, int k2) {
    if (k1 == 3 && k2 == 12) return 14.0;
    return 8.0;
}
void ecall_csp0_calculate_sigmoid_shares_optimized(
    int size, 
    int k1, 
    int k2, 
    uint64_t scale_factor,
    uint64_t* u0_buf, 
    uint64_t* v0_buf, 
    int len_uv
) {
    
    const uint64_t* b_coeffs = get_internal_sigmoid_b(k1, k2);
    int b_len = k2;
    int mid = b_len / 2; 

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, SEED_T0, scale_factor, 100);
    generate_and_map_random(t1.data(), size, SEED_T1, scale_factor, 100);

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, SEED_V0, scale_factor, 1);

    const double L_float = get_internal_sigmoid_L_const(k1, k2);

    for (int k = 0; k < b_len; k++) {
        
        
        
        if (k < mid) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        }
        
        
        else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;

            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);

                
                double u1_val = (int64_t)random_u[k*size + i] / (double)scale_factor;
                double v1_val = (int64_t)random_v[k*size + i] / (double)scale_factor;

                
                double u0_real = target_sin - u1_val;
                double v0_real = target_cos - v1_val;

                u0_buf[k*size + i] = static_cast<uint64_t>(u0_real * scale_factor);
                v0_buf[k*size + i] = static_cast<uint64_t>(v0_real * scale_factor);
            }
        }
    }
}
void ecall_csp0_generate_tanh_shares_internal(
    int size, 
    int k1, 
    int k2, 
    uint64_t scale_factor,
    uint64_t* u0_buf, 
    uint64_t* v0_buf, 
    int len_uv
) {
    
    
    generate_and_map_random(u0_buf, len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(v0_buf, len_uv, SEED_V0, scale_factor, 1);
}






static const uint64_t TANH_B_0_1[] = { 1294561 };
static const uint64_t TANH_B_0_6[] = { 1294561, 18446744073709479896ULL, 355212, 18446744073709455078ULL, 171276, 18446744073709460711ULL };
static const uint64_t TANH_B_0_12[] = {
    1294561, 18446744073709479896ULL, 355212, 18446744073709455078ULL, 171276, 18446744073709460711ULL,
    106339, 18446744073709474098ULL, 77366, 18446744073709486589ULL, 61614, 18446744073709496493ULL
};


static const uint64_t TANH_B_1_1[] = { 780363 };
static const uint64_t TANH_B_1_6[] = { 620141, 265490, 130407, 72066, 36393, 21497 };
static const uint64_t TANH_B_1_9[] = { 628101, 261509, 133060, 70076, 37985, 20170, 11132, 5788, 3317 };
static const uint64_t TANH_B_1_12[] = {
    615294, 244370, 115225, 56309, 27747, 13702, 6771, 3342, 1656, 812, 409, 193
};


static const uint64_t TANH_B_2_1[] = { 2826141 };
static const uint64_t TANH_B_2_6[] = { 
    18446744073708134600ULL, 514183, 59658, 100177, 23143, 28357 
}; 
static const uint64_t TANH_B_2_12[] = {
    433406, 286165, 125597, 73317, 36264, 21210, 10446, 6273, 2956, 1895, 806, 595
};
static const uint64_t TANH_B_3_12[] = {
    597468, 220209, 93775, 40982, 17976, 7893, 3478, 1518, 669, 300, 125, 50
};



static const uint64_t INVSQRT_STEEP_1_8_B[] = {
    18446744073708257638ULL, 18446744073708999558ULL, 18446744073709249300ULL, 18446744073709349212ULL, 18446744073709420674ULL, 18446744073709453125ULL,
    18446744073709486009ULL, 18446744073709499693ULL
};


static const uint64_t INVSQRT_STEEP_1_12_B[] = {
    18446744073708011611ULL, 18446744073708768491ULL, 18446744073709166779ULL, 18446744073709235077ULL, 18446744073709370663ULL, 18446744073709378535ULL,
    18446744073709449653ULL, 18446744073709445035ULL, 18446744073709488903ULL, 18446744073709481233ULL, 18446744073709508142ULL, 18446744073709495279ULL
};

static const uint64_t INVSQRT_STEEP_2_12_B[] = {
    256614962, 18446744073708974587ULL, 8804174, 18446744073709333994ULL, 1647286, 18446744073709440013ULL,
    482569, 18446744073709486706ULL, 164497, 18446744073709510001ULL, 50633, 18446744073709505364ULL
};


static const uint64_t INVSQRT_STEEP_3_12_B[] = {
    256614962, 18446744073708974587ULL, 8804174, 18446744073709333994ULL, 1647286, 18446744073709440013ULL,
    482569, 18446744073709486706ULL, 164497, 18446744073709510001ULL, 50633, 18446744073709505364ULL
};


static const uint64_t INVSQRT_FLAT_1_8_B[] = {
    18446744073709551219ULL, 115, 54, 18446744073709551347ULL, 1070, 617,
    18446744073709551430ULL, 2
};


static const uint64_t INVSQRT_FLAT_1_12_B[] = {
    18446744073709392100ULL, 18446744073709481456ULL, 18446744073709510276ULL, 18446744073709522219ULL, 18446744073709529047ULL, 18446744073709534751ULL,
    18446744073709538986ULL, 18446744073709540955ULL, 18446744073709541686ULL, 18446744073709543172ULL, 18446744073709544693ULL, 18446744073709546675ULL
};

static const uint64_t INVSQRT_FLAT_2_12_B[] = {
    18446744073709392032ULL, 18446744073709481390ULL, 18446744073709510185ULL, 18446744073709522128ULL, 18446744073709529025ULL, 18446744073709534735ULL,
    18446744073709538931ULL, 18446744073709540930ULL, 18446744073709541660ULL, 18446744073709543131ULL, 18446744073709544709ULL, 18446744073709546578ULL
};


static const uint64_t INVSQRT_FLAT_3_12_B[] = {
    18446744073709392100ULL, 18446744073709481456ULL, 18446744073709510276ULL, 18446744073709522219ULL, 18446744073709529047ULL, 18446744073709534751ULL,
    18446744073709538986ULL, 18446744073709540955ULL, 18446744073709541686ULL, 18446744073709543172ULL, 18446744073709544693ULL, 18446744073709546675ULL
};



static const uint64_t RECIP_STEEP_1_8_B[] = {
    18446744073705390564ULL, 18446744073707580372ULL, 18446744073708423472ULL, 18446744073708750666ULL, 18446744073709017682ULL, 18446744073709131966ULL,
    18446744073709264455ULL, 18446744073709315875ULL
};

static const uint64_t RECIP_STEEP_1_12_B[] = {
    18446744073703929147ULL, 18446744073706924146ULL, 18446744073707944001ULL, 18446744073708431294ULL, 18446744073708739547ULL, 18446744073708929201ULL,
    18446744073709076574ULL, 18446744073709175358ULL, 18446744073709261680ULL, 18446744073709322604ULL, 18446744073709379603ULL, 18446744073709437025ULL
};

static const uint64_t RECIP_STEEP_2_12_B[] = {
    18072361, 18446744073707477241ULL, 18446744073709093662ULL, 18446744073708672756ULL, 18446744073709103277ULL, 18446744073709092624ULL,
    18446744073709267888ULL, 18446744073709305407ULL, 18446744073709410287ULL, 18446744073709439180ULL, 18446744073709496594ULL, 18446744073709523952ULL
};

static const uint64_t RECIP_STEEP_3_12_B[] = {
    714535137, 91159492, 24347828, 10147358, 4479922, 2486683,
    1276906, 794953, 418005, 271291, 127898, 76473
};


static const uint64_t RECIP_FLAT_1_8_B[] = {
    18446744073709551458ULL, 47, 22, 18446744073709551507ULL, 365, 234,
    18446744073709551540ULL, 1
};


static const uint64_t RECIP_FLAT_1_12_B[] = {
    18446744073709509856ULL, 18446744073709531995ULL, 18446744073709539696ULL, 18446744073709543451ULL, 18446744073709545506ULL, 18446744073709546794ULL,
    18446744073709547749ULL, 18446744073709548572ULL, 18446744073709549359ULL, 18446744073709550127ULL, 18446744073709550689ULL, 18446744073709551117ULL
};

static const uint64_t RECIP_FLAT_2_12_B[] = {
    18446744073709509856ULL, 18446744073709531995ULL, 18446744073709539696ULL, 18446744073709543451ULL, 18446744073709545506ULL, 18446744073709546794ULL,
    18446744073709547749ULL, 18446744073709548572ULL, 18446744073709549359ULL, 18446744073709550127ULL, 18446744073709550689ULL, 18446744073709551117ULL
};

static const uint64_t RECIP_FLAT_3_12_B[] = {
    18446744073709509856ULL, 18446744073709531995ULL, 18446744073709539696ULL, 18446744073709543451ULL, 18446744073709545506ULL, 18446744073709546794ULL,
    18446744073709547749ULL, 18446744073709548572ULL, 18446744073709549359ULL, 18446744073709550127ULL, 18446744073709550689ULL, 18446744073709551117ULL
};


const uint64_t* get_internal_tanh_b(int k1, int k2) {
    if (k1 == 0) {
        if (k2 == 1) return TANH_B_0_1;
        if (k2 == 6) return TANH_B_0_6;
        if (k2 == 12) return TANH_B_0_12;
    } else if (k1 == 1) {
        if (k2 == 1) return TANH_B_1_1;
        if (k2 == 6) return TANH_B_1_6;
        if (k2 == 9) return TANH_B_1_9;
        if (k2 == 12) return TANH_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 1) return TANH_B_2_1;
        if (k2 == 6) return TANH_B_2_6;
        if (k2 == 12) return TANH_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return TANH_B_3_12;
    }
    return TANH_B_1_6; 
}

static double get_internal_tanh_L_const(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 7.0;
    if (k1 == 3 && k2 == 12) return 6.0;
    return 8.0;
}




void ecall_csp0_calculate_tanh_shares_optimized(
    int size, 
    int k1, 
    int k2, 
    uint64_t scale_factor,
    uint64_t* u0_buf, 
    uint64_t* v0_buf, 
    int len_uv
) {
    
    const uint64_t* b_coeffs = get_internal_tanh_b(k1, k2);
    int b_len = k2;
    int mid = b_len / 2; 

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, SEED_T0, scale_factor, 100);
    generate_and_map_random(t1.data(), size, SEED_T1, scale_factor, 100);

    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, SEED_V0, scale_factor, 1);

    const double L_float = get_internal_tanh_L_const(k1, k2);

    for (int k = 0; k < b_len; k++) {
        
        if (k < mid) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        }
        
        else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;

            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);

                
                double u1_val = (int64_t)random_u[k*size + i] / (double)scale_factor;
                double v1_val = (int64_t)random_v[k*size + i] / (double)scale_factor;

                
                double u0_real = target_sin - u1_val;
                double v0_real = target_cos - v1_val;

                u0_buf[k*size + i] = static_cast<uint64_t>(u0_real * scale_factor);
                v0_buf[k*size + i] = static_cast<uint64_t>(v0_real * scale_factor);
            }
        }
    }
}






static const uint64_t INVSQRT_B_0_1[] = { 180045 };
static const uint64_t INVSQRT_B_0_6[] = { 180045, 143822, 123579, 110219, 100537, 93095 };
static const uint64_t INVSQRT_B_0_12[] = { 
    180045, 143822, 123579, 110219, 100537, 93095,
    87136, 82221, 78074, 74513, 71409, 68672 
};


static const uint64_t INVSQRT_B_1_1[] = { 18446744073709192949ULL };
static const uint64_t INVSQRT_B_1_4_EX[] = { 
    309311829,              
    18446744073610605503ULL, 
    28266681,               
    18446744073704169271ULL  
};
static const uint64_t INVSQRT_B_1_9_INV[] = {
    18446744073708166137, 
    18446744073708991153, 
    18446744073709218830, 
    18446744073709345044, 
    18446744073709402429, 
    18446744073709450384, 
    18446744073709473017, 
    18446744073709497679, 
    18446744073709508276  
};
static const uint64_t INVSQRT_B_1_6[] = { 
    18446744073708616999ULL, 18446744073709138135ULL, 18446744073709303657ULL, 
    18446744073709383186ULL, 18446744073709429233ULL, 18446744073709458943ULL 
};
static const uint64_t INVSQRT_B_1_12[] = {
    18446744073707951128ULL, 18446744073708905266ULL, 18446744073709200638ULL, 18446744073709322176ULL,
    18446744073709387209ULL, 18446744073709436341ULL, 18446744073709474919ULL, 18446744073709498452ULL,
    18446744073709509287ULL, 18446744073709516778ULL, 18446744073709527423ULL, 18446744073709539370ULL
};


static const uint64_t INVSQRT_B_2_1[] = { 18446744073709109041ULL };
static const uint64_t INVSQRT_B_2_6[] = { 
    18446744073708519124ULL, 18446744073709124920ULL, 18446744073709299258ULL, 
    18446744073709381044ULL, 18446744073709427948ULL, 18446744073709458067ULL 
};
static const uint64_t INVSQRT_B_2_12[] = {
    262139902, 585496, 8453086, 298313,
    1388187, 170909, 330933, 95206,
    84781, 47871, 19522, 19516
};

static const uint64_t INVSQRT_B_3_12[] = {
    90935930, 10698460, 2894406, 1088570,
    486235, 239019, 122761, 63001,
    30958, 13971, 5592, 2013
};


const uint64_t* get_internal_invsqrt_b(int k1, int k2) {
    if (k1 == 0) {
        if (k2 == 1) return INVSQRT_B_0_1;
        if (k2 == 6) return INVSQRT_B_0_6;
        if (k2 == 12) return INVSQRT_B_0_12;
    } else if (k1 == 1) {
        if (k2 == 1) return INVSQRT_B_1_1;
        if (k2 == 4) return INVSQRT_B_1_4_EX;
        if (k2 == 9) return INVSQRT_B_1_9_INV;
        if (k2 == 6) return INVSQRT_B_1_6;
        if (k2 == 12) return INVSQRT_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 1) return INVSQRT_B_2_1;
        if (k2 == 6) return INVSQRT_B_2_6;
        if (k2 == 12) return INVSQRT_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return INVSQRT_B_3_12;
    }
    return INVSQRT_B_0_6; 
}





void ecall_csp0_calculate_invsqrt_shares_optimized(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv
) {
    const uint64_t* b_coeffs = get_internal_invsqrt_b(k1, k2);
    int b_len = k2;
    int mid = b_len / 2; 

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, SEED_T0, scale_factor, 100);
    generate_and_map_random(t1.data(), size, SEED_T1, scale_factor, 100);

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, SEED_V0, scale_factor, 1);

    const double L_float = get_internal_sigmoid_L_const(k1, k2);

    for (int k = 0; k < b_len; k++) {
        
        if (k < mid) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        }
        
        else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;

            for (int i = 0; i < size; i++) {
                
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                
                
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);

                
                double u1_val = (int64_t)random_u[k*size + i] / (double)scale_factor;
                double v1_val = (int64_t)random_v[k*size + i] / (double)scale_factor;

                double u0_real = target_sin - u1_val;
                double v0_real = target_cos - v1_val;

                u0_buf[k*size + i] = (uint64_t)((int64_t)(u0_real * scale_factor));
                v0_buf[k*size + i] = (uint64_t)((int64_t)(v0_real * scale_factor));
            }
        }
    }
}




void ecall_csp0_generate_invsqrt_shares_internal(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv
) {
    generate_and_map_random(u0_buf, len_uv, SEED_U0, scale_factor, 1);
    generate_and_map_random(v0_buf, len_uv, SEED_V0, scale_factor, 1);
}
static const double GELU_BETA[] = {
    -0.0818, -0.0809, -0.0424, -0.0176, 
    -0.0079, -0.0043, -0.0026, -0.0017
};
static const int GELU_TERMS = 8;
static const double GELU_L = 8.0; 

void ecall_csp0_gelu_shares_opt(
    int size, 
    uint64_t scale_factor,
    uint64_t* u0_buf, 
    uint64_t* v0_buf
) {
    int b_len = GELU_TERMS; 
    int mid = b_len / 2;    

    
    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 11111, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 22222, scale_factor, 100);

    
    
    std::vector<uint64_t> random_u(size * b_len), random_v(size * b_len);
    generate_and_map_random(random_u.data(), size * b_len, 33333, scale_factor, 1);
    generate_and_map_random(random_v.data(), size * b_len, 44444, scale_factor, 1);

    for (int k = 0; k < b_len; k++) {
        
        
        
        if (k < mid) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        }
        
        
        else {
            
            double K_val = M_PI * (k + 1) / GELU_L;
            double beta_val = GELU_BETA[k];

            for (int i = 0; i < size; i++) {
                
                
                
                double T_val = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * T_val;

                
                double target_sin = beta_val * sin(angle);
                double target_cos = beta_val * cos(angle);

                
                
                double r_u = (int64_t)random_u[k*size + i] / (double)scale_factor;
                double r_v = (int64_t)random_v[k*size + i] / (double)scale_factor;

                
                double u0_real = target_sin - r_u;
                double v0_real = target_cos - r_v;

                
                u0_buf[k*size + i] = (uint64_t)(u0_real * scale_factor);
                v0_buf[k*size + i] = (uint64_t)(v0_real * scale_factor);
            }
        }
    }
}

void ecall_calculate_sigmoid_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_internal_sigmoid_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2; 
    int mid_size = size / 2; 
    int s_shift = 20;        

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 12345, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100); 
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i]; 
            } else {
                t2_buf[i] = mask_t2[i]; 
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i]; 
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = get_internal_sigmoid_L_const(k1, k2);
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) { 
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else { 
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}
void ecall_calculate_tanh_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_internal_tanh_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2; 
    int mid_size = size / 2; 
    int s_shift = 20;        

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 12345, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100); 
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i]; 
            } else {
                t2_buf[i] = mask_t2[i]; 
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i]; 
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = get_internal_tanh_L_const(k1, k2);
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) { 
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else { 
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}

static const uint64_t ERF_B_1_6[] = {
    18446744073668382450ULL, 16780447, 18446744073702420757ULL,
    3040859, 18446744073708628600ULL, 246039
};
static const uint64_t ERF_B_1_8[] = {
    18446744073625986879ULL, 35350416, 18446744073692600342ULL, 8241410,
    18446744073706082381ULL, 1324353, 18446744073709191618ULL, 77662
};
static const uint64_t ERF_B_1_9[] = {
    105415858, 18446744073665394696ULL, 22566719,
    18446744073698405973ULL, 5287341, 18446744073707414385ULL,
    768512, 18446744073709354824ULL, 38766
};
static const uint64_t ERF_B_1_12[] = {
    18446744073598274300ULL, 49622739, 18446744073683107102ULL, 14839194,
    18446744073701673832ULL, 4031025, 18446744073707713113ULL, 774196,
    18446744073709279437ULL, 83334, 18446744073709533598ULL, 2865
};
static const uint64_t ERF_B_2_12[] = {
    18446744073598274300ULL, 49622739, 18446744073683107102ULL, 14839194,
    18446744073701673832ULL, 4031025, 18446744073707713113ULL, 774196,
    18446744073709279437ULL, 83334, 18446744073709533598ULL, 2865
};
static const uint64_t ERF_B_3_12[] = {
    322297, 37785370, 18446744073685762552ULL, 14088117,
    18446744073701899376ULL, 3965340, 18446744073707730410ULL, 770401,
    18446744073709280032ULL, 83299, 18446744073709533587ULL, 2867
};


const uint64_t* get_internal_erf_b(int k1, int k2) {
    if (k1 == 1) {
        if (k2 == 6) return ERF_B_1_6;
        if (k2 == 8) return ERF_B_1_8;
        if (k2 == 9) return ERF_B_1_9;
        if (k2 == 12) return ERF_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 12) return ERF_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return ERF_B_3_12;
    }
    return ERF_B_1_12; 
}

void ecall_calculate_erf_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_internal_erf_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2; 
    int mid_size = size / 2; 
    int s_shift = 20;        

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 12345, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100); 
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i]; 
            } else {
                t2_buf[i] = mask_t2[i]; 
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i]; 
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = 8.0;
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) { 
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else { 
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}


static const uint64_t EXP_B_1_8[] = {
    18446744073709548721ULL, 18446744073709527788ULL, 18446744073709534234ULL, 340,
    13884, 14698, 9387, 4809
};
static const uint64_t EXP_B_1_9[] = {
    18446744073709548739ULL, 18446744073709527827ULL, 18446744073709534192ULL, 679,
    14091, 13869, 8360, 5544, 18446744073709549454ULL
};
static const uint64_t EXP_B_1_12[] = {
    423940, 174451, 86830, 45304,
    23893, 12524, 6427, 3181,
    1485, 630, 232, 60
};
static const uint64_t EXP_B_2_12[] = {
    423940, 174451, 86830, 45304,
    23893, 12524, 6427, 3181,
    1485, 630, 232, 60
};
static const uint64_t EXP_B_3_12[] = {
    18446744073699805688ULL, 18446744073708522107ULL, 18446744073709316522ULL, 18446744073709480615ULL,
    18446744073709527135ULL, 18446744073709542592ULL, 18446744073709548196ULL, 18446744073709550326ULL,
    18446744073709551148ULL, 18446744073709551459ULL, 18446744073709551571ULL, 18446744073709551607ULL
};



static const uint64_t EXP_G1_A_1_8[] = { 1039111, 172250 };
static const uint64_t EXP_G1_B_1_8[] = {
    519519, 152972, 63828, 33781,
    15550, 5841, 5263, 10959
};
static const uint64_t EXP_G1_A_1_9[] = { 1040534, 172684 };
static const uint64_t EXP_G1_B_1_9[] = {
    520726, 154572, 62931, 30876,
    17039, 9576, 3502, 3486,
    8230
};
static const uint64_t EXP_G1_A_1_12[] = { 1040558, 172628 };
static const uint64_t EXP_G1_B_1_12[] = {
    521840, 155252, 62927, 30006,
    15355, 9805, 5923, 3504,
    2922, 1850, 1088, 1079
};
static const uint64_t EXP_G1_A_2_12[] = { 1048332, 4846163, 501155 };
static const uint64_t EXP_G1_B_2_12[] = {
    18446744073698634062ULL, 159198, 18446744073709277612ULL, 28509,
    18446744073709517412ULL, 5052, 18446744073709545719ULL, 454,
    18446744073709550682ULL, 18446744073709551423ULL, 18446744073709551523ULL, 18446744073709551502ULL
};
static const uint64_t EXP_G1_A_3_12[] = { 1048436, 2830428, 506715, 21161 };
static const uint64_t EXP_G1_B_3_12[] = {
    18446744073705955916ULL, 18446744073709233801ULL, 18446744073709490199ULL, 18446744073709534193ULL,
    18446744073709545709ULL, 18446744073709549167ULL, 18446744073709550581ULL, 18446744073709551091ULL,
    18446744073709551378ULL, 18446744073709551479ULL, 18446744073709551558ULL, 18446744073709551579ULL
};


static const uint64_t EXP_G2_A_1_8[] = { 314, 22 };
static const uint64_t EXP_G2_B_1_8[] = {
    85, 24, 18446744073709551582ULL, 18446744073709551569ULL,
    18446744073709551607ULL, 21, 4, 18446744073709551590ULL
};
static const uint64_t EXP_G2_A_1_9[] = { 315, 22 };
static const uint64_t EXP_G2_B_1_9[] = {
    84, 23, 18446744073709551582ULL, 18446744073709551570ULL,
    18446744073709551607ULL, 20, 3, 18446744073709551593ULL,
    18446744073709551614ULL
};
static const uint64_t EXP_G2_A_1_12[] = { 216574, 12032 };
static const uint64_t EXP_G2_B_1_12[] = {
    127259, 50247, 22862, 10220,
    4283, 1643, 565, 170,
    43, 9, 1, 0
};
static const uint64_t EXP_G2_A_2_12[] = { 184199, 9776, 48 };
static const uint64_t EXP_G2_B_2_12[] = {
    104673, 45625, 22224, 11052,
    5188, 2301, 925, 340,
    107, 29, 6, 1
};
static const uint64_t EXP_G2_A_3_12[] = { 184199, 9776, 48, 0 };
static const uint64_t EXP_G2_B_3_12[] = {
    104673, 45625, 22224, 11052,
    5188, 2301, 925, 340,
    107, 29, 6, 1
};


const uint64_t* get_internal_exp_b(int k1, int k2) {
    if (k1 == 1) {
        if (k2 == 8) return EXP_B_1_8;
        if (k2 == 9) return EXP_B_1_9;
        if (k2 == 12) return EXP_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 12) return EXP_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return EXP_B_3_12;
    }
    return EXP_B_1_12; 
}


const uint64_t* get_internal_exp_g1_b(int k1, int k2) {
    if (k1 == 1) {
        if (k2 == 8) return EXP_G1_B_1_8;
        if (k2 == 9) return EXP_G1_B_1_9;
        if (k2 == 12) return EXP_G1_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 12) return EXP_G1_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return EXP_G1_B_3_12;
    }
    return EXP_G1_B_1_12;
}

const uint64_t* get_internal_exp_g2_b(int k1, int k2) {
    if (k1 == 1) {
        if (k2 == 8) return EXP_G2_B_1_8;
        if (k2 == 9) return EXP_G2_B_1_9;
        if (k2 == 12) return EXP_G2_B_1_12;
    } else if (k1 == 2) {
        if (k2 == 12) return EXP_G2_B_2_12;
    } else if (k1 == 3) {
        if (k2 == 12) return EXP_G2_B_3_12;
    }
    return EXP_G2_B_1_12;
}

double get_internal_exp_g1_l(int k1, int k2) {
    if (k1 == 2 && k2 == 12) return 9.5;
    if (k1 == 3 && k2 == 12) return 8.0;
    return 6.0;
}

double get_internal_exp_g2_l(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 18.0;
    if ((k1 == 2 || k1 == 3) && k2 == 12) return 21.0;
    return 5.0;
}

double get_internal_exp_l(int k1, int k2) {
    if (k2 == 12 && (k1 == 1 || k1 == 2)) return 14.0;
    if (k1 == 3 && k2 == 12) return 16.0;
    return 8.0;
}


static void calculate_exp_shares_unified_csp0_impl(
    int size, int k1, int k2, uint64_t scale_factor,
    const uint64_t* b_coeffs, double L_float,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    int b_len = k2;
    int mid_k = b_len / 2; 
    int mid_size = size / 2; 
    int s_shift = 20;        

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 12345, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100); 
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i]; 
            } else {
                t2_buf[i] = mask_t2[i]; 
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i]; 
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) { 
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else { 
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}

void ecall_calculate_exp_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u_buf, uint64_t* v_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    calculate_exp_shares_unified_csp0_impl(
        size, k1, k2, scale_factor, get_internal_exp_b(k1, k2), get_internal_exp_l(k1, k2),
        u_buf, v_buf, len_uv, t2_buf, t3_buf);
}

void ecall_calculate_exp_g1_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u_buf, uint64_t* v_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    calculate_exp_shares_unified_csp0_impl(
        size, k1, k2, scale_factor, get_internal_exp_g1_b(k1, k2), get_internal_exp_g1_l(k1, k2),
        u_buf, v_buf, len_uv, t2_buf, t3_buf);
}

void ecall_calculate_exp_g2_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u_buf, uint64_t* v_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    calculate_exp_shares_unified_csp0_impl(
        size, k1, k2, scale_factor, get_internal_exp_g2_b(k1, k2), get_internal_exp_g2_l(k1, k2),
        u_buf, v_buf, len_uv, t2_buf, t3_buf);
}

const uint64_t* get_internal_rsqrt_b(int k1, int k2) {
    return get_internal_invsqrt_b(k1, k2);
}

double get_internal_rsqrt_l(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 5.0;
    if (k1 == 2 && k2 == 12) return 9.0;
    if (k1 == 3 && k2 == 12) return 4.5;
    return 8.0;
}
void ecall_calculate_invsqrt_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_internal_rsqrt_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2; 
    int mid_size = size / 2; 
    int s_shift = 20;        

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 12345, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100); 
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i]; 
            } else {
                t2_buf[i] = mask_t2[i]; 
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i]; 
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = get_internal_rsqrt_l(k1, k2);
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) { 
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else { 
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}
const uint64_t* get_internal_reciprocal_b(int k1, int k2) {
    static const uint64_t RECIP_BASE_1_12_B[] = {
        18446744073702718070ULL, 18446744073706486925ULL, 18446744073707733046ULL, 18446744073708344256ULL,
        18446744073708699271ULL, 18446744073708925897ULL, 18446744073709080298ULL, 18446744073709191231ULL,
        18446744073709274402ULL, 18446744073709337896ULL, 18446744073709383292ULL, 18446744073709390332ULL
    };
    static const uint64_t RECIP_BASE_2_12_B[] = {
        1770478873, 1437692, 60392925, 783659,
        11047352, 515288, 3095788, 350112,
        986331, 234759, 300501, 184678
    };
    static const uint64_t RECIP_BASE_3_12_B[] = {
        736748861, 88521550, 24647899, 9567571,
        4414265, 2252303, 1220807, 684765,
        389789, 221553, 124400, 73957
    };
    if (k1 == 1 && k2 == 12) return RECIP_BASE_1_12_B;
    if (k1 == 2 && k2 == 12) return RECIP_BASE_2_12_B;
    if (k1 == 3 && k2 == 12) return RECIP_BASE_3_12_B;
    return RECIP_BASE_1_12_B;
}

double get_internal_reciprocal_l(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 4.5;
    if (k1 == 2 && k2 == 12) return 8.5;
    if (k1 == 3 && k2 == 12) return 4.5;
    return 8.0;
}
void ecall_calculate_reciprocal_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_internal_reciprocal_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2; 
    int mid_size = size / 2; 
    int s_shift = 20;        

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 12345, scale_factor, 100);
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100); 
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i]; 
            } else {
                t2_buf[i] = mask_t2[i]; 
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i]; 
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = get_internal_reciprocal_l(k1, k2);
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) { 
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else { 
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle); 
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}




const uint64_t* get_invsqrt_steep_b(int k1, int k2) {
    if (k1 == 1 && k2 == 8) return INVSQRT_STEEP_1_8_B;
    if (k1 == 1 && k2 == 12) return INVSQRT_STEEP_1_12_B;
    if (k1 == 2 && k2 == 12) return INVSQRT_STEEP_2_12_B;
    if (k1 == 3 && k2 == 12) return INVSQRT_STEEP_3_12_B;
    return INVSQRT_STEEP_1_12_B; 
}

void ecall_calculate_invsqrt_steep_shares(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_invsqrt_steep_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2;
    int mid_size = size / 2;
    int s_shift = 20;

    
    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 23456, scale_factor, 100);  
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i];
            } else {
                t2_buf[i] = mask_t2[i];
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i];
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    
    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = 8.0;
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle);
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}


const uint64_t* get_invsqrt_flat_b(int k1, int k2) {
    if (k1 == 1 && k2 == 8) return INVSQRT_FLAT_1_8_B;
    if (k1 == 1 && k2 == 12) return INVSQRT_FLAT_1_12_B;
    if (k1 == 2 && k2 == 12) return INVSQRT_FLAT_2_12_B;
    if (k1 == 3 && k2 == 12) return INVSQRT_FLAT_3_12_B;
    return INVSQRT_FLAT_1_12_B;
}

void ecall_calculate_invsqrt_flat_shares(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_invsqrt_flat_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2;
    int mid_size = size / 2;
    int s_shift = 20;

    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 34567, scale_factor, 100);  
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i];
            } else {
                t2_buf[i] = mask_t2[i];
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i];
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = 1280.0;  
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle);
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}


const uint64_t* get_reciprocal_steep_b(int k1, int k2) {
    if (k1 == 1 && k2 == 8) return RECIP_STEEP_1_8_B;
    if (k1 == 1 && k2 == 12) return RECIP_STEEP_1_12_B;
    if (k1 == 2 && k2 == 12) return RECIP_STEEP_2_12_B;
    if (k1 == 3 && k2 == 12) return RECIP_STEEP_3_12_B;
    return RECIP_STEEP_1_12_B;
}

void ecall_calculate_reciprocal_steep_shares(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_reciprocal_steep_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2;
    int mid_size = size / 2;
    int s_shift = 20;

    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 23456, scale_factor, 100);  
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i];
            } else {
                t2_buf[i] = mask_t2[i];
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i];
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = 8.0;
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle);
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}


const uint64_t* get_reciprocal_flat_b(int k1, int k2) {
    if (k1 == 1 && k2 == 8) return RECIP_FLAT_1_8_B;
    if (k1 == 1 && k2 == 12) return RECIP_FLAT_1_12_B;
    if (k1 == 2 && k2 == 12) return RECIP_FLAT_2_12_B;
    if (k1 == 3 && k2 == 12) return RECIP_FLAT_3_12_B;
    return RECIP_FLAT_1_12_B;
}

void ecall_calculate_reciprocal_flat_shares(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
) {
    const uint64_t* b_coeffs = get_reciprocal_flat_b(k1, k2);
    int b_len = k2;
    int mid_k = b_len / 2;
    int mid_size = size / 2;
    int s_shift = 20;

    std::vector<uint64_t> t0(size), t1(size);
    generate_and_map_random(t0.data(), size, 34567, scale_factor, 100);  
    generate_and_map_random(t1.data(), size, 67890, scale_factor, 100);

    
    if (k1 >= 2 && t2_buf != nullptr) {
        std::vector<uint64_t> mask_t2(size);
        generate_and_map_random(mask_t2.data(), size, 55555, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                t2_buf[i] = t2_real - mask_t2[i];
            } else {
                t2_buf[i] = mask_t2[i];
            }
        }
    }

    if (k1 >= 3 && t3_buf != nullptr) {
        std::vector<uint64_t> mask_t3(size);
        generate_and_map_random(mask_t3.data(), size, 99999, scale_factor, 100);
        for (int i = 0; i < size; i++) {
            if (i < mid_size) {
                uint64_t t_real = t0[i] + t1[i];
                uint64_t t2_real = enc_trunc_product(t_real, t_real, s_shift);
                uint64_t t3_real = enc_trunc_product(t2_real, t_real, s_shift);
                t3_buf[i] = t3_real - mask_t3[i];
            } else {
                t3_buf[i] = mask_t3[i];
            }
        }
    }

    std::vector<uint64_t> random_u(len_uv), random_v(len_uv);
    generate_and_map_random(random_u.data(), len_uv, 11111, scale_factor, 1);
    generate_and_map_random(random_v.data(), len_uv, 22222, scale_factor, 1);

    const double L_float = 1216.0;  
    for (int k = 0; k < b_len; k++) {
        if (k < mid_k) {
            for (int i = 0; i < size; i++) {
                u0_buf[k*size + i] = random_u[k*size + i];
                v0_buf[k*size + i] = random_v[k*size + i];
            }
        } else {
            double K_val = M_PI * (k + 1) / L_float;
            double b_k_real = (int64_t)b_coeffs[k] / (double)scale_factor;
            for (int i = 0; i < size; i++) {
                double t_total = ((int64_t)t0[i] + (int64_t)t1[i]) / (double)scale_factor;
                double angle = K_val * t_total;
                double target_sin = b_k_real * sin(angle);
                double target_cos = b_k_real * cos(angle);
                u0_buf[k*size + i] = static_cast<uint64_t>(target_sin * scale_factor) - random_u[k*size + i];
                v0_buf[k*size + i] = static_cast<uint64_t>(target_cos * scale_factor) - random_v[k*size + i];
            }
        }
    }
}
