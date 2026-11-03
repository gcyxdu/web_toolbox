






























#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif



void generate_consistent_random_64(uint64_t* array, uint64_t count, uint64_t seed);


void generate_and_map_random(uint64_t* target_buf, uint64_t count, uint64_t seed, uint64_t scale, int bound_coeff);


void ecall_smp_reset_64(void);
void ecall_smp_gen_ab_r0_64(uint64_t seed, uint64_t count);
void ecall_smp_tee1_computation_64(uint64_t count, const uint64_t* x1_plus_r1, const uint64_t* y1_plus_r2, uint64_t* result);
void ecall_square_gen_a_r0_64(uint64_t seed, uint64_t count) ;
void ecall_sq_tee1_computation_64(uint64_t count, uint64_t start_idx, const uint64_t* x1_plus_r1, uint64_t* result) ;

void ecall_3smp_reset_64();
void ecall_3smp_gen_abc_r0_64(uint64_t seed, uint64_t count);
void ecall_3smp_tee1_compute_m3_64(uint64_t count, const uint64_t* x1_plus_r1, const uint64_t* y1_plus_r2, const uint64_t* w1_plus_r3);
void ecall_3smp_tee1_compute_m4_64(uint64_t count, const uint64_t* U, const uint64_t* V, const uint64_t* W, uint64_t* result);
void ecall_cube_opt_reset_64();
void ecall_cube_opt_gen_params_64(uint64_t seed, uint64_t count) ;
void ecall_cube_opt_step1_m3_64(uint64_t count, const uint64_t* x_plus_r1);
void ecall_cube_opt_step2_final_64(uint64_t count,
                                   const uint64_t* V, 
                                   uint64_t* final_result);
void ecall_xy2_opt_reset_64();
void ecall_xy2_opt_gen_params_64(uint64_t seed, uint64_t count) ;
void ecall_xy2_opt_step1_64(uint64_t count, const uint64_t* x_plus_r1, const uint64_t* y_plus_r2) ;
void ecall_xy2_opt_step2_final_64(uint64_t count, 
                                  const uint64_t* V_xy, 
                                  const uint64_t* V_yy, 
                                  uint64_t* final_result) ;

void ecall_odrelu_reset_uint64();
void ecall_odrelu_gen_shared_randomness_final_uint64(uint64_t seed, uint64_t vector_size, uint64_t xi);
void ecall_odrelu_tee1_step1_uint64(uint64_t vector_size, const uint64_t* x1_minus_r2, uint64_t* result);
void ecall_odrelu_tee1_step2_uint64(uint64_t vector_size, const uint64_t* z_plus_r3, uint64_t* result);
void ecall_odrelu_get_stored_values_uint64(uint64_t vector_size, uint64_t* a, uint64_t* b, uint64_t* r0, uint64_t* r1, uint64_t* v);


void ecall_matrix_batch_init(uint64_t seedT, int m, int k, int n, int count);
void ecall_matrix_batch_compute(
    int m, int k, int n, int count,
    const uint64_t* X_batch, size_t len_x,
    const uint64_t* Y_batch, size_t len_y,
    uint64_t* Tout_batch, size_t len_z
);




void ecall_csp1_calculate_sigmoid_shares_internal(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u1_buf, uint64_t* v1_buf, int len_uv
);
void ecall_csp1_calculate_sigmoid_shares_optimized(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u1_buf, uint64_t* v1_buf, int len_uv
);


void ecall_csp1_calculate_tanh_shares_internal(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u1_buf, uint64_t* v1_buf, int len_uv
);
void ecall_csp1_calculate_tanh_shares_optimized(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u1_buf, uint64_t* v1_buf, int len_uv
);


void ecall_csp1_calculate_invsqrt_shares_internal(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u1_buf, uint64_t* v1_buf, int len_uv
);
void ecall_csp1_calculate_invsqrt_shares_optimized(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u1_buf, uint64_t* v1_buf, int len_uv
);
void ecall_tee1_slave_compute(
    int m, int k, int n, int count,
    uint64_t* batch_C1, size_t len_C
) ;

void ecall_csp1_gelu_shares_opt(
    int size, 
    uint64_t scale_factor,
    uint64_t* u1_buf, 
    uint64_t* v1_buf
);
void ecall_calculate_sigmoid_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
);
void ecall_calculate_tanh_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
);
void ecall_calculate_erf_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
);
void ecall_calculate_exp_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
);
void ecall_calculate_invsqrt_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
);
void ecall_calculate_reciprocal_shares_unified(
    int size, int k1, int k2, uint64_t scale_factor,
    uint64_t* u0_buf, uint64_t* v0_buf, int len_uv,
    uint64_t* t2_buf, uint64_t* t3_buf
);

void ecall_cleanup();

#if defined(__cplusplus)
}
#endif

#endif 