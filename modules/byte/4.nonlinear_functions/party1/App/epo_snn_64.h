#ifndef EPO_SNN_64_H
#define EPO_SNN_64_H

#include <cstdint>
#include <vector>
#include "base_secure_protocols.h"
#include "calculate/basicSockets.h"




typedef struct {
    int in_h, in_w, in_c;
    int out_h, out_w, out_c;
    int pool_size;
    int stride;
    char* pool_type; 
    uint64_t MOD;
} PoolConfig_64;


typedef struct {
    BSNet* main_server;   
    BSNet* main_client;   
    BSNet* aux_server;    
    BSNet* aux_client;    
    BSNet* aux_server_1;    
    BSNet* aux_client_1;    
    BSNet* aux_server_2;    
    BSNet* aux_client_2;    
} CommPorts;


typedef struct {
    BSNet* main_client;   
    BSNet* main_server;   
    BSNet* aux_client;    
    BSNet* aux_server;    
    BSNet* aux_server_1;    
    BSNet* aux_client_1;    
    BSNet* aux_server_2;    
    BSNet* aux_client_2;    
} CommPorts_CSP1;




void generate_and_map_random(uint64_t* target_buf, uint64_t count, uint64_t seed, uint64_t scale, int bound_coeff);


void private_approx_sigmoid_base_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_tanh_base_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_erf_base_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_exp_base_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_exp_g1_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_exp_g2_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_sigmoid_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_tanh_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_erf_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_exp_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_invsqrt_base_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_inv_base_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_silu_2rounds_csp1(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_gelu_2rounds_csp1(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_invsqrt_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1_steep,
    int k1_flat,
    int k2,
    uint64_t MOD
);



void private_approx_inv_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int steep_k1,
    int steep_flat_k1,
    int steep_k2,
    uint64_t MOD
);


void private_approx_softmax_csp1(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int batch_size,
    int seq_len,
    int exp_k1,
    int exp_k2,
    int rec_steep_k1,
    int rec_flat_k1,
    int rec_steep_k2,
    int rec_flat_k2,
    uint64_t MOD
);
#endif 
