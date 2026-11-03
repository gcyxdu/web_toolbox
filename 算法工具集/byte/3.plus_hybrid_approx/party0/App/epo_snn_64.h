#ifndef EPO_SNN_64_H
#define EPO_SNN_64_H

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
#include "func.h"
#include "base_secure_protocols.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "calculate/basicSockets.h"  
#include <future>
#include <chrono>
#include <thread>
#include <cstdint>

#include <cstring>

typedef struct {
    int input_size;        
    int output_size;       
    float sparsity;        
    int fixed_n;           
    int demo_neurons;      
} OFPConfig;


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
} CommPorts_CSP0;



struct ConvConfig_64 {
    int in_h, in_w, in_c;       
    int out_h, out_w, out_c;    
    int kernel_size;            
    int stride, padding;         
    float sparsity;              
    uint64_t* kernel_weights;   
    uint64_t* kernel_bias;       
    
    
    int patch_size() const { return kernel_size * kernel_size ; }
    int filtered_size() const { return (int)(patch_size() * sparsity+1); }
    int total_patches() const { return out_h * out_w * out_c; }
};


typedef struct {
    uint64_t* gamma;    
    uint64_t* beta;     
    uint64_t* mean;     
    uint64_t* var;      
    float epsilon;      
    int channels;       
    int s;              
} BNParams_64;


typedef struct {
    uint64_t K1;  
    uint64_t K2;  
} ApproxParams_64;


enum ActivationType_64 {
    ACTIVATION_RELU_64 = 0,
    ACTIVATION_LEAKY_RELU_64  = 1,
    ACTIVATION_SIGMOID_64  = 2,
    ACTIVATION_TANH_64  = 3
};


typedef struct {
    ActivationType_64 type;      
    uint64_t s;               
    union {
        struct {             
            double alpha;     
        } relu;
        ApproxParams_64 approx; 
    } params;
} ActivationConfig_64;


typedef struct {
    bool is_leaky;           
    double alpha;            
    uint64_t s;              
} ReLUConfig_64;


typedef struct {
    int in_h;           
    int in_w;           
    int in_c;           
    int out_h;          
    int out_w;          
    int out_c;          
    int pool_size;      
    int stride;         
    char* pool_type; 
    uint64_t MOD;       
} PoolConfig_64;


typedef struct {
    int start_h;        
    int start_w;        
    int window_size;    
    int patch_index;    
    uint64_t* elements; 
} PoolWindow_64;


typedef struct {
    int input_size;      
    int fixed_n;         
    int demo_neurons;    
    float sparsity;      
    
} OFPConfig_64;



struct CIFAR10NetConfig_Final_64 {
    
    int input_channels = 3;
    int input_height = 32;
    int input_width = 32;
    int num_classes = 10;
    uint64_t MOD = UINT64_MAX;
    
    
    int conv1_out_channels = 64;    
    int conv2_out_channels = 64;    
    int conv3_out_channels = 64;    
    int conv4_out_channels = 64;    
    int conv5_out_channels = 64;    
    int conv6_out_channels = 64;    
    int conv7_out_channels = 16;    
    
    
    int pool_size = 2;
    int pool_stride = 2;
    
    
    float sparsity = 0.3f;
    
    
    int bn_scale = 16;
};


struct MNISTNetConfig_64 {
    int input_height = 28;
    int input_width = 28;
    int input_channels = 1;
    
    int conv1_out_channels = 16;
    int conv2_out_channels = 16;
    
    int pool_size = 2;
    int pool_stride = 2;
    
    int fc1_units = 100;
    int fc2_units = 10;
    int num_classes = 10;
    
    double sparsity = 0.7;  
    uint64_t bn_scale = 16;
    uint64_t MOD = UINT64_MAX;
};




void generate_and_map_random(uint64_t* target_buf, uint64_t count, uint64_t seed, uint64_t scale, int bound_coeff);


void private_approx_sigmoid_base_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_tanh_base_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_erf_base_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_exp_base_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_exp_g1_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_exp_g2_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_sigmoid_plus_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_tanh_plus_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_erf_plus_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_exp_plus_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_invsqrt_base_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);

void private_approx_inv_base_csp0(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_silu_2rounds_csp0(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
);


void private_approx_invsqrt_plus_csp0(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1_steep,
    int k1_flat,
    int k2,
    uint64_t MOD
);



void private_approx_inv_plus_csp0(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int steep_k1,
    int steep_flat_k1,
    int steep_k2,
    uint64_t MOD
);

#endif 
