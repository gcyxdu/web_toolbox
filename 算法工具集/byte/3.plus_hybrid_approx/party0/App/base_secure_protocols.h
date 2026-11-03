#ifndef BASE_SECURE_PROTOCOLS_H
#define BASE_SECURE_PROTOCOLS_H

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
#include "epo_snn_64.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "calculate/basicSockets.h"  
#include <future>
#include <chrono>
#include <thread>
#include <cstdint>
using namespace std;


extern sgx_enclave_id_t global_eid;
extern sgx_enclave_id_t global_eid0;
extern sgx_enclave_id_t global_eid1;
void generateRandomArrayUint64(uint64_t* array, uint64_t size, uint64_t seed, uint64_t range);
void ODReLU_CSP0_2Threads_64(BSNet* server_port12345, const uint64_t* x0_input, uint64_t* drelu_output, int vector_size);
void ODReLU_CSP0_4Threads_64(BSNet* client_port12345, BSNet* server_port12346,const uint64_t* x1_input, uint64_t* drelu_output, int vector_size);
void ODReLU_CSP0_4Threads_64_v2(BSNet* client_port12345, BSNet* server_port12346,const uint64_t* x1_input, uint64_t* drelu_output, int vector_size);
void secure_multiply_batch_parallel(BSNet* server, bool is_csp0, const uint64_t* input_a, const uint64_t* input_b, uint64_t* output, uint64_t count, uint64_t s, uint64_t L);
void secure_triple_multiply_batch_parallel(BSNet* server, bool is_csp0, const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w, uint64_t* output, uint64_t count, uint64_t s, uint64_t L);
void secure_multiply_batch_dualport(BSNet* server_port12345, BSNet* client_port12346, bool is_csp0, const uint64_t* input_a, const uint64_t* input_b, uint64_t* output, uint64_t count, uint64_t s, uint64_t L);
void secure_triple_multiply_batch_dualport(BSNet* server_port12345, BSNet* client_port12346, bool is_csp0,const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w,uint64_t* output, uint64_t count, uint64_t s, uint64_t L);

void secure_matrix_multiply_batch_csp0(
    BSNet* server,
    const uint64_t* input_X, 
    const uint64_t* input_Y, 
    uint64_t* output_Z,      
    int m, int k, int n,
    int batch_count          
);
void secure_matrix_batch_dualport_csp0(BSNet* send_net, BSNet* recv_net,const uint64_t* batch_X, const uint64_t* batch_Y, uint64_t* batch_Z, int count,int m, int k, int n);
void secure_matrix_batch_base_csp0(
    BSNet* send_net, BSNet* recv_net,
    const uint64_t* batch_X, 
    const uint64_t* batch_Y, 
    uint64_t* batch_Z,       
    int count, int m, int k, int n
) ;
void secure_relu_csp0_parallel(BSNet* server_net1,  BSNet* server_net2, 
                               const uint64_t* input_shares, 
                               uint64_t* output_shares,
                               int vector_size);
void secure_relu_csp0_dualport(BSNet* server_net1, BSNet* server_net2,
                               const uint64_t* input_shares, 
                               uint64_t* output_shares,
                               int vector_size);
void secure_square_batch_parallel_csp0(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, 
    uint64_t* output, uint64_t count, uint64_t s, uint64_t L
);
void secure_square_batch_dualport(BSNet* send_channel, BSNet* recv_channel, bool is_csp0, 
                                  const uint64_t* input_x, 
                                  uint64_t* output, 
                                  uint64_t count, 
                                  uint64_t s, uint64_t L) ;
void secure_cube_opt_batch_parallel(
    BSNet* server, bool is_csp0, 
    const uint64_t* batch_X, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
);
void secure_cube_opt_batch_dualport_csp0(
    BSNet* send_net, BSNet* recv_net,bool is_csp0, 
    const uint64_t* input_x, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
);
void secure_xy2_opt_batch_parallel_csp0(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) ;
void secure_xy2_opt_batch_dualport_csp0(
    BSNet* send_net, BSNet* recv_net, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) ;
#endif 