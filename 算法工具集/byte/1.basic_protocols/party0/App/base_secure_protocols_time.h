#ifndef BASE_SECURE_PROTOCOLS_TIME_H
#define BASE_SECURE_PROTOCOLS_TIME_H

#include <cstdint>

#include "App.h"
#include "Enclave_u.h"
#include "calculate/basicSockets.h"
#include "sgx_urts.h"

extern sgx_enclave_id_t global_eid;
extern sgx_enclave_id_t global_eid0;
extern sgx_enclave_id_t global_eid1;

bool set_base_secure_protocols_time_enabled_time(bool enabled);
bool set_odrelu_time_enabled_time(bool enabled);
void generate_consistent_random_64_time(uint64_t* array, uint64_t count, uint64_t seed);
void generateRandomArrayUint64_time(uint64_t* array, uint64_t size, uint64_t seed, uint64_t range);

void secure_multiply_batch_base_time(BSNet* net, bool is_csp0, const uint64_t* input_a,
                                         const uint64_t* input_b, uint64_t* output,
                                         uint64_t count, uint64_t s, uint64_t L);
void secure_multiply_batch_dualport_time(BSNet* send_net, BSNet* recv_net, bool is_csp0,
                                         const uint64_t* input_a, const uint64_t* input_b,
                                         uint64_t* output, uint64_t count, uint64_t s, uint64_t L);

void secure_triple_multiply_batch_base_time(BSNet* net, bool is_csp0,
                                                const uint64_t* input_x, const uint64_t* input_y,
                                                const uint64_t* input_w, uint64_t* output,
                                                uint64_t count, uint64_t s, uint64_t L);
void secure_triple_multiply_batch_dualport_time(BSNet* send_net, BSNet* recv_net, bool is_csp0,
                                                const uint64_t* input_x, const uint64_t* input_y,
                                                const uint64_t* input_w, uint64_t* output,
                                                uint64_t count, uint64_t s, uint64_t L);

void ODReLU_CSP0_2Threads_64_time(BSNet* net, const uint64_t* input_x,
                                  uint64_t* drelu_output, int vector_size);
void ODReLU_CSP0_4Threads_64_time(BSNet* send_net, BSNet* recv_net, const uint64_t* input_x,
                                  uint64_t* drelu_output, int vector_size);
void ODReLU_CSP0_4Threads_64_v2_time(BSNet* send_net, BSNet* recv_net, const uint64_t* input_x,
                                     uint64_t* drelu_output, int vector_size);

void secure_relu_csp0_base_time(BSNet* net1, BSNet* net2, const uint64_t* input_shares,
                                    uint64_t* output_shares, int vector_size);
void secure_relu_csp0_dualport_time(BSNet* net1, BSNet* net2, const uint64_t* input_shares,
                                    uint64_t* output_shares, int vector_size);

#endif
