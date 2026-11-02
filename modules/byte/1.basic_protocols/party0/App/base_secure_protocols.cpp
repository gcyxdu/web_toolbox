#include "base_secure_protocols.h"
#include "base_secure_protocols_time.h"

namespace {

class ScopedBaseSecureProtocolsTimeSilencer {
public:
    ScopedBaseSecureProtocolsTimeSilencer()
        : previous_(set_base_secure_protocols_time_enabled_time(false)) {}

    ~ScopedBaseSecureProtocolsTimeSilencer() {
        set_base_secure_protocols_time_enabled_time(previous_);
    }

private:
    bool previous_;
};

}  

#define FORWARD_WITH_TIMING_DISABLED(func, timed_func, signature, args) \
    void func signature {                                                \
        ScopedBaseSecureProtocolsTimeSilencer silencer;                  \
        timed_func args;                                                 \
    }

void generate_consistent_random_64(uint64_t* array, uint64_t count, uint64_t seed) {
    generate_consistent_random_64_time(array, count, seed);
}

void generateRandomArrayUint64(uint64_t* array, uint64_t size, uint64_t seed, uint64_t range) {
    generateRandomArrayUint64_time(array, size, seed, range);
}

FORWARD_WITH_TIMING_DISABLED(
    ODReLU_CSP0_2Threads_64,
    ODReLU_CSP0_2Threads_64_time,
    (BSNet* server_port12345, const uint64_t* x0_input, uint64_t* drelu_output, int vector_size),
    (server_port12345, x0_input, drelu_output, vector_size))

FORWARD_WITH_TIMING_DISABLED(
    ODReLU_CSP0_4Threads_64,
    ODReLU_CSP0_4Threads_64_time,
    (BSNet* client_port12345, BSNet* server_port12346, const uint64_t* x1_input, uint64_t* drelu_output, int vector_size),
    (client_port12345, server_port12346, x1_input, drelu_output, vector_size))

FORWARD_WITH_TIMING_DISABLED(
    ODReLU_CSP0_4Threads_64_v2,
    ODReLU_CSP0_4Threads_64_v2_time,
    (BSNet* client_port12345, BSNet* server_port12346, const uint64_t* x1_input, uint64_t* drelu_output, int vector_size),
    (client_port12345, server_port12346, x1_input, drelu_output, vector_size))

FORWARD_WITH_TIMING_DISABLED(
    secure_multiply_batch_base,
    secure_multiply_batch_base_time,
    (BSNet* server, bool is_csp0, const uint64_t* input_a, const uint64_t* input_b, uint64_t* output, uint64_t count, uint64_t s, uint64_t L),
    (server, is_csp0, input_a, input_b, output, count, s, L))

FORWARD_WITH_TIMING_DISABLED(
    secure_triple_multiply_batch_base,
    secure_triple_multiply_batch_base_time,
    (BSNet* server, bool is_csp0, const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w, uint64_t* output, uint64_t count, uint64_t s, uint64_t L),
    (server, is_csp0, input_x, input_y, input_w, output, count, s, L))

FORWARD_WITH_TIMING_DISABLED(
    secure_multiply_batch_dualport,
    secure_multiply_batch_dualport_time,
    (BSNet* server_port12345, BSNet* client_port12346, bool is_csp0, const uint64_t* input_a, const uint64_t* input_b, uint64_t* output, uint64_t count, uint64_t s, uint64_t L),
    (server_port12345, client_port12346, is_csp0, input_a, input_b, output, count, s, L))

FORWARD_WITH_TIMING_DISABLED(
    secure_triple_multiply_batch_dualport,
    secure_triple_multiply_batch_dualport_time,
    (BSNet* server_port12345, BSNet* client_port12346, bool is_csp0, const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w, uint64_t* output, uint64_t count, uint64_t s, uint64_t L),
    (server_port12345, client_port12346, is_csp0, input_x, input_y, input_w, output, count, s, L))

FORWARD_WITH_TIMING_DISABLED(
    secure_relu_csp0_base,
    secure_relu_csp0_base_time,
    (BSNet* server_net1, BSNet* server_net2, const uint64_t* input_shares, uint64_t* output_shares, int vector_size),
    (server_net1, server_net2, input_shares, output_shares, vector_size))

FORWARD_WITH_TIMING_DISABLED(
    secure_relu_csp0_dualport,
    secure_relu_csp0_dualport_time,
    (BSNet* server_net1, BSNet* server_net2, const uint64_t* input_shares, uint64_t* output_shares, int vector_size),
    (server_net1, server_net2, input_shares, output_shares, vector_size))

#undef FORWARD_WITH_TIMING_DISABLED
