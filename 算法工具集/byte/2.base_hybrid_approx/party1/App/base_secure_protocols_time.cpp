#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <cstdint>

#include <atomic>
#include <chrono>
#include <cmath>
#include <complex>
#include <condition_variable>
#include <future>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "sgx_urts.h"
#include "Enclave_u.h"  
#include "App.h"
#include "base_secure_protocols_time.h"
#include "func.h"
#include "calculate/basicSockets.h" 

#ifndef MAX_PATH
#define MAX_PATH FILENAME_MAX
#endif

using namespace std;

static bool g_base_secure_protocols_time_enabled = true;
static bool g_odrelu_time_enabled = false;



bool set_base_secure_protocols_time_enabled_time(bool enabled) {
    bool previous = g_base_secure_protocols_time_enabled;
    g_base_secure_protocols_time_enabled = enabled;
    return previous;
}

bool set_odrelu_time_enabled_time(bool enabled) {
    bool previous = g_odrelu_time_enabled;
    g_odrelu_time_enabled = enabled;
    return previous;
}

#define TIME_PRINTF(...)                                                     \
    do {                                                                     \
        if (g_base_secure_protocols_time_enabled) {                          \
            printf(__VA_ARGS__);                                             \
        }                                                                    \
    } while (0)

#define ODRELU_TIME_PRINTF(...)                                              \
    do {                                                                     \
        if (g_base_secure_protocols_time_enabled && g_odrelu_time_enabled) { \
            printf(__VA_ARGS__);                                             \
        }                                                                    \
    } while (0)


void generateRandomArrayUint64_time(uint64_t* array, uint64_t size, uint64_t seed, uint64_t range) {
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<uint64_t> dist(0, range - 1);
    
    for (uint64_t i = 0; i < size; i++) {
        array[i] = dist(gen);
    }
}

void generate_consistent_random_64_time(uint64_t* array, uint64_t count, uint64_t seed) {
    uint64_t state = seed;
    const uint64_t MULTIPLIER = 6364136223846793005ULL;
    const uint64_t INCREMENT = 1442695040888963407ULL;

    for (uint64_t i = 0; i < count; i++) {
        state = state * MULTIPLIER + INCREMENT;
        array[i] = state;
        if (array[i] == 0) array[i] = 1; 
    }
}
void secure_multiply_batch_parallel_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_a, const uint64_t* input_b, 
    uint64_t* output, 
    uint64_t count, 
    uint64_t s, uint64_t L
) {
    struct PerfStats {
        long a2_time = 0;    
        long b3_time = 0;    
        long c_time = 0;     
        long online_wall = 0; 
        long total_func = 0; 
        long waste_time = 0; 
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;

    struct SharedData {
        uint64_t* recv_buffer = nullptr;
        uint64_t* x_ptr = nullptr;
        uint64_t* y_ptr = nullptr;
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;

    shared.recv_buffer = new uint64_t[count * 2];
    shared.x_ptr = shared.recv_buffer;
    shared.y_ptr = shared.recv_buffer + count;

    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;

    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    
    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1_net = std::thread([&]() {
        wait_for_gun(); 

        long bytes = count * 2 * sizeof(uint64_t);
        auto t_recv_start = std::chrono::high_resolution_clock::now();
        
        server->recvMsg(shared.recv_buffer, bytes, 0);
        
        stats.b3_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_recv_start).count();
        stats.recv_bytes = bytes;

        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_done = true;
        }
        shared.cv.notify_one();
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        uint64_t* r1 = new uint64_t[count];
        uint64_t* r2 = new uint64_t[count];
        uint64_t* x1_plus_r1 = new uint64_t[count];
        uint64_t* y1_plus_r2 = new uint64_t[count];
        uint64_t* tee_result = new uint64_t[count];
        
        
        auto t_a2_start = std::chrono::high_resolution_clock::now();
        
        
        generate_consistent_random_64_time(r1, count, seedC);
        generate_consistent_random_64_time(r2, count, seedC + 1);
        
        
        ecall_smp_gen_ab_r0_64(global_eid1, seedT, count);
        
        
        for (uint64_t i = 0; i < count; i++) {
            x1_plus_r1[i] = input_a[i] + r1[i];
            y1_plus_r2[i] = input_b[i] + r2[i];
        }
        
        
        ecall_smp_tee1_computation_64(global_eid1, count, x1_plus_r1, y1_plus_r2, tee_result);
        
        stats.a2_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_a2_start).count();
        
        
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }
        
        
        auto t_c_start = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < count; i++) {
            uint64_t x_plus_a = shared.x_ptr[i] + input_a[i];
            uint64_t y_plus_b = shared.y_ptr[i] + input_b[i];
            output[i] = (x_plus_a * y_plus_b) + tee_result[i];
        }
        stats.c_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_c_start).count();

        delete[] r1; delete[] r2;
        delete[] x1_plus_r1; delete[] y1_plus_r2; delete[] tee_result;
    });

    long create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all(); 

    
    auto t_join_start = std::chrono::high_resolution_clock::now();
    t1_net.join();
    t2_comp.join();
    
    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();
    stats.waste_time = create_time;   

    delete[] shared.recv_buffer;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Single Mul Optimized (Sync):\n");
    TIME_PRINTF("a2的总时间（随机数+TEE计算）: %ld us\n", stats.a2_time);
    TIME_PRINTF("b3的时间（接收线程时间）: %ld us\n", stats.b3_time);
    TIME_PRINTF("c的时间（重构时间）: %ld us\n", stats.c_time);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall-stats.waste_time);
    TIME_PRINTF("函数总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_triple_multiply_batch_parallel_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w, 
    uint64_t* output, uint64_t count, uint64_t s, uint64_t L
) {
    if (is_csp0) return; 

    using uint128_t = unsigned __int128;

    struct PerfStats {
        long a2_time = 0;     
        long b3_time = 0;     
        long c_time = 0;      
        long create_time = 0; 
        long join_time = 0;   
        long online_wall = 0; 
        long total_func = 0;  
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456;
    uint64_t seedC = 654321;

    
    uint64_t* r1 = new uint64_t[count]; uint64_t* r2 = new uint64_t[count];
    uint64_t* r3 = new uint64_t[count]; uint64_t* r4 = new uint64_t[count];
    uint64_t* r5 = new uint64_t[count]; uint64_t* r6 = new uint64_t[count];

    struct SharedData {
        uint64_t* recv_buf = nullptr;
        uint64_t* ptr_x = nullptr; uint64_t* ptr_y = nullptr; uint64_t* ptr_w = nullptr;
        bool recv_done = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.recv_buf = new uint64_t[count * 3];
    shared.ptr_x = shared.recv_buf;
    shared.ptr_y = shared.recv_buf + count;
    shared.ptr_w = shared.recv_buf + count * 2;

    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;

    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    
    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1_net = std::thread([&]() {
        wait_for_gun(); 

        long bytes = count * 3 * sizeof(uint64_t);
        auto t_recv_start = std::chrono::high_resolution_clock::now();
        
        server->recvMsg(shared.recv_buf, bytes, 0);
        
        stats.b3_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_recv_start).count();
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        uint64_t* x1_r1 = new uint64_t[count]; 
        uint64_t* y1_r2 = new uint64_t[count]; 
        uint64_t* w1_r3 = new uint64_t[count];
        uint64_t* tee_final_sum = new uint64_t[count]; 

        
        auto t_a2_start = std::chrono::high_resolution_clock::now();

        
        generate_consistent_random_64_time(r1, count, seedC);
        generate_consistent_random_64_time(r2, count, seedC + 1);
        generate_consistent_random_64_time(r3, count, seedC + 2);
        generate_consistent_random_64_time(r4, count, seedC + 3);
        generate_consistent_random_64_time(r5, count, seedC + 4);
        generate_consistent_random_64_time(r6, count, seedC + 5);

        
        ecall_3smp_gen_abc_r0_64(global_eid1, seedT, count);

        
        for (uint64_t i = 0; i < count; i++) {
            x1_r1[i] = input_x[i] + r1[i]; 
            y1_r2[i] = input_y[i] + r2[i]; 
            w1_r3[i] = input_w[i] + r3[i];
        }
        
        
        ecall_3smp_tee1_compute_m3_64(global_eid1, count, x1_r1, y1_r2, w1_r3);
        
        stats.a2_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_a2_start).count();

        
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }

        
        auto t_c_start = std::chrono::high_resolution_clock::now();
        
        
        uint64_t *U = x1_r1, *V = y1_r2, *W = w1_r3; 
        
        for (uint64_t i = 0; i < count; i++) {
            uint64_t X_plus_a = shared.ptr_x[i] + input_x[i];
            uint64_t Y_plus_b = shared.ptr_y[i] + input_y[i];
            uint64_t W_plus_c = shared.ptr_w[i] + input_w[i];
            
            U[i] = Y_plus_b * W_plus_c + r4[i];
            V[i] = X_plus_a * W_plus_c + r5[i];
            W[i] = X_plus_a * Y_plus_b + r6[i];
            
            output[i] = (uint64_t)((uint128_t)X_plus_a * Y_plus_b * W_plus_c);
        }
        
        
        ecall_3smp_tee1_compute_m4_64(global_eid1, count, U, V, W, tee_final_sum);
        
        
        for (uint64_t i = 0; i < count; i++) output[i] += tee_final_sum[i];

        stats.c_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_c_start).count();
        
        delete[] x1_r1; delete[] y1_r2; delete[] w1_r3; delete[] tee_final_sum;
    });

    long create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all(); 

    
    auto t_join_start = std::chrono::high_resolution_clock::now();
    t1_net.join();
    t2_comp.join();
    stats.join_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_join_start).count();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();

    
    delete[] shared.recv_buf;
    delete[] r1; delete[] r2; delete[] r3; delete[] r4; delete[] r5; delete[] r6;

    
    
    
    long thread_waste = stats.create_time;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Triple Mul Optimized (Sync):\n");
    TIME_PRINTF("a2时间（随机数+TEE Init+Calc1）: %ld us\n", stats.a2_time);
    TIME_PRINTF("b3时间（接收线程时间）: %ld us\n", stats.b3_time);
    TIME_PRINTF("c时间 （重构+TEE Calc2）: %ld us\n", stats.c_time);
    TIME_PRINTF("创建线程浪费时间: %ld us\n", thread_waste);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("接收多少byte: %ld bytes\n", stats.recv_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}

void secure_multiply_batch_dualport_time(BSNet* send_channel, BSNet* recv_channel, bool is_csp0, 
                                  const uint64_t* input_a, const uint64_t* input_b, 
                                  uint64_t* output, 
                                  uint64_t count, 
                                  uint64_t s, uint64_t L) {
    
    struct PerfStats {
        long offline_time = 0; 
        
        long t1_time = 0;      
        
        
        long t2_total = 0;     
        long t2_prep = 0;      
        long t2_wait = 0;      
        long t2_recon = 0;     
        
        
        long t3_total = 0;     
        long t3_calc = 0;      
        long t3_send = 0;      
        
        long t4_time = 0;      
        
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
        long send_bytes = 0;
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    
    
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;
    uint64_t seedT_p2 = seedT + 0xFFFF; 
    uint64_t seedC_p2 = seedC + 0xFFFF;

    uint64_t half_count = count / 2;
    uint64_t second_count = count - half_count;

    
    auto t_off_start = std::chrono::high_resolution_clock::now();

    uint64_t* a_p2 = new uint64_t[second_count];
    uint64_t* b_p2 = new uint64_t[second_count];
    generate_consistent_random_64_time(a_p2, second_count, seedT_p2);
    generate_consistent_random_64_time(b_p2, second_count, seedT_p2 + 1);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_off_start).count();

    
    struct SharedData {
        uint64_t* res_tee = nullptr; uint64_t* res_local = nullptr;
        uint64_t* recv_buf = nullptr; uint64_t* recv_x = nullptr; uint64_t* recv_y = nullptr;
        bool recv_done = false; std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.res_tee = new uint64_t[half_count];
    shared.res_local = new uint64_t[second_count];
    shared.recv_buf = new uint64_t[half_count * 2]; 
    shared.recv_x = shared.recv_buf;
    shared.recv_y = shared.recv_buf + half_count;

    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;

    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    
    auto t_create_start = std::chrono::high_resolution_clock::now();

        
    auto t3 = std::thread([&]() {
        wait_for_gun(); 
        auto t3_start = std::chrono::high_resolution_clock::now();

        uint64_t* send_buf = new uint64_t[second_count * 2];
        
        
        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            send_buf[i] = input_a[idx] + a_p2[i]; 
            send_buf[second_count + i] = input_b[idx] + b_p2[i]; 
        }
        auto t3_calc_end = std::chrono::high_resolution_clock::now();
        
        
        long bytes = second_count * 2 * sizeof(uint64_t);
        send_channel->sendMsg(send_buf, bytes, 0);
        auto t3_send_end = std::chrono::high_resolution_clock::now();

        stats.send_bytes = bytes;
        delete[] send_buf;

        
        stats.t3_calc = std::chrono::duration_cast<std::chrono::microseconds>(t3_calc_end - t3_start).count();
        stats.t3_send = std::chrono::duration_cast<std::chrono::microseconds>(t3_send_end - t3_calc_end).count();
        stats.t3_total = stats.t3_calc + stats.t3_send; 
    });

    
    auto t4 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        uint64_t* r0_p2 = new uint64_t[second_count];
        uint64_t* r1_p2 = new uint64_t[second_count];
        uint64_t* r2_p2 = new uint64_t[second_count];

        generate_consistent_random_64_time(r0_p2, second_count, seedT_p2 + 2);
        generate_consistent_random_64_time(r1_p2, second_count, seedC_p2);
        generate_consistent_random_64_time(r2_p2, second_count, seedC_p2 + 1);

        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            uint64_t term1 = a_p2[i] * r2_p2[i];
            uint64_t term2 = b_p2[i] * r1_p2[i];
            uint64_t term3 = a_p2[i] * b_p2[i];
            uint64_t term4 = a_p2[i] * input_b[idx];
            uint64_t term5 = b_p2[i] * input_a[idx];
            uint64_t term6 = r0_p2[i];
            shared.res_local[i] = term1 + term2 - term3 - term4 - term5 - term6;
        }
        delete[] r0_p2; delete[] r1_p2; delete[] r2_p2;
        stats.t4_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });
    
    auto t1 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        long bytes = half_count * 2 * sizeof(uint64_t);
        recv_channel->recvMsg(shared.recv_buf, bytes, 0);
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
        stats.t1_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    
    auto t2 = std::thread([&]() {
        wait_for_gun(); 
        auto t2_start = std::chrono::high_resolution_clock::now();

        uint64_t* r1_p1 = new uint64_t[half_count];
        uint64_t* r2_p1 = new uint64_t[half_count];
        uint64_t* xr1 = new uint64_t[half_count];
        uint64_t* yr2 = new uint64_t[half_count];
        uint64_t* tres = new uint64_t[half_count];

        
        generate_consistent_random_64_time(r1_p1, half_count, seedC);
        generate_consistent_random_64_time(r2_p1, half_count, seedC + 1);
        ecall_smp_gen_ab_r0_64(global_eid1, seedT, half_count);

        for (uint64_t i = 0; i < half_count; i++) {
            xr1[i] = input_a[i] + r1_p1[i]; 
            yr2[i] = input_b[i] + r2_p1[i]; 
        }
        ecall_smp_tee1_computation_64(global_eid1, half_count, xr1, yr2, tres);
        auto t2_prep_end = std::chrono::high_resolution_clock::now();

        
        { 
            std::unique_lock<std::mutex> lock(shared.mtx); 
            shared.cv.wait(lock, [&]() { return shared.recv_done; }); 
        }
        auto t2_wait_end = std::chrono::high_resolution_clock::now();

        
        for (uint64_t i = 0; i < half_count; i++) {
            shared.res_tee[i] = ((shared.recv_x[i] + input_a[i]) * (shared.recv_y[i] + input_b[i])) + tres[i];
        }
        auto t2_recon_end = std::chrono::high_resolution_clock::now();
        
        delete[] r1_p1; delete[] r2_p1; delete[] xr1; delete[] yr2; delete[] tres;
        
        
        stats.t2_prep = std::chrono::duration_cast<std::chrono::microseconds>(t2_prep_end - t2_start).count();
        stats.t2_wait = std::chrono::duration_cast<std::chrono::microseconds>(t2_wait_end - t2_prep_end).count();
        stats.t2_recon = std::chrono::duration_cast<std::chrono::microseconds>(t2_recon_end - t2_wait_end).count();
        stats.t2_total = stats.t2_prep + stats.t2_wait + stats.t2_recon; 
    });



    long create_cost = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all(); 

    
    auto t_join_start = std::chrono::high_resolution_clock::now();
    t1.join(); t2.join(); t3.join(); t4.join();
    long join_cost = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - t_join_start).count();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.waste_time = create_cost;
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - func_start).count();

    
    for (uint64_t i = 0; i < half_count; i++) output[i] = shared.res_tee[i];
    for (uint64_t i = 0; i < second_count; i++) output[half_count + i] = shared.res_local[i];
    
    

    delete[] shared.res_tee; delete[] shared.res_local; delete[] shared.recv_buf;
    delete[] a_p2; delete[] b_p2;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] DualPort Breakdown:\n");
    TIME_PRINTF("  Offline Time (a,b)   : %ld us\n", stats.offline_time);
    TIME_PRINTF("  t1 (Recv)            : %ld us (Bytes: %ld)\n", stats.t1_time, stats.recv_bytes);
    TIME_PRINTF("  t2 (TEE)             : %ld us\n", stats.t2_total);
    TIME_PRINTF("      |-- Prep (RNG+TEE): %ld us\n", stats.t2_prep);
    TIME_PRINTF("      |-- Wait (Sync)   : %ld us\n", stats.t2_wait);
    TIME_PRINTF("      |-- Load (Recon)  : %ld us\n", stats.t2_recon);
    TIME_PRINTF("  t3 (Send)            : %ld us (Calc: %ld, Send: %ld)\n",
           stats.t3_total, stats.t3_calc, stats.t3_send);
    TIME_PRINTF("  t4 (Local Calc P2)   : %ld us\n", stats.t4_time);
    TIME_PRINTF("  Start Overhead       : %ld us\n", stats.waste_time);
    TIME_PRINTF("  Online Wall Time     : %ld us\n", stats.online_wall);
    TIME_PRINTF("  Total Function       : %ld us\n", stats.total_func);
    TIME_PRINTF("  Comm Bytes           : send=%ld recv=%ld\n", stats.send_bytes, stats.recv_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}

void secure_triple_multiply_batch_dualport_time(BSNet* send_channel, BSNet* recv_channel, bool is_csp0,
                                         const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w, 
                                         uint64_t* output, uint64_t count, uint64_t s, uint64_t L) {
    using uint128_t = unsigned __int128;

    
    struct PerfStats {
        long offline_time = 0;
        long send_total = 0;   long send_calc = 0; long send_net = 0; 
        long local_time = 0;   long local_rng = 0;                    
        long recv_time = 0;                                           
        long tee_total = 0;    long tee_prep = 0; long tee_wait = 0; long tee_recon = 0; 
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    
    
    uint64_t seedT = 123456;
    uint64_t seedT_Part2 = seedT + 2000;
    
    uint64_t seedC = 654321;
    uint64_t seedC_Part2 = seedC + 5000;

    uint64_t half_count = count / 2;
    uint64_t second_count = count - half_count;

    
    auto t_off_start = std::chrono::high_resolution_clock::now();

    
    uint64_t *a = new uint64_t[second_count]; uint64_t *b = new uint64_t[second_count]; 
    uint64_t *c = new uint64_t[second_count]; uint64_t *r0 = new uint64_t[second_count];
    
    uint64_t *r1 = new uint64_t[count]; uint64_t *r2 = new uint64_t[count]; uint64_t *r3 = new uint64_t[count];
    uint64_t *r4 = new uint64_t[count]; uint64_t *r5 = new uint64_t[count]; uint64_t *r6 = new uint64_t[count];

    
    generate_consistent_random_64_time(a, second_count, seedT_Part2);
    generate_consistent_random_64_time(b, second_count, seedT_Part2 + 1);
    generate_consistent_random_64_time(c, second_count, seedT_Part2 + 2);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_off_start).count();

    
    struct SharedData {
        uint64_t* res_local = nullptr; uint64_t* res_tee = nullptr; 
        uint64_t* recv_buf = nullptr;
        uint64_t* px = nullptr; uint64_t* py = nullptr; uint64_t* pw = nullptr;
        bool recv_done = false; std::mutex mtx; std::condition_variable cv;
    } shared;

    
    shared.res_tee = new uint64_t[half_count];
    shared.res_local = new uint64_t[second_count];
    
    
    shared.recv_buf = new uint64_t[half_count * 3];
    shared.px = shared.recv_buf; 
    shared.py = shared.recv_buf + half_count; 
    shared.pw = shared.recv_buf + half_count * 2;

    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;

    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    std::thread t1([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();
        
        recv_channel->recvMsg(shared.recv_buf, half_count * 3 * sizeof(uint64_t), 0);
        
        stats.recv_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_start).count();
        
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    
    std::thread t2([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* xr1 = new uint64_t[half_count]; uint64_t* yr2 = new uint64_t[half_count]; 
        uint64_t* wr3 = new uint64_t[half_count]; uint64_t* tf = new uint64_t[half_count];
        
        
        
        generate_consistent_random_64_time(r1, half_count, seedC);
        generate_consistent_random_64_time(r2, half_count, seedC + 1);
        generate_consistent_random_64_time(r3, half_count, seedC + 2);
        generate_consistent_random_64_time(r4, half_count, seedC + 3);
        generate_consistent_random_64_time(r5, half_count, seedC + 4);
        generate_consistent_random_64_time(r6, half_count, seedC + 5);

        
        ecall_3smp_gen_abc_r0_64(global_eid1, seedT, half_count);

        
        for (uint64_t i = 0; i < half_count; i++) {
            xr1[i] = input_x[i] + r1[i]; yr2[i] = input_y[i] + r2[i]; wr3[i] = input_w[i] + r3[i];
        }
        
        
        ecall_3smp_tee1_compute_m3_64(global_eid1, half_count, xr1, yr2, wr3);
        
        auto t_prep_end = std::chrono::high_resolution_clock::now();

        
        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.recv_done; }); }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        
        uint64_t* U = xr1; uint64_t* V = yr2; uint64_t* W = wr3;
        for (uint64_t i = 0; i < half_count; i++) {
            uint64_t Xa = shared.px[i] + input_x[i]; uint64_t Yb = shared.py[i] + input_y[i]; uint64_t Wc = shared.pw[i] + input_w[i];
            U[i] = Yb * Wc + r4[i]; V[i] = Xa * Wc + r5[i]; W[i] = Xa * Yb + r6[i];
            shared.res_tee[i] = (uint64_t)((uint128_t)Xa * Yb * Wc);
        }
        ecall_3smp_tee1_compute_m4_64(global_eid1, half_count, U, V, W, tf);
        for (uint64_t i = 0; i < half_count; i++) shared.res_tee[i] += tf[i];
        
        auto t_recon_end = std::chrono::high_resolution_clock::now();
        delete[] xr1; delete[] yr2; delete[] wr3; delete[] tf;

        stats.tee_prep = std::chrono::duration_cast<std::chrono::microseconds>(t_prep_end - t_start).count();
        stats.tee_wait = std::chrono::duration_cast<std::chrono::microseconds>(t_wait_end - t_prep_end).count();
        stats.tee_recon = std::chrono::duration_cast<std::chrono::microseconds>(t_recon_end - t_wait_end).count();
        stats.tee_total = stats.tee_prep + stats.tee_wait + stats.tee_recon;
    });

    
    std::thread t3([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();
        uint64_t* sbuf = new uint64_t[second_count * 3];
        
        
        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            sbuf[i] = input_x[idx] + a[i]; 
            sbuf[second_count+i] = input_y[idx] + b[i]; 
            sbuf[second_count*2+i] = input_w[idx] + c[i];
        }
        auto t_calc_end = std::chrono::high_resolution_clock::now();

        
        send_channel->sendMsg(sbuf, second_count * 3 * sizeof(uint64_t), 0);
        auto t_send_end = std::chrono::high_resolution_clock::now();
        
        delete[] sbuf;
        stats.send_calc = std::chrono::duration_cast<std::chrono::microseconds>(t_calc_end - t_start).count();
        stats.send_net = std::chrono::duration_cast<std::chrono::microseconds>(t_send_end - t_calc_end).count();
        stats.send_total = stats.send_calc + stats.send_net;
    });

    
    std::thread t4([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();
        
        
        generate_consistent_random_64_time(r0, second_count, seedT_Part2 + 3);

        uint64_t* r1_p2 = r1 + half_count; uint64_t* r2_p2 = r2 + half_count; uint64_t* r3_p2 = r3 + half_count;
        uint64_t* r4_p2 = r4 + half_count; uint64_t* r5_p2 = r5 + half_count; uint64_t* r6_p2 = r6 + half_count;

        generate_consistent_random_64_time(r1_p2, second_count, seedC_Part2);
        generate_consistent_random_64_time(r2_p2, second_count, seedC_Part2 + 1);
        generate_consistent_random_64_time(r3_p2, second_count, seedC_Part2 + 2);
        generate_consistent_random_64_time(r4_p2, second_count, seedC_Part2 + 3);
        generate_consistent_random_64_time(r5_p2, second_count, seedC_Part2 + 4);
        generate_consistent_random_64_time(r6_p2, second_count, seedC_Part2 + 5);

        auto t_rng_end = std::chrono::high_resolution_clock::now();

        
        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            uint64_t m1_val = 2*a[i]*b[i]*c[i] + a[i]*r4_p2[i] + b[i]*r5_p2[i] + c[i]*r6_p2[i];
            uint64_t m2_val = a[i]*b[i]*(input_w[idx]-r3_p2[i]) + a[i]*c[i]*(input_y[idx]-r2_p2[i]) + b[i]*c[i]*(input_x[idx]-r1_p2[i]);
            shared.res_local[i] = m1_val + m2_val - r0[i];
        }
        stats.local_rng = std::chrono::duration_cast<std::chrono::microseconds>(t_rng_end - t_start).count();
        stats.local_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_start).count();
    });

    stats.waste_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    
    t1.join(); t2.join(); t3.join(); t4.join();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();
    
    for(uint64_t i=0; i<half_count; i++) output[i] = shared.res_tee[i];
    for(uint64_t i=0; i<second_count; i++) output[half_count+i] = shared.res_local[i];

    
    delete[] shared.res_local; delete[] shared.res_tee; delete[] shared.recv_buf;
    delete[] a; delete[] b; delete[] c; delete[] r0; 
    delete[] r1; delete[] r2; delete[] r3; delete[] r4; delete[] r5; delete[] r6;



    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Triple Mul DualPort Breakdown:\n");
    TIME_PRINTF("  Offline/Init Time    : %ld us\n", stats.offline_time);
    TIME_PRINTF("  t1 (Recv P1)         : %ld us\n", stats.recv_time);
    TIME_PRINTF("  t2 (TEE Calc P1)     : %ld us\n", stats.tee_total);
    TIME_PRINTF("      |-- Prep         : %ld us\n", stats.tee_prep);
    TIME_PRINTF("      |-- Wait (Sync)  : %ld us\n", stats.tee_wait);
    TIME_PRINTF("      |-- Recon        : %ld us\n", stats.tee_recon);
    TIME_PRINTF("  t3 (Send P2)         : %ld us (Calc: %ld, Send: %ld)\n",
           stats.send_total, stats.send_calc, stats.send_net);
    TIME_PRINTF("  t4 (Local Calc P2)   : %ld us (RNG: %ld)\n", stats.local_time, stats.local_rng);
    TIME_PRINTF("  Start Overhead       : %ld us\n", stats.waste_time);
    TIME_PRINTF("  Online Wall Time     : %ld us\n", stats.online_wall);
    TIME_PRINTF("  Total Function       : %ld us\n", stats.total_func);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void host_odrelu_gen_params_time(uint64_t seed, uint64_t count, uint64_t xi,
                            uint64_t* a, uint64_t* b, uint64_t* r0, uint64_t* r1, uint64_t* v) {
    
    uint64_t* raw_rand = new uint64_t[count * 5];
    generate_consistent_random_64_time(raw_rand, count * 5, seed);
    
    uint64_t two_xi = 2 * xi;

    for (uint64_t i = 0; i < count; i++) {
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
            a[i] = abs_a;
            b[i] = abs_b;
            if(v) v[i] = 0;
        } else {
            a[i] = 0 - abs_a; 
            b[i] = 0 - abs_b;
            if(v) v[i] = 1;
        }
        
        if(r0) r0[i] = r_r0;
        if(r1) r1[i] = r_r1;
    }
    delete[] raw_rand;
}

void ODReLU_CSP1_2Threads_64_time(BSNet* client_port12345, const uint64_t* x1_input, uint64_t* drelu_output, int vector_size) {
    struct PerfStats {
        long init_time = 0;      
        long b3_time = 0;        
        long a2_time = 0;        
        long c_time = 0;         
        long create_time = 0;    
        long online_wall = 0;    
        long total_func = 0;
        long comm_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t L = UINT64_MAX;
    
    uint64_t seedT = 123456;
    uint64_t seedC = 654321;
    uint64_t xi = 100;
    
    
    uint64_t* x1 = new uint64_t[vector_size];
    memcpy(x1, x1_input, vector_size * sizeof(uint64_t));

    struct SharedData {
        uint64_t* csp0_data; uint64_t* c1;  
        bool network_done = false; std::mutex mtx; std::condition_variable cv;
        SharedData(int size) { csp0_data = new uint64_t[size]; c1 = new uint64_t[size]; }
        ~SharedData() { delete[] csp0_data; delete[] c1; }
    } shared(vector_size);
    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    
    auto t_create_start = std::chrono::high_resolution_clock::now();
    
    
    auto networkThread = std::thread([&]() {
        wait_for_gun(); 
        auto t1_start = std::chrono::high_resolution_clock::now();

        long bytes = vector_size * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        client_port12345->recvMsg(shared.csp0_data, bytes, 0);
        
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.network_done = true; }
        shared.cv.notify_one();

        stats.b3_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t1_start).count();
    });
    
    
    auto computeThread = std::thread([&]() {
        wait_for_gun(); 
        
        
        auto t_a2_start = std::chrono::high_resolution_clock::now();

        uint64_t* r2_local = new uint64_t[vector_size];
        uint64_t* r3_local = new uint64_t[vector_size];
        uint64_t* r4_local = new uint64_t[vector_size];
        
        
        generateRandomArrayUint64_time(r2_local, vector_size, seedC, 100);
        generateRandomArrayUint64_time(r3_local, vector_size, seedC + 1, 100);
        generateRandomArrayUint64_time(r4_local, vector_size, seedC + 2, 100);
        ecall_odrelu_gen_shared_randomness_final_uint64(global_eid1, seedT, vector_size, xi);
        uint64_t* x1_m_r2 = new uint64_t[vector_size];
        uint64_t* res1 = new uint64_t[vector_size];
        
        
        for (int i = 0; i < vector_size; i++) x1_m_r2[i] = x1[i] - r2_local[i];
        ecall_odrelu_tee1_step1_uint64(global_eid1, vector_size, x1_m_r2, res1);
        
        stats.a2_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_a2_start).count();
        
        
        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.network_done; }); }
        
        
        
        auto t_c_start = std::chrono::high_resolution_clock::now();

        uint64_t* z_p_r3 = new uint64_t[vector_size];
        for (int i = 0; i < vector_size; i++) {
            uint64_t s = shared.csp0_data[i] + res1[i];
            z_p_r3[i] = ((s < L/2) ? 1 : 0) + r3_local[i];
        }
        
        uint64_t* res2 = new uint64_t[vector_size];
        ecall_odrelu_tee1_step2_uint64(global_eid1, vector_size, z_p_r3, res2);
        
        for (int i = 0; i < vector_size; i++) shared.c1[i] = res2[i] - r4_local[i];
        
        stats.c_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_c_start).count();
        

        delete[] r2_local; delete[] r3_local; delete[] r4_local;
        delete[] x1_m_r2; delete[] res1; delete[] z_p_r3; delete[] res2;
    });
    
    stats.create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    networkThread.join();
    computeThread.join();
    
    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();
    for (int i = 0; i < vector_size; i++) drelu_output[i] = shared.c1[i];
    delete[] x1;

    long thread_waste = stats.create_time;
    ODRELU_TIME_PRINTF("---------------------------------------------\n");
    ODRELU_TIME_PRINTF("[CSP1] ODReLU 2Threads:\n");
    ODRELU_TIME_PRINTF("a2时间（随机数+TEE Step1）: %ld us\n", stats.a2_time);
    ODRELU_TIME_PRINTF("b3时间（网络接收时间）: %ld us\n", stats.b3_time);
    ODRELU_TIME_PRINTF("c时间 （重构+TEE Step2）: %ld us\n", stats.c_time);
    ODRELU_TIME_PRINTF("创建线程浪费时间: %ld us\n", thread_waste);
    ODRELU_TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    ODRELU_TIME_PRINTF("总时间: %ld us\n", stats.total_func);
    ODRELU_TIME_PRINTF("接收多少byte: %ld bytes\n", stats.comm_bytes);
    ODRELU_TIME_PRINTF("---------------------------------------------\n\n");
}
void ODReLU_CSP1_4Threads_64_time(BSNet* client_port12345, BSNet* server_port12346,
                             const uint64_t* x1_input, uint64_t* drelu_output, 
                             int vector_size) {
    
    
    struct PerfStats {
        long init_offline = 0;   
        long t1_recv = 0;        
        long t2_prep = 0;        
        long t2_ecall1 = 0;      
        long t2_wait = 0;        
        long t2_recon = 0;       
        long t2_ecall2 = 0;      
        long t3_calc = 0;        
        long t3_send = 0;        
        long t4_calc = 0;        
        long waste_time = 0;     
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;     
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    

    const uint64_t L = UINT64_MAX;
    int half_size = vector_size / 2;
    int second_size = vector_size - half_size;
    
    uint64_t seedT = 123456;
    uint64_t seedT_Part2 = seedT + 1000;
    uint64_t seedC = 654321;
    uint64_t xi = 100;

    
    uint64_t* a_loc = new uint64_t[second_size];
    uint64_t* b_loc = new uint64_t[second_size];
    uint64_t* r0_loc = new uint64_t[second_size];
    uint64_t* r1_loc = new uint64_t[second_size];
    uint64_t* v_loc = new uint64_t[second_size];
    
    
    auto init_start = std::chrono::high_resolution_clock::now();

    
    host_odrelu_gen_params_time(seedT_Part2, second_size, xi, a_loc, b_loc, r0_loc, r1_loc, v_loc);

    stats.init_offline = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - init_start).count();
    

    
    struct SharedData {
        uint64_t* c1_first = nullptr;      
        uint64_t* c0_second = nullptr;     
        uint64_t* csp0_send_data = nullptr;
        uint64_t* r2 = nullptr;            
        uint64_t* r3 = nullptr;
        uint64_t* r4 = nullptr;
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
        
        SharedData(int total_size, int part1_size, int part2_size) {
            c1_first = new uint64_t[part1_size]();
            c0_second = new uint64_t[part2_size]();
            csp0_send_data = new uint64_t[part1_size]();
            r2 = new uint64_t[total_size]();
            r3 = new uint64_t[total_size]();
            r4 = new uint64_t[total_size]();
        }
        ~SharedData() {
            delete[] c1_first; delete[] c0_second; delete[] csp0_send_data;
            delete[] r2; delete[] r3; delete[] r4;
        }
    } shared(vector_size, half_size, second_size);

    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };
    
    auto t_create_start = std::chrono::high_resolution_clock::now();
    
    
    
    auto t1 = std::thread([&]() {
        wait_for_gun(); 

        long bytes = half_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto recv_start = std::chrono::high_resolution_clock::now();
        client_port12345->recvMsg(shared.csp0_send_data, bytes, 0);
        stats.t1_recv = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recv_start).count();

        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_done = true;
        }
        shared.cv.notify_one();
    });
    
    
    auto t2 = std::thread([&]() {
        wait_for_gun(); 

        
        generateRandomArrayUint64_time(&shared.r2[0], half_size, seedC, 100);
        generateRandomArrayUint64_time(&shared.r3[0], half_size, seedC + 1, 100);
        generateRandomArrayUint64_time(&shared.r4[0], half_size, seedC + 2, 100);

        uint64_t* buf = new uint64_t[half_size];
        uint64_t* res = new uint64_t[half_size];

        
        auto prep_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            buf[i] = x1_input[i] - shared.r2[i];
        }

        ecall_odrelu_gen_shared_randomness_final_uint64(global_eid1, seedT, half_size, xi);
        stats.t2_prep = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - prep_start).count();

        
        auto ecall1_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step1_uint64(global_eid1, half_size, buf, res);

        stats.t2_ecall1 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall1_start).count();

        
        auto wait_start = std::chrono::high_resolution_clock::now();
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }
        stats.t2_wait = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - wait_start).count();

        
        auto recon_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            uint64_t s = shared.csp0_send_data[i] + res[i];
            buf[i] = ((s < L/2) ? 1 : 0) + shared.r3[i];
        }

        stats.t2_recon = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recon_start).count();

        
        auto ecall2_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step2_uint64(global_eid1, half_size, buf, res);

        stats.t2_ecall2 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall2_start).count();

        
        for (int i = 0; i < half_size; i++) {
            shared.c1_first[i] = res[i] - shared.r4[i];
        }

        delete[] buf; delete[] res;
    });
    
    
    auto t3 = std::thread([&]() {
        wait_for_gun(); 

        
        generateRandomArrayUint64_time(&shared.r2[half_size], second_size, seedC + 3, 100);
        uint64_t* sbuf = new uint64_t[second_size];

        
        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            int idx = half_size + i;
            sbuf[i] = a_loc[i] * (x1_input[idx] + shared.r2[idx]) + b_loc[i] + r0_loc[i];
        }

        stats.t3_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();

        
        long bytes = second_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto send_start = std::chrono::high_resolution_clock::now();
        server_port12346->sendMsg(sbuf, bytes, 0);
        stats.t3_send = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - send_start).count();
        delete[] sbuf;
    });
    
    
    auto t4 = std::thread([&]() {
        wait_for_gun(); 

        
        generateRandomArrayUint64_time(&shared.r3[half_size], second_size, seedC + 4, 100);
        generateRandomArrayUint64_time(&shared.r4[half_size], second_size, seedC + 5, 100);

        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            int idx = half_size + i;
            shared.c0_second[i] = (v_loc[i] == 0)
                ? (shared.r4[idx] - shared.r3[idx] - r1_loc[i])
                : (shared.r3[idx] - r1_loc[i] + shared.r4[idx]);
        }

        stats.t4_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();
    });
    
    
    stats.waste_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    
    t1.join(); t2.join(); t3.join(); t4.join();
    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();

    
    for (int i = 0; i < half_size; i++) drelu_output[i] = shared.c1_first[i];
    for (int i = 0; i < second_size; i++) drelu_output[half_size + i] = shared.c0_second[i];

    
    delete[] a_loc; delete[] b_loc; delete[] r0_loc; delete[] r1_loc; delete[] v_loc;

    long t2_total = stats.t2_prep + stats.t2_ecall1 + stats.t2_wait + stats.t2_recon + stats.t2_ecall2;
    long t3_total = stats.t3_calc + stats.t3_send;
    ODRELU_TIME_PRINTF("---------------------------------------------\n");
    ODRELU_TIME_PRINTF("[CSP1] ODReLU 4Threads:\n");
    ODRELU_TIME_PRINTF("  Offline Init        : %ld us\n", stats.init_offline);
    ODRELU_TIME_PRINTF("  t1 (Recv Part1)     : %ld us\n", stats.t1_recv);
    ODRELU_TIME_PRINTF("  t2 (TEE Part1)      : %ld us\n", t2_total);
    ODRELU_TIME_PRINTF("      |-- Prep        : %ld us\n", stats.t2_prep);
    ODRELU_TIME_PRINTF("      |-- ECALL1      : %ld us\n", stats.t2_ecall1);
    ODRELU_TIME_PRINTF("      |-- Wait        : %ld us\n", stats.t2_wait);
    ODRELU_TIME_PRINTF("      |-- Recon       : %ld us\n", stats.t2_recon);
    ODRELU_TIME_PRINTF("      |-- ECALL2      : %ld us\n", stats.t2_ecall2);
    ODRELU_TIME_PRINTF("  t3 (Send Part2)     : %ld us (Calc: %ld, Send: %ld)\n",
           t3_total, stats.t3_calc, stats.t3_send);
    ODRELU_TIME_PRINTF("  t4 (Local Part2)    : %ld us\n", stats.t4_calc);
    ODRELU_TIME_PRINTF("  Start Overhead      : %ld us\n", stats.waste_time);
    ODRELU_TIME_PRINTF("  Online Wall Time    : %ld us\n", stats.online_wall);
    ODRELU_TIME_PRINTF("  Total Function      : %ld us\n", stats.total_func);
    ODRELU_TIME_PRINTF("  Comm Bytes          : %ld bytes\n", stats.comm_bytes);
    ODRELU_TIME_PRINTF("---------------------------------------------\n\n");
}


void ODReLU_CSP1_4Threads_64_v2_time(BSNet* client_port12345, BSNet* server_port12346,
                                 const uint64_t* x1_input, uint64_t* drelu_output,
                                 int vector_size) {
    struct PerfStats {
        long init_offline = 0;
        long t1_recv = 0;
        long t2_prep = 0;
        long t2_ecall1 = 0;
        long t2_wait = 0;
        long t2_recon = 0;
        long t2_ecall2 = 0;
        long t3_calc = 0;
        long t3_send = 0;
        long t4_calc = 0;
        long waste_time = 0;
        long online_wall = 0;
        long total_func = 0;
        long comm_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    const uint64_t L = UINT64_MAX;
    int half_size = vector_size / 2;
    int second_size = vector_size - half_size;

    uint64_t seedT = 123456;
    uint64_t seedT_Part2 = seedT + 1000;
    uint64_t seedC = 654321;
    uint64_t xi = 100;

    uint64_t* a_loc = new uint64_t[second_size];
    uint64_t* b_loc = new uint64_t[second_size];
    uint64_t* r0_loc = new uint64_t[second_size];
    uint64_t* r1_loc = new uint64_t[second_size];
    uint64_t* v_loc = new uint64_t[second_size];

    auto init_start = std::chrono::high_resolution_clock::now();
    host_odrelu_gen_params_time(seedT_Part2, second_size, xi, a_loc, b_loc, r0_loc, r1_loc, v_loc);
    stats.init_offline = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - init_start).count();

    struct SharedData {
        uint64_t* c1_first = nullptr;
        uint64_t* c0_second = nullptr;
        uint64_t* csp0_send_data = nullptr;
        uint64_t* r2 = nullptr;
        uint64_t* r3 = nullptr;
        uint64_t* r4 = nullptr;
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
        SharedData(int total_size, int part1_size, int part2_size) {
            c1_first = new uint64_t[part1_size]();
            c0_second = new uint64_t[part2_size]();
            csp0_send_data = new uint64_t[part1_size]();
            r2 = new uint64_t[total_size]();
            r3 = new uint64_t[total_size]();
            r4 = new uint64_t[total_size]();
        }
        ~SharedData() {
            delete[] c1_first; delete[] c0_second; delete[] csp0_send_data;
            delete[] r2; delete[] r3; delete[] r4;
        }
    } shared(vector_size, half_size, second_size);

    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1 = std::thread([&]() {
        wait_for_gun();
        long bytes = half_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto recv_start = std::chrono::high_resolution_clock::now();
        client_port12345->recvMsg(shared.csp0_send_data, bytes, 0);
        stats.t1_recv = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recv_start).count();
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    
    auto t2 = std::thread([&]() {
        wait_for_gun();
        generateRandomArrayUint64_time(&shared.r2[0], half_size, seedC, 100);
        generateRandomArrayUint64_time(&shared.r3[0], half_size, seedC + 1, 100);
        generateRandomArrayUint64_time(&shared.r4[0], half_size, seedC + 2, 100);

        uint64_t* buf = new uint64_t[half_size];
        uint64_t* res = new uint64_t[half_size];

        auto prep_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            buf[i] = x1_input[i] - shared.r2[i];
        }
        
        ecall_odrelu_gen_shared_randomness_final_uint64_v2(global_eid1, seedT, half_size, xi);
        stats.t2_prep = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - prep_start).count();

        auto ecall1_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step1_uint64_v2(global_eid1, half_size, buf, res);
        stats.t2_ecall1 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall1_start).count();

        auto wait_start = std::chrono::high_resolution_clock::now();
        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.recv_done; }); }
        stats.t2_wait = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - wait_start).count();

        auto recon_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            uint64_t s = shared.csp0_send_data[i] + res[i];
            buf[i] = ((s < L/2) ? 1 : 0) + shared.r3[i];
        }
        stats.t2_recon = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recon_start).count();

        auto ecall2_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step2_uint64_v2(global_eid1, half_size, buf, res);
        stats.t2_ecall2 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall2_start).count();

        for (int i = 0; i < half_size; i++) {
            shared.c1_first[i] = res[i] - shared.r4[i];
        }
        delete[] buf; delete[] res;
    });

    
    auto t3 = std::thread([&]() {
        wait_for_gun();
        generateRandomArrayUint64_time(&shared.r2[half_size], second_size, seedC + 3, 100);
        uint64_t* sbuf = new uint64_t[second_size];

        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            int idx = half_size + i;
            sbuf[i] = a_loc[i] * (x1_input[idx] + shared.r2[idx]) + b_loc[i] + r0_loc[i];
        }
        stats.t3_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();

        long bytes = second_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto send_start = std::chrono::high_resolution_clock::now();
        server_port12346->sendMsg(sbuf, bytes, 0);
        stats.t3_send = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - send_start).count();
        delete[] sbuf;
    });

    
    auto t4 = std::thread([&]() {
        wait_for_gun();
        generateRandomArrayUint64_time(&shared.r3[half_size], second_size, seedC + 4, 100);
        generateRandomArrayUint64_time(&shared.r4[half_size], second_size, seedC + 5, 100);

        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            int idx = half_size + i;
            shared.c0_second[i] = (v_loc[i] == 0)
                ? (shared.r4[idx] - shared.r3[idx] - r1_loc[i])
                : (shared.r3[idx] - r1_loc[i] + shared.r4[idx]);
        }
        stats.t4_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();
    });

    stats.waste_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    auto t_online_start = std::chrono::high_resolution_clock::now();
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    t1.join(); t2.join(); t3.join(); t4.join();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();

    for (int i = 0; i < half_size; i++) drelu_output[i] = shared.c1_first[i];
    for (int i = 0; i < second_size; i++) drelu_output[half_size + i] = shared.c0_second[i];

    delete[] a_loc; delete[] b_loc; delete[] r0_loc; delete[] r1_loc; delete[] v_loc;

    long t2_total = stats.t2_prep + stats.t2_ecall1 + stats.t2_wait + stats.t2_recon + stats.t2_ecall2;
    long t3_total = stats.t3_calc + stats.t3_send;
    ODRELU_TIME_PRINTF("---------------------------------------------\n");
    ODRELU_TIME_PRINTF("[CSP1] ODReLU 4Threads v2:\n");
    ODRELU_TIME_PRINTF("  Offline Init        : %ld us\n", stats.init_offline);
    ODRELU_TIME_PRINTF("  t1 (Recv Part1)     : %ld us\n", stats.t1_recv);
    ODRELU_TIME_PRINTF("  t2 (TEE Part1)      : %ld us\n", t2_total);
    ODRELU_TIME_PRINTF("      |-- Prep        : %ld us\n", stats.t2_prep);
    ODRELU_TIME_PRINTF("      |-- ECALL1      : %ld us\n", stats.t2_ecall1);
    ODRELU_TIME_PRINTF("      |-- Wait        : %ld us\n", stats.t2_wait);
    ODRELU_TIME_PRINTF("      |-- Recon       : %ld us\n", stats.t2_recon);
    ODRELU_TIME_PRINTF("      |-- ECALL2      : %ld us\n", stats.t2_ecall2);
    ODRELU_TIME_PRINTF("  t3 (Send Part2)     : %ld us (Calc: %ld, Send: %ld)\n",
           t3_total, stats.t3_calc, stats.t3_send);
    ODRELU_TIME_PRINTF("  t4 (Local Part2)    : %ld us\n", stats.t4_calc);
    ODRELU_TIME_PRINTF("  Start Overhead      : %ld us\n", stats.waste_time);
    ODRELU_TIME_PRINTF("  Online Wall Time    : %ld us\n", stats.online_wall);
    ODRELU_TIME_PRINTF("  Total Function      : %ld us\n", stats.total_func);
    ODRELU_TIME_PRINTF("  Comm Bytes          : %ld bytes\n", stats.comm_bytes);
    ODRELU_TIME_PRINTF("---------------------------------------------\n\n");
}






void mat_mul_time(const uint64_t* A, const uint64_t* B, uint64_t* C, int m, int k, int n) {
    if (!C) return;
    memset(C, 0, (size_t)m * n * sizeof(uint64_t));
    bool use_omp = (m > 64);
    #pragma omp parallel for if(use_omp)
    for (int i = 0; i < m; i++) {
        const uint64_t* row_A = A + i * k;
        uint64_t* row_C = C + i * n;
        for (int p = 0; p < k; p++) {
            uint64_t a_val = row_A[p];
            if (a_val == 0) continue;
            const uint64_t* row_B = B + p * n;
            for (int j = 0; j < n; j++) {
                row_C[j] += a_val * row_B[j];
            }
        }
    }
}

inline void vec_add(const uint64_t* a, const uint64_t* b, uint64_t* c, size_t n) {
    for(size_t i=0; i<n; i++) c[i] = a[i] + b[i];
}

inline void vec_sub(const uint64_t* a, const uint64_t* b, uint64_t* c, size_t n) {
    for(size_t i=0; i<n; i++) c[i] = a[i] - b[i];
}



void secure_matrix_multiply_batch_csp1_time(
    BSNet* server, 
    const uint64_t* input_X, 
    const uint64_t* input_Y, 
    uint64_t* output_Z, 
    int m, int k, int n,
    int batch_count 
) {
    auto now = []() { return std::chrono::high_resolution_clock::now(); };
    auto diff_us = [](auto start, auto end) { 
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count(); 
    };
    auto start_total = now();

    
    long t_rand = 0;
    long t_tee_init = 0;
    long t_recv_net = 0;
    long t_tee_prep = 0;
    long t_ecall = 0;
    long t_wait = 0;
    long t_final_calc = 0;

    uint64_t seedT = 123456;
    uint64_t seedC = 654321;
    
    size_t len_one_X = (size_t)m * k;
    size_t len_one_Y = (size_t)k * n;
    size_t len_one_Z = (size_t)m * n;
    
    size_t total_X = len_one_X * batch_count;
    size_t total_Y = len_one_Y * batch_count;
    size_t total_Z = len_one_Z * batch_count;

    
    auto t1 = now();
    std::vector<uint64_t> R1(total_X), R2(total_Y);
    generate_consistent_random_64_time(R1.data(), total_X, seedC);
    generate_consistent_random_64_time(R2.data(), total_Y, seedC + 1);
    t_rand = diff_us(t1, now());

    
    auto t2 = now();
    ecall_matrix_batch_init(global_eid1, seedT, m, k, n, batch_count);
    t_tee_init = diff_us(t2, now());

    struct SharedData {
        std::vector<uint64_t> recv_buffer; 
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;

    
    std::thread t_recv([&]() {
        size_t total_recv_size = total_X + total_Y;
        std::vector<uint64_t> buf(total_recv_size);
        
        auto tr1 = now();
        server->recvMsg(buf.data(), total_recv_size * sizeof(uint64_t), 0);
        t_recv_net = diff_us(tr1, now());

        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_buffer = std::move(buf);
            shared.recv_done = true;
        }
        shared.cv.notify_one();
    });

    
    std::thread t_comp([&]() {
        
        auto tp1 = now();
        std::vector<uint64_t> X_plus_R(total_X);
        std::vector<uint64_t> Y_plus_R(total_Y);
        
        bool enable_omp_vec = (total_X > 50000);
        
        #pragma omp parallel sections if(enable_omp_vec)
        {
            #pragma omp section 
            {
                #pragma omp parallel for if(enable_omp_vec)
                for(size_t i=0; i<total_X; i++) X_plus_R[i] = input_X[i] + R1[i];
            }
            #pragma omp section
            {
                #pragma omp parallel for if(enable_omp_vec)
                for(size_t i=0; i<total_Y; i++) Y_plus_R[i] = input_Y[i] + R2[i];
            }
        }
        t_tee_prep = diff_us(tp1, now());

        
        auto te1 = now();
        std::vector<uint64_t> Tout(total_Z);
        
        ecall_matrix_batch_compute(
            global_eid1, m, k, n, batch_count,
            X_plus_R.data(), total_X, 
            Y_plus_R.data(), total_Y, 
            Tout.data(), total_Z      
        );
        t_ecall = diff_us(te1, now());

        
        auto tw1 = now();
        std::vector<uint64_t> local_buf;
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&](){ return shared.recv_done; });
            local_buf = std::move(shared.recv_buffer);
        }
        t_wait = diff_us(tw1, now());

        
        auto tf1 = now();
        const uint64_t* ptr_recv_X = local_buf.data();          
        const uint64_t* ptr_recv_Y = local_buf.data() + total_X; 

        
        std::vector<uint64_t> X_hat(len_one_X);
        std::vector<uint64_t> Y_hat(len_one_Y);
        std::vector<uint64_t> Z_main(len_one_Z);

        for (int i = 0; i < batch_count; i++) {
            size_t off_X = i * len_one_X;
            size_t off_Y = i * len_one_Y;
            size_t off_Z = i * len_one_Z;

            
            vec_add(ptr_recv_X + off_X, input_X + off_X, X_hat.data(), len_one_X);
            vec_add(ptr_recv_Y + off_Y, input_Y + off_Y, Y_hat.data(), len_one_Y);
            
            
            mat_mul_time(X_hat.data(), Y_hat.data(), Z_main.data(), m, k, n);

            
            vec_add(Z_main.data(), Tout.data() + off_Z, output_Z + off_Z, len_one_Z);
        }
        t_final_calc = diff_us(tf1, now());
    });

    t_recv.join();
    t_comp.join();

    long t_total = diff_us(start_total, now());

    TIME_PRINTF("\n=== CSP1 Batch Timings [Count %d] ===\n", batch_count);
    TIME_PRINTF("1. Random Gen   : %ld us\n", t_rand);
    TIME_PRINTF("2. TEE Init     : %ld us\n", t_tee_init);
    TIME_PRINTF("3. Thread Recv  :\n"); 
    TIME_PRINTF("   |- Network Recv: %ld us\n", t_recv_net);
    TIME_PRINTF("4. Thread Comp  :\n");
    TIME_PRINTF("   |- TEE Prep     : %ld us (OMP: %d)\n", t_tee_prep, (total_X > 50000));
    TIME_PRINTF("   |- **ECALL** : %ld us\n", t_ecall);
    TIME_PRINTF("   |- Wait for Net : %ld us\n", t_wait);
    TIME_PRINTF("   |- Final Reconst: %ld us (Parallel MatMul)\n", t_final_calc);
    TIME_PRINTF("=== Total Wall Time: %ld us ===\n\n", t_total);
}


#define OMP_THRESHOLD 10000

void secure_matrix_batch_dualport_csp1_time(
    BSNet* send_net, BSNet* recv_net,
    const uint64_t* batch_X, 
    const uint64_t* batch_Y, 
    uint64_t* batch_Z,       
    int count,               
    int m, int k, int n
) {
    struct MatrixStats {
        long t1_time = 0; 
        long t2_total = 0, t2_prep = 0, t2_ecall = 0, t2_wait = 0, t2_recon = 0; 
        long t3_total = 0, t3_calc = 0, t3_send = 0; 
        long t4_time = 0; 
        long online_wall = 0, waste_time = 0, total_func = 0; long init_offline = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };
    auto t_init_start = std::chrono::high_resolution_clock::now();
    size_t sz_one_X = (size_t)m * k;
    size_t sz_one_Y = (size_t)k * n;
    size_t sz_one_Z = (size_t)m * n;

    int count_p1 = count / 2;          
    int count_p2 = count - count_p1;   

    size_t off_X2 = count_p1 * sz_one_X;
    size_t off_Y2 = count_p1 * sz_one_Y;
    size_t off_Z2 = count_p1 * sz_one_Z;

    uint64_t seedT_p1 = 10000; uint64_t seedC = 55555;
    uint64_t seedT_p2 = 20000;
    std::vector<uint64_t> A_loc(count_p2 * sz_one_X);
    std::vector<uint64_t> B_loc(count_p2 * sz_one_Y);
        
    
    size_t total_rng = count_p2 * (sz_one_X + sz_one_Y);
    #pragma omp parallel sections if(total_rng > OMP_THRESHOLD)
    {
        #pragma omp section
        generate_consistent_random_64_time(A_loc.data(), A_loc.size(), seedT_p2);
        #pragma omp section
        generate_consistent_random_64_time(B_loc.data(), B_loc.size(), seedT_p2 + 1);
        }
    stats.init_offline = diff_us(t_init_start, std::chrono::high_resolution_clock::now());
    struct SharedData {
        std::vector<uint64_t> recv_buf;
        bool done = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;

    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    

    
    std::thread t_recv([&]() {
        wait_for_gun(); 
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        size_t total_recv = count_p1 * (sz_one_X + sz_one_Y);
        std::vector<uint64_t> buf(total_recv);
        
        recv_net->recvMsg(buf.data(), total_recv * 8, 0);
        
        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_buf = std::move(buf);
            shared.done = true;
        }
        shared.cv.notify_one();
        stats.t1_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_tee([&]() {
        wait_for_gun(); 
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> R1_p1(count_p1 * sz_one_X);
        std::vector<uint64_t> R2_p1(count_p1 * sz_one_Y);
        
        
        size_t total_rng = count_p1 * (sz_one_X + sz_one_Y);
        #pragma omp parallel sections if(total_rng > OMP_THRESHOLD)
        {
            #pragma omp section
            generate_consistent_random_64_time(R1_p1.data(), R1_p1.size(), seedC);
            #pragma omp section
            generate_consistent_random_64_time(R2_p1.data(), R2_p1.size(), seedC + 1);
            #pragma omp section
            {
                ecall_matrix_batch_init(global_eid1, seedT_p1, m, k, n, count_p1);
            }
        }

        std::vector<uint64_t> XR(count_p1 * sz_one_X);
        std::vector<uint64_t> YR(count_p1 * sz_one_Y);
        
        
        bool use_omp_vec = (count_p1 * sz_one_X > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp_vec)
        for(size_t i=0; i<XR.size(); i++) XR[i] = batch_X[i] + R1_p1[i];
        
        use_omp_vec = (count_p1 * sz_one_Y > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp_vec)
        for(size_t i=0; i<YR.size(); i++) YR[i] = batch_Y[i] + R2_p1[i];
        
        auto t_prep_end = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> Tout(count_p1 * sz_one_Z);
        ecall_matrix_batch_compute(global_eid1, m, k, n, count_p1, 
                                   XR.data(), XR.size(), 
                                   YR.data(), YR.size(), 
                                   Tout.data(), Tout.size());
        auto t_ecall_end = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> recv_data;
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&](){ return shared.done; });
            recv_data = std::move(shared.recv_buf);
        }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        const uint64_t* ptr_recv_X = recv_data.data();
        const uint64_t* ptr_recv_Y = recv_data.data() + (count_p1 * sz_one_X);
        uint64_t* p_outZ = batch_Z; 

        for(int i=0; i<count_p1; i++) {
            size_t ix = i * sz_one_X; size_t iy = i * sz_one_Y; size_t iz = i * sz_one_Z;
            std::vector<uint64_t> X_hat(sz_one_X), Y_hat(sz_one_Y), Z_main(sz_one_Z);

            vec_add(ptr_recv_X + ix, batch_X + ix, X_hat.data(), sz_one_X);
            vec_add(ptr_recv_Y + iy, batch_Y + iy, Y_hat.data(), sz_one_Y);
            mat_mul_time(X_hat.data(), Y_hat.data(), Z_main.data(), m, k, n);
            vec_add(Z_main.data(), Tout.data() + iz, p_outZ + iz, sz_one_Z);
        }
        auto t_recon_end = std::chrono::high_resolution_clock::now();

        stats.t2_prep = diff_us(t_start, t_prep_end);
        stats.t2_ecall = diff_us(t_prep_end, t_ecall_end);
        stats.t2_wait = diff_us(t_ecall_end, t_wait_end);
        stats.t2_recon = diff_us(t_wait_end, t_recon_end);
        stats.t2_total = diff_us(t_start, t_recon_end);
    });

    
    std::thread t_send([&]() {
        wait_for_gun(); 
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        size_t total_elems = count_p2 * (sz_one_X + sz_one_Y);
        std::vector<uint64_t> buf(total_elems);
        uint64_t* ptr_X = buf.data();
        uint64_t* ptr_Y = buf.data() + (count_p2 * sz_one_X);

        
        bool use_omp_calc = (total_elems > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp_calc)
        for(size_t i=0; i<count_p2 * sz_one_X; i++) ptr_X[i] = batch_X[off_X2 + i] + A_loc[i];
        #pragma omp parallel for if(use_omp_calc)
        for(size_t i=0; i<count_p2 * sz_one_Y; i++) ptr_Y[i] = batch_Y[off_Y2 + i] + B_loc[i];
        
        auto t_calc_end = std::chrono::high_resolution_clock::now();

        send_net->sendMsg(buf.data(), total_elems * 8, 0);
        
        auto t_send_end = std::chrono::high_resolution_clock::now();
        stats.t3_calc = diff_us(t_start, t_calc_end);
        stats.t3_send = diff_us(t_calc_end, t_send_end);
        stats.t3_total = stats.t3_calc + stats.t3_send;
    });

    
    std::thread t_local([&]() {
        wait_for_gun(); 
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        uint64_t seedC_p2 = seedC + 1000; 

        std::vector<uint64_t> R1_p2(count_p2 * sz_one_X);
        std::vector<uint64_t> R2_p2(count_p2 * sz_one_Y);
        std::vector<uint64_t> A_loc(count_p2 * sz_one_X);
        std::vector<uint64_t> B_loc(count_p2 * sz_one_Y);
        std::vector<uint64_t> R0_loc(count_p2 * sz_one_Z);

        
        size_t total_rng = count_p2 * (2*sz_one_X + 2*sz_one_Y + sz_one_Z);
        #pragma omp parallel sections if(total_rng > OMP_THRESHOLD)
        {
            #pragma omp section
            generate_consistent_random_64_time(R1_p2.data(), R1_p2.size(), seedC_p2);
            #pragma omp section
            generate_consistent_random_64_time(R2_p2.data(), R2_p2.size(), seedC_p2 + 1);
            #pragma omp section
            generate_consistent_random_64_time(A_loc.data(), A_loc.size(), seedT_p2);
            #pragma omp section
            generate_consistent_random_64_time(B_loc.data(), B_loc.size(), seedT_p2 + 1);
            #pragma omp section
            generate_consistent_random_64_time(R0_loc.data(), R0_loc.size(), seedT_p2 + 2);
        }

        std::vector<uint64_t> T1(sz_one_X);
        std::vector<uint64_t> T2(sz_one_Y);
        std::vector<uint64_t> ResMat(sz_one_Z);

        for(int i=0; i<count_p2; i++) {
            size_t ix = i * sz_one_X; size_t iy = i * sz_one_Y; size_t iz = i * sz_one_Z;
            
            const uint64_t* cur_X = batch_X + off_X2 + ix;
            const uint64_t* cur_Y = batch_Y + off_Y2 + iy;
            uint64_t* out = batch_Z + off_Z2 + iz; 
            memset(out, 0, sz_one_Z * 8);

            
            bool use_omp_vec = (sz_one_X > OMP_THRESHOLD);
            #pragma omp parallel for if(use_omp_vec)
            for(size_t j=0; j<sz_one_X; j++) T1[j] = R1_p2[j] - cur_X[j] - A_loc[ix + j];
            
            mat_mul_time(T1.data(), B_loc.data() + iy, out, m, k, n);

            use_omp_vec = (sz_one_Y > OMP_THRESHOLD);
            #pragma omp parallel for if(use_omp_vec)
            for(size_t j=0; j<sz_one_Y; j++) T2[j] = R2_p2[j] - cur_Y[j];
            
            mat_mul_time(A_loc.data() + ix, T2.data(), ResMat.data(), m, k, n);

            use_omp_vec = (sz_one_Z > OMP_THRESHOLD);
            #pragma omp parallel for if(use_omp_vec)
            for(size_t j=0; j<sz_one_Z; j++) out[j] = out[j] + ResMat[j] - R0_loc[iz + j];
        }
        stats.t4_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    long create_cost = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    auto t_online_sync = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    t_recv.join(); t_tee.join(); t_send.join(); t_local.join();

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.waste_time = create_cost;
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Matrix Batch DualPort (Smart Parallel)\n");
    TIME_PRINTF("  Offline Init     : %ld us\n", stats.init_offline);
    TIME_PRINTF("  T1 (Recv Eval)   : %ld us\n", stats.t1_time);
    TIME_PRINTF("  T2 (TEE Eval)    : %ld us\n", stats.t2_total);
    TIME_PRINTF("      |-- Prep     : %ld us\n", stats.t2_prep);
    TIME_PRINTF("      |-- ECALL    : %ld us\n", stats.t2_ecall);
    TIME_PRINTF("      |-- Wait     : %ld us\n", stats.t2_wait);
    TIME_PRINTF("      |-- Recon    : %ld us\n", stats.t2_recon);
    TIME_PRINTF("  T3 (Send Helper) : %ld us (Calc: %ld, Send: %ld)\n", stats.t3_total, stats.t3_calc, stats.t3_send);
    TIME_PRINTF("  T4 (Local Helper): %ld us\n", stats.t4_time);
    TIME_PRINTF("  Start Cost       : %ld us\n", stats.waste_time);
    TIME_PRINTF("  Online Wall      : %ld us\n", stats.online_wall);
    TIME_PRINTF("  Total Function   : %ld us\n", stats.total_func);
    TIME_PRINTF("---------------------------------------------\n\n");
}
static const uint64_t SEED_A0 = 12345;
static const uint64_t SEED_A1 = 67890;
static const uint64_t SEED_B0 = 9999;
static const uint64_t SEED_B1 = 8888;
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <cstring>
#include <cstdio>

void secure_matrix_batch_base_csp1_time(
    BSNet* send_net, BSNet* recv_net,
    const uint64_t* batch_X, 
    const uint64_t* batch_Y, 
    uint64_t* batch_Z,       
    int count, int m, int k, int n
) {
    
    struct MatrixBaseStats {
        long setup_time = 0;
        long t_send_total = 0, t_send_calc = 0, t_send_net = 0;
        long t_recv_time = 0;
        long reconst_time = 0;
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };

    
    size_t sz_X = (size_t)m * k;
    size_t sz_Y = (size_t)k * n;
    size_t sz_Z = (size_t)m * n;

    
    auto t1 = std::chrono::high_resolution_clock::now();

    std::vector<uint64_t> C1(count * sz_Z);
    std::vector<uint64_t> A1(count * sz_X), B1(count * sz_Y);

    std::thread t_prepare([&]() {
        
        ecall_tee1_slave_compute(global_eid1, 
            m, k, n, count, 
            C1.data(), C1.size() * sizeof(uint64_t) 
        );
    });

    
    #pragma omp parallel for if(count > 2000)
    for(int i=0; i<count; i++) {
        generate_consistent_random_64_time(A1.data() + i*sz_X, sz_X, SEED_A1 + i);
        generate_consistent_random_64_time(B1.data() + i*sz_Y, sz_Y, SEED_B1 + i);
    }

    t_prepare.join(); 
    stats.setup_time = diff_us(t1, std::chrono::high_resolution_clock::now());

    
    std::vector<uint64_t> E1(count * sz_X), F1(count * sz_Y); 
    std::vector<uint64_t> E0(count * sz_X), F0(count * sz_Y); 

    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    

    
    std::thread t_recv([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();

        recv_net->recvMsg(E0.data(), E0.size()*8, 0);
        recv_net->recvMsg(F0.data(), F0.size()*8, 0);

        stats.t_recv_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_send([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();

        
        bool use_omp = (count * sz_X > 50000); 
        #pragma omp parallel sections if(use_omp)
        {
            #pragma omp section
            {
                #pragma omp parallel for if(use_omp)
                for(size_t i=0; i<E1.size(); i++) E1[i] = batch_X[i] + A1[i];
            }
            #pragma omp section
            {
                #pragma omp parallel for if(use_omp)
                for(size_t i=0; i<F1.size(); i++) F1[i] = batch_Y[i] + B1[i];
            }
        }
        auto t_calc_end = std::chrono::high_resolution_clock::now();
        
        
        send_net->sendMsg(E1.data(), E1.size()*8, 0);
        send_net->sendMsg(F1.data(), F1.size()*8, 0);
        auto t_send_end = std::chrono::high_resolution_clock::now();

        stats.t_send_calc = diff_us(t_start, t_calc_end);
        stats.t_send_net = diff_us(t_calc_end, t_send_end);
        stats.t_send_total = stats.t_send_calc + stats.t_send_net;
    });

    stats.waste_time = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    
    auto t_online_sync = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    t_recv.join();
    t_send.join();

    
    auto t_recon_start = std::chrono::high_resolution_clock::now();
    
    #pragma omp parallel for if(count > 100)
    for(int i=0; i<count; i++) {
        size_t offX = i*sz_X, offY = i*sz_Y, offZ = i*sz_Z;
        
        
        std::vector<uint64_t> E(sz_X), F(sz_Y);
        vec_add(&E0[offX], &E1[offX], E.data(), sz_X);
        vec_add(&F0[offY], &F1[offY], F.data(), sz_Y);

        uint64_t* z_ptr = &batch_Z[offZ];
        memset(z_ptr, 0, sz_Z * sizeof(uint64_t)); 
        
        std::vector<uint64_t> tmp(sz_Z);
        
        
        mat_mul_time(&A1[offX], F.data(), tmp.data(), m, k, n); 
        vec_sub(z_ptr, tmp.data(), z_ptr, sz_Z);
        
        
        mat_mul_time(E.data(), &B1[offY], tmp.data(), m, k, n); 
        vec_sub(z_ptr, tmp.data(), z_ptr, sz_Z);
        
        
        vec_add(z_ptr, &C1[offZ], z_ptr, sz_Z);            
    }
    stats.reconst_time = diff_us(t_recon_start, std::chrono::high_resolution_clock::now());

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    
    TIME_PRINTF("\n=== CSP1 Base Batch [Count %d] ===\n", count);
    TIME_PRINTF("1. Setup (TEE+Rand): %ld us\n", stats.setup_time);
    TIME_PRINTF("2. Online Phase (Wall): %ld us\n", stats.online_wall);
    TIME_PRINTF("   |- T_Send Total : %ld us (Calc: %ld, Net: %ld)\n", stats.t_send_total, stats.t_send_calc, stats.t_send_net);
    TIME_PRINTF("   |- T_Recv Total : %ld us\n", stats.t_recv_time);
    TIME_PRINTF("   |- Reconstruct  : %ld us\n", stats.reconst_time);
    TIME_PRINTF("3. Overhead (Start): %ld us\n", stats.waste_time);
    TIME_PRINTF("=== Total Func Time: %ld us ===\n\n", stats.total_func);
}
void secure_relu_csp1_parallel_time(BSNet* server_net1, BSNet* server_net2, 
                               const uint64_t* input_shares, 
                               uint64_t* output_shares,
                               int vector_size) {
    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };

    uint64_t* drelu_shares = new uint64_t[vector_size];

    
    auto t1_start = std::chrono::high_resolution_clock::now();
    ODReLU_CSP1_2Threads_64_time(server_net1, input_shares, drelu_shares, vector_size);
    auto t1_end = std::chrono::high_resolution_clock::now();
    
    
    const uint64_t L = UINT64_MAX;
    const uint64_t s = 63;
    
    auto t2_start = std::chrono::high_resolution_clock::now();
    secure_multiply_batch_parallel_time(server_net2, false,
                                  input_shares, drelu_shares,
                                  output_shares, vector_size, s, L);
    auto t2_end = std::chrono::high_resolution_clock::now();
    


    long drelu_time = diff_us(t1_start, t1_end);
    long mult_time  = diff_us(t2_start, t2_end);
    long total_time = diff_us(func_start, std::chrono::high_resolution_clock::now());
    delete[] drelu_shares;
    TIME_PRINTF("[CSP1] ReLU Parallel (Size %d)\n", vector_size);
    TIME_PRINTF("  |- DReLU Step : %ld us\n", drelu_time);
    TIME_PRINTF("  |- Mult Step  : %ld us\n", mult_time);
    TIME_PRINTF("  Total Time    : %ld us\n", total_time);
    TIME_PRINTF("---------------------------------------------\n");
}

void secure_relu_csp1_dualport_time(BSNet* server_net1, BSNet* server_net2,
                               const uint64_t* input_shares, 
                               uint64_t* output_shares,
                               int vector_size) {
    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };

    uint64_t* drelu_shares = new uint64_t[vector_size];

    
    auto t1_start = std::chrono::high_resolution_clock::now();
    ODReLU_CSP1_4Threads_64_time(server_net1, server_net2, input_shares, drelu_shares, vector_size);
    auto t1_end = std::chrono::high_resolution_clock::now();
    
    
    const uint64_t L = UINT64_MAX;
    const uint64_t s = 63;
    
    auto t2_start = std::chrono::high_resolution_clock::now();
    
    
    secure_multiply_batch_dualport_time(server_net2, server_net1, false,
                                  input_shares, drelu_shares,
                                  output_shares, vector_size, s, L);
    auto t2_end = std::chrono::high_resolution_clock::now();
    


    long drelu_time = diff_us(t1_start, t1_end);
    long mult_time  = diff_us(t2_start, t2_end);
    long total_time = diff_us(func_start, std::chrono::high_resolution_clock::now());
    delete[] drelu_shares;
    TIME_PRINTF("[CSP1] ReLU DualPort (Size %d)\n", vector_size);
    TIME_PRINTF("  |- DReLU Step : %ld us\n", drelu_time);
    TIME_PRINTF("  |- Mult Step  : %ld us\n", mult_time);
    TIME_PRINTF("  Total Time    : %ld us\n", total_time);
    TIME_PRINTF("---------------------------------------------\n");
}
void secure_square_batch_csp1_time(
    BSNet* recv_net, 
    const uint64_t* input_x, 
    uint64_t* output_z,      
    uint64_t count, 
    uint64_t L               
) {
    struct PerfStats {
        long t_prep = 0;
        long t_tee = 0;
        long t_comm = 0;
        long t_reconst = 0;
        long t_total = 0;
    } stats;

    auto start_total = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;

    
    std::vector<uint64_t> recv_mask(count);
    std::atomic<bool> recv_done{false};

    
    auto t1 = std::chrono::high_resolution_clock::now();

    
    std::thread t_recv([&]() {
        recv_net->recvMsg(recv_mask.data(), count * sizeof(uint64_t), 0);
        recv_done = true;
    });

    
    
    std::vector<uint64_t> r1(count);
    generate_consistent_random_64_time(r1.data(), count, seedC);

    
    ecall_square_gen_a_r0_64(global_eid1, seedT, count);

    
    std::vector<uint64_t> tee_input(count);
    std::vector<uint64_t> tee_result(count);
    
    for(size_t i=0; i<count; i++) {
        tee_input[i] = (input_x[i] + r1[i]) % L;
    }
    stats.t_prep = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t1).count();

    
    
    auto t_tee_start = std::chrono::high_resolution_clock::now();
    ecall_sq_tee1_computation_64(global_eid1, count, 0, tee_input.data(), tee_result.data());
    
    stats.t_tee = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_tee_start).count();

    
    t_recv.join(); 

    auto t3 = std::chrono::high_resolution_clock::now();
    
    
    
    for(size_t i=0; i<count; i++) {
        
        uint64_t x_plus_a = (recv_mask[i] + input_x[i]) % L;
        
        
        uint64_t sq_val = x_plus_a * x_plus_a % L;
        
        
        output_z[i] = (sq_val + tee_result[i]) % L;
    }
    stats.t_reconst = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t3).count();

    stats.t_total = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start_total).count();

    TIME_PRINTF("\n[CSP1] Square Batch (Count %lu):\n", count);
    TIME_PRINTF("  Prep+RNG: %ld us\n", stats.t_prep);
    TIME_PRINTF("  TEE Call: %ld us\n", stats.t_tee);
    TIME_PRINTF("  Reconst : %ld us\n", stats.t_reconst);
    TIME_PRINTF("  Total   : %ld us\n", stats.t_total);
}
void secure_square_batch_parallel_csp1_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, 
    uint64_t* output, uint64_t count, uint64_t s, uint64_t L
) {
    struct PerfStats {
        long a2_time = 0;    
        long b3_time = 0;    
        long c_time = 0;     
        long online_wall = 0; 
        long total_func = 0; 
        long waste_time = 0; 
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;

    
    uint64_t* r1 = new uint64_t[count];

    struct SharedData {
        uint64_t* recv_buffer = nullptr;
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;

    
    shared.recv_buffer = new uint64_t[count];

    
    auto t_online_start = std::chrono::high_resolution_clock::now();
    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1_net = std::thread([&]() {
        long bytes = count * sizeof(uint64_t); 
        auto t_recv_start = std::chrono::high_resolution_clock::now();
        
        server->recvMsg(shared.recv_buffer, bytes, 0);
        
        stats.b3_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_recv_start).count();
        stats.recv_bytes = bytes;

        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_done = true;
        }
        shared.cv.notify_one();
    });

    
    auto t2_comp = std::thread([&]() {
        uint64_t* x1_plus_r1 = new uint64_t[count];
        uint64_t* tee_result = new uint64_t[count];
        
        
        auto t_a2_start = std::chrono::high_resolution_clock::now();
        
        
        generate_consistent_random_64_time(r1, count, seedC);
        
        
        
        ecall_square_gen_a_r0_64(global_eid1, seedT, count);
        
        
        for (uint64_t i = 0; i < count; i++) {
            x1_plus_r1[i] = input_x[i] + r1[i];
        }
        
        
        
        ecall_sq_tee1_computation_64(global_eid1, count, 0, x1_plus_r1, tee_result);
        
        stats.a2_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_a2_start).count();
        
        
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }
        
        
        auto t_c_start = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < count; i++) {
            
            uint64_t x_plus_a = shared.recv_buffer[i] + input_x[i];
            uint64_t square_val = x_plus_a * x_plus_a;
            
            
            output[i] = square_val + tee_result[i];
        }
        stats.c_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_c_start).count();

        delete[] x1_plus_r1; delete[] tee_result;
    });

    long create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_join_start = std::chrono::high_resolution_clock::now();
    t1_net.join();
    t2_comp.join();
    
    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();
    stats.waste_time = create_time;   

    delete[] shared.recv_buffer;
    delete[] r1;

    
    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Square Optimized:\n");
    TIME_PRINTF("a2的总时间（随机数+TEE计算）: %ld us\n", stats.a2_time);
    TIME_PRINTF("b3的时间（接收线程时间）: %ld us\n", stats.b3_time);
    TIME_PRINTF("c的时间（重构时间）: %ld us\n", stats.c_time);
    TIME_PRINTF("线程浪费总时间: %ld us\n", stats.waste_time);
    TIME_PRINTF("线程总时间 (Online Wall): %ld us\n", stats.online_wall);
    TIME_PRINTF("函数总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_square_batch_dualport_time(BSNet* send_channel, BSNet* recv_channel, bool is_csp0, 
                                  const uint64_t* input_x, 
                                  uint64_t* output, 
                                  uint64_t count, 
                                  uint64_t s, uint64_t L) {
    if (is_csp0) return; 

    struct PerfStats {
        long offline_time = 0; 
        
        long t1_time = 0;      
        
        
        long t2_total = 0;     
        long t2_prep = 0;      
        long t2_wait = 0;      
        long t2_recon = 0;     
        
        
        long t3_total = 0;     
        long t3_calc = 0;      
        long t3_send = 0;      
        
        long t4_time = 0;      
        
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
        long send_bytes = 0;
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    
    
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;
    uint64_t seedT_p2 = seedT + 0xFFFF; 
    uint64_t seedC_p2 = seedC + 0xFFFF;

    uint64_t half_count = count / 2;
    uint64_t second_count = count - half_count;

    
    auto t_off_start = std::chrono::high_resolution_clock::now();

    
    uint64_t* a_p2 = new uint64_t[second_count];
    generate_consistent_random_64_time(a_p2, second_count, seedT_p2);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_off_start).count();

    
    struct SharedData {
        uint64_t* res_tee = nullptr; uint64_t* res_local = nullptr;
        uint64_t* recv_buf = nullptr; 
        bool recv_done = false; std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.res_tee = new uint64_t[half_count];
    shared.res_local = new uint64_t[second_count];
    
    shared.recv_buf = new uint64_t[half_count]; 

    
    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;

    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    
    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        
        long bytes = half_count * sizeof(uint64_t);
        recv_channel->recvMsg(shared.recv_buf, bytes, 0);
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
        stats.t1_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    
    auto t2 = std::thread([&]() {
        wait_for_gun(); 
        auto t2_start = std::chrono::high_resolution_clock::now();

        uint64_t* r1_p1 = new uint64_t[half_count];
        uint64_t* tee_input = new uint64_t[half_count];
        uint64_t* tee_res = new uint64_t[half_count];

        
        generate_consistent_random_64_time(r1_p1, half_count, seedC);
        
        
        ecall_square_gen_a_r0_64(global_eid1, seedT, half_count);

        
        for (uint64_t i = 0; i < half_count; i++) {
            tee_input[i] = input_x[i] + r1_p1[i]; 
        }
        
        
        ecall_sq_tee1_computation_64(global_eid1, half_count, 0, tee_input, tee_res);
        auto t2_prep_end = std::chrono::high_resolution_clock::now();

        
        { 
            std::unique_lock<std::mutex> lock(shared.mtx); 
            shared.cv.wait(lock, [&]() { return shared.recv_done; }); 
        }
        auto t2_wait_end = std::chrono::high_resolution_clock::now();

        
        for (uint64_t i = 0; i < half_count; i++) {
            
            uint64_t x_plus_a = shared.recv_buf[i] + input_x[i];
            uint64_t sq_val = x_plus_a * x_plus_a;
            
            shared.res_tee[i] = sq_val + tee_res[i];
        }
        auto t2_recon_end = std::chrono::high_resolution_clock::now();
        
        delete[] r1_p1; delete[] tee_input; delete[] tee_res;
        
        stats.t2_prep = std::chrono::duration_cast<std::chrono::microseconds>(t2_prep_end - t2_start).count();
        stats.t2_wait = std::chrono::duration_cast<std::chrono::microseconds>(t2_wait_end - t2_prep_end).count();
        stats.t2_recon = std::chrono::duration_cast<std::chrono::microseconds>(t2_recon_end - t2_wait_end).count();
        stats.t2_total = stats.t2_prep + stats.t2_wait + stats.t2_recon;
    });

    
    auto t3 = std::thread([&]() {
        wait_for_gun(); 
        auto t3_start = std::chrono::high_resolution_clock::now();

        
        uint64_t* send_buf = new uint64_t[second_count];
        
        
        for (uint64_t i = 0; i < second_count; i++) {
            send_buf[i] = input_x[half_count + i] + a_p2[i]; 
        }
        auto t3_calc_end = std::chrono::high_resolution_clock::now();
        
        
        long bytes = second_count * sizeof(uint64_t);
        send_channel->sendMsg(send_buf, bytes, 0);
        auto t3_send_end = std::chrono::high_resolution_clock::now();

        stats.send_bytes = bytes;
        delete[] send_buf;

        stats.t3_calc = std::chrono::duration_cast<std::chrono::microseconds>(t3_calc_end - t3_start).count();
        stats.t3_send = std::chrono::duration_cast<std::chrono::microseconds>(t3_send_end - t3_calc_end).count();
        stats.t3_total = stats.t3_calc + stats.t3_send;
    });

    
    auto t4 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        uint64_t* r0_p2 = new uint64_t[second_count];
        uint64_t* r1_p2 = new uint64_t[second_count];

        
        generate_consistent_random_64_time(r0_p2, second_count, seedT_p2 + 1); 
        generate_consistent_random_64_time(r1_p2, second_count, seedC_p2);     

        
        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t term1 = (2 * a_p2[i]) * r1_p2[i];
            uint64_t term2 = a_p2[i] * a_p2[i];
            uint64_t term3 = (2 * a_p2[i]) * input_x[half_count + i];
            
            shared.res_local[i] = term1 - term2 - term3 - r0_p2[i];
        }
        delete[] r0_p2; delete[] r1_p2;
        stats.t4_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    long create_cost = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all(); 

    
    auto t_join_start = std::chrono::high_resolution_clock::now();
    t1.join(); t2.join(); t3.join(); t4.join();
    
    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.waste_time = create_cost;

    
    for (uint64_t i = 0; i < half_count; i++) output[i] = shared.res_tee[i];
    for (uint64_t i = 0; i < second_count; i++) output[half_count + i] = shared.res_local[i];
    
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - func_start).count();

    delete[] shared.res_tee; delete[] shared.res_local; delete[] shared.recv_buf;
    delete[] a_p2;

    
    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Square DualPort Breakdown:\n");
    TIME_PRINTF("  Offline Time (a)  : %ld us\n", stats.offline_time);
    TIME_PRINTF("  t1 (Recv P1)      : %ld us (Bytes: %ld)\n", stats.t1_time, stats.recv_bytes);
    TIME_PRINTF("  t2 (TEE P1)       : %ld us (Prep: %ld, Wait: %ld, Recon: %ld)\n", 
            stats.t2_total, stats.t2_prep, stats.t2_wait, stats.t2_recon);
    TIME_PRINTF("  t3 (Send P2)      : %ld us (Calc: %ld, Send: %ld)\n", 
           stats.t3_total, stats.t3_calc, stats.t3_send);
    TIME_PRINTF("  t4 (Local P2)     : %ld us\n", stats.t4_time);
    TIME_PRINTF("  Sys Overhead      : %ld us\n", stats.waste_time);
    TIME_PRINTF("  Online Wall Time  : %ld us\n", stats.online_wall);
    TIME_PRINTF("  Total Function    : %ld us\n", stats.total_func);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_cube_opt_batch_parallel_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* batch_X, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {

    struct PerfStats {
        long a2_time = 0;     
        long b3_time = 0;     
        long c_time = 0;      
        long create_time = 0; 
        long online_wall = 0; 
        long total_func = 0;  
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456;
    uint64_t seedC = 654321;

    
    uint64_t* r1 = new uint64_t[count]; 
    uint64_t* r2 = new uint64_t[count];

    struct SharedData {
        uint64_t* recv_buf = nullptr; 
        bool recv_done = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.recv_buf = new uint64_t[count]; 

    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1_net = std::thread([&]() {
        wait_for_gun(); 

        long bytes = count * sizeof(uint64_t); 
        auto t_recv_start = std::chrono::high_resolution_clock::now();
        
        server->recvMsg(shared.recv_buf, bytes, 0);
        
        stats.b3_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_recv_start).count();
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        uint64_t* x1_r1 = new uint64_t[count]; 
        uint64_t* tee_final_sum = new uint64_t[count]; 

        
        auto t_a2_start = std::chrono::high_resolution_clock::now();

        generate_consistent_random_64_time(r1, count, seedC);
        generate_consistent_random_64_time(r2, count, seedC + 1);

        
        ecall_cube_opt_gen_params_64(global_eid1, seedT, count);

        
        for (uint64_t i = 0; i < count; i++) {
            x1_r1[i] = batch_X[i] + r1[i]; 
        }
        
        
        ecall_cube_opt_step1_m3_64(global_eid1, count, x1_r1);
        
        stats.a2_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_a2_start).count();

        
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }

        
        auto t_c_start = std::chrono::high_resolution_clock::now();
        
        
        uint64_t* V = x1_r1; 
        
        for (uint64_t i = 0; i < count; i++) {
            
            uint64_t E = shared.recv_buf[i] + batch_X[i];
            
            
            V[i] = (E * E) + r2[i];
            
            
            output[i] = E * E * E;
        }
        
        
        ecall_cube_opt_step2_final_64(global_eid1, count, V, tee_final_sum);
        
        
        for (uint64_t i = 0; i < count; i++) output[i] += tee_final_sum[i];

        stats.c_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_c_start).count();
        
        delete[] x1_r1; delete[] tee_final_sum;
    });

    long create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all(); 

    
    t1_net.join();
    t2_comp.join();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();

    delete[] shared.recv_buf;
    delete[] r1; delete[] r2;

    long thread_waste = create_time;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Cube Opt Protocol (Sync):\n");
    TIME_PRINTF("a2时间（随机数+TEE Init+Calc1）: %ld us\n", stats.a2_time);
    TIME_PRINTF("b3时间（接收线程时间）: %ld us\n", stats.b3_time);
    TIME_PRINTF("c时间 （重构+TEE Calc2）: %ld us\n", stats.c_time);
    TIME_PRINTF("创建线程浪费时间: %ld us\n", thread_waste);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("接收多少byte: %ld bytes\n", stats.recv_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_cube_opt_batch_dualport_csp1_time(
    BSNet* send_net, BSNet* recv_net, bool is_csp0, 
    const uint64_t* input_x, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    if (count == 0) return;
    
    if (is_csp0) return; 

    struct CubeDualStats {
        long offline_time = 0;
        
        
        long t1_recv_time = 0;
        long t2_tee_total = 0;
        long t2_prep = 0; long t2_wait = 0; long t2_recon = 0;
        
        
        long t3_send_total = 0;
        long t4_local_time = 0;
        
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };

    
    int count_p1 = count / 2;          
    int count_p2 = count - count_p1;   
    size_t off_p2 = count_p1;          

    uint64_t seedT_p1 = 10000; uint64_t seedC = 55555;
    uint64_t seedT_p2 = 20000; uint64_t seedC_p2 = seedC + 1000;

    
    
    auto t_off_start = std::chrono::high_resolution_clock::now();

    std::vector<uint64_t> A_p2(count_p2);
    generate_consistent_random_64_time(A_p2.data(), count_p2, seedT_p2);

    stats.offline_time = diff_us(t_off_start, std::chrono::high_resolution_clock::now());

    
    struct SharedData {
        std::vector<uint64_t> recv_buf;
        bool done = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    
    std::thread t1([&]() {
        wait_for_gun();
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> buf(count_p1);
        recv_net->recvMsg(buf.data(), buf.size()*8, 0);

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_buf = std::move(buf); shared.done = true; }
        shared.cv.notify_one();
        
        stats.t1_recv_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    
    std::thread t2([&]() {
        wait_for_gun();
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint64_t> R1_p1(count_p1), R2_p1(count_p1);

        
        generate_consistent_random_64_time(R1_p1.data(), count_p1, seedC);
        generate_consistent_random_64_time(R2_p1.data(), count_p1, seedC + 1);
        ecall_cube_opt_gen_params_64(global_eid1, seedT_p1, count_p1);

        
        const uint64_t* p_in = input_x;
        std::vector<uint64_t> X_r1(count_p1);
        
        bool use_omp = (count_p1 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            X_r1[i] = p_in[i] + R1_p1[i];
        }
        
        ecall_cube_opt_step1_m3_64(global_eid1, count_p1, X_r1.data());
        auto t_step1_end = std::chrono::high_resolution_clock::now();

        
        std::vector<uint64_t> recv_data;
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&](){ return shared.done; });
            recv_data = std::move(shared.recv_buf);
        }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        
        
        
        std::vector<uint64_t> V(count_p1);
        std::vector<uint64_t> tee_res(count_p1);

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            uint64_t E = recv_data[i] + p_in[i];
            V[i] = (E * E) + R2_p1[i];
            
            
            output[i] = E * E * E;
        }

        ecall_cube_opt_step2_final_64(global_eid1, count_p1, V.data(), tee_res.data());

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) output[i] += tee_res[i];

        auto t_step2_end = std::chrono::high_resolution_clock::now();

        stats.t2_prep = diff_us(t_start, t_step1_end);
        stats.t2_wait = diff_us(t_step1_end, t_wait_end);
        stats.t2_recon = diff_us(t_wait_end, t_step2_end);
        stats.t2_tee_total = diff_us(t_start, t_step2_end);
    });

    
    std::thread t3([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> buf(count_p2);
        const uint64_t* p_in = input_x + off_p2;
        
        bool use_omp = (count_p2 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            buf[i] = p_in[i] + A_p2[i];
        }
        
        send_net->sendMsg(buf.data(), buf.size()*8, 0);
        stats.t3_send_total = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    
    std::thread t4([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint64_t> R0_p2(count_p2), R1_p2(count_p2), R2_p2(count_p2);

        generate_consistent_random_64_time(R0_p2.data(), count_p2, seedT_p2 + 1);
        generate_consistent_random_64_time(R1_p2.data(), count_p2, seedC_p2);
        generate_consistent_random_64_time(R2_p2.data(), count_p2, seedC_p2 + 1);

        const uint64_t* p_in = input_x + off_p2;
        bool use_omp = (count_p2 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            uint64_t a = A_p2[i];
            uint64_t a2 = a * a;
            uint64_t a3 = a2 * a;
            
            uint64_t m1 = 2*a3 + 3*a*R2_p2[i];
            uint64_t m2 = 3*a2*(p_in[i] - R1_p2[i]);
            
            
            output[off_p2 + i] = m1 + m2 - R0_p2[i];
        }
        stats.t4_local_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    stats.waste_time = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    
    auto t_online_sync = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    
    t1.join(); t2.join(); t3.join(); t4.join();

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());
    

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] Secure Cube Opt DualPort\n");
    TIME_PRINTF("1. Offline Setup   : %ld us (Only a)\n", stats.offline_time);
    TIME_PRINTF("2. Online Wall     : %ld us\n", stats.online_wall);
    TIME_PRINTF("   |- T1 (Recv P1) : %ld us\n", stats.t1_recv_time);
    TIME_PRINTF("   |- T2 (TEE P1)  : %ld us [Prep:%ld, Wait:%ld, Recon:%ld]\n",
           stats.t2_tee_total, stats.t2_prep, stats.t2_wait, stats.t2_recon);
    TIME_PRINTF("   |- T3 (Send P2) : %ld us\n", stats.t3_send_total);
    TIME_PRINTF("   |- T4 (Locl P2) : %ld us (RNG+Calc)\n", stats.t4_local_time);
    TIME_PRINTF("3. Start Overhead  : %ld us\n", stats.waste_time);
    TIME_PRINTF("=== Total Time     : %ld us ===\n\n", stats.total_func);
}
void secure_xy2_opt_batch_parallel_csp1_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    if (is_csp0 || count == 0) return;

    struct PerfStats {
        long a2_time = 0;     
        long b3_time = 0;     
        long c_time = 0;      
        long create_time = 0; 
        long online_wall = 0; 
        long total_func = 0;  
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456;
    uint64_t seedC = 654321;

    struct SharedData {
        uint64_t* recv_buf = nullptr; 
        bool recv_done = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.recv_buf = new uint64_t[count * 2]; 

    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1_net = std::thread([&]() {
        wait_for_gun(); 

        long bytes = count * 2 * sizeof(uint64_t); 
        auto t_recv_start = std::chrono::high_resolution_clock::now();
        
        server->recvMsg(shared.recv_buf, bytes, 0);
        
        stats.b3_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_recv_start).count();
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        uint64_t* r1 = new uint64_t[count]; 
        uint64_t* r2 = new uint64_t[count];
        uint64_t* r3 = new uint64_t[count]; 
        uint64_t* r4 = new uint64_t[count];

        
        auto t_a2_start = std::chrono::high_resolution_clock::now();

        generate_consistent_random_64_time(r1, count, seedC);
        generate_consistent_random_64_time(r2, count, seedC + 1);
        generate_consistent_random_64_time(r3, count, seedC + 2);
        generate_consistent_random_64_time(r4, count, seedC + 3);

        
        ecall_xy2_opt_gen_params_64(global_eid1, seedT, count);

        uint64_t* x_r1 = new uint64_t[count]; 
        uint64_t* y_r2 = new uint64_t[count];
        
        bool use_omp = (count > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for (uint64_t i = 0; i < count; i++) {
            x_r1[i] = input_x[i] + r1[i]; 
            y_r2[i] = input_y[i] + r2[i]; 
        }
        
        
        ecall_xy2_opt_step1_64(global_eid1, count, x_r1, y_r2);
        
        stats.a2_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_a2_start).count();

        
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }

        
        auto t_c_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* V_xy = new uint64_t[count]; 
        uint64_t* V_yy = new uint64_t[count];
        uint64_t* tee_final_sum = new uint64_t[count]; 

        uint64_t* p_ex = shared.recv_buf;
        uint64_t* p_ey = shared.recv_buf + count;

        #pragma omp parallel for if(use_omp)
        for (uint64_t i = 0; i < count; i++) {
            
            uint64_t Ex = p_ex[i] + input_x[i];
            uint64_t Ey = p_ey[i] + input_y[i];
            
            
            V_xy[i] = (Ex * Ey) + r3[i];
            V_yy[i] = (Ey * Ey) + r4[i];
            
            
            output[i] = Ex * Ey * Ey;
        }
        
        
        ecall_xy2_opt_step2_final_64(global_eid1, count, V_xy, V_yy, tee_final_sum);
        
        
        #pragma omp parallel for if(use_omp)
        for (uint64_t i = 0; i < count; i++) {
            output[i] += tee_final_sum[i];
        }

        stats.c_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_c_start).count();
        
        delete[] r1; delete[] r2; delete[] r3; delete[] r4;
        delete[] x_r1; delete[] y_r2; delete[] V_xy; delete[] V_yy; delete[] tee_final_sum;
    });

    stats.create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_online_sync_start = std::chrono::high_resolution_clock::now();
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all(); 

    t1_net.join();
    t2_comp.join();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_sync_start).count();
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count();

    delete[] shared.recv_buf;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] XY^2 Single-Channel Protocol (Evaluator):\n");
    TIME_PRINTF("a2时间（TEE Init+Calc1）: %ld us\n", stats.a2_time);
    TIME_PRINTF("b3时间（网络接收时间）: %ld us\n", stats.b3_time);
    TIME_PRINTF("c时间 （重构+TEE Calc2）: %ld us\n", stats.c_time);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("接收流量: %ld bytes\n", stats.recv_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
};

void secure_xy2_opt_batch_dualport_csp1_time(
    BSNet* send_net, BSNet* recv_net, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    if (count == 0 || is_csp0) return; 

    struct XY2DualStats {
        long offline_time = 0;
        long t1_recv_time = 0;
        long t2_tee_total = 0;
        long t2_prep = 0;
        long t2_wait = 0;
        long t2_recon = 0;
        long t3_send_total = 0;
        long t4_local_time = 0;
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
        long send_bytes = 0;
        long recv_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s0, auto e0) {
        return std::chrono::duration_cast<std::chrono::microseconds>(e0 - s0).count();
    };

    int count_p1 = count / 2;          
    int count_p2 = count - count_p1;   
    size_t off_p2 = count_p1;

    uint64_t seedT_p1 = 10000; uint64_t seedC = 55555;
    uint64_t seedT_p2 = 20000; uint64_t seedC_p2 = seedC + 1000;

    
    auto t_off_start = std::chrono::high_resolution_clock::now();
    std::vector<uint64_t> A_p2(count_p2), B_p2(count_p2);
    generate_consistent_random_64_time(A_p2.data(), count_p2, seedT_p2);
    generate_consistent_random_64_time(B_p2.data(), count_p2, seedT_p2 + 1);
    stats.offline_time = diff_us(t_off_start, std::chrono::high_resolution_clock::now());

    
    struct SharedData {
        std::vector<uint64_t> recv_buf;
        bool done = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&] { return start_signal; });
    };

    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    std::thread t1([&]() {
        wait_for_gun();
        if (count_p1 == 0) return;
        std::vector<uint64_t> buf(count_p1 * 2);
        stats.recv_bytes = static_cast<long>(buf.size() * sizeof(uint64_t));
        auto recv_start = std::chrono::high_resolution_clock::now();
        recv_net->recvMsg(buf.data(), buf.size()*8, 0);
        stats.t1_recv_time = diff_us(recv_start, std::chrono::high_resolution_clock::now());

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_buf = std::move(buf); shared.done = true; }
        shared.cv.notify_one();
    });

    
    std::thread t2([&]() {
        wait_for_gun();
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint64_t> R1(count_p1), R2(count_p1), R3(count_p1), R4(count_p1);
        generate_consistent_random_64_time(R1.data(), count_p1, seedC);
        generate_consistent_random_64_time(R2.data(), count_p1, seedC + 1);
        generate_consistent_random_64_time(R3.data(), count_p1, seedC + 2);
        generate_consistent_random_64_time(R4.data(), count_p1, seedC + 3);
        ecall_xy2_opt_gen_params_64(global_eid1, seedT_p1, count_p1);

        std::vector<uint64_t> X_r1(count_p1), Y_r2(count_p1);
        bool use_omp = (count_p1 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            X_r1[i] = input_x[i] + R1[i];
            Y_r2[i] = input_y[i] + R2[i];
        }
        ecall_xy2_opt_step1_64(global_eid1, count_p1, X_r1.data(), Y_r2.data());
        auto t_prep_end = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> recv_data;
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&](){ return shared.done; });
            recv_data = std::move(shared.recv_buf);
        }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> V_xy(count_p1), V_yy(count_p1), tee_res(count_p1);
        uint64_t* p_ex0 = recv_data.data();
        uint64_t* p_ey0 = recv_data.data() + count_p1;

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            uint64_t Ex = p_ex0[i] + input_x[i];
            uint64_t Ey = p_ey0[i] + input_y[i];
            
            V_xy[i] = (Ex * Ey) + R3[i];
            V_yy[i] = (Ey * Ey) + R4[i];
            output[i] = Ex * Ey * Ey; 
        }

        ecall_xy2_opt_step2_final_64(global_eid1, count_p1, V_xy.data(), V_yy.data(), tee_res.data());

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) output[i] += tee_res[i];
        auto t_recon_end = std::chrono::high_resolution_clock::now();

        stats.t2_prep = diff_us(t_start, t_prep_end);
        stats.t2_wait = diff_us(t_prep_end, t_wait_end);
        stats.t2_recon = diff_us(t_wait_end, t_recon_end);
        stats.t2_tee_total = diff_us(t_start, t_recon_end);
    });

    
    std::thread t3([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> buf(count_p2 * 2);
        const uint64_t* px = input_x + off_p2;
        const uint64_t* py = input_y + off_p2;
        
        bool use_omp = (count_p2 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            buf[i] = px[i] + A_p2[i];
            buf[count_p2 + i] = py[i] + B_p2[i];
        }
        stats.send_bytes = static_cast<long>(buf.size() * sizeof(uint64_t));
        send_net->sendMsg(buf.data(), buf.size()*8, 0);
        stats.t3_send_total = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t4([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint64_t> R0(count_p2), R1(count_p2), R2(count_p2), R3(count_p2), R4(count_p2);
        generate_consistent_random_64_time(R0.data(), count_p2, seedT_p2 + 2);
        generate_consistent_random_64_time(R1.data(), count_p2, seedC_p2);
        generate_consistent_random_64_time(R2.data(), count_p2, seedC_p2 + 1);
        generate_consistent_random_64_time(R3.data(), count_p2, seedC_p2 + 2);
        generate_consistent_random_64_time(R4.data(), count_p2, seedC_p2 + 3);

        const uint64_t* px = input_x + off_p2;
        const uint64_t* py = input_y + off_p2;
        bool use_omp = (count_p2 > OMP_THRESHOLD);
        
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            uint64_t a = A_p2[i], b = B_p2[i];
            uint64_t b2 = b * b;
            uint64_t ab2 = 2 * a * b; 
            
            uint64_t t1 = b2 * (px[i] - R1[i]);
            uint64_t t2 = ab2 * (py[i] - R2[i]);
            uint64_t t3 = 2 * b * R3[i];
            uint64_t t4 = a * R4[i];
            uint64_t const_term = 2 * a * b2; 
            
            output[off_p2 + i] = t1 + t2 + t3 + t4 - R0[i] + const_term;
        }
        stats.t4_local_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    stats.waste_time = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    
    auto t_online_sync = std::chrono::high_resolution_clock::now();
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    t1.join(); t2.join(); t3.join(); t4.join();

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP1] XY^2 DualPort Protocol:\n");
    TIME_PRINTF("1. Offline Setup   : %ld us (A,B)\n", stats.offline_time);
    TIME_PRINTF("2. Online Wall     : %ld us\n", stats.online_wall);
    TIME_PRINTF("   |- T1 (Recv P1) : %ld us\n", stats.t1_recv_time);
    TIME_PRINTF("   |- T2 (TEE P1)  : %ld us [Prep:%ld, Wait:%ld, Recon:%ld]\n",
           stats.t2_tee_total, stats.t2_prep, stats.t2_wait, stats.t2_recon);
    TIME_PRINTF("   |- T3 (Send P2) : %ld us\n", stats.t3_send_total);
    TIME_PRINTF("   |- T4 (Locl P2) : %ld us (RNG+Calc)\n", stats.t4_local_time);
    TIME_PRINTF("3. Start Overhead  : %ld us\n", stats.waste_time);
    TIME_PRINTF("4. Comm Bytes      : send=%ld recv=%ld\n", stats.send_bytes, stats.recv_bytes);
    TIME_PRINTF("=== Total Time     : %ld us ===\n\n", stats.total_func);
}

namespace {

static const uint64_t RECIP_STEEP_TIME_1_8_A[] = { 7302750, 18446744073708636921ULL };
static const uint64_t RECIP_STEEP_TIME_1_8_B[] = {
    18446744073705390564ULL, 18446744073707580372ULL, 18446744073708423472ULL, 18446744073708750666ULL,
    18446744073709017682ULL, 18446744073709131966ULL, 18446744073709264455ULL, 18446744073709315875ULL
};
static const uint64_t RECIP_STEEP_TIME_1_12_A[] = { 9042731, 18446744073708425725ULL };
static const uint64_t RECIP_STEEP_TIME_1_12_B[] = {
    18446744073704251352ULL, 18446744073707043738ULL, 18446744073708045298ULL, 18446744073708484106ULL,
    18446744073708792649ULL, 18446744073708956205ULL, 18446744073709105714ULL, 18446744073709186085ULL,
    18446744073709274122ULL, 18446744073709319104ULL, 18446744073709376840ULL, 18446744073709403738ULL
};
static const uint64_t RECIP_STEEP_TIME_2_12_A[] = { 10541262, 18446744073478563805ULL, 28721910 };
static const uint64_t RECIP_STEEP_TIME_2_12_B[] = {
    467512132, 18446744073706823865ULL, 15571795, 18446744073708375307ULL, 2743818, 18446744073708884932ULL,
    729954, 18446744073709133947ULL, 213524, 18446744073709278738ULL, 52355, 18446744073709371459ULL
};
static const uint64_t RECIP_STEEP_TIME_3_12_A[] = { 10493721, 18446744073397609819ULL, 60303471, 18446744073706867396ULL };
static const uint64_t RECIP_STEEP_TIME_3_12_B[] = {
    457649439, 63521310, 15357315, 7010609, 2757155, 1707326,
    762561, 548885, 242211, 195671, 74244, 77524
};

static const uint64_t INVSQRT_STEEP_TIME_1_8_A[] = { 2868183, 18446744073709235478ULL };
static const uint64_t INVSQRT_STEEP_TIME_1_8_B[] = {
    18446744073708257638ULL, 18446744073708999558ULL, 18446744073709249300ULL, 18446744073709349212ULL,
    18446744073709420674ULL, 18446744073709453125ULL, 18446744073709486009ULL, 18446744073709499693ULL
};
static const uint64_t INVSQRT_STEEP_TIME_1_12_A[] = { 3730054, 18446744073709072108ULL };
static const uint64_t INVSQRT_STEEP_TIME_1_12_B[] = {
    18446744073707992685ULL, 18446744073708583861ULL, 18446744073709162028ULL, 18446744073709141744ULL,
    18446744073709369761ULL, 18446744073709314877ULL, 18446744073709451842ULL, 18446744073709394806ULL,
    18446744073709496788ULL, 18446744073709432371ULL, 18446744073709549087ULL, 18446744073709281533ULL
};
static const uint64_t INVSQRT_STEEP_TIME_2_12_A[] = { 3500553, 18446744073666860342ULL, 5289533 };
static const uint64_t INVSQRT_STEEP_TIME_2_12_B[] = {
    85545813, 18446744073708850021ULL, 2764810, 18446744073709275014ULL, 467702, 18446744073709404290ULL,
    118180, 18446744073709463726ULL, 32091, 18446744073709496542ULL, 6675, 18446744073709516618ULL
};
static const uint64_t INVSQRT_STEEP_TIME_3_12_A[] = { 4582560, 18446744073573651975ULL, 32914154, 18446744073707552004ULL };
static const uint64_t INVSQRT_STEEP_TIME_3_12_B[] = {
    145048019, 48352595, 4842633, 5677967, 862819, 1530272,
    233378, 569537, 68202, 250668, 8332, 165149
};

static void get_recip_steep_time_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 8) { *out_a = RECIP_STEEP_TIME_1_8_A; *out_b = RECIP_STEEP_TIME_1_8_B; }
    else if (k1 == 1 && k2 == 12) { *out_a = RECIP_STEEP_TIME_1_12_A; *out_b = RECIP_STEEP_TIME_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = RECIP_STEEP_TIME_2_12_A; *out_b = RECIP_STEEP_TIME_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = RECIP_STEEP_TIME_3_12_A; *out_b = RECIP_STEEP_TIME_3_12_B; }
    else {
        printf("⚠️  [RECIP_BASE_TIME] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = RECIP_STEEP_TIME_1_12_A; *out_b = RECIP_STEEP_TIME_1_12_B;
    }
}

static void get_invsqrt_steep_time_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 8) { *out_a = INVSQRT_STEEP_TIME_1_8_A; *out_b = INVSQRT_STEEP_TIME_1_8_B; }
    else if (k1 == 1 && k2 == 12) { *out_a = INVSQRT_STEEP_TIME_1_12_A; *out_b = INVSQRT_STEEP_TIME_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = INVSQRT_STEEP_TIME_2_12_A; *out_b = INVSQRT_STEEP_TIME_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = INVSQRT_STEEP_TIME_3_12_A; *out_b = INVSQRT_STEEP_TIME_3_12_B; }
    else {
        printf("⚠️  [INVSQRT_BASE_TIME] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = INVSQRT_STEEP_TIME_1_12_A; *out_b = INVSQRT_STEEP_TIME_1_12_B;
    }
}

static inline uint64_t secure_truncate_time_local(uint64_t value, int shift_bits) {
    if (value < (1ULL << 63)) {
        return value >> shift_bits;
    }
    uint64_t complement = UINT64_MAX - value + 1;
    uint64_t truncated = complement >> shift_bits;
    return UINT64_MAX - truncated + 1;
}

static inline uint64_t multiply_public_fixed_share_time_local(
    uint64_t public_coeff, uint64_t share, int shift_bits
) {
    return secure_truncate_time_local(public_coeff * share, shift_bits);
}

static void calculate_hybrid_reciprocal_steep_csp1_time_local(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_recip_steep_time_coeffs(k1, k2, &current_a, &current_b);
    const int b_len = k2;
    const uint64_t s = 20;

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx;
    std::condition_variable gun_cv;
    bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        ecall_calculate_reciprocal_steep_shares(
            global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
        );
        {
            std::unique_lock<std::mutex> lk(shared.mtx);
            shared.cv.wait(lk, [&] { return shared.done_net; });
        }

        const double inv_scale = 1.0 / static_cast<double>(scale);
        const double L_const = 8.0;
        #pragma omp parallel for
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
            double delta_d = static_cast<int64_t>(d1) * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle);
                double cv_v = cos(angle);
                double v1v = static_cast<int64_t>(v1[k * size + i]) * inv_scale;
                double u1v = static_cast<int64_t>(u1[k * size + i]) * inv_scale;
                trig_sum += static_cast<uint64_t>(static_cast<int64_t>(std::round((sv * v1v - cv_v * u1v) * scale)));
            }
            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += secure_truncate_time_local(current_a[1] * ((uint64_t)0 - t1[i]), s);
            if (k1 >= 2) {
                uint64_t x2_share = (uint64_t)0 - 2 * secure_truncate_time_local(d1 * t1[i], s) + t2_share1[i];
                poly_sum += secure_truncate_time_local(current_a[2] * x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                uint64_t x3_share = (uint64_t)0 - 3 * secure_truncate_time_local(d2 * t1[i], s)
                    + 3 * secure_truncate_time_local(d1 * t2_share1[i], s) - t3_share1[i];
                poly_sum += secure_truncate_time_local(current_a[3] * x3_share, s);
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u1;
        delete[] v1;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input_x[i] + t1[i];
        net_send->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        net_recv->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        {
            std::lock_guard<std::mutex> lk(shared.mtx);
            shared.done_net = true;
        }
        shared.cv.notify_all();
    });

    {
        std::lock_guard<std::mutex> lk(gun_mtx);
        gun = true;
    }
    gun_cv.notify_all();
    th_calc.join();
    th_send.join();
    th_recv.join();

    delete[] t1;
    delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

static void calculate_hybrid_rsqrt_steep_csp1_time_local(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_invsqrt_steep_time_coeffs(k1, k2, &current_a, &current_b);
    const int b_len = k2;
    const uint64_t s = 20;

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx;
    std::condition_variable gun_cv;
    bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        ecall_calculate_invsqrt_steep_shares(
            global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
        );
        {
            std::unique_lock<std::mutex> lk(shared.mtx);
            shared.cv.wait(lk, [&] { return shared.done_net; });
        }

        uint64_t* x2_share1_buf = (k1 >= 2) ? new uint64_t[size] : nullptr;
        uint64_t* x3_share1_buf = (k1 >= 3) ? new uint64_t[size] : nullptr;
        if (k1 >= 2) {
            for (int i = 0; i < size; i++) {
                uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
                x2_share1_buf[i] = (uint64_t)0 - 2 * secure_truncate_time_local(d1 * t1[i], s) + t2_share1[i];
            }
        }
        if (k1 >= 3) {
            for (int i = 0; i < size; i++) {
                uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                x3_share1_buf[i] = (uint64_t)0 - 3 * secure_truncate_time_local(d2 * t1[i], s)
                    + 3 * secure_truncate_time_local(d1 * t2_share1[i], s) - t3_share1[i];
            }
        }

        uint64_t* x2_share0_buf = (k1 >= 2) ? new uint64_t[size] : nullptr;
        uint64_t* x3_share0_buf = (k1 >= 3) ? new uint64_t[size] : nullptr;
        if (k1 >= 2) net_recv->recvMsg(x2_share0_buf, size * sizeof(uint64_t), 0);
        if (k1 >= 3) net_recv->recvMsg(x3_share0_buf, size * sizeof(uint64_t), 0);

        net_send->sendMsg(u1, size * b_len * sizeof(uint64_t), 0);
        net_send->sendMsg(v1, size * b_len * sizeof(uint64_t), 0);
        if (k1 >= 2) net_send->sendMsg(x2_share1_buf, size * sizeof(uint64_t), 0);
        if (k1 >= 3) net_send->sendMsg(x3_share1_buf, size * sizeof(uint64_t), 0);

        const double inv_scale = 1.0 / static_cast<double>(scale);
        const double L_const = 8.0;
        if (x2_share0_buf) delete[] x2_share0_buf;
        if (x3_share0_buf) delete[] x3_share0_buf;
        if (x2_share1_buf) delete[] x2_share1_buf;
        if (x3_share1_buf) delete[] x3_share1_buf;

        #pragma omp parallel for
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
            double delta_d = static_cast<int64_t>(d1) * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle);
                double cv_v = cos(angle);
                double v1v = static_cast<int64_t>(v1[k * size + i]) * inv_scale;
                double u1v = static_cast<int64_t>(u1[k * size + i]) * inv_scale;
                trig_sum += static_cast<uint64_t>(static_cast<int64_t>(std::round((sv * v1v - cv_v * u1v) * scale)));
            }
            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += secure_truncate_time_local(current_a[1] * ((uint64_t)0 - t1[i]), s);
            if (k1 >= 2) {
                uint64_t x2_share = (uint64_t)0 - 2 * secure_truncate_time_local(d1 * t1[i], s) + t2_share1[i];
                poly_sum += secure_truncate_time_local(current_a[2] * x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                uint64_t x3_share = (uint64_t)0 - 3 * secure_truncate_time_local(d2 * t1[i], s)
                    + 3 * secure_truncate_time_local(d1 * t2_share1[i], s) - t3_share1[i];
                poly_sum += secure_truncate_time_local(current_a[3] * x3_share, s);
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u1;
        delete[] v1;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input_x[i] + t1[i];
        net_send->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        net_recv->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        {
            std::lock_guard<std::mutex> lk(shared.mtx);
            shared.done_net = true;
        }
        shared.cv.notify_all();
    });

    {
        std::lock_guard<std::mutex> lk(gun_mtx);
        gun = true;
    }
    gun_cv.notify_all();
    th_calc.join();
    th_send.join();
    th_recv.join();

    delete[] t1;
    delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

}
