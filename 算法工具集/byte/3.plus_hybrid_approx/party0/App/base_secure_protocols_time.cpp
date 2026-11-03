#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>


#include <atomic>
#include <chrono>
#include <cmath>
#include <complex>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <cstring>

#include "sgx_urts.h"
#include "Enclave_u.h"


#include "App.h"
#include "base_secure_protocols_time.h"
#include "calculate/basicSockets.h"
#include "epo_snn_64.h"
#include "func.h"


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



void generateRandomArrayUint64_time(uint64_t* array, uint64_t size, uint64_t seed, uint64_t range) {
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<uint64_t> dist(0, range - 1);
    
    for (uint64_t i = 0; i < size; i++) {
        array[i] = dist(gen);
    }
}
void secure_multiply_batch_parallel_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_a, const uint64_t* input_b, 
    uint64_t* output, uint64_t count, uint64_t s, uint64_t L
) {
    struct PerfStats {
        long offline_time = 0;   
        long t1_calc_time = 0;   
        long t1_send_time = 0;   
        long t2_total_time = 0;  
        long create_time = 0;    
        long join_time = 0;      
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;     
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;

    
    auto t_offline_start = std::chrono::high_resolution_clock::now();

    
    uint64_t* a = new uint64_t[count];
    uint64_t* b = new uint64_t[count];
    
    generate_consistent_random_64_time(a, count, seedT);
    generate_consistent_random_64_time(b, count, seedT + 1);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_offline_start).count();

    
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

        uint64_t* send_buffer = new uint64_t[count * 2];
        uint64_t* mask_x_ptr = send_buffer;
        uint64_t* mask_y_ptr = send_buffer + count;
        
        
        auto t_calc_start = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < count; i++) {
            mask_x_ptr[i] = input_a[i] + a[i];
            mask_y_ptr[i] = input_b[i] + b[i];
        }
        stats.t1_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_calc_start).count();

        
        long bytes = count * 2 * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        auto t_send_start = std::chrono::high_resolution_clock::now();
        server->sendMsg(send_buffer, bytes, 0);
        stats.t1_send_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_send_start).count();

        delete[] send_buffer;
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        auto t2_start = std::chrono::high_resolution_clock::now();
        
        
        uint64_t* r0 = new uint64_t[count];
        uint64_t* r1 = new uint64_t[count];
        uint64_t* r2 = new uint64_t[count];

        
        generate_consistent_random_64_time(r0, count, seedT + 2);
        generate_consistent_random_64_time(r1, count, seedC);
        generate_consistent_random_64_time(r2, count, seedC + 1);
        
        
        for (uint64_t i = 0; i < count; i++) {
            uint64_t term1 = (r1[i] * b[i]) + (a[i] * r2[i]);
            uint64_t term2 = (input_a[i] * b[i]) + (a[i] * input_b[i]) + (a[i] * b[i]) + r0[i];
            output[i] = term1 - term2;
        }
        
        stats.t2_total_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t2_start).count();
        
        delete[] r0; delete[] r1; delete[] r2;
    });

    stats.create_time = std::chrono::duration_cast<std::chrono::microseconds>(
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

    
    delete[] a; delete[] b;
    
    
    long a1_total = stats.offline_time + stats.t1_calc_time;
    long thread_waste = stats.create_time; 

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Single Mul Optimized (Sync):\n");
    TIME_PRINTF("a1时间（Offline + Thread1 Mask计算）: %ld us (Offline: %ld us, Mask: %ld us)\n", 
           a1_total, stats.offline_time, stats.t1_calc_time);
    TIME_PRINTF("b1时间（发送时间）: %ld us\n", stats.t1_send_time);
    TIME_PRINTF("thread2计算时间: %ld us\n", stats.t2_total_time);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("总时间: %ld us\n", stats.total_func-thread_waste);
    TIME_PRINTF("发送多少byte: %ld bytes\n", stats.comm_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_triple_multiply_batch_parallel_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, const uint64_t* input_w, 
    uint64_t* output, uint64_t count, uint64_t s, uint64_t L
) {
    if (!is_csp0) return; 

    struct PerfStats {
        long offline_time = 0;   
        long t1_calc_time = 0;   
        long t1_send_time = 0;   
        long t2_total_time = 0;  
        long create_time = 0;    
        long join_time = 0;      
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;     
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456;
    uint64_t seedC = 654321;

    
    auto t_offline_start = std::chrono::high_resolution_clock::now();

    uint64_t* a = new uint64_t[count]; 
    uint64_t* b = new uint64_t[count]; 
    uint64_t* c = new uint64_t[count];

    generate_consistent_random_64_time(a, count, seedT);
    generate_consistent_random_64_time(b, count, seedT + 1);
    generate_consistent_random_64_time(c, count, seedT + 2);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_offline_start).count();

    
    uint64_t* r0 = new uint64_t[count]; uint64_t* r1 = new uint64_t[count]; uint64_t* r2 = new uint64_t[count];
    uint64_t* r3 = new uint64_t[count]; uint64_t* r4 = new uint64_t[count]; uint64_t* r5 = new uint64_t[count];
    uint64_t* r6 = new uint64_t[count];

    
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

        uint64_t* send_buf = new uint64_t[count * 3];
        
        
        auto t_calc_start = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < count; i++) {
            send_buf[i] = input_x[i] + a[i];
            send_buf[count + i] = input_y[i] + b[i];
            send_buf[count * 2 + i] = input_w[i] + c[i];
        }
        stats.t1_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_calc_start).count();

        
        long bytes = count * 3 * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        auto t_send_start = std::chrono::high_resolution_clock::now();
        server->sendMsg(send_buf, bytes, 0);
        stats.t1_send_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_send_start).count();

        delete[] send_buf;
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        auto t2_start = std::chrono::high_resolution_clock::now();
        
        
        generate_consistent_random_64_time(r0, count, seedT + 3);
        generate_consistent_random_64_time(r1, count, seedC);
        generate_consistent_random_64_time(r2, count, seedC + 1);
        generate_consistent_random_64_time(r3, count, seedC + 2);
        generate_consistent_random_64_time(r4, count, seedC + 3);
        generate_consistent_random_64_time(r5, count, seedC + 4);
        generate_consistent_random_64_time(r6, count, seedC + 5);

        
        for (uint64_t i = 0; i < count; i++) {
            uint64_t m1 = 2*a[i]*b[i]*c[i] + a[i]*r4[i] + b[i]*r5[i] + c[i]*r6[i];
            uint64_t m2 = a[i]*b[i]*(input_w[i]-r3[i]) + a[i]*c[i]*(input_y[i]-r2[i]) + b[i]*c[i]*(input_x[i]-r1[i]);
            output[i] = m1 + m2 - r0[i];
        }
        
        stats.t2_total_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t2_start).count();
    });

    stats.create_time = std::chrono::duration_cast<std::chrono::microseconds>(
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

    
    delete[] a; delete[] b; delete[] c; delete[] r0;
    delete[] r1; delete[] r2; delete[] r3; delete[] r4; delete[] r5; delete[] r6;

    
    
    
    long a1_total = stats.offline_time + stats.t1_calc_time;
    long thread_waste = stats.create_time; 

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Triple Mul Optimized (Sync):\n");
    TIME_PRINTF("a1时间（Offline + Thread1 Mask计算）: %ld us (Offline: %ld us, Mask: %ld us)\n", 
           a1_total, stats.offline_time, stats.t1_calc_time);
    TIME_PRINTF("b1时间（发送时间）: %ld us\n", stats.t1_send_time);
    TIME_PRINTF("thread2计算时间: %ld us\n", stats.t2_total_time);
    TIME_PRINTF("创建线程浪费时间: %ld us\n", thread_waste);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("发送多少byte: %ld bytes\n", stats.comm_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_multiply_batch_dualport_time(BSNet* send_channel, BSNet* recv_channel, bool is_csp0, 
                                  const uint64_t* input_a, const uint64_t* input_b, 
                                  uint64_t* output, 
                                  uint64_t count, 
                                  uint64_t s, uint64_t L) {
    
    struct PerfStats {
        long offline_time = 0; 
        
        
        long t1_total = 0;
        long t1_calc = 0;      
        long t1_send = 0;      
        
        long t2_time = 0;      
        long t3_time = 0;      
        
        
        long t4_total = 0;
        long t4_prep = 0;      
        long t4_wait = 0;      
        long t4_recon = 0;     
        
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
    
    uint64_t* a_p1 = new uint64_t[half_count];
    uint64_t* b_p1 = new uint64_t[half_count];
    generate_consistent_random_64_time(a_p1, half_count, seedT);
    generate_consistent_random_64_time(b_p1, half_count, seedT + 1);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_off_start).count();

    
    struct SharedData {
        uint64_t* res_local = nullptr; uint64_t* res_tee = nullptr;   
        uint64_t* recv_buf = nullptr;  uint64_t* recv_x = nullptr; uint64_t* recv_y = nullptr;
        bool recv_done = false; std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.res_local = new uint64_t[half_count];
    shared.res_tee = new uint64_t[second_count];
    shared.recv_buf = new uint64_t[second_count * 2]; 
    shared.recv_x = shared.recv_buf;
    shared.recv_y = shared.recv_buf + second_count;

    
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
        auto t1_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* send_buf = new uint64_t[half_count * 2];
        
        
        for (uint64_t i = 0; i < half_count; i++) {
            send_buf[i] = input_a[i] + a_p1[i];
            send_buf[half_count + i] = input_b[i] + b_p1[i];
        }
        auto t1_calc_end = std::chrono::high_resolution_clock::now();
        
        
        long bytes = half_count * 2 * sizeof(uint64_t);
        send_channel->sendMsg(send_buf, bytes, 0);
        auto t1_send_end = std::chrono::high_resolution_clock::now();

        stats.send_bytes = bytes;
        delete[] send_buf;

        
        stats.t1_calc = std::chrono::duration_cast<std::chrono::microseconds>(t1_calc_end - t1_start).count();
        stats.t1_send = std::chrono::duration_cast<std::chrono::microseconds>(t1_send_end - t1_calc_end).count();
        stats.t1_total = stats.t1_calc + stats.t1_send;
    });

    
    auto t2 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        uint64_t* r0_p1 = new uint64_t[half_count];
        uint64_t* r1_p1 = new uint64_t[half_count];
        uint64_t* r2_p1 = new uint64_t[half_count];

        generate_consistent_random_64_time(r0_p1, half_count, seedT + 2);
        generate_consistent_random_64_time(r1_p1, half_count, seedC);
        generate_consistent_random_64_time(r2_p1, half_count, seedC + 1);

        for (uint64_t i = 0; i < half_count; i++) {
            shared.res_local[i] = (a_p1[i] * r2_p1[i]) + (b_p1[i] * r1_p1[i]) - (a_p1[i] * b_p1[i]) 
                                - (a_p1[i] * input_b[i]) - (b_p1[i] * input_a[i]) - r0_p1[i];
        }
        delete[] r0_p1; delete[] r1_p1; delete[] r2_p1;
        stats.t2_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    
    auto t3 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        long bytes = second_count * 2 * sizeof(uint64_t);
        recv_channel->recvMsg(shared.recv_buf, bytes, 0);
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
        stats.t3_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    
    auto t4 = std::thread([&]() {
        wait_for_gun(); 
        auto t4_start = std::chrono::high_resolution_clock::now();

        uint64_t* r1_p2 = new uint64_t[second_count];
        uint64_t* r2_p2 = new uint64_t[second_count];
        uint64_t* xr1 = new uint64_t[second_count];
        uint64_t* yr2 = new uint64_t[second_count];
        uint64_t* tres = new uint64_t[second_count];
        uint64_t* tee_a_p2 = nullptr;
        uint64_t* tee_b_p2 = nullptr;
        uint64_t* tee_r0_p2 = nullptr;

        
        generate_consistent_random_64_time(r1_p2, second_count, seedC_p2);
        generate_consistent_random_64_time(r2_p2, second_count, seedC_p2 + 1);
        ecall_smp_gen_ab_r0_64(global_eid1, seedT_p2, second_count);


        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            xr1[i] = input_a[idx] + r1_p2[i]; 
            yr2[i] = input_b[idx] + r2_p2[i];
        }
        ecall_smp_tee1_computation_64(global_eid1, second_count, half_count, xr1, yr2, tres);

        auto t4_prep_end = std::chrono::high_resolution_clock::now();

        
        { 
            std::unique_lock<std::mutex> lock(shared.mtx); 
            shared.cv.wait(lock, [&]() { return shared.recv_done; }); 
        }
        auto t4_wait_end = std::chrono::high_resolution_clock::now();

        
        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            uint64_t recon_x = shared.recv_x[i] + input_a[idx];
            uint64_t recon_y = shared.recv_y[i] + input_b[idx];
            uint64_t recon_mul = recon_x * recon_y;
            __int128 recon_mul_signed_wide =
                (__int128)(int64_t)recon_x * (__int128)(int64_t)recon_y;
            uint64_t recon_mul_signed = (uint64_t)recon_mul_signed_wide;
            shared.res_tee[i] = recon_mul + tres[i];
        }
        auto t4_recon_end = std::chrono::high_resolution_clock::now();
        
        delete[] r1_p2; delete[] r2_p2; delete[] xr1; delete[] yr2; delete[] tres;
        delete[] tee_a_p2; delete[] tee_b_p2; delete[] tee_r0_p2;

        
        stats.t4_prep = std::chrono::duration_cast<std::chrono::microseconds>(t4_prep_end - t4_start).count();
        stats.t4_wait = std::chrono::duration_cast<std::chrono::microseconds>(t4_wait_end - t4_prep_end).count();
        stats.t4_recon = std::chrono::duration_cast<std::chrono::microseconds>(t4_recon_end - t4_wait_end).count();
        stats.t4_total = stats.t4_prep + stats.t4_wait + stats.t4_recon;
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

    
    for (uint64_t i = 0; i < half_count; i++) output[i] = shared.res_local[i];
    for (uint64_t i = 0; i < second_count; i++) output[half_count + i] = shared.res_tee[i];
    
    

    delete[] shared.res_local; delete[] shared.res_tee; delete[] shared.recv_buf;
    delete[] a_p1; delete[] b_p1;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] DualPort Breakdown:\n");
    TIME_PRINTF("batchsize=%ld\n", count);
    TIME_PRINTF("  Offline Time         : %ld us\n", stats.offline_time);
    TIME_PRINTF("  t1 (Send)            : %ld us (Calc: %ld, Send: %ld)\n",
           stats.t1_total, stats.t1_calc, stats.t1_send);
    TIME_PRINTF("  t2 (Local Calc)      : %ld us\n", stats.t2_time);
    TIME_PRINTF("  t3 (Recv)            : %ld us\n", stats.t3_time);
    TIME_PRINTF("  t4 (TEE)             : %ld us\n", stats.t4_total);
    TIME_PRINTF("      |-- Prep (RNG+TEE): %ld us\n", stats.t4_prep);
    TIME_PRINTF("      |-- Wait (Sync)   : %ld us\n", stats.t4_wait);
    TIME_PRINTF("      |-- Load (Recon)  : %ld us\n", stats.t4_recon);
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

    uint64_t *a = new uint64_t[half_count]; uint64_t *b = new uint64_t[half_count]; 
    uint64_t *c = new uint64_t[half_count]; uint64_t *r0 = new uint64_t[half_count];
    
    uint64_t *r1 = new uint64_t[count]; uint64_t *r2 = new uint64_t[count]; uint64_t *r3 = new uint64_t[count];
    uint64_t *r4 = new uint64_t[count]; uint64_t *r5 = new uint64_t[count]; uint64_t *r6 = new uint64_t[count];

    generate_consistent_random_64_time(a, half_count, seedT);
    generate_consistent_random_64_time(b, half_count, seedT + 1);
    generate_consistent_random_64_time(c, half_count, seedT + 2);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_off_start).count();

    
    struct SharedData {
        uint64_t* res_local = nullptr; uint64_t* res_tee = nullptr; 
        uint64_t* recv_buf = nullptr;
        uint64_t* px = nullptr; uint64_t* py = nullptr; uint64_t* pw = nullptr;
        bool recv_done = false; std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.res_local = new uint64_t[half_count];
    shared.res_tee = new uint64_t[second_count];
    
    shared.recv_buf = new uint64_t[second_count * 3];
    shared.px = shared.recv_buf; 
    shared.py = shared.recv_buf + second_count; 
    shared.pw = shared.recv_buf + second_count * 2;

    
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
        uint64_t* sbuf = new uint64_t[half_count * 3];
        
        
        for (uint64_t i = 0; i < half_count; i++) {
            sbuf[i] = input_x[i] + a[i]; 
            sbuf[half_count + i] = input_y[i] + b[i]; 
            sbuf[half_count*2 + i] = input_w[i] + c[i];
        }
        auto t_calc_end = std::chrono::high_resolution_clock::now();

        
        send_channel->sendMsg(sbuf, half_count * 3 * sizeof(uint64_t), 0);
        auto t_send_end = std::chrono::high_resolution_clock::now();
        
        delete[] sbuf;
        stats.send_calc = std::chrono::duration_cast<std::chrono::microseconds>(t_calc_end - t_start).count();
        stats.send_net = std::chrono::duration_cast<std::chrono::microseconds>(t_send_end - t_calc_end).count();
        stats.send_total = stats.send_calc + stats.send_net;
    });

    std::thread t2([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();

        generate_consistent_random_64_time(r0, half_count, seedT + 3);
        
        generate_consistent_random_64_time(r1, half_count, seedC);
        generate_consistent_random_64_time(r2, half_count, seedC + 1);
        generate_consistent_random_64_time(r3, half_count, seedC + 2);
        generate_consistent_random_64_time(r4, half_count, seedC + 3);
        generate_consistent_random_64_time(r5, half_count, seedC + 4);
        generate_consistent_random_64_time(r6, half_count, seedC + 5);
        
        auto t_rng_end = std::chrono::high_resolution_clock::now();

        for (uint64_t i = 0; i < half_count; i++) {
            uint64_t m1 = 2*a[i]*b[i]*c[i] + a[i]*r4[i] + b[i]*r5[i] + c[i]*r6[i];
            uint64_t m2 = a[i]*b[i]*(input_w[i]-r3[i]) + a[i]*c[i]*(input_y[i]-r2[i]) + b[i]*c[i]*(input_x[i]-r1[i]);
            shared.res_local[i] = m1 + m2 - r0[i];
        }
        
        stats.local_rng = std::chrono::duration_cast<std::chrono::microseconds>(t_rng_end - t_start).count();
        stats.local_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_start).count();
    });

    std::thread t3([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();
        
        recv_channel->recvMsg(shared.recv_buf, second_count * 3 * sizeof(uint64_t), 0);
        
        stats.recv_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_start).count();
        
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    std::thread t4([&]() {
        wait_for_gun();
        auto t_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* xr1 = new uint64_t[second_count]; uint64_t* yr2 = new uint64_t[second_count]; 
        uint64_t* wr3 = new uint64_t[second_count]; uint64_t* tf = new uint64_t[second_count];
        
        uint64_t* r1_p2 = r1 + half_count; uint64_t* r2_p2 = r2 + half_count; uint64_t* r3_p2 = r3 + half_count;
        uint64_t* r4_p2 = r4 + half_count; uint64_t* r5_p2 = r5 + half_count; uint64_t* r6_p2 = r6 + half_count;

        generate_consistent_random_64_time(r1_p2, second_count, seedC_Part2);
        generate_consistent_random_64_time(r2_p2, second_count, seedC_Part2 + 1);
        generate_consistent_random_64_time(r3_p2, second_count, seedC_Part2 + 2);
        generate_consistent_random_64_time(r4_p2, second_count, seedC_Part2 + 3);
        generate_consistent_random_64_time(r5_p2, second_count, seedC_Part2 + 4);
        generate_consistent_random_64_time(r6_p2, second_count, seedC_Part2 + 5);

        ecall_3smp_gen_abc_r0_64(global_eid1, seedT_Part2, second_count);

        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            xr1[i] = input_x[idx] + r1[idx]; yr2[i] = input_y[idx] + r2[idx]; wr3[i] = input_w[idx] + r3[idx];
        }
        
        ecall_3smp_tee1_compute_m3_64(global_eid1, second_count, xr1, yr2, wr3);
        
        auto t_prep_end = std::chrono::high_resolution_clock::now();

        
        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.recv_done; }); }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        
        uint64_t* U = xr1; uint64_t* V = yr2; uint64_t* W = wr3;
        for (uint64_t i = 0; i < second_count; i++) {
            uint64_t idx = half_count + i;
            uint64_t Xa = shared.px[i] + input_x[idx]; uint64_t Yb = shared.py[i] + input_y[idx]; uint64_t Wc = shared.pw[i] + input_w[idx];
            U[i] = Yb * Wc + r4[idx]; V[i] = Xa * Wc + r5[idx]; W[i] = Xa * Yb + r6[idx];
            shared.res_tee[i] = (uint64_t)((uint128_t)Xa * Yb * Wc);
        }
        ecall_3smp_tee1_compute_m4_64(global_eid1, second_count, U, V, W, tf);
        for (uint64_t i = 0; i < second_count; i++) shared.res_tee[i] += tf[i];
        
        auto t_recon_end = std::chrono::high_resolution_clock::now();
        delete[] xr1; delete[] yr2; delete[] wr3; delete[] tf;

        stats.tee_prep = std::chrono::duration_cast<std::chrono::microseconds>(t_prep_end - t_start).count();
        stats.tee_wait = std::chrono::duration_cast<std::chrono::microseconds>(t_wait_end - t_prep_end).count();
        stats.tee_recon = std::chrono::duration_cast<std::chrono::microseconds>(t_recon_end - t_wait_end).count();
        stats.tee_total = stats.tee_prep + stats.tee_wait + stats.tee_recon;
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
    for(uint64_t i=0; i<half_count; i++) output[i] = shared.res_local[i];
    for(uint64_t i=0; i<second_count; i++) output[half_count+i] = shared.res_tee[i];

    
    delete[] shared.res_local; delete[] shared.res_tee; delete[] shared.recv_buf;
    delete[] a; delete[] b; delete[] c; delete[] r0; 
    delete[] r1; delete[] r2; delete[] r3; delete[] r4; delete[] r5; delete[] r6;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Triple Mul DualPort Breakdown:\n");
    TIME_PRINTF("  Offline/Init Time    : %ld us\n", stats.offline_time);
    TIME_PRINTF("  t1 (Send P1)         : %ld us (Calc: %ld, Send: %ld)\n",
           stats.send_total, stats.send_calc, stats.send_net);
    TIME_PRINTF("  t2 (Local Calc P1)   : %ld us (RNG: %ld)\n", stats.local_time, stats.local_rng);
    TIME_PRINTF("  t3 (Recv P2)         : %ld us\n", stats.recv_time);
    TIME_PRINTF("  t4 (TEE Calc P2)     : %ld us\n", stats.tee_total);
    TIME_PRINTF("      |-- Prep (RNG+Init): %ld us\n", stats.tee_prep);
    TIME_PRINTF("      |-- Wait (Sync)    : %ld us\n", stats.tee_wait);
    TIME_PRINTF("      |-- Recon          : %ld us\n", stats.tee_recon);
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
void ODReLU_CSP0_2Threads_64_time(BSNet* server_port12345, const uint64_t* x0_input, uint64_t* drelu_output, int vector_size) {
    
    struct PerfStats {
        long offline_time = 0;   
        long t1_calc_time = 0;   
        long t1_send_time = 0;   
        long t2_calc_time = 0;   
        long create_time = 0;    
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();

    uint64_t seedT = 123456;
    uint64_t seedC = 654321;
    uint64_t xi = 100;
    
    
    uint64_t* x0 = new uint64_t[vector_size];
    memcpy(x0, x0_input, vector_size * sizeof(uint64_t));
    
    
    uint64_t* r2 = new uint64_t[vector_size];
    uint64_t* a = new uint64_t[vector_size];
    uint64_t* b = new uint64_t[vector_size];
    uint64_t* r0 = new uint64_t[vector_size];
    uint64_t* r1 = new uint64_t[vector_size];
    uint64_t* v = new uint64_t[vector_size];

    
    auto init_start = std::chrono::high_resolution_clock::now();
    
    host_odrelu_gen_params_time(seedT, vector_size, xi, a, b, r0, r1, v);

    generateRandomArrayUint64_time(r2, vector_size, seedC, 100); 

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - init_start).count();
    
    struct SharedData {
        uint64_t* c0;
        bool network_done = false;
        std::mutex mtx;
        std::condition_variable cv;
        SharedData(int size) { c0 = new uint64_t[size]; }
        ~SharedData() { delete[] c0; }
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
        
        uint64_t* send_data = new uint64_t[vector_size];
        
        
        auto t_calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < vector_size; i++) {
            send_data[i] = a[i] * (x0[i] + r2[i]) + b[i] + r0[i];
        }
        stats.t1_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_calc_start).count();
        
        
        long bytes = vector_size * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        auto t_send_start = std::chrono::high_resolution_clock::now();
        
        server_port12345->sendMsg(send_data, bytes, 0);
        
        stats.t1_send_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_send_start).count();
        
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.network_done = true; }
        shared.cv.notify_one();
        delete[] send_data;
    });

    
    auto computeThread = std::thread([&]() {
        wait_for_gun(); 
        auto t2_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* r3_local = new uint64_t[vector_size];
        uint64_t* r4_local = new uint64_t[vector_size];
        
        generateRandomArrayUint64_time(r3_local, vector_size, seedC + 1, 100);
        generateRandomArrayUint64_time(r4_local, vector_size, seedC + 2, 100);

        for (int i = 0; i < vector_size; i++) {
            shared.c0[i] = (v[i] == 0) ? (r4_local[i] - r3_local[i] - r1[i]) : (r3_local[i] - r1[i] + r4_local[i]);
        }
        delete[] r3_local; delete[] r4_local;

        stats.t2_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t2_start).count();
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
    for (int i = 0; i < vector_size; i++) drelu_output[i] = shared.c0[i];

    delete[] x0; delete[] r2;
    delete[] a; delete[] b; delete[] r0; delete[] r1; delete[] v;

    long t1_total = stats.t1_calc_time + stats.t1_send_time;
    ODRELU_TIME_PRINTF("---------------------------------------------\n");
    ODRELU_TIME_PRINTF("[CSP0] ODReLU 2Threads:\n");
    ODRELU_TIME_PRINTF("  Offline Init        : %ld us\n", stats.offline_time);
    ODRELU_TIME_PRINTF("  t1 (Mask+Send)      : %ld us (Mask: %ld, Send: %ld)\n",
           t1_total, stats.t1_calc_time, stats.t1_send_time);
    ODRELU_TIME_PRINTF("  t2 (Local Calc)     : %ld us\n", stats.t2_calc_time);
    ODRELU_TIME_PRINTF("  Start Overhead      : %ld us\n", stats.create_time);
    ODRELU_TIME_PRINTF("  Online Wall Time    : %ld us\n", stats.online_wall);
    ODRELU_TIME_PRINTF("  Total Function      : %ld us\n", stats.total_func);
    ODRELU_TIME_PRINTF("  Comm Bytes          : %ld bytes\n", stats.comm_bytes);
    ODRELU_TIME_PRINTF("---------------------------------------------\n\n");
}
void ODReLU_CSP0_4Threads_64_time(BSNet* server_port12345, BSNet* client_port12346,
                             const uint64_t* x0_input, uint64_t* drelu_output, 
                             int vector_size) {
    
    
    struct PerfStats {
        long init_offline = 0;   
        long t1_calc = 0;        
        long t1_send = 0;        
        long t2_calc = 0;        
        long t3_recv = 0;        
        long t4_prep = 0;        
        long t4_ecall1 = 0;      
        long t4_wait = 0;        
        long t4_recon = 0;       
        long t4_ecall2 = 0;      
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

    
    uint64_t* a_loc = new uint64_t[half_size];
    uint64_t* b_loc = new uint64_t[half_size];
    uint64_t* r0_loc = new uint64_t[half_size];
    uint64_t* r1_loc = new uint64_t[half_size];
    uint64_t* v_loc = new uint64_t[half_size];

    
    auto init_start = std::chrono::high_resolution_clock::now();

    
    host_odrelu_gen_params_time(seedT, half_size, xi, a_loc, b_loc, r0_loc, r1_loc, v_loc);

    stats.init_offline = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - init_start).count();
    

    
    struct SharedData {
        uint64_t* c0_first = nullptr;      
        uint64_t* c1_second = nullptr;     
        uint64_t* csp1_recv_data = nullptr;
        uint64_t* r2 = nullptr;            
        uint64_t* r3 = nullptr;
        uint64_t* r4 = nullptr;
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
        
        SharedData(int total_size, int part1_size, int part2_size) {
            c0_first = new uint64_t[part1_size]();
            c1_second = new uint64_t[part2_size]();
            csp1_recv_data = new uint64_t[part2_size]();
            r2 = new uint64_t[total_size]();
            r3 = new uint64_t[total_size]();
            r4 = new uint64_t[total_size]();
        }
        ~SharedData() {
            delete[] c0_first; delete[] c1_second; delete[] csp1_recv_data;
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

        
        generateRandomArrayUint64_time(&shared.r2[0], half_size, seedC, 100);

        uint64_t* sbuf = new uint64_t[half_size];

        
        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            sbuf[i] = a_loc[i] * (x0_input[i] + shared.r2[i]) + b_loc[i] + r0_loc[i];
        }

        stats.t1_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();

        
        long bytes = half_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto send_start = std::chrono::high_resolution_clock::now();
        server_port12345->sendMsg(sbuf, bytes, 0);
        stats.t1_send = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - send_start).count();

        delete[] sbuf;
    });
    
    
    auto t2 = std::thread([&]() {
        wait_for_gun(); 

        
        generateRandomArrayUint64_time(&shared.r3[0], half_size, seedC + 1, 100);
        generateRandomArrayUint64_time(&shared.r4[0], half_size, seedC + 2, 100);

        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            shared.c0_first[i] = (v_loc[i] == 0)
                ? (shared.r4[i] - shared.r3[i] - r1_loc[i])
                : (shared.r3[i] - r1_loc[i] + shared.r4[i]);
        }

        stats.t2_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();
    });
    
    
    auto t3 = std::thread([&]() {
        wait_for_gun(); 

        long bytes = second_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto recv_start = std::chrono::high_resolution_clock::now();
        client_port12346->recvMsg(shared.csp1_recv_data, bytes, 0);
        stats.t3_recv = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recv_start).count();

        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_done = true;
        }
        shared.cv.notify_one();
    });
    
    
    auto t4 = std::thread([&]() {
        wait_for_gun(); 

        
        generateRandomArrayUint64_time(&shared.r2[half_size], second_size, seedC + 3, 100);
        generateRandomArrayUint64_time(&shared.r3[half_size], second_size, seedC + 4, 100);
        generateRandomArrayUint64_time(&shared.r4[half_size], second_size, seedC + 5, 100);

        uint64_t* x0r2 = new uint64_t[second_size];
        uint64_t* res1 = new uint64_t[second_size];

        
        auto prep_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            x0r2[i] = x0_input[half_size + i] - shared.r2[half_size + i];
        }

        ecall_odrelu_gen_shared_randomness_final_uint64(global_eid1, seedT_Part2, second_size, xi);
        stats.t4_prep = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - prep_start).count();

        
        auto ecall1_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step1_uint64(global_eid1, second_size, x0r2, res1);

        stats.t4_ecall1 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall1_start).count();

        
        auto wait_start = std::chrono::high_resolution_clock::now();
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.recv_done; });
        }
        stats.t4_wait = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - wait_start).count();

        
        auto recon_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            uint64_t s = shared.csp1_recv_data[i] + res1[i];
            x0r2[i] = ((s < L/2) ? 1 : 0) + shared.r3[half_size + i];
        }

        stats.t4_recon = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recon_start).count();

        
        auto ecall2_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step2_uint64(global_eid1, second_size, x0r2, res1);

        stats.t4_ecall2 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall2_start).count();

        
        for (int i = 0; i < second_size; i++) {
            shared.c1_second[i] = res1[i] - shared.r4[half_size + i];
        }

        delete[] x0r2; delete[] res1;
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

    
    for (int i = 0; i < half_size; i++) drelu_output[i] = shared.c0_first[i];
    for (int i = 0; i < second_size; i++) drelu_output[half_size + i] = shared.c1_second[i];

    
    delete[] a_loc; delete[] b_loc; delete[] r0_loc; delete[] r1_loc; delete[] v_loc;

    long t1_total = stats.t1_calc + stats.t1_send;
    long t4_total = stats.t4_prep + stats.t4_ecall1 + stats.t4_wait + stats.t4_recon + stats.t4_ecall2;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}


void ODReLU_CSP0_4Threads_64_v2_time(BSNet* server_port12345, BSNet* client_port12346,
                                 const uint64_t* x0_input, uint64_t* drelu_output,
                                 int vector_size) {
    struct PerfStats {
        long init_offline = 0;
        long t1_calc = 0;
        long t1_send = 0;
        long t2_calc = 0;
        long t3_recv = 0;
        long t4_prep = 0;
        long t4_ecall1 = 0;
        long t4_wait = 0;
        long t4_recon = 0;
        long t4_ecall2 = 0;
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

    uint64_t* a_loc = new uint64_t[half_size];
    uint64_t* b_loc = new uint64_t[half_size];
    uint64_t* r0_loc = new uint64_t[half_size];
    uint64_t* r1_loc = new uint64_t[half_size];
    uint64_t* v_loc = new uint64_t[half_size];

    auto init_start = std::chrono::high_resolution_clock::now();
    host_odrelu_gen_params_time(seedT, half_size, xi, a_loc, b_loc, r0_loc, r1_loc, v_loc);
    stats.init_offline = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - init_start).count();

    struct SharedData {
        uint64_t* c0_first = nullptr;
        uint64_t* c1_second = nullptr;
        uint64_t* csp1_recv_data = nullptr;
        uint64_t* r2 = nullptr;
        uint64_t* r3 = nullptr;
        uint64_t* r4 = nullptr;
        bool recv_done = false;
        std::mutex mtx;
        std::condition_variable cv;
        SharedData(int total_size, int part1_size, int part2_size) {
            c0_first = new uint64_t[part1_size]();
            c1_second = new uint64_t[part2_size]();
            csp1_recv_data = new uint64_t[part2_size]();
            r2 = new uint64_t[total_size]();
            r3 = new uint64_t[total_size]();
            r4 = new uint64_t[total_size]();
        }
        ~SharedData() {
            delete[] c0_first; delete[] c1_second; delete[] csp1_recv_data;
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
        generateRandomArrayUint64_time(&shared.r2[0], half_size, seedC, 100);
        uint64_t* sbuf = new uint64_t[half_size];

        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            sbuf[i] = a_loc[i] * (x0_input[i] + shared.r2[i]) + b_loc[i] + r0_loc[i];
        }
        stats.t1_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();

        long bytes = half_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto send_start = std::chrono::high_resolution_clock::now();
        server_port12345->sendMsg(sbuf, bytes, 0);
        stats.t1_send = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - send_start).count();
        delete[] sbuf;
    });

    auto t2 = std::thread([&]() {
        wait_for_gun();
        generateRandomArrayUint64_time(&shared.r3[0], half_size, seedC + 1, 100);
        generateRandomArrayUint64_time(&shared.r4[0], half_size, seedC + 2, 100);

        auto calc_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < half_size; i++) {
            shared.c0_first[i] = (v_loc[i] == 0)
                ? (shared.r4[i] - shared.r3[i] - r1_loc[i])
                : (shared.r3[i] - r1_loc[i] + shared.r4[i]);
        }
        stats.t2_calc = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - calc_start).count();
    });

    auto t3 = std::thread([&]() {
        wait_for_gun();
        long bytes = second_size * sizeof(uint64_t);
        stats.comm_bytes += bytes;
        auto recv_start = std::chrono::high_resolution_clock::now();
        client_port12346->recvMsg(shared.csp1_recv_data, bytes, 0);
        stats.t3_recv = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recv_start).count();
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
    });

    auto t4 = std::thread([&]() {
        wait_for_gun();
        generateRandomArrayUint64_time(&shared.r2[half_size], second_size, seedC + 3, 100);
        generateRandomArrayUint64_time(&shared.r3[half_size], second_size, seedC + 4, 100);
        generateRandomArrayUint64_time(&shared.r4[half_size], second_size, seedC + 5, 100);

        uint64_t* x0r2 = new uint64_t[second_size];
        uint64_t* res1 = new uint64_t[second_size];

        auto prep_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            x0r2[i] = x0_input[half_size + i] - shared.r2[half_size + i];
        }
        
        ecall_odrelu_gen_shared_randomness_final_uint64_v2(global_eid1, seedT_Part2, second_size, xi);
        stats.t4_prep = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - prep_start).count();

        auto ecall1_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step1_uint64_v2(global_eid1, second_size, x0r2, res1);
        stats.t4_ecall1 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall1_start).count();

        auto wait_start = std::chrono::high_resolution_clock::now();
        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.recv_done; }); }
        stats.t4_wait = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - wait_start).count();

        auto recon_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < second_size; i++) {
            uint64_t s = shared.csp1_recv_data[i] + res1[i];
            x0r2[i] = ((s < L/2) ? 1 : 0) + shared.r3[half_size + i];
        }
        stats.t4_recon = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - recon_start).count();

        auto ecall2_start = std::chrono::high_resolution_clock::now();
        ecall_odrelu_tee1_step2_uint64_v2(global_eid1, second_size, x0r2, res1);
        stats.t4_ecall2 = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - ecall2_start).count();

        for (int i = 0; i < second_size; i++) {
            shared.c1_second[i] = res1[i] - shared.r4[half_size + i];
        }
        delete[] x0r2; delete[] res1;
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

    for (int i = 0; i < half_size; i++) drelu_output[i] = shared.c0_first[i];
    for (int i = 0; i < second_size; i++) drelu_output[half_size + i] = shared.c1_second[i];

    delete[] a_loc; delete[] b_loc; delete[] r0_loc; delete[] r1_loc; delete[] v_loc;

    long t1_total = stats.t1_calc + stats.t1_send;
    long t4_total = stats.t4_prep + stats.t4_ecall1 + stats.t4_wait + stats.t4_recon + stats.t4_ecall2;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}

inline void vec_add(const uint64_t* a, const uint64_t* b, uint64_t* c, size_t n) {
    for(size_t i=0; i<n; i++) c[i] = a[i] + b[i];
}

inline void vec_sub(const uint64_t* a, const uint64_t* b, uint64_t* c, size_t n) {
    for(size_t i=0; i<n; i++) c[i] = a[i] - b[i];
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
void secure_matrix_multiply_batch_csp0_time(
    BSNet* server,
    const uint64_t* input_X, 
    const uint64_t* input_Y, 
    uint64_t* output_Z,      
    int m, int k, int n,
    int batch_count          
){
    auto now = []() { return std::chrono::high_resolution_clock::now(); };
    auto diff_us = [](auto start, auto end) { 
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count(); 
    };
    
    auto start_total = now();
    long t_rand = 0, t_send_prep = 0, t_send_net = 0, t_calc_cpu = 0;

    size_t len_one_X = (size_t)m * k;
    size_t len_one_Y = (size_t)k * n;
    size_t len_one_Z = (size_t)m * n;
    size_t total_X = len_one_X * batch_count;
    size_t total_Y = len_one_Y * batch_count;
    size_t total_Z = len_one_Z * batch_count;

    uint64_t seedT = 123456, seedC = 654321;

    
    auto t1 = now();
    std::vector<uint64_t> A(total_X), B(total_Y), R0(total_Z);
    std::vector<uint64_t> R1(total_X), R2(total_Y);
    
    generate_consistent_random_64_time(A.data(), total_X, seedT);
    generate_consistent_random_64_time(B.data(), total_Y, seedT + 1);
    generate_consistent_random_64_time(R0.data(), total_Z, seedT + 2);
    generate_consistent_random_64_time(R1.data(), total_X, seedC);
    generate_consistent_random_64_time(R2.data(), total_Y, seedC + 1);
    t_rand = diff_us(t1, now());

    
    std::thread t_send([&]() {
        size_t send_size = total_X + total_Y;
        std::vector<uint64_t> Send_Buffer(send_size);
        uint64_t* buf_X = Send_Buffer.data();
        uint64_t* buf_Y = Send_Buffer.data() + total_X;

        auto ts1 = now();
        bool enable_omp_vec = (total_X > 50000);
        #pragma omp parallel sections if(enable_omp_vec)
        {
            #pragma omp section
            {
                #pragma omp parallel for if(enable_omp_vec)
                for(size_t i=0; i<total_X; i++) buf_X[i] = input_X[i] + A[i];
            }
            #pragma omp section
            {
                #pragma omp parallel for if(enable_omp_vec)
                for(size_t i=0; i<total_Y; i++) buf_Y[i] = input_Y[i] + B[i];
            }
        }
        t_send_prep = diff_us(ts1, now());
        
        auto ts2 = now();
        server->sendMsg(Send_Buffer.data(), send_size * sizeof(uint64_t), 0);
        t_send_net = diff_us(ts2, now());
    });

    
    std::thread t_calc([&]() {
        auto tc1 = now();
        
        
        
        std::vector<uint64_t> T1(len_one_X); 
        std::vector<uint64_t> T2(len_one_Y); 
        std::vector<uint64_t> ResMat(len_one_Z);

        for (int i = 0; i < batch_count; i++) {
            size_t off_X = i * len_one_X;
            size_t off_Y = i * len_one_Y;
            size_t off_Z = i * len_one_Z;

            const uint64_t* p_input_X = input_X + off_X;
            const uint64_t* p_input_Y = input_Y + off_Y;
            const uint64_t* p_A  = A.data()  + off_X;
            const uint64_t* p_B  = B.data()  + off_Y;
            const uint64_t* p_R1 = R1.data() + off_X;
            const uint64_t* p_R2 = R2.data() + off_Y;
            const uint64_t* p_R0 = R0.data() + off_Z;
            uint64_t* p_Z = output_Z + off_Z;

            

            
            bool use_omp = (len_one_X > 50000);
            #pragma omp parallel for if(use_omp)
            for(size_t j=0; j<len_one_X; j++) T1[j] = p_R1[j] - p_input_X[j] - p_A[j];

            
            mat_mul_time(T1.data(), p_B, p_Z, m, k, n);

            
            use_omp = (len_one_Y > 50000);
            #pragma omp parallel for if(use_omp)
            for(size_t j=0; j<len_one_Y; j++) T2[j] = p_R2[j] - p_input_Y[j];

            
            mat_mul_time(p_A, T2.data(), ResMat.data(), m, k, n);

            
            use_omp = (len_one_Z > 50000);
            #pragma omp parallel for if(use_omp)
            for(size_t j=0; j<len_one_Z; j++) p_Z[j] = p_Z[j] + ResMat[j] - p_R0[j];
        }
        t_calc_cpu = diff_us(tc1, now());
    });

    t_send.join();
    t_calc.join();

    long t_total = diff_us(start_total, now());

    TIME_PRINTF("\n=== CSP0 Batch Timings [Count %d] ===\n", batch_count);
    TIME_PRINTF("1. Random Gen   : %ld us\n", t_rand);
    TIME_PRINTF("2. Thread Send  :\n");
    TIME_PRINTF("   |- Buffer Prep: %ld us\n", t_send_prep);
    TIME_PRINTF("   |- Network Send: %ld us\n", t_send_net);
    TIME_PRINTF("3. Thread Calc  :\n");
    TIME_PRINTF("   |- Matrix Comp : %ld us (Optimized: 2 Mults)\n", t_calc_cpu);
    TIME_PRINTF("=== Total Wall Time: %ld us ===\n\n", t_total);
}


#define OMP_THRESHOLD 10000

void secure_matrix_batch_dualport_csp0_time(
    BSNet* send_net, BSNet* recv_net,
    const uint64_t* batch_X, 
    const uint64_t* batch_Y, 
    uint64_t* batch_Z,       
    int count,               
    int m, int k, int n
) {
    struct MatrixStats {
        long t1_total = 0, t1_calc = 0, t1_send = 0;
        long t2_time = 0;
        long t3_time = 0;
        long t4_total = 0, t4_prep = 0, t4_ecall = 0, t4_wait = 0, t4_recon = 0;
        long init_offline = 0;
        long online_wall = 0;
        long waste_time = 0;
        long total_func = 0;
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
    std::vector<uint64_t> A_loc(count_p1 * sz_one_X);
    std::vector<uint64_t> B_loc(count_p1 * sz_one_Y);
        
    
    bool use_omp_rng = (count_p1 * (sz_one_X + sz_one_Y) > OMP_THRESHOLD);
    #pragma omp parallel sections if(use_omp_rng)
    {
        #pragma omp section 
        generate_consistent_random_64_time(A_loc.data(), A_loc.size(), seedT_p1);
        #pragma omp section
        generate_consistent_random_64_time(B_loc.data(), B_loc.size(), seedT_p1 + 1);
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

    

    
    std::thread t_send([&]() {
        wait_for_gun(); 
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        size_t total_elems = count_p1 * (sz_one_X + sz_one_Y);
        std::vector<uint64_t> buf(total_elems);
        uint64_t* ptr_X = buf.data();
        uint64_t* ptr_Y = buf.data() + (count_p1 * sz_one_X);

        
        bool use_omp_calc = (total_elems > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp_calc)
        for(size_t i=0; i<count_p1 * sz_one_X; i++) ptr_X[i] = batch_X[i] + A_loc[i];
        
        #pragma omp parallel for if(use_omp_calc)
        for(size_t i=0; i<count_p1 * sz_one_Y; i++) ptr_Y[i] = batch_Y[i] + B_loc[i];

        auto t_calc_end = std::chrono::high_resolution_clock::now();

        send_net->sendMsg(buf.data(), total_elems * 8, 0);
        
        auto t_send_end = std::chrono::high_resolution_clock::now();
        stats.t1_calc = diff_us(t_start, t_calc_end);
        stats.t1_send = diff_us(t_calc_end, t_send_end);
        stats.t1_total = stats.t1_calc + stats.t1_send;
    });

    
    std::thread t_local([&]() {
        wait_for_gun(); 
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> R1(count_p1 * sz_one_X);
        std::vector<uint64_t> R2(count_p1 * sz_one_Y);
        std::vector<uint64_t> A_loc(count_p1 * sz_one_X);
        std::vector<uint64_t> B_loc(count_p1 * sz_one_Y);
        std::vector<uint64_t> R0_loc(count_p1 * sz_one_Z);

        
        size_t total_rng = count_p1 * (2*sz_one_X + 2*sz_one_Y + sz_one_Z);
        #pragma omp parallel sections if(total_rng > OMP_THRESHOLD)
        {
            #pragma omp section 
            generate_consistent_random_64_time(R1.data(), R1.size(), seedC);
            #pragma omp section 
            generate_consistent_random_64_time(R2.data(), R2.size(), seedC + 1);
            #pragma omp section 
            generate_consistent_random_64_time(A_loc.data(), A_loc.size(), seedT_p1);
            #pragma omp section 
            generate_consistent_random_64_time(B_loc.data(), B_loc.size(), seedT_p1 + 1);
            #pragma omp section 
            generate_consistent_random_64_time(R0_loc.data(), R0_loc.size(), seedT_p1 + 2);
        }

        std::vector<uint64_t> T1(sz_one_X);
        std::vector<uint64_t> T2(sz_one_Y);
        std::vector<uint64_t> ResMat(sz_one_Z);

        
        
        
        for(int i=0; i<count_p1; i++) {
            size_t ix = i * sz_one_X; size_t iy = i * sz_one_Y; size_t iz = i * sz_one_Z;
            uint64_t* out = batch_Z + iz; 
            memset(out, 0, sz_one_Z * 8);

            
            bool use_omp_vec = (sz_one_X > OMP_THRESHOLD);
            #pragma omp parallel for if(use_omp_vec)
            for(size_t j=0; j<sz_one_X; j++) T1[j] = R1[ix+j] - batch_X[ix+j] - A_loc[ix+j];
            
            mat_mul_time(T1.data(), B_loc.data() + iy, out, m, k, n);

            use_omp_vec = (sz_one_Y > OMP_THRESHOLD);
            #pragma omp parallel for if(use_omp_vec)
            for(size_t j=0; j<sz_one_Y; j++) T2[j] = R2[iy+j] - batch_Y[iy+j];
            
            mat_mul_time(A_loc.data() + ix, T2.data(), ResMat.data(), m, k, n);

            use_omp_vec = (sz_one_Z > OMP_THRESHOLD);
            #pragma omp parallel for if(use_omp_vec)
            for(size_t j=0; j<sz_one_Z; j++) out[j] = out[j] + ResMat[j] - R0_loc[iz+j];
        }
        stats.t2_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_recv([&]() {
        wait_for_gun(); 
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        size_t total_recv = count_p2 * (sz_one_X + sz_one_Y);
        std::vector<uint64_t> buf(total_recv);
        
        recv_net->recvMsg(buf.data(), total_recv * 8, 0);
        
        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.recv_buf = std::move(buf);
            shared.done = true;
        }
        shared.cv.notify_one();
        
        stats.t3_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_tee([&]() {
        wait_for_gun(); 
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> R1_p2(count_p2 * sz_one_X);
        std::vector<uint64_t> R2_p2(count_p2 * sz_one_Y);
        uint64_t seedC_p2 = seedC + 1000; 

        
        size_t total_rng = count_p2 * (sz_one_X + sz_one_Y);
        #pragma omp parallel sections if(total_rng > OMP_THRESHOLD)
        {
            #pragma omp section
            generate_consistent_random_64_time(R1_p2.data(), R1_p2.size(), seedC_p2);
            #pragma omp section
            generate_consistent_random_64_time(R2_p2.data(), R2_p2.size(), seedC_p2 + 1);
            #pragma omp section
            {
                ecall_matrix_batch_init(global_eid1, seedT_p2, m, k, n, count_p2);
            }
        }

        const uint64_t* p_inX = batch_X + off_X2;
        const uint64_t* p_inY = batch_Y + off_Y2;
        std::vector<uint64_t> XR(count_p2 * sz_one_X);
        std::vector<uint64_t> YR(count_p2 * sz_one_Y);
        
        
        bool use_omp_vec = (count_p2 * sz_one_X > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp_vec)
        for(size_t i=0; i<XR.size(); i++) XR[i] = p_inX[i] + R1_p2[i];
        
        use_omp_vec = (count_p2 * sz_one_Y > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp_vec)
        for(size_t i=0; i<YR.size(); i++) YR[i] = p_inY[i] + R2_p2[i];
        
        auto t_prep_end = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> Tout(count_p2 * sz_one_Z);
        ecall_matrix_batch_compute(global_eid1, m, k, n, count_p2, 
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
        const uint64_t* ptr_recv_Y = recv_data.data() + (count_p2 * sz_one_X);
        uint64_t* p_outZ = batch_Z + off_Z2; 

        for(int i=0; i<count_p2; i++) {
            size_t ix = i * sz_one_X; size_t iy = i * sz_one_Y; size_t iz = i * sz_one_Z;
            std::vector<uint64_t> X_hat(sz_one_X), Y_hat(sz_one_Y), Z_main(sz_one_Z);

            bool use_omp_recon = (sz_one_X > OMP_THRESHOLD);
            vec_add(ptr_recv_X + ix, p_inX + ix, X_hat.data(), sz_one_X); 
            vec_add(ptr_recv_Y + iy, p_inY + iy, Y_hat.data(), sz_one_Y);
            
            mat_mul_time(X_hat.data(), Y_hat.data(), Z_main.data(), m, k, n);
            vec_add(Z_main.data(), Tout.data() + iz, p_outZ + iz, sz_one_Z);
        }
        auto t_recon_end = std::chrono::high_resolution_clock::now();

        stats.t4_prep = diff_us(t_start, t_prep_end);
        stats.t4_ecall = diff_us(t_prep_end, t_ecall_end);
        stats.t4_wait = diff_us(t_ecall_end, t_wait_end);
        stats.t4_recon = diff_us(t_wait_end, t_recon_end);
        stats.t4_total = diff_us(t_start, t_recon_end);
    });

    long create_cost = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    auto t_online_sync = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();

    t_send.join(); t_local.join(); t_recv.join(); t_tee.join();

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.waste_time = create_cost;
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Matrix Batch DualPort (Smart Parallel)\n");
    TIME_PRINTF("  Offline Init     : %ld us\n", stats.init_offline);
    TIME_PRINTF("  T1 (Send Helper) : %ld us (Calc: %ld, Send: %ld)\n", stats.t1_total, stats.t1_calc, stats.t1_send);
    TIME_PRINTF("  T2 (Local Helper): %ld us\n", stats.t2_time);
    TIME_PRINTF("  T3 (Recv Eval)   : %ld us\n", stats.t3_time);
    TIME_PRINTF("  T4 (TEE Eval)    : %ld us\n", stats.t4_total);
    TIME_PRINTF("      |-- Prep     : %ld us\n", stats.t4_prep);
    TIME_PRINTF("      |-- ECALL    : %ld us\n", stats.t4_ecall);
    TIME_PRINTF("      |-- Wait     : %ld us\n", stats.t4_wait);
    TIME_PRINTF("      |-- Recon    : %ld us\n", stats.t4_recon);
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

void secure_matrix_batch_base_csp0_time(
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
    std::vector<uint64_t> C0(count * sz_Z);
    std::vector<uint64_t> A0(count * sz_X), B0(count * sz_Y);

    std::thread t_prepare([&]() {
        ecall_tee0_master_compute(global_eid1, m, k, n, count, C0.data(), C0.size() * 8);
    });

    #pragma omp parallel for if(count > 2000)
    for(int i=0; i<count; i++) {
        generate_consistent_random_64_time(A0.data() + i*sz_X, sz_X, SEED_A0 + i);
        generate_consistent_random_64_time(B0.data() + i*sz_Y, sz_Y, SEED_B0 + i);
    }
    t_prepare.join(); 
    stats.setup_time = diff_us(t1, std::chrono::high_resolution_clock::now());

    
    std::vector<uint64_t> E0(count * sz_X), F0(count * sz_Y); 
    std::vector<uint64_t> E1(count * sz_X), F1(count * sz_Y);

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
        recv_net->recvMsg(E1.data(), E1.size()*8, 0);
        recv_net->recvMsg(F1.data(), F1.size()*8, 0);
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
                for(size_t i=0; i<E0.size(); i++) E0[i] = batch_X[i] + A0[i];
            }
            #pragma omp section
            {
                #pragma omp parallel for if(use_omp)
                for(size_t i=0; i<F0.size(); i++) F0[i] = batch_Y[i] + B0[i];
            }
        }
        auto t_calc_end = std::chrono::high_resolution_clock::now();
        send_net->sendMsg(E0.data(), E0.size()*8, 0);
        send_net->sendMsg(F0.data(), F0.size()*8, 0);
        stats.t_send_calc = diff_us(t_start, t_calc_end);
        stats.t_send_net = diff_us(t_calc_end, std::chrono::high_resolution_clock::now());
        stats.t_send_total = stats.t_send_calc + stats.t_send_net;
    });

    stats.waste_time = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    auto t_online_sync = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();
    t_recv.join(); t_send.join();

    
    auto t_recon_start = std::chrono::high_resolution_clock::now();
    
    #pragma omp parallel for if(count > 100)
    for(int i=0; i<count; i++) {
        size_t offX = i*sz_X, offY = i*sz_Y, offZ = i*sz_Z;
        
        std::vector<uint64_t> E(sz_X), F(sz_Y);
        vec_add(&E0[offX], &E1[offX], E.data(), sz_X);
        vec_add(&F0[offY], &F1[offY], F.data(), sz_Y);

        uint64_t* z_ptr = &batch_Z[offZ];

        
        std::vector<uint64_t> tmp_sub(sz_X);
        vec_sub(E.data(), &A0[offX], tmp_sub.data(), sz_X);

        
        
        mat_mul_time(tmp_sub.data(), F.data(), z_ptr, m, k, n); 

        
        std::vector<uint64_t> tmp_mul(sz_Z);
        
        mat_mul_time(E.data(), &B0[offY], tmp_mul.data(), m, k, n);

        
        vec_sub(z_ptr, tmp_mul.data(), z_ptr, sz_Z);
        vec_add(z_ptr, &C0[offZ], z_ptr, sz_Z);
    }
    stats.reconst_time = diff_us(t_recon_start, std::chrono::high_resolution_clock::now());
    
    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("\n=== CSP0 Base Batch [Count %d] ===\n", count);
    TIME_PRINTF("1. Setup (TEE+Rand): %ld us\n", stats.setup_time);
    TIME_PRINTF("2. Online Phase (Wall): %ld us\n", stats.online_wall);
    TIME_PRINTF("   |- T_Send Total : %ld us (Calc: %ld, Net: %ld)\n", stats.t_send_total, stats.t_send_calc, stats.t_send_net);
    TIME_PRINTF("   |- T_Recv Total : %ld us\n", stats.t_recv_time);
    TIME_PRINTF("   |- Reconstruct  : %ld us (Optimized: 2 MatMuls)\n", stats.reconst_time);
    TIME_PRINTF("3. Overhead (Start): %ld us\n", stats.waste_time);
    TIME_PRINTF("=== Total Func Time: %ld us ===\n\n", stats.total_func);
}
#include <chrono>
#include <cstdio>
#include <iostream>




void secure_relu_csp0_parallel_time(BSNet* server_net1, BSNet* server_net2, 
                               const uint64_t* input_shares, 
                               uint64_t* output_shares,
                               int vector_size) {
    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };

    uint64_t* drelu_shares = new uint64_t[vector_size];

    
    auto t1_start = std::chrono::high_resolution_clock::now();
    ODReLU_CSP0_2Threads_64_time(server_net1, input_shares, drelu_shares, vector_size);
    auto t1_end = std::chrono::high_resolution_clock::now();
    
    
    const uint64_t L = UINT64_MAX;
    const uint64_t s = 63;
    
    auto t2_start = std::chrono::high_resolution_clock::now();
    secure_multiply_batch_parallel_time(server_net2, true,
                                  input_shares, drelu_shares,
                                  output_shares, vector_size, s, L);
    auto t2_end = std::chrono::high_resolution_clock::now();
    
    delete[] drelu_shares;

    long drelu_time = diff_us(t1_start, t1_end);
    long mult_time  = diff_us(t2_start, t2_end);
    long total_time = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("[CSP0] ReLU Parallel (Size %d)\n", vector_size);
    TIME_PRINTF("  |- DReLU Step : %ld us\n", drelu_time);
    TIME_PRINTF("  |- Mult Step  : %ld us\n", mult_time);
    TIME_PRINTF("  Total Time    : %ld us\n", total_time);
    TIME_PRINTF("---------------------------------------------\n");
}

void secure_relu_csp0_dualport_time(BSNet* server_net1, BSNet* server_net2,
                               const uint64_t* input_shares, 
                               uint64_t* output_shares,
                               int vector_size) {
    auto func_start = std::chrono::high_resolution_clock::now();
    auto diff_us = [](auto s, auto e) { return std::chrono::duration_cast<std::chrono::microseconds>(e - s).count(); };

    uint64_t* drelu_shares = new uint64_t[vector_size];

    
    auto t1_start = std::chrono::high_resolution_clock::now();
    ODReLU_CSP0_4Threads_64_time(server_net1, server_net2, input_shares, drelu_shares, vector_size);
    auto t1_end = std::chrono::high_resolution_clock::now();
    
    
    const uint64_t L = UINT64_MAX;
    const uint64_t s = 63;
    
    auto t2_start = std::chrono::high_resolution_clock::now();
    
    secure_multiply_batch_dualport_time(server_net1, server_net2, true,
                                  input_shares, drelu_shares,
                                  output_shares, vector_size, s, L);
    auto t2_end = std::chrono::high_resolution_clock::now();
    


    long drelu_time = diff_us(t1_start, t1_end);
    long mult_time  = diff_us(t2_start, t2_end);
    long total_time = diff_us(func_start, std::chrono::high_resolution_clock::now());
    delete[] drelu_shares;
    TIME_PRINTF("[CSP0] ReLU DualPort (Size %d)\n", vector_size);
    TIME_PRINTF("  |- DReLU Step : %ld us\n", drelu_time);
    TIME_PRINTF("  |- Mult Step  : %ld us\n", mult_time);
    TIME_PRINTF("  Total Time    : %ld us\n", total_time);
    TIME_PRINTF("---------------------------------------------\n");
}


void secure_square_batch_parallel_csp0_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, 
    uint64_t* output, uint64_t count, uint64_t s, uint64_t L
) {
    struct PerfStats {
        long offline_time = 0;   
        long t1_calc_time = 0;   
        long t1_send_time = 0;   
        long t2_total_time = 0;  
        long create_time = 0;    
        long join_time = 0;      
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;     
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456789;
    uint64_t seedC = 987654321;

    
    auto t_offline_start = std::chrono::high_resolution_clock::now();

    
    uint64_t* a = new uint64_t[count];
    generate_consistent_random_64_time(a, count, seedT);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_offline_start).count();
    

    
    uint64_t* r0 = new uint64_t[count];
    uint64_t* r1 = new uint64_t[count];

    
    auto t_online_start = std::chrono::high_resolution_clock::now();
    auto t_create_start = std::chrono::high_resolution_clock::now();

    
    auto t1_net = std::thread([&]() {
        uint64_t* send_buffer = new uint64_t[count]; 
        
        
        auto t_calc_start = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < count; i++) {
            
            send_buffer[i] = input_x[i] + a[i];
        }
        stats.t1_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_calc_start).count();

        
        long bytes = count * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        auto t_send_start = std::chrono::high_resolution_clock::now();
        server->sendMsg(send_buffer, bytes, 0);
        stats.t1_send_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_send_start).count();

        delete[] send_buffer;
    });

    
    auto t2_comp = std::thread([&]() {
        auto t2_start = std::chrono::high_resolution_clock::now();
        
        
        
        generate_consistent_random_64_time(r0, count, seedT + 1); 
        generate_consistent_random_64_time(r1, count, seedC);
        
        
        
        for (uint64_t i = 0; i < count; i++) {
            uint64_t term1 = (2 * a[i]) * r1[i];
            uint64_t term2 = (a[i] * a[i]);
            uint64_t term3 = (2 * a[i]) * input_x[i];
            
            
            output[i] = term1 - term2 - term3 - r0[i];
        }
        
        stats.t2_total_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t2_start).count();
    });

    stats.create_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_create_start).count();

    
    auto t_join_start = std::chrono::high_resolution_clock::now();
    t1_net.join();
    t2_comp.join();
    stats.join_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_join_start).count();

    stats.online_wall = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_online_start).count();

    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - func_start).count(); 

    
    delete[] a; delete[] r0; delete[] r1;
    
    
    long a1_total = stats.offline_time + stats.t1_calc_time;
    long thread_waste = stats.create_time; 

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Square Optimized:\n");
    TIME_PRINTF("a1时间（Offline + Thread1 Mask计算）: %ld us (Offline: %ld us, Mask: %ld us)\n", 
           a1_total, stats.offline_time, stats.t1_calc_time);
    TIME_PRINTF("b1时间（发送时间）: %ld us\n", stats.t1_send_time);
    TIME_PRINTF("thread2计算时间: %ld us\n", stats.t2_total_time);
    TIME_PRINTF("创建线程浪费时间: %ld us\n", thread_waste);
    TIME_PRINTF("总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("发送多少byte: %ld bytes\n", stats.comm_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}
void secure_square_batch_dualport_time(BSNet* send_channel, BSNet* recv_channel, bool is_csp0, 
                                  const uint64_t* input_x, 
                                  uint64_t* output, 
                                  uint64_t count, 
                                  uint64_t s, uint64_t L) {
    if (!is_csp0) return; 

    
    struct PerfStats {
        long offline_time = 0; 
        
        
        long t1_total = 0;
        long t1_calc = 0;      
        long t1_send = 0;      
        
        
        long t2_time = 0;      
        
        
        long t3_time = 0;      
        
        
        long t4_total = 0;
        long t4_prep = 0;      
        long t4_wait = 0;      
        long t4_recon = 0;     
        
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
    
    
    uint64_t* a_p1 = new uint64_t[half_count];
    generate_consistent_random_64_time(a_p1, half_count, seedT);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_off_start).count();

    
    struct SharedData {
        uint64_t* res_local = nullptr; uint64_t* res_tee = nullptr;   
        uint64_t* recv_buf = nullptr;  
        bool recv_done = false; std::mutex mtx; std::condition_variable cv;
    } shared;

    shared.res_local = new uint64_t[half_count];
    shared.res_tee = new uint64_t[second_count];
    
    shared.recv_buf = new uint64_t[second_count]; 

    
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
        auto t1_start = std::chrono::high_resolution_clock::now();
        
        
        uint64_t* send_buf = new uint64_t[half_count];
        
        
        for (uint64_t i = 0; i < half_count; i++) {
            send_buf[i] = input_x[i] + a_p1[i];
        }
        auto t1_calc_end = std::chrono::high_resolution_clock::now();
        
        
        long bytes = half_count * sizeof(uint64_t);
        send_channel->sendMsg(send_buf, bytes, 0);
        auto t1_send_end = std::chrono::high_resolution_clock::now();

        stats.send_bytes = bytes;
        delete[] send_buf;

        stats.t1_calc = std::chrono::duration_cast<std::chrono::microseconds>(t1_calc_end - t1_start).count();
        stats.t1_send = std::chrono::duration_cast<std::chrono::microseconds>(t1_send_end - t1_calc_end).count();
        stats.t1_total = stats.t1_calc + stats.t1_send;
    });

    
    auto t2 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        uint64_t* r0_p1 = new uint64_t[half_count];
        uint64_t* r1_p1 = new uint64_t[half_count];

        
        generate_consistent_random_64_time(r0_p1, half_count, seedT + 1); 
        generate_consistent_random_64_time(r1_p1, half_count, seedC);     

        
        for (uint64_t i = 0; i < half_count; i++) {
            uint64_t term1 = (2 * a_p1[i]) * r1_p1[i];
            uint64_t term2 = a_p1[i] * a_p1[i];
            uint64_t term3 = (2 * a_p1[i]) * input_x[i];
            
            shared.res_local[i] = term1 - term2 - term3 - r0_p1[i];
        }
        delete[] r0_p1; delete[] r1_p1;
        stats.t2_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    
    auto t3 = std::thread([&]() {
        wait_for_gun(); 
        auto start = std::chrono::high_resolution_clock::now();

        
        long bytes = second_count * sizeof(uint64_t);
        recv_channel->recvMsg(shared.recv_buf, bytes, 0);
        stats.recv_bytes = bytes;

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_done = true; }
        shared.cv.notify_one();
        stats.t3_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    });

    
    auto t4 = std::thread([&]() {
        wait_for_gun(); 
        auto t4_start = std::chrono::high_resolution_clock::now();

        uint64_t* r1_p2 = new uint64_t[second_count];
        uint64_t* tee_input = new uint64_t[second_count];
        uint64_t* tee_res = new uint64_t[second_count];

        
        generate_consistent_random_64_time(r1_p2, second_count, seedC_p2); 
        
        
        ecall_square_gen_a_r0_64(global_eid1, seedT_p2, second_count);

        
        for (uint64_t i = 0; i < second_count; i++) {
            tee_input[i] = input_x[half_count + i] + r1_p2[i]; 
        }
        
        
        ecall_sq_tee1_computation_64(global_eid1, second_count, 0, tee_input, tee_res);
        auto t4_prep_end = std::chrono::high_resolution_clock::now();

        
        { 
            std::unique_lock<std::mutex> lock(shared.mtx); 
            shared.cv.wait(lock, [&]() { return shared.recv_done; }); 
        }
        auto t4_wait_end = std::chrono::high_resolution_clock::now();

        
        for (uint64_t i = 0; i < second_count; i++) {
            
            uint64_t x_plus_a = shared.recv_buf[i] + input_x[half_count + i];
            uint64_t sq_val = x_plus_a * x_plus_a;
            
            shared.res_tee[i] = sq_val + tee_res[i];
        }
        auto t4_recon_end = std::chrono::high_resolution_clock::now();
        
        delete[] r1_p2; delete[] tee_input; delete[] tee_res;

        stats.t4_prep = std::chrono::duration_cast<std::chrono::microseconds>(t4_prep_end - t4_start).count();
        stats.t4_wait = std::chrono::duration_cast<std::chrono::microseconds>(t4_wait_end - t4_prep_end).count();
        stats.t4_recon = std::chrono::duration_cast<std::chrono::microseconds>(t4_recon_end - t4_wait_end).count();
        stats.t4_total = stats.t4_prep + stats.t4_wait + stats.t4_recon;
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

    
    for (uint64_t i = 0; i < half_count; i++) output[i] = shared.res_local[i];
    for (uint64_t i = 0; i < second_count; i++) output[half_count + i] = shared.res_tee[i];
    
    stats.total_func = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - func_start).count();
    
    delete[] shared.res_local; delete[] shared.res_tee; delete[] shared.recv_buf;
    delete[] a_p1;

    
    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Square DualPort Breakdown:\n");
    TIME_PRINTF("  Offline Time         : %ld us\n", stats.offline_time);
    TIME_PRINTF("  t1 (Send P1)      : %ld us (Calc: %ld, Send: %ld)\n", 
            stats.t1_total, stats.t1_calc, stats.t1_send);
    TIME_PRINTF("  t2 (Local P1)     : %ld us\n", stats.t2_time);
    TIME_PRINTF("  t3 (Recv P2)      : %ld us\n", stats.t3_time);
    TIME_PRINTF("  t4 (TEE P2)       : %ld us (Prep: %ld, Wait: %ld, Recon: %ld)\n", 
            stats.t4_total, stats.t4_prep, stats.t4_wait, stats.t4_recon);
    TIME_PRINTF("  Sys Overhead         : %ld us\n", stats.waste_time);
    TIME_PRINTF("  Online Wall Time     : %ld us\n", stats.online_wall);
    TIME_PRINTF("  Total Function       : %ld us\n", stats.total_func); 
    TIME_PRINTF("---------------------------------------------\n\n");
}
#define OMP_THRESHOLD 10000

void secure_cube_opt_batch_parallel_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* batch_X, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    if (!is_csp0) return;

    struct PerfStats {
        long offline_time = 0;   
        long t1_calc_time = 0;   
        long t1_send_time = 0;   
        long t2_total_time = 0;  
        long create_time = 0;    
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;     
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456;
    uint64_t seedC = 654321;

    
    auto t_offline_start = std::chrono::high_resolution_clock::now();

    
    uint64_t* a = new uint64_t[count]; 
    generate_consistent_random_64_time(a, count, seedT);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_offline_start).count();

    
    uint64_t* r0 = new uint64_t[count]; 
    uint64_t* r1 = new uint64_t[count]; 
    uint64_t* r2 = new uint64_t[count]; 

    
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

        
        uint64_t* send_buf = new uint64_t[count];
        
        
        auto t_calc_start = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < count; i++) {
            send_buf[i] = batch_X[i] + a[i];
        }
        stats.t1_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_calc_start).count();

        
        long bytes = count * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        auto t_send_start = std::chrono::high_resolution_clock::now();
        
        server->sendMsg(send_buf, bytes, 0);
        
        stats.t1_send_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_send_start).count();

        delete[] send_buf;
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 

        auto t2_start = std::chrono::high_resolution_clock::now();
        
        
        
        generate_consistent_random_64_time(r0, count, seedT + 1); 
        generate_consistent_random_64_time(r1, count, seedC);     
        generate_consistent_random_64_time(r2, count, seedC + 1); 

        
        
        for (uint64_t i = 0; i < count; i++) {
            uint64_t a2 = a[i] * a[i];
            uint64_t a3 = a2 * a[i];
            
            
            uint64_t m1 = 2 * a3 + 3 * a[i] * r2[i];
            
            
            uint64_t m2 = 3 * a2 * (batch_X[i] - r1[i]);
            
            output[i] = m1 + m2 - r0[i];
        }
        
        stats.t2_total_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t2_start).count();
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

    delete[] a; delete[] r0; delete[] r1; delete[] r2;

    long a1_total = stats.offline_time + stats.t1_calc_time;
    long thread_waste = stats.create_time; 

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Cube Opt Protocol (1/3 Comm):\n");
    TIME_PRINTF("a1时间（Offline + Thread1 Mask计算）: %ld us (Offline: %ld us, Mask: %ld us)\n", 
           a1_total, stats.offline_time, stats.t1_calc_time);
    TIME_PRINTF("b1时间（发送时间）: %ld us\n", stats.t1_send_time);
    TIME_PRINTF("thread2计算时间: %ld us\n", stats.t2_total_time);
    TIME_PRINTF("创建线程浪费时间: %ld us\n", thread_waste);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("总时间: %ld us\n", stats.total_func);
    TIME_PRINTF("发送多少byte: %ld bytes\n", stats.comm_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}

void secure_cube_opt_batch_dualport_csp0_time(
    BSNet* send_net, BSNet* recv_net,bool is_csp0, 
    const uint64_t* input_x, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    
    struct CubeStats {
        long offline_time = 0;   
        
        
        long t1_send_total = 0;  
        long t2_local_time = 0;  
        
        
        long t3_recv_time = 0;   
        long t4_tee_total = 0;   
        long t4_prep = 0;        
        long t4_wait = 0;
        long t4_recon = 0;       
        
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

    std::vector<uint64_t> A_p1(count_p1);
    generate_consistent_random_64_time(A_p1.data(), count_p1, seedT_p1);

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

    
    
    std::thread t_send([&]() {
        wait_for_gun(); 
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> buf(count_p1);
        bool use_omp = (count_p1 > OMP_THRESHOLD);
        
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            buf[i] = input_x[i] + A_p1[i];
        }
        
        send_net->sendMsg(buf.data(), buf.size()*8, 0);
        stats.t1_send_total = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    
    std::thread t_local([&]() {
        wait_for_gun();
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> R0_p1(count_p1), R1_p1(count_p1), R2_p1(count_p1);

        generate_consistent_random_64_time(R0_p1.data(), count_p1, seedT_p1 + 1);
        generate_consistent_random_64_time(R1_p1.data(), count_p1, seedC);
        generate_consistent_random_64_time(R2_p1.data(), count_p1, seedC + 1);
        
        bool use_omp = (count_p1 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            uint64_t a = A_p1[i];
            uint64_t a2 = a * a;
            uint64_t a3 = a2 * a;
            
            uint64_t m1 = 2*a3 + 3*a*R2_p1[i];
            uint64_t m2 = 3*a2*(input_x[i] - R1_p1[i]);
            
            output[i] = m1 + m2 - R0_p1[i];
        }
        stats.t2_local_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_recv([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> buf(count_p2);
        recv_net->recvMsg(buf.data(), buf.size()*8, 0);

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_buf = std::move(buf); shared.done = true; }
        shared.cv.notify_one();
        
        stats.t3_recv_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    
    std::thread t_tee([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> R1_p2(count_p2), R2_p2(count_p2);

        
        generate_consistent_random_64_time(R1_p2.data(), count_p2, seedC_p2);
        generate_consistent_random_64_time(R2_p2.data(), count_p2, seedC_p2 + 1);
        ecall_cube_opt_gen_params_64(global_eid1, seedT_p2, count_p2);


        
        const uint64_t* p_in = input_x + off_p2;
        std::vector<uint64_t> X_r1(count_p2);
        
        bool use_omp = (count_p2 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            X_r1[i] = p_in[i] + R1_p2[i];
        }
        
        ecall_cube_opt_step1_m3_64(global_eid1, count_p2, X_r1.data());
        auto t_step1_end = std::chrono::high_resolution_clock::now();

        
        std::vector<uint64_t> recv_data;
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&](){ return shared.done; });
            recv_data = std::move(shared.recv_buf);
        }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        
        std::vector<uint64_t> V(count_p2);
        std::vector<uint64_t> tee_res(count_p2);

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            
            uint64_t E = recv_data[i] + p_in[i];
            
            
            V[i] = (E * E) + R2_p2[i];
            
            
            output[off_p2 + i] = E * E * E;
        }

        ecall_cube_opt_step2_final_64(global_eid1, count_p2, V.data(), tee_res.data());

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) output[off_p2 + i] += tee_res[i];

        auto t_step2_end = std::chrono::high_resolution_clock::now();

        stats.t4_prep = diff_us(t_start, t_step1_end);
        stats.t4_wait = diff_us(t_step1_end, t_wait_end);
        stats.t4_recon = diff_us(t_wait_end, t_step2_end);
        stats.t4_tee_total = diff_us(t_start, t_step2_end);
    });

    stats.waste_time = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    
    auto t_online_sync = std::chrono::high_resolution_clock::now();
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    t_send.join(); t_local.join(); t_recv.join(); t_tee.join();

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] Secure Cube Opt DualPort\n");
    TIME_PRINTF("1. Offline Setup   : %ld us (Only a)\n", stats.offline_time);
    TIME_PRINTF("2. Online Wall     : %ld us\n", stats.online_wall);
    TIME_PRINTF("   |- T1 (Send P1) : %ld us\n", stats.t1_send_total);
    TIME_PRINTF("   |- T2 (Locl P1) : %ld us (RNG+Calc)\n", stats.t2_local_time);
    TIME_PRINTF("   |- T3 (Recv P2) : %ld us\n", stats.t3_recv_time);
    TIME_PRINTF("   |- T4 (TEE P2)  : %ld us [Prep:%ld, Wait:%ld, Recon:%ld]\n",
           stats.t4_tee_total, stats.t4_prep, stats.t4_wait, stats.t4_recon);
    TIME_PRINTF("3. Start Overhead  : %ld us\n", stats.waste_time);
    TIME_PRINTF("=== Total Time     : %ld us ===\n\n", stats.total_func);
}


#define OMP_THRESHOLD 10000

void secure_xy2_opt_batch_parallel_csp0_time(
    BSNet* server, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    if (!is_csp0 || count == 0) return;

    struct PerfStats {
        long offline_time = 0;   
        long t1_calc_time = 0;   
        long t1_send_time = 0;   
        long t2_total_time = 0;  
        long create_time = 0;    
        long online_wall = 0;    
        long total_func = 0;     
        long comm_bytes = 0;     
    } stats;

    auto func_start = std::chrono::high_resolution_clock::now();
    uint64_t seedT = 123456; 
    uint64_t seedC = 654321; 

    
    auto t_offline_start = std::chrono::high_resolution_clock::now();

    
    uint64_t* a = new uint64_t[count]; 
    uint64_t* b = new uint64_t[count]; 
    generate_consistent_random_64_time(a, count, seedT);
    generate_consistent_random_64_time(b, count, seedT + 1);

    stats.offline_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - t_offline_start).count();

    
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

        
        uint64_t* send_buf = new uint64_t[count * 2];
        bool use_omp = (count > OMP_THRESHOLD);
        
        auto t_calc_start = std::chrono::high_resolution_clock::now();
        #pragma omp parallel for if(use_omp)
        for (uint64_t i = 0; i < count; i++) {
            send_buf[i] = input_x[i] + a[i];         
            send_buf[count + i] = input_y[i] + b[i]; 
        }
        stats.t1_calc_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_calc_start).count();

        
        long bytes = count * 2 * sizeof(uint64_t);
        stats.comm_bytes = bytes;
        auto t_send_start = std::chrono::high_resolution_clock::now();
        
        server->sendMsg(send_buf, bytes, 0);
        
        stats.t1_send_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t_send_start).count();

        delete[] send_buf;
    });

    
    auto t2_comp = std::thread([&]() {
        wait_for_gun(); 
        auto t2_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* r0 = new uint64_t[count];
        uint64_t* r1 = new uint64_t[count]; 
        uint64_t* r2 = new uint64_t[count]; 
        uint64_t* r3 = new uint64_t[count]; 
        uint64_t* r4 = new uint64_t[count]; 

        generate_consistent_random_64_time(r0, count, seedT + 2); 
        generate_consistent_random_64_time(r1, count, seedC);     
        generate_consistent_random_64_time(r2, count, seedC + 1); 
        generate_consistent_random_64_time(r3, count, seedC + 2); 
        generate_consistent_random_64_time(r4, count, seedC + 3); 

        bool use_omp = (count > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for (uint64_t i = 0; i < count; i++) {
            uint64_t ai = a[i], bi = b[i];
            uint64_t b2 = bi * bi;
            uint64_t ab2 = 2 * ai * bi; 
            
            uint64_t t1 = b2 * (input_x[i] - r1[i]);
            uint64_t t2 = ab2 * (input_y[i] - r2[i]);
            uint64_t t3 = 2 * bi * r3[i];
            uint64_t t4 = ai * r4[i];
            uint64_t const_term = 2 * ai * b2; 
            
            output[i] = t1 + t2 + t3 + t4 - r0[i] + const_term;
        }
        
        stats.t2_total_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - t2_start).count();

        delete[] r0; delete[] r1; delete[] r2; delete[] r3; delete[] r4;
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

    delete[] a; delete[] b;

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] XY^2 Single-Channel Protocol (Helper):\n");
    TIME_PRINTF("a1时间（Offline + Mask生成）: %ld us\n", stats.offline_time + stats.t1_calc_time);
    TIME_PRINTF("b1时间（发送时间）: %ld us\n", stats.t1_send_time);
    TIME_PRINTF("thread2 本地计算时间: %ld us\n", stats.t2_total_time);
    TIME_PRINTF("Online Wall Time: %ld us\n", stats.online_wall);
    TIME_PRINTF("发送流量: %ld bytes\n", stats.comm_bytes);
    TIME_PRINTF("---------------------------------------------\n\n");
}

void secure_xy2_opt_batch_dualport_csp0_time(
    BSNet* send_net, BSNet* recv_net, bool is_csp0, 
    const uint64_t* input_x, const uint64_t* input_y, 
    uint64_t* output, 
    uint64_t count, uint64_t s, uint64_t L
) {
    if (count == 0 || !is_csp0) return;

    struct XY2DualStats {
        long offline_time = 0;
        long t1_send_total = 0;
        long t2_local_time = 0;
        long t3_recv_time = 0;
        long t4_tee_total = 0;
        long t4_prep = 0;
        long t4_wait = 0;
        long t4_recon = 0;
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
    std::vector<uint64_t> A_p1(count_p1), B_p1(count_p1);
    generate_consistent_random_64_time(A_p1.data(), count_p1, seedT_p1);
    generate_consistent_random_64_time(B_p1.data(), count_p1, seedT_p1 + 1);
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

    
    std::thread t_send([&]() {
        wait_for_gun(); 
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint64_t> buf(count_p1 * 2); 
        bool use_omp = (count_p1 > OMP_THRESHOLD);
        
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            buf[i] = input_x[i] + A_p1[i];
            buf[count_p1 + i] = input_y[i] + B_p1[i];
        }
        stats.send_bytes = static_cast<long>(buf.size() * sizeof(uint64_t));
        send_net->sendMsg(buf.data(), buf.size()*8, 0);
        stats.t1_send_total = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_local([&]() {
        wait_for_gun();
        if (count_p1 == 0) return;
        auto t_start = std::chrono::high_resolution_clock::now();
        std::vector<uint64_t> R0(count_p1), R1(count_p1), R2(count_p1), R3(count_p1), R4(count_p1);

        generate_consistent_random_64_time(R0.data(), count_p1, seedT_p1 + 2);
        generate_consistent_random_64_time(R1.data(), count_p1, seedC);
        generate_consistent_random_64_time(R2.data(), count_p1, seedC + 1);
        generate_consistent_random_64_time(R3.data(), count_p1, seedC + 2);
        generate_consistent_random_64_time(R4.data(), count_p1, seedC + 3);

        bool use_omp = (count_p1 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p1; i++) {
            uint64_t a = A_p1[i], b = B_p1[i];
            uint64_t b2 = b * b;
            uint64_t ab2 = 2 * a * b; 
            
            uint64_t t1 = b2 * (input_x[i] - R1[i]);
            uint64_t t2 = ab2 * (input_y[i] - R2[i]);
            uint64_t t3 = 2 * b * R3[i];
            uint64_t t4 = a * R4[i];
            uint64_t const_term = 2 * a * b2; 
            
            output[i] = t1 + t2 + t3 + t4 - R0[i] + const_term;
        }
        stats.t2_local_time = diff_us(t_start, std::chrono::high_resolution_clock::now());
    });

    
    std::thread t_recv([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;
        std::vector<uint64_t> buf(count_p2 * 2);
        stats.recv_bytes = static_cast<long>(buf.size() * sizeof(uint64_t));
        auto recv_start = std::chrono::high_resolution_clock::now();
        recv_net->recvMsg(buf.data(), buf.size()*8, 0);
        stats.t3_recv_time = diff_us(recv_start, std::chrono::high_resolution_clock::now());

        { std::lock_guard<std::mutex> lock(shared.mtx); shared.recv_buf = std::move(buf); shared.done = true; }
        shared.cv.notify_one();
    });

    
    std::thread t_tee([&]() {
        wait_for_gun();
        if (count_p2 == 0) return;

        auto t_start = std::chrono::high_resolution_clock::now();
        std::vector<uint64_t> R1(count_p2), R2(count_p2), R3(count_p2), R4(count_p2);

        
        generate_consistent_random_64_time(R1.data(), count_p2, seedC_p2);
        generate_consistent_random_64_time(R2.data(), count_p2, seedC_p2 + 1);
        generate_consistent_random_64_time(R3.data(), count_p2, seedC_p2 + 2);
        generate_consistent_random_64_time(R4.data(), count_p2, seedC_p2 + 3);
        ecall_xy2_opt_gen_params_64(global_eid1, seedT_p2, count_p2);

        const uint64_t* px = input_x + off_p2;
        const uint64_t* py = input_y + off_p2;
        std::vector<uint64_t> X_r1(count_p2), Y_r2(count_p2);
        
        bool use_omp = (count_p2 > OMP_THRESHOLD);
        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            X_r1[i] = px[i] + R1[i];
            Y_r2[i] = py[i] + R2[i];
        }
        
        ecall_xy2_opt_step1_64(global_eid1, count_p2, X_r1.data(), Y_r2.data());
        auto t_prep_end = std::chrono::high_resolution_clock::now();

        
        std::vector<uint64_t> recv_data;
        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&](){ return shared.done; });
            recv_data = std::move(shared.recv_buf);
        }
        auto t_wait_end = std::chrono::high_resolution_clock::now();

        
        std::vector<uint64_t> V_xy(count_p2), V_yy(count_p2), tee_res(count_p2);
        uint64_t* p_ex0 = recv_data.data();
        uint64_t* p_ey0 = recv_data.data() + count_p2;

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) {
            uint64_t Ex = p_ex0[i] + px[i];
            uint64_t Ey = p_ey0[i] + py[i];
            
            V_xy[i] = (Ex * Ey) + R3[i];
            V_yy[i] = (Ey * Ey) + R4[i];
            output[off_p2 + i] = Ex * Ey * Ey; 
        }

        ecall_xy2_opt_step2_final_64(global_eid1, count_p2, V_xy.data(), V_yy.data(), tee_res.data());

        #pragma omp parallel for if(use_omp)
        for(int i=0; i<count_p2; i++) output[off_p2 + i] += tee_res[i];
        auto t_recon_end = std::chrono::high_resolution_clock::now();

        stats.t4_prep = diff_us(t_start, t_prep_end);
        stats.t4_wait = diff_us(t_prep_end, t_wait_end);
        stats.t4_recon = diff_us(t_wait_end, t_recon_end);
        stats.t4_tee_total = diff_us(t_start, t_recon_end);
    });

    stats.waste_time = diff_us(t_create_start, std::chrono::high_resolution_clock::now());

    
    auto t_online_sync = std::chrono::high_resolution_clock::now();
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    t_send.join(); t_local.join(); t_recv.join(); t_tee.join();

    stats.online_wall = diff_us(t_online_sync, std::chrono::high_resolution_clock::now());
    stats.total_func = diff_us(func_start, std::chrono::high_resolution_clock::now());

    TIME_PRINTF("---------------------------------------------\n");
    TIME_PRINTF("[CSP0] XY^2 DualPort Protocol:\n");
    TIME_PRINTF("1. Offline Setup   : %ld us (A,B)\n", stats.offline_time);
    TIME_PRINTF("2. Online Wall     : %ld us\n", stats.online_wall);
    TIME_PRINTF("   |- T1 (Send P1) : %ld us\n", stats.t1_send_total);
    TIME_PRINTF("   |- T2 (Locl P1) : %ld us (RNG+Calc)\n", stats.t2_local_time);
    TIME_PRINTF("   |- T3 (Recv P2) : %ld us\n", stats.t3_recv_time);
    TIME_PRINTF("   |- T4 (TEE P2)  : %ld us [Prep:%ld, Wait:%ld, Recon:%ld]\n",
           stats.t4_tee_total, stats.t4_prep, stats.t4_wait, stats.t4_recon);
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

static void calculate_hybrid_reciprocal_steep_csp0_time_local(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_recip_steep_time_coeffs(k1, k2, &current_a, &current_b);
    const int b_len = k2;
    const uint64_t s = 20;

    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 23456, scale, 100);

    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

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
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        ecall_calculate_reciprocal_steep_shares(
            global_eid1, size, k1, k2, scale, u0, v0, size * b_len, t2_share0, t3_share0
        );
        {
            std::unique_lock<std::mutex> lk(shared.mtx);
            shared.cv.wait(lk, [&] { return shared.done_net; });
        }

        const double inv_scale = 1.0 / static_cast<double>(scale);
        const double L_const = 8.0;
        #pragma omp parallel for
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t0[i]) + shared.recv_buf[i];
            double delta_d = static_cast<int64_t>(d1) * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle);
                double cv_v = cos(angle);
                double v0v = static_cast<int64_t>(v0[k * size + i]) * inv_scale;
                double u0v = static_cast<int64_t>(u0[k * size + i]) * inv_scale;
                trig_sum += static_cast<uint64_t>(static_cast<int64_t>(std::round((sv * v0v - cv_v * u0v) * scale)));
            }
            uint64_t poly_sum = current_a[0];
            if (k1 >= 1) poly_sum += secure_truncate_time_local(current_a[1] * (d1 - t0[i]), s);
            if (k1 >= 2) {
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                poly_sum += secure_truncate_time_local(
                    current_a[2] * (d2 - 2 * secure_truncate_time_local(d1 * t0[i], s) + t2_share0[i]), s
                );
            }
            if (k1 >= 3) {
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                uint64_t d3 = secure_truncate_time_local(d2 * d1, s);
                poly_sum += secure_truncate_time_local(
                    current_a[3] * (d3 - 3 * secure_truncate_time_local(d2 * t0[i], s)
                    + 3 * secure_truncate_time_local(d1 * t2_share0[i], s) - t3_share0[i]),
                    s
                );
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u0;
        delete[] v0;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input_x[i] + t0[i];
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

    delete[] t0;
    delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0;
    if (t3_share0) delete[] t3_share0;
}

static void calculate_hybrid_rsqrt_steep_csp0_time_local(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_invsqrt_steep_time_coeffs(k1, k2, &current_a, &current_b);
    const int b_len = k2;
    const uint64_t s = 20;

    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 23456, scale, 100);

    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

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
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        ecall_calculate_invsqrt_steep_shares(
            global_eid1, size, k1, k2, scale, u0, v0, size * b_len, t2_share0, t3_share0
        );
        {
            std::unique_lock<std::mutex> lk(shared.mtx);
            shared.cv.wait(lk, [&] { return shared.done_net; });
        }

        uint64_t* x2_share0_buf = (k1 >= 2) ? new uint64_t[size] : nullptr;
        uint64_t* x3_share0_buf = (k1 >= 3) ? new uint64_t[size] : nullptr;
        if (k1 >= 2) {
            for (int i = 0; i < size; i++) {
                uint64_t d1 = (input_x[i] + t0[i]) + shared.recv_buf[i];
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                x2_share0_buf[i] = d2 - 2 * secure_truncate_time_local(d1 * t0[i], s) + t2_share0[i];
            }
            net_send->sendMsg(x2_share0_buf, size * sizeof(uint64_t), 0);
        }
        if (k1 >= 3) {
            for (int i = 0; i < size; i++) {
                uint64_t d1 = (input_x[i] + t0[i]) + shared.recv_buf[i];
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                uint64_t d3 = secure_truncate_time_local(d2 * d1, s);
                x3_share0_buf[i] = d3 - 3 * secure_truncate_time_local(d2 * t0[i], s)
                    + 3 * secure_truncate_time_local(d1 * t2_share0[i], s) - t3_share0[i];
            }
            net_send->sendMsg(x3_share0_buf, size * sizeof(uint64_t), 0);
        }

        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        uint64_t* x2_share1_buf = (k1 >= 2) ? new uint64_t[size] : nullptr;
        uint64_t* x3_share1_buf = (k1 >= 3) ? new uint64_t[size] : nullptr;
        net_recv->recvMsg(u1, size * b_len * sizeof(uint64_t), 0);
        net_recv->recvMsg(v1, size * b_len * sizeof(uint64_t), 0);
        if (k1 >= 2) net_recv->recvMsg(x2_share1_buf, size * sizeof(uint64_t), 0);
        if (k1 >= 3) net_recv->recvMsg(x3_share1_buf, size * sizeof(uint64_t), 0);

        const double inv_scale = 1.0 / static_cast<double>(scale);
        const double L_const = 8.0;
        delete[] u1;
        delete[] v1;
        if (x2_share0_buf) delete[] x2_share0_buf;
        if (x3_share0_buf) delete[] x3_share0_buf;
        if (x2_share1_buf) delete[] x2_share1_buf;
        if (x3_share1_buf) delete[] x3_share1_buf;

        #pragma omp parallel for
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t0[i]) + shared.recv_buf[i];
            double delta_d = static_cast<int64_t>(d1) * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle);
                double cv_v = cos(angle);
                double v0v = static_cast<int64_t>(v0[k * size + i]) * inv_scale;
                double u0v = static_cast<int64_t>(u0[k * size + i]) * inv_scale;
                trig_sum += static_cast<uint64_t>(static_cast<int64_t>(std::round((sv * v0v - cv_v * u0v) * scale)));
            }
            uint64_t poly_sum = current_a[0];
            if (k1 >= 1) poly_sum += secure_truncate_time_local(current_a[1] * (d1 - t0[i]), s);
            if (k1 >= 2) {
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                poly_sum += secure_truncate_time_local(
                    current_a[2] * (d2 - 2 * secure_truncate_time_local(d1 * t0[i], s) + t2_share0[i]), s
                );
            }
            if (k1 >= 3) {
                uint64_t d2 = secure_truncate_time_local(d1 * d1, s);
                uint64_t d3 = secure_truncate_time_local(d2 * d1, s);
                poly_sum += secure_truncate_time_local(
                    current_a[3] * (d3 - 3 * secure_truncate_time_local(d2 * t0[i], s)
                    + 3 * secure_truncate_time_local(d1 * t2_share0[i], s) - t3_share0[i]),
                    s
                );
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u0;
        delete[] v0;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input_x[i] + t0[i];
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

    delete[] t0;
    delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0;
    if (t3_share0) delete[] t3_share0;
}

using CoreApproxFnCSP0 = void (*)(const CommPorts&, const uint64_t*, uint64_t*, int, int, int, uint64_t);

static void private_approx_bounded_plus_csp0_time_impl(
    const char* tag,
    CoreApproxFnCSP0 core_fn,
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD,
    bool negative_left_constant,
    int alpha_star
) {
    auto start_all = std::chrono::high_resolution_clock::now();
    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const uint64_t half_s = s / 2;
    const int64_t alpha_fp_signed = static_cast<int64_t>(alpha_star) * static_cast<int64_t>(scale);
    const uint64_t alpha_fp = static_cast<uint64_t>(alpha_fp_signed);

    uint64_t* core_share = new uint64_t[size];
    uint64_t* t1 = new uint64_t[size];
    uint64_t* t2 = new uint64_t[size];
    uint64_t* x_plus_alpha = new uint64_t[size];
    uint64_t* x_minus_alpha = new uint64_t[size];

    for (int i = 0; i < size; i++) {
        x_plus_alpha[i] = input_x[i] + alpha_fp;
        x_minus_alpha[i] = input_x[i] - alpha_fp;
    }

    auto r1_start = std::chrono::high_resolution_clock::now();

    std::thread th_core([&]() {
        core_fn(ports, input_x, core_share, size, k1, k2, UINT64_MAX);
    });
    std::thread th_cmp1([&]() {
        ODReLU_CSP0_4Threads_64_time(ports.aux_server, ports.aux_client, x_plus_alpha, t1, size);
    });
    std::thread th_cmp2([&]() {
        ODReLU_CSP0_4Threads_64_v2_time(ports.aux_server_1, ports.aux_client_1, x_minus_alpha, t2, size);
    });

    th_core.join();
    th_cmp1.join();
    th_cmp2.join();

    for (int i = 0; i < size; i++) {
        t1[i] *= scale;
        t2[i] *= scale;
    }

    auto r1_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - r1_start).count();

    auto r2_start = std::chrono::high_resolution_clock::now();

    uint64_t* t1_trunc = new uint64_t[size];
    uint64_t* one_minus_t2_trunc = new uint64_t[size];
    uint64_t* core_trunc = new uint64_t[size];
    uint64_t* mid_share = new uint64_t[size];

    for (int i = 0; i < size; i++) {
        t1_trunc[i] = secure_truncate_time_local(t1[i], half_s);
        one_minus_t2_trunc[i] = secure_truncate_time_local(scale - t2[i], half_s);
        core_trunc[i] = secure_truncate_time_local(core_share[i], half_s);
    }

    secure_triple_multiply_batch_dualport_time(
        ports.main_client, ports.main_server, true,
        t1_trunc, one_minus_t2_trunc, core_trunc, mid_share,
        static_cast<uint64_t>(size), s, UINT64_MAX
    );

    for (int i = 0; i < size; i++) {
        mid_share[i] = secure_truncate_time_local(mid_share[i], half_s);
    }

    for (int i = 0; i < size; i++) {
        uint64_t one_minus_t1 = scale - t1[i];
        uint64_t result = mid_share[i] + t2[i];
        if (negative_left_constant) {
            result += (uint64_t)0 - one_minus_t1;
        }
        output_y[i] = (MOD != 0) ? (result % MOD) : result;
    }

    auto r2_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - r2_start).count();
    auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start_all).count();

    TIME_PRINTF("  [Round 1] %s core + CMPx2 : %ld us\n", tag, r1_time);
    TIME_PRINTF("  [Round 2] %s 3SMP mux     : %ld us\n", tag, r2_time);
    TIME_PRINTF("  [Total]   %s+ total       : %ld us\n", tag, total_time);
    TIME_PRINTF("==========================================================\n\n");

    delete[] core_share;
    delete[] t1;
    delete[] t2;
    delete[] x_plus_alpha;
    delete[] x_minus_alpha;
    delete[] t1_trunc;
    delete[] one_minus_t2_trunc;
    delete[] core_trunc;
    delete[] mid_share;
}

} 

void private_approx_reciprocal_base_csp0_time(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();
    const uint64_t s = 20;
    const uint64_t half_s = s / 2;
    const uint64_t scale = 1ULL << s;

    uint64_t* y_curr = new uint64_t[size];
    uint64_t* xy2_share = new uint64_t[size];
    uint64_t* input_x_trunc = new uint64_t[size];
    uint64_t* y_curr_trunc = new uint64_t[size];

    auto r1_start = std::chrono::high_resolution_clock::now();
    calculate_hybrid_reciprocal_steep_csp0_time_local(
        ports.main_client, ports.main_server, input_x, y_curr, size, k1, k2, scale
    );
    auto r1_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - r1_start).count();

    for (int i = 0; i < size; i++) {
        input_x_trunc[i] = secure_truncate_time_local(input_x[i], half_s);
        y_curr_trunc[i] = secure_truncate_time_local(y_curr[i], half_s);
    }

    long iter_times[3] = {0, 0, 0};
    for (int iter = 0; iter < 3; iter++) {
        auto iter_start = std::chrono::high_resolution_clock::now();
        secure_xy2_opt_batch_dualport_csp0_time(
            ports.main_server, ports.main_client, true,
            input_x_trunc, y_curr_trunc, xy2_share,
            static_cast<uint64_t>(size), s, UINT64_MAX
        );
        for (int i = 0; i < size; i++) {
            xy2_share[i] = secure_truncate_time_local(xy2_share[i], half_s);
            y_curr[i] = (y_curr[i] + y_curr[i]) - xy2_share[i];
            if (iter != 2) {
                y_curr_trunc[i] = secure_truncate_time_local(y_curr[i], half_s);
            } else {
                output_y[i] = (MOD != 0) ? (y_curr[i] % MOD) : y_curr[i];
            }
        }
        iter_times[iter] = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - iter_start).count();
    }

    auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start_all).count();

    TIME_PRINTF("  [Round 1] Reciprocal base hybrid : %ld us\n", r1_time);
    TIME_PRINTF("  [Round 2] Newton iter #1 (xy2)   : %ld us\n", iter_times[0]);
    TIME_PRINTF("  [Round 3] Newton iter #2 (xy2)   : %ld us\n", iter_times[1]);
    TIME_PRINTF("  [Round 4] Newton iter #3 (xy2)   : %ld us\n", iter_times[2]);
    TIME_PRINTF("  [Total]   Reciprocal base total  : %ld us\n", total_time);
    TIME_PRINTF("==========================================================\n\n");

    delete[] y_curr;
    delete[] xy2_share;
    delete[] input_x_trunc;
    delete[] y_curr_trunc;
}

void private_approx_rsqrt_base_csp0_time(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();
    const uint64_t s = 20;
    const uint64_t half_s = s / 2;
    const uint64_t scale = 1ULL << s;

    const uint64_t C_0_5004 = static_cast<uint64_t>(0.500438180 * scale);
    const uint64_t C_1_5013 = static_cast<uint64_t>(1.50131454 * scale);
    const uint64_t C_0_9991 = static_cast<uint64_t>(0.999124984 * scale);
    const uint64_t C_1_5000 = static_cast<uint64_t>(1.5000086 * scale);
    const uint64_t C_combined = secure_truncate_time_local(C_0_9991 * C_0_5004, s);

    uint64_t* y_curr = new uint64_t[size];
    uint64_t* x0_share = new uint64_t[size];
    uint64_t* x0_prime_share = new uint64_t[size];
    uint64_t* y_curr_trunc = new uint64_t[size];
    uint64_t* y3_share = new uint64_t[size];
    uint64_t* cross_share = new uint64_t[size];

    auto r1_start = std::chrono::high_resolution_clock::now();
    calculate_hybrid_rsqrt_steep_csp0_time_local(
        ports.main_client, ports.main_server, input_x, y_curr, size, k1, k2, scale
    );
    auto r1_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - r1_start).count();

    for (int i = 0; i < size; i++) {
        x0_share[i] = multiply_public_fixed_share_time_local(C_0_5004, input_x[i], s);
        x0_prime_share[i] = multiply_public_fixed_share_time_local(C_combined, input_x[i], s);
    }

    long iter_times[2] = {0, 0};

    auto iter1_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < size; i++) {
        y_curr_trunc[i] = secure_truncate_time_local(y_curr[i], half_s);
    }
    secure_cube_opt_batch_dualport_csp0_time(
        ports.main_client, ports.main_server, true,
        y_curr_trunc, y3_share, static_cast<uint64_t>(size), s, UINT64_MAX
    );
    for (int i = 0; i < size; i++) {
        y3_share[i] = secure_truncate_time_local(y3_share[i], half_s);
    }
    secure_multiply_batch_dualport_time(
        ports.main_client, ports.main_server, true,
        x0_share, y3_share, cross_share, static_cast<uint64_t>(size), s, UINT64_MAX
    );
    for (int i = 0; i < size; i++) {
        cross_share[i] = secure_truncate_time_local(cross_share[i], s);
        y_curr[i] = multiply_public_fixed_share_time_local(C_1_5013, y_curr[i], s) - cross_share[i];
    }
    iter_times[0] = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - iter1_start).count();

    auto iter2_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < size; i++) {
        y_curr_trunc[i] = secure_truncate_time_local(y_curr[i], half_s);
    }
    secure_cube_opt_batch_dualport_csp0_time(
        ports.main_client, ports.main_server, true,
        y_curr_trunc, y3_share, static_cast<uint64_t>(size), s, UINT64_MAX
    );
    for (int i = 0; i < size; i++) {
        y3_share[i] = secure_truncate_time_local(y3_share[i], half_s);
    }
    secure_multiply_batch_dualport_time(
        ports.main_client, ports.main_server, true,
        x0_prime_share, y3_share, cross_share, static_cast<uint64_t>(size), s, UINT64_MAX
    );
    for (int i = 0; i < size; i++) {
        cross_share[i] = secure_truncate_time_local(cross_share[i], s);
        uint64_t final_y = multiply_public_fixed_share_time_local(C_1_5000, y_curr[i], s) - cross_share[i];
        output_y[i] = (MOD != 0) ? (final_y % MOD) : final_y;
    }
    iter_times[1] = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - iter2_start).count();

    auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start_all).count();

    TIME_PRINTF("  [Round 1] InvSqrt base hybrid : %ld us\n", r1_time);
    TIME_PRINTF("  [Round 2] Newton iter #1      : %ld us\n", iter_times[0]);
    TIME_PRINTF("  [Round 3] Newton iter #2      : %ld us\n", iter_times[1]);
    TIME_PRINTF("  [Total]   InvSqrt base total  : %ld us\n", total_time);
    TIME_PRINTF("==========================================================\n\n");

    delete[] y_curr;
    delete[] x0_share;
    delete[] x0_prime_share;
    delete[] y_curr_trunc;
    delete[] y3_share;
    delete[] cross_share;
}

void private_approx_sigmoid_plus_csp0_time(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
) {
    private_approx_bounded_plus_csp0_time_impl(
        "Sigmoid",
        private_approx_sigmoid_base_csp0,
        ports,
        input_x,
        output_y,
        size,
        k1,
        k2,
        MOD,
        false,
        8
    );
}

void private_approx_tanh_plus_csp0_time(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
) {
    private_approx_bounded_plus_csp0_time_impl(
        "Tanh",
        private_approx_tanh_base_csp0,
        ports,
        input_x,
        output_y,
        size,
        k1,
        k2,
        MOD,
        true,
        8
    );
}

void private_approx_erf_plus_csp0_time(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
) {
    private_approx_bounded_plus_csp0_time_impl(
        "Erf",
        private_approx_erf_base_csp0,
        ports,
        input_x,
        output_y,
        size,
        k1,
        k2,
        MOD,
        true,
        8
    );
}

void private_approx_exp_plus_csp0_time(
    const CommPorts& ports,
    const uint64_t* input_x,
    uint64_t* output_y,
    int size,
    int k1,
    int k2,
    uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();
    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const uint64_t half_s = s / 2;
    const int split_alpha = -8;
    const int64_t alpha_fp_signed = static_cast<int64_t>(split_alpha) * static_cast<int64_t>(scale);
    const uint64_t alpha_fp = static_cast<uint64_t>(alpha_fp_signed);

    uint64_t* exp_near = new uint64_t[size];
    uint64_t* exp_far = new uint64_t[size];
    uint64_t* t_cmp = new uint64_t[size];
    uint64_t* x_minus_alpha = new uint64_t[size];

    for (int i = 0; i < size; i++) {
        x_minus_alpha[i] = input_x[i] - alpha_fp;
    }

    CommPorts aux_ports = ports;
    aux_ports.main_server = ports.aux_server;
    aux_ports.main_client = ports.aux_client;

    auto r1_start = std::chrono::high_resolution_clock::now();

    std::thread th_near([&]() {
        private_approx_exp_g1_csp0(ports, input_x, exp_near, size, k1, k2, UINT64_MAX);
    });
    std::thread th_far([&]() {
        private_approx_exp_g2_csp0(aux_ports, input_x, exp_far, size, k1, k2, UINT64_MAX);
    });
    std::thread th_cmp([&]() {
        ODReLU_CSP0_4Threads_64_time(ports.aux_server_1, ports.aux_client_1, x_minus_alpha, t_cmp, size);
    });

    th_near.join();
    th_far.join();
    th_cmp.join();

    for (int i = 0; i < size; i++) {
        t_cmp[i] *= scale;
    }

    auto r1_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - r1_start).count();

    auto r2_start = std::chrono::high_resolution_clock::now();

    uint64_t* t_cmp_trunc = new uint64_t[size];
    uint64_t* diff_trunc = new uint64_t[size];
    uint64_t* mux_share = new uint64_t[size];

    for (int i = 0; i < size; i++) {
        t_cmp_trunc[i] = secure_truncate_time_local(t_cmp[i], half_s);
        diff_trunc[i] = secure_truncate_time_local(exp_near[i] - exp_far[i], half_s);
    }

    secure_multiply_batch_dualport_time(
        ports.main_client, ports.main_server, true,
        t_cmp_trunc, diff_trunc, mux_share,
        static_cast<uint64_t>(size), s, UINT64_MAX
    );

    for (int i = 0; i < size; i++) {
        uint64_t result = exp_far[i] + mux_share[i];
        output_y[i] = (MOD != 0) ? (result % MOD) : result;
    }

    auto r2_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - r2_start).count();
    auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start_all).count();

    TIME_PRINTF("  [Round 1] Exp core x2 + CMP  : %ld us\n", r1_time);
    TIME_PRINTF("  [Round 2] Exp piecewise mux  : %ld us\n", r2_time);
    TIME_PRINTF("  [Total]   Exp+ total         : %ld us\n", total_time);
    TIME_PRINTF("==========================================================\n\n");

    delete[] exp_near;
    delete[] exp_far;
    delete[] t_cmp;
    delete[] x_minus_alpha;
    delete[] t_cmp_trunc;
    delete[] diff_trunc;
    delete[] mux_share;
}
