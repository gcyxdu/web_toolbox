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
void secure_multiply_batch_base_time(
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

}
void secure_triple_multiply_batch_base_time(
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
void secure_relu_csp0_base_time(BSNet* server_net1, BSNet* server_net2, 
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
    secure_multiply_batch_base_time(server_net2, true,
                                  input_shares, drelu_shares,
                                  output_shares, vector_size, s, L);
    auto t2_end = std::chrono::high_resolution_clock::now();
    
    delete[] drelu_shares;

    long drelu_time = diff_us(t1_start, t1_end);
    long mult_time  = diff_us(t2_start, t2_end);
    long total_time = diff_us(func_start, std::chrono::high_resolution_clock::now());

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
}
