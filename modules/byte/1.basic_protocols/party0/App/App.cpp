





#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <random>
#include <thread>
#include <vector>

#define MAX_PATH FILENAME_MAX

#include "App.h"
#include "Enclave_u.h"
#include "base_secure_protocols_time.h"
#include "calculate/basicSockets.h"
#include "define/define.h"
#include "sgx_urts.h"

static const uint64_t BASIC_BATCH_SIZE = 100000;
static const uint64_t BASIC_ACCURACY_SIZE = 10;
static const uint64_t RING_L = UINT64_MAX;

static const int64_t SMP_A_FIXED[10] = {-7, -3, -1, 0, 1, 2, 5, 9, 17, 31};
static const int64_t SMP_B_FIXED[10] = {6, -8, 11, 13, -5, 4, -2, 7, -3, 2};
static const uint64_t SMP_A0_FIXED[10] = {101, 202, 303, 404, 505, 606, 707, 808, 909, 1001};
static const uint64_t SMP_B0_FIXED[10] = {71, 82, 93, 104, 115, 126, 137, 148, 159, 170};

static const uint64_t TSMP_X_FIXED[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
static const uint64_t TSMP_Y_FIXED[10] = {3, 5, 7, 9, 11, 13, 15, 17, 19, 21};
static const uint64_t TSMP_W_FIXED[10] = {2, 4, 6, 8, 10, 12, 14, 16, 18, 20};
static const uint64_t TSMP_X0_FIXED[10] = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
static const uint64_t TSMP_Y0_FIXED[10] = {21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
static const uint64_t TSMP_W0_FIXED[10] = {31, 32, 33, 34, 35, 36, 37, 38, 39, 40};

static const int64_t RELU_X_FIXED[10] = {-15, -8, -1, 0, 1, 3, -5, 7, 12, -20};
static const uint64_t RELU_X0_FIXED[10] = {1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010};

sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid0 = 1;
sgx_enclave_id_t global_eid1 = 2;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char* msg;
    const char* sug;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.", NULL},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
};

void print_error_message(sgx_status_t ret) {
    for (size_t idx = 0; idx < sizeof(sgx_errlist) / sizeof(sgx_errlist[0]); idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (sgx_errlist[idx].sug) printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            return;
        }
    }
    printf("Error code is 0x%X.\n", ret);
}

int initialize_enclave(sgx_enclave_id_t eid) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    int updated = 0;

    const char* home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir && strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1 <= MAX_PATH) {
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    } else {
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE* fp = fopen(token_path, "rb");
    if (!fp) fp = fopen(token_path, "wb");
    if (fp) {
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            memset(&token, 0, sizeof(sgx_launch_token_t));
        }
    }

    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp) fclose(fp);
        return -1;
    }

    if (updated && fp) {
        fp = freopen(token_path, "wb", fp);
        if (fp) fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    }
    if (fp) fclose(fp);
    return 0;
}

void ocall_print_string(const char* str) {
    printf("%s", str);
}

static long long elapsed_us(std::chrono::high_resolution_clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::high_resolution_clock::now() - start)
        .count();
}

static void print_result(const char* name, uint64_t count, long long us, size_t errors) {
    printf("\n[%s] count=%llu time=%.3f ms", name, (unsigned long long)count, us / 1000.0);
    if (errors == 0) {
        printf(" accuracy=PASS\n");
    } else {
        printf(" accuracy=FAIL errors=%zu\n", errors);
    }
}

static void print_function_title(const char* title) {
    printf("\n**************************%s**********************\n\n", title);
}

static void print_performance_result(const char* title, const char* scheme_name, uint64_t count,
                                     long long us, size_t errors,
                                     const BSNetStatsSnapshot& stats) {
    print_function_title(title);
    printf("%s方案进行%llu次计算的耗时为：%.3f ms\n",
           scheme_name,
           (unsigned long long)count,
           us / 1000.0);
    printf("%s方案进行%llu次计算的发送通信量为：%llu bytes\n",
           scheme_name,
           (unsigned long long)count,
           stats.send_bytes);
    printf("%s方案进行%llu次计算的接收通信量为：%llu bytes\n",
           scheme_name,
           (unsigned long long)count,
           stats.recv_bytes);
    printf("%s方案进行%llu次计算的总通信量为：%llu bytes\n",
           scheme_name,
           (unsigned long long)count,
           stats.send_bytes + stats.recv_bytes);
    printf("%s方案进行%llu次计算的通信轮次计数为：%llu\n",
           scheme_name,
           (unsigned long long)count,
           std::max(stats.send_calls, stats.recv_calls));
    if (errors == 0) {
        printf("\n%s方案准确度检查：PASS\n", scheme_name);
    } else {
        printf("\n%s方案准确度检查：FAIL errors=%zu\n", scheme_name, errors);
    }
}

static void print_i64_array(const char* label, const int64_t* data, uint64_t count) {
    printf("%s\n", label);
    for (uint64_t i = 0; i < count; i++) {
        printf("%lld\t", (long long)data[i]);
    }
    printf("\n");
}

static void print_u64_array(const char* label, const uint64_t* data, uint64_t count) {
    printf("%s\n", label);
    for (uint64_t i = 0; i < count; i++) {
        printf("%llu\t", (unsigned long long)data[i]);
    }
    printf("\n");
}

static void print_u64_as_i64_array(const char* label, const uint64_t* data, uint64_t count) {
    printf("%s\n", label);
    for (uint64_t i = 0; i < count; i++) {
        printf("%lld\t", (long long)(int64_t)data[i]);
    }
    printf("\n");
}

static void print_binary_rows(const char* title, const char* output_label,
                              const int64_t* a, const int64_t* b,
                              const uint64_t* recon, const uint64_t* expected, uint64_t count) {
    print_function_title(title);
    print_i64_array("明文输入x为：", a, count);
    print_i64_array("明文输入y为：", b, count);
    print_u64_as_i64_array(output_label, recon, count);
    print_u64_as_i64_array("期望输出结果为：", expected, count);
}

static void print_triple_rows(const char* title, const char* output_label,
                              const uint64_t* x, const uint64_t* y,
                              const uint64_t* w, const uint64_t* recon,
                              const uint64_t* expected, uint64_t count) {
    print_function_title(title);
    print_u64_array("明文输入x为：", x, count);
    print_u64_array("明文输入y为：", y, count);
    print_u64_array("明文输入w为：", w, count);
    print_u64_array(output_label, recon, count);
    print_u64_array("期望输出结果为：", expected, count);
}

static void print_unary_rows(const char* title, const char* output_label, const int64_t* x,
                             const uint64_t* recon, const uint64_t* expected, uint64_t count) {
    print_function_title(title);
    print_i64_array("明文输入x为：", x, count);
    print_u64_as_i64_array(output_label, recon, count);
    print_u64_as_i64_array("期望输出结果为：", expected, count);
}

static void run_smp_base(BSNet* net, uint64_t count, bool verify) {
    std::mt19937_64 gen(123456);
    std::uniform_int_distribution<int64_t> val_dis(-10000, 10000);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> a0(count), b0(count), out0(count), expected(count);
    std::vector<uint64_t> a1(count), b1(count);
    for (uint64_t i = 0; i < count; i++) {
        uint64_t a = verify && count == BASIC_ACCURACY_SIZE ? (uint64_t)SMP_A_FIXED[i] : (uint64_t)val_dis(gen);
        uint64_t b = verify && count == BASIC_ACCURACY_SIZE ? (uint64_t)SMP_B_FIXED[i] : (uint64_t)val_dis(gen);
        a0[i] = verify && count == BASIC_ACCURACY_SIZE ? SMP_A0_FIXED[i] : share_dis(gen);
        b0[i] = verify && count == BASIC_ACCURACY_SIZE ? SMP_B0_FIXED[i] : share_dis(gen);
        a1[i] = a - a0[i];
        b1[i] = b - b0[i];
        expected[i] = a * b;
    }
    net->sendMsg(a1.data(), count * sizeof(uint64_t), 0);
    net->sendMsg(b1.data(), count * sizeof(uint64_t), 0);

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    secure_multiply_batch_base_time(net, true, a0.data(), b0.data(), out0.data(), count, 0, RING_L);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    net->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_binary_rows("多方数据求积功能测试（单通道）", "乘法方案输出结果为：",
                              SMP_A_FIXED, SMP_B_FIXED, recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("SMP base", count, us, errors);
    } else {
        print_performance_result("多方数据求积性能测试（单通道）", "乘法", count, us, errors, stats);
    }
}

static void run_smp_dualport(BSNet* send_net, BSNet* recv_net, uint64_t count, bool verify) {
    std::mt19937_64 gen(123456789);
    std::uniform_int_distribution<int64_t> val_dis(-10000, 10000);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> a0(count), b0(count), out0(count), expected(count);
    for (uint64_t i = 0; i < count; i++) {
        uint64_t a = verify && count == BASIC_ACCURACY_SIZE ? (uint64_t)SMP_A_FIXED[i] : (uint64_t)val_dis(gen);
        uint64_t b = verify && count == BASIC_ACCURACY_SIZE ? (uint64_t)SMP_B_FIXED[i] : (uint64_t)val_dis(gen);
        a0[i] = verify && count == BASIC_ACCURACY_SIZE ? SMP_A0_FIXED[i] : share_dis(gen);
        b0[i] = verify && count == BASIC_ACCURACY_SIZE ? SMP_B0_FIXED[i] : share_dis(gen);
        expected[i] = a * b;
    }

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    secure_multiply_batch_dualport_time(send_net, recv_net, true, a0.data(), b0.data(), out0.data(), count, 64, 0);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    recv_net->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_binary_rows("多方数据求积功能测试（双通道）", "乘法方案输出结果为：",
                              SMP_A_FIXED, SMP_B_FIXED, recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("SMP dualport", count, us, errors);
    } else {
        print_performance_result("多方数据求积性能测试（双通道）", "乘法", count, us, errors, stats);
    }
}

static void run_3smp_base(BSNet* net, uint64_t count, bool verify) {
    std::mt19937_64 gen(223344);
    std::uniform_int_distribution<uint64_t> val_dis(1, 100);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> x0(count), y0(count), w0(count), out0(count), expected(count);
    std::vector<uint64_t> x1(count), y1(count), w1(count);
    for (uint64_t i = 0; i < count; i++) {
        uint64_t x = verify && count == BASIC_ACCURACY_SIZE ? TSMP_X_FIXED[i] : val_dis(gen);
        uint64_t y = verify && count == BASIC_ACCURACY_SIZE ? TSMP_Y_FIXED[i] : val_dis(gen);
        uint64_t w = verify && count == BASIC_ACCURACY_SIZE ? TSMP_W_FIXED[i] : val_dis(gen);
        x0[i] = verify && count == BASIC_ACCURACY_SIZE ? TSMP_X0_FIXED[i] : share_dis(gen);
        y0[i] = verify && count == BASIC_ACCURACY_SIZE ? TSMP_Y0_FIXED[i] : share_dis(gen);
        w0[i] = verify && count == BASIC_ACCURACY_SIZE ? TSMP_W0_FIXED[i] : share_dis(gen);
        x1[i] = x - x0[i];
        y1[i] = y - y0[i];
        w1[i] = w - w0[i];
        expected[i] = (uint64_t)((unsigned __int128)x * y * w);
    }
    net->sendMsg(x1.data(), count * sizeof(uint64_t), 0);
    net->sendMsg(y1.data(), count * sizeof(uint64_t), 0);
    net->sendMsg(w1.data(), count * sizeof(uint64_t), 0);

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    secure_triple_multiply_batch_base_time(net, true, x0.data(), y0.data(), w0.data(), out0.data(), count, 0, RING_L);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    net->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_triple_rows("三方数据求积功能测试（单通道）", "三输入乘法方案输出结果为：",
                              TSMP_X_FIXED, TSMP_Y_FIXED, TSMP_W_FIXED,
                              recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("3SMP base", count, us, errors);
    } else {
        print_performance_result("多方三输入乘法性能测试（单通道）", "三输入乘法", count, us, errors, stats);
    }
}

static void run_3smp_dualport(BSNet* send_net, BSNet* recv_net, uint64_t count, bool verify) {
    std::mt19937_64 gen(888888);
    std::uniform_int_distribution<uint64_t> val_dis(1, 100);
    std::uniform_int_distribution<uint64_t> share_dis(1, 500);

    std::vector<uint64_t> x0(count), y0(count), w0(count), out0(count), expected(count);
    for (uint64_t i = 0; i < count; i++) {
        uint64_t x = verify && count == BASIC_ACCURACY_SIZE ? TSMP_X_FIXED[i] : val_dis(gen);
        uint64_t y = verify && count == BASIC_ACCURACY_SIZE ? TSMP_Y_FIXED[i] : val_dis(gen);
        uint64_t w = verify && count == BASIC_ACCURACY_SIZE ? TSMP_W_FIXED[i] : val_dis(gen);
        x0[i] = verify && count == BASIC_ACCURACY_SIZE ? TSMP_X0_FIXED[i] : share_dis(gen);
        y0[i] = verify && count == BASIC_ACCURACY_SIZE ? TSMP_Y0_FIXED[i] : share_dis(gen);
        w0[i] = verify && count == BASIC_ACCURACY_SIZE ? TSMP_W0_FIXED[i] : share_dis(gen);
        expected[i] = (uint64_t)((unsigned __int128)x * y * w);
    }

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    secure_triple_multiply_batch_dualport_time(send_net, recv_net, true, x0.data(), y0.data(), w0.data(), out0.data(), count, 64, 0);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    recv_net->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_triple_rows("三方数据求积功能测试（双通道）", "三输入乘法方案输出结果为：",
                              TSMP_X_FIXED, TSMP_Y_FIXED, TSMP_W_FIXED,
                              recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("3SMP dualport", count, us, errors);
    } else {
        print_performance_result("多方三输入乘法性能测试（双通道）", "三输入乘法", count, us, errors, stats);
    }
}

static void run_odrelu_base(BSNet* net, uint64_t count, bool verify) {
    std::mt19937_64 gen(777777);
    std::uniform_int_distribution<int64_t> val_dis(-10000, 10000);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> x0(count), x1(count), out0(count), expected(count);
    for (uint64_t i = 0; i < count; i++) {
        int64_t x = verify && count == BASIC_ACCURACY_SIZE ? RELU_X_FIXED[i] : val_dis(gen);
        x0[i] = verify && count == BASIC_ACCURACY_SIZE ? RELU_X0_FIXED[i] : share_dis(gen);
        x1[i] = (uint64_t)x - x0[i];
        expected[i] = x >= 0 ? 1 : 0;
    }
    net->sendMsg(x1.data(), count * sizeof(uint64_t), 0);

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    ODReLU_CSP0_2Threads_64_time(net, x0.data(), out0.data(), (int)count);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    net->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_unary_rows("ODReLU功能测试（单通道）", "ODReLU方案输出结果为：",
                             RELU_X_FIXED, recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("ODReLU base", count, us, errors);
    } else {
        print_performance_result("ODReLU性能测试（单通道）", "ODReLU", count, us, errors, stats);
    }
}

static void run_odrelu_dualport(BSNet* send_net, BSNet* recv_net, uint64_t count, bool verify) {
    std::mt19937_64 gen(999999);
    std::uniform_int_distribution<int64_t> val_dis(-1024 * 1024, 1024 * 1024);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> x0(count), out0(count), expected(count);
    for (uint64_t i = 0; i < count; i++) {
        int64_t x = verify && count == BASIC_ACCURACY_SIZE ? RELU_X_FIXED[i] : val_dis(gen);
        x0[i] = verify && count == BASIC_ACCURACY_SIZE ? RELU_X0_FIXED[i] : share_dis(gen);
        expected[i] = x >= 0 ? 1 : 0;
    }

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    ODReLU_CSP0_4Threads_64_time(send_net, recv_net, x0.data(), out0.data(), (int)count);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    send_net->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_unary_rows("ODReLU功能测试（双通道）", "ODReLU方案输出结果为：",
                             RELU_X_FIXED, recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("ODReLU dualport", count, us, errors);
    } else {
        print_performance_result("ODReLU性能测试（双通道）", "ODReLU", count, us, errors, stats);
    }
}

static void run_relu_base(BSNet* net1, BSNet* net2, uint64_t count, bool verify) {
    std::mt19937_64 gen(888888);
    std::uniform_int_distribution<int64_t> val_dis(-10000, 10000);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> x0(count), x1(count), out0(count), expected(count);
    for (uint64_t i = 0; i < count; i++) {
        int64_t x = verify && count == BASIC_ACCURACY_SIZE ? RELU_X_FIXED[i] : val_dis(gen);
        x0[i] = verify && count == BASIC_ACCURACY_SIZE ? RELU_X0_FIXED[i] : share_dis(gen);
        x1[i] = (uint64_t)x - x0[i];
        expected[i] = (uint64_t)(x >= 0 ? x : 0);
    }
    net1->sendMsg(x1.data(), count * sizeof(uint64_t), 0);

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    secure_relu_csp0_base_time(net1, net2, x0.data(), out0.data(), (int)count);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    net1->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_unary_rows("ReLU功能测试（单通道）", "ReLU方案输出结果为：",
                             RELU_X_FIXED, recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("ReLU base", count, us, errors);
    } else {
        print_performance_result("ReLU性能测试（单通道）", "ReLU", count, us, errors, stats);
    }
}

static void run_relu_dualport(BSNet* net1, BSNet* net2, uint64_t count, bool verify) {
    std::mt19937_64 gen(888888);
    std::uniform_int_distribution<int64_t> val_dis(-10000, 10000);
    std::uniform_int_distribution<uint64_t> share_dis(0, UINT64_MAX);

    std::vector<uint64_t> x0(count), out0(count), expected(count);
    for (uint64_t i = 0; i < count; i++) {
        int64_t x = verify && count == BASIC_ACCURACY_SIZE ? RELU_X_FIXED[i] : val_dis(gen);
        x0[i] = verify && count == BASIC_ACCURACY_SIZE ? RELU_X0_FIXED[i] : share_dis(gen);
        expected[i] = (uint64_t)(x >= 0 ? x : 0);
    }

    reset_bsnet_stats();
    auto start = std::chrono::high_resolution_clock::now();
    secure_relu_csp0_dualport_time(net1, net2, x0.data(), out0.data(), (int)count);
    long long us = elapsed_us(start);
    BSNetStatsSnapshot stats = get_bsnet_stats();

    std::vector<uint64_t> out1(count);
    net1->recvMsg(out1.data(), count * sizeof(uint64_t), 0);
    size_t errors = 0;
    if (verify) {
        std::vector<uint64_t> recon(count);
        for (uint64_t i = 0; i < count; i++) {
            recon[i] = out0[i] + out1[i];
            errors += recon[i] != expected[i];
        }
        if (count == BASIC_ACCURACY_SIZE) {
            print_unary_rows("ReLU功能测试（双通道）", "ReLU方案输出结果为：",
                             RELU_X_FIXED, recon.data(), expected.data(), count);
        }
    }
    if (count == BASIC_ACCURACY_SIZE) {
        print_result("ReLU dualport", count, us, errors);
    } else {
        print_performance_result("ReLU性能测试（双通道）", "ReLU", count, us, errors, stats);
    }
}

int main() {
    if (initialize_enclave(global_eid1) < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    printf("Starting CSP0 basic protocol tests...\n");
    BSNet* main_server = new BSNet((unsigned int)12345);
    BSNet* main_client = new BSNet((char*)"127.0.0.1", 12346);
    BSNet* aux_server = new BSNet((unsigned int)12347);
    BSNet* aux_client = new BSNet((char*)"127.0.0.1", 12348);
    BSNet* tri_server = new BSNet((unsigned int)12349);
    BSNet* tri_client = new BSNet((char*)"127.0.0.1", 12350);
    BSNet* dbg_server = new BSNet((unsigned int)12351);
    BSNet* dbg_client = new BSNet((char*)"127.0.0.1", 12352);

    main_server->listenNow();
    aux_server->listenNow();
    tri_server->listenNow();
    dbg_server->listenNow();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    main_client->connectNow();
    aux_client->connectNow();
    tri_client->connectNow();
    dbg_client->connectNow();

#ifdef SMP_FUNCTION_TEST
    run_smp_base(aux_server, BASIC_ACCURACY_SIZE, true);
    run_smp_dualport(aux_server, aux_client, BASIC_ACCURACY_SIZE, true);
#endif
#ifdef SMP_PERFORMANCE_TEST
    run_smp_base(aux_server, BASIC_BATCH_SIZE, true);
    run_smp_dualport(aux_server, aux_client, BASIC_BATCH_SIZE, true);
#endif

#ifdef THREE_SMP_FUNCTION_TEST
    run_3smp_base(aux_server, BASIC_ACCURACY_SIZE, true);
    run_3smp_dualport(aux_server, aux_client, BASIC_ACCURACY_SIZE, true);
#endif
#ifdef THREE_SMP_PERFORMANCE_TEST
    run_3smp_base(aux_server, BASIC_BATCH_SIZE, true);
    run_3smp_dualport(aux_server, aux_client, BASIC_BATCH_SIZE, true);
#endif

#ifdef ODRELU_FUNCTION_TEST
    run_odrelu_base(aux_server, BASIC_ACCURACY_SIZE, true);
    run_odrelu_dualport(aux_server, aux_client, BASIC_ACCURACY_SIZE, true);
#endif
#ifdef ODRELU_PERFORMANCE_TEST
    run_odrelu_base(aux_server, BASIC_BATCH_SIZE, true);
    run_odrelu_dualport(aux_server, aux_client, BASIC_BATCH_SIZE, true);
#endif

#ifdef RELU_FUNCTION_TEST
    run_relu_base(aux_server, aux_client, BASIC_ACCURACY_SIZE, true);
    run_relu_dualport(aux_server, aux_client, BASIC_ACCURACY_SIZE, true);
#endif
#ifdef RELU_PERFORMANCE_TEST
    run_relu_base(aux_server, aux_client, BASIC_BATCH_SIZE, true);
    run_relu_dualport(aux_server, aux_client, BASIC_BATCH_SIZE, true);
#endif

    sgx_destroy_enclave(global_eid1);
    delete main_server;
    delete main_client;
    delete aux_server;
    delete aux_client;
    delete tri_server;
    delete tri_client;
    delete dbg_server;
    delete dbg_client;
    printf("CSP0 basic protocol tests complete.\n");
    return 0;
}
