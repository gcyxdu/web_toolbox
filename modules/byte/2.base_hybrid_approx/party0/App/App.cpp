





#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <random>
#include <string>
#include <thread>
#include <vector>

#define MAX_PATH FILENAME_MAX

#include "App.h"
#include "Enclave_u.h"
#include "calculate/basicSockets.h"
#include "define/define.h"
#include "epo_snn_64.h"
#include "sgx_urts.h"

sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid0 = 1;
sgx_enclave_id_t global_eid1 = 2;

struct SgxErrList {
    sgx_status_t err;
    const char* msg;
    const char* sug;
};

static SgxErrList sgx_errlist[] = {
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

using UnaryApproxCsp0Fn = void (*)(
    const CommPorts&,
    const uint64_t*,
    uint64_t*,
    int,
    int,
    int,
    uint64_t);

struct TestConfig {
    int k1;
    int k2;
    const char* desc;
};

struct BaseTestSpec {
    const char* title;
    const char* flag_name;
    UnaryApproxCsp0Fn fn;
    double (*expected_fn)(double);
    double lo;
    double hi;
    int size;
    std::vector<TestConfig> configs;
};

static double expected_sigmoid(double x) { return 1.0 / (1.0 + std::exp(-x)); }
static double expected_tanh(double x) { return std::tanh(x); }
static double expected_erf(double x) { return std::erf(x); }
static double expected_exp(double x) { return std::exp(x); }
static double expected_inv(double x) { return 1.0 / x; }
static double expected_invsqrt(double x) { return 1.0 / std::sqrt(x); }

static void print_comm_result(const char* scheme_name, int count, const BSNetStatsSnapshot& stats) {
    unsigned long long rounds = std::max(stats.send_calls, stats.recv_calls);
    printf("%s方案进行%d次计算的发送通信量为：%llu bytes\n",
           scheme_name, count, stats.send_bytes);
    printf("%s方案进行%d次计算的接收通信量为：%llu bytes\n",
           scheme_name, count, stats.recv_bytes);
    printf("%s方案进行%d次计算的总通信量为：%llu bytes\n",
           scheme_name, count, stats.send_bytes + stats.recv_bytes);
    printf("%s方案进行%d次计算的通信轮次计数为：%llu\n",
           scheme_name, count, rounds);
}

static CommPorts make_ports(BSNet* main_server, BSNet* main_client,
                            BSNet* aux_server, BSNet* aux_client,
                            BSNet* aux_server_1, BSNet* aux_client_1,
                            BSNet* aux_server_2, BSNet* aux_client_2) {
    CommPorts ports;
    ports.main_server = main_server;
    ports.main_client = main_client;
    ports.aux_server = aux_server;
    ports.aux_client = aux_client;
    ports.aux_server_1 = aux_server_1;
    ports.aux_client_1 = aux_client_1;
    ports.aux_server_2 = aux_server_2;
    ports.aux_client_2 = aux_client_2;
    return ports;
}

static void run_base_test_csp0(const BaseTestSpec& spec, const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP0 %s base 动态精度测试 ===\n", spec.title);
    printf("==========================================================\n");
    printf("输入拟合范围: [%.3f, %.3f]\n", spec.lo, spec.hi);

    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const uint64_t MOD = 0;
    const double scale_inv = 1.0 / (double)scale;

    printf("[Init] 生成 %d 个固定样本...\n", spec.size);
    std::mt19937_64 value_gen(12345);
    std::mt19937_64 share_gen(67890);
    std::uniform_real_distribution<double> dis(spec.lo, spec.hi);

    std::vector<double> original_real(spec.size);
    std::vector<uint64_t> input_share_0(spec.size);
    std::vector<uint64_t> input_share_1(spec.size);
    for (int i = 0; i < spec.size; i++) {
        original_real[i] = dis(value_gen);
        int64_t fixed_val = static_cast<int64_t>(original_real[i] * scale);
        input_share_0[i] = share_gen();
        input_share_1[i] = (uint64_t)fixed_val - input_share_0[i];
    }

    printf("[Init] 发送输入分片给 CSP1...\n");
    if (!ports.main_server->sendMsg(input_share_1.data(), spec.size * sizeof(uint64_t), 0)) {
        printf("发送分片失败\n");
        return;
    }

    std::vector<uint64_t> output_share_0(spec.size);
    std::vector<uint64_t> output_share_1(spec.size);
    BSNetStatsSnapshot first_stats = {0, 0, 0, 0};
    bool have_stats = false;

    for (const TestConfig& cfg : spec.configs) {
        printf("\n------------------------------------------------\n");
        printf("Testing Config: K1=%d, K2=%d [%s]\n", cfg.k1, cfg.k2, cfg.desc);

        reset_bsnet_stats();
        auto start_time = std::chrono::high_resolution_clock::now();
        spec.fn(ports, input_share_0.data(), output_share_0.data(), spec.size, cfg.k1, cfg.k2, MOD);
        auto end_time = std::chrono::high_resolution_clock::now();
        BSNetStatsSnapshot stats = get_bsnet_stats();

        if (!ports.main_server->recvMsg(output_share_1.data(), spec.size * sizeof(uint64_t), 0)) {
            printf("接收结果失败\n");
            return;
        }
        if (!have_stats) {
            first_stats = stats;
            have_stats = true;
        }

        double total_error = 0.0;
        double max_error = 0.0;
        for (int i = 0; i < spec.size; i++) {
            uint64_t sum_fixed = output_share_0[i] + output_share_1[i];
            double output_real = (int64_t)sum_fixed * scale_inv;
            double expected = spec.expected_fn(original_real[i]);
            double err = std::fabs(output_real - expected);
            total_error += err;
            if (err > max_error) max_error = err;
        }

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        printf("  耗时: %.2f ms\n", duration.count() / 1000.0);
        printf("  平均误差: %.8f | 最大误差: %.8f\n", total_error / spec.size, max_error);
    }

    if (have_stats) {
        printf("\n");
        print_comm_result(spec.title, spec.size, first_stats);
    }
}

static std::vector<BaseTestSpec> make_base_specs() {
    return {
        {"Sigmoid", "sigmoid", private_approx_sigmoid_base_csp0, expected_sigmoid, -8.0, 8.0, 10000,
         {{1, 12, "线性+12项三角"}, {3, 12, "三次+12项三角"}}},
        {"Tanh", "tanh", private_approx_tanh_base_csp0, expected_tanh, -8.0, 8.0, 10000,
         {{1, 12, "线性+12项三角"}, {3, 12, "三次+12项三角"}}},
        {"ERF", "erf", private_approx_erf_base_csp0, expected_erf, -5.0, 5.0, 10000,
         {{1, 12, "线性+12项三角"}, {3, 12, "三次+12项三角"}}},
        {"Exp", "exp", private_approx_exp_base_csp0, expected_exp, -18.0, -2.0, 10000,
         {{1, 12, "线性+12项三角"}, {2, 12, "二次+12项三角"}, {3, 12, "三次+12项三角"}}},
        {"Inv", "inv", private_approx_inv_base_csp0, expected_inv, 0.125, 8.0, 10000,
         {{1, 12, "线性+12项三角"}, {2, 12, "二次+12项三角"}, {3, 12, "三次+12项三角"}}},
        {"InvSqrt", "invsqrt", private_approx_invsqrt_base_csp0, expected_invsqrt, 0.125, 8.0, 10000,
         {{1, 12, "线性+12项三角"}, {2, 12, "二次+12项三角"}, {3, 12, "三次+12项三角"}}},
    };
}

static void run_named_base_test_csp0(const char* flag_name, const CommPorts& ports) {
    std::vector<BaseTestSpec> specs = make_base_specs();
    for (const BaseTestSpec& spec : specs) {
        if (strcmp(spec.flag_name, flag_name) == 0) {
            run_base_test_csp0(spec, ports);
            return;
        }
    }
}

int main() {
    if (initialize_enclave(global_eid1) < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    printf("Starting CSP0 base hybrid approximation tests...\n");
    BSNet* main_server = new BSNet((unsigned int)12345);
    BSNet* main_client = new BSNet((char*)"127.0.0.1", 12346);
    BSNet* aux_server = new BSNet((unsigned int)12347);
    BSNet* aux_client = new BSNet((char*)"127.0.0.1", 12348);
    BSNet* aux_server_1 = new BSNet((unsigned int)12349);
    BSNet* aux_client_1 = new BSNet((char*)"127.0.0.1", 12350);
    BSNet* aux_server_2 = new BSNet((unsigned int)12351);
    BSNet* aux_client_2 = new BSNet((char*)"127.0.0.1", 12352);

    main_server->listenNow();
    aux_server->listenNow();
    aux_server_1->listenNow();
    aux_server_2->listenNow();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    main_client->connectNow();
    aux_client->connectNow();
    aux_client_1->connectNow();
    aux_client_2->connectNow();

    CommPorts ports = make_ports(main_server, main_client, aux_server, aux_client,
                                 aux_server_1, aux_client_1, aux_server_2, aux_client_2);

#ifdef SIGMOID_BASE_TEST
    run_named_base_test_csp0("sigmoid", ports);
#endif
#ifdef TANH_BASE_TEST
    run_named_base_test_csp0("tanh", ports);
#endif
#ifdef ERF_BASE_TEST
    run_named_base_test_csp0("erf", ports);
#endif
#ifdef EXP_BASE_TEST
    run_named_base_test_csp0("exp", ports);
#endif
#ifdef INV_BASE_TEST
    run_named_base_test_csp0("inv", ports);
#endif
#ifdef INVSQRT_BASE_TEST
    run_named_base_test_csp0("invsqrt", ports);
#endif

    sgx_destroy_enclave(global_eid1);
    delete main_server;
    delete main_client;
    delete aux_server;
    delete aux_client;
    delete aux_server_1;
    delete aux_client_1;
    delete aux_server_2;
    delete aux_client_2;
    printf("CSP0 base hybrid approximation tests complete.\n");
    return 0;
}
