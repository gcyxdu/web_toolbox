




#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <chrono>
#include <algorithm>
#include <cmath>
#include <random>
#include <thread>
#include <vector>

#define MAX_PATH FILENAME_MAX

#include "App.h"
#include "Enclave_u.h"
#include "SecureBert.h"
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
    {SGX_ERROR_INVALID_VERSION, "Enclave was invalid.", NULL},
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

static const int kGeluTestCount = 10000;
static const int kSoftmaxTestCount = 512;
static const int kLayerNormTestCount = 768;
static const uint64_t kScaleBits = 20;
static const uint64_t kScale = 1ULL << kScaleBits;

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

static void print_comm_stats(const char* scheme_name, int count,
                             const BSNetStatsSnapshot& stats,
                             unsigned long long logical_rounds = 0) {
    unsigned long long rounds = logical_rounds;
    if (rounds == 0) {
        rounds = std::max(stats.send_calls, stats.recv_calls);
    }
    printf("\n%s方案进行%d次计算的发送通信量为：%llu bytes\n",
           scheme_name, count, stats.send_bytes);
    printf("%s方案进行%d次计算的接收通信量为：%llu bytes\n",
           scheme_name, count, stats.recv_bytes);
    printf("%s方案进行%d次计算的总通信量为：%llu bytes\n",
           scheme_name, count, stats.send_bytes + stats.recv_bytes);
    printf("%s方案进行%d次计算的通信轮次计数为：%llu\n",
           scheme_name, count, rounds);
}

static void make_secret_shared_input(double lo, double hi, int size,
                                     std::vector<double>& original_real,
                                     std::vector<uint64_t>& share0,
                                     std::vector<uint64_t>& share1) {
    std::mt19937_64 value_gen(12345);
    std::mt19937_64 share_gen(67890);
    std::uniform_real_distribution<double> dis(lo, hi);
    original_real.resize(size);
    share0.resize(size);
    share1.resize(size);
    for (int i = 0; i < size; i++) {
        original_real[i] = dis(value_gen);
        int64_t fixed_val = static_cast<int64_t>(std::llround(original_real[i] * (double)kScale));
        share0[i] = share_gen();
        share1[i] = (uint64_t)fixed_val - share0[i];
    }
}

static double gelu_ref(double x) {
    return 0.5 * x * (1.0 + std::erf(x / std::sqrt(2.0)));
}

static void test_gelu_csp0(const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP0 GeLU 动态精度测试 ===\n");
    printf("==========================================================\n");

    struct Cfg { int k1; int k2; };
    const std::vector<Cfg> configs = {{1, 12}, {3, 12}};
    const int size = kGeluTestCount;
    const double scale_inv = 1.0 / (double)kScale;

    std::mt19937_64 value_gen(123456);
    std::mt19937_64 share_gen(67890);
    std::uniform_real_distribution<double> dis(-7.0, 7.0);
    std::vector<double> input_real(size);
    std::vector<uint64_t> share0(size);
    std::vector<uint64_t> share1(size);
    for (int i = 0; i < size; i++) {
        input_real[i] = dis(value_gen);
        uint64_t fixed = (uint64_t)((int64_t)(input_real[i] * (1ULL << kScaleBits)));
        share0[i] = share_gen();
        share1[i] = fixed - share0[i];
    }
    if (!ports.main_server->sendMsg(share1.data(), size * sizeof(uint64_t), 0)) return;
    printf("[Init] 生成 %d 个固定样本...\n", size);
    std::vector<uint64_t> out0(size);
    std::vector<uint64_t> out1(size);
    BSNetStatsSnapshot first_stats{};
    bool has_stats = false;
    for (const Cfg& cfg : configs) {
        printf("\n------------------------------------------------\n");
        printf("Testing Config: K1=%d, K2=%d\n", cfg.k1, cfg.k2);
        reset_bsnet_stats();
        auto start = std::chrono::high_resolution_clock::now();
        private_approx_gelu_2rounds_csp0(ports, share0.data(), out0.data(), size, cfg.k1, cfg.k2, UINT64_MAX);
        auto end = std::chrono::high_resolution_clock::now();
        BSNetStatsSnapshot stats = get_bsnet_stats();
        if (!has_stats) {
            first_stats = stats;
            has_stats = true;
        }
        if (!ports.main_server->recvMsg(out1.data(), size * sizeof(uint64_t), 0)) return;

        double total_error = 0.0;
        double max_error = 0.0;
        for (int i = 0; i < size; i++) {
            double mpc = (double)(int64_t)(out0[i] + out1[i]) * scale_inv;
            double err = std::fabs(mpc - gelu_ref(input_real[i]));
            total_error += err;
            if (err > max_error) max_error = err;
        }
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        printf("  耗时: %.2f ms\n", duration.count() / 1000.0);
        printf("  平均误差: %.10f | 最大误差: %.10f\n", total_error / size, max_error);
    }
    if (has_stats) {
        print_comm_stats("GeLU", size, first_stats, 2);
    }
}

static void test_softmax_csp0(const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP0 Softmax 动态精度测试 ===\n");
    printf("==========================================================\n");

    struct Cfg { int k1; int k2; };
    const std::vector<Cfg> configs = {{1, 12}, {2, 12}, {3, 12}};
    const int size = kSoftmaxTestCount;
    const double scale_inv = 1.0 / (double)kScale;
    std::mt19937_64 gen(12345);
    std::uniform_real_distribution<double> dis(-6.0, 0.0);
    printf("[Init] 生成 %d 个固定样本...\n", size);
    std::vector<double> real_input(size);
    std::vector<double> expected(size);
    double sum_exp = 0.0;
    for (int i = 0; i < size; i++) {
        real_input[i] = dis(gen);
        sum_exp += std::exp(real_input[i]);
    }
    for (int i = 0; i < size; i++) expected[i] = std::exp(real_input[i]) / sum_exp;

    std::vector<uint64_t> share0(size);
    std::vector<uint64_t> share1(size);
    for (int i = 0; i < size; i++) {
        int64_t fixed = static_cast<int64_t>(std::llround(real_input[i] * (double)kScale));
        share0[i] = gen();
        share1[i] = (uint64_t)fixed - share0[i];
    }
    if (!ports.main_server->sendMsg(share1.data(), size * sizeof(uint64_t), 0)) return;

    std::vector<uint64_t> out0(size);
    std::vector<uint64_t> out1(size);
    BSNetStatsSnapshot first_stats{};
    bool has_stats = false;
    for (const Cfg& cfg : configs) {
        printf("\n------------------------------------------------\n");
        printf("Testing Config: K1=%d, K2=%d\n", cfg.k1, cfg.k2);
        reset_bsnet_stats();
        auto start = std::chrono::high_resolution_clock::now();
        private_approx_softmax_csp0(ports, share0.data(), out0.data(), 1, size,
                                    cfg.k1, cfg.k2, cfg.k1, cfg.k1, cfg.k2, cfg.k2, 0);
        auto end = std::chrono::high_resolution_clock::now();
        BSNetStatsSnapshot stats = get_bsnet_stats();
        if (!has_stats) {
            first_stats = stats;
            has_stats = true;
        }
        if (!ports.main_server->recvMsg(out1.data(), size * sizeof(uint64_t), 0)) return;

        double sum_prob = 0.0;
        double total_error = 0.0;
        double max_error = 0.0;
        for (int i = 0; i < size; i++) {
            double mpc = (double)(int64_t)(out0[i] + out1[i]) * scale_inv;
            double err = std::fabs(mpc - expected[i]);
            sum_prob += mpc;
            total_error += err;
            if (err > max_error) max_error = err;
        }
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        printf("  耗时: %.2f ms \n", duration.count() / 1000.0);
        printf("  平均误差: %.10f | 最大误差: %.10f\n", total_error / size, max_error);
    }
    if (has_stats) {
        print_comm_stats("Softmax", size, first_stats, 9);
    }
}

static void test_layernorm_csp0(const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP0 LayerNorm 动态精度测试 ===\n");
    printf("==========================================================\n");

    struct Cfg { int k1; int k2; };
    const std::vector<Cfg> configs = {{1, 12}, {2, 12}, {3, 12}};
    const int rows = 1;
    const int cols = kLayerNormTestCount;
    const double scale = (double)kScale;
    std::mt19937_64 value_gen(42);
    std::mt19937_64 share_gen(999);
    std::normal_distribution<double> dist(0.0, 1.0);

    std::vector<double> x_real(cols);
    for (double& v : x_real) v = dist(value_gen);
    double mean = 0.0;
    for (double v : x_real) mean += v;
    mean /= cols;
    double var = 0.0;
    for (double v : x_real) var += (v - mean) * (v - mean);
    var /= cols;
    double inv_std = 1.0 / std::sqrt(var);

    SecureTensor x0(rows, cols), x1(rows, cols);
    SecureTensor g0(1, cols), g1(1, cols);
    SecureTensor b0(1, cols), b1(1, cols);
    for (int i = 0; i < cols; i++) {
        int64_t fixed = static_cast<int64_t>(std::llround(x_real[i] * scale));
        x0.shares[i] = share_gen();
        x1.shares[i] = (uint64_t)fixed - x0.shares[i];
        g0.shares[i] = (uint64_t)std::llround(scale);
        g1.shares[i] = 0;
        b0.shares[i] = 0;
        b1.shares[i] = 0;
    }

    ports.aux_client_1->sendMsg(x1.shares.data(), cols * sizeof(uint64_t), 0);
    ports.aux_client_1->sendMsg(g1.shares.data(), cols * sizeof(uint64_t), 0);
    ports.aux_client_1->sendMsg(b1.shares.data(), cols * sizeof(uint64_t), 0);
    printf("[Init] 生成 %d 个固定样本...\n", cols);
    std::vector<uint64_t> out1(cols);
    BSNetStatsSnapshot first_stats{};
    bool has_stats = false;
    for (const Cfg& cfg : configs) {
        printf("\n------------------------------------------------\n");
        printf("Testing Config: K1=%d, K2=%d\n", cfg.k1, cfg.k2);
        SecureTensor x0_run = x0;
        reset_bsnet_stats();
        auto start = std::chrono::high_resolution_clock::now();
        Op_LayerNorm(x0_run, g0, b0, ports, cfg.k1, cfg.k1, cfg.k2);
        auto end = std::chrono::high_resolution_clock::now();
        BSNetStatsSnapshot stats = get_bsnet_stats();
        if (!has_stats) {
            first_stats = stats;
            has_stats = true;
        }
        if (!ports.aux_server_1->recvMsg(out1.data(), cols * sizeof(uint64_t), 0)) return;

        double total_error = 0.0;
        double max_error = 0.0;
        for (int i = 0; i < cols; i++) {
            double mpc = (double)(int64_t)(x0_run.shares[i] + out1[i]) / scale;
            double ref = (x_real[i] - mean) * inv_std;
            double err = std::fabs(mpc - ref);
            total_error += err;
            if (err > max_error) max_error = err;
        }
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        printf("  耗时: %.2f ms\n", duration.count() / 1000.0);
        printf("  平均误差: %.10f | 最大误差: %.10f\n", total_error / cols, max_error);
    }
    if (has_stats) {
        print_comm_stats("LayerNorm", cols, first_stats, 10);
    }
}

int main() {
    if (initialize_enclave(global_eid1) < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    printf("Starting CSP0 nonlinear function tests...\n");
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

#ifdef GELU_TEST
    test_gelu_csp0(ports);
#endif
#ifdef LAYERNORM_TEST
    test_layernorm_csp0(ports);
#endif
#ifdef SOFTMAX_TEST
    test_softmax_csp0(ports);
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
    printf("CSP0 nonlinear function tests complete.\n");
    return 0;
}
