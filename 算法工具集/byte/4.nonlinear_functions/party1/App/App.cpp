




#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <chrono>
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

static const int kGeluTestCount = 10000;
static const int kSoftmaxTestCount = 512;
static const int kLayerNormTestCount = 768;

static CommPorts make_ports(BSNet* main_client, BSNet* main_server,
                            BSNet* aux_client, BSNet* aux_server,
                            BSNet* aux_client_1, BSNet* aux_server_1,
                            BSNet* aux_client_2, BSNet* aux_server_2) {
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

static void test_gelu_csp1(const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP1 GeLU 动态精度测试 ===\n");
    printf("==========================================================\n");

    struct Cfg { int k1; int k2; };
    const std::vector<Cfg> configs = {{1, 12}, {3, 12}};
    const int size = kGeluTestCount;
    std::vector<uint64_t> input(size);
    if (!ports.main_client->recvMsg(input.data(), size * sizeof(uint64_t), 0)) return;

    std::vector<uint64_t> output(size);
    for (const Cfg& cfg : configs) {
        printf("\nRunning Config: K1=%d, K2=%d...\n", cfg.k1, cfg.k2);
        private_approx_gelu_2rounds_csp1(ports, input.data(), output.data(), size, cfg.k1, cfg.k2, UINT64_MAX);
        if (!ports.main_client->sendMsg(output.data(), size * sizeof(uint64_t), 0)) return;
        printf("Done.\n");
    }
}

static void test_layernorm_csp1(const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP1 LayerNorm 动态精度测试 ===\n");
    printf("==========================================================\n");

    struct Cfg { int k1; int k2; };
    const std::vector<Cfg> configs = {{1, 12}, {2, 12}, {3, 12}};
    const int rows = 1;
    const int cols = kLayerNormTestCount;
    SecureTensor x1(rows, cols), g1(1, cols), b1(1, cols);
    if (!ports.aux_server_1->recvMsg(x1.shares.data(), cols * sizeof(uint64_t), 0)) return;
    if (!ports.aux_server_1->recvMsg(g1.shares.data(), cols * sizeof(uint64_t), 0)) return;
    if (!ports.aux_server_1->recvMsg(b1.shares.data(), cols * sizeof(uint64_t), 0)) return;

    for (const Cfg& cfg : configs) {
        printf("\nRunning Config: K1=%d, K2=%d...\n", cfg.k1, cfg.k2);
        SecureTensor x1_run = x1;
        Op_LayerNorm(x1_run, g1, b1, ports, cfg.k1, cfg.k1, cfg.k2);
        ports.aux_client_1->sendMsg(x1_run.shares.data(), cols * sizeof(uint64_t), 0);
        printf("Done.\n");
    }
}

static void test_softmax_csp1(const CommPorts& ports) {
    printf("\n==========================================================\n");
    printf("=== CSP1 Softmax 动态精度测试 ===\n");
    printf("==========================================================\n");

    struct Cfg { int k1; int k2; };
    const std::vector<Cfg> configs = {{1, 12}, {2, 12}, {3, 12}};
    const int size = kSoftmaxTestCount;
    std::vector<uint64_t> input(size);
    if (!ports.main_client->recvMsg(input.data(), size * sizeof(uint64_t), 0)) return;

    std::vector<uint64_t> output(size);
    for (const Cfg& cfg : configs) {
        printf("\nRunning Config: K1=%d, K2=%d...\n", cfg.k1, cfg.k2);
        private_approx_softmax_csp1(ports, input.data(), output.data(), 1, size,
                                    cfg.k1, cfg.k2, cfg.k1, cfg.k1, cfg.k2, cfg.k2, 0);
        ports.main_client->sendMsg(output.data(), size * sizeof(uint64_t), 0);
        printf("Done.\n");
    }
}

int main() {
    if (initialize_enclave(global_eid1) < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    printf("Starting CSP1 nonlinear function tests...\n");
    BSNet* main_server = new BSNet((unsigned int)12346);
    BSNet* main_client = new BSNet((char*)"127.0.0.1", 12345);
    BSNet* aux_server = new BSNet((unsigned int)12348);
    BSNet* aux_client = new BSNet((char*)"127.0.0.1", 12347);
    BSNet* aux_server_1 = new BSNet((unsigned int)12350);
    BSNet* aux_client_1 = new BSNet((char*)"127.0.0.1", 12349);
    BSNet* aux_server_2 = new BSNet((unsigned int)12352);
    BSNet* aux_client_2 = new BSNet((char*)"127.0.0.1", 12351);

    main_client->connectNow();
    aux_client->connectNow();
    aux_client_1->connectNow();
    aux_client_2->connectNow();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    main_server->listenNow();
    aux_server->listenNow();
    aux_server_1->listenNow();
    aux_server_2->listenNow();

    CommPorts ports = make_ports(main_client, main_server, aux_client, aux_server,
                                 aux_client_1, aux_server_1, aux_client_2, aux_server_2);

#ifdef GELU_TEST
    test_gelu_csp1(ports);
#endif
#ifdef LAYERNORM_TEST
    test_layernorm_csp1(ports);
#endif
#ifdef SOFTMAX_TEST
    test_softmax_csp1(ports);
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
    printf("CSP1 nonlinear function tests complete.\n");
    return 0;
}
