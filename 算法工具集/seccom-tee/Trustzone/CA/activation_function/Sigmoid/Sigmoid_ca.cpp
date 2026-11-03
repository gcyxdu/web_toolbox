/**
 * @author heqi
 * @date 09/01/2025
 * */

#include <cstdio>
#include <cstdlib>
#include <sys/time.h>
#include "tee_client_api.h"

/*摘取的TestAPP的部分*/
#include "pwd.h"
#include <iostream>
#include <random>
#include "she.h"
#include "sheFloat.h"
#include <fstream>
#include "string"
#include "../../common/config_loader.hpp"
// da21c465-11dd-4c8d-862b-f0cbc4aff4df
static const TEEC_UUID TA_uuid = {
        0xda21c465, 0x11dd, 0x4c8d,
        { 0x86, 0x2b, 0xf0, 0xcb, 0xc4, 0xaf, 0xf4, 0xdf }
};
/*---------------常量内容----------------*/
#define __DEBUG__ 1

// 共享内存相关常量
#define SHARED_MEM_POOL_SIZE 16  // 16个共享内存槽位
#define SHARED_MEM_SIZE (1024 * 1024)  // 1MB per slot

enum {
    sheRescale = 0,
    calENegx,
    keySynthronize,
    sigmoidInverseX,
    SHEgenerateRandomKeysTee2,
};
/*-------------------------------------*/
TEEC_Context g_context;
TEEC_Session g_session;

// 共享内存池
static TEEC_SharedMemory g_shared_mem_pool[SHARED_MEM_POOL_SIZE];
static int g_shared_mem_initialized = 0;
static int g_shared_mem_index = 0;
/*-------------------------------------*/
extern SHE_key KEY;
using namespace std;

namespace {

struct AppConfig {
    std::string ta_path;
    std::string input_dir;
    std::size_t combined_str_len;
    int cycle_num;
    int k;
};

AppConfig g_app_config;

AppConfig LoadAppConfig() {
    const auto config = seccom::LoadFlatYamlFile(
        seccom::JoinPath(seccom::GetExecutableDir(), "config.yaml"));
    return AppConfig{
        config.Require("ta_path"),
        config.Require("input_dir"),
        config.GetSizeT("combined_str_len", 60000),
        config.GetInt("cycle_num", 10000),
        config.GetInt("k", 1000000),
    };
}

}  // namespace


void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
double decryptAndGetDouble(BIGNUM *input, int k, int kTimes, SHE_key *key, BN_CTX *ctx);

// 初始化共享内存池
static TEEC_Result init_shared_memory_pool() {
    if (g_shared_mem_initialized) {
        return TEEC_SUCCESS;
    }
    
    for (int i = 0; i < SHARED_MEM_POOL_SIZE; i++) {
        g_shared_mem_pool[i].flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
        g_shared_mem_pool[i].size = SHARED_MEM_SIZE;
        TEEC_Result result = TEEC_AllocateSharedMemory(&g_context, &g_shared_mem_pool[i]);
        
        if (result != TEEC_SUCCESS) {
            // 如果分配失败，清理已分配的内存
            for (int j = 0; j < i; j++) {
                TEEC_ReleaseSharedMemory(&g_shared_mem_pool[j]);
            }
            return result;
        }
    }
    
    g_shared_mem_initialized = 1;
    g_shared_mem_index = 0;
    return TEEC_SUCCESS;
}

// 清理共享内存池
static void cleanup_shared_memory_pool() {
    if (!g_shared_mem_initialized) {
        return;
    }
    
    for (int i = 0; i < SHARED_MEM_POOL_SIZE; i++) {
        TEEC_ReleaseSharedMemory(&g_shared_mem_pool[i]);
    }
    
    g_shared_mem_initialized = 0;
    g_shared_mem_index = 0;
}

// 获取共享内存槽位
static TEEC_SharedMemory* get_shared_memory_slot() {
    if (!g_shared_mem_initialized) {
        return nullptr;
    }
    
    TEEC_SharedMemory* slot = &g_shared_mem_pool[g_shared_mem_index];
    g_shared_mem_index = (g_shared_mem_index + 1) % SHARED_MEM_POOL_SIZE;
    return slot;
}


// 带符号二进制转换函数
static size_t bn_to_signed_bin_buffer(const BIGNUM *bn, unsigned char *buffer, size_t buffer_size) {
    if (bn == nullptr || buffer == nullptr || buffer_size < 6) {
        return 0;
    }
    
    int is_negative = BN_is_negative(bn);
    int data_bytes = BN_num_bytes(bn);
    
    // 处理零值
    if (data_bytes == 0) {
        buffer[0] = 0; // 符号位
        buffer[1] = 0; buffer[2] = 0; buffer[3] = 0; buffer[4] = 1; // 长度 = 1
        buffer[5] = 0; // 数据 = 0
        return 6;
    }
    
    // 检查缓冲区大小
    if ((size_t)(5 + data_bytes) > buffer_size) {
        return 0;
    }
    
    // 写入符号位
    buffer[0] = is_negative ? 1 : 0;
    
    // 写入长度（大端序）
    buffer[1] = (data_bytes >> 24) & 0xFF;
    buffer[2] = (data_bytes >> 16) & 0xFF;
    buffer[3] = (data_bytes >> 8) & 0xFF;
    buffer[4] = data_bytes & 0xFF;
    
    // 获取绝对值并写入数据
    BIGNUM *abs_bn = BN_dup(bn);
    if (abs_bn == nullptr) {
        return 0;
    }
    
    if (is_negative) {
        BN_set_negative(abs_bn, 0);
    }
    
    int written = BN_bn2bin(abs_bn, buffer + 5);
    BN_free(abs_bn);
    
    if (written != data_bytes) {
        return 0;
    }
    
    return 5 + data_bytes;
}

static size_t bn_from_signed_bin_buffer(const unsigned char *buffer, size_t buffer_size, BIGNUM *bn) {
    if (buffer == nullptr || bn == nullptr || buffer_size < 6) {
        return 0;
    }
    
    int is_negative = buffer[0];
    int data_bytes = (buffer[1] << 24) | (buffer[2] << 16) | (buffer[3] << 8) | buffer[4];
    
    if (data_bytes < 0 || (size_t)(5 + data_bytes) > buffer_size) {
        return 0;
    }
    
    if (data_bytes == 0) {
        BN_zero(bn);
        return 5;
    }
    
    BIGNUM *temp = BN_bin2bn(buffer + 5, data_bytes, nullptr);
    if (temp == nullptr) {
        return 0;
    }
    
    if (is_negative) {
        BN_set_negative(temp, 1);
    }
    
    BN_copy(bn, temp);
    BN_free(temp);
    
    return 5 + data_bytes;
}

/* initialize context and opensession */
TEEC_Result TeecInit(void)
{

    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    result = TEEC_InitializeContext(nullptr, &g_context);
    if (result != TEEC_SUCCESS) {
        printf("teec initial failed");

        return result;
    }

    /* pass TA's FULLPATH to TEE, then OpenSession. */
    /* CA MUST use the TEEC_LOGIN_IDENTIFY mode to login. */
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT);
    g_context.ta_path = reinterpret_cast<uint8_t *>(
        const_cast<char *>(g_app_config.ta_path.c_str()));

    result = TEEC_OpenSession(&g_context, &g_session, &TA_uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("open session failed: result:%x orgin: %u.\n", (int)result, origin);
        TEEC_FinalizeContext(&g_context);
        return result;
    }

    // 初始化共享内存池
    TEEC_Result shared_result = init_shared_memory_pool();
    if (shared_result != TEEC_SUCCESS) {
        TEEC_Error("Failed to initialize shared memory pool: 0x%x", shared_result);
        TEEC_CloseSession(&g_session);
        TEEC_FinalizeContext(&g_context);
        return shared_result;
    }
    
    TEEC_Debug("teec init OK.");
    return result;
}
// 关闭链接
void TeecClose(void)
{
    TEEC_CloseSession(&g_session);
    TEEC_FinalizeContext(&g_context);
    
    // 清理共享内存池
    cleanup_shared_memory_pool();

    TEEC_Debug("teec uninit OK.");
}
/*---------------------调用TA侧的内容------------------------*/

TEEC_Result invoke_sheRescale(BIGNUM *output, BIGNUM *input, int k, int kTimes){
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    // 获取两个共享内存槽位：一个给input，一个给output
    TEEC_SharedMemory* input_mem = get_shared_memory_slot();
    TEEC_SharedMemory* output_mem = get_shared_memory_slot();
    if (input_mem == nullptr || output_mem == nullptr) {
        TEEC_Error("Failed to get shared memory slots");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_VALUE_INPUT,
            TEEC_VALUE_INPUT
    );

    // 直接将 BIGNUM 转换为带符号二进制并写入缓冲区
    size_t input_size = bn_to_signed_bin_buffer(input, (unsigned char *)input_mem->buffer, SHARED_MEM_SIZE);
    if (input_size == 0) {
        TEEC_Error("Failed to convert BIGNUM to signed binary or buffer too small");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    // 检查共享内存大小是否足够（输出可能需要更多空间）
    if (input_size * 2 > SHARED_MEM_SIZE) {
        TEEC_Error("Input too large for shared memory: %zu bytes", input_size * 2);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    operation.params[0].memref.parent = output_mem;
    operation.params[0].memref.size = input_size * 3;  // 输出可能需要更多空间
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input_mem;
    operation.params[1].memref.size = input_size;
    operation.params[1].memref.offset = 0;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;

    result = TEEC_InvokeCommand(&g_session, sheRescale, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke invoke_sheRescale failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    TEEC_Debug("invoke invoke_sheRescale is successed.");
    return result;
}

TEEC_Result invoke_calENegx(BIGNUM *output, BIGNUM *input, int k, int kTimes){
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    // 获取两个共享内存槽位：一个给input，一个给output
    TEEC_SharedMemory* input_mem = get_shared_memory_slot();
    TEEC_SharedMemory* output_mem = get_shared_memory_slot();
    if (input_mem == nullptr || output_mem == nullptr) {
        TEEC_Error("Failed to get shared memory slots");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_VALUE_INPUT,
            TEEC_VALUE_INPUT
    );

    // 直接将 BIGNUM 转换为带符号二进制并写入缓冲区
    size_t input_size = bn_to_signed_bin_buffer(input, (unsigned char *)input_mem->buffer, SHARED_MEM_SIZE);
    if (input_size == 0) {
        TEEC_Error("Failed to convert BIGNUM to signed binary or buffer too small");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    // 检查共享内存大小是否足够（输出可能需要更多空间）
    if (input_size * 2 > SHARED_MEM_SIZE) {
        TEEC_Error("Input too large for shared memory: %zu bytes", input_size * 2);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    operation.params[0].memref.parent = output_mem;
    operation.params[0].memref.size = input_size * 3;  // 输出可能需要更多空间
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input_mem;
    operation.params[1].memref.size = input_size;
    operation.params[1].memref.offset = 0;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;

    result = TEEC_InvokeCommand(&g_session, calENegx, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke invoke_calENegx failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    TEEC_Debug("invoke invoke_calENegx is successed.");
    return result;
}

static bool process_response_from_tee(char *combined_str, BIGNUM **p, BIGNUM **q, BIGNUM **l,
                                      BIGNUM **n, BIGNUM **e_negative1, BIGNUM **l_2,
                                      BIGNUM **cipher_zero, const char *SEPARATOR) {
    // 使用 strtok 分割字符串
    char *token;
    char *str = strdup(combined_str); // 使用 strdup 复制一份，strtok 会修改原字符串

    // 分割并转换为 BIGNUM
    token = strtok(str, SEPARATOR); // 分割第一个部分（p）
    if (!BN_dec2bn(p, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第二部分（q）
    if (!BN_dec2bn(q, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第三部分（l）
    if (!BN_dec2bn(l, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第四部分（n）
    if (!BN_dec2bn(n, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第五部分（e_negative1）
    if (!BN_dec2bn(e_negative1, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第六部分（l_2）
    if (!BN_dec2bn(l_2, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第七部分（cipher_zero）
    if (!BN_dec2bn(cipher_zero, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    // 释放临时字符串
    free(str);

    return TEEC_SUCCESS;
}

TEEC_Result invoke_keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1,
                                  BIGNUM *l_2, BIGNUM *cipher_zero){

    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );
    char *combined_str = (char *)malloc(g_app_config.combined_str_len);
    char * SEPARATOR = "||";
    if (combined_str == NULL) {
        printf("Memory allocation failed");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    operation.params[0].tmpref.buffer = combined_str;
    operation.params[0].tmpref.size = g_app_config.combined_str_len;

    result = TEEC_InvokeCommand(&g_session, keySynthronize, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        cout <<"invoke_keySynthronize失败"<<endl;
        printf("invoke invoke_keySynthronize failed, codes=0x%x, origin=0x%x\n",result,origin);
    }
    // 分割之后重新传递值
    bool ok = process_response_from_tee(combined_str, &p, &q, &l, &n, &e_negative1, &l_2,
                                                   &cipher_zero, SEPARATOR);

    free(combined_str);
    return result;
}


TEEC_Result invoke_sigmoidInverseX(BIGNUM *output, BIGNUM *input, int k, int kTimes){
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    // 获取两个共享内存槽位：一个给input，一个给output
    TEEC_SharedMemory* input_mem = get_shared_memory_slot();
    TEEC_SharedMemory* output_mem = get_shared_memory_slot();
    if (input_mem == nullptr || output_mem == nullptr) {
        TEEC_Error("Failed to get shared memory slots");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_VALUE_INPUT,
            TEEC_VALUE_INPUT
    );

    // 直接将 BIGNUM 转换为带符号二进制并写入缓冲区
    size_t input_size = bn_to_signed_bin_buffer(input, (unsigned char *)input_mem->buffer, SHARED_MEM_SIZE);
    if (input_size == 0) {
        TEEC_Error("Failed to convert BIGNUM to signed binary or buffer too small");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    // 检查共享内存大小是否足够（输出可能需要更多空间）
    if (input_size * 2 > SHARED_MEM_SIZE) {
        TEEC_Error("Input too large for shared memory: %zu bytes", input_size * 2);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    operation.params[0].memref.parent = output_mem;
    operation.params[0].memref.size = input_size * 3;  // 输出可能需要更多空间
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input_mem;
    operation.params[1].memref.size = input_size;
    operation.params[1].memref.offset = 0;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;

    result = TEEC_InvokeCommand(&g_session, sigmoidInverseX, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke invoke_sigmoidInverseX failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    TEEC_Debug("invoke invoke_sigmoidInverseX is successed.");
    return result;
}

TEEC_Result invoke_she_generateRandomKeysTee2(){
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );

    result = TEEC_InvokeCommand(&g_session,SHEgenerateRandomKeysTee2,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke invoke_she_generateRandomKeysTee2 failed, codes=0x%x, origin=0x%x\n",result,origin);
        return result;
    }

    TEEC_Debug("invoke invoke_she_generateRandomKeysTee2 is successed.")
    return result;
}


/*--------------------------------------------------------*/
double getRandomDouble(double min, double max) {
    // 创建一个随机数引擎，可以用不同的发生器来生成不同分布的随机数
    std::random_device rd;
    std::mt19937 gen(rd());  // 使用 Mersenne Twister 发生器

    // 创建一个均匀分布的浮点数分布，范围在 [min, max)
    std::uniform_real_distribution<double> dis(min, max);

    // 生成随机浮点数
    double random_double = dis(gen);
    return random_double;
}

// 测试用的
void decPrint(BIGNUM *cipher) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    she_decryptBignum(plain, cipher, &KEY, ctx);
    bn_printfDec(plain);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void timeStart(struct timeval *timePointer) {
    gettimeofday(timePointer, NULL);
}
void timeEnd(struct timeval *timePointer1, struct timeval *timePointer2) {
    float timeuse;
    gettimeofday(timePointer2, NULL);
    timeuse = (timePointer2->tv_sec - timePointer1->tv_sec) * 1000000 + timePointer2->tv_usec - timePointer1->tv_usec;
    printf("cost time(s):%f\n", timeuse / 1000000);
}

float timeEnd2(struct timeval *timePointer1, struct timeval *timePointer2) {
    float timeuse;
    gettimeofday(timePointer2, NULL);
    timeuse = (timePointer2->tv_sec - timePointer1->tv_sec) * 1000000 + timePointer2->tv_usec - timePointer1->tv_usec;
    return timeuse;
}

void sigmoidREETEE(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    double r1, r2;
    BIGNUM *tmp1, *tmp2;
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    SHECipher tmp3;
    tmp3.cipher = tmp1;
    tmp3.kTimes = 0;
    SHECipher tmp4;
    tmp4.cipher = tmp2;
    tmp4.kTimes = 0;
    r1 = getRandomDouble(-2.0, 3.0);
    r2 = getRandomDouble(exp(-3.0) + 1, exp(2.0) + 1);
    if (BN_is_zero(input->cipher)) {
        BN_copy(input->cipher, key->cipher_zero);
    }
    sheADDConstant(&tmp3, r1, input, k, key, ctx);
    BN_copy(tmp4.cipher, key->n);
    invoke_calENegx(tmp4.cipher, tmp3.cipher, k, tmp3.kTimes);

    tmp4.kTimes = 1;

    sheMULConstant(&tmp4, exp(r1), &tmp4, k, key, ctx);
    sheADDConstant(&tmp3, 1.0, &tmp4, k, key, ctx);
    sheMULConstant(&tmp3, r2, &tmp3, k, key, ctx);
    invoke_sigmoidInverseX(tmp4.cipher, tmp3.cipher, k, tmp3.kTimes);
    tmp4.kTimes = 1;
    sheMULConstant(&tmp4, r2, &tmp4, k, key, ctx);
    sheSETC(res, &tmp4);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void poly3Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx3Big = BN_CTX_get(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx3;
    sheInitC(&tmpx3, tmpx3Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

    sheMULConstant(&tmpx1, 1.50099885e-01, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 5.04270021e-01, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 3.34431493e-04, &tmpx2, k, key, ctx);
    sheNEGC(&tmpx2, &tmpx2, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx3, 1.59389033e-03, &tmpx3, k, key, ctx);
    sheNEGC(&tmpx3, &tmpx3, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);
    sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

    sheSETC(res, &tmp1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void poly4Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx3Big = BN_CTX_get(ctx);
    BIGNUM *tmpx4Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx3;
    sheInitC(&tmpx3, tmpx3Big);
    SHECipher tmpx4;
    sheInitC(&tmpx4, tmpx4Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

    sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 1.50705409e-01, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 4.94662473e-01, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 1.17494397e-03, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx3, 1.61605908e-03, &tmpx3, k, key, ctx);
    sheNEGC(&tmpx3, &tmpx3, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);
    sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx4, 2.77109428e-05, &tmpx4, k, key, ctx);
    sheNEGC(&tmpx4, &tmpx4, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);
    sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

    sheSETC(res, &tmp2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// [ 4.24813287e-05  1.47703859e-05 -4.60674462e-03 -6.26264361e-04 1.91377645e-01  5.02844989e-01]
void poly5Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx3Big = BN_CTX_get(ctx);
    BIGNUM *tmpx4Big = BN_CTX_get(ctx);
    BIGNUM *tmpx5Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx3;
    sheInitC(&tmpx3, tmpx3Big);
    SHECipher tmpx4;
    sheInitC(&tmpx4, tmpx4Big);
    SHECipher tmpx5;
    sheInitC(&tmpx5, tmpx5Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

    sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

    sheMULCC(&tmpx5, &tmpx4, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx5, &tmpx5, k, key, ctx);

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 1.91377645e-01, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 5.02844989e-01, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 6.26264361e-04, &tmpx2, k, key, ctx);
    sheNEGC(&tmpx2, &tmpx2, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx3, 4.60674462e-03, &tmpx3, k, key, ctx);
    sheNEGC(&tmpx3, &tmpx3, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);
    sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx4, 1.47703859e-05, &tmpx4, k, key, ctx);
    sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx5, 4.24813287e-05, &tmpx5, k, key, ctx);
    sheADDCC(&tmp1, &tmpx5, &tmp2, k, key, ctx);

    sheSETC(res, &tmp1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void poly5Comp2(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx3Big = BN_CTX_get(ctx);
    BIGNUM *tmpx4Big = BN_CTX_get(ctx);
    BIGNUM *tmpx5Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx3;
    sheInitC(&tmpx3, tmpx3Big);
    SHECipher tmpx4;
    sheInitC(&tmpx4, tmpx4Big);
    SHECipher tmpx5;
    sheInitC(&tmpx5, tmpx5Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    // sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);  // 1次深度

    sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
    // sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

    sheMULCC(&tmpx5, &tmpx4, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx5, &tmpx5, k, key, ctx);  // 1次深度

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 1.91377645e-01, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 5.02844989e-01, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 6.26264361e-04, &tmpx2, k, key, ctx);
    sheNEGC(&tmpx2, &tmpx2, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx3, 4.60674462e-03, &tmpx3, k, key, ctx);
    sheNEGC(&tmpx3, &tmpx3, k, key, ctx);
    // sheRefresh(&tmpx3, &tmpx3, k, key, ctx);
    sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx4, 1.47703859e-05, &tmpx4, k, key, ctx);
    sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx5, 4.24813287e-05, &tmpx5, k, key, ctx);
    sheADDCC(&tmp1, &tmpx5, &tmp2, k, key, ctx);

    sheSETC(res, &tmp1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void poly6Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx3Big = BN_CTX_get(ctx);
    BIGNUM *tmpx4Big = BN_CTX_get(ctx);
    BIGNUM *tmpx5Big = BN_CTX_get(ctx);
    BIGNUM *tmpx6Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx3;
    sheInitC(&tmpx3, tmpx3Big);
    SHECipher tmpx4;
    sheInitC(&tmpx4, tmpx4Big);
    SHECipher tmpx5;
    sheInitC(&tmpx5, tmpx5Big);
    SHECipher tmpx6;
    sheInitC(&tmpx6, tmpx6Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

    sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

    sheMULCC(&tmpx5, &tmpx4, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx5, &tmpx5, k, key, ctx);

    sheMULCC(&tmpx6, &tmpx5, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx6, &tmpx6, k, key, ctx);

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 1.92201143e-01, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 4.96680846e-01, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 1.41689066e-03, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx3, 4.68463102e-03, &tmpx3, k, key, ctx);
    sheNEGC(&tmpx3, &tmpx3, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);
    sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx4, 8.21374485e-05, &tmpx4, k, key, ctx);
    sheNEGC(&tmpx4, &tmpx4, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);
    sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx5, 4.38318179e-05, &tmpx5, k, key, ctx);
    sheADDCC(&tmp1, &tmpx5, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx6, 1.12540770e-06, &tmpx6, k, key, ctx);
    sheADDCC(&tmp2, &tmpx6, &tmp1, k, key, ctx);

    sheSETC(res, &tmp2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void poly6Comp2(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx3Big = BN_CTX_get(ctx);
    BIGNUM *tmpx4Big = BN_CTX_get(ctx);
    BIGNUM *tmpx5Big = BN_CTX_get(ctx);
    BIGNUM *tmpx6Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx3;
    sheInitC(&tmpx3, tmpx3Big);
    SHECipher tmpx4;
    sheInitC(&tmpx4, tmpx4Big);
    SHECipher tmpx5;
    sheInitC(&tmpx5, tmpx5Big);
    SHECipher tmpx6;
    sheInitC(&tmpx6, tmpx6Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    // sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

    sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
    // sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

    sheMULCC(&tmpx5, &tmpx4, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx5, &tmpx5, k, key, ctx);

    sheMULCC(&tmpx6, &tmpx5, &tmpx1, k, key, ctx);
    // sheRefresh(&tmpx6, &tmpx6, k, key, ctx);

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 1.92201143e-01, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 4.96680846e-01, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 1.41689066e-03, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx3, 4.68463102e-03, &tmpx3, k, key, ctx);
    sheNEGC(&tmpx3, &tmpx3, k, key, ctx);
    // sheRefresh(&tmpx3, &tmpx3, k, key, ctx);
    sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx4, 8.21374485e-05, &tmpx4, k, key, ctx);
    sheNEGC(&tmpx4, &tmpx4, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);
    sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx5, 4.38318179e-05, &tmpx5, k, key, ctx);
    sheADDCC(&tmp1, &tmpx5, &tmp2, k, key, ctx);

    sheMULConstant(&tmpx6, 1.12540770e-06, &tmpx6, k, key, ctx);
    sheADDCC(&tmp2, &tmpx6, &tmp1, k, key, ctx);

    sheSETC(res, &tmp2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}


void APPpartPre(SHECipher *output, SHECipher *z, int k, SHE_key *key, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    SHECipher tmp1;
    tmp1.cipher = tmp1Big;
    tmp1.kTimes = 0;
    SHECipher tmp2;
    tmp2.cipher = tmp2Big;
    tmp2.kTimes = 0;
    // 2.722+z^2
    sheMULCC(&tmp1, z, z, k, key, ctx);
    sheRefresh(&tmp1, &tmp1, k, key, ctx);
    sheADDConstant(&tmp2, 2.722, &tmp1, k, key, ctx);
    //-(2.722+z^2)
    sheNEGC(&tmp2, &tmp2, k, key, ctx);
    sheRefresh(output, &tmp2, k, key, ctx);
    BN_CTX_end(ctx);
}

void APPpart(SHECipher *res, SHECipher *uk, SHECipher *preCal, int k, int AISRTime, double uk0d, SHE_key *key,
             BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    SHECipher tmp1;
    tmp1.cipher = tmp1Big;
    tmp1.kTimes = 0;
    SHECipher tmp2;
    tmp2.cipher = tmp2Big;
    tmp2.kTimes = 0;
    double uk0d2 = uk0d * uk0d;
    double halfuk0 = uk0d * 0.5;
    //-(2.722+z^2)*uk^2
    if (AISRTime == 1) {
        sheMULConstant(&tmp1, uk0d2, preCal, k, key, ctx);
    } else {
        sheMULCC(&tmp1, uk, uk, k, key, ctx);
        sheRefresh(&tmp1, &tmp1, k, key, ctx);
        sheMULCC(&tmp1, &tmp1, preCal, k, key, ctx);
        sheRefresh(&tmp1, &tmp1, k, key, ctx);
    }
    // 3-(2.722+z^2)*uk^2
    sheADDConstant(&tmp2, 3, &tmp1, k, key, ctx);
    // 0.5*uk*(3-(2.722+z^2)*uk^2)
    if (AISRTime == 1) {
        sheMULConstant(res, halfuk0, &tmp2, k, key, ctx);
    } else {
        sheMULConstant(&tmp1, 0.5, uk, k, key, ctx);
        sheMULCC(res, &tmp1, &tmp2, k, key, ctx);
        sheRefresh(res, res, k, key, ctx);
    }
    BN_CTX_end(ctx);
}

// polynomial compare//input 和 res 可以一致
void secureLRAISR(SHECipher *res, SHECipher *input, int AISRTimes, int k, SHE_key *key) {
    // struct timeval t1, t2;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    double uk0d = 0.14;
    SHECipher tmp1;
    tmp1.cipher = tmp1Big;
    tmp1.kTimes = 0;
    SHECipher tmp2;
    tmp2.cipher = tmp2Big;
    tmp2.kTimes = 0;
    // timeStart(&t1);
    APPpartPre(&tmp2, input, k, key, ctx);

    for (int i = 1; i <= AISRTimes; ++i) {
        APPpart(&tmp1, &tmp1, &tmp2, k, i, uk0d, key, ctx);
    }  // tmp2保持-(2.722+z^2)不变，tmp1疯狂迭代

    sheMULConstant(&tmp1, 0.5, &tmp1, k, key, ctx);

    sheMULCC(&tmp1, &tmp1, input, k, key, ctx);

    sheRefresh(&tmp1, &tmp1, k, key, ctx);

    sheADDConstant(&tmp2, 0.5, &tmp1, k, key, ctx);
    sheSETC(res, &tmp2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx)
{
    double r1 = getRandomDouble(0.0, 3.0);
    BN_CTX_start(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *kr1 = BN_CTX_get(ctx);
    int64_t kr1Int = (int64_t)(r1 * k);
    SHECipher tmp3;
    tmp3.cipher = tmp1;
    tmp3.kTimes = 0;
    BN_set_word(kr1, kr1Int);
    sheADDConstant(&tmp3, r1, input, k, key, ctx);
    // 进入TEE,tmp1输入，tmp2输出,输出tmp2的空间够么？所以加个复制l
    BN_copy(tmp2, key->n); // 这个是为了保证出来有空间
    invoke_sheRescale(tmp2, tmp3.cipher, k, tmp3.kTimes);
    BN_mod_sub(output->cipher, tmp2, kr1, key->n, ctx); // 出来的那个不能是0，否则0减去会有问题
    output->kTimes = 1;
    BN_CTX_end(ctx);
}

double decryptAndGetDouble(BIGNUM *input, int k, int kTimes, SHE_key *key, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    she_decryptBignum(plain, input, key, ctx);  // 采用截断技术吧，反正是打印
    int64_t plainInt;
    double plainDouble;
    for (int i = 0; i < kTimes - 1; ++i)  // 默认至少放大一倍
        BN_div_word(plain, k);
    BN_bn2lebinpad(plain, (unsigned char *)(&plainInt), sizeof(int64_t));  // 一次放大后不能大于int64_t
    if (BN_is_negative(plain)) {
        plainInt = -plainInt;
    }
    plainDouble = plainInt / 1.0;
    plainDouble = plainDouble / k;
    BN_CTX_end(ctx);
    return plainDouble;
}
using namespace std;

static string input_filename;
void init_filePath(){

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_number = dist(gen);
    input_filename = seccom::JoinPath(
        g_app_config.input_dir, std::to_string(random_number) + ".txt");
    cout << "选择的文件" << input_filename << endl;
    return;
}
// 读取文件中下一个浮点数函数-3.0 - 3.0
double readNextDoubleFromFile(){
    static ifstream file(input_filename);
    static bool fileEnded = false;

    if (fileEnded) {
        file.clear();  // 清除 EOF 标志
        file.seekg(0, ios::beg);  // 重新回到文件开头
        fileEnded = false;
    }

    double value;
    if (file >> value) {
        return value;
    } else {
        // 文件读取充值到开头
        fileEnded = true;
        return readNextDoubleFromFile();  // 重新读取
    }
}

void calTimePerformance(int k, SHE_key *key) {
    cout << "******************时间开销测试******************" << endl;
    // 前期准备工作
    srand((unsigned)time(0));
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    double r1 = 0;
    BIGNUM *tmp1Big;
    BIGNUM *tmp2Big;
    SHECipher tmp2;
    SHECipher tmp1;

    struct timeval t1;
    struct timeval t2;
    float timeuse = 0;

    for (int i = 0; i < g_app_config.cycle_num; ++i) {
        // TODO 修改这里变成文件读取
        r1 = readNextDoubleFromFile();
        tmp1Big = BN_CTX_get(ctx);
        tmp2Big = BN_CTX_get(ctx);
        BIGNUM *k2r1 = BN_CTX_get(ctx);

        tmp1.cipher = tmp1Big;
        tmp1.kTimes = 0;

        tmp2.cipher = tmp2Big;
        tmp2.kTimes = 0;
        BN_set_word(k2r1, (int)(k * r1));
        BN_mul_word(k2r1, k);
        tmp1.kTimes = 2;
        she_encryptBignumSupportNegative2(tmp1.cipher, k2r1, key, ctx);
        timeStart(&t1);
        sigmoidREETEE(&tmp2, &tmp1, k, key);
        timeuse += timeEnd2(&t1, &t2);
    }
    // 计算结果分析
    cout << "产生的明文随机值: " << r1 << endl;
    double res1 = 1.0 / (1 + exp(-r1));
    cout << "明文计算结果：" << res1 << endl;
    cout << "Sigmoid安全计算密文结果(部分): " << endl;
    bn_printfHex_part(tmp2.cipher, 1000);
    cout << endl;
    double res2 = decryptAndGetDouble(tmp2.cipher, k, tmp2.kTimes, key, ctx);
    cout << "解密后的协议计算结果: " << res2 << endl;
    cout << "差值百分比：" << (abs(res1 - res2) / res1) * 100.0 << endl;

    printf("重复%d次测试用时: %fs\n", g_app_config.cycle_num, timeuse / 1000000);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void testSHESUB(int k, SHE_key *key) {
    srand((unsigned)time(0));
    double r1 = getRandomDouble(0.0, 3.0);
    r1 = 0.5;
    double r2 = getRandomDouble(0.0, 3.0);
    r2 = 1.5;
    cout << "r1:" << r1 << endl;
    cout << "r2:" << r2 << endl;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmp3Big = BN_CTX_get(ctx);
    BIGNUM *k2r1 = BN_CTX_get(ctx);
    BIGNUM *k2r2 = BN_CTX_get(ctx);
    SHECipher tmp1;
    tmp1.cipher = tmp1Big;
    tmp1.kTimes = 0;
    SHECipher tmp2;
    tmp2.cipher = tmp2Big;
    tmp2.kTimes = 0;
    SHECipher tmp3;
    tmp3.cipher = tmp3Big;
    tmp3.kTimes = 0;
    BN_set_word(k2r1, (int)(k * r1));
    BN_mul_word(k2r1, k);
    tmp1.kTimes = 2;
    BN_set_word(k2r2, (int)(k * r2));
    BN_mul_word(k2r2, k);
    tmp2.kTimes = 2;
    she_encryptBignumSupportNegative2(tmp1.cipher, k2r1, key, ctx);
    she_encryptBignumSupportNegative2(tmp2.cipher, k2r2, key, ctx);
    BN_mod_sub(tmp3.cipher, tmp1.cipher, tmp2.cipher, key->n, ctx);
    tmp3.kTimes = 2;
    decPrint(tmp3.cipher);

    // 收尾
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calAccPerformance(int k, SHE_key *key) {
    cout << "******************准确度测试******************" << endl;
    srand((unsigned)time(0));
    double percenSum = 0.0;
    int times = 100;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *k2r1 = BN_CTX_get(ctx);
    SHECipher tmp1;
    tmp1.cipher = tmp1Big;
    tmp1.kTimes = 0;
    SHECipher tmp2;
    tmp2.cipher = tmp2Big;
    tmp2.kTimes = 0;
    cout << "展示最后3次的运行结果: " << endl;
    for (int i = 0; i < times; ++i) {
        double r1 = getRandomDouble(0.0, 5.0);
        BN_set_word(k2r1, (int)(k * r1));
        BN_mul_word(k2r1, k);
        tmp1.kTimes = 2;
        she_encryptBignumSupportNegative2(tmp1.cipher, k2r1, key, ctx);

        sigmoidREETEE(&tmp2, &tmp1, k, key);
        double res1 = 1.0 / (1 + exp(-r1));
        double res2 = decryptAndGetDouble(tmp2.cipher, k, tmp2.kTimes, key, ctx);
        percenSum += (abs(res1 - res2) / res1) * 100.0;
        if (i >= times - 3) {
            cout << "产生的明文随机值: " << r1 << endl;
            cout << "明文计算结果：" << res1 << endl;
            cout << "协议计算结果: " << res2 << endl;
            cout << "差值百分比：" << (abs(res1 - res2) / res1) * 100.0 << endl;
        }
    }
    cout << times << "次测试的平均精度偏差为：" << percenSum / times << endl;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
// 生成随机数
int expandSpace(BIGNUM *target, int bits, int increment = 0) {
    if (!BN_rand(target, bits + increment, 0, 0)) {
        printf("Error: Could not generate a random number.\n");
        return 1;
    }
    return 0;
}

void keySynthronizeREE(SHE_key *key) {
    invoke_keySynthronize(key->p, key->q, key->l, key->n, key->e_negative1, key->l_2, key->cipher_zero);
}

int main(int argc, char *argv[]) {
    (void)(argc);
    (void)(argv);
    try {
        g_app_config = LoadAppConfig();
    } catch (const std::exception &ex) {
        std::cerr << "load config failed: " << ex.what() << std::endl;
        return -1;
    }
    if (TEEC_SUCCESS != TeecInit()) {
        printf("TeecInit Failed!\n");
        return -1;
    }
    init_filePath();
    int k = g_app_config.k;
    invoke_she_generateRandomKeysTee2();
    she_generateRandomKeysTee2();
    // OK
    keySynthronizeREE(&KEY);
    calTimePerformance(k, &KEY);
    calAccPerformance(k, &KEY);

    TeecClose();
    return 0;
}

