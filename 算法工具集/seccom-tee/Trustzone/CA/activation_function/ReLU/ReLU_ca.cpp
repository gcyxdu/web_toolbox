/**
 * @author heqi
 * @date 21/10/2024
 * */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include "tee_client_api.h"
#include <fstream>
/*摘取的TestAPP的部分*/
#include "pwd.h"
#include <iostream>
#include <random>
#include "she.h"
#include "sheFloat.h"
#include <string>
#include "../../common/config_loader.hpp"

// da21c465-11dd-4c8d-862b-f0cbc4aff4df
static const TEEC_UUID TA_uuid = {
        0xda21c465, 0x11dd, 0x4c8d,
        { 0x86, 0x2b, 0xf0, 0xcb, 0xc4, 0xaf, 0xf4, 0xdf }
};

/*---------------常量内容----------------*/
#define __DEBUG__ 1

enum {
    sheRescale = 0,
    sheRescaleNeg,
    calRelu,
    keySynthronize,
    reluCipherMulTEE,
    SHEgenerateRandomKeysTee2,
};

/*-------------------------------------*/
TEEC_Context g_context;
TEEC_Session g_session;

// 共享内存池优化：使用预分配的共享内存，避免频繁malloc/free

// 共享内存池
#define SHARED_MEM_POOL_SIZE 16  // 16个共享内存槽位
#define SHARED_MEM_SIZE (1024 * 1024)  // 1MB per slot
static TEEC_SharedMemory g_shared_mem_pool[SHARED_MEM_POOL_SIZE];
static int g_shared_mem_initialized = 0;
static int g_shared_mem_index = 0;


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

// 获取共享内存槽位
static TEEC_SharedMemory* get_shared_memory_slot() {
    if (!g_shared_mem_initialized) {
        return nullptr;
    }
    
    TEEC_SharedMemory* slot = &g_shared_mem_pool[g_shared_mem_index];
    g_shared_mem_index = (g_shared_mem_index + 1) % SHARED_MEM_POOL_SIZE;
    return slot;
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

// void BN_printf(BIGNUM *num);
void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
void sheRefreshNeg(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
double decryptAndGetDouble(BIGNUM *input, int k, int kTimes, SHE_key *key, BN_CTX *ctx);
void reluCipherMul(BIGNUM *Eres, BIGNUM *Eb, BIGNUM *Em, int EmKTimes, SHE_key *key, int k, BN_CTX *ctx);

/**
 * 将 BIGNUM 转换为带符号的二进制格式并写入缓冲区
 * - 格式：[1字节符号][4字节长度][二进制数据]
 * - 符号：0=正数，1=负数
 * - 长度：二进制数据的字节数（大端序）
 * - 返回写入的总字节数
 */
static size_t bn_to_signed_bin_buffer(const BIGNUM *bn, unsigned char *buffer, size_t buffer_size) {
    if (bn == nullptr || buffer == nullptr || buffer_size < 6) {
        return 0; // 至少需要6字节：1字节符号 + 4字节长度 + 1字节数据
    }
    
    int is_negative = BN_is_negative(bn);
    int data_bytes = BN_num_bytes(bn);
    
    if (data_bytes == 0) {
        // 处理零的情况
        buffer[0] = 0; // 正数
        buffer[1] = 0; buffer[2] = 0; buffer[3] = 0; buffer[4] = 1; // 长度=1
        buffer[5] = 0; // 数据=0
        return 6;
    }
    
    if ((size_t)(5 + data_bytes) > buffer_size) {
        return 0; // 缓冲区太小
    }
    
    // 写入符号
    buffer[0] = is_negative ? 1 : 0;
    
    // 写入长度（大端序）
    buffer[1] = (data_bytes >> 24) & 0xFF;
    buffer[2] = (data_bytes >> 16) & 0xFF;
    buffer[3] = (data_bytes >> 8) & 0xFF;
    buffer[4] = data_bytes & 0xFF;
    
    // 写入二进制数据
    BIGNUM *abs_bn = BN_dup(bn);
    if (abs_bn == nullptr) return 0;
    
    if (is_negative) {
        BN_set_negative(abs_bn, 0); // 确保是正数
    }
    
    int written = BN_bn2bin(abs_bn, buffer + 5);
    BN_free(abs_bn);
    
    if (written != data_bytes) {
        return 0;
    }
    
    return 5 + data_bytes;
}

/**
 * 从带符号的二进制格式恢复 BIGNUM
 * - 格式：[1字节符号][4字节长度][二进制数据]
 * - 返回恢复的字节数，0表示失败
 */
static size_t bn_from_signed_bin_buffer(const unsigned char *buffer, size_t buffer_size, BIGNUM *bn) {
    if (buffer == nullptr || bn == nullptr || buffer_size < 6) {
        return 0;
    }
    
    // 读取符号
    int is_negative = buffer[0];
    
    // 读取长度（大端序）
    int data_bytes = (buffer[1] << 24) | (buffer[2] << 16) | (buffer[3] << 8) | buffer[4];
    
    if (data_bytes < 0 || (size_t)(5 + data_bytes) > buffer_size) {
        return 0;
    }
    
    if (data_bytes == 0) {
        BN_zero(bn);
        return 5;
    }
    
    // 从二进制数据恢复BIGNUM
    BIGNUM *temp = BN_bin2bn(buffer + 5, data_bytes, nullptr);
    if (temp == nullptr) {
        return 0;
    }
    
    // 设置符号
    if (is_negative) {
        BN_set_negative(temp, 1);
    }
    
    BN_copy(bn, temp);
    BN_free(temp);
    
    return 5 + data_bytes;
}


/**
 * 将 BIGNUM 的幅值以二进制（大端）写入调用方提供的缓冲区。
 * - out 中仅写入无符号幅值（不含负号）。
 * - 若需要符号，请通过 is_negative 输出参数获知并单独传递。
 * - 返回写入的字节数；失败返回 0。
 */
static size_t bn_to_bin_into_buffer(const BIGNUM *bn, unsigned char *out, size_t out_size, int *is_negative) {
    if (bn == nullptr || out == nullptr || out_size == 0) return 0;

    if (is_negative) {
        *is_negative = BN_is_negative(bn) ? 1 : 0;
    }

    if (BN_is_zero(bn)) {
        if (out_size < 1) return 0;
        out[0] = 0x00;
        return 1;
    }

    BIGNUM *abs_bn = BN_dup(bn);
    if (abs_bn == nullptr) return 0;
    if (BN_is_negative(abs_bn)) BN_set_negative(abs_bn, 0);

    int need = BN_num_bytes(abs_bn);
    if ((size_t)need > out_size) {
        BN_free(abs_bn);
        return 0;
    }
    int written = BN_bn2bin(abs_bn, out); // 大端，无前导零
    BN_free(abs_bn);
    if (written != need) return 0;
    return (size_t)written;
}


// 初始化TEE的g_context以及g_session
/* initialize context and opensession */
TEEC_Result TeecInit(void)
{

    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    result = TEEC_InitializeContext(nullptr, &g_context);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("teec initial failed");
        return result;
    }
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

    // 直接将 BIGNUM 转换为带符号二进制并写入input缓冲区
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
    operation.params[0].memref.size = input_size * 2;  // 输出可能需要更多空间
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input_mem;
    operation.params[1].memref.size = input_size;
    operation.params[1].memref.offset = 0;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;

    result = TEEC_InvokeCommand(&g_session,sheRescale,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    
    // 接收返回的参数 - 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    TEEC_Debug("invoke GenerateRandomCmd is successed.");
    return result;
}
TEEC_Result invoke_sheRescaleNeg(BIGNUM *output, BIGNUM *input, int k, int kTimes){

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

    // 直接将 BIGNUM 转换为带符号二进制并写入input缓冲区
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
    operation.params[0].memref.size = input_size * 2;  // 输出可能需要更多空间
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input_mem;
    operation.params[1].memref.size = input_size;
    operation.params[1].memref.offset = 0;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;

    result = TEEC_InvokeCommand(&g_session,sheRescaleNeg,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        cout <<"invoke_sheRescaleNeg失败"<< endl;
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    
    // 接收返回的参数 - 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    TEEC_Debug("invoke GenerateRandomCmd is successed.");
    return result;
}

TEEC_Result invoke_calRelu(BIGNUM *Eb1, BIGNUM *Eb2, BIGNUM *Em1) {
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    // 获取三个共享内存槽位
    TEEC_SharedMemory* mem1 = get_shared_memory_slot();
    TEEC_SharedMemory* mem2 = get_shared_memory_slot();
    TEEC_SharedMemory* mem3 = get_shared_memory_slot();
    if (mem1 == nullptr || mem2 == nullptr || mem3 == nullptr) {
        TEEC_Error("Failed to get shared memory slots");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_NONE
    );

    // 直接将 BIGNUM 转换为带符号二进制并写入缓冲区
    size_t size1 = bn_to_signed_bin_buffer(Eb1, (unsigned char *)mem1->buffer, SHARED_MEM_SIZE);
    size_t size2 = bn_to_signed_bin_buffer(Eb2, (unsigned char *)mem2->buffer, SHARED_MEM_SIZE);
    size_t size3 = bn_to_signed_bin_buffer(Em1, (unsigned char *)mem3->buffer, SHARED_MEM_SIZE);
    
    if (size1 == 0 || size2 == 0 || size3 == 0) {
        TEEC_Error("Failed to convert BIGNUM to signed binary or buffer too small");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    // 检查共享内存大小是否足够
    size_t max_size = max(max(size1, size2), size3);
    if (max_size * 2 > SHARED_MEM_SIZE) {
        TEEC_Error("Input too large for shared memory");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    operation.params[0].memref.parent = mem1;
    operation.params[0].memref.size = size1 * 2;
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = mem2;
    operation.params[1].memref.size = size2 * 2;
    operation.params[1].memref.offset = 0;
    operation.params[2].memref.parent = mem3;
    operation.params[2].memref.size = size3 * 2;
    operation.params[2].memref.offset = 0;

    // 调用 TEEC_InvokeCommand
    result = TEEC_InvokeCommand(&g_session, calRelu, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        cout<<"invoke_calRelu失败"<<endl;
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 直接将带符号二进制转换回原始的大数
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, Eb1) == 0 || 
        bn_from_signed_bin_buffer((unsigned char*)operation.params[1].memref.parent->buffer, 
                                  operation.params[1].memref.size, Eb2) == 0 || 
        bn_from_signed_bin_buffer((unsigned char*)operation.params[2].memref.parent->buffer, 
                                  operation.params[2].memref.size, Em1) == 0) {
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    TEEC_Debug("invoke_calRelu is successed.");
    return result;
}


static bool process_response_from_tee(char *combined_str, BIGNUM **p, BIGNUM **q, BIGNUM **l,
                                      BIGNUM **n, BIGNUM **e_negative1, BIGNUM **l_2,
                                      BIGNUM **cipher_zero, BIGNUM **cipher_one, const char *SEPARATOR) {
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

    token = strtok(NULL, SEPARATOR); // 分割第八部分（cipher_one）
    if (!BN_dec2bn(cipher_one, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    // 释放临时字符串
    free(str);

    return TEEC_SUCCESS;
}

TEEC_Result invoke_keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1, BIGNUM *l_2, BIGNUM *cipher_zero,
                                  BIGNUM *cipher_one){

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
    char * SEPARATOR = "||";

    // 为最终的长字符串分配内存
    char *combined_str = (char *)malloc(g_app_config.combined_str_len);
    if (combined_str == NULL) {
        printf("Memory allocation failed\n");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    operation.params[0].tmpref.buffer = combined_str;
    operation.params[0].tmpref.size = g_app_config.combined_str_len;

    result = TEEC_InvokeCommand(&g_session, keySynthronize, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        cout <<"invoke_keySynthronize失败"<<endl;
        printf("invoke_keySynthronize failed, codes=0x%x, origin=0x%x\n", result, origin);
    }
    // 分割之后重新传递值
    bool ok = process_response_from_tee(combined_str, &p, &q, &l, &n, &e_negative1, &l_2,
                                                   &cipher_zero, &cipher_one, SEPARATOR);

    free(combined_str);
    return result;
}



TEEC_Result invoke_reluCipherMulTEE(BIGNUM *output, BIGNUM *Eb, BIGNUM *Em, int k, int EmTimes){

    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    
    // 获取三个共享内存槽位
    TEEC_SharedMemory* output_mem = get_shared_memory_slot();
    TEEC_SharedMemory* input_mem1 = get_shared_memory_slot();
    TEEC_SharedMemory* input_mem2 = get_shared_memory_slot();
    if (output_mem == nullptr || input_mem1 == nullptr || input_mem2 == nullptr) {
        TEEC_Error("Failed to get shared memory slots");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_VALUE_INPUT
    );

    // 直接将 BIGNUM 转换为带符号二进制并写入缓冲区
    size_t size2 = bn_to_signed_bin_buffer(Eb, (unsigned char *)input_mem1->buffer, SHARED_MEM_SIZE);
    size_t size3 = bn_to_signed_bin_buffer(Em, (unsigned char *)input_mem2->buffer, SHARED_MEM_SIZE);
    
    if (size2 == 0 || size3 == 0) {
        TEEC_Error("Failed to convert BIGNUM to signed binary or buffer too small");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    // 检查共享内存大小是否足够
    size_t max_size = max(size2, size3);
    if (max_size * 2 > SHARED_MEM_SIZE) {
        TEEC_Error("Input too large for shared memory");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    operation.params[0].memref.parent = output_mem;
    operation.params[0].memref.size = max_size * 2;
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input_mem1;
    operation.params[1].memref.size = size2;
    operation.params[1].memref.offset = 0;
    operation.params[2].memref.parent = input_mem2;
    operation.params[2].memref.size = size3;
    operation.params[2].memref.offset = 0;
    operation.params[3].value.a = k;
    operation.params[3].value.b = EmTimes;

    result = TEEC_InvokeCommand(&g_session,reluCipherMulTEE,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        cout << "invoke_reluCipherMulTEE 失败" << endl;
        printf("invoke invoke_reluCipherMulTEE failed, codes=0x%x, origin=0x%x\n", result, origin);
        return result;
    }
    
    // 数值返回回来 - 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    TEEC_Debug("invoke invoke_reluCipherMulTEE is successed.");
    return result;
}
// 虚假的操作，仍然在REE操作调用，暂时这样处理过程OK
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
        printf("invoke invoke_she_generateRandomKeysTee2 failed, codes=0x%x, origin=0x%x\n", result, origin);
        return result;
    }

    TEEC_Debug("invoke invoke_she_generateRandomKeysTee2 is successed.")
    return result;
}

/**---------------------复制的内容------------------------*/

// 统计时间
void timeStart(struct timeval *timePointer) {
    gettimeofday(timePointer, NULL);
}
// 统计时间
void timeEnd(struct timeval *timePointer1, struct timeval *timePointer2) {
    float timeuse;
    gettimeofday(timePointer2, NULL);
    timeuse = (timePointer2->tv_sec - timePointer1->tv_sec) * 1000000 + timePointer2->tv_usec - timePointer1->tv_usec;
    printf("cost time(s):%f\n", timeuse / 1000000);
}
// 统计时间
float timeEnd2(struct timeval *timePointer1, struct timeval *timePointer2) {
    float timeuse;
    gettimeofday(timePointer2, NULL);
    timeuse = (timePointer2->tv_sec - timePointer1->tv_sec) * 1000000 + timePointer2->tv_usec - timePointer1->tv_usec;
    return timeuse;
}

double decryptAndGetDouble(BIGNUM *input, int k, int kTimes, SHE_key *key, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    she_decryptBignum(plain, input, key, ctx);
    int64_t plainInt;
    double plainDouble;
    for (int i = 0; i < kTimes - 1; ++i) {
        BN_div_word(plain, k);
    }
    BN_bn2lebinpad(plain, (unsigned char *)(&plainInt), sizeof(int64_t));
    if (BN_is_negative(plain)) {
        plainInt = -plainInt;
    }
    plainDouble = plainInt / 1.0;
    plainDouble = plainDouble / k;
    BN_CTX_end(ctx);
    return plainDouble;
}
// 获取随机数引擎
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

// 例如: E(k^5x)+k^5r进去TEE, TEE解密再加密出来为E(k(x+r)), 那么REE应该计算E(k(x+r))-kr
void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx) {
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
    BN_copy(tmp2, key->n);
    invoke_sheRescale( tmp2, tmp3.cipher, k, tmp3.kTimes);
    BN_mod_sub(output->cipher, tmp2, kr1, key->n, ctx);
    output->kTimes = 1;
    BN_CTX_end(ctx);
}
void sheRefreshNeg(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx) {
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
    BN_copy(tmp2, key->n);
    invoke_sheRescaleNeg(tmp2, tmp3.cipher, k, tmp3.kTimes);
    BN_mod_add(output->cipher, tmp2, kr1, key->n, ctx);
    output->kTimes = 1;
    BN_CTX_end(ctx);
}
void reluREETEE(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *Eb1Big = BN_CTX_get(ctx); // E(b')
    BIGNUM *Eb2Big = BN_CTX_get(ctx); // E(b'')
    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big, 0);

    double r1 = getRandomDouble(3.0, 6.0);
    double r2 = getRandomDouble(0.0, 3.0);
    int64_t kr2Int = k * r2;
    srand((unsigned)time(nullptr));
    int b_int = rand() % 2 == 0 ? 1 : -1;
    BIGNUM *kr2 = BN_CTX_get(ctx);
    BN_set_word(kr2, kr2Int);
    if (BN_is_zero(input->cipher)) {
        BN_copy(input->cipher, key->cipher_zero);
    }
    sheMULConstant(&tmp1, r1, input, k, key, ctx);

    BN_mod_add(tmp2Big, kr2, tmp1.cipher, key->n, ctx);
    tmp1.cipher = tmp2Big;
    if (b_int == -1) {
        // 调用负的
        sheRefreshNeg(&tmp1, &tmp1, k, key, ctx);
    }
    BN_copy(Eb1Big, key->n);
    BN_copy(Eb2Big, key->n);

    invoke_calRelu(Eb1Big, Eb2Big, tmp1.cipher);
    if (b_int == 1) {
        reluCipherMul(tmp1.cipher, Eb1Big, input->cipher, input->kTimes, key, k, ctx);
        tmp1.kTimes = 1;
    } else {
        reluCipherMul(tmp1.cipher, Eb2Big, input->cipher, input->kTimes, key, k, ctx);
        tmp1.kTimes = 1;
    }
    // 调用正的
    sheRefresh(&tmp1, &tmp1, k, key, ctx);
    sheSETC(res, &tmp1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
void HACIpoly4Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    BIGNUM *tmpx4Big = BN_CTX_get(ctx);

    SHECipher tmp1;
    sheInitC(&tmp1, tmp1Big);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big);
    SHECipher tmpx1;
    sheInitC(&tmpx1, tmpx1Big);
    SHECipher tmpx2;
    sheInitC(&tmpx2, tmpx2Big);
    SHECipher tmpx4;
    sheInitC(&tmpx4, tmpx4Big);

    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    sheMULCC(&tmpx4, &tmpx2, &tmpx2, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

    // 乘以系数并相加
    sheMULConstant(&tmpx1, 0.5, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 0.234606, &tmpx1, k, key, ctx);

    sheMULConstant(&tmpx2, 0.204875, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheMULConstant(&tmpx4, 0.0063896, &tmpx4, k, key, ctx);
    sheNEGC(&tmpx4, &tmpx4, k, key, ctx);
    sheRefresh(&tmpx4, &tmpx4, k, key, ctx);
    sheADDCC(&tmp1, &tmpx4, &tmp2, k, key, ctx);

    sheSETC(res, &tmp1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
static string input_filename;
void init_filePath(){

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_number = dist(gen);
    input_filename = seccom::JoinPath(g_app_config.input_dir, std::to_string(random_number) + ".txt");
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
        // cout << "r1:" << r1 << endl;  // 注释掉避免大量输出
        tmp1Big = BN_CTX_get(ctx);
        tmp2Big = BN_CTX_get(ctx);
        BIGNUM *k2r1 = BN_CTX_get(ctx);

        tmp1.cipher = tmp1Big;
        tmp1.kTimes = 0;

        tmp2.cipher = tmp2Big;
        tmp2.kTimes = 0;
        if (r1 < 0) {
            BN_set_word(k2r1, (int)(k * (-r1)));
            BN_set_negative(k2r1, 1);
        } else {
            BN_set_word(k2r1, (int)(k * (r1)));
        }
        BN_mul_word(k2r1, k);
        tmp1.kTimes = 2;
        she_encryptBignumSupportNegative2(tmp1.cipher, k2r1, key, ctx);

        // 在这里计算时间
        timeStart(&t1);
        reluREETEE(&tmp2, &tmp1, k, key);
        timeuse += timeEnd2(&t1, &t2);
    }
    // 计算结果分析
    cout << "产生的明文随机值: " << r1 << endl;
    double res1 = r1 > 0 ? r1 : 0.0;
    cout << "明文计算结果：" << res1 << endl;
    cout << "ReLU安全计算密文结果(部分): " << endl;
    bn_printfHex_part(tmp2.cipher, 1000);
    double res2 = decryptAndGetDouble(tmp2.cipher, k, tmp2.kTimes, key, ctx);
    cout << endl;
    cout << "解密后的协议计算结果: " << res2 << endl;
    cout << "差值：" << abs(res1 - res2) << endl;

    printf("重复%d次测试用时: %fs\n", g_app_config.cycle_num, timeuse / 1000000);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// 测试准确度
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
    cout << "展示最后5次的运行结果: " << endl;
    for (int i = 0; i < times; ++i) {
        double r1 = getRandomDouble(-3.0, 3.0);
        if (r1 < 0) {
            BN_set_word(k2r1, (int)(k * (-r1)));
            BN_set_negative(k2r1, 1);
        } else {
            BN_set_word(k2r1, (int)(k * (r1)));
        }
        BN_mul_word(k2r1, k);
        tmp1.kTimes = 2;
        she_encryptBignumSupportNegative2(tmp1.cipher, k2r1, key, ctx);

        reluREETEE(&tmp2, &tmp1, k, key);

        // 计算结果分析
        double res1 = r1 > 0 ? r1 : 0;
        double res2 = decryptAndGetDouble(tmp2.cipher, k, tmp2.kTimes, key, ctx);
        percenSum += abs(res1 - res2);
        if (i >= times - 5) {
            cout << "产生的明文随机值: " << r1 << endl;
            cout << "明文计算结果：" << res1 << endl;
            // decPrint(tmp2.cipher);
            cout << "协议计算结果：" << res2 << endl;
            double percent = res1 != 0 ? (abs(res1 - res2) / res1) * 100.0 : 0.0;
            cout << "差值百分比：" << percent << endl;
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
    invoke_keySynthronize(key->p, key->q, key->l, key->n, key->e_negative1, key->l_2, key->cipher_zero,
                   key->cipher_one);
}

void reluCipherMul(BIGNUM *Eres, BIGNUM *Eb, BIGNUM *Em, int EmKTimes, SHE_key *key, int k, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *r1 = BN_CTX_get(ctx);
    BIGNUM *r2 = BN_CTX_get(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmp3Big = BN_CTX_get(ctx);
    BIGNUM *tmp4Big = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    SHECipher tmp1;
    BN_copy(tmp1Big, Em);
    sheInitC(&tmp1, tmp1Big, EmKTimes);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big, 0);

    sheRefresh(&tmp1, &tmp1, k, key, ctx);
    int r1_int = rand() % 10 + 1;
    r1_int = 10;
    int r2_int = rand() % 8 + 1;
    r2_int = 5;
    BN_set_word(r1, r1_int);
    BN_set_word(r2, r2_int);

    BN_sub(tmp3Big, Eb, r1);
    BN_sub(tmp2.cipher, tmp1.cipher, r2);
    tmp2.kTimes = 1;

    BN_copy(res, key->n);
    invoke_reluCipherMulTEE( res, tmp3Big, tmp2.cipher, k, tmp2.kTimes);
    BN_mod_mul(tmp3Big, Eb, r2, key->n, ctx);
    BN_mod_add(tmp4Big, res, tmp3Big, key->n, ctx);

    BN_mod_mul(tmp3Big, tmp1.cipher, r1, key->n, ctx);
    BN_mod_add(res, tmp4Big, tmp3Big, key->n, ctx);

    BN_mul(tmp3Big, r2, r1, ctx);
    BN_mod_sub(tmp4Big, res, tmp3Big, key->n, ctx);

    BN_copy(Eres, tmp4Big);
    BN_CTX_end(ctx);
}

int main(int argc, char *argv[] ){
    // 代表使用了一下
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
    int k = g_app_config.k;
    init_filePath();
    // 模拟在TA侧开一遍函数运行
    invoke_she_generateRandomKeysTee2();
    she_generateRandomKeysTee2();
    keySynthronizeREE(&KEY);

    calTimePerformance(k, &KEY);
    calAccPerformance(k, &KEY);

    TeecClose();
    return 0;
}
