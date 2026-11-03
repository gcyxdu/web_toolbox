/**
 * @author heqi
 * @date 09/01/2025
 * */

#include <cstdio>
#include <cstdlib>
#include <sys/time.h>
#include "tee_client_api.h"
#include <fstream>
/*摘取的TestAPP的部分*/
#include "pwd.h"
#include <iostream>
#include <random>
#include "she.h"
#include "sheFloat.h"
#include "string"
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
    calEx,
    keySynthronize,
    getFraction,
    reluCipherMulTEE,
    SHEgenerateRandomKeysTee2,
};
/*-------------------------------------*/
TEEC_Context g_context;
TEEC_Session g_session;
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

void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
void sheRefreshNeg(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
double decryptAndGetDouble(BIGNUM *input, int k, int kTimes, SHE_key *key, BN_CTX *ctx);
void reluCipherMul(BIGNUM *Eres, BIGNUM *Eb, BIGNUM *Em, int EmKTimes, SHE_key *key, int k, BN_CTX *ctx);
void BN_printf(BIGNUM *num);

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

void polyCmpMethod(SHECipher *res, SHECipher *input, int dim, int k, int polyTimes, SHE_key *key);

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
TEEC_Result invoke_calEx(BIGNUM *output, BIGNUM *input, int k, int kTimes){
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

    result = TEEC_InvokeCommand(&g_session,calEx,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        cout << "invoke_calEx 失败"<<endl;
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

// 处理字符串的函数
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


TEEC_Result invoke_keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1, BIGNUM *l_2, BIGNUM *cipher_zero, BIGNUM *cipher_one){

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

    char *combined_str = (char *)malloc(g_app_config.combined_str_len);
    if (combined_str == NULL) {
        TEEC_Error("Memory allocation failed");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    operation.params[0].tmpref.buffer = combined_str;
    operation.params[0].tmpref.size = g_app_config.combined_str_len;

    result = TEEC_InvokeCommand(&g_session, keySynthronize, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        cout <<"invoke_keySynthronize失败"<<endl;
        TEEC_Error("invoke_keySynthronize failed, codes=0x%x, origin=0x%x", result, origin);
    }
    // 分割之后重新传递值
    bool ok = process_response_from_tee(combined_str, &p, &q, &l, &n, &e_negative1, &l_2,
                                                     &cipher_zero, &cipher_one, SEPARATOR);
    free(combined_str);
    return result;
}
TEEC_Result invoke_getFraction(BIGNUM *res1, BIGNUM *res2, BIGNUM *input1, BIGNUM *input2, int k_times){
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    // 获取三个共享内存槽位：两个给input，一个给output
    TEEC_SharedMemory* input1_mem = get_shared_memory_slot();
    TEEC_SharedMemory* input2_mem = get_shared_memory_slot();
    TEEC_SharedMemory* output_mem = get_shared_memory_slot();
    if (input1_mem == nullptr || input2_mem == nullptr || output_mem == nullptr) {
        TEEC_Error("Failed to get shared memory slots");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_PARTIAL_INOUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_MEMREF_PARTIAL_INPUT,
            TEEC_VALUE_INPUT
    );

    // 直接将 BIGNUM 转换为带符号二进制并写入缓冲区
    size_t size1 = bn_to_signed_bin_buffer(input1, (unsigned char *)input1_mem->buffer, SHARED_MEM_SIZE);
    size_t size2 = bn_to_signed_bin_buffer(input2, (unsigned char *)input2_mem->buffer, SHARED_MEM_SIZE);
    
    if (size1 == 0 || size2 == 0) {
        TEEC_Error("Failed to convert BIGNUM to signed binary or buffer too small");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    
    // 检查共享内存大小是否足够
    size_t max_size = max(size1, size2);
    if (max_size * 2 > SHARED_MEM_SIZE) {
        TEEC_Error("Input too large for shared memory");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    operation.params[0].memref.parent = output_mem;
    operation.params[0].memref.size = max_size * 2;
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = input1_mem;
    operation.params[1].memref.size = size1;
    operation.params[1].memref.offset = 0;
    operation.params[2].memref.parent = input2_mem;
    operation.params[2].memref.size = size2;
    operation.params[2].memref.offset = 0;
    operation.params[3].value.a = k_times;

    result = TEEC_InvokeCommand(&g_session,getFraction,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        cout << "invoke_getFraction 失败" << endl;
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, res1) == 0){
        cout << "Failed to convert signed binary to BIGNUM for res1" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    // 对于第二个结果，我们需要从输出缓冲区的后半部分读取
    // 这里假设TA侧返回的是两个连续的带符号二进制数据
    // 先计算res1的大小
    int res1_data_bytes = BN_num_bytes(res1);
    int res1_is_negative = BN_is_negative(res1);
    size_t res1_size = (res1_data_bytes == 0) ? 6 : (5 + res1_data_bytes); // 计算res1的完整大小
    
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer + res1_size, 
                                  operation.params[0].memref.size - res1_size, res2) == 0){
        cout << "Failed to convert signed binary to BIGNUM for res2" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

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
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    
    // 数值返回回来 - 从带符号二进制转换回BIGNUM
    if (bn_from_signed_bin_buffer((unsigned char*)operation.params[0].memref.parent->buffer, 
                                  operation.params[0].memref.size, output) == 0){
        cout << "Failed to convert signed binary to BIGNUM" <<endl;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    TEEC_Debug("invoke GenerateRandomCmd is successed.");
    return result;
}
TEEC_Result invoke_SHEgenerateRandomKeysTee2(){
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
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    TEEC_Debug("invoke GenerateRandomCmd is successed.")
    return result;
}

/*--------------------------------------------------------*/
// 搞一个随机生成浮点数的函数
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
    // bn_printfHex(plain);
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


// 求和得分母
// getSoftmax1(tmp1, sumEx, input, dim, k, key);
void getSoftmax1(SHECipher *output, BIGNUM *sumEx, SHECipher *input, int dim, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    double r1;
    BIGNUM **tmp1Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    SHECipher *tmp1 = (SHECipher *)malloc(sizeof(SHECipher) * dim);
    for (int i = 0; i < dim; ++i) {
        tmp1Big[i] = BN_CTX_get(ctx);
        sheInitC(&tmp1[i], tmp1Big[i]);
    }
    BN_zero(sumEx);
    for (int i = 0; i < dim; ++i) {
        r1 = getRandomDouble(-2.0, 3.0);
        sheADDConstant(&tmp1[i], r1, &input[i], k, key, ctx);
        invoke_calEx(tmp1[i].cipher, tmp1[i].cipher, k,
              tmp1[i].kTimes);  // 出来是k*e^(x+r1)
        tmp1[i].kTimes = 1;
        sheMULConstant(&tmp1[i], exp(-r1), &tmp1[i], k, key,
                       ctx);  // tmp1[i]里面是E(k^2*e^x)
        sheSETC(&output[i], &tmp1[i]);
        BN_mod_add(sumEx, sumEx, tmp1[i].cipher, key->n, ctx);
    }
    // cout << "他们的和为：" << endl;
    // decPrint(sumEx);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// 半诚实下算softmax,k的平方进来，k的3次方出去
void getSoftmax2(SHECipher *res, SHECipher *input, SHECipher *sumEx, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    double r1, r2;
    SHECipher tmp1, tmp2, tmp3;
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmp3Big = BN_CTX_get(ctx);
    sheInitC(&tmp1, tmp1Big);
    sheInitC(&tmp2, tmp2Big);
    sheInitC(&tmp3, tmp3Big);

    r1 = getRandomDouble(exp(1.0), exp(2.0));
    r2 = getRandomDouble(1.0, 3.0);
    sheADDConstant(&tmp1, -r1, input, k, key, ctx);  // 掩盖分子,得到k2*(e^x-r1)
    // cout << decryptAndGetDouble(tmp1.cipher, k, tmp1.kTimes, key, ctx) << endl;
    sheMULConstant(&tmp2, r2, sumEx, k, key, ctx);  // 掩盖分母,得到k*r2*k2*sigma()
    invoke_getFraction(tmp1.cipher, tmp2.cipher, tmp1.cipher, tmp2.cipher, k);
    tmp1.kTimes = 2;
    tmp2.kTimes = 1;
    // cout << decryptAndGetDouble(tmp1.cipher, k, tmp1.kTimes, key, ctx) << endl;
    // cout << decryptAndGetDouble(tmp2.cipher, k, tmp2.kTimes, key, ctx) << endl;
    sheMULConstant(&tmp2, r1, &tmp2, k, key, ctx);  // 得到k^2*[r1/r2*sigma()]
    sheADDCC(&tmp3, &tmp1, &tmp2, k, key, ctx);     // 得到k^2*[e^x/r2*sigma()]
    sheMULConstant(&tmp2, r2, &tmp3, k, key, ctx);  // 得到k^3*[e^x/sigma()]
    sheSETC(res, &tmp2);
    // sleep(10000);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// 半诚实下算softmax,乘法深度至少得是1
// input 和 res可以一样
void softmaxREETEE(SHECipher *res, SHECipher *input, int dim, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *sumExBig = BN_CTX_get(ctx);
    SHECipher sumEx;
    sheInitC(&sumEx, sumExBig);
    BIGNUM **tmp1Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    SHECipher *tmp1 = (SHECipher *)malloc(sizeof(SHECipher) * dim);
    for (int i = 0; i < dim; ++i) {
        tmp1Big[i] = BN_CTX_get(ctx);
        sheInitC(&tmp1[i], tmp1Big[i]);
    }
    getSoftmax1(tmp1, sumExBig, input, dim, k, key);
    sumEx.kTimes = 2;
    for (int i = 0; i < dim; ++i) {
        // k平方进，k3次方出来
        getSoftmax2(&res[i], &tmp1[i], &sumEx, k, key);
        sheRefresh(&res[i], &res[i], k, key, ctx);
    }
    // sleep(10000);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly2coeff = [0.117071,0.5,0.375373]
void HACIpoly2Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
    // BIGNUM *tmpx3Big = BN_CTX_get(ctx);
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


    sheSETC(&tmpx1, input);

    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 0.5, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 0.375373, &tmpx1, k, key, ctx);  // ax+b

    sheMULConstant(&tmpx2, 0.117071, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheSETC(res, &tmp2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly2coeff = [0.131,0.5007,0.357]
void TensorHEpoly2Comp(SHECipher *res, SHECipher *input, int k, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *tmpx1Big = BN_CTX_get(ctx);
    BIGNUM *tmpx2Big = BN_CTX_get(ctx);
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

    sheSETC(&tmpx1, input);
    sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
    sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 0.5007, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 0.357, &tmpx1, k, key, ctx);  // ax+b
    sheMULConstant(&tmpx2, 0.131, &tmpx2, k, key, ctx);
    sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

    sheSETC(res, &tmp2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly4coeff = [-0.0063896,0,0.204875,0.5,0.234606]
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

    // 开始乘以系数并相加
    sheMULConstant(&tmpx1, 0.5, &tmpx1, k, key, ctx);
    sheADDConstant(&tmp1, 0.234606, &tmpx1, k, key, ctx);  // ax+b

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
    BN_copy(tmp2, key->n); // 这个是为了保证出来有空间
    invoke_sheRescale(tmp2, tmp3.cipher, k, tmp3.kTimes);
    BN_mod_sub(output->cipher, tmp2, kr1, key->n, ctx); // 出来的那个不能是0，否则0减去会有问题
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

double decryptAndGetDouble(BIGNUM *input, int k, int kTimes, SHE_key *key, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    she_decryptBignum(plain, input, key, ctx);  // 采用截断技术吧，反正是打印
    // bn_printfDec(plain);
    int64_t plainInt;
    double plainDouble;
    for (int i = 0; i < kTimes - 1; ++i)  // 默认至少放大一倍
        BN_div_word(plain, k);
    BN_bn2lebinpad(plain, (unsigned char *)(&plainInt),
                   sizeof(int64_t));  // 一次放大后不能大于int64_t
    if (BN_is_negative(plain)) {
        plainInt = -plainInt;
    }
    plainDouble = plainInt / 1.0;
    plainDouble = plainDouble / k;
    BN_CTX_end(ctx);
    return plainDouble;
}

void softmaxPlain(double *output, double *input, int dim) {
    double *tmp1 = (double *)malloc(sizeof(double) * dim);
    double exSum = 0.0;
    for (int i = 0; i < dim; ++i) {
        tmp1[i] = exp(input[i]);
        exSum += tmp1[i];
    }
    for (int i = 0; i < dim; ++i) {
        output[i] = tmp1[i] / exSum;
    }
}

// 定义输出数组元素并以逗号分隔的函数
void printDoubleArray(const double *arr, size_t size) {
    if (size == 0) {
        return;
    }

    for (size_t i = 0; i < size; ++i) {
        // 输出元素并以逗号分隔
        std::cout << arr[i];

        // 最后一个元素后面不加逗号
        if (i != size - 1) {
            std::cout << ", ";
        }
    }

    std::cout << std::endl;
}
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
    int dim = 3;
    double *arr1 = (double *)malloc(sizeof(double) * dim);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM **tmp1Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    BIGNUM **tmp2Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    BIGNUM **k2arr1 = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    SHECipher *tmp1 = (SHECipher *)malloc(sizeof(SHECipher) * dim);
    SHECipher *tmp2 = (SHECipher *)malloc(sizeof(SHECipher) * dim);

    struct timeval t1;
    struct timeval t2;
    float timeuse = 0;

    for (int i = 0; i < g_app_config.cycle_num; ++i) {
        for (int i = 0; i < dim; ++i) {
            arr1[i] = readNextDoubleFromFile();
            tmp1Big[i] = BN_CTX_get(ctx);
            tmp2Big[i] = BN_CTX_get(ctx);
            k2arr1[i] = BN_CTX_get(ctx);
            sheInitC(&tmp1[i], tmp1Big[i]);
            sheInitC(&tmp2[i], tmp2Big[i]);
            if (arr1[i] < 0) {
                BN_set_word(k2arr1[i], (int)(k * (-arr1[i])));
                BN_set_negative(k2arr1[i], 1);
            } else {
                BN_set_word(k2arr1[i], (int)(k * (arr1[i])));
            }
            BN_mul_word(k2arr1[i], k);
            she_encryptBignumSupportNegative2(tmp1[i].cipher, k2arr1[i], key, ctx);
            tmp1[i].kTimes = 2;
        }
        timeStart(&t1);
        softmaxREETEE(tmp2, tmp1, dim, k, key);
        timeuse += timeEnd2(&t1, &t2);
    }

    double *res1 = (double *)malloc(sizeof(double) * dim);
    double *res2 = (double *)malloc(sizeof(double) * dim);
    softmaxPlain(res1, arr1, dim);
    for (int i = 0; i < dim; ++i) {
        res2[i] = decryptAndGetDouble(tmp2[i].cipher, k, tmp2[i].kTimes, key, ctx);
    }
    cout << "产生的明文随机值: ";
    printDoubleArray(arr1, dim);
    cout << "明文计算结果：";
    printDoubleArray(res1, dim);
    cout << "Softmax安全计算密文结果(部分): " << endl;
    for (int i = 0; i < dim; ++i) {
        cout << "arr[" << i << "]: " << endl;
        bn_printfHex_part(tmp2[i].cipher, 600);
        cout << endl;
    }
    cout << "解密后的协议计算结果: ";
    printDoubleArray(res2, dim);
    double percent = 0;
    for (int i = 0; i < dim; ++i) {
        percent += abs((res1[i] - res2[i]) / res1[i]) * 100.0;
    }
    cout << "差值百分比：" << percent / dim << endl;

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

void testSHEMulOne(int k, SHE_key *key) {
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

    BN_mod_mul(tmp3.cipher, tmp1.cipher, KEY.cipher_one, key->n, ctx);
    tmp3.kTimes = 2;
    decPrint(tmp3.cipher);
    cout << "kq" << BN_num_bits(KEY.q) << endl;
    cout << "kp" << BN_num_bits(KEY.p) << endl;

    // 收尾
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calAccPerformance(int k, SHE_key *key) {
    cout << "******************准确度测试******************" << endl;
    srand((unsigned)time(0));
    int times = 100;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    int dim = 3;
    double *arr1 = (double *)malloc(sizeof(double) * dim);
    BIGNUM **tmp1Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    BIGNUM **tmp2Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    BIGNUM **k2arr1 = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    SHECipher *tmp1 = (SHECipher *)malloc(sizeof(SHECipher) * dim);
    SHECipher *tmp2 = (SHECipher *)malloc(sizeof(SHECipher) * dim);
    for (int i = 0; i < dim; ++i) {
        tmp1Big[i] = BN_CTX_get(ctx);
        tmp2Big[i] = BN_CTX_get(ctx);
        k2arr1[i] = BN_CTX_get(ctx);
        sheInitC(&tmp1[i], tmp1Big[i]);
        sheInitC(&tmp2[i], tmp2Big[i]);
    }

    double deltaSum = 0.0;
    cout << "展示最后3次的运行结果: " << endl;
    for (int i = 0; i < times; ++i) {
        for (int i = 0; i < dim; ++i) {
            arr1[i] = getRandomDouble(-3.0, 3.0);
            if (arr1[i] < 0) {
                BN_set_word(k2arr1[i], (int)(k * (-arr1[i])));
                BN_set_negative(k2arr1[i], 1);
            } else {
                BN_set_word(k2arr1[i], (int)(k * (arr1[i])));
            }
            BN_mul_word(k2arr1[i], k);
            she_encryptBignumSupportNegative2(tmp1[i].cipher, k2arr1[i], key, ctx);
            tmp1[i].kTimes = 2;
        }

        double *res1 = (double *)malloc(sizeof(double) * dim);
        double *res2 = (double *)malloc(sizeof(double) * dim);
        softmaxPlain(res1, arr1, dim);

        softmaxREETEE(tmp2, tmp1, dim, k, key);
        for (int i = 0; i < dim; ++i) {
            res2[i] = decryptAndGetDouble(tmp2[i].cipher, k, tmp2[i].kTimes, key, ctx);
            deltaSum += abs((res1[i] - res2[i]) / res1[i]) * 100.0;
        }
        if (i >= times - 3) {
            cout << "产生的明文随机值: ";
            printDoubleArray(arr1, dim);
            cout << "明文计算结果：";
            printDoubleArray(res1, dim);
            cout << "协议计算结果: ";
            printDoubleArray(res2, dim);
            double percent = 0;
            for (int i = 0; i < dim; ++i) {
                percent += abs((res1[i] - res2[i]) / res1[i]) * 100.0;
            }
            cout << "差值百分比：" << percent / dim << endl;
        }
    }
    cout << times << "次测试的平均精度偏差为：" << deltaSum / (times * dim) << endl;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void checkPrimePrintBits(BIGNUM *input) {
    if (input == NULL) {
        cout << "空指针" << endl;
    }
    int is_prime = BN_is_prime_ex(input, BN_prime_checks, NULL, NULL);
    if (is_prime == 1) {
        printf("The number is prime.\n");
        BN_printf(KEY.q);
        printf("\n");
    } else if (is_prime == 0) {
        printf("The number is not prime.\n");
    } else {
        printf("Error occurred during prime test.\n");
    }
    cout << "大数位数：" << BN_num_bits(input) << endl;
}

// expand的基础也是你先得开创好了啊。。。
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

// 本来按理说应该实现下SHE交互式乘法的，但时间很紧张，先用这个用一下
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

    sheRefresh(&tmp1, &tmp1, k, key,
               ctx);  // 变成只有一倍扩张,扰动前的变量需要保存，因为后面恢复需要
    int r1_int = rand() % 10 + 1;
    r1_int = 10;
    int r2_int = rand() % 8 + 1;
    r2_int = 5;
    BN_set_word(r1, r1_int);  // 掩盖Eb
    BN_set_word(r2, r2_int);

    BN_sub(tmp3Big, Eb, r1);  // 扰动Eb
    // decPrint(tmp3Big);
    BN_sub(tmp2.cipher, tmp1.cipher,
           r2);  // tmp2为扰动后的Em，tmp1为扰动前扩大次数为1的m
    tmp2.kTimes = 1;
    BN_copy(res, key->n);
    invoke_reluCipherMulTEE(res, tmp3Big, tmp2.cipher, k,
                     tmp2.kTimes);  // res就是(b-r1)(km+r2)

    BN_mod_mul(tmp3Big, Eb, r2, key->n, ctx);  // Eb*r2
    BN_mod_add(tmp4Big, res, tmp3Big, key->n, ctx);
    BN_mod_mul(tmp3Big, tmp1.cipher, r1, key->n, ctx);  // Ekm_*r1
    BN_mod_add(res, tmp4Big, tmp3Big, key->n, ctx);

    BN_mul(tmp3Big, r2, r1, ctx);  // r1*r2
    BN_mod_sub(tmp4Big, res, tmp3Big, key->n, ctx);

    BN_copy(Eres, tmp4Big);
    BN_CTX_end(ctx);
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
    invoke_SHEgenerateRandomKeysTee2();
    she_generateRandomKeysTee2();
    keySynthronizeREE(&KEY);
    calTimePerformance(k, &KEY);
    calAccPerformance(k, &KEY);
    TeecClose();
    return 0;
}

void BN_printf(BIGNUM *num) {
    char *tmp = NULL;
    tmp = BN_bn2dec(num);
    printf("%s", tmp);
    // printf("\n");
}

// 下面全是多项式逼近的方法
//  poly3coeff = [0.21713332 ,0.86969832 ,0.98157042 ,0.67070608]
void poly3Comp(SHECipher *res, BIGNUM *sumEx, SHECipher *input, int dim, int k, SHE_key *key) {
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

    BN_zero(sumEx);
    for (int i = 0; i < dim; ++i) {
        sheSETC(&tmpx1, &input[i]);
        sheRefresh(&tmpx1, &tmpx1, k, key,
                   ctx);  // 因为需要保证sumEx是扩大两次，如果不刷新，ax就会变成3次了

        sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

        sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

        // 开始乘以系数并相加
        sheMULConstant(&tmpx1, 0.98157042, &tmpx1, k, key, ctx);
        sheADDConstant(&tmp1, 0.67070608, &tmpx1, k, key, ctx);  // ax+b

        sheMULConstant(&tmpx2, 0.86969832, &tmpx2, k, key, ctx);
        sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

        sheMULConstant(&tmpx3, 0.21713332, &tmpx3, k, key, ctx);
        sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);
        sheSETC(&res[i], &tmp1);
        // cout << "次数：" << tmp1.kTimes << endl;
        BN_mod_add(sumEx, sumEx, res[i].cipher, key->n, ctx);
        // sleep(10000);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly4coeff = [0.04983487,0.25700122 ,0.50462228 ,0.83235057 ,0.98638465]
void poly4Comp(SHECipher *res, BIGNUM *sumEx, SHECipher *input, int dim, int k, SHE_key *key) {
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

    BN_zero(sumEx);
    for (int i = 0; i < dim; ++i) {
        sheSETC(&tmpx1, &input[i]);
        sheRefresh(&tmpx1, &tmpx1, k, key, ctx);

        sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

        sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

        sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

        // 开始乘以系数并相加
        sheMULConstant(&tmpx1, 0.83235057, &tmpx1, k, key, ctx);
        sheADDConstant(&tmp1, 0.98638465, &tmpx1, k, key, ctx);  // ax+b

        sheMULConstant(&tmpx2, 0.50462228, &tmpx2, k, key, ctx);
        sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

        sheMULConstant(&tmpx3, 0.25700122, &tmpx3, k, key, ctx);
        sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

        sheMULConstant(&tmpx4, 0.04983487, &tmpx4, k, key, ctx);
        sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

        sheSETC(&res[i], &tmp2);
        BN_mod_add(sumEx, sumEx, res[i].cipher, key->n, ctx);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly5coeff = [0.00936975 ,0.05920462 ,0.16996664 ,0.45090237 ,0.99001629
// ,1.01935832]
void poly5Comp(SHECipher *res, BIGNUM *sumEx, SHECipher *input, int dim, int k, SHE_key *key) {
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

    BN_zero(sumEx);
    for (int i = 0; i < dim; ++i) {
        sheSETC(&tmpx1, &input[i]);
        sheRefresh(&tmpx1, &tmpx1, k, key, ctx);

        sheMULCC(&tmpx2, &tmpx1, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx2, &tmpx2, k, key, ctx);

        sheMULCC(&tmpx3, &tmpx2, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx3, &tmpx3, k, key, ctx);

        sheMULCC(&tmpx4, &tmpx3, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx4, &tmpx4, k, key, ctx);

        sheMULCC(&tmpx5, &tmpx4, &tmpx1, k, key, ctx);
        sheRefresh(&tmpx5, &tmpx5, k, key, ctx);

        // 开始乘以系数并相加
        sheMULConstant(&tmpx1, 0.99001629, &tmpx1, k, key, ctx);
        sheADDConstant(&tmp1, 1.01935832, &tmpx1, k, key, ctx);  // ax+b

        sheMULConstant(&tmpx2, 0.45090237, &tmpx2, k, key, ctx);
        sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

        sheMULConstant(&tmpx3, 0.16996664, &tmpx3, k, key, ctx);
        sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

        sheMULConstant(&tmpx4, 0.05920462, &tmpx4, k, key, ctx);
        sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

        sheMULConstant(&tmpx5, 0.00936975, &tmpx5, k, key, ctx);
        sheADDCC(&tmp1, &tmpx5, &tmp2, k, key, ctx);

        sheSETC(&res[i], &tmp1);
        BN_mod_add(sumEx, sumEx, res[i].cipher, key->n, ctx);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly5coeff = [0.00936975 ,0.05920462 ,0.16996664 ,0.45090237 ,0.99001629
// ,1.01935832] 2指2次的乘法深度
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

// poly6coeff = [0.00148998 ,0.01115773 ,0.04265231 ,0.156248   ,0.49631671
// ,1.00928715 ,1.00133983]
//[0.00186437 0.01169093 0.03909518 0.15225813 0.50428999 1.01475327 0.99891577]
void poly6Comp(SHECipher *res, BIGNUM *sumEx, SHECipher *input, int dim, int k, SHE_key *key) {
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

    BN_zero(sumEx);
    for (int i = 0; i < dim; ++i) {
        sheSETC(&tmpx1, &input[i]);
        sheRefresh(&tmpx1, &tmpx1, k, key, ctx);

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
        sheMULConstant(&tmpx1, 1.01475327, &tmpx1, k, key, ctx);
        sheADDConstant(&tmp1, 0.99891577, &tmpx1, k, key, ctx);  // ax+b

        sheMULConstant(&tmpx2, 0.50428999, &tmpx2, k, key, ctx);
        sheADDCC(&tmp2, &tmpx2, &tmp1, k, key, ctx);

        sheMULConstant(&tmpx3, 0.15225813, &tmpx3, k, key, ctx);
        sheADDCC(&tmp1, &tmpx3, &tmp2, k, key, ctx);

        sheMULConstant(&tmpx4, 0.03909518, &tmpx4, k, key, ctx);
        sheADDCC(&tmp2, &tmpx4, &tmp1, k, key, ctx);

        sheMULConstant(&tmpx5, 0.01169093, &tmpx5, k, key, ctx);
        sheADDCC(&tmp1, &tmpx5, &tmp2, k, key, ctx);

        sheMULConstant(&tmpx6, 0.00186437, &tmpx6, k, key, ctx);
        sheADDCC(&tmp2, &tmpx6, &tmp1, k, key, ctx);

        sheSETC(&res[i], &tmp2);
        BN_mod_add(sumEx, sumEx, res[i].cipher, key->n, ctx);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// poly6coeff = [0.00148998 ,0.01115773 ,0.04265231 ,0.156248   ,0.49631671
// ,1.00928715 ,1.00133983]
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

void polyCmpMethod(SHECipher *res, SHECipher *input, int dim, int k, int polyTimes, SHE_key *key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *sumExBig = BN_CTX_get(ctx);
    SHECipher sumEx;
    sheInitC(&sumEx, sumExBig);
    BIGNUM **tmp1Big = (BIGNUM **)malloc(sizeof(BIGNUM *) * dim);
    SHECipher *tmp1 = (SHECipher *)malloc(sizeof(SHECipher) * dim);
    for (int i = 0; i < dim; ++i) {
        tmp1Big[i] = BN_CTX_get(ctx);
        sheInitC(&tmp1[i], tmp1Big[i]);
    }
    switch (polyTimes) {
        case 3:
            poly3Comp(tmp1, sumExBig, input, dim, k, key);  // 保证是k^2*e^x就行
            break;
        case 4:
            poly4Comp(tmp1, sumExBig, input, dim, k, key);  // 保证是k^2*e^x就行
            break;
        case 5:
            poly5Comp(tmp1, sumExBig, input, dim, k, key);  // 保证是k^2*e^x就行
            break;
        case 6:
            poly6Comp(tmp1, sumExBig, input, dim, k, key);  // 保证是k^2*e^x就行
            break;

        default:
            cout << "input PolyTimes error!" << endl;
            break;
    }
    sumEx.kTimes = 2;
    for (int i = 0; i < dim; ++i) {
        // k平方进，k3次方出来
        getSoftmax2(&res[i], &tmp1[i], &sumEx, k, key);
        sheRefresh(&res[i], &res[i], k, key, ctx);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
