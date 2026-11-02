#include "MPC_Add_ta.h"

#include <stdarg.h>
#include <stdio.h>
#include "string.h"
#include "stdlib.h"

// TODO 需要把CPP的内容修改为C的
#include "GTCKKS/CTRingMultiplier.h"
#include "GTCKKS/scheme.h"
#include "GTCKKS/plaintext.h"
#include "GTCKKS/stringUtils.h"

#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include "tee_object_api.h"
#include "tee_ext_api.h"


/**
 * 公共参数区域
 * */
// 全局使用的scheme
Scheme scheme;
uint64_t * t1 = NULL;
uint64_t * t = NULL;
unsigned __int128 * mulMessage1;
spritz_ctx ctx_main;

int addLength = 0;

/**----------------------------原函数声明-------------------------*/
/**
 * 对函数进行加密方案的初始化
 * */
void cmd_init(size_t logN, void* s, void* a, void* b){
    Scheme_scheme_Init(logN,s,a,b,&scheme);
    if(t1 != NULL && t != NULL&& mulMessage1 != NULL){
        free(t1);
        free(t);
        free(mulMessage1);
    }
    t1 = (uint64_t *)malloc(sizeof(uint64_t) * scheme.ploy_modulus_degree);
    t = (uint64_t *)malloc(sizeof(uint64_t) * scheme.ploy_modulus_degree);
    uint64_t scalefactor = 1 << scheme.scale;
    // 初始化一下
    init_random_ctx(&ctx_main);
    for (size_t i = 0; i < scheme.ploy_modulus_degree; i++)
    {
        t1[i] =(100000 +  spritz_random64(&ctx_main)% 10000)  * (scalefactor);
        t[i] = t1[i] * (scalefactor);
    }
    mulMessage1 = (unsigned __int128 *)malloc(sizeof( unsigned __int128) * scheme.ploy_modulus_degree);
}
/**
 * 该函数执行加密数据的多项式乘法，并更新密文
 * */
void cmd_send_ciphertext(void *c01, void *c11, void *c00, void *c10){
    uint64_t** cipher01 = (uint64_t**)malloc(sizeof(uint64_t*) * 1);
    uint64_t** cipher11 = (uint64_t**)malloc(sizeof(uint64_t*) * 1);
    uint64_t* cipher00 = (uint64_t*) c00;
    uint64_t* cipher10 = (uint64_t*) c10;

    CTRingMultiplier_fast_mult_poly(cipher01, c01, scheme.s, scheme.multiple);
    CTRingMultiplier_fast_mult_poly(cipher11, c11, scheme.s, scheme.multiple);

    // 2. multiple
    for (size_t i = 0; i < scheme.ploy_modulus_degree; i++)
    {
        cipher00[i] = cipher00[i] + cipher01[0][i] - scheme.qmod;
        cipher10[i] = cipher10[i] + cipher11[0][i] - scheme.qmod;
        mulMessage1[i] = (unsigned __int128)(cipher00[i]) * cipher10[i] + (unsigned __int128)(t[i]);
    }
}

/**
 * 安全求和函数
 */

void cmd_secure_add(void * c0, void * c1, void* batchCipher0, void* batchCipher1){
    uint64_t** cipher1 = (uint64_t**)malloc(sizeof(uint64_t*) * 1);
    uint64_t* cipher0 = (uint64_t*) c0;

    CTRingMultiplier_fast_mult_poly(cipher1,(uint64_t *) c1,scheme.s,scheme.multiple);
    CTRingMultiplier_add(cipher1,cipher0,scheme.multiple);

    double * result = Scheme_Simpledecode(cipher1[0], scheme.ploy_modulus_degree,&scheme);
    double *num = (double *)malloc(sizeof(double) * 1);
    for (size_t i = 0; i < addLength; i++)
    {
        num[0] += result[i];
    }
    free(result);
    Plaintext plain;

    Scheme_Simpleencode_double(num, &plain, 1,&scheme);

    scheme.ciphers[scheme.cur_cipher].c0[0] += plain.coffe_data[0];
    memcpy(batchCipher0, scheme.ciphers[scheme.cur_cipher].c0, sizeof(uint64_t)*scheme.ploy_modulus_degree);
    memcpy(batchCipher1, scheme.ciphers[scheme.cur_cipher].c1, sizeof(uint64_t)*scheme.ploy_modulus_degree);

    scheme.cur_cipher = (scheme.cur_cipher + 1) % scheme.ciphers_num;
    free(num);
}

/**
 * 该函数用于批量传输加密的乘法消息。
 * */
void cmd_ecall_batchtrans_information(void* mulMessage){
    memcpy(mulMessage, mulMessage1, sizeof(unsigned __int128)*scheme.ploy_modulus_degree);
}
/**
 * 该函数执行解密并更新批量加密数据
 * */
void cmd_decodeEncrypt(void* batchCipher0, void* batchCipher1, void* mulMessage){

    uint64_t* temp = (uint64_t*) mulMessage;
    CTRingMultiplier_sub_o(&temp, temp, t1,scheme.multiple);

    CTRingMultiplier_add(&scheme.ciphers[scheme.cur_cipher].c0, temp,scheme.multiple);
    memcpy(batchCipher0, scheme.ciphers[scheme.cur_cipher].c0, sizeof(uint64_t)*scheme.ploy_modulus_degree);
    memcpy(batchCipher1, scheme.ciphers[scheme.cur_cipher].c1, sizeof(uint64_t)*scheme.ploy_modulus_degree);

    scheme.cur_cipher = (scheme.cur_cipher + 1) % scheme.ciphers_num;

}

/**----------------------------定义invoke函数声明-------------------------*/

TEE_Result CMDinit(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
            TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
            TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)) {
        SLogError("INIT: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取参数
    void *s = params[0].memref.buffer;
    void *a = params[1].memref.buffer;
    void *b = params[2].memref.buffer;

    // 获取 logN 参数
    size_t logN = params[3].value.a;
    // 全局给addLength赋值
    addLength = params[3].value.b;
    SLogTrace("logN的长度为%d", (int)logN);
    // 检查参数有效性
    if (s == NULL || a == NULL || b == NULL) {
        SLogError("INIT: Invalid parameters: buffers are NULL or size is 0.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cmd_init(logN,s,a,b);
    // 调用实际的初始化函数
    return TEE_SUCCESS;

}
TEE_Result CMDsend_ciphertext(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){

    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 3)) {
        SLogError("SEND_CIPHERTEXT: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取参数
    void *c01 = params[0].memref.buffer;
    size_t length = params[0].memref.size;
    void *c11 = params[1].memref.buffer;
    void *c00 = params[2].memref.buffer;
    void *c10 = params[3].memref.buffer;

    // 检查参数有效性
    if (c01 == NULL || c11 == NULL || c00 == NULL || c10 == NULL || length == 0) {
        SLogError("SEND_CIPHERTEXT: Invalid parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cmd_send_ciphertext(c01,c11,c00,c10);
    // 调用实际的处理函数
    return TEE_SUCCESS;
}
TEE_Result CMDecall_batchtrans_information(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)) {
        SLogError("ECALL_BATCHTRANS_INFORMATION: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取参数
    void *mulMessage = params[0].memref.buffer;
    size_t length = params[0].memref.size;

    // 检查参数有效性
    if (mulMessage == NULL || length == 0) {
        SLogError("ECALL_BATCHTRANS_INFORMATION: Invalid parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cmd_ecall_batchtrans_information(mulMessage);
    return TEE_SUCCESS;

}
TEE_Result CMDdecodeEncrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    // 验证参数
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 2)) {
        SLogError("DECODE_ENCRYPT: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取参数
    void *batchCipher0 = params[0].memref.buffer;
    void *batchCipher1 = params[1].memref.buffer;
    void *mulMessage = params[2].memref.buffer;
    size_t length = params[0].memref.size;

    // 检查参数有效性
    if (batchCipher0 == NULL || batchCipher1 == NULL || mulMessage == NULL || length == 0) {
        SLogError("DECODE_ENCRYPT: Invalid parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cmd_decodeEncrypt(batchCipher0,batchCipher1,mulMessage);
    return TEE_SUCCESS;
}

TEE_Result CMDsecure_sum(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    // 验证参数
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 3) ) {
        SLogError("DECODE_ENCRYPT: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取参数
    void * c0 = params[0].memref.buffer;
    void * c1 = params[1].memref.buffer;
    void * batchCipher0 = params[2].memref.buffer;
    void * batchCipher1 = params[3].memref.buffer;

    // 检查参数有效性
    if (batchCipher0 == NULL ||c1 == NULL || batchCipher1 == NULL || c0 == NULL) {
        SLogError("DECODE_ENCRYPT: Invalid parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cmd_secure_add(c0,c1,batchCipher0,batchCipher1);
    return TEE_SUCCESS;
}

/**----------------------------TEE原函数声明-------------------------*/
TEE_Result TA_CreateEntryPoint(void)
{
    // SLogTrace 可能是自定义函数，注意
    SLogTrace("----- TA_CreateEntryPoint ----- ");
    if (addcaller_ca_exec(CLIENT_APPLICATION_NAME, "root") == TEE_SUCCESS) {
        SLogTrace("TA_CreateEntryPoint: AddCaller_CA_exec ok.");
    } else {
        SLogError("TA_CreateEntryPoint: AddCaller_CA_exec failed.");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

// 打开一个session的进入点.
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4], void **sessionContext)
{
    TEE_Result ret = TEE_SUCCESS;
    SLogTrace("---- TA_OpenSessionEntryPoint -------- ");
    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    return ret;
}
// 传递调用参数的函数
TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmdId,
                                      uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    TEE_Result ret = 0;

    SLogTrace("---- TA_InvokeCommandEntryPoint ----cmdid: %d------- ", cmdId);
    (void)sessionContext;
    switch (cmdId) {
        case init:
            CMDinit(paramTypes, params);
            SLogTrace("invoke init");
            break;
        case send_ciphertext:
            CMDsend_ciphertext(paramTypes, params);
            SLogTrace("invoke send_ciphertext");
            break;
        case ecall_batchtrans_information:
            CMDecall_batchtrans_information(paramTypes, params);
            SLogTrace("invoke ecall_batchtrans_information");
            break;
        case decodeEncrypt:
            CMDdecodeEncrypt(paramTypes, params);
            SLogTrace("invoke decodeEncrypt");
            break;
        case secure_sum:
            CMDsecure_sum(paramTypes, params);
            SLogTrace("invoke secure_sum");
            break;
    }

    return  ret;
}

// 在这里对于持久保存的对象进行销毁，或者进行创建工作
void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    SLogTrace("---- TA_CloseSessionEntryPoint ----- ");
}

void TA_DestroyEntryPoint(void)
{
    SLogTrace("---- TA_DestroyEntryPoint ---- ");
}
