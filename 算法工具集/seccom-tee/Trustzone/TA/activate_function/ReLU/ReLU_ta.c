#include "ReLU_TA.h"
#include "she.h"

#include "string.h"
#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include "tee_object_api.h"
#include "tee_ext_api.h"

#define PARAMS_IDX4              4    // params参数的下标索引 4
// 外拓展得到KEY
extern SHE_key KEY;

/**
 * 将 BIGNUM 转换为带符号的二进制格式并写入缓冲区 (TA侧版本)
 * - 格式：[1字节符号][4字节长度][二进制数据]
 * - 符号：0=正数，1=负数
 * - 长度：二进制数据的字节数（大端序）
 * - 返回写入的总字节数
 */
static size_t bn_to_signed_bin_buffer_ta(const BIGNUM *bn, unsigned char *buffer, size_t buffer_size) {
    if (bn == NULL || buffer == NULL || buffer_size < 6) {
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
    if (abs_bn == NULL) return 0;
    
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
 * 从带符号的二进制格式恢复 BIGNUM (TA侧版本)
 * - 格式：[1字节符号][4字节长度][二进制数据]
 * - 返回恢复的字节数，0表示失败
 */
static size_t bn_from_signed_bin_buffer_ta(const unsigned char *buffer, size_t buffer_size, BIGNUM *bn) {
    if (buffer == NULL || bn == NULL || buffer_size < 6) {
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
    BIGNUM *temp = BN_bin2bn(buffer + 5, data_bytes, NULL);
    if (temp == NULL) {
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


// 打开的对象句柄
// TEE_ObjectHandle Obj1;
/**-------------------------在这里显示的定义需要在CA中调用的函数，验证参数，然后调用这些函数的原型-------------------------------*/
// 搬用1
void CMD_sheRescale(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i)  // 默认至少放大一倍...
        BN_div_word(xMulKTimes, k);  // 其实就是一种截断，小数就不要了，因为你这里不需要计算，所以小数没关系
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
// 搬用2
void CMD_sheRescaleNeg(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    BIGNUM *negOne = BN_CTX_get(ctx);
    BN_one(negOne);
    BN_set_negative(negOne, 1);
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i)  // 默认至少放大一倍...
        BN_div_word(xMulKTimes, k);  // 其实就是一种截断，小数就不要了，因为你这里不需要计算，所以小数没关系
    BN_mul(xMulKTimes, xMulKTimes, negOne, ctx);
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
// 搬用3
void CMD_calRelu(BIGNUM *Eb1, BIGNUM *Eb2, BIGNUM *Em1) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *m1 = BN_CTX_get(ctx);
    she_decryptBignum(m1, Em1, &KEY, ctx);
    // bn_printfDec(m1);
    if (BN_is_negative(m1))  //<0
    {
        // printf("TEE解密为负数\n");
        BN_copy(Eb1, KEY.cipher_zero);
        BN_copy(Eb2, KEY.cipher_one);
    } else  //>0
    {
        BN_copy(Eb1, KEY.cipher_one);
        BN_copy(Eb2, KEY.cipher_zero);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void CMD_keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1, BIGNUM *l_2, BIGNUM *cipher_zero,
                    BIGNUM *cipher_one) {
    BN_copy(p, KEY.p);
    BN_copy(q, KEY.q);
    BN_copy(l, KEY.l);
    BN_copy(n, KEY.n);
    BN_copy(e_negative1, KEY.e_negative1);
    BN_copy(l_2, KEY.l_2);
    BN_copy(cipher_zero, KEY.cipher_zero);
    BN_copy(cipher_one, KEY.cipher_one);
}
void CMD_reluCipherMulTEE(BIGNUM *output, BIGNUM *Eb, BIGNUM *Em, int k, int EmTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *mMulKTimes = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);

    she_decryptBignum(mMulKTimes, Em, &KEY, ctx);
    she_decryptBignum(b, Eb, &KEY, ctx);
    for (int i = 0; i < EmTimes - 1; ++i)  // 默认至少放大一倍
        BN_div_word(mMulKTimes, k);
    BN_mul(res, mMulKTimes, b, ctx);
    she_encryptBignumSupportNegative2(res, res, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
// 搬用5
void CMD_she_generateRandomKeysTee2(){
    she_generateRandomKeysTee2();
}

/*----------------------------包裹上面的需要调用实际函数----------------------------*/
TEE_Result CmdsheRescale(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 对于传入参数的检验
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();

    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[1].memref.buffer, params[1].memref.size, input) == 0) {
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    CMD_sheRescale(output, input, params[2].value.a, params[3].value.a);

    // 直接将 BIGNUM 转换为带符号二进制并写入输出缓冲区
    size_t output_size = bn_to_signed_bin_buffer_ta(output, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    if (output_size == 0) {
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(output);
    BN_free(input);

    return TEE_SUCCESS;
}
TEE_Result CmdsheRescaleNeg(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 对于传入参数的检验
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();

    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[1].memref.buffer, params[1].memref.size, input) == 0) {
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    CMD_sheRescaleNeg(output, input, params[2].value.a, params[3].value.a);

    // 直接将 BIGNUM 转换为带符号二进制并写入输出缓冲区
    size_t output_size = bn_to_signed_bin_buffer_ta(output, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    if (output_size == 0) {
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(output);
    BN_free(input);
    return TEE_SUCCESS;
}

TEE_Result CmdcalRelu(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 对于传入参数的检验 - 使用 MEMREF 类型检查，因为TA侧不支持PARTIAL类型
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 2)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *Eb1 = BN_new();
    BIGNUM *Eb2 = BN_new();
    BIGNUM *Em1 = BN_new();

    // 假设传递的是二进制数据，用 BN_bin2bn 转换
    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[0].memref.buffer, params[0].memref.size, Eb1) == 0) {
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[1].memref.buffer, params[1].memref.size, Eb2) == 0) {
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[2].memref.buffer, params[2].memref.size, Em1) == 0) {
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 执行 calRelu 操作（这里假设 CMD_calRelu 处理 BIGNUM 类型）
    CMD_calRelu(Eb1, Eb2, Em1);
    
    // 直接将 BIGNUM 转换为带符号二进制并写入输出缓冲区
    size_t size1 = bn_to_signed_bin_buffer_ta(Eb1, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    size_t size2 = bn_to_signed_bin_buffer_ta(Eb2, (unsigned char*)params[1].memref.buffer, params[1].memref.size);
    size_t size3 = bn_to_signed_bin_buffer_ta(Em1, (unsigned char*)params[2].memref.buffer, params[2].memref.size);
    
    if (size1 == 0 || size2 == 0 || size3 == 0) {
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(Eb1);
    BN_free(Eb2);
    BN_free(Em1);
    return TEE_SUCCESS;
}


TEE_Result CmdkeySynthronize(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    char * SEPARATOR = "||";
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* l = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e_negative1 = BN_new();
    BIGNUM* l_2 = BN_new();
    BIGNUM* cipher_zero = BN_new();
    BIGNUM* cipher_one = BN_new();

    if ( p == NULL ||  q == NULL ||  l == NULL ||
         n == NULL ||  e_negative1 == NULL ||  l_2 == NULL ||
         cipher_zero == NULL ||  cipher_one == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // 调用实际的处理函数
    CMD_keySynthronize( p,  q,  l,  n,
                        e_negative1,  l_2,  cipher_zero,  cipher_one);

    // 将 BIGNUM 转换回字符串，并用分隔符连接它们
    char *p_str = BN_bn2dec(p);
    char *q_str = BN_bn2dec(q);
    char *l_str = BN_bn2dec(l);
    char *n_str = BN_bn2dec(n);
    char *e_negative1_str = BN_bn2dec(e_negative1);
    char *l_2_str = BN_bn2dec(l_2);
    char *cipher_zero_str = BN_bn2dec(cipher_zero);
    char *cipher_one_str = BN_bn2dec(cipher_one);

    size_t total_len = strlen(p_str) + strlen(q_str) + strlen(l_str) + strlen(n_str) +
                       strlen(e_negative1_str) + strlen(l_2_str) + strlen(cipher_zero_str) +
                       strlen(cipher_one_str) + 7 * strlen(SEPARATOR) + 1;
    if(total_len > params[0].memref.size){
    }
    // params[0].memref.buffer的size需要获取
    snprintf((char *)params[0].memref.buffer, total_len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                               p_str, SEPARATOR, q_str, SEPARATOR,
                               l_str, SEPARATOR, n_str, SEPARATOR, e_negative1_str, SEPARATOR,
                               l_2_str, SEPARATOR, cipher_zero_str, SEPARATOR, cipher_one_str);
    // 更新返回的参数

    // 释放临时字符串
    OPENSSL_free(p_str);
    OPENSSL_free(q_str);
    OPENSSL_free(l_str);
    OPENSSL_free(n_str);
    OPENSSL_free(e_negative1_str);
    OPENSSL_free(l_2_str);
    OPENSSL_free(cipher_zero_str);
    OPENSSL_free(cipher_one_str);

    // 释放 BIGNUM 内存
    BN_free(p);
    BN_free(q);
    BN_free(l);
    BN_free(n);
    BN_free(e_negative1);
    BN_free(l_2);
    BN_free(cipher_zero);
    BN_free(cipher_one);

    return TEE_SUCCESS;
}
TEE_Result CmdreluCipherMulTEE(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]) {
    // 对于传入参数的检验 - 使用 MEMREF 类型检查，因为TA侧不支持PARTIAL类型
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *output = BN_new();
    BIGNUM *Eb = BN_new();
    BIGNUM *Em = BN_new();

    if (bn_from_signed_bin_buffer_ta((unsigned char *) params[1].memref.buffer, params[1].memref.size, Eb) == 0) {
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (bn_from_signed_bin_buffer_ta((unsigned char *) params[2].memref.buffer, params[2].memref.size, Em) == 0) {
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 传入转换的参数
    CMD_reluCipherMulTEE(output, Eb, Em, params[3].value.a, params[3].value.b);

    // 直接将 BIGNUM 转换为带符号二进制并写入输出缓冲区
    size_t output_size = bn_to_signed_bin_buffer_ta(output, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    if (output_size == 0) {
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(output);
    BN_free(Eb);
    BN_free(Em);
    return TEE_SUCCESS;
}

TEE_Result CmdSHEgenerateRandomKeysTee2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    (void)paramTypes;  // 避免未使用参数警告
    (void)params;      // 避免未使用参数警告
    CMD_she_generateRandomKeysTee2();
    return TEE_SUCCESS;
}


/**-----------------------------------TA中必须定义的宏--------------------------------------*/
TEE_Result TA_CreateEntryPoint(void)
{
    if (addcaller_ca_exec(CLIENT_APPLICATION_NAME, "root") != TEE_SUCCESS) {
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

// 打开一个session的进入点.TODO 我是真没想到华为的tee里面TA内容这么水
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4], void **sessionContext)
{
    TEE_Result ret = TEE_SUCCESS;
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

    (void)sessionContext;
    switch (cmdId) {
        case sheRescale:
            ret = CmdsheRescale(paramTypes, params);
            break;
        case sheRescaleNeg:
            ret = CmdsheRescaleNeg(paramTypes,  params);
            break;
        case calRelu:
            ret = CmdcalRelu(paramTypes,  params);
            break;
        case keySynthronize:
            ret = CmdkeySynthronize(paramTypes,  params);
            break;
        case reluCipherMulTEE:
            ret = CmdreluCipherMulTEE(paramTypes,  params);
            break;
        case SHEgenerateRandomKeysTee2:
            ret = CmdSHEgenerateRandomKeysTee2(paramTypes,  params);
            break;
    }

    return  ret;
}

// 在这里对于持久保存的对象进行销毁，或者进行创建工作
void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
}

void TA_DestroyEntryPoint(void)
{
}



