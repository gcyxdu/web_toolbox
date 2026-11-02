#include "Sigmoid_ta.h"
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

// 带符号二进制转换函数
static size_t bn_to_signed_bin_buffer_ta(const BIGNUM *bn, unsigned char *buffer, size_t buffer_size) {
    if (bn == NULL || buffer == NULL || buffer_size < 6) {
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
    if (abs_bn == NULL) {
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

static size_t bn_from_signed_bin_buffer_ta(const unsigned char *buffer, size_t buffer_size, BIGNUM *bn) {
    if (buffer == NULL || bn == NULL || buffer_size < 6) {
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
    
    BIGNUM *temp = BN_bin2bn(buffer + 5, data_bytes, NULL);
    if (temp == NULL) {
        return 0;
    }
    
    if (is_negative) {
        BN_set_negative(temp, 1);
    }
    
    BN_copy(bn, temp);
    BN_free(temp);
    
    return 5 + data_bytes;
}

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
void CMD_calENegx(BIGNUM *output, BIGNUM *input, int k, int kTimes) {

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *ex, *x, *ex_MulKtimes, *en_ex_MulKtimes;
    x = BN_CTX_get(ctx);
    ex = BN_CTX_get(ctx);
    ex_MulKtimes = BN_CTX_get(ctx);
    en_ex_MulKtimes = BN_CTX_get(ctx);
    int ret = 0;
    int64_t x_int; // 2的64次方，大于10的18次方，所以来的数字不要大于这个
    she_decryptBignum(x, input, &KEY, ctx);
    // bn_printfDec(x);
    BN_bn2lebinpad(x, (unsigned char *)(&x_int), sizeof(int64_t));
    if (BN_is_negative(x))
    {
        x_int = -x_int;
    }
    // printf("k2(x+r1):%lld\n", x_int);
    double x_double;
    double ex_double;
    x_double = ((double)x_int) / 1.0;
    for (int i = 0; i < kTimes; ++i)
        x_double = x_double / k;
    x_double = -x_double; // 因为是算e的-x
    // printf("x_double:%lf\n", x_double);
    ex_double = exp(x_double);
    // printf("ex_double:%lf\n", ex_double);
    // 乘以k然后加密出来	//越界了，兄弟，哎。。。
    // int ex_MulKtimes_int;
    int64_t ex_MulKtimes_int;
    ex_MulKtimes_int = ex_double * k;
    // printf("ex_MulKtimes:%d\n",ex_MulKtimes_int);
    BN_set_word(ex_MulKtimes, ex_MulKtimes_int);
    // bn_printfDec(ex_MulKtimes);
    she_encryptBignumSupportNegative2(en_ex_MulKtimes, ex_MulKtimes, &KEY, ctx);
    BN_copy(output, en_ex_MulKtimes);
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

void CMD_sigmoidInverseX(BIGNUM *output, BIGNUM *input, int k, int kTimes) {

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x_Mulk3, *inverse_x_MulKtimes, *en_inverse_x_MulKtimes;
    x_Mulk3 = BN_CTX_get(ctx);
    inverse_x_MulKtimes = BN_CTX_get(ctx);
    en_inverse_x_MulKtimes = BN_CTX_get(ctx);
    int ret = 0;
    int64_t xMulk2_int;
    she_decryptBignum(x_Mulk3, input, &KEY, ctx); // 解密完肯定是正数
    // 即使是Int64t，还是装不下，所以除以一个k,但我感觉似乎能装下啊。。。算了
    BN_div_word(x_Mulk3, k);
    // bn_printfHex(x);
    BN_bn2lebinpad(x_Mulk3, (unsigned char *)(&xMulk2_int), sizeof(int64_t)); // sigmoid分母的数字耶，就是正数吧，哈哈
    // printf("打印下越界的k^3,比int64大：%lld\n", xMulk2_int);
    double x_double;
    double inverse_x_double;
    x_double = ((double)xMulk2_int) / k;
    for (int i = 0; i < kTimes - 2; ++i) // 这岂不是默认至少要两次了
    {
        x_double = x_double / k;
    }

    // printf("x_double:%lf\n",x_double);
    inverse_x_double = 1 / x_double;

    int inverse_x_MulKtimes_int;
    inverse_x_MulKtimes_int = inverse_x_double * k;
    // printf("inverse_x_MulKtimes:%d\n",inverse_x_MulKtimes_int);
    BN_set_word(inverse_x_MulKtimes, inverse_x_MulKtimes_int); // 这里假定就是正数了，毕竟sigmoid下面都是正数吧
    she_encryptBignumSupportNegative2(en_inverse_x_MulKtimes, inverse_x_MulKtimes, &KEY, ctx);
    BN_copy(output, en_inverse_x_MulKtimes);
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
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();


    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[1].memref.buffer, params[1].memref.size, input) == 0) {
        SLogTrace("Failed to convert signed binary to BIGNUM for input.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    CMD_sheRescale(output, input, params[2].value.a, params[3].value.a);

    size_t output_size = bn_to_signed_bin_buffer_ta(output, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    if (output_size == 0) {
        SLogError("Failed to convert BIGNUM to signed binary or buffer too small.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(output);
    BN_free(input);
    return TEE_SUCCESS;
}

// TODO 跟抄
TEE_Result CmdcalENegx(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){

    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();

    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[1].memref.buffer, params[1].memref.size, input) == 0) {
        SLogTrace("Failed to convert signed binary to BIGNUM for input.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    CMD_calENegx(output, input, params[2].value.a, params[3].value.a);

    size_t output_size = bn_to_signed_bin_buffer_ta(output, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    if (output_size == 0) {
        SLogError("Failed to convert BIGNUM to signed binary or buffer too small.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(output);
    BN_free(input);
    return TEE_SUCCESS;
}

TEE_Result CmdkeySynthronize(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    char * SEPARATOR = "||";
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
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
        SLogError("Memory allocation for BIGNUM failed");
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
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    // params[0].memref.buffer的size需要获取
    snprintf((char *)params[0].memref.buffer, total_len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
             p_str, SEPARATOR, q_str, SEPARATOR,
             l_str, SEPARATOR, n_str, SEPARATOR, e_negative1_str, SEPARATOR,
             l_2_str, SEPARATOR, cipher_zero_str, SEPARATOR, cipher_one_str);

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

// TODO 跟抄
TEE_Result CmdsigmoidInverseX(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){

    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();

    if (bn_from_signed_bin_buffer_ta((unsigned char*)params[1].memref.buffer, params[1].memref.size, input) == 0) {
        SLogTrace("Failed to convert signed binary to BIGNUM for input.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    CMD_sigmoidInverseX(output, input, params[2].value.a, params[3].value.a);

    size_t output_size = bn_to_signed_bin_buffer_ta(output, (unsigned char*)params[0].memref.buffer, params[0].memref.size);
    if (output_size == 0) {
        SLogError("Failed to convert BIGNUM to signed binary or buffer too small.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    BN_free(output);
    BN_free(input);
    return TEE_SUCCESS;
}

TEE_Result CmdSHEgenerateRandomKeysTee2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
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

// 打开一个session的进入点
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
        case calENegx:
            ret = CmdcalENegx(paramTypes,  params);
            break;
        case keySynthronize:
            ret = CmdkeySynthronize(paramTypes,  params);
            break;
        case sigmoidInverseX:
            ret = CmdsigmoidInverseX(paramTypes,  params);
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



