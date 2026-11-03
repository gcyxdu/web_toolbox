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
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();

    if (!BN_dec2bn(&input, (char*)params[1].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    CMD_sheRescale(output,input,params[2].value.a,params[3].value.a);

    char *output_str = BN_bn2dec(output); // 转换为十进制字符串
    if (output_str == NULL) {
        SLogError("Failed to convert BIGNUM to string.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t output_size = strlen(output_str) + 1;  // 包括结束符

    if(params[0].memref.size < output_size){
        SLogTrace("output_str len so long...");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    memcpy(params[0].memref.buffer, output_str, output_size);
    OPENSSL_free(output_str);
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
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *output = BN_new();
    BIGNUM *input = BN_new();

    if (!BN_dec2bn(&input, (char*)params[1].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    CMD_sheRescaleNeg(output,input,params[2].value.a,params[3].value.a);

    char *output_str = BN_bn2dec(output); // 转换为十进制字符串
    if (output_str == NULL) {
        SLogError("Failed to convert BIGNUM to string.");
        BN_free(output);
        BN_free(input);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t output_size = strlen(output_str) + 1;  // 包括结束符

    if(params[0].memref.size < output_size){
        SLogTrace("output_str len so long...");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    memcpy(params[0].memref.buffer, output_str, output_size);
    OPENSSL_free(output_str);
    BN_free(output);
    BN_free(input);
    return TEE_SUCCESS;
}

TEE_Result CmdcalRelu(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 对于传入参数的检验
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 2)) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *Eb1 = BN_new();
    BIGNUM *Eb2 = BN_new();
    BIGNUM *Em1 = BN_new();

    // 假设传递的 char * 是十进制字符串，用 BN_dec2bn 转换
    if (!BN_dec2bn(&Eb1, (char*)params[0].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //SLog("str before %d", strlen((char*)params[0].memref.buffer));

    if (!BN_dec2bn(&Eb2, (char*)params[1].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb2.");
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!BN_dec2bn(&Em1, (char*)params[2].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Em1.");
        BN_free(Eb1);
        BN_free(Eb2);
        BN_free(Em1);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // 执行 calRelu 操作（这里假设 CMD_calRelu 处理 BIGNUM 类型）
    CMD_calRelu(Eb1, Eb2, Em1);
    // 处理完后，转换回 char *
    char *result1 = BN_bn2dec(Eb1); // 将 BIGNUM 转换为十进制字符串
    char *result2 = BN_bn2dec(Eb2);
    char *result3 = BN_bn2dec(Em1);

    // 分配内存并复制十进制字符串到缓冲区
    size_t len1 = strlen(result1) + 1;
    size_t len2 = strlen(result2) + 1;
    size_t len3 = strlen(result3) + 1;
    if(len1 > params[0].memref.size || len2 > params[1].memref.size|| len3 >params[2].memref.size){
        SLogTrace("length so long...");
    }
    memcpy((char*)params[0].memref.buffer, result1, len1);
    memcpy((char*)params[1].memref.buffer, result2, len2);
    memcpy((char*)params[2].memref.buffer, result3, len3);

    //SLog("str after %d", strlen((char*)params[0].memref.buffer));
    // 释放 BIGNUM 内存
    OPENSSL_free(result1);
    OPENSSL_free(result2);
    OPENSSL_free(result3);

    BN_free(Eb1);
    BN_free(Eb2);
    BN_free(Em1);

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
    SLogTrace("total len is %zu",total_len);
    if(total_len > params[0].memref.size){
        SLogTrace("total_len is long...");
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
    // 对于传入参数的检验
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 将传递进来的 char * 转换为 BIGNUM *
    BIGNUM *output = BN_new();
    BIGNUM *Eb = BN_new();
    BIGNUM *Em = BN_new();

    if (!BN_dec2bn(&Eb, (char *) params[1].memref.buffer)) {
        SLogError("Failed to convert char* to BIGNUM for Eb.");
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!BN_dec2bn(&Em, (char *) params[2].memref.buffer)) {
        SLogError("Failed to convert char* to BIGNUM for Em.");
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 传入转换的参数
    CMD_reluCipherMulTEE(output, Eb, Em, params[3].value.a, params[3].value.b);

    char *output_str = BN_bn2dec(output); // 转换为十进制字符串
    if (output_str == NULL) {
        SLogError("Failed to convert BIGNUM to string.");
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t output_size = strlen(output_str) + 1;  // 包括结束符

    if(params[0].memref.size < output_size){
        SLogTrace("output_str len so long...");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    memcpy((char *) params[0].memref.buffer, output_str, output_size);
    OPENSSL_free(output_str);
    BN_free(output);
    BN_free(Eb);
    BN_free(Em);
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

// 打开一个session的进入点.TODO 我是真没想到华为的tee里面TA内容这么水
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
        case sheRescale:
            ret = CmdsheRescale(paramTypes, params);
            SLogTrace("调用sheRescale");
            break;
        case sheRescaleNeg:
            ret = CmdsheRescaleNeg(paramTypes,  params);
            SLogTrace("调用sheRescaleNeg");
            break;
        case calRelu:
            ret = CmdcalRelu(paramTypes,  params);
            SLogTrace("调用calRelu");
            break;
        case keySynthronize:
            ret = CmdkeySynthronize(paramTypes,  params);
            SLogTrace("调用keySynthronize");
            break;
        case reluCipherMulTEE:
            ret = CmdreluCipherMulTEE(paramTypes,  params);
            SLogTrace("调用reluCipherMulTEE");
            break;
        case SHEgenerateRandomKeysTee2:
            ret = CmdSHEgenerateRandomKeysTee2(paramTypes,  params);
            SLogTrace("调用SHEgenerateRandomKeysTee2");
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



