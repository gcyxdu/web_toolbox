#include "Softmax_ta.h"
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

void CMD_sheRescaleNeg(BIGNUM *output, BIGNUM *input, int k, int kTimes)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    BIGNUM *negOne = BN_CTX_get(ctx);
    BN_one(negOne);
    BN_set_negative(negOne, 1);
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i) // 默认至少放大一倍...
        BN_div_word(xMulKTimes, k);		 // 其实就是一种截断，小数就不要了，因为你这里不需要计算，所以小数没关系
    BN_mul(xMulKTimes, xMulKTimes, negOne, ctx);
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
void CMD_calEx(BIGNUM *output, BIGNUM *input, int k, int kTimes)
{
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
    BN_bn2lebinpad(x, (unsigned char *)(&x_int), sizeof(int64_t));
    if (BN_is_negative(x))
    {
        x_int = -x_int;
    }
    double x_double;
    double ex_double;
    x_double = ((double)x_int) / 1.0;
    for (int i = 0; i < kTimes; ++i)
        x_double = x_double / k;
    ex_double = exp(x_double);
    int64_t ex_MulKtimes_int;
    ex_MulKtimes_int = ex_double * k;
    BN_set_word(ex_MulKtimes, ex_MulKtimes_int);
    she_encryptBignumSupportNegative2(en_ex_MulKtimes, ex_MulKtimes, &KEY, ctx);
    BN_copy(output, en_ex_MulKtimes);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
void CMD_keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1, BIGNUM *l_2, BIGNUM *cipher_zero, BIGNUM *cipher_one)
{
    BN_copy(p, KEY.p);
    BN_copy(q, KEY.q);
    BN_copy(l, KEY.l);
    BN_copy(n, KEY.n);
    BN_copy(e_negative1, KEY.e_negative1);
    BN_copy(l_2, KEY.l_2);
    BN_copy(cipher_zero, KEY.cipher_zero);
    BN_copy(cipher_one, KEY.cipher_one);
}
void CMD_getFraction(BIGNUM *res1, BIGNUM *res2, BIGNUM *input1, BIGNUM *input2, int k_times)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *dec1, *dec2, *tmp1, *tmp2;
    dec1 = BN_CTX_get(ctx);
    dec2 = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    int64_t frac1, frac2;
    double f1, f2;
    she_decryptBignum(dec1, input1, &KEY, ctx);
    she_decryptBignum(dec2, input2, &KEY, ctx);
    // bn_printfHex(dec1);
    BN_div_word(dec2, k_times);
    BN_bn2lebinpad(dec1, (unsigned char *)(&frac1), sizeof(int64_t));
    if (BN_is_negative(dec1))
    {
        frac1 = -frac1;
    }
    BN_bn2lebinpad(dec2, (unsigned char *)(&frac2), sizeof(int64_t));
    if (BN_is_negative(dec2))
    {
        frac2 = -frac2;
    }
    f1 = ((double)frac1) / k_times;
    f1 = f1 / k_times;
    f2 = ((double)frac2) / k_times;
    f2 = f2 / k_times;

    f1 = f1 / f2;
    f2 = 1 / f2;

    frac1 = (f1 * k_times) * k_times;
    if (frac1 < 0)
    {
        BN_set_word(tmp1, -frac1);
        BN_set_negative(tmp1, 1);
    }
    else
    {
        BN_set_word(tmp1, frac1);
    }
    she_encryptBignumSupportNegative2(dec1, tmp1, &KEY, ctx);
    BN_copy(res1, dec1);
    frac2 = f2 * k_times;
    if (frac2 < 0)
    {
        BN_set_word(tmp2, -frac2);
        BN_set_negative(tmp2, 1);
    }
    else
    {
        BN_set_word(tmp2, frac2);
    }
    she_encryptBignumSupportNegative2(dec2, tmp2, &KEY, ctx);
    BN_copy(res2, dec2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
void CMD_reluCipherMulTEE(BIGNUM *output, BIGNUM *Eb, BIGNUM *Em, int k, int EmTimes)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *mMulKTimes = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);

    she_decryptBignum(mMulKTimes, Em, &KEY, ctx);
    she_decryptBignum(b, Eb, &KEY, ctx);
    for (int i = 0; i < EmTimes - 1; ++i) // 默认至少放大一倍
        BN_div_word(mMulKTimes, k);
    BN_mul(res, mMulKTimes, b, ctx);
    she_encryptBignumSupportNegative2(res, res, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
void CMD_SHEgenerateRandomKeysTee2(){
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

TEE_Result CmdsheRescaleNeg(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){

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

TEE_Result CmdcalEx(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
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
    CMD_calEx(output,input,params[2].value.a,params[3].value.a);

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

TEE_Result CmdgetFraction(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char * separator = "||";
    BIGNUM *res1 = BN_new();
    BIGNUM *res2 = BN_new();
    BIGNUM *input1 = BN_new();
    BIGNUM *input2 = BN_new();

    if (!BN_dec2bn(&input1, (char*)params[1].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(res1);
        BN_free(res2);
        BN_free(input1);
        BN_free(input2);
        return TEE_ERROR_BAD_PARAMETERS;
    }if (!BN_dec2bn(&input2, (char*)params[2].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(res1);
        BN_free(res2);
        BN_free(input1);
        BN_free(input2);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    CMD_getFraction(res1,res2,input1,input2,params[3].value.a);
    // 开辟空间，然后将res1和res2合并成一体的内容
    char *res1_str = BN_bn2dec(res1); // 转换为十进制字符串
    if (res1_str == NULL) {
        SLogError("Failed to convert BIGNUM to string.");
        BN_free(res1);
        BN_free(res2);
        BN_free(input1);
        BN_free(input2);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char *res2_str = BN_bn2dec(res2); // 转换为十进制字符串
    if (res2_str == NULL) {
        SLogError("Failed to convert BIGNUM to string.");
        BN_free(res1);
        BN_free(res2);
        BN_free(input1);
        BN_free(input2);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // 计算合并后的字符串长度
    size_t total_len = strlen(res1_str) + strlen(res2_str) + strlen(separator) +1; // 2个"||"的长度 + 1个终止符

    if(params[0].memref.size < total_len){
        SLogTrace("output_str len so long...");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    snprintf(params[0].memref.buffer, total_len, "%s||%s", res1_str, res2_str);
    OPENSSL_free(res1_str);
    OPENSSL_free(res2_str);
    BN_free(res1);
    BN_free(res2);
    BN_free(input1);
    BN_free(input2);
    return TEE_SUCCESS;
}
TEE_Result CmdreluCipherMulTEE(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)||
        TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 2)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 3)
            ) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    BIGNUM *output = BN_new();
    BIGNUM *Eb = BN_new();
    BIGNUM *Em = BN_new();

    if (!BN_dec2bn(&Eb, (char*)params[1].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }if (!BN_dec2bn(&Em, (char*)params[2].memref.buffer)) {
        SLogTrace("Failed to convert char* to BIGNUM for Eb1.");
        BN_free(output);
        BN_free(Eb);
        BN_free(Em);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    CMD_reluCipherMulTEE(output,Eb,Em,params[3].value.a,params[3].value.b);

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
    memcpy(params[0].memref.buffer, output_str, output_size);
    OPENSSL_free(output_str);
    BN_free(output);
    BN_free(Eb);
    BN_free(Em);
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
    SLogTrace("TA测的total_len：%zu",total_len);
    if(total_len > params[0].memref.size){
        SLogTrace("total_len so long...");
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

TEE_Result CmdSHEgenerateRandomKeysTee2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    CMD_SHEgenerateRandomKeysTee2();
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
        case calEx:
            ret = CmdcalEx(paramTypes,params);
            SLogTrace("调用calEx");
            break;
        case keySynthronize:
            ret = CmdkeySynthronize(paramTypes,  params);
            SLogTrace("调用keySynthronize");
            break;
        case getFraction:
            ret = CmdgetFraction(paramTypes,  params);
            SLogTrace("调用getFraction");
            break;
        case reluCipherMulTEE:
            ret = CmdreluCipherMulTEE(paramTypes,params);
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



