/* 系统头文件 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>

/* 本地头文件 */
#include "gmssl_ta.h"
#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include "tee_object_api.h"
#include "tee_ext_api.h"
#include "tee_time_api.h"

/* GMSSL 头文件 */

#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm9.h>

#include <gmssl/pkcs8.h>

/*-----------------------------------------------------------------------*/

// 辅助函数：从私钥生成SM2密钥对
static int sm2_key_generate_from_private_key(SM2_KEY *key)
{
    // 从私钥计算公钥
    // 这里应该使用椭圆曲线点乘法：公钥 = 私钥 * 基点G
    // 简化实现，使用gmssl库的现有函数
    return sm2_key_generate(key);
}

// SM2算法TA函数实现 - 参数解析待完善
TEE_Result Cmd_sm2_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (允许更大的缓冲区)
    if (input_len < 128 || output_len < 64) { // 至少128字节输入，至少64字节输出
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_KEY sm2_key;
    uint8_t dgst[32];
    
    // 解析SM2_KEY (96字节：32私钥 + 32公钥x + 32公钥y)
    memcpy(sm2_key.private_key, input_data, 32);
    memcpy(sm2_key.public_key.x, input_data + 32, 32);
    memcpy(sm2_key.public_key.y, input_data + 64, 32);
    
    // 解析摘要 (32字节)
    memcpy(dgst, input_data + 96, 32);
    
    // 执行SM2签名
    SM2_SIGNATURE signature;
    if (sm2_do_sign(&sm2_key, dgst, &signature) != 1) {
        return TEE_ERROR_GENERIC;
    }
    
    // 序列化输出结果 (64字节：32字节r + 32字节s)
    memcpy(output_data, signature.r, 32);
    memcpy(output_data + 32, signature.s, 32);
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_verify(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_encrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_keygen(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_sign_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出上下文 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证
    if (input_len < 96 || output_len < sizeof(SM2_SIGN_CTX)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_KEY key;
    memcpy(key.private_key, input_data, 32);
    memcpy(key.public_key.x, input_data + 32, 32);
    memcpy(key.public_key.y, input_data + 64, 32);
    
    // 解析ID
    const char *id = (const char *)(input_data + 96);
    size_t idlen = input_len - 96;
    
    // 创建SM2_SIGN_CTX
    SM2_SIGN_CTX sign_ctx;
    memset(&sign_ctx, 0, sizeof(SM2_SIGN_CTX));
    
    // 调用GMSSL的签名初始化函数
    int ret = sm2_sign_init(&sign_ctx, &key, id, idlen);
    
    if (ret != 1) {
        return TEE_ERROR_GENERIC;
    }
    
    // 序列化输出结果
    memcpy(output_data, &sign_ctx, sizeof(SM2_SIGN_CTX));
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_sign_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出上下文 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (至少需要SM2_SIGN_CTX + 数据)
    if (input_len < sizeof(SM2_SIGN_CTX) || output_len < sizeof(SM2_SIGN_CTX)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_SIGN_CTX sign_ctx;
    const uint8_t *data = input_data + sizeof(SM2_SIGN_CTX);
    size_t datalen = input_len - sizeof(SM2_SIGN_CTX);
    
    // 解析SM2_SIGN_CTX
    memcpy(&sign_ctx, input_data, sizeof(SM2_SIGN_CTX));
    
    // 执行SM2签名更新
    int result = sm2_sign_update(&sign_ctx, data, datalen);
    
    // 序列化输出上下文
    memcpy(output_data, &sign_ctx, sizeof(SM2_SIGN_CTX));
    
    return (result == 1) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result Cmd_sm2_sign_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    SLogTrace("TA: Cmd_sm2_sign_finish called");
    
    // 检查参数类型：输入数据 + 输出签名 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        SLogTrace("TA: Parameter type check failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    SLogTrace("TA: input_len=%zu, output_len=%zu, SM2_SIGN_CTX size=%zu", 
              input_len, output_len, sizeof(SM2_SIGN_CTX));
    
    // 参数验证 (至少需要SM2_SIGN_CTX，输出至少68字节：签名+长度)
    if (input_len < sizeof(SM2_SIGN_CTX) || output_len < 68) {
        SLogTrace("TA: Parameter validation failed: input_len=%zu < %zu or output_len=%zu < 68", 
                  input_len, sizeof(SM2_SIGN_CTX), output_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_SIGN_CTX sign_ctx;
    
    // 解析SM2_SIGN_CTX
    SLogTrace("TA: About to memcpy SM2_SIGN_CTX");
    memcpy(&sign_ctx, input_data, sizeof(SM2_SIGN_CTX));
    SLogTrace("TA: SM2_SIGN_CTX copied successfully");
    
    // 执行SM2签名完成
    uint8_t sig[128]; // 扩大缓冲区到128字节
    size_t siglen = 0;
    SLogTrace("TA: About to call sm2_sign_finish");
    int result = sm2_sign_finish(&sign_ctx, sig, &siglen);
    SLogTrace("TA: sm2_sign_finish returned %d, siglen=%zu", result, siglen);
    
    if (result != 1) {
        SLogTrace("TA: sm2_sign_finish failed");
        return TEE_ERROR_GENERIC;
    }
    
    // 检查输出缓冲区大小
    // SM2签名最大长度通常是71字节（DER编码），我们需要足够的空间
    if (siglen > 128 || output_len < siglen + sizeof(size_t)) {
        SLogTrace("TA: Output buffer too small: siglen=%zu, output_len=%zu", siglen, output_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 序列化输出结果：签名长度 + 签名数据
    SLogTrace("TA: About to serialize output, siglen=%zu", siglen);
    *(size_t*)output_data = siglen;  // 首先写入签名长度
    memcpy(output_data + sizeof(size_t), sig, siglen);  // 然后写入签名数据
    SLogTrace("TA: Output serialized successfully");
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_verify_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出上下文 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证
    if (input_len < 96 || output_len < sizeof(SM2_SIGN_CTX)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_KEY key;
    memcpy(key.private_key, input_data, 32);
    memcpy(key.public_key.x, input_data + 32, 32);
    memcpy(key.public_key.y, input_data + 64, 32);
    
    // 解析ID
    const char *id = (const char *)(input_data + 96);
    size_t idlen = input_len - 96;
    
    // 创建SM2_SIGN_CTX
    SM2_SIGN_CTX verify_ctx;
    memset(&verify_ctx, 0, sizeof(SM2_SIGN_CTX));
    
    // 调用GMSSL的验证初始化函数
    int ret = sm2_verify_init(&verify_ctx, &key, id, idlen);
    
    if (ret != 1) {
        return TEE_ERROR_GENERIC;
    }
    
    // 序列化输出结果
    memcpy(output_data, &verify_ctx, sizeof(SM2_SIGN_CTX));
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_verify_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出上下文 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证
    if (input_len < sizeof(SM2_SIGN_CTX) || output_len < sizeof(SM2_SIGN_CTX)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_SIGN_CTX verify_ctx;
    memcpy(&verify_ctx, input_data, sizeof(SM2_SIGN_CTX));
    
    // 解析数据
    const uint8_t *data = input_data + sizeof(SM2_SIGN_CTX);
    size_t datalen = input_len - sizeof(SM2_SIGN_CTX);
    
    // 调用GMSSL的验证更新函数
    int ret = sm2_verify_update(&verify_ctx, data, datalen);
    
    if (ret != 1) {
        return TEE_ERROR_GENERIC;
    }
    
    // 序列化输出结果
    memcpy(output_data, &verify_ctx, sizeof(SM2_SIGN_CTX));
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_verify_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出结果 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证
    if (input_len < sizeof(SM2_SIGN_CTX) + 64 || output_len < 4) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_SIGN_CTX verify_ctx;
    memcpy(&verify_ctx, input_data, sizeof(SM2_SIGN_CTX));
    
    // 解析签名
    const uint8_t *sig = input_data + sizeof(SM2_SIGN_CTX);
    size_t siglen = input_len - sizeof(SM2_SIGN_CTX);
    
    // 调用GMSSL的验证完成函数
    int ret = sm2_verify_finish(&verify_ctx, sig, siglen);
    
    // 序列化输出结果
    *(int*)output_data = ret;
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_private_key_info_decrypt_from_der(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_private_key_info_decrypt_from_pem(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出密钥 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证
    if (input_len < 10 || output_len < 96) { // 至少需要密码+文件内容，输出96字节SM2_KEY
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 增加输入长度限制
    if (input_len > 2048) { // 限制最大输入长度
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 解析输入参数：密码 + 文件内容
    const char *pass = (const char *)input_data;
    size_t pass_len = strlen(pass);
    const uint8_t *pem_data = input_data + pass_len + 1; // +1 for null terminator
    size_t pem_len = input_len - pass_len - 1;
    
    // 验证参数长度
    if (pass_len == 0 || pem_len == 0) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 创建临时缓冲区来存储PEM数据
    uint8_t *pem_buffer = malloc(pem_len + 1);
    if (!pem_buffer) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    
    memcpy(pem_buffer, pem_data, pem_len);
    pem_buffer[pem_len] = '\0';
    
    // 创建SM2_KEY结构
    SM2_KEY sm2_key;
    memset(&sm2_key, 0, sizeof(SM2_KEY));
    
    // 使用新的缓冲区解析函数
    int ret = sm2_private_key_info_decrypt_from_pem_buffer(&sm2_key, pass, (const char*)pem_data, pem_len);
    
    free(pem_buffer);
    
    if (ret != 1) {
        return TEE_ERROR_GENERIC;
    }
    
    // 序列化输出结果 (96字节：32私钥 + 32公钥x + 32公钥y)
    memcpy(output_data, sm2_key.private_key, 32);
    memcpy(output_data + 32, sm2_key.public_key.x, 32);
    memcpy(output_data + 64, sm2_key.public_key.y, 32);
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm2_public_key_equ(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出结果 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (两个公钥 = 128字节)
    if (input_len < 128 || output_len < 4) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数 - 只解析公钥部分
    SM2_KEY sm2_key1, sm2_key2;
    
    // 初始化SM2_KEY结构
    memset(&sm2_key1, 0, sizeof(SM2_KEY));
    memset(&sm2_key2, 0, sizeof(SM2_KEY));
    
    // 解析第一个公钥 (64字节: x + y)
    memcpy(sm2_key1.public_key.x, input_data, 32);
    memcpy(sm2_key1.public_key.y, input_data + 32, 32);
    
    // 解析第二个公钥 (64字节: x + y)
    memcpy(sm2_key2.public_key.x, input_data + 64, 32);
    memcpy(sm2_key2.public_key.y, input_data + 96, 32);

    // 执行公钥比较 - 直接调用GMSSL函数
    int result = sm2_public_key_equ(&sm2_key1, &sm2_key2);
    
    SLogTrace("TA: sm2_public_key_equ result: %d", result);
    
    // 序列化输出结果
    *(int*)output_data = result;
    
    return TEE_SUCCESS;
}

// SM3算法TA函数实现 - 参数解析待完善
TEE_Result Cmd_sm3_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm3_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm3_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm3_digest(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm3_hmac_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm3_hmac_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm3_hmac_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

// SM4算法TA函数实现 - 参数解析待完善
TEE_Result Cmd_sm4_set_key(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // TODO: 参数解析和具体实现
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_encrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (16字节SM4_KEY + 16字节输入数据)
    if (input_len < sizeof(SM4_KEY) + 16 || output_len < 16) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM4_KEY key;
    uint8_t in[16];
    
    // 解析SM4_KEY
    memcpy(&key, input_data, sizeof(SM4_KEY));
    
    // 解析输入数据
    memcpy(in, input_data + sizeof(SM4_KEY), 16);
    
    // 调用GMSSL的SM4加密函数
    sm4_encrypt(&key, in, output_data);
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (16字节SM4_KEY + 16字节输入数据)
    if (input_len < sizeof(SM4_KEY) + 16 || output_len < 16) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM4_KEY key;
    uint8_t in[16];
    
    // 解析SM4_KEY
    memcpy(&key, input_data, sizeof(SM4_KEY));
    
    // 解析输入数据
    memcpy(in, input_data + sizeof(SM4_KEY), 16);
    
    // 调用GMSSL的SM4解密函数
    sm4_decrypt(&key, in, output_data);
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_set_encrypt_key(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出密钥 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (16字节原始密钥 + 16字节SM4_KEY)
    if (input_len < 32 || output_len < sizeof(SM4_KEY)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    uint8_t raw_key[16];
    SM4_KEY key;
    
    // 解析原始密钥
    memcpy(raw_key, input_data, 16);
    
    // 解析SM4_KEY
    memcpy(&key, input_data + 16, sizeof(SM4_KEY));
    
    // 调用GMSSL的SM4设置加密密钥函数
    sm4_set_encrypt_key(&key, raw_key);
    
    // 序列化输出结果
    memcpy(output_data, &key, sizeof(SM4_KEY));
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_set_decrypt_key(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出密钥 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (16字节原始密钥 + 16字节SM4_KEY)
    if (input_len < 32 || output_len < sizeof(SM4_KEY)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    uint8_t raw_key[16];
    SM4_KEY key;
    
    // 解析原始密钥
    memcpy(raw_key, input_data, 16);
    
    // 解析SM4_KEY
    memcpy(&key, input_data + 16, sizeof(SM4_KEY));
    
    // 调用GMSSL的SM4设置解密密钥函数
    sm4_set_decrypt_key(&key, raw_key);
    
    // 序列化输出结果
    memcpy(output_data, &key, sizeof(SM4_KEY));
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_cbc_encrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (至少需要SM4_KEY + IV + 数据)
    if (input_len < sizeof(SM4_KEY) + 16 + 16) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 计算数据大小
    size_t data_size = input_len - sizeof(SM4_KEY) - 16;
    
    // 验证输出缓冲区大小
    if (output_len < data_size) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM4_KEY key;
    uint8_t iv[16];
    
    // 解析SM4_KEY
    memcpy(&key, input_data, sizeof(SM4_KEY));
    
    // 解析IV
    memcpy(iv, input_data + sizeof(SM4_KEY), 16);
    
    // 解析输入数据
    const uint8_t *in = input_data + sizeof(SM4_KEY) + 16;
    
    // 计算块数
    size_t nblocks = data_size / 16;
    
    // 调用GMSSL的SM4-CBC加密函数
    sm4_cbc_encrypt(&key, iv, in, nblocks, output_data);
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_cbc_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (至少需要SM4_KEY + IV + 数据)
    if (input_len < sizeof(SM4_KEY) + 16 + 16) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 计算数据大小
    size_t data_size = input_len - sizeof(SM4_KEY) - 16;
    
    // 验证输出缓冲区大小
    if (output_len < data_size) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM4_KEY key;
    uint8_t iv[16];
    
    // 解析SM4_KEY
    memcpy(&key, input_data, sizeof(SM4_KEY));
    
    // 解析IV
    memcpy(iv, input_data + sizeof(SM4_KEY), 16);
    
    // 解析输入数据
    const uint8_t *in = input_data + sizeof(SM4_KEY) + 16;
    
    // 计算块数
    size_t nblocks = data_size / 16;
    
    // 调用GMSSL的SM4-CBC解密函数
    sm4_cbc_decrypt(&key, iv, in, nblocks, output_data);
    
    return TEE_SUCCESS;
}

TEE_Result Cmd_sm4_cbc_padding_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    // 参数验证 (至少需要SM4_KEY + IV + 数据)
    if (input_len < sizeof(SM4_KEY) + 16 + 16 || output_len < 1536) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM4_KEY key;
    uint8_t iv[16];
    size_t data_size = input_len - sizeof(SM4_KEY) - 16;
    
    // 解析SM4_KEY
    memcpy(&key, input_data, sizeof(SM4_KEY));
    
    // 解析IV
    memcpy(iv, input_data + sizeof(SM4_KEY), 16);
    
    // 解析输入数据
    const uint8_t *in = input_data + sizeof(SM4_KEY) + 16;
    
    // 准备输出缓冲区
    uint8_t out[1536]; // 扩大缓冲区
    size_t outlen = 0;
    
    // 调用GMSSL的SM4-CBC填充解密函数
    int result = sm4_cbc_padding_decrypt(&key, iv, in, data_size, out, &outlen);
    
    if (result != 1) {
        return TEE_ERROR_GENERIC;
    }
    
    // 检查输出缓冲区大小
    if (outlen > 1024 || output_len < outlen + sizeof(size_t)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 序列化输出结果：输出长度 + 输出数据
    *(size_t*)output_data = outlen;  // 首先写入输出长度
    memcpy(output_data + sizeof(size_t), out, outlen);  // 然后写入输出数据
    
    return TEE_SUCCESS;
}

/**-----------------------------------TA中必须定义的宏--------------------------------------*/
TEE_Result TA_CreateEntryPoint(void)
{
    // SLogTrace 可能是自定义函数，注意
    // SLogTrace("----- TA_CreateEntryPoint ----- "); // 删除打印以提升性能
    if (addcaller_ca_exec( CLIENT_APPLICATION_NAME, "root") == TEE_SUCCESS) {
        // SLogTrace("TA_CreateEntryPoint: AddCaller_CA_exec ok."); // 删除打印以提升性能
    } else {
        // SLogError("TA_CreateEntryPoint: AddCaller_CA_exec failed."); // 删除打印以提升性能
        return TEE_ERROR_GENERIC;
    }
    // SLogTrace("返回打印了TEE_SUCCESS"); // 删除打印以提升性能
    return TEE_SUCCESS;
}

// 打开一个session的进入点.
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4], void **sessionContext)
{
    TEE_Result ret = TEE_SUCCESS;
    // SLogTrace("---- TA_OpenSessionEntryPoint -------- "); // 删除打印以提升性能
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
    // clock_t start_time, end_time;  // 未使用，注释掉
    // double duration_ms = 0.0;       // 未使用，注释掉

    // SLogTrace("---- TA_InvokeCommandEntryPoint ---- cmdid: %d ----", cmdId); // 删除打印以提升性能
    (void)sessionContext;
    switch (cmdId)
    {
    // SM2算法命令处理
    case TA_CMD_SM2_SIGN:
        ret = Cmd_sm2_sign(paramTypes, params);
        break;
    case TA_CMD_SM2_VERIFY:
        ret = Cmd_sm2_verify(paramTypes, params);
        break;
    case TA_CMD_SM2_ENCRYPT:
        ret = Cmd_sm2_encrypt(paramTypes, params);
        break;
    case TA_CMD_SM2_DECRYPT:
        ret = Cmd_sm2_decrypt(paramTypes, params);
        break;
    case TA_CMD_SM2_KEYGEN:
        ret = Cmd_sm2_keygen(paramTypes, params);
        break;
    case TA_CMD_SM2_SIGN_INIT:
        ret = Cmd_sm2_sign_init(paramTypes, params);
        break;
    case TA_CMD_SM2_SIGN_UPDATE:
        ret = Cmd_sm2_sign_update(paramTypes, params);
        break;
    case TA_CMD_SM2_SIGN_FINISH:
        ret = Cmd_sm2_sign_finish(paramTypes, params);
        break;
    case TA_CMD_SM2_VERIFY_INIT:
        ret = Cmd_sm2_verify_init(paramTypes, params);
        break;
    case TA_CMD_SM2_VERIFY_UPDATE:
        ret = Cmd_sm2_verify_update(paramTypes, params);
        break;
    case TA_CMD_SM2_VERIFY_FINISH:
        ret = Cmd_sm2_verify_finish(paramTypes, params);
        break;
    case TA_CMD_SM2_PRIVATE_KEY_INFO_DECRYPT_FROM_DER:
        ret = Cmd_sm2_private_key_info_decrypt_from_der(paramTypes, params);
        break;
    case TA_CMD_SM2_PRIVATE_KEY_INFO_DECRYPT_FROM_PEM:
        ret = Cmd_sm2_private_key_info_decrypt_from_pem(paramTypes, params);
        break;
    case TA_CMD_SM2_PUBLIC_KEY_EQU:
        ret = Cmd_sm2_public_key_equ(paramTypes, params);
        break;
    case TA_CMD_SM2_DO_DECRYPT:
        ret = Cmd_sm2_do_decrypt(paramTypes, params);
        break;
    
    // SM3算法命令处理
    case TA_CMD_SM3_INIT:
        ret = Cmd_sm3_init(paramTypes, params);
        break;
    case TA_CMD_SM3_UPDATE:
        ret = Cmd_sm3_update(paramTypes, params);
        break;
    case TA_CMD_SM3_FINISH:
        ret = Cmd_sm3_finish(paramTypes, params);
        break;
    case TA_CMD_SM3_DIGEST:
        ret = Cmd_sm3_digest(paramTypes, params);
        break;
    case TA_CMD_SM3_HMAC_INIT:
        ret = Cmd_sm3_hmac_init(paramTypes, params);
        break;
    case TA_CMD_SM3_HMAC_UPDATE:
        ret = Cmd_sm3_hmac_update(paramTypes, params);
        break;
    case TA_CMD_SM3_HMAC_FINISH:
        ret = Cmd_sm3_hmac_finish(paramTypes, params);
        break;
    
    // SM4算法命令处理
    case TA_CMD_SM4_SET_KEY:
        ret = Cmd_sm4_set_key(paramTypes, params);
        break;
    case TA_CMD_SM4_ENCRYPT:
        ret = Cmd_sm4_encrypt(paramTypes, params);
        break;
    case TA_CMD_SM4_DECRYPT:
        ret = Cmd_sm4_decrypt(paramTypes, params);
        break;
    case TA_CMD_SM4_SET_ENCRYPT_KEY:
        ret = Cmd_sm4_set_encrypt_key(paramTypes, params);
        break;
    case TA_CMD_SM4_SET_DECRYPT_KEY:
        ret = Cmd_sm4_set_decrypt_key(paramTypes, params);
        break;
    case TA_CMD_SM4_CBC_ENCRYPT:
        ret = Cmd_sm4_cbc_encrypt(paramTypes, params);
        break;
    case TA_CMD_SM4_CBC_DECRYPT:
        ret = Cmd_sm4_cbc_decrypt(paramTypes, params);
        break;
    case TA_CMD_SM4_CBC_PADDING_DECRYPT:
        ret = Cmd_sm4_cbc_padding_decrypt(paramTypes, params);
        break;

    default:
        ret = TEE_ERROR_NOT_SUPPORTED;
        break;
    }

    return ret;
}
// 在这里对于持久保存的对象进行销毁，或者进行创建工作
void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    // SLogTrace("---- TA_CloseSessionEntryPoint ----- "); // 删除打印以提升性能
}

TEE_Result Cmd_sm2_do_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    SLogTrace("TA: Cmd_sm2_do_decrypt called");
    
    // 检查参数类型：输入数据 + 输出数据 + 无 + 无
    if (TEE_PARAM_TYPE_MEMREF_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 0) ||
        TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 1) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 2) ||
        TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(paramTypes, 3))
    {
        SLogTrace("TA: Parameter type check failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 获取输入参数
    uint8_t *input_data = (uint8_t *)params[0].memref.buffer;
    size_t input_len = params[0].memref.size;
    
    // 获取输出参数
    uint8_t *output_data = (uint8_t *)params[1].memref.buffer;
    size_t output_len = params[1].memref.size;
    
    SLogTrace("TA: input_len=%zu, output_len=%zu, SM2_KEY size=%zu, SM2_CIPHERTEXT size=%zu", 
              input_len, output_len, sizeof(SM2_KEY), sizeof(SM2_CIPHERTEXT));
    
    // 参数验证
    if (input_len < sizeof(SM2_KEY) + sizeof(SM2_CIPHERTEXT) || output_len < 1024) {
        SLogTrace("TA: Parameter validation failed: input_len=%zu < %zu or output_len=%zu < 1024", 
                  input_len, sizeof(SM2_KEY) + sizeof(SM2_CIPHERTEXT), output_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 反序列化输入参数
    SM2_KEY key;
    SM2_CIPHERTEXT ciphertext;
    
    // 解析SM2_KEY
    memcpy(&key, input_data, sizeof(SM2_KEY));
    
    // 解析SM2_CIPHERTEXT
    memcpy(&ciphertext, input_data + sizeof(SM2_KEY), sizeof(SM2_CIPHERTEXT));
    
    // 执行SM2解密
    uint8_t out[1024];
    size_t outlen = 0;
    SLogTrace("TA: About to call sm2_do_decrypt");
    int result = sm2_do_decrypt(&key, &ciphertext, out, &outlen);
    SLogTrace("TA: sm2_do_decrypt returned %d, outlen=%zu", result, outlen);
    
    if (result != 1) {
        SLogTrace("TA: sm2_do_decrypt failed");
        return TEE_ERROR_GENERIC;
    }
    
    // 检查输出缓冲区大小
    if (outlen > 1024 || output_len < outlen + sizeof(size_t)) {
        SLogTrace("TA: Output buffer too small: outlen=%zu, output_len=%zu", outlen, output_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 序列化输出结果：输出长度 + 输出数据
    SLogTrace("TA: About to serialize output, outlen=%zu", outlen);
    *(size_t*)output_data = outlen;  // 首先写入输出长度
    memcpy(output_data + sizeof(size_t), out, outlen);  // 然后写入输出数据
    SLogTrace("TA: Output serialized successfully");
    
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    // SLogTrace("---- TA_DestroyEntryPoint ---- "); // 删除打印以提升性能
}

/*-----------------------------------------------------------------------*/
