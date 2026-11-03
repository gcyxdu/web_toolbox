#include "MPC_ta.h"

#include <stdarg.h>
#include <stdio.h>
#include "string.h"
#include "stdlib.h"
#include "utils/mt1993764.h"
#include "utils/SpritzCipher.h"
#include "utils/tools.h"

#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include "tee_object_api.h"
#include "tee_ext_api.h"

static const uint64_t rand64Seed = 2333;

// cli的一个
spritz_ctx ctx_cli;
// server的一个
spritz_ctx ctx_server;

const uint8_t csprngSeed[64] =
        {'1', '1', '4', '1', '5', '9', '2', '6',
         '5', '3', '5', '8', '9', '7', '9', '3',
         '2', '3', '8', '4', '6', '2', '6', '4',
         '3', '3', '8', '3', '2', '7', '9', '5',
         '0', '2', '8', '8', '4', '1', '9', '7',
         '1', '6', '9', '3', '9', '9', '3', '7',
         '5', '1', '0', '5', '8', '2', '0', '9',
         '7', '4', '9', '4', '4', '5', '9', '2'};
/*-----------------------------------------------------------------------*/
// 获取随机数
uint64_t getSecureRandom(spritz_ctx *ctx)
{
    return spritz_random64(ctx);
}
void cmd_GenAndOutBeaverTribles(uint64_t *arr, size_t len,int PARTY_FLAG)
{

    uint64_t loopTimes = len / sizeof(uint64_t);
    uint64_t * randbuff = (uint64_t *)malloc(sizeof(uint64_t) * loopTimes);

    // 这里代表CLI
    if (PARTY_FLAG == 0)
    {
        for (size_t i = 0; i < loopTimes; i += 3)
        {
            randbuff[i] = getSecureRandom(&ctx_cli);
            getSecureRandom(&ctx_cli);
            randbuff[i + 1] = getSecureRandom(&ctx_cli);
            getSecureRandom(&ctx_cli);
            randbuff[i + 2] = getSecureRandom(&ctx_cli);
        }
    }
    // 这里代表SERVER
    if (PARTY_FLAG == 1)
    {
        uint64_t a, b, c;
        for (size_t i = 0; i < loopTimes; i += 3)
        {
            a = getSecureRandom(&ctx_server);
            randbuff[i] = getSecureRandom(&ctx_server);
            b = getSecureRandom(&ctx_server);
            randbuff[i + 1] = getSecureRandom(&ctx_server);
            c = getSecureRandom(&ctx_server);
            randbuff[i + 2] = (a + randbuff[i]) * (b + randbuff[i + 1]) - c;
        }
    }

    memcpy(arr, randbuff, len);
    free(randbuff); // 释放内存
}
/*-----------------------------------------------------------------------*/
TEE_Result CmdGenAndOutBeaverTribles(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]){
    // 验证参数
    if (TEE_PARAM_TYPE_MEMREF_INOUT != TEE_PARAM_TYPE_GET(paramTypes, 0)||
        TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(paramTypes, 1)
            ) {
        SLogError("CMD_GENERATE_RANDOM: Bad expected parameter types.");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint64_t * arr = (uint64_t*)params[0].memref.buffer;
    size_t len = params[0].memref.size;

    int PARTY_FLAG = params[1].value.a;


    // 调用 cmd_GenAndOutBeaverTribles 函数
    cmd_GenAndOutBeaverTribles(arr, len, PARTY_FLAG);

    // 打印进入方法后的 arr 值（打印前 5 个元素作为示例）
//    SLogTrace("After calling cmd_GenAndOutBeaverTribles:");
//    for (size_t i = 0; i < len / sizeof(uint64_t); i++) {
//        SLogTrace("arr[%zu] = %llu", i, arr[i]);
//    }

    return TEE_SUCCESS;
}
/*-----------------------------------------------------------------------*/
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

// 打开一个session的进入点.
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4], void **sessionContext)
{
    TEE_Result ret = TEE_SUCCESS;
    SLogTrace("---- TA_OpenSessionEntryPoint -------- ");
    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    spritz_setup(&ctx_cli, csprngSeed, 64);
    spritz_setup(&ctx_server, csprngSeed, 64);

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
        case GenAndOutBeaverTribles:
            CmdGenAndOutBeaverTribles(paramTypes, params);
            SLogTrace("invoke GenAndOutBeaverTribles");
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

/*-----------------------------------------------------------------------*/
