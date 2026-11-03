#ifndef __MPC_TA_INTERFACE_H
#define __MPC_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"
#define CLIENT_APPLICATION_NAME           "/vendor/bin/teec_tckks"

#define PARAMS_IDX4              4    // params参数的下标索引 4
// 定义invoke调用的内容
enum {
    // 定义调用函数
    init = 0,
    send_ciphertext,
    ecall_batchtrans_information,
    decodeEncrypt,
    secure_sum
};

TEE_Result CMDinit(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDsend_ciphertext(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDecall_batchtrans_information(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDdecodeEncrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDsecure_sum(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

#endif