#ifndef __SOFTMAX_TA_INTERFACE_H
#define __SOFTMAX_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"
#define CLIENT_APPLICATION_NAME           "/vendor/bin/teec_softmax_contrast"

#define PARAMS_IDX4              4    // params参数的下标索引 4

enum {
    sheRescale = 0,
    sheRescaleNeg,
    calEx,
    keySynthronize,
    getFraction,
    reluCipherMulTEE,
    SHEgenerateRandomKeysTee2,
};

TEE_Result CmdsheRescale(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdsheRescaleNeg(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdcalEx(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdkeySynthronize(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdgetFraction(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdreluCipherMulTEE(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdSHEgenerateRandomKeysTee2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

#endif