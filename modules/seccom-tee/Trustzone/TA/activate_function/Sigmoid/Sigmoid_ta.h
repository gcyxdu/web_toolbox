#ifndef __SIGMOID_TA_INTERFACE_H
#define __SIGMOID_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"
#define CLIENT_APPLICATION_NAME           "/vendor/bin/teec_sigmoid"

#define PARAMS_IDX4              4    // params参数的下标索引 4

enum {
    sheRescale = 0,
    calENegx,
    keySynthronize,
    sigmoidInverseX,
    SHEgenerateRandomKeysTee2,
};

TEE_Result CmdsheRescale(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdcalENegx(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdkeySynthronize(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdsigmoidInverseX(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CmdSHEgenerateRandomKeysTee2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

#endif