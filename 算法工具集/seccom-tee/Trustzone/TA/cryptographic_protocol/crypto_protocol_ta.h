#ifndef __CP_TA_INTERFACE_H
#define __CP_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"
#define CLIENT_APPLICATION_NAME           "/vendor/bin/teec_crypto_p"

#define PARAMS_IDX4              4    // params参数的下标索引 4
enum {
    sheRescale = 0,
    sheRescaleNeg,
    keySynthronize,
    reluCipherMulTEE,
    sheGenerateRandomKeysTee2,
};
TEE_Result CMDsheRescale(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDsheRescaleNeg(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDkeySynthronize(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDreluCipherMulTEE(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result CMDsheGenerateRandomKeysTee2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

#endif