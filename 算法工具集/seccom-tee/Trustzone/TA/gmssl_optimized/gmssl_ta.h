#ifndef __MATRIX_TA_INTERFACE_H
#define __MATRIX_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"
#define CLIENT_APPLICATION_NAME "/vendor/bin/teec_gmssl"

#define PARAMS_IDX4 4 // params参数的下标索引 4

enum
{
    // test_sm2_sign = 0,
    // test_sm3,
    // test_sm4,
    // test_sm9_z256_sign
    test_sm2 = 0,
    test_sm2_sign,
    test_sm2_verify,
    test_sm3,
    test_sm4,
    test_sm9,
    test_sm9_sign,
    test_sm9_verify
};
TEE_Result Cmd_test_sm2_do_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm2_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm2_verify(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm3(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_speed_sm3(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm4(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm9(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm9_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_test_sm9_verify(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

#endif