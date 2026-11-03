#ifndef __MPC_TA_INTERFACE_H
#define __MPC_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"
#define CLIENT_APPLICATION_NAME           "/vendor/bin/teec_mpc"

#define PARAMS_IDX4              4    // params参数的下标索引 4

enum {
    // 定义调用函数
    GenAndOutBeaverTribles = 0,
};

TEE_Result CmdGenAndOutBeaverTribles(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);


#endif