#ifndef __GMSSL_TA_INTERFACE_H
#define __GMSSL_TA_INTERFACE_H

#include <stddef.h>
#include "tee_defines.h"

#define CLIENT_APPLICATION_NAME           "/vendor/bin/teec_tlcp"
#define PARAMS_IDX4                      4    // params参数的下标索引 4

// TLCP TrustZone命令定义 - 与CA端trustzone_adapter.h保持一致
enum {
    // SM2相关命令
    TA_CMD_SM2_SIGN = 0x1001,
    TA_CMD_SM2_VERIFY = 0x1002,
    TA_CMD_SM2_ENCRYPT = 0x1003,
    TA_CMD_SM2_DECRYPT = 0x1004,
    TA_CMD_SM2_KEYGEN = 0x1005,
    TA_CMD_SM2_SIGN_INIT = 0x1006,
    TA_CMD_SM2_SIGN_UPDATE = 0x1007,
    TA_CMD_SM2_SIGN_FINISH = 0x1008,
    TA_CMD_SM2_VERIFY_INIT = 0x1009,
    TA_CMD_SM2_VERIFY_UPDATE = 0x100A,
    TA_CMD_SM2_VERIFY_FINISH = 0x100B,
    TA_CMD_SM2_PRIVATE_KEY_INFO_DECRYPT_FROM_DER = 0x100C,
    TA_CMD_SM2_PRIVATE_KEY_INFO_DECRYPT_FROM_PEM = 0x100D,
    TA_CMD_SM2_PUBLIC_KEY_EQU = 0x100E,
    TA_CMD_SM2_DO_DECRYPT = 0x100F,
    
    // SM3相关命令
    TA_CMD_SM3_INIT = 0x2001,
    TA_CMD_SM3_UPDATE = 0x2002,
    TA_CMD_SM3_FINISH = 0x2003,
    TA_CMD_SM3_DIGEST = 0x2004,
    TA_CMD_SM3_HMAC_INIT = 0x2005,
    TA_CMD_SM3_HMAC_UPDATE = 0x2006,
    TA_CMD_SM3_HMAC_FINISH = 0x2007,
    
    // SM4相关命令
    TA_CMD_SM4_SET_KEY = 0x3001,
    TA_CMD_SM4_ENCRYPT = 0x3002,
    TA_CMD_SM4_DECRYPT = 0x3003,
    TA_CMD_SM4_SET_ENCRYPT_KEY = 0x3004,
    TA_CMD_SM4_SET_DECRYPT_KEY = 0x3005,
    TA_CMD_SM4_CBC_ENCRYPT = 0x3006,
    TA_CMD_SM4_CBC_DECRYPT = 0x3007,
    TA_CMD_SM4_CBC_PADDING_DECRYPT = 0x3008,
};

// SM2算法TA函数声明
TEE_Result Cmd_sm2_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_verify(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_encrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_keygen(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_sign_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_sign_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_sign_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_verify_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_verify_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_verify_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_private_key_info_decrypt_from_der(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_private_key_info_decrypt_from_pem(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_public_key_equ(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm2_do_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

// SM3算法TA函数声明
TEE_Result Cmd_sm3_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm3_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm3_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm3_digest(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm3_hmac_init(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm3_hmac_update(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm3_hmac_finish(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

// SM4算法TA函数声明
TEE_Result Cmd_sm4_set_key(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_encrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_set_encrypt_key(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_set_decrypt_key(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_cbc_encrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_cbc_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);
TEE_Result Cmd_sm4_cbc_padding_decrypt(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4]);

#endif