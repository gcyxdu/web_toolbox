#ifndef _GMSSL_h
#define _GMSSL_h

#include "tee_client_api.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define MAX_PATH FILENAME_MAX

// 函数声明
TEEC_Result TeecInit(void);
void TeecClose(void);
TEEC_Result _test_sm2(uint32_t *success_flag, uint32_t *duration_us);
TEEC_Result _test_sm2_sign(uint32_t *success_flag, uint32_t *duration_us);
TEEC_Result _test_sm2_verify(uint32_t *success_flag, uint32_t *duration_us);
TEEC_Result _test_sm3(uint32_t *success_flag, uint32_t *duration_us);
TEEC_Result _test_sm4(uint32_t* success_flag, uint32_t* duration_us);
TEEC_Result _test_sm9(uint32_t *success_flag, uint32_t *duration_us);
TEEC_Result _test_sm9_sign(uint32_t* success_flag, uint32_t* duration_us);
TEEC_Result _test_sm9_verify(uint32_t *success_flag, uint32_t *duration_us);

// 测试函数
void single_test_sm2();
void single_test_sm9();
void test_sm3();
void test_sm4();
void performance_test_sm2_sign();
void performance_test_sm2_verify();
void performance_test_sm9_sign();
void performance_test_sm9_verify();

#endif