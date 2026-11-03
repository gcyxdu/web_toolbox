#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "openssl/bn.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int she_generateRandomKeysTee(void);
int she_generateRandomKeysTee2(void);
void getActivation(char* res, int LayerSeqNum, int NodeSeqNum, BIGNUM* input);
int she_encryptTeeString(char* str_c, char* str_m);
void SHEkMulTEE(char* outputString, BIGNUM* input1, BIGNUM* input2);
void calRefreshX(char* outputString, int inputTimes, int outputTimes, BIGNUM* input);
void calENegx(char* outputString, BIGNUM* input);
void calNegx(char* outputString, int flag, BIGNUM* input);
void sigmoid_inverseX(char* outputString, BIGNUM* input);
void calRelu(BIGNUM* output1, BIGNUM* output2, BIGNUM* input);
void sheRescale(BIGNUM* output, BIGNUM* input, int k, int kTimes);
void sheRescaleNeg(BIGNUM* output, BIGNUM* input, int k, int kTimes);
void reluCipherMulTEE(BIGNUM* output, BIGNUM* Eb, BIGNUM* Em, int k, int EmTimes);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
