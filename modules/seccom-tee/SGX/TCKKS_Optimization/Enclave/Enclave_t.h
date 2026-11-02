#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void printf_helloworld(int logN);
void init(int logN, void* s, void* a, void* b);
void TEE_NTT_test(int logN);
void send_ciphertext(void* c00, void* c01, void* c10, void* c11);
void decodeEncrypt(void* batchCipher0, void* batchCipher1, void* mulMessage);
void getPTest(void* batchCipher0);
void ecall_batchtrans_ciphertext1(void* batchCipher0, void* batchCipher1);
void ecall_batchtrans_information(void* mulMessage);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
