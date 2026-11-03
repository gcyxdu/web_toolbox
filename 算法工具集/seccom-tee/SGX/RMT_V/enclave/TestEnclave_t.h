#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _struct_foo_t
#define _struct_foo_t
typedef struct struct_foo_t {
	uint32_t count;
	size_t size;
	char* buf;
} struct_foo_t;
#endif

void generate_bool(void);
void test_ecall_inner_product(char** ptr, char* ret);
void model_training(unsigned char* ciphertext, int length);
void initSystem(void);
void Rand_Num_Generator(int* Rand_Num, int Lower, int Upper);
void decoding(float*** Xy_train_Output, char*** Block_Str, int* Participants, int Block_Size, int Num_Block, int Validator);
void update(float** theta_updated_Output, float* theta_t, float** Xy_train, int M, int Block_Size, int Num_Block, float alpha);
void Batch_Str_Decryption(char**** Batch_Str_D_Output, char*** Batch_Str, int Number_Participants, unsigned char* ivec);

sgx_status_t SGX_CDECL uprint(const char* str);
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
