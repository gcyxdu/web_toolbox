#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_printf_helloworld_t {
	int ms_logN;
} ms_printf_helloworld_t;

typedef struct ms_init_t {
	int ms_logN;
	void* ms_s;
	void* ms_a;
	void* ms_b;
} ms_init_t;

typedef struct ms_TEE_NTT_test_t {
	int ms_logN;
} ms_TEE_NTT_test_t;

typedef struct ms_send_ciphertext_t {
	void* ms_c00;
	void* ms_c01;
	void* ms_c10;
	void* ms_c11;
} ms_send_ciphertext_t;

typedef struct ms_decodeEncrypt_t {
	void* ms_batchCipher0;
	void* ms_batchCipher1;
	void* ms_mulMessage;
} ms_decodeEncrypt_t;

typedef struct ms_getPTest_t {
	void* ms_batchCipher0;
} ms_getPTest_t;

typedef struct ms_ecall_batchtrans_ciphertext1_t {
	void* ms_batchCipher0;
	void* ms_batchCipher1;
} ms_ecall_batchtrans_ciphertext1_t;

typedef struct ms_ecall_batchtrans_information_t {
	void* ms_mulMessage;
} ms_ecall_batchtrans_information_t;

typedef struct ms_secure_add_t {
	void* ms_c0;
	void* ms_c1;
	void* ms_batchCipher0;
	void* ms_batchCipher1;
	int ms_len;
} ms_secure_add_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_printf_helloworld(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_printf_helloworld_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_printf_helloworld_t* ms = SGX_CAST(ms_printf_helloworld_t*, pms);
	ms_printf_helloworld_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_printf_helloworld_t), ms, sizeof(ms_printf_helloworld_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	printf_helloworld(__in_ms.ms_logN);


	return status;
}

static sgx_status_t SGX_CDECL sgx_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_init_t* ms = SGX_CAST(ms_init_t*, pms);
	ms_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_init_t), ms, sizeof(ms_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_s = __in_ms.ms_s;
	void* _tmp_a = __in_ms.ms_a;
	void* _tmp_b = __in_ms.ms_b;


	init(__in_ms.ms_logN, _tmp_s, _tmp_a, _tmp_b);


	return status;
}

static sgx_status_t SGX_CDECL sgx_TEE_NTT_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TEE_NTT_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TEE_NTT_test_t* ms = SGX_CAST(ms_TEE_NTT_test_t*, pms);
	ms_TEE_NTT_test_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TEE_NTT_test_t), ms, sizeof(ms_TEE_NTT_test_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	TEE_NTT_test(__in_ms.ms_logN);


	return status;
}

static sgx_status_t SGX_CDECL sgx_send_ciphertext(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_send_ciphertext_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_send_ciphertext_t* ms = SGX_CAST(ms_send_ciphertext_t*, pms);
	ms_send_ciphertext_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_send_ciphertext_t), ms, sizeof(ms_send_ciphertext_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_c00 = __in_ms.ms_c00;
	void* _tmp_c01 = __in_ms.ms_c01;
	void* _tmp_c10 = __in_ms.ms_c10;
	void* _tmp_c11 = __in_ms.ms_c11;


	send_ciphertext(_tmp_c00, _tmp_c01, _tmp_c10, _tmp_c11);


	return status;
}

static sgx_status_t SGX_CDECL sgx_decodeEncrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decodeEncrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decodeEncrypt_t* ms = SGX_CAST(ms_decodeEncrypt_t*, pms);
	ms_decodeEncrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_decodeEncrypt_t), ms, sizeof(ms_decodeEncrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_batchCipher0 = __in_ms.ms_batchCipher0;
	void* _tmp_batchCipher1 = __in_ms.ms_batchCipher1;
	void* _tmp_mulMessage = __in_ms.ms_mulMessage;


	decodeEncrypt(_tmp_batchCipher0, _tmp_batchCipher1, _tmp_mulMessage);


	return status;
}

static sgx_status_t SGX_CDECL sgx_getPTest(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getPTest_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getPTest_t* ms = SGX_CAST(ms_getPTest_t*, pms);
	ms_getPTest_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_getPTest_t), ms, sizeof(ms_getPTest_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_batchCipher0 = __in_ms.ms_batchCipher0;


	getPTest(_tmp_batchCipher0);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_batchtrans_ciphertext1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_batchtrans_ciphertext1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_batchtrans_ciphertext1_t* ms = SGX_CAST(ms_ecall_batchtrans_ciphertext1_t*, pms);
	ms_ecall_batchtrans_ciphertext1_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_batchtrans_ciphertext1_t), ms, sizeof(ms_ecall_batchtrans_ciphertext1_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_batchCipher0 = __in_ms.ms_batchCipher0;
	void* _tmp_batchCipher1 = __in_ms.ms_batchCipher1;


	ecall_batchtrans_ciphertext1(_tmp_batchCipher0, _tmp_batchCipher1);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_batchtrans_information(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_batchtrans_information_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_batchtrans_information_t* ms = SGX_CAST(ms_ecall_batchtrans_information_t*, pms);
	ms_ecall_batchtrans_information_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_batchtrans_information_t), ms, sizeof(ms_ecall_batchtrans_information_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_mulMessage = __in_ms.ms_mulMessage;


	ecall_batchtrans_information(_tmp_mulMessage);


	return status;
}

static sgx_status_t SGX_CDECL sgx_secure_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secure_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_secure_add_t* ms = SGX_CAST(ms_secure_add_t*, pms);
	ms_secure_add_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_secure_add_t), ms, sizeof(ms_secure_add_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_c0 = __in_ms.ms_c0;
	void* _tmp_c1 = __in_ms.ms_c1;
	void* _tmp_batchCipher0 = __in_ms.ms_batchCipher0;
	void* _tmp_batchCipher1 = __in_ms.ms_batchCipher1;


	secure_add(_tmp_c0, _tmp_c1, _tmp_batchCipher0, _tmp_batchCipher1, __in_ms.ms_len);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_printf_helloworld, 0, 0},
		{(void*)(uintptr_t)sgx_init, 0, 0},
		{(void*)(uintptr_t)sgx_TEE_NTT_test, 0, 0},
		{(void*)(uintptr_t)sgx_send_ciphertext, 0, 0},
		{(void*)(uintptr_t)sgx_decodeEncrypt, 0, 0},
		{(void*)(uintptr_t)sgx_getPTest, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_batchtrans_ciphertext1, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_batchtrans_information, 0, 0},
		{(void*)(uintptr_t)sgx_secure_add, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][9];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

