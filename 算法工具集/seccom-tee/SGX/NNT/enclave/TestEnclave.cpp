#include "TestEnclave.h"

#include <math.h>
#include <sgx_trts.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "TestEnclave_t.h"
#include "network.h"
#include "tSgxSSL_api.h"

#define ADD_ENTROPY_SIZE 32

extern SHE_key KEY;
using namespace std;

Network *_global_network;

void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

void SHEkMulTEE(char *outputString, BIGNUM *input1, BIGNUM *input2) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x1, *x2, *x1_mul_x2, *en_x1_mul_x2;
    char *tmp_char = NULL;
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    x1_mul_x2 = BN_CTX_get(ctx);
    en_x1_mul_x2 = BN_CTX_get(ctx);
    int x1_int, x2_int, x1_mul_x2_int;
    int k = 1000000;
    double x1_double, x2_double;
    she_decryptBignum(x1, input1, &KEY, ctx);
    she_decryptBignum(x2, input2, &KEY, ctx);

    BN_bn2lebinpad(x1, (unsigned char *)&x1_int, sizeof(int));
    if (BN_is_negative(x1)) {
        x1_int = -x1_int;
    }
    x1_double = ((double)x1_int) / k;

    BN_bn2lebinpad(x2, (unsigned char *)&x2_int, sizeof(int));
    if (BN_is_negative(x2)) {
        x2_int = -x2_int;
    }
    x2_double = ((double)x2_int) / k;

    x1_mul_x2_int = (int)(x1_double * x2_double * k);
    if (x1_mul_x2_int < 0) {
        BN_set_word(x1_mul_x2, -x1_mul_x2_int);
        BN_set_negative(x1_mul_x2, 1);
    } else {
        BN_set_word(x1_mul_x2, x1_mul_x2_int);
    }

    she_encryptBignumSupportNegative2(en_x1_mul_x2, x1_mul_x2, &KEY, ctx);
    tmp_char = BN_bn2hex(en_x1_mul_x2);
    memcpy(outputString, tmp_char, strlen(tmp_char) + 1);
    OPENSSL_free(tmp_char);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

double Sigmoid(double x) {
    return 1.0 / (1 + exp(-x));
}

void getActivation(char *res, int LayerSeqNum, int NodeSeqNum, BIGNUM *input) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    int64_t tmp1 = 0;
    double tmp2;
    int k = 1000000;
    she_decryptBignum(plain, input, &KEY, ctx);
    BN_bn2lebinpad(plain, (unsigned char *)&tmp1, sizeof(int64_t));
    if (BN_is_negative(plain)) {
        tmp1 = -tmp1;
    }
    tmp2 = ((double)tmp1) / k;
    tmp2 = tmp2 / k;

    Layer *tmpLayer = _global_network->mLayers[LayerSeqNum];
    tmpLayer->mOutputs[NodeSeqNum] = Sigmoid(tmp2);
    tmp1 = (int64_t)(tmpLayer->mOutputs[NodeSeqNum] * k);

    BN_set_word(plain, tmp1);
    she_encryptTeeStringBignum2(res, plain);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calENegx(char *outputString, BIGNUM *input) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x, *ex_MulKtimes, *en_ex_MulKtimes;
    char *tmp_char = NULL;
    x = BN_CTX_get(ctx);
    ex_MulKtimes = BN_CTX_get(ctx);
    en_ex_MulKtimes = BN_CTX_get(ctx);

    int64_t x_int;
    int k_times = 1000000;
    she_decryptBignum(x, input, &KEY, ctx);
    BN_bn2lebinpad(x, (unsigned char *)(&x_int), sizeof(int64_t));
    if (BN_is_negative(x)) {
        x_int = -x_int;
    }

    double x_double;
    double ex_double;
    x_double = ((double)x_int) / k_times;
    x_double = x_double / k_times;
    x_double = -x_double;
    ex_double = exp(x_double);

    int64_t ex_MulKtimes_int;
    ex_MulKtimes_int = ex_double * k_times;
    BN_set_word(ex_MulKtimes, ex_MulKtimes_int);
    she_encryptBignumSupportNegative2(en_ex_MulKtimes, ex_MulKtimes, &KEY, ctx);
    tmp_char = BN_bn2hex(en_ex_MulKtimes);
    memcpy(outputString, tmp_char, strlen(tmp_char) + 1);
    OPENSSL_free(tmp_char);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calNegx(char *outputString, int flag, BIGNUM *input) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x, *x_MulKtimes, *en_x_MulKtimes;
    char *tmp_char = NULL;
    x = BN_CTX_get(ctx);
    x_MulKtimes = BN_CTX_get(ctx);
    en_x_MulKtimes = BN_CTX_get(ctx);
    int64_t x_int;
    int k_times = 1000000;

    she_decryptBignum(x, input, &KEY, ctx);
    BN_div_word(x, k_times);
    BN_bn2lebinpad(x, (unsigned char *)(&x_int), sizeof(int64_t));
    if (BN_is_negative(x)) {
        x_int = -x_int;
    }
    double x_double;
    x_double = ((double)x_int) / k_times;
    x_double = x_double / k_times;
    x_double = -x_double;

    int64_t x_MulKtimes_int;
    if (flag == 1) {
        x_MulKtimes_int = x_double * k_times * k_times;
    } else {
        x_MulKtimes_int = x_double * k_times;
    }

    BN_set_word(x_MulKtimes, (x_MulKtimes_int < 0) ? -x_MulKtimes_int : x_MulKtimes_int);
    // 设置正负号
    if (x_MulKtimes_int < 0) {
        BN_set_negative(x_MulKtimes, 1);
    }
    she_encryptBignumSupportNegative2(en_x_MulKtimes, x_MulKtimes, &KEY, ctx);
    tmp_char = BN_bn2hex(en_x_MulKtimes);
    memcpy(outputString, tmp_char, strlen(tmp_char) + 1);
    OPENSSL_free(tmp_char);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calRefreshX(char *outputString, int inputTimes, int outputTimes, BIGNUM *input) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x, *x_MulKtimes, *en_x_MulKtimes;
    char *tmp_char = NULL;
    x = BN_CTX_get(ctx);
    x_MulKtimes = BN_CTX_get(ctx);
    en_x_MulKtimes = BN_CTX_get(ctx);
    int64_t x_int;
    int k_times = 1000000;

    she_decryptBignum(x, input, &KEY, ctx);
    while (BN_num_bytes(x) > sizeof(int64_t)) {
        BN_div_word(x, k_times);
        inputTimes--;
    }

    BN_bn2lebinpad(x, (unsigned char *)(&x_int), sizeof(int64_t));
    if (BN_is_negative(x)) {
        x_int = -x_int;
    }

    double x_double = (double)x_int;
    for (int i = 0; i < inputTimes; i++) {
        x_double = x_double / k_times;
    }

    int64_t x_MulKtimes_int;
    x_MulKtimes_int = x_double * k_times;
    BN_set_word(x_MulKtimes, (x_MulKtimes_int < 0) ? -x_MulKtimes_int : x_MulKtimes_int);
    if (x_MulKtimes_int < 0) {
        BN_set_negative(x_MulKtimes, 1);
    }

    for (int i = 0; i < outputTimes - 1; i++) {
        BN_mul_word(x_MulKtimes, k_times);
    }

    she_encryptBignumSupportNegative2(en_x_MulKtimes, x_MulKtimes, &KEY, ctx);
    tmp_char = BN_bn2hex(en_x_MulKtimes);
    memcpy(outputString, tmp_char, strlen(tmp_char) + 1);

    OPENSSL_free(tmp_char);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void sigmoid_inverseX(char *outputString, BIGNUM *input) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x_Mulk3, *inverse_x_MulKtimes, *en_inverse_x_MulKtimes;
    char *tmp_char = NULL;
    x_Mulk3 = BN_CTX_get(ctx);
    inverse_x_MulKtimes = BN_CTX_get(ctx);
    en_inverse_x_MulKtimes = BN_CTX_get(ctx);
    int64_t xMulk2_int;
    int k_times = 1000000;

    she_decryptBignum(x_Mulk3, input, &KEY, ctx);
    BN_div_word(x_Mulk3, k_times);
    BN_bn2lebinpad(x_Mulk3, (unsigned char *)(&xMulk2_int), sizeof(int64_t));

    double x_double;
    double inverse_x_double;
    x_double = ((double)xMulk2_int) / k_times;
    x_double = x_double / k_times;
    inverse_x_double = 1 / x_double;
    int inverse_x_MulKtimes_int;
    inverse_x_MulKtimes_int = inverse_x_double * k_times;
    BN_set_word(inverse_x_MulKtimes, inverse_x_MulKtimes_int);

    she_encryptBignumSupportNegative2(en_inverse_x_MulKtimes, inverse_x_MulKtimes, &KEY, ctx);
    tmp_char = BN_bn2hex(en_inverse_x_MulKtimes);
    memcpy(outputString, tmp_char, strlen(tmp_char) + 1);
    OPENSSL_free(tmp_char);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calRelu(BIGNUM *Eb1, BIGNUM *Eb2, BIGNUM *Em1) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *m1 = BN_CTX_get(ctx);
    she_decryptBignum(m1, Em1, &KEY, ctx);
    if (BN_is_negative(m1)) {
        BN_copy(Eb1, KEY.cipher_zero);
        BN_copy(Eb2, KEY.cipher_one);
    } else {
        BN_copy(Eb1, KEY.cipher_one);
        BN_copy(Eb2, KEY.cipher_zero);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void sheRescale(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i) {
        BN_div_word(xMulKTimes, k);
    }
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void sheRescaleNeg(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    BIGNUM *negOne = BN_CTX_get(ctx);
    BN_one(negOne);
    BN_set_negative(negOne, 1);
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i) {
        BN_div_word(xMulKTimes, k);
    }
    BN_mul(xMulKTimes, xMulKTimes, negOne, ctx);
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void reluCipherMulTEE(BIGNUM *output, BIGNUM *Eb, BIGNUM *Em, int k, int EmTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *mMulKTimes = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);

    she_decryptBignum(mMulKTimes, Em, &KEY, ctx);
    she_decryptBignum(b, Eb, &KEY, ctx);
    for (int i = 0; i < EmTimes - 1; ++i) {
        BN_div_word(mMulKTimes, k);
    }
    BN_mul(res, mMulKTimes, b, ctx);
    she_encryptBignumSupportNegative2(res, res, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
