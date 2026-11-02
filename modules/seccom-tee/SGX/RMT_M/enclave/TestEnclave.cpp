#include "TestEnclave.h"
#include <math.h>
#include <sgx_trts.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "TestEnclave_t.h"
#include "network.h"
#include "tSgxSSL_api.h"

extern SHE_key KEY;
using namespace std;

Network *_enclave_network;

void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

void t_sgxssl_call_apis() {
    she_test();
    printf("Start tests\n");
}

void initial(int networkInputs, int networkOutputs, int *LayNum, int num) {
    _enclave_network = new Network(networkInputs, networkOutputs);
    for (int k = 0; k < num - 1; ++k) {
        _enclave_network->addLayer(LayNum[k + 1]);
    }
}

void getSoftmaxSum(double *exSumAddr, int LayerSeqNum, BIGNUM **input) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    int64_t tmp1 = 0;
    double tmp2;
    int k = 1000000;

    Layer *tmpLayer = _enclave_network->mLayers[LayerSeqNum];
    double *exArr = (double *)malloc(sizeof(double) * tmpLayer->mNumNodes);
    for (int i = 0; i < tmpLayer->mNumNodes; ++i) {
        she_decryptBignum(plain, input[i], &KEY, ctx);
        BN_bn2lebinpad(plain, (unsigned char *)&tmp1, sizeof(int64_t));
        if (BN_is_negative(plain)) {
            tmp1 = -tmp1;
        }
        tmp2 = ((double)tmp1) / k;
        tmp2 = tmp2 / k;
        exArr[i] = tmp2;
    }
    tmp2 = 0.0;
    for (int i = 0; i < tmpLayer->mNumNodes; ++i) {
        tmp2 += exArr[i];
    }
    *exSumAddr = tmp2;

    free(exArr);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void getSoftmax(char *res, int LayerSeqNum, int NodeSeqNum, BIGNUM **input, double sumEx) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    int64_t tmp1 = 0;
    double tmp2;
    int k = 1000000;
    Layer *tmpLayer = _enclave_network->mLayers[LayerSeqNum];
    double *exArr = (double *)malloc(sizeof(double) * tmpLayer->mNumNodes);

    for (int i = 0; i < tmpLayer->mNumNodes; ++i) {
        if (i != NodeSeqNum) {
            continue;
        }
        she_decryptBignum(plain, input[i], &KEY, ctx);
        BN_bn2lebinpad(plain, (unsigned char *)&tmp1, sizeof(int64_t));
        if (BN_is_negative(plain)) {
            tmp1 = -tmp1;
        }
        tmp2 = ((double)tmp1) / k;
        tmp2 = tmp2 / k;
        exArr[i] = tmp2;
    }

    tmpLayer->mOutputs[NodeSeqNum] = exArr[NodeSeqNum] / sumEx;
    tmp1 = (int64_t)(tmpLayer->mOutputs[NodeSeqNum] * k);
    BN_set_word(plain, tmp1);
    she_encryptTeeStringBignum2(res, plain);

    free(exArr);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void getFraction(char *res1, char *res2, BIGNUM *tmp1, BIGNUM *tmp2) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *dec1, *dec2;
    char *tmp_char1 = NULL;
    char *tmp_char2 = NULL;
    dec1 = BN_CTX_get(ctx);
    dec2 = BN_CTX_get(ctx);
    int64_t frac1, frac2;
    double f1, f2;
    int k_times = 1000000;
    she_decryptBignum(dec1, tmp1, &KEY, ctx);
    she_decryptBignum(dec2, tmp2, &KEY, ctx);

    BN_div_word(dec2, k_times);
    BN_bn2lebinpad(dec1, (unsigned char *)(&frac1), sizeof(int64_t));
    if (BN_is_negative(dec1)) {
        frac1 = -frac1;
    }
    BN_bn2lebinpad(dec2, (unsigned char *)(&frac2), sizeof(int64_t));
    if (BN_is_negative(dec2)) {
        frac2 = -frac2;
    }
    f1 = ((double)frac1) / k_times;
    f1 = f1 / k_times;
    f2 = ((double)frac2) / k_times;
    f2 = f2 / k_times;

    f1 = f1 / f2;
    f2 = 1 / f2;

    frac1 = (f1 * k_times) * k_times;
    if (frac1 < 0) {
        BN_set_word(tmp1, -frac1);
        BN_set_negative(tmp1, 1);
    } else {
        BN_set_word(tmp1, frac1);
    }
    she_encryptBignumSupportNegative2(dec1, tmp1, &KEY, ctx);
    tmp_char1 = BN_bn2hex(dec1);
    memcpy(res1, tmp_char1, strlen(tmp_char1) + 1);
    OPENSSL_free(tmp_char1);
    frac2 = f2 * k_times;
    if (frac2 < 0) {
        BN_set_word(tmp2, -frac2);
        BN_set_negative(tmp2, 1);
    } else {
        BN_set_word(tmp2, frac2);
    }
    she_encryptBignumSupportNegative2(dec2, tmp2, &KEY, ctx);
    tmp_char2 = BN_bn2hex(dec2);
    memcpy(res2, tmp_char2, strlen(tmp_char2) + 1);

    OPENSSL_free(tmp_char2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void calEx(char *outputString, BIGNUM *input) {
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
