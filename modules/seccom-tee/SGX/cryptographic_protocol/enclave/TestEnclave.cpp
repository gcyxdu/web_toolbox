#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "TestEnclave.h"
#include "TestEnclave_t.h" /* print_string */
#include "tSgxSSL_api.h"

#define ADD_ENTROPY_SIZE 32
// paillier
// #include <stdlib.h>
#include <iostream>
// #include<fstream>
#include <deque>
#include <iomanip>
#include <list>
#include <string>
#include <vector>
// sgx_read_rand
#include <math.h>
#include <sgx_trts.h>
#include <string.h>
// 下面即使include了没用，得extern c
//  #include "./tests/she.h"
extern SHE_key KEY;
using namespace std;
// #define IMAGE_SIZE 4
// #define LABEL_SIZE 3
// #define LAYER_1_SIZE 128
// #define LAYER_2_SIZE 64
// 输入层是第0层，按标号的话是-1层
// 漏了加1,即漏了b
// double W1[LAYER_1_SIZE][IMAGE_SIZE + 1], W3[LABEL_SIZE][LAYER_1_SIZE + 1];
// // int W1K[LAYER_1_SIZE][IMAGE_SIZE],W2K[LAYER_2_SIZE][LAYER_1_SIZE],W3K[LABEL_SIZE][LAYER_2_SIZE];
// double A1[LAYER_1_SIZE], A3[LABEL_SIZE];

void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

int vprintf_cb(Stream_t stream, const char *fmt, va_list arg) {
    char buf[BUFSIZ] = {'\0'};

    int res = vsnprintf(buf, BUFSIZ, fmt, arg);
    if (res >= 0) {
        sgx_status_t sgx_ret = uprint((const char *)buf);
        TEST_CHECK(sgx_ret);
    }
    return res;
}

void t_sgxssl_call_apis() {
    //	printf("i am here1\n");
    she_test();
    // char str_c[2000]={0};
    // char str_plain[2000]={0};
    // generateRandomKeys_she_py();
    // encrypt_she_py(str_c, "-AA");
    // printf("%s\n",str_c);
    // decrypt_she_py(str_plain,str_c);
    // printf("%s\n",str_plain);

    //	printf("i am here2\n");
    // int ret = 0;
    printf("Start tests\n");
    // uint32_t val;
    // sgx_read_rand((unsigned char *)&val, 4);
    // printf("随机数：%u\n", val);
}

// BIGNUM *p, *q, *l, *n, *e_negative1, *l_2, *cipher_zero;
void keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1, BIGNUM *l_2, BIGNUM *cipher_zero,
                    BIGNUM *cipher_one) {
    BN_copy(p, KEY.p);
    BN_copy(q, KEY.q);
    BN_copy(l, KEY.l);
    BN_copy(n, KEY.n);
    BN_copy(e_negative1, KEY.e_negative1);
    BN_copy(l_2, KEY.l_2);
    BN_copy(cipher_zero, KEY.cipher_zero);
    BN_copy(cipher_one, KEY.cipher_one);
}

void reluCipherMulTEE(BIGNUM *output, BIGNUM *Eb, BIGNUM *Em, int k, int EmTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *mMulKTimes = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);

    she_decryptBignum(mMulKTimes, Em, &KEY, ctx);
    she_decryptBignum(b, Eb, &KEY, ctx);
    for (int i = 0; i < EmTimes - 1; ++i)  // 默认至少放大一倍
        BN_div_word(mMulKTimes, k);
    BN_mul(res, mMulKTimes, b, ctx);
    she_encryptBignumSupportNegative2(res, res, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// k^2进来，算完e(-x)乘以k出去
void calENegx(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *ex, *x, *ex_MulKtimes, *en_ex_MulKtimes;
    x = BN_CTX_get(ctx);
    ex = BN_CTX_get(ctx);
    ex_MulKtimes = BN_CTX_get(ctx);
    en_ex_MulKtimes = BN_CTX_get(ctx);
    int ret = 0;
    int64_t x_int;  // 2的64次方，大于10的18次方，所以来的数字不要大于这个
    she_decryptBignum(x, input, &KEY, ctx);
    // bn_printfDec(x);
    BN_bn2lebinpad(x, (unsigned char *)(&x_int), sizeof(int64_t));
    if (BN_is_negative(x)) {
        x_int = -x_int;
    }
    // printf("k2(x+r1):%lld\n", x_int);
    double x_double;
    double ex_double;
    x_double = ((double)x_int) / 1.0;
    for (int i = 0; i < kTimes; ++i) x_double = x_double / k;
    x_double = -x_double;  // 因为是算e的-x
    // printf("x_double:%lf\n", x_double);
    ex_double = exp(x_double);
    // printf("ex_double:%lf\n", ex_double);
    // 乘以k然后加密出来	//越界了，兄弟，哎。。。
    // int ex_MulKtimes_int;
    int64_t ex_MulKtimes_int;
    ex_MulKtimes_int = ex_double * k;
    // printf("ex_MulKtimes:%d\n",ex_MulKtimes_int);
    BN_set_word(ex_MulKtimes, ex_MulKtimes_int);
    // bn_printfDec(ex_MulKtimes);
    she_encryptBignumSupportNegative2(en_ex_MulKtimes, ex_MulKtimes, &KEY, ctx);
    BN_copy(output, en_ex_MulKtimes);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// 解密算个正负，返回两个值，一个E(0)，一个E(1)
void calRelu(BIGNUM *Eb1, BIGNUM *Eb2, BIGNUM *Em1) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *m1 = BN_CTX_get(ctx);
    she_decryptBignum(m1, Em1, &KEY, ctx);
    // bn_printfDec(m1);
    if (BN_is_negative(m1))  //<0
    {
        // printf("TEE解密为负数\n");
        BN_copy(Eb1, KEY.cipher_zero);
        BN_copy(Eb2, KEY.cipher_one);
    } else  //>0
    {
        BN_copy(Eb1, KEY.cipher_one);
        BN_copy(Eb2, KEY.cipher_zero);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// 注意，进来时k三次方乘以x，出去是乘以k,默认算sigmoid的分母
void sigmoid_inverseX(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x_Mulk3, *inverse_x_MulKtimes, *en_inverse_x_MulKtimes;
    x_Mulk3 = BN_CTX_get(ctx);
    inverse_x_MulKtimes = BN_CTX_get(ctx);
    en_inverse_x_MulKtimes = BN_CTX_get(ctx);
    int ret = 0;
    int64_t xMulk2_int;
    she_decryptBignum(x_Mulk3, input, &KEY, ctx);  // 解密完肯定是正数
    // 即使是Int64t，还是装不下，所以除以一个k,但我感觉似乎能装下啊。。。算了
    BN_div_word(x_Mulk3, k);
    // bn_printfHex(x);
    BN_bn2lebinpad(x_Mulk3, (unsigned char *)(&xMulk2_int), sizeof(int64_t));  // sigmoid分母的数字耶，就是正数吧，哈哈
    // printf("打印下越界的k^3,比int64大：%lld\n", xMulk2_int);
    double x_double;
    double inverse_x_double;
    x_double = ((double)xMulk2_int) / k;
    for (int i = 0; i < kTimes - 2; ++i)  // 这岂不是默认至少要两次了
    {
        x_double = x_double / k;
    }

    // printf("x_double:%lf\n",x_double);
    inverse_x_double = 1 / x_double;
    // printf("inverse_x_double:%lf\n",inverse_x_double);
    // 乘以k然后加密出来
    int inverse_x_MulKtimes_int;
    inverse_x_MulKtimes_int = inverse_x_double * k;
    // printf("inverse_x_MulKtimes:%d\n",inverse_x_MulKtimes_int);
    BN_set_word(inverse_x_MulKtimes, inverse_x_MulKtimes_int);  // 这里假定就是正数了，毕竟sigmoid下面都是正数吧
    she_encryptBignumSupportNegative2(en_inverse_x_MulKtimes, inverse_x_MulKtimes, &KEY, ctx);
    BN_copy(output, en_inverse_x_MulKtimes);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// kTimes放大倍数进来,1次放大倍数出去
void sheRescale(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    // printf("debug start\n");
    // bn_printfHex(input);
    // bn_printfHex(KEY.n);
    // printf("debug end\n");
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i)  // 默认至少放大一倍...
        BN_div_word(xMulKTimes, k);  // 其实就是一种截断，小数就不要了，因为你这里不需要计算，所以小数没关系
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

// kTimes放大倍数进来,1次放大倍数出去
void sheRescaleNeg(BIGNUM *output, BIGNUM *input, int k, int kTimes) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *xMulKTimes = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    BIGNUM *negOne = BN_CTX_get(ctx);
    BN_one(negOne);
    BN_set_negative(negOne, 1);
    // printf("debug start\n");
    // bn_printfHex(input);
    // bn_printfHex(KEY.n);
    // printf("debug end\n");
    she_decryptBignum(xMulKTimes, input, &KEY, ctx);
    for (int i = 0; i < kTimes - 1; ++i)  // 默认至少放大一倍...
        BN_div_word(xMulKTimes, k);  // 其实就是一种截断，小数就不要了，因为你这里不需要计算，所以小数没关系
    BN_mul(xMulKTimes, xMulKTimes, negOne, ctx);
    she_encryptBignumSupportNegative2(res, xMulKTimes, &KEY, ctx);
    BN_copy(output, res);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
