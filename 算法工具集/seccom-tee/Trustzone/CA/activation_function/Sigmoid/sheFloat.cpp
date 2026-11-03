#include "sheFloat.h"

void sheADDConstant(SHECipher *res, double cons, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx) {
    int64_t tmpInt = (int64_t)(cons * k);
    BN_CTX_start(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *bigK = BN_CTX_get(ctx);
    BN_set_word(bigK, k);
    if (tmpInt < 0) {
        BN_set_word(tmp1, -tmpInt);
        BN_set_negative(tmp1, 1);
    } else {
        BN_set_word(tmp1, tmpInt);
    }
    for (int i = 0; i < c1->kTimes - 1; ++i) {
        BN_mul(tmp1, tmp1, bigK, ctx);
    }

#ifdef __DEBUG__
    printf("delta方乘以r1结果为: \n");
    bn_printfDec(tmp1);
    bn_printfDec(c1->cipher);
    bn_printfDec(key->n);
    BN_add(res->cipher, c1->cipher, tmp1);
    bn_printfDec(res->cipher);
    BN_mod(res->cipher, res->cipher, key->n, ctx);
    bn_printfDec(res->cipher);
#endif
    BN_mod_add(res->cipher, c1->cipher, tmp1, key->n, ctx);
    res->kTimes = c1->kTimes;
    BN_CTX_end(ctx);
}

void sheADDCC(SHECipher *res, SHECipher *c1, SHECipher *c2, int k, SHE_key *key, BN_CTX *ctx) {
    BIGNUM *bigK = BN_new();
    BN_set_word(bigK, k);
    if (c1->kTimes > c2->kTimes) {
        for (int i = 0; i < c1->kTimes - c2->kTimes; ++i) {
            BN_mod_mul(c2->cipher, c2->cipher, bigK, key->n, ctx);
        }
        c2->kTimes = c1->kTimes;
    } else if (c1->kTimes < c2->kTimes) {
        for (int i = 0; i < c2->kTimes - c1->kTimes; ++i) {
            BN_mod_mul(c1->cipher, c1->cipher, bigK, key->n, ctx);
        }
        c1->kTimes = c2->kTimes;
    }
    BN_mod_add(res->cipher, c1->cipher, c2->cipher, key->n, ctx);
    res->kTimes = c1->kTimes;
    BN_free(bigK);
}

// 加法不管是密文和密文相加, 还是密文和明文相加, 都要保持扩大倍数一致, 乘法就不需要了
void sheMULCC(SHECipher *res, SHECipher *c1, SHECipher *c2, int k, SHE_key *key, BN_CTX *ctx) {
    BN_mod_mul(res->cipher, c1->cipher, c2->cipher, key->n, ctx);
    res->kTimes = c1->kTimes + c2->kTimes;
}

// 注意: 这里cons不能是负数
void sheMULConstant(SHECipher *res, double cons, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx) {
    if (cons <= 0) {
        printf("SHE不能乘以明文的负数或者0\n");
        exit(-1);
    }
    int64_t tmpInt = (int64_t)(cons * k);
    BIGNUM *tmp1 = BN_new();
    BN_set_word(tmp1, tmpInt);
    BN_mod_mul(res->cipher, c1->cipher, tmp1, key->n, ctx);
    res->kTimes = c1->kTimes + 1;
    BN_free(tmp1);
}

void sheNEGC(SHECipher *res, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx) {
    BN_mod_mul(res->cipher, c1->cipher, key->e_negative1, key->n, ctx);
    res->kTimes = c1->kTimes;
}

void sheSETC(SHECipher *res, SHECipher *c1) {
    BN_copy(res->cipher, c1->cipher);
    res->kTimes = c1->kTimes;
}

void sheInitC(SHECipher *res, BIGNUM *b, int kTimes) {
    res->cipher = b;
    res->kTimes = kTimes;
}
