#include "sheFloat.h"
// she密文加上的那个常数的扩大倍数得一致
// bn_mod_add没说结果和输入能不能一致，那就当不一致吧，看了手册bn_add就可以
void sheADDConstant(SHECipher *res, double cons, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx)
{
    int64_t tmpInt = (int64_t)(cons * k); // 加法默认至少有一个扩大次数,乘一次应该不至于超过int64,精度暂这样吧
    BN_CTX_start(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *bigK = BN_CTX_get(ctx);
    BN_set_word(bigK, k);
    if (tmpInt < 0)
    {
        BN_set_word(tmp1, -tmpInt);
        BN_set_negative(tmp1, 1);
    }
    else
    {
        BN_set_word(tmp1, tmpInt);
    }
    for (int i = 0; i < c1->kTimes - 1; ++i)
    {
        BN_mul(tmp1, tmp1, bigK, ctx);
    }
// 上面是根据cipher的扩大倍数去扩大自己
// BN_add(res->cipher, c1->cipher, tmp1);
#ifdef __DEBUG__
    printf("delta方乘以r1结果为：\n");
    bn_printfDec(tmp1);
    bn_printfDec(c1->cipher);
    bn_printfDec(key->n);
    BN_add(res->cipher, c1->cipher, tmp1);
    bn_printfDec(res->cipher);
    BN_mod(res->cipher, res->cipher, key->n, ctx);
    bn_printfDec(res->cipher);
#endif
    BN_mod_add(res->cipher, c1->cipher, tmp1, key->n, ctx); // 因为tmp1可能是负数，所以cipher不能是0
    // bn_printfDec(res->cipher);
    res->kTimes = c1->kTimes;
    BN_CTX_end(ctx);
}
// 输入和结果最好不一样
// 推导了下，SHE不支持密文减法。。。因为一旦出现负数，它就会用p去弥补，（假设明文是-2）变成p-2,再mod l必然不对啊
// 注意这里说得减法是指默认两个正数通过she加密后得来的密文，然后再减
// 我在TEE实战SHE算法里搞了个照片，推了下各种情况，你可以看下
// 除非你给它编码，变成l-m，因为你的支持负数都是通过l空间的划分得来的
void sheADDCC(SHECipher *res, SHECipher *c1, SHECipher *c2, int k, SHE_key *key, BN_CTX *ctx)
{
    BIGNUM *bigK = BN_new();
    BN_set_word(bigK, k);
    if (c1->kTimes > c2->kTimes)
    {
        for (int i = 0; i < c1->kTimes - c2->kTimes; ++i)
        {
            BN_mod_mul(c2->cipher, c2->cipher, bigK, key->n, ctx);
        }
        c2->kTimes = c1->kTimes;
    }
    else if (c1->kTimes < c2->kTimes)
    {
        for (int i = 0; i < c2->kTimes - c1->kTimes; ++i)
        {
            BN_mod_mul(c1->cipher, c1->cipher, bigK, key->n, ctx);
        }
        c1->kTimes = c2->kTimes;
    }
    // 经过上面一波操作后，到这里肯定是两个人的扩大倍数一致了
    // BN_mod_add() adds a to b modulo m and places the nonnegative result in r.
    // 所以加法建议还是res,c1别一样
    BN_mod_add(res->cipher, c1->cipher, c2->cipher, key->n, ctx);
    res->kTimes = c1->kTimes;
    BN_free(bigK);
}

// 输出可以和输入一致
//  加法不管是密文和密文相加，还是密文和明文，都要保持扩大倍数一致，乘法就不需要了
void sheMULCC(SHECipher *res, SHECipher *c1, SHECipher *c2, int k, SHE_key *key, BN_CTX *ctx)
{
    // 密文和密文的乘法，默认都扩大好了吧，直接乘就行
    // BN_CTX_start(ctx);
    // 乘法res可以和c1或者c2一样
    BN_mod_mul(res->cipher, c1->cipher, c2->cipher, key->n, ctx);
    res->kTimes = c1->kTimes + c2->kTimes;
    // BN_CTX_end(ctx);
}
// 输出可以和输入一致
// 注意这里cons不能是负数
void sheMULConstant(SHECipher *res, double cons, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx)
{
    if (cons <= 0)
    {
        printf("SHE不能乘以明文的负数或者0\n");
        exit(-1);
    }
    int64_t tmpInt = (int64_t)(cons * k); // 默认有一个扩大次数,乘一次应该不至于超过int64,精度暂这样吧
    BIGNUM *tmp1 = BN_new();
    BN_set_word(tmp1, tmpInt);
    // 乘法res可以和c1或者c2一样
    BN_mod_mul(res->cipher, c1->cipher, tmp1, key->n, ctx);
    res->kTimes = c1->kTimes + 1;
    BN_free(tmp1);
}
// 输出可以和输入一致
void sheNEGC(SHECipher *res, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx)
{
    // BN_CTX_start(ctx);
    // 乘法res可以和c1或者c2一样
    BN_mod_mul(res->cipher, c1->cipher, key->e_negative1, key->n, ctx);
    res->kTimes = c1->kTimes;
    // BN_CTX_end(ctx);
}
// 输出和输入可以一致
void sheSETC(SHECipher *res, SHECipher *c1)
{
    BN_copy(res->cipher, c1->cipher);
    res->kTimes = c1->kTimes;
}

void sheInitC(SHECipher *res, BIGNUM *b, int kTimes)
{
    res->cipher = b;
    res->kTimes = kTimes;
}