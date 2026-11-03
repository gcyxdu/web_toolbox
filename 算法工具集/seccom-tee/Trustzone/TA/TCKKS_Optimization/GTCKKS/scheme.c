#include "scheme.h"
#include "stdlib.h"
#include "string.h"
#include "NumUtils.h"
#include "CTRingMultiplier.h"
#include "ciphertext.h"
#include "plaintext.h"
#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"
// 初始化 Scheme 对象
void Scheme_scheme_Init(size_t ploy_Lenth, void *s, void *a, void *b, Scheme *scheme) {



    scheme->ploy_modulus_degree = 1 << ploy_Lenth;
    scheme->scale = 20;
    scheme->multiple = (CTRingMultiplier *)malloc(sizeof(CTRingMultiplier));
    CTRingMultiplier_generate_prime(ploy_Lenth, 60, true,scheme->multiple); // 生成相关的素数
    scheme->qmod = scheme->multiple->pVec;

    scheme->s = (uint64_t *) malloc(sizeof(uint64_t) * scheme->ploy_modulus_degree);
    memcpy(scheme->s,s,sizeof(uint64_t) * scheme->ploy_modulus_degree);
    scheme->a = (uint64_t *) malloc(sizeof(uint64_t) * scheme->ploy_modulus_degree);
    memcpy(scheme->a,a,sizeof(uint64_t) * scheme->ploy_modulus_degree);
    scheme->b = (uint64_t *) malloc(sizeof(uint64_t) * scheme->ploy_modulus_degree);
    memcpy(scheme->b,b,sizeof(uint64_t) * scheme->ploy_modulus_degree);

    scheme->ciphers_num = 100;
    scheme->cur_cipher = 0;
    scheme->ciphers = (Ciphertext *) malloc(sizeof(Ciphertext) * scheme->ciphers_num);
    for (size_t i = 0; i < scheme->ciphers_num; i++) {
        // TODO 修改
        Scheme_init_pre_cipher(&(scheme->ciphers[i]), i,scheme);
    }
    /*// 打印参数：
    SLogTrace("scheme->ploy_modulus_degree:%zu",scheme->ploy_modulus_degree);
    SLogTrace("scheme->qmod:%lu",scheme->qmod);
    // 打印multiple里面的所有的内容
    SLogTrace("scheme->multiple->pVec:%lu",scheme->multiple->pVec);
    SLogTrace("scheme->multiple->prVec:%lu",scheme->multiple->prVec);
    SLogTrace("scheme->multiple->invp:%lu",scheme->multiple->invp);
    SLogTrace("scheme->multiple->inv:%lu",scheme->multiple->inv);
    SLogTrace("scheme->multiple->N:%lu",scheme->multiple->N);
    SLogTrace("scheme->multiple->logN:%lu",scheme->multiple->logN);
    SLogTrace("scheme->multiple->M:%lu",scheme->multiple->M);
    SLogTrace("scheme->multiple->primeLen:%d",scheme->multiple->primeLen);
    SLogTrace("s,a,b:\n");
    for(int i = 0 ; i < 3 ; ++i){
        SLogTrace("%lu,%lu,%lu\n",scheme->s[i],scheme->a[i],scheme->b[i]);
    }*/
}

// 用于 double 类型的简单编码
void Scheme_Simpleencode_double(double *v, Plaintext *plaintext, size_t slots, Scheme *scheme) {
    plaintext->length = slots;
    plaintext->coffe_data = (uint64_t *)malloc(sizeof (uint64_t) * scheme->ploy_modulus_degree);
    int64_t p = 1 << scheme->scale;
    for (size_t i = 0; i < scheme->ploy_modulus_degree; i++) {
        if (i < slots) {
            int64_t temp = (int64_t)(v[i] * p);
            plaintext->coffe_data[i] = (temp >= 0) ? (uint64_t)temp : ((uint64_t)(temp + scheme->qmod));
        } else {
            plaintext->coffe_data[i] = 0;
        }
    }
}

// 用于 int64_t 类型的简单编码
void Scheme_Simpleencode_int(int64_t *v, Plaintext *plaintext, size_t slots,Scheme *scheme) {
    plaintext->length = slots;
    plaintext->coffe_data = (uint64_t * )malloc(sizeof (uint64_t) * scheme->ploy_modulus_degree);
    int64_t p = 1 << scheme->scale;
    for (size_t i = 0; i < scheme->ploy_modulus_degree; i++) {
        if (i < slots) {
            int64_t temp = v[i] * p;
            plaintext->coffe_data[i] = temp >= 0 ? (uint64_t)temp : ((uint64_t)(temp + scheme->qmod));
        } else {
            plaintext->coffe_data[i] = 0;
        }
    }
}

// 解码
double *Scheme_Simpledecode(uint64_t *msg, long slots,Scheme *scheme) {
    double *res = (double *)malloc(sizeof(double ) * slots);
    int64_t p = 1 << scheme->scale;
    uint64_t pr_2 = scheme->qmod >> 1;
    for (size_t i = 0; i < slots; i++) {
        res[i] = msg[i] <= pr_2 ? ((double)(msg[i]) / p) : (((double)(msg[i]) - (double)(scheme->qmod)) / p);
    }
    return res;
}

// 加法操作
void Scheme_add(Ciphertext *cipher, Ciphertext *cipher1, Ciphertext *cipher2,Scheme *scheme) {
    cipher->scale_factor = scheme->scale;
    cipher->length = cipher1->length;
    cipher->ploy_modulus_degree = scheme->ploy_modulus_degree;
    cipher->c0 = (uint64_t *)malloc(sizeof(uint64_t) * scheme->ploy_modulus_degree);
    cipher->c1 = (uint64_t *)malloc(sizeof(uint64_t) * scheme->ploy_modulus_degree);

    CTRingMultiplier_add_o(&cipher->c0, cipher1->c0, cipher2->c0,scheme->multiple);
    CTRingMultiplier_add_o(&cipher->c1, cipher1->c1, cipher2->c1,scheme->multiple);
}

// 简单加密操作
void Scheme_Simple_encrypt(Ciphertext *cipher, Plaintext *plaintext,Scheme *scheme) {
    cipher->scale_factor = scheme->scale;
    cipher->length = plaintext->length;
    cipher->ploy_modulus_degree = scheme->ploy_modulus_degree;
    uint64_t *r;
    // TODO
    samplesZO(&r, scheme->ploy_modulus_degree, scheme->qmod);
    CTRingMultiplier_NTT(r,scheme->multiple);

    CTRingMultiplier_mult_poly(&cipher->c0, scheme->b, r,scheme->multiple);
    CTRingMultiplier_mult(&cipher->c1, scheme->a, r,scheme->multiple);

    uint64_t *e0;
    uint64_t *e1;
    // TODO
    samplesGauss(&e0, scheme->ploy_modulus_degree, 3.2, scheme->qmod);
    samplesGauss(&e1, scheme->ploy_modulus_degree, 3.2, scheme->qmod);
    CTRingMultiplier_NTT(e1,scheme->multiple);

    CTRingMultiplier_add(&cipher->c0, e0,scheme->multiple);
    CTRingMultiplier_add(&cipher->c1, e1,scheme->multiple);

    CTRingMultiplier_add(&cipher->c0, plaintext->coffe_data,scheme->multiple);

    free(r);
    free(e0);
    free(e1);
}

// 异步加密操作
void Scheme_async_encrypt(Ciphertext *cipher, Plaintext *plaintext,Scheme *scheme) {
    cipher->c0 = scheme->ciphers[scheme->cur_cipher].c0;
    cipher->c1 = scheme->ciphers[scheme->cur_cipher].c1;
    cipher->ploy_modulus_degree = scheme->ciphers[scheme->cur_cipher].ploy_modulus_degree;
    cipher->scale_factor = scheme->ciphers[scheme->cur_cipher].scale_factor;
    cipher->length = plaintext->length;
    CTRingMultiplier_add(&cipher->c0, plaintext->coffe_data,scheme->multiple);
    scheme->cur_cipher = (scheme->cur_cipher + 1) % scheme->ciphers_num;
}

// 解密操作
void Scheme_Simple_decrypt(Plaintext *plaintext, Ciphertext *cipher,Scheme *scheme) {
    plaintext->length = cipher->length;
    CTRingMultiplier_mult_poly(&plaintext->coffe_data, cipher->c1, scheme->s,scheme->multiple);
    CTRingMultiplier_add(&plaintext->coffe_data, cipher->c0,scheme->multiple);
}

// 快速解密操作
void Scheme_fast_Simple_decrypt(Plaintext *plaintext, Ciphertext *cipher,Scheme *scheme) {
    plaintext->length = cipher->length;
    CTRingMultiplier_fast_mult_poly(&plaintext->coffe_data, cipher->c1, scheme->s,scheme->multiple);
    CTRingMultiplier_add(&plaintext->coffe_data, cipher->c0,scheme->multiple);
}

// 初始化预处理密码本
void Scheme_init_pre_cipher( Ciphertext *cipher, size_t seed,Scheme *scheme) {
    cipher->scale_factor = scheme->scale;
    cipher->ploy_modulus_degree = scheme->ploy_modulus_degree;
    uint64_t *r;
    // TODO 这里除了生成0 1 还能生成一个很大的数，是不是这里不合适了？
    samplesZO(&r, scheme->ploy_modulus_degree, scheme->qmod);
    CTRingMultiplier_NTT(r,scheme->multiple);

    CTRingMultiplier_mult_poly(&cipher->c0, scheme->b, r,scheme->multiple);
    CTRingMultiplier_mult(&cipher->c1, scheme->a, r,scheme->multiple);

    uint64_t *e0;
    uint64_t *e1;
    // TODO
    samplesGauss(&e0, scheme->ploy_modulus_degree, 3.2, scheme->qmod);
    samplesGauss(&e1, scheme->ploy_modulus_degree, 3.2, scheme->qmod);
    CTRingMultiplier_NTT(e1,scheme->multiple);
    // 打印查看加和是否正确:这里加和是正确的，不过仍然e0里面存在很大的数
    CTRingMultiplier_add(&cipher->c0, e0,scheme->multiple);
    CTRingMultiplier_add(&cipher->c1, e1,scheme->multiple);
}
