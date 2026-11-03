#ifndef SCHEME_H
#define SCHEME_H

#include "NumUtils.h"
#include "CTRingMultiplier.h"
#include "ciphertext.h"
#include "plaintext.h"

#define MAX_CIPHERS_NUM 100

// 结构体定义
typedef struct {
    CTRingMultiplier *multiple; // 乘法器
    size_t ploy_modulus_degree;  // 多项式最高次数
    size_t scale;                // 放缩因子
    uint64_t qmod;               // 大模数
    uint64_t *s;                 // 私钥
    uint64_t *a;                 // 公钥a
    uint64_t *b;                 // 公钥b
    Ciphertext *ciphers;         // 预先计算好的密码本
    size_t cur_cipher;           // 当前密码本索引
    size_t ciphers_num;          // 密码本数量
} Scheme;

// 函数声明
void Scheme_scheme_Init(size_t ploy_Lenth, void *s, void *a, void *b, Scheme *scheme);
void Scheme_Simpleencode_double(double *v, Plaintext *plaintext, size_t slots, Scheme *scheme);
void Scheme_Simpleencode_int(int64_t *v, Plaintext *plaintext, size_t slots, Scheme *scheme);
double *Scheme_Simpledecode(uint64_t *msg, long slots, Scheme *scheme);
void Scheme_add(Ciphertext *cipher, Ciphertext *cipher1, Ciphertext *cipher2, Scheme *scheme);
void Scheme_Simple_encrypt(Ciphertext *cipher, Plaintext *plaintext, Scheme *scheme);
void Scheme_async_encrypt(Ciphertext *cipher, Plaintext *plaintext, Scheme *scheme);
void Scheme_Simple_decrypt(Plaintext *plaintext, Ciphertext *cipher, Scheme *scheme);
void Scheme_fast_Simple_decrypt(Plaintext *plaintext, Ciphertext *cipher, Scheme *scheme);
void Scheme_init_pre_cipher(Ciphertext *cipher, size_t seed, Scheme *scheme);


#endif // SCHEME_H
