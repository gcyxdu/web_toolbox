#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// 定义 Ciphertext 结构体
typedef struct Ciphertext {
    uint64_t* c0; // 密文的第一个部分
    uint64_t* c1; // 密文的第二个部分
    size_t ploy_modulus_degree; // 多项式的度数
    size_t length; // 密文的长度
    size_t scale_factor; // 缩放因子
} Ciphertext;

// 函数声明
void Ciphertext_init(uint64_t* t1, uint64_t* t2, size_t ploy_modulus_degree,Ciphertext* ciphertext);

#ifdef __cplusplus
}
#endif

#endif // CIPHERTEXT_H
