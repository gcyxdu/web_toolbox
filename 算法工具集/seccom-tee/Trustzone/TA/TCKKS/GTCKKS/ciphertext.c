#include "ciphertext.h"
#include <string.h>

// 初始化 Ciphertext 结构体
void Ciphertext_init(uint64_t* t1, uint64_t* t2, size_t ploy_modulus_degree,Ciphertext* ciphertext) {
    if (ciphertext != NULL) {
        ciphertext->c0 = t1;
        ciphertext->c1 = t2;
        ciphertext->ploy_modulus_degree = ploy_modulus_degree;
        ciphertext->length =0;
        ciphertext->scale_factor = 0; // 默认为0，可以根据实际情况设置
    }
}

