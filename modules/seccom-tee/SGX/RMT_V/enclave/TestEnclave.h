/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _TESTENCLAVE_H_
#define _TESTENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#include <cstring>
#include <cstdio>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MAX_LENGTH 1000
// 测试集加载
#define MAX_LINE_LENGTH 1000  // 每行的最大长度
#define MAX_ROWS 200          // 假设最大行数为100
#define MAX_COLS 20           // 假设最大列数为50

#define TEST_CHECK(status)  \
{   \
    if (status != SGX_SUCCESS) {    \
        printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);  \
        abort();    \
    }   \
}

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
void generate_bool();
void test_ecall_inner_product(char** ptr, char*);
void model_training(unsigned char* ciphertext, int length);
void initSystem();

/* version 2.0 202408281336 */

void Rand_Num_Generator(int* Rand_Num,int Lower,int Upper); // 随机数生成器，REE侧会调用
void Batch_Str_Decryption(char**** Batch_Str_D_Output,char*** Batch_Str,int Number_Participants,unsigned char* ivec); // 块字符串解密
void decoding(float*** Xy_train_Output,char*** Block_Str,int* Participants,int Block_Size,int Num_Block,int Validator); // 块字符串解码，得到Xy_train，Validator为校验器。REE侧会调用
float h(float* theta,float* x,int M); // h函数，M是特征数（Dia: M=8 ; Brea: M=9）
float Predictive_value_calculation(float* theta,float* x,int M); // 预测值计算函数
void update(float** theta_updated_Output,float* theta_t,float** Xy_train,int M,int Block_Size,int Num_Block,float alpha); // 模型参数更新函数

/* version 2.0 202408281336 */


#if defined(__cplusplus)
}
#endif

#endif /* !_TESTENCLAVE_H_ */