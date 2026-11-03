/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include "math.h"

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_trts.h"
#include <unordered_map>
#include <vector>
#include "GTCKKS/scheme.hpp"
#include "GTCKKS/randomgen.h"

using namespace std;
using namespace gtfhe;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void printf_helloworld(int logN)
{ 
    // encpyted_test(logN);
    // add_test(logN);
    // mul_test(logN);
    // NTT_test(logN);
}

Scheme scheme;
uint64_t* t1;
uint64_t* t;
// uint64_t* temp1;
// uint64_t* temp2;
unsigned __int128* mulMessage1;

void TEE_NTT_test(int logN){
    // // NTT test
    // multiple.NTTtest1();
    // multiple.NTTtest2();
    // multiple.NTTtest3();
}

void init(int logN, void* s, void* a, void* b){
    //  printf("cmd_init\n");
    // printf_ploy((uint64_t *)s,2048);
    // printf_ploy((uint64_t *)a,2048);
    // printf_ploy((uint64_t *)b,2048);
    scheme.scheme_Init(logN, s, a, b);
    t1 = new uint64_t[scheme.ploy_modulus_degree];
    t = new uint64_t[scheme.ploy_modulus_degree];
    uint64_t scalefactor = 1 << scheme.scale;
    UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>();
    for (size_t i = 0; i < scheme.ploy_modulus_degree; i++)
    {
        t1[i] =(100000 +  ran->generate()% 10000)  * (scalefactor);
        t[i] = t1[i] * (scalefactor);
    }
    mulMessage1 = new unsigned __int128[scheme.ploy_modulus_degree];
} 


void send_ciphertext(void *c01, void *c11, void *c00, void *c10){
    uint64_t* cipher01 = (uint64_t*) c01;
    uint64_t* cipher11 = (uint64_t*) c11;
    uint64_t* cipher00 = (uint64_t*) c00;
    uint64_t* cipher10 = (uint64_t*) c10;
    // 1. decrypt

    scheme.multiple.fast_mult_poly(cipher01, cipher01, scheme.s);
   
    scheme.multiple.fast_mult_poly(cipher11, cipher11, scheme.s);
    printf("CTRingMultiplier_fast_mult_poly after:");
    
    printf_ploy(cipher01,2048);
    printf_ploy(cipher11,2048);
    printf_ploy(cipher00,2048);
    printf_ploy(cipher10,2048);
    // 2. multiple
    for (size_t i = 0; i < scheme.ploy_modulus_degree; i++)
    {
        cipher00[i] = cipher00[i] + cipher01[i] - scheme.qmod;
        cipher10[i] = cipher10[i] + cipher11[i] - scheme.qmod;
        mulMessage1[i] = static_cast<unsigned __int128>(cipher00[i]) * cipher10[i] + static_cast<unsigned __int128>(t[i]);
    }
}

void getPTest(void* batchCipher0){
    memcpy(batchCipher0, t, sizeof(uint64_t)*scheme.ploy_modulus_degree);	
}


void decodeEncrypt(void* batchCipher0, void* batchCipher1, void* mulMessage){

    uint64_t* temp = (uint64_t*) mulMessage;
    scheme.multiple.sub(temp, temp, t1);
   
    scheme.multiple.add(scheme.ciphers[scheme.cur_cipher].c0, temp);
    memcpy(batchCipher0, scheme.ciphers[scheme.cur_cipher].c0, sizeof(uint64_t)*scheme.ploy_modulus_degree);	
    memcpy(batchCipher1, scheme.ciphers[scheme.cur_cipher].c1, sizeof(uint64_t)*scheme.ploy_modulus_degree);

    scheme.cur_cipher = (scheme.cur_cipher + 1) % scheme.ciphers_num;

}

void ecall_batchtrans_information(void* mulMessage){
    memcpy(mulMessage, mulMessage1, sizeof(unsigned __int128)*scheme.ploy_modulus_degree); 
}

void ecall_batchtrans_ciphertext1(void* batchCipher0, void* batchCipher1){
    // memcpy(batchCipher0, temp1, sizeof(uint64_t)*scheme.ploy_modulus_degree);	
    // memcpy(batchCipher1, temp2, sizeof(uint64_t)*scheme.ploy_modulus_degree);
}

void secure_add(void * c0, void * c1, void* batchCipher0, void* batchCipher1, int len){
    uint64_t* cipher1 = (uint64_t*) c1;
    uint64_t* cipher0 = (uint64_t*) c0;
    scheme.multiple.fast_mult_poly(cipher1, cipher1, scheme.s);
    scheme.multiple.add(cipher1, cipher0);

    double * result = scheme.Simpledecode(cipher1, scheme.ploy_modulus_degree);
    // printf_vector(result, len);

    double *num = new double[1];
    for (size_t i = 0; i < len; i++)
    {
        num[0] += result[i];
    }

    Plaintext plain;

    scheme.Simpleencode(num, plain, 1);

    scheme.ciphers[scheme.cur_cipher].c0[0] += plain.coffe_data[0];
    memcpy(batchCipher0, scheme.ciphers[scheme.cur_cipher].c0, sizeof(uint64_t)*scheme.ploy_modulus_degree);	
    memcpy(batchCipher1, scheme.ciphers[scheme.cur_cipher].c1, sizeof(uint64_t)*scheme.ploy_modulus_degree);

    scheme.cur_cipher = (scheme.cur_cipher + 1) % scheme.ciphers_num;

}

