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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>

#include "utils/mt1993764.h"
#include "utils/tools.h"
#include "define/define.h"
#include "utils/SpritzCipher.h"

#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <iostream>
#include <bitset>

using std::bitset;

static const uint64_t rand64Seed = 2333;

uint64_t *matrixB, matrixC;
spritz_ctx ctx;

const uint8_t csprngSeed[64] =
    {'1', '1', '4', '1', '5', '9', '2', '6',
     '5', '3', '5', '8', '9', '7', '9', '3',
     '2', '3', '8', '4', '6', '2', '6', '4',
     '3', '3', '8', '3', '2', '7', '9', '5',
     '0', '2', '8', '8', '4', '1', '9', '7',
     '1', '6', '9', '3', '9', '9', '3', '7',
     '5', '1', '0', '5', '8', '2', '0', '9',
     '7', '4', '9', '4', '4', '5', '9', '2'};

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

// 初始化CSPRNG
void enclaveInitCSPRNG()
{
	// spritz参数
    // spritz_setup(&ctx, csprngSeed, 64);
    // printf("Enclave CSPRNG Init Success!\n");

	// mt19937_64参数
	init_genrand64(rand64Seed);
	printf("Enclave CSPRNG Init Success!\n");
}

// 获取随机数
uint64_t getSecureRandom()
{
    // return spritz_random64(&ctx);
	return genrand64_uint64();
}

// 普通乘法三元组实现 len = sizeof(uint64_t)*randnum and len is times of 3
void enclaveGenAndOutBeaverTribles(uint64_t *arr, size_t len)
{

    uint64_t loopTimes = len / sizeof(uint64_t);
    uint64_t randbuff[loopTimes];

    if (currentParty == PARTY0)
    {
        for (size_t i = 0; i < loopTimes; i += 3)
        {
            randbuff[i] = getSecureRandom();
            getSecureRandom();
            randbuff[i + 1] = getSecureRandom();
            getSecureRandom();
            randbuff[i + 2] = getSecureRandom();
        }
    }

    if (currentParty == PARTY1)
    {
        uint64_t a, b, c;
        for (size_t i = 0; i < loopTimes; i += 3)
        {
            a = getSecureRandom();
            randbuff[i] = getSecureRandom();
            b = getSecureRandom();
            randbuff[i + 1] = getSecureRandom();
            c = getSecureRandom();
            randbuff[i + 2] = (a + randbuff[i]) * (b + randbuff[i + 1]) - c;
        }
    }

    memcpy(arr, randbuff, len);
}

// 矩阵形式乘法三元组实现
void enclaveGenAndOutMatrixTribles(uint64_t *matrixSize, uint64_t *arr, size_t len)
{
    uint64_t mSize[3];
    memcpy(mSize, matrixSize, 24);

    uint64_t sizeA = mSize[0] * mSize[1];
    uint64_t sizeB = mSize[1] * mSize[2];
    uint64_t sizeC = mSize[0] * mSize[2];

    uint64_t rand_maxtrix[sizeA + sizeB + sizeC];

    for (size_t i = 0; i < sizeA; i++)
    {
        rand_maxtrix[i] = getSecureRandom();
    }

    for (size_t i = 0; i < sizeB; i++)
    {
        rand_maxtrix[sizeA + i] = getSecureRandom();
    }
    matrixMulEigen(mSize[0], mSize[1], mSize[2], rand_maxtrix, rand_maxtrix + sizeA, rand_maxtrix + sizeA + sizeB);

    if (currentParty == PARTY0)
    {
        for (size_t i = 0; i < sizeA; i++)
        {
            rand_maxtrix[i] = getSecureRandom();
        }
        for (size_t i = 0; i < sizeB; i++)
        {
            rand_maxtrix[sizeA + i] = getSecureRandom();
        }
        for (size_t i = 0; i < sizeC; i++)
        {
            rand_maxtrix[sizeA + sizeB + i] = getSecureRandom();
        }
    }

    if (currentParty == PARTY1)
    {
        for (size_t i = 0; i < sizeA; i++)
        {
            rand_maxtrix[i] -= getSecureRandom();
        }
        for (size_t i = 0; i < sizeB; i++)
        {
            rand_maxtrix[sizeA + i] -= getSecureRandom();
        }
        for (size_t i = 0; i < sizeC; i++)
        {
            rand_maxtrix[sizeA + sizeB + i] -= getSecureRandom();
        }
    }

    memcpy(arr, rand_maxtrix, len);
}