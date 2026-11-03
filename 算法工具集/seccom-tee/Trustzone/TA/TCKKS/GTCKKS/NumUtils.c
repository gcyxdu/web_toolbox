#include <stdint.h>
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include "tee_crypto_api.h"
#include "SpritzCipher.h"
#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"

static int isInitCtx;
static spritz_ctx ctx;


void samplesGauss(uint64_t* *e, size_t ploy_modulus_degree, double stdev, uint64_t qmod) {
    *e = (uint64_t*)malloc(ploy_modulus_degree * sizeof(uint64_t));
    const double pi = 4 * atan(1);
    uint64_t bignum = 0xfffffff;

    if(isInitCtx == 0){
        init_random_ctx(&ctx);
        // 初始化随机数引擎
        isInitCtx = 1;
    }

    for (size_t i = 0; i < ploy_modulus_degree; i += 2) {
        double r1 = (1 + (spritz_random64(&ctx) % bignum)) / ((double) bignum + 1);
        double r2 = (1 + (spritz_random64(&ctx) % bignum)) / ((double) bignum + 1);
        double theta = 2 * pi * r1;
        double rr = sqrt(-2 * log(r2)) * stdev;
        assert(rr < 8 * stdev);
        int64_t g1 = (int64_t) floor(rr * cos(theta) + 0.5);
        int64_t g2 = (int64_t) floor(rr * sin(theta) + 0.5);

        (*e)[i] = g1 >= 0 ? g1 : g1 + qmod;
        if (i + 1 < ploy_modulus_degree) {
            (*e)[i + 1] = g2 >= 0 ? g2 : g2 + qmod;
        }
    }
}

long bit(long a, long k) {
    unsigned long aa;
    if (a < 0)
        aa = -((unsigned long)a);
    else
        aa = a;

    if (k < 0 || k >= 64)
        return 0;
    else
        return (long)((aa >> k) & 1);
}

void samplesHWT(uint64_t **s, size_t ploy_modulus_degree, const long h, uint64_t qmod) {
    *s = (uint64_t*)malloc(ploy_modulus_degree * sizeof(uint64_t));
    long idx = 0;
    uint64_t tmp;
    // TODO 获取随机数
    TEE_GenerateRandom(&tmp, sizeof(uint64_t));

    for (int i = 0; i < ploy_modulus_degree; ++i) {
        (*s)[i] = 0;
    }

    if(isInitCtx == 0){
        init_random_ctx(&ctx);
    }

    while (idx < h) {
        long i = spritz_random64(&ctx) % ploy_modulus_degree;
        if ((*s)[i] == 0) {
            long hwt = (bit((int64_t)tmp, idx) == 0) ? 1 : -1;
            (*s)[i] = hwt >= 0 ? hwt : hwt + qmod;
            idx++;
        }
    }
}

void samplesZO(uint64_t* *r, size_t ploy_modulus_degree, uint64_t qmod) {
    *r = (uint64_t*)malloc(ploy_modulus_degree * sizeof(uint64_t));
    if (*r == NULL) {
        SLogTrace("samplesZO r Memory allocation failed");
        return; // 早期退出或者报错
    }
    uint64_t tmp;
    TEE_GenerateRandom(&tmp, sizeof(uint64_t));
    // SLogTrace("TEE_GenerateRandom tmp is %lu,int64_t is %ld",tmp,(int64_t)tmp);
    for (int i = 0; i < ploy_modulus_degree; ++i) {
        long zo = (bit((int64_t)tmp, 2 * i) == 0) ? 0 : (bit((int64_t)tmp, 2 * i + 1) == 0) ? 1 : -1;
        // SLogTrace("[%d] data is :%ld",i,zo);
        (*r)[i] = (zo >= 0 ? zo : zo + qmod);
//        if(i < 64){
//            SLogTrace("[%d] data is :%lu",i,(*r)[i]);
//        }
    }
}

void samplesUniform2(uint64_t* *a, size_t ploy_modulus_degree, uint64_t qmod) {
    *a = (uint64_t*)malloc(ploy_modulus_degree * sizeof(uint64_t));
    uint64_t tmp;
    for (int i = 0; i < ploy_modulus_degree; ++i) {
        TEE_GenerateRandom(&tmp, sizeof(uint64_t));
        (*a)[i] = (uint64_t)floor(((double)tmp / (RAND_MAX)) * qmod);
    }
}
