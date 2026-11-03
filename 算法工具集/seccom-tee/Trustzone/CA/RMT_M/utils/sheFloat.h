#ifndef SHE_FLOAT
#define SHE_FLOAT
#include "she.h"
typedef struct _SHE_CIPHER
{
    BIGNUM *cipher;
    int kTimes;
} SHECipher;

void sheADDConstant(SHECipher *res, double cons, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx);
void sheADDCC(SHECipher *res, SHECipher *c1, SHECipher *c2, int k, SHE_key *key, BN_CTX *ctx);
void sheMULCC(SHECipher *res, SHECipher *c1, SHECipher *c2, int k, SHE_key *key, BN_CTX *ctx);
void sheMULConstant(SHECipher *res, double cons, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx);
void sheNEGC(SHECipher *res, SHECipher *c1, int k, SHE_key *key, BN_CTX *ctx);
void sheSETC(SHECipher *res, SHECipher *c1);
void sheInitC(SHECipher *res, BIGNUM *b, int kTimes = 0);
#endif