#ifndef SHE_H
#define SHE_H

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#ifdef DEPTH2
#define CENG 2
#endif
#ifdef DEPTH3
#define CENG 3
#endif
#ifdef DEPTH4
#define CENG 4
#endif
#ifdef DEPTH5
#define CENG 5
#endif
#ifdef DEPTH6
#define CENG 6
#endif
#ifdef DEPTH7
#define CENG 7
#endif
#ifdef DEPTH8
#define CENG 8
#endif
#ifdef DEPTH9
#define CENG 9
#endif
#ifdef DEPTH10
#define CENG 10
#endif

// 测试乘法深度时使用
// #define DEFAULT_K1 20
// #define DEFAULT_K2 (CENG+1)*DEFAULT_K1
// #define DEFAULT_K0 2*(CENG+1)*DEFAULT_K2

#define DEFAULT_K0 2048
#define DEFAULT_K1 100
#define DEFAULT_K2 200

#define M_BITS 40
#define R_BITS 80
#define L_BITS 820
#define P_BITS 1024
#define Q_BITS 33976

/* SHE keys */
typedef struct _SHE_key {
    BIGNUM *p, *q, *l, *n, *e_negative1, *l_2, *cipher_zero, *cipher_one;
} SHE_key;

int she_generateRandomKeys(SHE_key *key, int k0, int k1, int k2, BN_CTX *ctx);
int she_encryptBignumRaw(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx);
int she_encryptBignumSupportNegative(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx);
int she_encryptBignumSupportNegative2(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx);
int she_encryptTeeStringBignum(char *str_c, BIGNUM *m);
int she_encryptTeeStringBignum2(char *str_c, BIGNUM *m);
int she_encryptTeeString(char *str_c, char *str_m);
int she_decryptBignum(BIGNUM *plain, const BIGNUM *c, const SHE_key *key, BN_CTX *ctx);
int mulString(char *str1, char *str2, char *str3);
int addString(char *str1, char *str2, char *str3);
int she_decryptTeeString(char *str_plain, char *str_c);
int she_generateRandomKeysTee();
int she_generateRandomKeysTee2();
void bn_printfHex(BIGNUM *num);
void bn_printfDec(BIGNUM *num);

#endif
