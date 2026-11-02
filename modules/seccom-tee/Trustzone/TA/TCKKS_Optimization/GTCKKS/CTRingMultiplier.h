#ifndef TZCODE_CTRINGMULTIPLIER_H
#define TZCODE_CTRINGMULTIPLIER_H
#include "math.h"
#include "SpritzCipher.h"
#include <stdint.h>
#include "stdbool.h"

typedef struct {
    uint64_t pVec;                            //各个素数
    uint64_t prVec;
    uint64_t invp;
    uint64_t* g;                               //pvec的原根
    uint64_t* gi;                              //pvec的原根的逆原
    uint64_t inv;                             //M的逆
    uint64_t N;                                //多项式次数
    uint64_t logN;
    uint64_t M;                                //二倍多项式次数
    int *rev;                                  //蝶形变幻的索引
    int primeLen;
} CTRingMultiplier;
static spritz_ctx ctxx;
/**-----------------------------------函数声明部分--------------------------------------*/
void CTRingMultiplier_Modshift(uint64_t *r, unsigned __int128 a, uint64_t mod, uint64_t m);
void CTRingMultiplier_mulMod(uint64_t *r, uint64_t a, uint64_t b, uint64_t m);
void CTRingMultiplier_mulModBarrett(uint64_t *r, uint64_t a, uint64_t b, uint64_t m, uint64_t pr,CTRingMultiplier *ring);
uint64_t CTRingMultiplier_powMod(uint64_t x, uint64_t y, uint64_t modulus);
uint64_t CTRingMultiplier_powModBarrett(uint64_t x, uint64_t y, uint64_t modulus, uint64_t pr,CTRingMultiplier * ring);
void CTRingMultiplier_get_fac(uint64_t *s, int *size,uint64_t number);
uint64_t CTRingMultiplier_inver(uint64_t x);
uint64_t CTRingMultiplier_pow(uint64_t x, uint64_t y);
uint64_t CTRingMultiplier_get_prime_root(uint64_t modulus);
uint64_t CTRingMultiplier_invMod(uint64_t x, uint64_t m);
uint64_t CTRingMultiplier_findMthRootOfUnity(uint64_t M, uint64_t mod, uint64_t pr,CTRingMultiplier * ring);
bool CTRingMultiplier_primeTest(uint64_t p);
void CTRingMultiplier_bitreverse(CTRingMultiplier* ring);
void CTRingMultiplier_preTable(uint64_t Np, uint64_t *root, uint64_t *invroot,CTRingMultiplier *ring);
/**
 * @param is_use_pretable default_vale false
 * */
int CTRingMultiplier_generate_prime(uint64_t Np, int primeLen, bool is_use_pretable,CTRingMultiplier * ring);
uint64_t CTRingMultiplier_REDC(uint64_t a, uint64_t b,CTRingMultiplier *ring);
void CTRingMultiplier_NTT(uint64_t *a,CTRingMultiplier * ring);
void CTRingMultiplier_INTT(uint64_t *a,CTRingMultiplier * ring);
void CTRingMultiplier_fast_INTT(uint64_t *a,CTRingMultiplier * ring);
void CTRingMultiplier_pre_handle_s(uint64_t *s,CTRingMultiplier *ring);
void CTRingMultiplier_mult_raw(int64_t *c, uint64_t *a, uint64_t *b, uint64_t mod,CTRingMultiplier * ring);
void CTRingMultiplier_uintchangeint(uint64_t *a, size_t slots,CTRingMultiplier * ring);
void CTRingMultiplier_mult(uint64_t **x, uint64_t *a, uint64_t *b,CTRingMultiplier * ring);
void CTRingMultiplier_mult_poly(uint64_t **x, uint64_t *a, uint64_t *b,CTRingMultiplier * ring);
void CTRingMultiplier_fast_mult_poly(uint64_t **x, uint64_t *a, uint64_t *b,CTRingMultiplier * ring);
void CTRingMultiplier_sub(uint64_t *e, uint64_t **b,CTRingMultiplier * ring);
void CTRingMultiplier_sub_o(uint64_t **c, uint64_t *a, uint64_t *b,CTRingMultiplier * ring);
void CTRingMultiplier_add(uint64_t **a, uint64_t *b,CTRingMultiplier * ring);
void CTRingMultiplier_add_o(uint64_t **c, uint64_t *a, uint64_t *b,CTRingMultiplier * ring);

#endif //TZCODE_CTRINGMULTIPLIER_H
