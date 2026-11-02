#include "stdio.h"
#include "math.h"
#include "string.h"
#include "ciphertext.h"
#include "stringUtils.h"
#include "SpritzCipher.h"
#include <stdint.h>
#include "CTRingMultiplier.h"
#include "stdbool.h"

#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"

extern spritz_ctx ctxx;

/**-------------------------------具体方法实现----------------------------------*/
void CTRingMultiplier_Modshift(uint64_t *r, unsigned __int128 a, uint64_t mod, uint64_t m) {
    a %= (unsigned __int128)(mod);  // C中的类型转换
    *r = (uint64_t)(a) >> m;  // 强制类型转换
}

void CTRingMultiplier_mulMod(uint64_t *r, uint64_t a, uint64_t b, uint64_t m) {
    unsigned __int128 mul = (unsigned __int128)(a) * b;  // C中的类型转换
    mul %= (unsigned __int128)(m);  // 取模
    *r = (uint64_t)(mul);  // 强制类型转换为 uint64_t
}

void CTRingMultiplier_mulModBarrett(uint64_t *r, uint64_t a, uint64_t b, uint64_t m, uint64_t pr, CTRingMultiplier *ring) {
    // 打印一遍入参
    // printf("in CTRingMultiplier_mulModBarrett\na is %lu,b is %lu,m is %lu, pr is %lu\n",a,b,m,pr);
    unsigned __int128 mul = (unsigned __int128)(a) * b;  // C中的类型转换
    uint64_t abot = (uint64_t)(mul);  // 低位部分
    uint64_t atop = (uint64_t)(mul >> 64);  // 高位部分
    unsigned __int128 tmp = (unsigned __int128)(abot) * pr;  // C中的类型转换
    tmp >>= 64;
    tmp += (unsigned __int128)(atop) * pr;
    tmp >>= 2 * (ring->primeLen + 1) - 64;
    tmp *= m;
    tmp = mul - tmp;
    *r = (uint64_t)(tmp);  // 强制类型转换
    if (*r > m) {
        *r -= m;  // 如果r大于m，做减法
    }
}
uint64_t CTRingMultiplier_powMod(uint64_t x, uint64_t y, uint64_t modulus){
    uint64_t res = 1;
    while (y > 0) {
        if (y & 1) {
            CTRingMultiplier_mulMod(&res, res, x, modulus);
        }
        y = y >> 1;
        CTRingMultiplier_mulMod(&x, x, x, modulus);
    }
    return res;
}

uint64_t CTRingMultiplier_powModBarrett(uint64_t x, uint64_t y, uint64_t modulus, uint64_t pr,CTRingMultiplier * ring){
    uint64_t res = 1;
    while (y > 0) {
        if (y & 1) {
            CTRingMultiplier_mulModBarrett(&res, res, x, modulus, pr,ring);
        }
        y = y >> 1;
        CTRingMultiplier_mulModBarrett(&x, x, x, modulus, pr,ring);
    }
    return res;
}

void CTRingMultiplier_get_fac(uint64_t *s, int *size,uint64_t number){
    int j = 0;
    while (number % 2 == 0) {
        s[j++] = 2;
        number /= 2;
    }
    for (uint64_t i = 3; i < sqrt(number); i++) {
        while (number % i == 0) {
            s[j++] = i;
            number /= i;
        }
    }
    if (number > 2) {
        s[j++] = number;
    }
    *size = j;
}

uint64_t CTRingMultiplier_inver(uint64_t x){
    return CTRingMultiplier_pow(x, (uint64_t)(-1));
}
uint64_t CTRingMultiplier_pow(uint64_t x, uint64_t y) {
    uint64_t res = 1;
    while (y > 0) {
        if (y & 1) {
            res *= x;
        }
        y = y >> 1;
        x *= x;
    }
    return res;
}
uint64_t CTRingMultiplier_get_prime_root(uint64_t modulus){
    // 初始化为0
    uint64_t s[100] = {0};
    uint64_t phi = modulus - 1;
    int size = 0;
    CTRingMultiplier_get_fac(s, &size,phi);
    for (uint64_t r = 2; r <= phi; r++) {
        bool flag = false;
        for (int i = 0; i < size; i++) {
            if (CTRingMultiplier_powMod(r, phi / s[i], modulus) == 1) {
                flag = true;
                break;
            }
        }
        if (flag == false) {
            return r;
        }
    }
    return 0;
}

uint64_t CTRingMultiplier_invMod(uint64_t x, uint64_t m){
    return CTRingMultiplier_powMod(x, m - 2, m);
}

uint64_t CTRingMultiplier_findMthRootOfUnity(uint64_t M, uint64_t mod, uint64_t pr,CTRingMultiplier * ring){
    uint64_t res;
    res = CTRingMultiplier_get_prime_root(mod);
    if((mod - 1) % M == 0) {
        uint64_t factor = (mod - 1) / M;
        res = CTRingMultiplier_powModBarrett(res, factor, mod, pr,ring);
        return res;
    }else{
        return 0;
    }
}
bool CTRingMultiplier_primeTest(uint64_t p){
    if (p < 2) return false;
    if (p != 2 && p % 2 == 0) return false;
    uint64_t s = p - 1;
    while (s % 2 == 0) {
        s /= 2;
    }
    init_random_ctx(&ctxx);
    for (long i = 0; i < 200; i++) {
        uint64_t temp1 = spritz_random64(&ctxx);
        temp1  = (temp1 << 32) | spritz_random64(&ctxx);
        temp1 = temp1 % (p - 1) + 1;
        uint64_t temp2 = s;
        uint64_t mod = CTRingMultiplier_powMod(temp1, temp2, p);
        while (temp2 != p - 1 && mod != 1 && mod != p - 1) {
            CTRingMultiplier_mulMod(&mod, mod, mod, p);
            temp2 *= 2;
        }
        if (mod != p - 1 && temp2 % 2 == 0) return false;
    }
    return true;
}
void CTRingMultiplier_bitreverse(CTRingMultiplier* ring){
    int *revint = (int *)malloc(sizeof(int) * ring->N);
    for (int i = 0; i < (int)ring->N; ++i)
    {
        revint[i] = 0;
        ring->rev[i] = i;
    }
    for (int i = 0; i < (int)ring->N; ++i){				// get rev
        revint[i] = (revint[i >> 1] >> 1) | ((i & 1) << (ring->logN - 1));
        if(i < revint[i]){
            ring->rev[revint[i]] = i;
            ring->rev[i] = revint[i];
        }
    }
    free(revint);
}

void CTRingMultiplier_preTable(uint64_t Np, uint64_t *root, uint64_t *invroot,CTRingMultiplier *ring){
    if(Np == 11){
        ring->pVec = 576460752303439873;
        ring->prVec = 9223372036854513648;
        ring->invp = -504407556043587583;
        *root = 94501300158356233;
        *invroot = 351196243136101305;
        ring->inv = 9007199254740992;
    }else if(Np == 12){
        ring->pVec = 576460752303439873;
        ring->prVec = 9223372036854513648;
        ring->invp = -504407556043587583;
        *root = 324227211372304498;
        *invroot = 295240848901397616;
        ring->inv = 4503599627370496;
    }else if(Np == 13){
        ring->pVec = 576460752303439873;
        ring->prVec = 9223372036854513648;
        ring->invp = -504407556043587583;
        *root = 3848444851313459;
        *invroot = 409403081178837348;
        ring->inv = 2251799813685248;
    }else if(Np == 14){
        ring->pVec = 576460752304439297;
        ring->prVec = 9223372036838522864;
        ring->invp = -471715844730093567;
        *root = 191393272803421785;
        *invroot = 427853369549297084;
        ring->inv = 1125899906842624;
    }else if(Np == 15){
        ring->pVec = 576460752308273153;
        ring->prVec = 9223372036777181168;
        ring->invp = -3956388753408917503;
        *root = 272758541886322648;
        *invroot = 13217847085486481;
        ring->inv = 562949953421312;
    }else{
        printf("error! cannot support this logN");
    }
}

// TODO is_use_pretable 默认值是false
int CTRingMultiplier_generate_prime(uint64_t Np, int primeLen, bool is_use_pretable,CTRingMultiplier * ring){
    ring->N = 1 << Np;
    ring->logN = Np;
    ring->primeLen = primeLen;
    ring->rev = (int *)malloc(sizeof (int) * ring->N);

    CTRingMultiplier_bitreverse(ring);
//    printf("bitreverse after\n");
//    for(int i = 0 ; i < 2048 ; ++i){
//        printf("%d ",ring->rev[i]);
//    }
    printf("\n");
    if (primeLen > 63){
        return 0;
    }

    uint64_t primetest = (1ULL << (ring->primeLen-1)) + 1;

    if (!is_use_pretable){
        while(true) {
            primetest += ring->N << 1;
            if(CTRingMultiplier_primeTest(primetest)) {
                ring->pVec = (int64_t) primetest;
                ring->prVec = (unsigned __int128)(1) << (2*(ring->primeLen + 1)) / ring->pVec;
                ring->invp = CTRingMultiplier_inver(ring->pVec);
                ring->g = (uint64_t *) malloc(sizeof (uint64_t) * (ring->N >> 1));
                ring->gi = (uint64_t *) malloc(sizeof (uint64_t) * (ring->N >> 1));

                uint64_t root = CTRingMultiplier_findMthRootOfUnity(ring->N, ring->pVec, ring->prVec,ring);   // get prime N-root of mod
                uint64_t invroot = CTRingMultiplier_invMod(root, ring->pVec);                // get inv prime N-root of mod

                uint64_t temp = ((uint64_t)1) << 32;
                ring->g[0] = 1;
                CTRingMultiplier_mulModBarrett(&ring->g[0], ring->g[0], temp, ring->pVec, ring->prVec,ring);
                CTRingMultiplier_mulModBarrett(&ring->g[0], ring->g[0], temp, ring->pVec, ring->prVec,ring);
                ring->gi[0] = ring->g[0];

                for (int P = 1; P < (int )(ring->N >> 1); P++){
                    ring->g[P] = CTRingMultiplier_REDC(ring->g[P-1], root,ring);
                    CTRingMultiplier_mulModBarrett(&ring->g[P], ring->g[P], temp, ring->pVec, ring->prVec,ring);
                    CTRingMultiplier_mulModBarrett(&ring->g[P], ring->g[P], temp, ring->pVec, ring->prVec,ring);
                    ring->gi[P] = CTRingMultiplier_REDC(ring->gi[P-1], invroot,ring);
                    CTRingMultiplier_mulModBarrett(&ring->gi[P], ring->gi[P], temp, ring->pVec, ring->prVec,ring);
                    CTRingMultiplier_mulModBarrett(&ring->gi[P], ring->gi[P], temp, ring->pVec, ring->prVec,ring);
                }

                ring->inv = CTRingMultiplier_powMod(ring->N, ring->pVec - 2, ring->pVec);                            //inv为len的逆元（费马小定理求逆元）
                CTRingMultiplier_mulModBarrett(&ring->inv,ring-> inv, temp, ring->pVec, ring->prVec,ring);
                CTRingMultiplier_mulModBarrett(&ring->inv, ring->inv, temp, ring->pVec, ring->prVec,ring);
                break;
            }
        }
    }else{
        uint64_t root;
        uint64_t invroot;
        ring->g = (uint64_t *) malloc(sizeof (uint64_t) * (ring->N >> 1));
        ring->gi = (uint64_t *) malloc(sizeof (uint64_t) * (ring->N >> 1));
        CTRingMultiplier_preTable(ring->logN, &root, &invroot,ring);

        uint64_t temp = ((uint64_t)1) << 32;
        ring->g[0] = 1;
        CTRingMultiplier_mulModBarrett(&ring->g[0], ring->g[0], temp, ring->pVec, ring->prVec,ring);
        CTRingMultiplier_mulModBarrett(&ring->g[0], ring->g[0], temp, ring->pVec, ring->prVec,ring);
        ring->gi[0] = ring->g[0];

        for (int P = 1; P < (int)(ring->N >> 1); P++){
            ring->g[P] = CTRingMultiplier_REDC(ring->g[P-1], root,ring);
            CTRingMultiplier_mulModBarrett(&ring->g[P], ring->g[P], temp, ring->pVec, ring->prVec,ring);
            CTRingMultiplier_mulModBarrett(&ring->g[P], ring->g[P], temp, ring->pVec, ring->prVec,ring);
            ring->gi[P] = CTRingMultiplier_REDC(ring->gi[P-1], invroot,ring);
            CTRingMultiplier_mulModBarrett(&ring->gi[P], ring->gi[P], temp, ring->pVec, ring->prVec,ring);
            CTRingMultiplier_mulModBarrett(&ring->gi[P], ring->gi[P], temp, ring->pVec, ring->prVec,ring);
        }
    }

    return 1;
}
uint64_t CTRingMultiplier_REDC(uint64_t a, uint64_t b,CTRingMultiplier *ring){
    unsigned __int128 U = ((unsigned __int128)a) * b;
    uint64_t U0 = ((uint64_t)U);
    uint64_t U1 = U >> 64;
    uint64_t Q = U0 * ring->invp;
    unsigned __int128 Hx = ((unsigned __int128)Q) * ring->pVec;
    uint64_t H = Hx >> 64;
    uint64_t V = U1 < H ? U1 + ring->pVec - H : U1 - H;
    return V;
}

void CTRingMultiplier_NTT(uint64_t *a,CTRingMultiplier * ring){
    int NLess2 = ring->N >> 1;

    uint64_t* temp_a =  (uint64_t *)malloc(sizeof (uint64_t) * ring->N);
    for (int i = 0; i < NLess2; i++)
    {
        uint64_t U1 = a[ring->rev[2 * i]] + a[ring->rev[2 * i + 1]];
        uint64_t U2 = a[ring->rev[2 * i]] - a[ring->rev[2 * i + 1]];
        temp_a[i] = U1 > ring->pVec ? U1 - ring->pVec : U1;
        temp_a[i + NLess2] = U2 > ring->pVec ? U2 + ring->pVec : U2;
    }
    memcpy(a, temp_a, sizeof(uint64_t)*ring->N);
    for (size_t i = 1; i < ring->logN; i++){
        int shift = ring->logN - 1 - i;
        for (int j = 0; j < NLess2; j++){
            int P = (j >> shift) << shift;
            uint64_t odd = CTRingMultiplier_REDC(a[2 * j + 1], ring->g[P],ring);
            uint64_t U1 = a[2 * j] + odd;
            uint64_t U2 = a[2 * j] - odd;
            temp_a[j] = U1 > ring->pVec ? U1 - ring->pVec : U1;
            temp_a[j + NLess2] = U2 > ring->pVec ? U2 + ring->pVec : U2;

        }
        memcpy(a, temp_a, sizeof(uint64_t)*ring->N);
    }
    free(temp_a);
}

void CTRingMultiplier_INTT(uint64_t *a,CTRingMultiplier * ring){

    int NLess2 = ring->N >> 1;
    uint64_t* temp_a = (uint64_t *) malloc(sizeof (uint64_t)*ring->N);
    for (int i = 0; i < NLess2; i++)
    {
        uint64_t U1 = a[ring->rev[2 * i]] + a[ring->rev[2 * i + 1]];
        uint64_t U2 = a[ring->rev[2 * i]] - a[ring->rev[2 * i + 1]];
        temp_a[i] = U1 > ring->pVec ? U1 - ring->pVec : U1;
        temp_a[i + NLess2] = U2 > ring->pVec ? U2 + ring->pVec : U2;
    }
    memcpy(a, temp_a, sizeof(uint64_t)*ring->N);
    for (size_t i = 1; i < ring->logN; i++){
        int shift = ring->logN - 1 - i;
        for (int j = 0; j < NLess2; j++){
            int P = (j >> shift) << shift;
            uint64_t odd = CTRingMultiplier_REDC(a[2 * j + 1], ring->gi[P],ring);
            uint64_t U1 = a[2 * j] + odd;
            uint64_t U2 = a[2 * j] - odd;
            temp_a[j] = U1 > ring->pVec ? U1 - ring->pVec : U1;
            temp_a[j + NLess2] = U2 > ring->pVec ? U2 + ring->pVec : U2;
        }
        memcpy(a, temp_a, sizeof(uint64_t)*ring->N);
    }
    free(temp_a);
    for (uint64_t i = 0; i < ring->N; i++)
    {
        a[i] = CTRingMultiplier_REDC(a[i], ring->inv,ring);
    }
}
int i = 0;
void fast_INTT(uint64_t *a,CTRingMultiplier * ring){
    int NLess2 = ring->N >> 1;
    uint64_t *temp_a = (uint64_t *)malloc(sizeof(uint64_t) * ring->N);
    for (int i = 0; i < NLess2; i++)
    {
        uint64_t U1 = a[ring->rev[2 * i]] + a[ring->rev[2 * i + 1]];
        uint64_t U2 = a[ring->rev[2 * i]] - a[ring->rev[2 * i + 1]];

        temp_a[i] = U1 > ring->pVec ? U1 - ring->pVec : U1;
        temp_a[i + NLess2] = U2 > ring->pVec ? U2 + ring->pVec : U2;
    }

    memcpy(a, temp_a, sizeof(uint64_t) * ring->N);

    for (int i = 1; i < ring->logN; i++)
    {
        int shift = ring->logN - 1 - i;
        for (int j = 0; j < NLess2; j++)
        {
            int P = (j >> shift) << shift;
            uint64_t odd = CTRingMultiplier_REDC(a[2 * j + 1], ring->gi[P],ring);
            // mulModBarrett(odd, a[2 * j + 1], gi[P], pVec, prVec);
            uint64_t U1 = a[2 * j] + odd;
            uint64_t U2 = a[2 * j] - odd;
            temp_a[j] = U1 > ring->pVec ? U1 - ring->pVec : U1;
            temp_a[j + NLess2] = U2 > ring->pVec ? U2 + ring->pVec : U2;
        }
        memcpy(a, temp_a, sizeof(uint64_t) * ring->N);
    }
    free(temp_a);
}

void CTRingMultiplier_pre_handle_s(uint64_t *s,CTRingMultiplier *ring){
    for (uint64_t i = 0; i < ring->N; i++)
    {
        // mulModBarrett(s[i], s[i], inv, pVec, prVec);
        s[i] = CTRingMultiplier_REDC(s[i], ring->inv,ring);
    }
}

void CTRingMultiplier_mult_raw(int64_t *c, uint64_t *a, uint64_t *b, uint64_t mod,CTRingMultiplier * ring){
    uint64_t temp1 = ring->pVec >> 1;
    for (uint64_t i = 0; i < ring->N; i++)
    {
        for (size_t j = 0; j < ring->N; j++)
        {
            uint64_t temp = 0;
            CTRingMultiplier_mulMod(&temp, a[i], b[j], mod);
            c[(i + j) % ring->N] += temp;
            c[(i + j) % ring->N] %= mod;
        }
    }
    for (uint64_t i = 0; i < ring->N; i++)
    {
        if (c[i] > (int64_t)temp1)
        {
            c[i] = c[i] - ring->pVec;
        }
    }
}

void CTRingMultiplier_uintchangeint(uint64_t *a, size_t slots,CTRingMultiplier * ring){
    uint64_t pr_2 = ring->pVec >> 1;
    int64_t *b = (int64_t *)malloc(sizeof(int64_t) * slots);
    for (size_t i = 0; i < slots; i++)
    {
        b[i] = a[i] >= pr_2 ? (a[i] - ring->pVec) : a[i];
    }
    printf_ploy_int64_t(b, slots);
}

void CTRingMultiplier_mult(uint64_t **x, uint64_t *a, uint64_t *b,CTRingMultiplier * ring){
    *x = (uint64_t *)malloc(sizeof(uint64_t) * ring->N);
    for (uint64_t i = 0; i < ring->N; ++i)
        CTRingMultiplier_mulModBarrett(&(*x)[i], a[i], b[i], ring->pVec, ring->prVec,ring);
}
void CTRingMultiplier_mult_poly(uint64_t **x, uint64_t *a, uint64_t *b,CTRingMultiplier * ring){
    *x = (uint64_t *)malloc(sizeof(uint64_t) * ring->N);
    // 申请空间失败
    if (*x == NULL) {
        SLogTrace("CTRingMultiplier_mult_poly x Memory allocation failed");
        return; // 早期退出或者报错
    }
    for (int i = 0; i < ring->N; ++i){
        CTRingMultiplier_mulModBarrett(&(*x)[i], a[i], b[i], ring->pVec, ring->prVec,ring); // O(n)乘法
    }
    CTRingMultiplier_INTT(*x,ring);
}
void CTRingMultiplier_fast_mult_poly(uint64_t **x, uint64_t *a, uint64_t *b,CTRingMultiplier * ring){
    *x = (uint64_t *)malloc(sizeof(uint64_t) * ring->N);
    memset(*x,0,sizeof(uint64_t) * ring->N);
    for (int i = 0; i < ring->N; ++i){
        // 问题
        CTRingMultiplier_mulModBarrett(&(x[0][i]), a[i], b[i], ring->pVec, ring->prVec,ring); // O(n)乘法
    }
    fast_INTT(*x,ring);

}
void CTRingMultiplier_sub(uint64_t *e, uint64_t **b,CTRingMultiplier * ring){
    for (uint64_t i = 0; i < ring->N; i++)
        (*b)[i] = (ring->pVec - (*b)[i] + e[i]) % ring->pVec;
}
void CTRingMultiplier_sub_o(uint64_t **c, uint64_t *a, uint64_t *b,CTRingMultiplier * ring){
    for (uint64_t i = 0; i < ring->N; i++)
        (*c)[i] = (ring->pVec - b[i] + a[i]) % ring->pVec;
}

void CTRingMultiplier_add(uint64_t **a, uint64_t *b,CTRingMultiplier * ring){
    for (uint64_t i = 0; i < ring->N; i++)
        a[0][i] = ((*a)[i] + b[i]) % ring->pVec;
}

void CTRingMultiplier_add_o(uint64_t **c, uint64_t *a, uint64_t *b,CTRingMultiplier * ring){
    for (uint64_t i = 0; i < ring->N; i++)
        (*c)[i] = (a[i] + b[i]) % ring->pVec;
}