/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/rand.h>


const sm9_bn_t SM9_ZERO = {0,0,0,0,0,0,0,0};
const sm9_bn_t SM9_ONE = {1,0,0,0,0,0,0,0};
static const sm9_bn_t SM9_TWO = {2,0,0,0,0,0,0,0};
static const sm9_bn_t SM9_FIVE = {5,0,0,0,0,0,0,0};


// p =  b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
// n =  b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25
// mu_p = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
// mu_n = 2^512 // n
const sm9_bn_t SM9_P = {0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
const sm9_bn_t SM9_N = {0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
const sm9_bn_t SM9_2e512modp = {0xb417e2d2, 0x27dea312, 0xae1a5d3f, 0x88f8105f, 0xd6706e7b, 0xe479b522, 0x56f62fbd, 0x2ea795a6};
const sm9_bn_t SM9_W = {0x2f2ee42b, 0x892bc42c, 0x13c8dbaf, 0x181ae396, 0x1522b137, 0x966a4b29, 0x558a13b3, 0xafd2bac5};
const uint64_t SM9_M0 = 0x2f2ee42b;
const sm9_bn_t SM9_MONT_ONE = {0x1caeba83, 0x1a9064d8, 0xe5851124, 0xde0d6cb4, 0x0a7138ba, 0x29fc54b0, 0xfd5c590e, 0x49bfffff};
const sm9_bn_t SM9_MONT_FIVE = {0xc8c71995, 0xb9f2c1e8, 0x46a377fc, 0x125df8f2, 0x49188d1c, 0x25e650d0, 0xed866f63, 0x43fffff};
#define SM9_NEG_P SM9_MONT_ONE
static const sm9_bn_t SM9_P_MINUS_ONE = {0xe351457c, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const sm9_bn_t SM9_N_MINUS_ONE = {0xd69ecf24, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const sm9_barrett_bn_t SM9_MU_P = {0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001};
static const sm9_barrett_bn_t SM9_MU_N = {0xdfc97c2f, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001};
static const sm9_barrett_bn_t SM9_MU_N_MINUS_ONE = {0xdfc97c31, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001};


// P1.X 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
// P1.Y 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
const SM9_POINT _SM9_P1 = {
	{0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f, 0x93de051d},
	{0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607, 0x21fe8dda},
	{1,0,0,0,0,0,0,0}
};
const SM9_POINT *SM9_P1 = &_SM9_P1;
const SM9_POINT _SM9_MONT_P1 = {
	{0x9860501b, 0x22e935e2, 0x0073282c, 0xa946fd5e, 0x17a649be, 0xefd0cec8, 0x869140b5, 0x5129787c},
	{0xeb87f7c7, 0xee779649, 0xec30a576, 0x15563cbd, 0x2824efbf, 0x32635391, 0x63c39828, 0x72157177},
	{0x1caeba83, 0x1a9064d8, 0xe5851124, 0xde0d6cb4, 0x0a7138ba, 0x29fc54b0, 0xfd5c590e, 0x49bfffff}
};
const SM9_POINT *SM9_MONT_P1 = &_SM9_MONT_P1;

/*
	X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
	     0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n],
	Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
	     0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n],
	Z : [1n, 0n],
*/
const SM9_TWIST_POINT _SM9_P2 = {
	{{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
	 {0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}},
	{{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
	 {0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}},
	{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
};
const SM9_TWIST_POINT *SM9_P2 = &_SM9_P2;
const SM9_TWIST_POINT _SM9_MONT_P2 = {
	{{0x8ce2da8f, 0x260226a6, 0xdbf6c06b, 0x7ee5645e, 0xb1495444, 0xf8f57c82, 0xbc47c4d1, 0x61fcf018},
	 {0x2750a8a6, 0xdb6db482, 0x5121f134, 0x84c6135a, 0x88791d41, 0x1874032f, 0xb85f3a37, 0x905112f2}},
	{{0x9171c24a, 0xc03f138f, 0xa15a3ca7, 0x92fbab45, 0x2ff77cdb, 0x2445561e, 0xc0f62ece, 0x108495e0},
	 {0x4c89bfbb, 0xf7b82dac, 0xa49dc12f, 0x3706f3f6, 0xd3eef769, 0x1e29de93, 0xc76a5d53, 0x81e448c3}},
	{{0x1caeba83, 0x1a9064d8, 0xe5851124, 0xde0d6cb4, 0x0a7138ba, 0x29fc54b0, 0xfd5c590e, 0x49bfffff}, {0,0,0,0}},
};
const SM9_TWIST_POINT *SM9_MONT_P2 = &_SM9_MONT_P2;


const SM9_TWIST_POINT _SM9_Ppubs = {
	{{0x96EA5E32, 0x8F14D656, 0x386A92DD, 0x414D2177, 0x24A3B573, 0x6CE843ED, 0x152D1F78, 0x29DBA116},
	 {0x1B94C408, 0x0AB1B679, 0x5E392CFB, 0x1CE0711C, 0x41B56501, 0xE48AFF4B, 0x3084F733, 0x9F64080B}},
	{{0xB4E3216D, 0x0E75C05F, 0x5CDFF073, 0x1006E85F, 0xB7A46F74, 0x1A7CE027, 0xDDA532DA, 0x41E00A53},
         {0xD0EF1C25, 0xE89E1408, 0x1A77F335, 0xAD3E2FDB, 0x47E3A0CB, 0xB57329F4, 0xABEA0112, 0x69850938}},
	{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
};
const SM9_TWIST_POINT *SM9_Ppubs = &_SM9_Ppubs;


void sm9_bn_set_zero(sm9_bn_t r)
{
	sm9_bn_copy(r, SM9_ZERO);
}

void sm9_bn_set_one(sm9_bn_t r)
{
	sm9_bn_copy(r, SM9_ONE);
	// sm9_bn_copy(r, SM9_2e512modp);
}

int sm9_bn_is_zero(const sm9_bn_t a)
{
	return (sm9_bn_cmp(a, SM9_ZERO) == 0);
}

int sm9_bn_is_one(const sm9_bn_t a)
{
	return (sm9_bn_cmp(a, SM9_ONE) == 0);
	// return (sm9_bn_cmp(a, SM9_2e512modp) == 0);
}

void sm9_bn_to_bytes(const sm9_bn_t a, uint8_t out[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		PUTU32(out, (uint32_t)a[i]);
		out += sizeof(uint32_t);
	}
}

void sm9_bn_from_bytes(sm9_bn_t r, const uint8_t in[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		r[i] = GETU32(in);
		in += sizeof(uint32_t);
	}
}

int sm9_bn_from_hex(sm9_bn_t r, const char hex[64])
{
	uint8_t buf[32];
	size_t len;
	if (hex_to_bytes(hex, 64, buf, &len) < 0) {
		return -1;
	}
	sm9_bn_from_bytes(r, buf);
	return 1;
}

void sm9_bn_to_hex(const sm9_bn_t a, char hex[64])
{
	int i;
	for (i = 7; i >= 0; i--) {
		(void)sprintf(hex + 8*(7-i), "%08x", (uint32_t)a[i]);
		//hex += 8;
	}
}

void sm9_print_bn(const char *prefix, const sm9_bn_t a)
{
	char hex[65] = {0};
	sm9_bn_to_hex(a, hex);
	printf("%s\n%s\n", prefix, hex);
}

void sm9_bn_to_bits(const sm9_bn_t a, char bits[256])
{
	int i, j;
	for (i = 7; i >= 0; i--) {
		uint32_t w = (uint32_t)a[i];
		for (j = 0; j < 32; j++) {
			*bits++ = (w & 0x80000000) ? '1' : '0';
			w <<= 1;
		}
	}
}

int sm9_bn_cmp(const sm9_bn_t a, const sm9_bn_t b)
{
	int i;
	for (i = 7; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}




void sm9_bn_copy(sm9_bn_t r, const sm9_bn_t a)
{
	memcpy(r, a, sizeof(sm9_bn_t));
}

void sm9_bn_set_word(sm9_bn_t r, uint32_t a)
{
	sm9_bn_set_zero(r);
	r[0] = a;
}

void sm9_bn_add(sm9_bn_t r, const sm9_bn_t a, const sm9_bn_t b)
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 8; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 7; i++) {
		r[i] &= 0xffffffff;
	}
}

void sm9_bn_sub(sm9_bn_t ret, const sm9_bn_t a, const sm9_bn_t b)
{
	int i;
	sm9_bn_t r;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 7; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	sm9_bn_copy(ret, r);
}

int sm9_bn_rand_range(sm9_bn_t r, const sm9_bn_t range)
{
	uint8_t buf[256];

	do {
		rand_bytes(buf, sizeof(buf));
		sm9_bn_from_bytes(r, buf);
	} while (sm9_bn_cmp(r, range) >= 0);
	return 1;
}

int sm9_bn_equ(const sm9_bn_t a, const sm9_bn_t b)
{
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

void sm9_fp_set_mont_one(sm9_fp_t r)
{
	// sm9_bn_copy(r, SM9_2e512modp);
	sm9_bn_copy(r, SM9_MONT_ONE);
}

int sm9_fp_is_mont_one(sm9_fp_t a)
{
	return sm9_bn_equ(a, SM9_MONT_ONE);
}

void sm9_fp_add(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b)
{
	sm9_bn_add(r, a, b);
	if (sm9_bn_cmp(r, SM9_P) >= 0) {
		sm9_bn_sub(r, r, SM9_P);
	}
}

void sm9_fp_sub(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b)
{
	if (sm9_bn_cmp(a, b) >= 0) {
		sm9_bn_sub(r, a, b);
	} else {
		sm9_bn_t t;
		sm9_bn_sub(t, SM9_P, b);
		sm9_bn_add(r, t, a);
	}
}

void sm9_fp_dbl(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_add(r, a, a);
	// r[0] = a[0] << 1;
	// for (int i = 1; i < 8; i++) {
	// 	r[i] = a[i] << 1 | a[i - 1] >> 31;
	// }
	// for (int i = 0; i < 7; i++) {
	// 	r[i] &= 0xffffffff;
	// }
	// if (sm9_bn_cmp(r, SM9_P) >= 0) {
	// 	sm9_bn_sub(r, r, SM9_P);
	// }
}

void sm9_fp_tri(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_t t;
	sm9_fp_dbl(t, a);
	sm9_fp_add(r, t, a);
}

void sm9_fp_div2(sm9_fp_t r, const sm9_fp_t a)
{
	int i;
	sm9_bn_copy(r, a);
	if (r[0] & 0x01) {
		sm9_bn_add(r, r, SM9_P);
	}
	for (i = 0; i < 7; i++) {
		r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
	}
	r[i] >>= 1;
}

void sm9_fp_neg(sm9_fp_t r, const sm9_fp_t a)
{
	if (sm9_bn_is_zero(a)) {
		sm9_bn_copy(r, a);
	} else {
		sm9_bn_sub(r, SM9_P, a);
	}
}

int sm9_bn_print(FILE *fp, int fmt, int ind, const char *label, const sm9_bn_t a)
{
	uint8_t buf[32];
	sm9_bn_to_bytes(a, buf);
	format_bytes(fp, fmt, ind, label, buf, sizeof(buf));
	return 1;
}

int sm9_barrett_bn_cmp(const sm9_barrett_bn_t a, const sm9_barrett_bn_t b)
{
	int i;
	for (i = 8; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

void sm9_barrett_bn_add(sm9_barrett_bn_t r, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b)
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 9; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 8; i++) {
		r[i] &= 0xffffffff;
	}
}

void sm9_barrett_bn_sub(sm9_barrett_bn_t ret, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b)
{
	sm9_barrett_bn_t r;
	int i;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 8; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	for (i = 0; i < 9; i++) {
		ret[i] = r[i];
	}
}

int sm9_get_booth(const uint64_t a[8], uint64_t window_size, int i)
{
	uint64_t mask = (1 << window_size) - 1;
	uint64_t wbits;
	int n, j;

	if (i == 0) {
		return (int)((a[0] << 1) & mask) - (int)(a[0] & mask);
	}

	j = i * (int)window_size - 1;
	n = j / 32;
	j = j % 32;

	wbits = a[n] >> j;
	if ((32 - j) < (window_size + 1) && n < 7) {
		wbits |= a[n + 1] << (32 - j);
	}
	return (int)(wbits & mask) - (int)((wbits >> 1) & mask);
}

void sm9_fp_mont_mul(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b)
{
	int i, j;
	sm9_fp_t t;
	sm9_fp_copy(t, SM9_ZERO);
	uint64_t tN = 0;

	for (i = 0; i < 8; i++) {
		uint64_t carry1 = 0;
		uint64_t carry2 = 0;
		t[0] = a[0] * b[i] + t[0];
		carry1 = t[0] >> 32;
		t[0] &= 0xffffffff;
		// printf("t[0] = %08lx, carry1 = %08lx when i = %d\n", t[0], carry1, i);

		uint64_t m = (t[0] * SM9_M0) & 0xffffffff;
		carry2 = m * SM9_P[0] + t[0];
		carry2 >>= 32;
		// printf("m = %08lx, carry2 = %08lx when i = %d\n", m, carry2, i);
		for (j = 1; j < 8; j++) {
			t[j] = a[j] * b[i] + t[j] + carry1;
			carry1 = t[j] >> 32;
			t[j] &= 0xffffffff;
			// printf("t[j] = %08lx, carry1 = %08lx when i = %d, j = %d\n", t[j], carry1, i, j);
			t[j - 1] = m * SM9_P[j] + t[j] + carry2;
			carry2 = t[j - 1] >> 32;
			t[j - 1] &= 0xffffffff;
			// printf("t[j - 1] = %08lx, carry2 = %08lx when i = %d, j = %d\n", t[j - 1], carry2, i, j);
		}

		t[7] = tN + carry1 + carry2;
		tN = t[7] >> 32;
		t[7] &= 0xffffffff;
		// printf("t[7] = %08lx, tN = %08lx when i = %d\n", t[7], tN, i);
	}
	// t[7] |= (tN << 32);

	if (tN > 0) {
		sm9_fp_add(r, t, SM9_NEG_P);
	} else if (sm9_bn_cmp(t, SM9_P) >= 0) {
		sm9_fp_sub(r, t, SM9_P);
	} else {
		sm9_fp_copy(r, t);
	}
	
	// int i, j;
	// uint64_t t[10] = {0};
	// for (i = 0; i < 8; i++) {
	// 	uint64_t carry = 0;
	// 	for (j = 0; j < 8; j++)
	// 	{
	// 		t[j] = a[j] * b[i] + t[j] + carry;
	// 		carry = t[j] >> 32;
	// 		t[j] &= 0xffffffff;
	// 	}
	// 	t[8] = t[8] + carry;
	// 	t[9] = t[8] >> 32;
	// 	t[8] &= 0xffffffff;
	// 	uint64_t m = (t[0] * SM9_M0) & 0xffffffff;
	// 	carry = m * SM9_P[0] + t[0];
	// 	carry >>= 32;
	// 	for (j = 1; j < 8; j++) {
	// 		t[j - 1] = m * SM9_P[j] + t[j] + carry;
	// 		carry = t[j - 1] >> 32;
	// 		t[j - 1] &= 0xffffffff;
	// 	}
	// 	t[7] = t[8] + carry;
	// 	carry = t[7] >> 32;
	// 	t[7] &= 0xffffffff;
	// 	t[8] = t[9] + carry;
	// }
	// t[9] = 0;

	// int ge = 1;
	// for (i = 7; i >= 0; i--) {
	// 	if (t[i] > SM9_P[i]) {
	// 		ge = 1;
	// 		break;
	// 	} else if (t[i] < SM9_P[i]) {
	// 		ge = 0;
	// 		break;
	// 	}
	// }

	// if (ge || t[8] > 0) {
	// 	// t >= p, subtract p
	// 	uint64_t borrow = 0;
	// 	for (i = 0; i < 8; i++) {
	// 		uint64_t diff = t[i] - SM9_P[i] - borrow;
	// 		r[i] = diff & 0xffffffff;
	// 		borrow = (diff >> 63) & 1; // borrow if MSB is set (negative)
	// 	}
	// } else {
	// 	// t < p, copy directly
	// 	for (i = 0; i < 8; i++) {
	// 		r[i] = t[i];
	// 	}
	// }
}

void sm9_fp_to_mont(sm9_fp_t r, const sm9_fp_t a)
{
	if (sm9_bn_is_zero(a)) {
		sm9_bn_copy(r, a);
	} else {
		sm9_fp_mont_mul(r, a, SM9_2e512modp);
	}
}

void sm9_fp_from_mont(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_copy(r, a);
	int i, j;
	for (i = 0; i < 8; i++) {
		uint64_t m = r[i] * SM9_M0 & 0xffffffff;
		uint64_t carry = 0;
		carry = m * SM9_P[0] + r[i];
		carry >>= 32;

		for (j = 1; j < 8; j++) {
			r[(i + j) % 8] = m * SM9_P[j] + r[(i + j) % 8] + carry;
			carry = r[(i + j) % 8] >> 32;
			r[(i + j) % 8] &= 0xffffffff;
		}
		r[i % 8] = carry;
	}
}

void sm9_fp_mul(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b)
{
	uint64_t s[18];
	sm9_barrett_bn_t zh, zl, q;
	uint64_t w;
	int i, j;

	/* z = a * b */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + a[i] * b[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 9; j++) {
			w += s[i + j] + zh[i] * SM9_MU_P[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 9] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[9 + i];
	}

	/* q = q * p mod (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM9_P[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}

	/* r = zl - q (mod (2^32)^9) */

	if (sm9_barrett_bn_cmp(zl, q)) {
		sm9_barrett_bn_sub(zl, zl, q);
	} else {
		sm9_barrett_bn_t c = {0,0,0,0,0,0,0,0,0x100000000};
		sm9_barrett_bn_sub(q, c, q);
		sm9_barrett_bn_add(zl, q, zl);
	}


	for (i = 0; i < 8; i++) {
		r[i] = zl[i];
	}

	r[7] += (zl[8] << 32);

	/* while r >= p do: r = r - p */
	while (sm9_bn_cmp(r, SM9_P) >= 0) {

		sm9_bn_sub(r, r, SM9_P);
	}
}

void sm9_fp_mont_sqr(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_mont_mul(r, a, a);
}

void sm9_fp_sqr(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_mul(r, a, a);
}

void sm9_fp_pow(sm9_fp_t r, const sm9_fp_t a, const sm9_bn_t e)
{
	sm9_fp_t t;
	uint32_t w;
	int i, j;

	assert(sm9_bn_cmp(e, SM9_P_MINUS_ONE) < 0);

	// sm9_bn_set_one(t);
	sm9_bn_copy(t, SM9_MONT_ONE);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			sm9_fp_mont_sqr(t, t);
			// sm9_fp_sqr(t, t);
			if (w & 0x80000000)
				sm9_fp_mont_mul(t, t, a);
				// sm9_fp_mul(t, t, a);
			w <<= 1;
		}
	}
	sm9_bn_copy(r, t);
}

void sm9_fp_mont_inv(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_t u, v, b, c, tmp;
	sm9_bn_copy(u, a);
	sm9_bn_copy(v, SM9_P);
	sm9_bn_copy(b, SM9_2e512modp);
	sm9_bn_copy(c, SM9_ZERO);

	while (!sm9_bn_equ(u, SM9_ONE) && !sm9_bn_equ(v, SM9_ONE)) {
		while (u[0] & 0x1 == 0) {
			sm9_fp_div2(u, u);
			if (b[0] & 0x1 == 0) {
				sm9_fp_div2(b, b);
			} else {
				sm9_fp_add(tmp, b, SM9_P);
				sm9_fp_div2(b, tmp);
			}
		}

		while (v[0] & 0x1 == 0) {
			sm9_fp_div2(v, v);
			if (c[0] & 0x1 == 0) {
				sm9_fp_div2(c, c);
			} else {
				sm9_fp_add(tmp, c, SM9_P);
				sm9_fp_div2(c, tmp);
			}
		}

		if (sm9_bn_cmp(u, v) >= 0) {
			sm9_fp_sub(u, u, v);
			sm9_fp_sub(b, b, c);
		} else {
			sm9_fp_sub(v, v, u);
			sm9_fp_sub(c, c, b);
		}
	}

	if (sm9_bn_equ(u, SM9_ONE)) {
		sm9_bn_copy(r, b);
	} else {
		sm9_bn_copy(r, c);
	}
}

void sm9_fp_inv(sm9_fp_t r, const sm9_fp_t a)
{
	sm9_fp_t e;
	sm9_bn_sub(e, SM9_P, SM9_TWO);
	sm9_fp_pow(r, a, e);
}

void sm9_sum_of_products(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b, const sm9_fp_t c, const sm9_fp_t d)
{
	uint64_t s[8] = {0};
	uint64_t carry1, carry2;
	int i, j, k;

	for (i = 0; i < 8; i++) {
		carry1 = 0;
		carry2 = 0;
		uint64_t tmp[8];
		sm9_bn_copy(tmp, s);
		for (j = 0; j < 2; j++) {
			uint64_t v, carry = 0;
			for (k = 0; k < 8; k++) {
				if (j == 0) {
					v = a[i] * b[k] + tmp[k] + carry;
					tmp[k] = v & 0xffffffff;
					carry = v >> 32;
				} else {
					v = c[i] * d[k] + tmp[k] + carry;
					tmp[k] = v & 0xffffffff;
					carry = v >> 32;
				}
				carry1 = carry + carry1 + carry2;
				carry2 = carry1 >> 32;
				carry1 = carry1 & 0xffffffff;
			}
		}

		uint64_t m = tmp[0] * SM9_M0 & 0xffffffff;
		uint64_t carry = 0;
		carry = (m * SM9_P[0] + tmp[0]) >> 32;
		for (j = 1; j < 8; j++) {
			tmp[j - 1] = m * SM9_P[j] + tmp[j] + carry;
			carry = tmp[j - 1] >> 32;
			tmp[j - 1] &= 0xffffffff;
		}
		tmp[7] = (carry1 + carry2 + carry) & 0xffffffff;
		sm9_bn_copy(s, tmp);
	}

	sm9_bn_copy(r, s);

	if (sm9_bn_cmp(r, SM9_P) >= 0) {
		sm9_fp_sub(r, r, SM9_P);
	}
}

int sm9_fp_from_bytes(sm9_fp_t r, const uint8_t buf[32])
{
	sm9_bn_from_bytes(r, buf);
	if (sm9_bn_cmp(r, SM9_P) >= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_fp_from_hex(sm9_fp_t r, const char hex[64])
{
	if (sm9_bn_from_hex(r, hex) != 1) {
		error_print();
		return -1;
	}
	if (sm9_bn_cmp(r, SM9_P) >= 0) {
		error_print();
		return -1;
	}
	return 1;
}


const sm9_fp2_t SM9_FP2_ZERO = {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}};
const sm9_fp2_t SM9_FP2_ONE = {{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}};
const sm9_fp2_t SM9_FP2_U = {{0,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0}};
static const sm9_fp2_t SM9_FP2_5U = {{0,0,0,0,0,0,0,0},{5,0,0,0,0,0,0,0}};
static const sm9_fp2_t SM9_FP2_MONT_ONE = {
	{0x1caeba83, 0x1a9064d8, 0xe5851124, 0xde0d6cb4, 0x0a7138ba, 0x29fc54b0, 0xfd5c590e, 0x49bfffff}, 
	{0, 0, 0, 0, 0, 0, 0, 0}
};
static const sm9_fp2_t SM9_FP2_MONT_5U = {
	{0,0,0,0,0,0,0,0},
	{0xc8c71995, 0xb9f2c1e8, 0x46a377fc, 0x125df8f2,
		0x49188d1c, 0x25e650d0, 0xed866f63, 0x043fffff}
};

void sm9_fp2_set_mont_one(sm9_fp2_t r)
{
	sm9_fp_copy(r[0], SM9_MONT_ONE);
	sm9_fp_set_zero(r[1]);
}

int sm9_fp2_equ(const sm9_fp2_t a, const sm9_fp2_t b)
{
	// return (gmssl_secure_memcmp(a, b, sizeof(sm9_fp2_t)) == 0);
	return sm9_fp_equ(a[0], b[0]) && sm9_fp_equ(a[1], b[1]);
}

void sm9_fp2_copy(sm9_fp2_t r, const sm9_fp2_t a)
{
	memcpy(r, a, sizeof(sm9_fp2_t));
}

int sm9_fp2_rand(sm9_fp2_t r)
{
	if (sm9_fp_rand(r[0]) != 1
		|| sm9_fp_rand(r[1]) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void sm9_fp2_to_bytes(const sm9_fp2_t a, uint8_t buf[64])
{
	sm9_fp_t z;

	sm9_fp_from_mont(z, a[1]);
	sm9_fp_to_bytes(z, buf);

	sm9_fp_from_mont(z, a[0]);
	sm9_fp_to_bytes(z, buf + 32);
}

int sm9_fp2_from_bytes(sm9_fp2_t r, const uint8_t buf[64])
{
	if (sm9_fp_from_bytes(r[1], buf) != 1
		|| sm9_fp_from_bytes(r[0], buf + 32) != 1) {
		error_print();
		return -1;
	}
	sm9_fp_to_mont(r[1], r[1]);
	sm9_fp_to_mont(r[0], r[0]);
	return 1;
}

int sm9_fp2_from_hex(sm9_fp2_t r, const char hex[129])
{
	if (sm9_fp_from_hex(r[1], hex) != 1
		|| sm9_fp_from_hex(r[0], hex + 65) != 1) {
		error_print();
		return -1;
	}
	sm9_fp_to_mont(r[1], r[1]);
	sm9_fp_to_mont(r[0], r[0]);
	/*
	if (hex[64] != SM9_HEX_SEP) {
		error_print();
		return -1;
	}
	*/
	return 1;
}

void sm9_fp2_to_hex(const sm9_fp2_t a, char hex[129])
{
	sm9_fp_t z;

	sm9_fp_from_mont(z, a[1]);
	sm9_fp_to_hex(z, hex);
	hex[64] = SM9_HEX_SEP;
	sm9_fp_from_mont(z, a[0]);
	sm9_fp_to_hex(z, hex + 65);
}

void sm9_fp2_set_fp(sm9_fp2_t r, const sm9_fp_t a)
{
	sm9_fp_copy(r[0], a);
	sm9_fp_set_zero(r[1]);
}

void sm9_fp2_set(sm9_fp2_t r, const sm9_fp_t a0, const sm9_fp_t a1)
{
	sm9_fp_copy(r[0], a0);
	sm9_fp_copy(r[1], a1);
}

void sm9_fp2_add(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b)
{
	sm9_fp_add(r[0], a[0], b[0]);
	sm9_fp_add(r[1], a[1], b[1]);
}

void sm9_fp2_dbl(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_dbl(r[0], a[0]);
	sm9_fp_dbl(r[1], a[1]);
}

void sm9_fp2_tri(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_tri(r[0], a[0]);
	sm9_fp_tri(r[1], a[1]);
}

void sm9_fp2_haf(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_div2(r[0], a[0]);
	sm9_fp_div2(r[1], a[1]);
}

void sm9_fp2_sub(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b)
{
	sm9_fp_sub(r[0], a[0], b[0]);
	sm9_fp_sub(r[1], a[1], b[1]);
}

void sm9_fp2_neg(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_neg(r[0], a[0]);
	sm9_fp_neg(r[1], a[1]);
}


void sm9_fp2_a_mul_u(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_t r0;

	sm9_fp_dbl(r0, a[1]);
	sm9_fp_neg(r0, r0);

	sm9_fp_copy(r[1], a[0]);
	sm9_fp_copy(r[0], r0);
}

void sm9_fp2_mul(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b)
{
	// sm9_fp_t r0;
	// sm9_fp_t r1;
	// sm9_fp_t t;
	// sm9_fp_dbl(t, a[1]);
	// sm9_fp_neg(t, t);
	// sm9_sum_of_products(r0, a[0], b[0], t, b[1]);
	// sm9_sum_of_products(r1, a[0], b[1], a[1], b[0]);
	// sm9_fp_copy(r[0], r0);
	// sm9_fp_copy(r[1], r1);

	sm9_fp_t t0;
	sm9_fp_t t1;
	sm9_fp_t t2;

	// t2 = (a0 + a1) * (b0 + b1)
	sm9_fp_add(t0, a[0], a[1]);
	sm9_fp_add(t1, b[0], b[1]);
	sm9_fp_mont_mul(t2, t0, t1);

	// t0 = a0 * b0
	sm9_fp_mont_mul(t0, a[0], b[0]);

	// t1 = a1 * b1
	sm9_fp_mont_mul(t1, a[1], b[1]);

	// r1 = t2 - t0 - t1 = a0 * b1 + a1 * b0
	sm9_fp_sub(t2, t2, t0);
	sm9_fp_sub(t2, t2, t1);

	// r0 = t0 - 2*t1 = a0 * b0 - 2(a1 * b1)
	sm9_fp_dbl(t1, t1);
	sm9_fp_sub(t0, t0, t1);

	sm9_fp_copy(r[0], t0);
	sm9_fp_copy(r[1], t2);

	// sm9_fp_t r0, r1, t;
	//
	// // r0 = a0 * b0 - 2 * a1 * b1
	// sm9_fp_mul(r0, a[0], b[0]);
	// sm9_fp_mul(t, a[1], b[1]);
	// sm9_fp_dbl(t, t);
	// sm9_fp_sub(r0, r0, t);
	//
	// // r1 = a0 * b1 + a1 * b0
	// sm9_fp_mul(r1, a[0], b[1]);
	// sm9_fp_mul(t, a[1], b[0]);
	// sm9_fp_add(r1, r1, t);
	//
	// sm9_fp_copy(r[0], r0);
	// sm9_fp_copy(r[1], r1);
}

void sm9_fp2_mul_u(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b)
{
	sm9_fp_t t0, t1, t2;

	// t2 = (a0 + a1) * (b0 + b1)
	sm9_fp_add(t0, a[0], a[1]);
	sm9_fp_add(t1, b[0], b[1]);
	sm9_fp_mont_mul(t2, t0, t1);

	// t0 = a0 * b0
	sm9_fp_mont_mul(t0, a[0], b[0]);

	// t1 = a1 * b1
	sm9_fp_mont_mul(t1, a[1], b[1]);

	// r0 = -2 * (t2 - t0 - t1) = -2 * (a0 * b1 + a1 * b0)
	sm9_fp_sub(t2, t2, t0);
	sm9_fp_sub(t2, t2, t1);
	sm9_fp_dbl(t2, t2);
	sm9_fp_neg(t2, t2);

	// r1 = t0 - 2 * t1 = a0 * b0 - 2(a1 * b1)
	sm9_fp_dbl(t1, t1);
	sm9_fp_sub(t0, t0, t1);

	sm9_fp_copy(r[0], t2);
	sm9_fp_copy(r[1], t0);
}

void sm9_fp2_mul_fp(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp_t k)
{
	sm9_fp_mont_mul(r[0], a[0], k);
	sm9_fp_mont_mul(r[1], a[1], k);
}

void sm9_fp2_sqr(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_t r0, r1, c0, c1;

	// r0 = (a0 + a1) * (a0 - 2a1) + a0 * a1 = a0^2 - 2 * a1^2
	sm9_fp_mont_mul(r1, a[0], a[1]);
	sm9_fp_add(c0, a[0], a[1]);
	sm9_fp_dbl(c1, a[1]);
	sm9_fp_sub(c1, a[0], c1);
	sm9_fp_mont_mul(r0, c0, c1);
	sm9_fp_add(r0, r0, r1);

	// r1 = 2 * a0 * a1
	sm9_fp_dbl(r1, r1);

	sm9_bn_copy(r[0], r0);
	sm9_bn_copy(r[1], r1);
}

void sm9_fp2_sqr_u(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_t t0, t1, t2;

	// t0 = a0 * a1
	sm9_fp_mont_mul(t0, a[0], a[1]);

	// t1 = a0 + a1
	sm9_fp_add(t1, a[0], a[1]);

	// t2 = a0 - 2*a
	sm9_fp_sub(t2, a[0], a[1]);
	sm9_fp_sub(t2, t2, a[1]);

	// r1 = t1 * t2 + t0
	sm9_fp_mont_mul(t2, t2, t1);
	sm9_fp_add(t2, t2, t0);

	// r0 = -4 * t0
	sm9_fp_dbl(t0, t0);
	sm9_fp_dbl(t0, t0);
	sm9_fp_neg(t0, t0);

	sm9_fp_copy(r[0], t0);
	sm9_fp_copy(r[1], t2);
}

void sm9_fp2_inv(sm9_fp2_t r, const sm9_fp2_t a)
{
	if (sm9_fp_is_zero(a[0])) {
		// r0 = 0
		sm9_fp_set_zero(r[0]);
		// r1 = -(2 * a1)^-1
		sm9_fp_dbl(r[1], a[1]);
		sm9_fp_mont_inv(r[1], r[1]);
		// sm9_fp_inv(r[1], r[1]);
		sm9_fp_neg(r[1], r[1]);

	} else if (sm9_fp_is_zero(a[1])) {
		/* r1 = 0 */
		sm9_fp_set_zero(r[1]);
		/* r0 = a0^-1 */
		sm9_fp_mont_inv(r[0], a[0]);
		// sm9_fp_inv(r[0], a[0]);

	} else {
		sm9_fp_t k, t;

		// k = (a[0]^2 + 2 * a[1]^2)^-1
		sm9_fp_mont_sqr(k, a[0]);
		sm9_fp_mont_sqr(t, a[1]);
		// sm9_fp_sqr(k, a[0]);
		// sm9_fp_sqr(t, a[1]);
		sm9_fp_dbl(t, t);
		sm9_fp_add(k, k, t);
		sm9_fp_mont_inv(k, k);
		// sm9_fp_inv(k, k);

		// r[0] = a[0] * k
		sm9_fp_mont_mul(r[0], a[0], k);
		// sm9_fp_mul(r[0], a[0], k);

		// r[1] = -a[1] * k
		sm9_fp_mont_mul(r[1], a[1], k);
		// sm9_fp_mul(r[1], a[1], k);
		sm9_fp_neg(r[1], r[1]);
	}
}

void sm9_fp2_div(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b)
{
	sm9_fp2_t t;
	sm9_fp2_inv(t, b);
	sm9_fp2_mul(r, a, t);
}

void sm9_fp2_div2(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_div2(r[0], a[0]);
	sm9_fp_div2(r[1], a[1]);
}

int sm9_fp2_print(FILE *fp, int fmt, int ind, const char *label, const sm9_fp2_t a)
{
	return 1;
}


const sm9_fp4_t SM9_FP4_ZERO = {{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
const sm9_fp4_t SM9_FP4_ONE = {{{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
const sm9_fp4_t SM9_FP4_U = {{{0,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
const sm9_fp4_t SM9_FP4_V = {{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
const sm9_fp4_t SM9_FP4_MONT_ONE = {
	{{0x1caeba83, 0x1a9064d8, 0xe5851124, 0xde0d6cb4, 0x0a7138ba, 0x29fc54b0, 0xfd5c590e, 0x49bfffff},{0,0,0,0,0,0,0,0}},
	{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}
};

int sm9_fp4_equ(const sm9_fp4_t a, const sm9_fp4_t b)
{
	// return (gmssl_secure_memcmp(a, b, sizeof(sm9_fp4_t)) == 0);
	return sm9_fp2_equ(a[0], b[0]) && sm9_fp2_equ(a[1], b[1]);
}

int sm9_fp4_rand(sm9_fp4_t r)
{
	if (sm9_fp2_rand(r[1]) != 1
		|| sm9_fp2_rand(r[0]) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void sm9_fp4_copy(sm9_fp4_t r, const sm9_fp4_t a)
{
	memcpy(r, a, sizeof(sm9_fp4_t));
}

void sm9_fp4_to_bytes(const sm9_fp4_t a, uint8_t buf[128])
{
	sm9_fp2_to_bytes(a[1], buf);
	sm9_fp2_to_bytes(a[0], buf + 64);
}

int sm9_fp4_from_bytes(sm9_fp4_t r, const uint8_t buf[128])
{
	if (sm9_fp2_from_bytes(r[1], buf) != 1
		|| sm9_fp2_from_bytes(r[0], buf + 64) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_fp4_from_hex(sm9_fp4_t r, const char hex[65 * 4])
{
	if (sm9_fp2_from_hex(r[1], hex) != 1
		|| hex[129] != SM9_HEX_SEP
		|| sm9_fp2_from_hex(r[0], hex + 130) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void sm9_fp4_to_hex(const sm9_fp4_t a, char hex[259])
{
	sm9_fp2_to_hex(a[1], hex);
	hex[129] = SM9_HEX_SEP;
	sm9_fp2_to_hex(a[0], hex + 130);
}

void sm9_fp4_set_fp(sm9_fp4_t r, const sm9_fp_t a)
{
	sm9_fp2_set_fp(r[0], a);
	sm9_fp2_set_zero(r[1]);
}

void sm9_fp4_set_fp2(sm9_fp4_t r, const sm9_fp2_t a)
{
	sm9_fp2_copy(r[0], a);
	sm9_fp2_set_zero(r[1]);
}

void sm9_fp4_set(sm9_fp4_t r, const sm9_fp2_t a0, const sm9_fp2_t a1)
{
	sm9_fp2_copy(r[0], a0);
	sm9_fp2_copy(r[1], a1);
}

void sm9_fp4_set_u(sm9_fp4_t r)
{
	sm9_fp2_set_u(r[0]);
	sm9_fp2_set_zero(r[1]);
}

void sm9_fp4_set_v(sm9_fp4_t r)
{
	sm9_fp2_set_zero(r[0]);
	sm9_fp2_set_mont_one(r[1]);
}

void sm9_fp4_add(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b)
{
	sm9_fp2_add(r[0], a[0], b[0]);
	sm9_fp2_add(r[1], a[1], b[1]);
}

void sm9_fp4_dbl(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_dbl(r[0], a[0]);
	sm9_fp2_dbl(r[1], a[1]);
}

void sm9_fp4_tri(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_tri(r[0], a[0]);
	sm9_fp2_tri(r[1], a[1]);
}

void sm9_fp4_haf(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_haf(r[0], a[0]);
	sm9_fp2_haf(r[1], a[1]);
}

void sm9_fp4_sub(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b)
{
	sm9_fp2_sub(r[0], a[0], b[0]);
	sm9_fp2_sub(r[1], a[1], b[1]);
}

void sm9_fp4_neg(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_neg(r[0], a[0]);
	sm9_fp2_neg(r[1], a[1]);
}

void sm9_fp4_mul(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b)
{
	sm9_fp2_t r0, r1, t;

	// r0 = a0 + a1
	sm9_fp2_add(r0, a[0], a[1]);

	// t = b0 + b1
	sm9_fp2_add(t, b[0], b[1]);

	// r1 = (a0 + a1) * (b0 + b1)
	sm9_fp2_mul(r1, t, r0);

	// r0 = a0 * b0
	sm9_fp2_mul(r0, a[0], b[0]);

	// t = a1 * b1
	sm9_fp2_mul(t, a[1], b[1]);

	// r1 = a0 * b1 + a1 * b0
	sm9_fp2_sub(r1, r1, r0);
	sm9_fp2_sub(r1, r1, t);

	// t = a1 * b1 * u
	sm9_fp2_a_mul_u(t, t);

	// r0 = a0 * b0 + a1 * b1 * u
	sm9_fp2_add(r0, r0, t);

	sm9_fp2_copy(r[0], r0);
	sm9_fp2_copy(r[1], r1);
	// sm9_fp2_t r0, r1, t;
	//
	// sm9_fp2_mul(r0, a[0], b[0]);
	// sm9_fp2_mul_u(t, a[1], b[1]);
	// sm9_fp2_add(r0, r0, t);
	//
	// sm9_fp2_mul(r1, a[0], b[1]);
	// sm9_fp2_mul(t, a[1], b[0]);
	// sm9_fp2_add(r1, r1, t);
	//
	// sm9_fp2_copy(r[0], r0);
	// sm9_fp2_copy(r[1], r1);
}

void sm9_fp4_mul_fp(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp_t k)
{
	sm9_fp2_mul_fp(r[0], a[0], k);
	sm9_fp2_mul_fp(r[1], a[1], k);
}

void sm9_fp4_mul_fp2(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp2_t b0)
{
	sm9_fp2_mul(r[0], a[0], b0);
	sm9_fp2_mul(r[1], a[1], b0);
}

void sm9_fp4_mul_v(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b)
{
	sm9_fp2_t r0, r1, t;

	sm9_fp2_mul_u(r0, a[0], b[1]);
	sm9_fp2_mul_u(t, a[1], b[0]);
	sm9_fp2_add(r0, r0, t);

	sm9_fp2_mul(r1, a[0], b[0]);
	sm9_fp2_mul_u(t, a[1], b[1]);
	sm9_fp2_add(r1, r1, t);

	sm9_fp2_copy(r[0], r0);
	sm9_fp2_copy(r[1], r1);
}

// (a0 + a1*v) * v = a0 * v + a1 * v^2 = a1 * u + a0 * v
void sm9_fp4_a_mul_v(sm9_fp4_t r, sm9_fp4_t a)
{
	sm9_fp2_t r0; // incase r is a

	sm9_fp2_a_mul_u(r0, a[1]);

	sm9_fp2_copy(r[1], a[0]);
	sm9_fp2_copy(r[0], r0);
}

void sm9_fp4_sqr(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_t r0, r1, t;

	sm9_fp2_add(r1, a[0], a[1]);
	sm9_fp2_sqr(r1, r1);

	sm9_fp2_sqr(r0, a[0]);
	sm9_fp2_sqr(t, a[1]);

	sm9_fp2_sub(r1, r1, r0);
	sm9_fp2_sub(r1, r1, t);

	sm9_fp2_a_mul_u(t, t);
	sm9_fp2_add(r0, r0, t);

	sm9_fp2_copy(r[0], r0);
	sm9_fp2_copy(r[1], r1);
	// sm9_fp2_t r0, r1, t;
	//
	// sm9_fp2_sqr(r0, a[0]);
	// sm9_fp2_sqr_u(t, a[1]);
	// sm9_fp2_add(r0, r0, t);
	//
	// sm9_fp2_mul(r1, a[0], a[1]);
	// sm9_fp2_dbl(r1, r1);
	// sm9_fp2_copy(r[0], r0);
	// sm9_fp2_copy(r[1], r1);
}

void sm9_fp4_sqr_v(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_t r0, r1, t;

	sm9_fp2_mul_u(t, a[0], a[1]);
	sm9_fp2_dbl(r0, t);

	sm9_fp2_sqr(r1, a[0]);
	sm9_fp2_sqr_u(t, a[1]);
	sm9_fp2_add(r1, r1, t);

	sm9_fp2_copy(r[0], r0);
	sm9_fp2_copy(r[1], r1);
}

void sm9_fp4_inv(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_t r0, r1, k;

	sm9_fp2_sqr_u(k, a[1]);
	sm9_fp2_sqr(r0, a[0]);
	sm9_fp2_sub(k, k, r0);
	sm9_fp2_inv(k, k);

	sm9_fp2_mul(r0, a[0], k);
	sm9_fp2_neg(r0, r0);

	sm9_fp2_mul(r1, a[1], k);

	sm9_fp2_copy(r[0], r0);
	sm9_fp2_copy(r[1], r1);
}

void sm9_fp12_copy(sm9_fp12_t r, const sm9_fp12_t a)
{
	sm9_fp4_copy(r[0], a[0]);
	sm9_fp4_copy(r[1], a[1]);
	sm9_fp4_copy(r[2], a[2]);
}

int sm9_fp12_rand(sm9_fp12_t r)
{
	if (sm9_fp4_rand(r[0]) != 1
		|| sm9_fp4_rand(r[1]) != 1
		|| sm9_fp4_rand(r[2]) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void sm9_fp12_set_zero(sm9_fp12_t r)
{
	sm9_fp4_set_zero(r[0]);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_one(sm9_fp12_t r)
{
	sm9_fp4_set_one(r[0]);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

int sm9_fp12_is_one(const sm9_fp12_t a)
{
	return sm9_fp4_is_one(a[0])
		&& sm9_fp4_is_zero(a[1])
		&& sm9_fp4_is_zero(a[2]);
}

int sm9_fp12_is_zero(const sm9_fp12_t a)
{
	return sm9_fp4_is_zero(a[0])
		&& sm9_fp4_is_zero(a[1])
		&& sm9_fp4_is_zero(a[2]);
}

int sm9_fp12_from_hex(sm9_fp12_t r, const char hex[65 * 12 - 1])
{
	if (sm9_fp4_from_hex(r[2], hex) != 1
		|| hex[65 * 4 - 1] != SM9_HEX_SEP
		|| sm9_fp4_from_hex(r[1], hex + 65 * 4) != 1
		|| hex[65 * 4 - 1] != SM9_HEX_SEP
		|| sm9_fp4_from_hex(r[0], hex + 65 * 8) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void sm9_fp12_to_hex(const sm9_fp12_t a, char hex[65 * 12 - 1])
{
	sm9_fp4_to_hex(a[2], hex);
	hex[65 * 4 - 1] = SM9_HEX_SEP;
	sm9_fp4_to_hex(a[1], hex + 65 * 4);
	hex[65 * 8 - 1] = SM9_HEX_SEP;
	sm9_fp4_to_hex(a[0], hex + 65 * 8);
}

void sm9_fp12_print(const char *prefix, const sm9_fp12_t a)
{
	char hex[65 * 12];
	sm9_fp12_to_hex(a, hex);
	printf("%s\n%s\n", prefix, hex);
}

void sm9_fp12_set(sm9_fp12_t r, const sm9_fp4_t a0, const sm9_fp4_t a1, const sm9_fp4_t a2)
{
	sm9_fp4_copy(r[0], a0);
	sm9_fp4_copy(r[1], a1);
	sm9_fp4_copy(r[2], a2);
}

void sm9_fp12_set_fp(sm9_fp12_t r, const sm9_fp_t a)
{
	sm9_fp4_set_fp(r[0], a);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_fp2(sm9_fp12_t r, const sm9_fp2_t a)
{
	sm9_fp4_set_fp2(r[0], a);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_fp4(sm9_fp12_t r, const sm9_fp4_t a)
{
	sm9_fp4_copy(r[0], a);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_u(sm9_fp12_t r)
{
	sm9_fp4_set_u(r[0]);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_v(sm9_fp12_t r)
{
	sm9_fp4_set_v(r[0]);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_w(sm9_fp12_t r)
{
	sm9_fp4_set_zero(r[0]);
	sm9_fp4_set_one(r[1]);
	sm9_fp4_set_zero(r[2]);
}

void sm9_fp12_set_w_sqr(sm9_fp12_t r)
{
	sm9_fp4_set_zero(r[0]);
	sm9_fp4_set_zero(r[1]);
	sm9_fp4_set_one(r[2]);
}

int sm9_fp12_equ(const sm9_fp12_t a, const sm9_fp12_t b)
{
	return sm9_fp4_equ(a[0], b[0])
		&& sm9_fp4_equ(a[1], b[1])
		&& sm9_fp4_equ(a[2], b[2]);
}

void sm9_fp12_add(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b)
{
	sm9_fp4_add(r[0], a[0], b[0]);
	sm9_fp4_add(r[1], a[1], b[1]);
	sm9_fp4_add(r[2], a[2], b[2]);
}

void sm9_fp12_dbl(sm9_fp12_t r, const sm9_fp12_t a)
{
	sm9_fp4_dbl(r[0], a[0]);
	sm9_fp4_dbl(r[1], a[1]);
	sm9_fp4_dbl(r[2], a[2]);
}

void sm9_fp12_tri(sm9_fp12_t r, const sm9_fp12_t a)
{
	sm9_fp12_t t;
	sm9_fp12_dbl(t, a);
	sm9_fp12_add(r, t, a);
}

void sm9_fp12_sub(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b)
{
	sm9_fp4_sub(r[0], a[0], b[0]);
	sm9_fp4_sub(r[1], a[1], b[1]);
	sm9_fp4_sub(r[2], a[2], b[2]);
}

void sm9_fp12_neg(sm9_fp12_t r, const sm9_fp12_t a)
{
	sm9_fp4_neg(r[0], a[0]);
	sm9_fp4_neg(r[1], a[1]);
	sm9_fp4_neg(r[2], a[2]);
}

void sm9_fp12_mul(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b)
{
	sm9_fp4_t r0, r1, r2;
	sm9_fp4_t t,  k0, k1;
	sm9_fp4_t m0, m1, m2;

	sm9_fp4_mul(m0, a[0], b[0]);
	sm9_fp4_mul(m1, a[1], b[1]);
	sm9_fp4_mul(m2, a[2], b[2]);

	sm9_fp4_add(k0, a[1], a[2]);
	sm9_fp4_add(k1, b[1], b[2]);
	sm9_fp4_mul(t, k0, k1);
	sm9_fp4_sub(t, t, m1);
	sm9_fp4_sub(t, t, m2);
	sm9_fp4_a_mul_v(t, t);
	sm9_fp4_add(r0, t, m0);

	sm9_fp4_add(k0, a[0], a[2]);
	sm9_fp4_add(k1, b[0], b[2]);
	sm9_fp4_mul(t, k0, k1);
	sm9_fp4_sub(t, t, m0);
	sm9_fp4_sub(t, t, m2);
	sm9_fp4_add(r2, t, m1);

	sm9_fp4_add(k0, a[0], a[1]);
	sm9_fp4_add(k1, b[0], b[1]);
	sm9_fp4_mul(t, k0, k1);
	sm9_fp4_sub(t, t, m0);
	sm9_fp4_sub(t, t, m1);
	sm9_fp4_a_mul_v(m2, m2);
	sm9_fp4_add(r1, t, m2);

	sm9_fp4_copy(r[0], r0);
	sm9_fp4_copy(r[1], r1);
	sm9_fp4_copy(r[2], r2);
	// sm9_fp4_t r0, r1, r2, t;
	//
	// sm9_fp4_mul(r0, a[0], b[0]);
	// sm9_fp4_mul_v(t, a[1], b[2]);
	// sm9_fp4_add(r0, r0, t);
	// sm9_fp4_mul_v(t, a[2], b[1]);
	// sm9_fp4_add(r0, r0, t);
	//
	// sm9_fp4_mul(r1, a[0], b[1]);
	// sm9_fp4_mul(t, a[1], b[0]);
	// sm9_fp4_add(r1, r1, t);
	// sm9_fp4_mul_v(t, a[2], b[2]);
	// sm9_fp4_add(r1, r1, t);
	//
	// sm9_fp4_mul(r2, a[0], b[2]);
	// sm9_fp4_mul(t, a[1], b[1]);
	// sm9_fp4_add(r2, r2, t);
	// sm9_fp4_mul(t, a[2], b[0]);
	// sm9_fp4_add(r2, r2, t);
	//
	// sm9_fp4_copy(r[0], r0);
	// sm9_fp4_copy(r[1], r1);
	// sm9_fp4_copy(r[2], r2);
}

void sm9_fp12_sqr(sm9_fp12_t r, const sm9_fp12_t a)
{
	sm9_fp4_t h0, h1, h2, t;
	sm9_fp4_t s0, s1, s2, s3;

	sm9_fp4_sqr(h0, a[0]);
	sm9_fp4_sqr(h1, a[2]);
	sm9_fp4_add(s0, a[2], a[0]);

	sm9_fp4_sub(t, s0, a[1]);
	sm9_fp4_sqr(s1, t);

	sm9_fp4_add(t, s0, a[1]);
	sm9_fp4_sqr(s0, t);

	sm9_fp4_mul(s2, a[1], a[2]);
	sm9_fp4_dbl(s2, s2);

	sm9_fp4_add(s3, s0, s1);
	sm9_fp4_haf(s3, s3);

	sm9_fp4_sub(t, s3, h1);
	sm9_fp4_sub(h2, t, h0);

	sm9_fp4_a_mul_v(h1, h1);
	sm9_fp4_add(h1, h1, s0);
	sm9_fp4_sub(h1, h1, s2);
	sm9_fp4_sub(h1, h1, s3);

	sm9_fp4_a_mul_v(s2, s2);
	sm9_fp4_add(h0, h0, s2);

	sm9_fp4_copy(r[0], h0);
	sm9_fp4_copy(r[1], h1);
	sm9_fp4_copy(r[2], h2);

	// sm9_fp4_t r0, r1, r2, t;
	//
	// sm9_fp4_sqr(r0, a[0]);
	// sm9_fp4_mul_v(t, a[1], a[2]);
	// sm9_fp4_dbl(t, t);
	// sm9_fp4_add(r0, r0, t);
	//
	// sm9_fp4_mul(r1, a[0], a[1]);
	// sm9_fp4_dbl(r1, r1);
	// sm9_fp4_sqr_v(t, a[2]);
	// sm9_fp4_add(r1, r1, t);
	//
	// sm9_fp4_mul(r2, a[0], a[2]);
	// sm9_fp4_dbl(r2, r2);
	// sm9_fp4_sqr(t, a[1]);
	// sm9_fp4_add(r2, r2, t);
	//
	// sm9_fp4_copy(r[0], r0);
	// sm9_fp4_copy(r[1], r1);
	// sm9_fp4_copy(r[2], r2);
}

void sm9_fp12_inv(sm9_fp12_t r, const sm9_fp12_t a)
{
	if (sm9_fp4_is_zero(a[2])) {
		sm9_fp4_t k, t;

		sm9_fp4_sqr(k, a[0]);
		sm9_fp4_mul(k, k, a[0]);
		sm9_fp4_sqr_v(t, a[1]);
		sm9_fp4_mul(t, t, a[1]);
		sm9_fp4_add(k, k, t);
		sm9_fp4_inv(k, k);

		sm9_fp4_sqr(r[2], a[1]);
		sm9_fp4_mul(r[2], r[2], k);

		sm9_fp4_mul(r[1], a[0], a[1]);
		sm9_fp4_mul(r[1], r[1], k);
		sm9_fp4_neg(r[1], r[1]);

		sm9_fp4_sqr(r[0], a[0]);
		sm9_fp4_mul(r[0], r[0], k);

	} else {
		sm9_fp4_t t0, t1, t2, t3;

		sm9_fp4_sqr(t0, a[1]);
		sm9_fp4_mul(t1, a[0], a[2]);
		sm9_fp4_sub(t0, t0, t1);

		sm9_fp4_mul(t1, a[0], a[1]);
		sm9_fp4_sqr_v(t2, a[2]);
		sm9_fp4_sub(t1, t1, t2);

		sm9_fp4_sqr(t2, a[0]);
		sm9_fp4_mul_v(t3, a[1], a[2]);
		sm9_fp4_sub(t2, t2, t3);

		sm9_fp4_sqr(t3, t1);
		sm9_fp4_mul(r[0], t0, t2);
		sm9_fp4_sub(t3, t3, r[0]);
		sm9_fp4_inv(t3, t3);
		sm9_fp4_mul(t3, a[2], t3);

		sm9_fp4_mul(r[0], t2, t3);

		sm9_fp4_mul(r[1], t1, t3);
		sm9_fp4_neg(r[1], r[1]);

		sm9_fp4_mul(r[2], t0, t3);
	}
}

void sm9_fp12_pow(sm9_fp12_t r, const sm9_fp12_t a, const sm9_bn_t k)
{
	char kbits[257];
	sm9_fp12_t t;
	int i;

	assert(sm9_bn_cmp(k, SM9_P_MINUS_ONE) < 0);
	// sm9_fp12_set_zero(t);

	sm9_bn_to_bits(k, kbits);
	sm9_fp12_set_one(t);
	for (i = 0; i < 256; i++) {
		sm9_fp12_sqr(t, t);
		if (kbits[i] == '1') {
			sm9_fp12_mul(t, t, a);
		}
	}
	sm9_fp12_copy(r, t);
}

void sm9_fp2_conjugate(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp_copy(r[0], a[0]);
	sm9_fp_neg (r[1], a[1]);

}

void sm9_fp2_frobenius(sm9_fp2_t r, const sm9_fp2_t a)
{
	sm9_fp2_conjugate(r, a);
}

// beta   = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
// alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
// alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333
// alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686
static const sm9_fp2_t SM9_BETA = {{0xda24d011, 0xf5b21fd3, 0x06dc5177, 0x9f9d4118, 0xee0baf15, 0xf55acc93, 0xdc0a3f2c, 0x6c648de5}, {0}};
static const sm9_fp_t SM9_ALPHA1 = {0x377b698b, 0xa91d8354, 0x0ddd04ed, 0x47c5c86e, 0x9c086749, 0x843c6cfa, 0xe5720bdb, 0x3f23ea58};
static const sm9_fp_t SM9_ALPHA2 = {0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235, 0x02a3a6f2, 0xf3000000, 0x0,        0x0       };
static const sm9_fp_t SM9_ALPHA3 = {0xda24d011, 0xf5b21fd3, 0x06dc5177, 0x9f9d4118, 0xee0baf15, 0xf55acc93, 0xdc0a3f2c, 0x6c648de5};
static const sm9_fp_t SM9_ALPHA4 = {0x7be65333, 0xd5fc1196, 0x4f8b78f4, 0x78027235, 0x02a3a6f2, 0xf3000000, 0x0,        0x0       };
static const sm9_fp_t SM9_ALPHA5 = {0xa2a96686, 0x4c949c7f, 0xf8ff4c8a, 0x57d778a9, 0x520347cc, 0x711e5f99, 0xf6983351, 0x2d40a38c};
static const sm9_fp2_t SM9_MONT_BETA  = {{0x3ee72529, 0x39b4ef0f, 0x08582782, 0xdb043bf5, 0x54ac91e3, 0xb8554ab0, 0x5498cab5, 0x9848eec2}, {0}};
static const sm9_fp_t SM9_MONT_ALPHA1   = {0x4575299f, 0x1a98dfbd, 0x245c54fd, 0x9ec8547b, 0x13df846c, 0xf51f5eac, 0xd5a16393, 0x9ef74015};
static const sm9_fp_t SM9_MONT_ALPHA2   = {0xce4736ca, 0xb626197d, 0x57ed0186, 0x08296b35, 0xfd91512a, 0x9c705db2, 0x8601c992, 0x1c753e74};
static const sm9_fp_t SM9_MONT_ALPHA3   = {0x3ee72529, 0x39b4ef0f, 0x08582782, 0xdb043bf5, 0x54ac91e3, 0xb8554ab0, 0x5498cab5, 0x9848eec2};
static const sm9_fp_t SM9_MONT_ALPHA4   = {0x94e9c1c4, 0x81054fcd, 0x8ce2df3e, 0x4c0e91cb, 0xe8aedfb4, 0x4877b452, 0x8b491776, 0x88f53e74};
static const sm9_fp_t SM9_MONT_ALPHA5   = {0xdcc34107, 0x048baa79, 0xfe76c161, 0x5e2e7ac4, 0x365bd4bc, 0x99399754, 0x819b0e13, 0xaf91aeac};


void sm9_fp4_frobenius(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_conjugate(r[0], a[0]);
	sm9_fp2_conjugate(r[1], a[1]);
	// sm9_fp2_mul(r[1], r[1], SM9_BETA);
	sm9_fp2_mul(r[1], r[1], SM9_MONT_BETA);
}

void sm9_fp4_conjugate(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_copy(r[0], a[0]);
	sm9_fp2_neg(r[1], a[1]);
}

void sm9_fp4_frobenius2(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp4_conjugate(r, a);
}

void sm9_fp4_frobenius3(sm9_fp4_t r, const sm9_fp4_t a)
{
	sm9_fp2_conjugate(r[0], a[0]);
	sm9_fp2_conjugate(r[1], a[1]);
	// sm9_fp2_mul(r[1], r[1], SM9_BETA);
	sm9_fp2_mul(r[1], r[1], SM9_MONT_BETA);
	sm9_fp2_neg(r[1], r[1]);
}

void sm9_fp12_frobenius(sm9_fp12_t r, const sm9_fp12_t x)
{
	const sm9_fp2_t *xa = x[0];
	const sm9_fp2_t *xb = x[1];
	const sm9_fp2_t *xc = x[2];
	sm9_fp4_t ra;
	sm9_fp4_t rb;
	sm9_fp4_t rc;

	sm9_fp2_conjugate(ra[0], xa[0]);
	sm9_fp2_conjugate(ra[1], xa[1]);
	sm9_fp2_mul_fp(ra[1], ra[1], SM9_MONT_ALPHA3);
	// sm9_fp2_mul_fp(ra[1], ra[1], SM9_ALPHA3);

	sm9_fp2_conjugate(rb[0], xb[0]);
	sm9_fp2_mul_fp(rb[0], rb[0], SM9_MONT_ALPHA1);
	// sm9_fp2_mul_fp(rb[0], rb[0], SM9_ALPHA1);
	sm9_fp2_conjugate(rb[1], xb[1]);
	sm9_fp2_mul_fp(rb[1], rb[1], SM9_MONT_ALPHA4);
	// sm9_fp2_mul_fp(rb[1], rb[1], SM9_ALPHA4);

	sm9_fp2_conjugate(rc[0], xc[0]);
	sm9_fp2_mul_fp(rc[0], rc[0], SM9_MONT_ALPHA2);
	// sm9_fp2_mul_fp(rc[0], rc[0], SM9_ALPHA2);
	sm9_fp2_conjugate(rc[1], xc[1]);
	sm9_fp2_mul_fp(rc[1], rc[1], SM9_MONT_ALPHA5);
	// sm9_fp2_mul_fp(rc[1], rc[1], SM9_ALPHA5);

	sm9_fp12_set(r, ra, rb, rc);
}

void sm9_fp12_frobenius2(sm9_fp12_t r, const sm9_fp12_t x)
{
	sm9_fp4_t a;
	sm9_fp4_t b;
	sm9_fp4_t c;

	sm9_fp4_conjugate(a, x[0]);
	sm9_fp4_conjugate(b, x[1]);
	sm9_fp4_mul_fp(b, b, SM9_MONT_ALPHA2);
	// sm9_fp4_mul_fp(b, b, SM9_ALPHA2);
	sm9_fp4_conjugate(c, x[2]);
	sm9_fp4_mul_fp(c, c, SM9_MONT_ALPHA4);
	// sm9_fp4_mul_fp(c, c, SM9_ALPHA4);

	sm9_fp4_copy(r[0], a);
	sm9_fp4_copy(r[1], b);
	sm9_fp4_copy(r[2], c);
}

void sm9_fp12_frobenius3(sm9_fp12_t r, const sm9_fp12_t x)
{
	const sm9_fp2_t *xa = x[0];
	const sm9_fp2_t *xb = x[1];
	const sm9_fp2_t *xc = x[2];
	sm9_fp4_t ra;
	sm9_fp4_t rb;
	sm9_fp4_t rc;

	sm9_fp2_conjugate(ra[0], xa[0]);
	sm9_fp2_conjugate(ra[1], xa[1]);
	sm9_fp2_mul(ra[1], ra[1], SM9_MONT_BETA);
	// sm9_fp2_mul(ra[1], ra[1], SM9_BETA);
	sm9_fp2_neg(ra[1], ra[1]);

	sm9_fp2_conjugate(rb[0], xb[0]);
	sm9_fp2_mul(rb[0], rb[0], SM9_MONT_BETA);
	// sm9_fp2_mul(rb[0], rb[0], SM9_BETA);
	sm9_fp2_conjugate(rb[1], xb[1]);

	sm9_fp2_conjugate(rc[0], xc[0]);
	sm9_fp2_neg(rc[0], rc[0]);
	sm9_fp2_conjugate(rc[1], xc[1]);
	sm9_fp2_mul(rc[1], rc[1], SM9_MONT_BETA);
	// sm9_fp2_mul(rc[1], rc[1], SM9_BETA);

	sm9_fp4_copy(r[0], ra);
	sm9_fp4_copy(r[1], rb);
	sm9_fp4_copy(r[2], rc);
}

void sm9_fp12_frobenius6(sm9_fp12_t r, const sm9_fp12_t x)
{
	sm9_fp4_t a;
	sm9_fp4_t b;
	sm9_fp4_t c;

	sm9_fp4_copy(a, x[0]);
	sm9_fp4_copy(b, x[1]);
	sm9_fp4_copy(c, x[2]);

	sm9_fp4_conjugate(a, a);
	sm9_fp4_conjugate(b, b);
	sm9_fp4_neg(b, b);
	sm9_fp4_conjugate(c, c);

	sm9_fp4_copy(r[0], a);
	sm9_fp4_copy(r[1], b);
	sm9_fp4_copy(r[2], c);
}



void sm9_point_from_hex(SM9_POINT *R, const char hex[65 * 2])
{
	sm9_bn_from_hex(R->X, hex);
	sm9_fp_to_mont(R->X, R->X);
	sm9_bn_from_hex(R->Y, hex + 65);
	sm9_fp_to_mont(R->Y, R->Y);
	// sm9_bn_set_one(R->Z);
	sm9_fp_copy(R->Z, SM9_MONT_ONE);
}

int sm9_point_is_at_infinity(const SM9_POINT *P) {
	return sm9_fp_is_zero(P->Z);
}

void sm9_point_set_infinity(SM9_POINT *R) {
	sm9_fp_set_mont_one(R->X);
	sm9_fp_set_mont_one(R->Y);
	sm9_fp_set_zero(R->Z);
}

void sm9_point_copy(SM9_POINT *R, const SM9_POINT *P)
{
	*R = *P;
}

void sm9_point_get_xy(const SM9_POINT *P, sm9_fp_t x, sm9_fp_t y)
{
	sm9_fp_t z_inv;

	assert(!sm9_fp_is_zero(P->Z));

	if (sm9_fp_is_mont_one(P->Z)) {
		// sm9_fp_copy(x, P->X);
		// sm9_fp_copy(y, P->Y);
		sm9_fp_from_mont(x, P->X);
		sm9_fp_from_mont(y, P->Y);
		return;
	}

	sm9_fp_mont_inv(z_inv, P->Z);
	if (y)
		sm9_fp_mont_mul(y, P->Y, z_inv);
	sm9_fp_mont_sqr(z_inv, z_inv);
	sm9_fp_mont_mul(x, P->X, z_inv);
	sm9_fp_from_mont(x, x);
	if (y) {
		sm9_fp_mont_mul(y, y, z_inv);
		sm9_fp_from_mont(y, y);
	}
}

int sm9_point_equ(const SM9_POINT *P, const SM9_POINT *Q)
{
	sm9_fp_t t1, t2, t3, t4;
	sm9_fp_mont_sqr(t1, P->Z);
	sm9_fp_mont_sqr(t2, Q->Z);
	sm9_fp_mont_mul(t3, P->X, t2);
	sm9_fp_mont_mul(t4, Q->X, t1);
	if (!sm9_fp_equ(t3, t4)) {
		return 0;
	}
	sm9_fp_mont_mul(t1, t1, P->Z);
	sm9_fp_mont_mul(t2, t2, Q->Z);
	sm9_fp_mont_mul(t3, P->Y, t2);
	sm9_fp_mont_mul(t4, Q->Y, t1);
	return sm9_fp_equ(t3, t4);
}

int sm9_point_is_on_curve(const SM9_POINT *P)
{
	sm9_fp_t t0, t1, t2;
	if (sm9_fp_is_mont_one(P->Z)) {
		sm9_fp_mont_sqr(t0, P->Y);
		sm9_fp_mont_sqr(t1, P->X);
		sm9_fp_mont_mul(t1, t1, P->X);
		// sm9_fp_add(t1, t1, SM9_FIVE);
		sm9_fp_add(t1, t1, SM9_MONT_FIVE);
	} else {
		sm9_fp_mont_sqr(t0, P->X);
		sm9_fp_mont_mul(t0, t0, P->X);
		sm9_fp_mont_sqr(t1, P->Z);
		sm9_fp_mont_sqr(t2, t1);
		sm9_fp_mont_mul(t1, t1, t2);
		sm9_fp_mont_mul(t1, t1, SM9_MONT_FIVE);
		sm9_fp_add(t1, t0, t1);
		sm9_fp_mont_sqr(t0, P->Y);
	}
	if (sm9_fp_equ(t0, t1) != 1) {
		error_print();
		return 0;
	}
	return 1;
}

void sm9_point_dbl(SM9_POINT *R, const SM9_POINT *P)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	sm9_fp_t X3, Y3, Z3, T1, T2, T3;

	if (sm9_point_is_at_infinity(P)) {
		sm9_point_copy(R, P);
		return;
	}

	sm9_fp_mont_sqr(T2, X1);
	sm9_fp_tri(T2, T2);
	sm9_fp_dbl(Y3, Y1);
	sm9_fp_mont_mul(Z3, Y3, Z1);
	sm9_fp_mont_sqr(Y3, Y3);
	sm9_fp_mont_mul(T3, Y3, X1);
	sm9_fp_mont_sqr(Y3, Y3);
	sm9_fp_div2(Y3, Y3);
	sm9_fp_mont_sqr(X3, T2);
	sm9_fp_dbl(T1, T3);
	sm9_fp_sub(X3, X3, T1);
	sm9_fp_sub(T1, T3, X3);
	sm9_fp_mont_mul(T1, T1, T2);
	sm9_fp_sub(Y3, T1, Y3);

	sm9_fp_copy(R->X, X3);
	sm9_fp_copy(R->Y, Y3);
	sm9_fp_copy(R->Z, Z3);
}

void sm9_point_add(SM9_POINT *R, const SM9_POINT *P, const SM9_POINT *Q)
{
	if (sm9_point_is_at_infinity(Q)) {
		*R = *P;
		return;
	}
	if (sm9_point_is_at_infinity(P)) {
		*R = *Q;
		return;
	}

	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *X2 = Q->X;
	const uint64_t *Y2 = Q->Y;
	const uint64_t *Z2 = Q->Z;
	
	sm9_fp_t X3, Y3, Z3, T1, T2, U1, U2, S1, S2, H, I;

	sm9_fp_mont_sqr(T1, Z1);
	sm9_fp_mont_sqr(T2, Z2);
	sm9_fp_mont_mul(U1, X1, T2);
	sm9_fp_mont_mul(U2, X2, T1);
	sm9_fp_add(Z3, Z1, Z2);
	sm9_fp_mont_sqr(Z3, Z3);
	sm9_fp_sub(Z3, Z3, T1);
	sm9_fp_sub(Z3, Z3, T2);
	sm9_fp_mont_mul(T1, T1, Z1);
	sm9_fp_mont_mul(T2, T2, Z2);
	sm9_fp_mont_mul(S1, Y1, T2);
	sm9_fp_mont_mul(S2, Y2, T1);
	sm9_fp_sub(H, U2, U1);
	sm9_fp_sub(U2, S2, S1);
	if (sm9_fp_is_zero(H)) {
		if (sm9_fp_is_zero(U2)) {
			sm9_point_dbl(R, Q);
			return;
		} else {
			sm9_point_set_infinity(R);
			return;
		}
	}
	sm9_fp_mont_mul(Z3, Z3, H);
	sm9_fp_dbl(I, H);
	sm9_fp_mont_sqr(I, I);
	sm9_fp_mont_mul(H, H, I);
	sm9_fp_mont_mul(I, U1, I);
	sm9_fp_dbl(U2, U2);
	sm9_fp_mont_sqr(X3, U2);
	sm9_fp_sub(X3, H, X3);
	sm9_fp_tri(Y3, I);
	sm9_fp_add(X3, Y3, X3);
	sm9_fp_mont_mul(Y3, U2, X3);
	sm9_fp_mont_mul(S1, S1, H);
	sm9_fp_dbl(S1, S1);
	sm9_fp_sub(Y3, Y3, S1);
	sm9_fp_sub(X3, I, X3);

	sm9_fp_copy(R->X, X3);
	sm9_fp_copy(R->Y, Y3);
	sm9_fp_copy(R->Z, Z3);
	
	// sm9_fp_t x;
	// sm9_fp_t y;
	// sm9_point_get_xy(Q, x, y);

	// const uint64_t *X1 = P->X;
	// const uint64_t *Y1 = P->Y;
	// const uint64_t *Z1 = P->Z;
	// const uint64_t *x2 = x;
	// const uint64_t *y2 = y;
	// sm9_fp_t X3, Y3, Z3, T1, T2, T3, T4;

	// if (sm9_point_is_at_infinity(Q)) {
	// 	sm9_point_copy(R, P);
	// 	return;
	// }
	// if (sm9_point_is_at_infinity(P)) {
	// 	sm9_point_copy(R, Q);
	// 	return;
	// }

	// sm9_fp_mont_sqr(T1, Z1);
	// sm9_fp_mont_mul(T2, T1, Z1);
	// sm9_fp_mont_mul(T1, T1, x2);
	// sm9_fp_mont_mul(T2, T2, y2);
	// sm9_fp_sub(T1, T1, X1);
	// sm9_fp_sub(T2, T2, Y1);

	// if (sm9_fp_is_zero(T1)) {
	// 	if (sm9_fp_is_zero(T2)) {
	// 		sm9_point_dbl(R, Q);
	// 		return;
	// 	} else {
	// 		sm9_point_set_infinity(R);
	// 		return;
	// 	}
	// }

	// sm9_fp_mont_mul(Z3, Z1, T1);
	// sm9_fp_mont_sqr(T3, T1);
	// sm9_fp_mont_mul(T4, T3, T1);
	// sm9_fp_mont_mul(T3, T3, X1);
	// sm9_fp_dbl(T1, T3);
	// sm9_fp_mont_sqr(X3, T2);
	// sm9_fp_sub(X3, X3, T1);
	// sm9_fp_sub(X3, X3, T4);
	// sm9_fp_sub(T3, T3, X3);
	// sm9_fp_mont_mul(T3, T3, T2);
	// sm9_fp_mont_mul(T4, T4, Y1);
	// sm9_fp_sub(Y3, T3, T4);

	// sm9_fp_copy(R->X, X3);
	// sm9_fp_copy(R->Y, Y3);
	// sm9_fp_copy(R->Z, Z3);
}

void sm9_point_neg(SM9_POINT *R, const SM9_POINT *P)
{
	sm9_fp_copy(R->X, P->X);
	sm9_fp_neg(R->Y, P->Y);
	sm9_fp_copy(R->Z, P->Z);
}

void sm9_point_sub(SM9_POINT *R, const SM9_POINT *P, const SM9_POINT *Q)
{
	SM9_POINT _T, *T = &_T;
	sm9_point_neg(T, Q);
	sm9_point_add(R, P, T);
}

void sm9_point_dbl_x5(SM9_POINT *R, const SM9_POINT *A)

{
	sm9_point_dbl(R, A);
	sm9_point_dbl(R, R);
	sm9_point_dbl(R, R);
	sm9_point_dbl(R, R);
	sm9_point_dbl(R, R);
}

void sm9_point_mul(SM9_POINT *R, const sm9_bn_t k, const SM9_POINT *P)
{
	uint64_t window_size = 5;
	SM9_POINT T[16];
	int R_infinity = 1;
	int n = (int)((256 + window_size - 1)/window_size);
	int i;

	// T[i] = (i + 1) * P
	T[0] = *P;

	sm9_point_dbl(&T[2-1], &T[1-1]);
	sm9_point_dbl(&T[4-1], &T[2-1]);
	sm9_point_dbl(&T[8-1], &T[4-1]);
	sm9_point_dbl(&T[16-1], &T[8-1]);
	sm9_point_add(&T[3-1], &T[2-1], P);
	sm9_point_dbl(&T[6-1], &T[3-1]);
	sm9_point_dbl(&T[12-1], &T[6-1]);
	sm9_point_add(&T[5-1], &T[3-1], &T[2-1]);
	sm9_point_dbl(&T[10-1], &T[5-1]);
	sm9_point_add(&T[7-1], &T[4-1], &T[3-1]);
	sm9_point_dbl(&T[14-1], &T[7-1]);
	sm9_point_add(&T[9-1], &T[4-1], &T[5-1]);
	sm9_point_add(&T[11-1], &T[6-1], &T[5-1]);
	sm9_point_add(&T[13-1], &T[7-1], &T[6-1]);
	sm9_point_add(&T[15-1], &T[8-1], &T[7-1]);


	for (i = n - 1; i >= 0; i--) {
		int booth = sm9_get_booth(k, window_size, i);

		if (R_infinity) {
			if (booth != 0) {
				*R = T[booth - 1];
				R_infinity = 0;
			}
		} else {
			sm9_point_dbl_x5(R, R);

			if (booth > 0) {
				sm9_point_add(R, R, &T[booth - 1]);
			} else if (booth < 0) {
				sm9_point_sub(R, R, &T[-booth - 1]);
			}
		}
	}

	if (R_infinity) {
		memset(R, 0, sizeof(*R));
	}
	// char kbits[257];
	// SM9_POINT _Q, *Q = &_Q;
	// int i;
	//
	// sm9_bn_to_bits(k, kbits);
	// sm9_point_set_infinity(Q);
	// for (i = 0; i < 256; i++) {
	// 	sm9_point_dbl(Q, Q);
	// 	if (kbits[i] == '1') {
	// 		sm9_point_add(Q, Q, P);
	// 	}
	// }
	// sm9_point_copy(R, Q);
}

void sm9_point_mul_generator(SM9_POINT *R, const sm9_bn_t k)
{
	// sm9_point_mul(R, k, SM9_P1);
	sm9_point_mul(R, k, SM9_MONT_P1);
}


int sm9_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_POINT *P)
{
	uint8_t buf[65];
	sm9_point_to_uncompressed_octets(P, buf);
	format_bytes(fp, fmt, ind, label, buf, sizeof(buf));
	return 1;
}

int sm9_twist_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_TWIST_POINT *P)
{
	uint8_t buf[129];
	sm9_twist_point_to_uncompressed_octets(P, buf);
	format_bytes(fp, fmt, ind, label, buf, sizeof(buf));
	return 1;
}

void sm9_twist_point_from_hex(SM9_TWIST_POINT *R, const char hex[65 * 4])
{
	sm9_fp2_from_hex(R->X, hex);
	sm9_fp2_from_hex(R->Y, hex + 65 * 2);
	sm9_fp2_set_mont_one(R->Z);
}

int sm9_twist_point_is_at_infinity(const SM9_TWIST_POINT *P)
{
	return sm9_fp2_is_zero(P->Z);
}

void sm9_twist_point_set_infinity(SM9_TWIST_POINT *R)
{
	sm9_fp2_set_mont_one(R->X);
	sm9_fp2_set_mont_one(R->Y);
	sm9_fp2_set_zero(R->Z);
}

void sm9_twist_point_get_xy(const SM9_TWIST_POINT *P, sm9_fp2_t x, sm9_fp2_t y)
{
	sm9_fp2_t z_inv;

	assert(!sm9_fp2_is_zero(P->Z));

	if (sm9_fp2_is_one(P->Z)) {
		sm9_fp2_copy(x, P->X);
		sm9_fp2_copy(y, P->Y);
	}

	sm9_fp2_inv(z_inv, P->Z);
	if (y)
		sm9_fp2_mul(y, P->Y, z_inv);
	sm9_fp2_sqr(z_inv, z_inv);
	sm9_fp2_mul(x, P->X, z_inv);
	if (y)
		sm9_fp2_mul(y, y, z_inv);
}


int sm9_twist_point_equ(const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q)
{
	sm9_fp2_t t1, t2, t3, t4;

	sm9_fp2_sqr(t1, P->Z);
	sm9_fp2_sqr(t2, Q->Z);
	sm9_fp2_mul(t3, P->X, t2);
	sm9_fp2_mul(t4, Q->X, t1);
	if (!sm9_fp2_equ(t3, t4)) {
		return 0;
	}
	sm9_fp2_mul(t1, t1, P->Z);
	sm9_fp2_mul(t2, t2, Q->Z);
	sm9_fp2_mul(t3, P->Y, t2);
	sm9_fp2_mul(t4, Q->Y, t1);
	return sm9_fp2_equ(t3, t4);
}

int sm9_twist_point_is_on_curve(const SM9_TWIST_POINT *P)
{
	sm9_fp2_t t0, t1, t2;

	if (sm9_fp2_is_one(P->Z)) {
		sm9_fp2_sqr(t0, P->Y);
		sm9_fp2_sqr(t1, P->X);
		sm9_fp2_mul(t1, t1, P->X);
		// sm9_fp2_add(t1, t1, SM9_FP2_5U);
		sm9_fp2_add(t1, t1, SM9_FP2_MONT_5U);

	} else {
		sm9_fp2_sqr(t0, P->X);
		sm9_fp2_mul(t0, t0, P->X);
		sm9_fp2_sqr(t1, P->Z);
		sm9_fp2_sqr(t2, t1);
		sm9_fp2_mul(t1, t1, t2);
		// sm9_fp2_mul(t1, t1, SM9_FP2_5U);
		sm9_fp2_mul(t1, t1, SM9_FP2_MONT_5U);
		sm9_fp2_add(t1, t0, t1);
		sm9_fp2_sqr(t0, P->Y);
	}

	return sm9_fp2_equ(t0, t1);
}

void sm9_twist_point_neg(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P)
{
	sm9_fp2_copy(R->X, P->X);
	sm9_fp2_neg(R->Y, P->Y);
	sm9_fp2_copy(R->Z, P->Z);
}

void sm9_twist_point_dbl(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P)
{
	const sm9_fp_t *X1 = P->X;
	const sm9_fp_t *Y1 = P->Y;
	const sm9_fp_t *Z1 = P->Z;
	sm9_fp2_t X3, Y3, Z3, T1, T2, T3;

	if (sm9_twist_point_is_at_infinity(P)) {
		sm9_twist_point_copy(R, P);
		return;
	}
	sm9_fp2_sqr(T2, X1);
	sm9_fp2_tri(T2, T2);
	sm9_fp2_dbl(Y3, Y1);
	sm9_fp2_mul(Z3, Y3, Z1);
	sm9_fp2_sqr(Y3, Y3);
	sm9_fp2_mul(T3, Y3, X1);
	sm9_fp2_sqr(Y3, Y3);
	sm9_fp2_div2(Y3, Y3);
	sm9_fp2_sqr(X3, T2);
	sm9_fp2_dbl(T1, T3);
	sm9_fp2_sub(X3, X3, T1);
	sm9_fp2_sub(T1, T3, X3);
	sm9_fp2_mul(T1, T1, T2);
	sm9_fp2_sub(Y3, T1, Y3);

	sm9_fp2_copy(R->X, X3);
	sm9_fp2_copy(R->Y, Y3);
	sm9_fp2_copy(R->Z, Z3);
}

void sm9_twist_point_add(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q)
{
	const sm9_fp_t *X1 = P->X;
	const sm9_fp_t *Y1 = P->Y;
	const sm9_fp_t *Z1 = P->Z;
	const sm9_fp_t *x2 = Q->X;
	const sm9_fp_t *y2 = Q->Y;
	sm9_fp2_t X3, Y3, Z3, T1, T2, T3, T4;

	if (sm9_twist_point_is_at_infinity(Q)) {
		sm9_twist_point_copy(R, P);
		return;
	}
	if (sm9_twist_point_is_at_infinity(P)) {
		sm9_twist_point_copy(R, Q);
		return;
	}

	sm9_fp2_sqr(T1, Z1);
	sm9_fp2_mul(T2, T1, Z1);
	sm9_fp2_mul(T1, T1, x2);
	sm9_fp2_mul(T2, T2, y2);
	sm9_fp2_sub(T1, T1, X1);
	sm9_fp2_sub(T2, T2, Y1);
	if (sm9_fp2_is_zero(T1)) {
		if (sm9_fp2_is_zero(T2)) {
			sm9_twist_point_dbl(R, Q);
			return;
		} else {
			sm9_twist_point_set_infinity(R);
			return;
		}
	}
	sm9_fp2_mul(Z3, Z1, T1);
	sm9_fp2_sqr(T3, T1);
	sm9_fp2_mul(T4, T3, T1);
	sm9_fp2_mul(T3, T3, X1);
	sm9_fp2_dbl(T1, T3);
	sm9_fp2_sqr(X3, T2);
	sm9_fp2_sub(X3, X3, T1);
	sm9_fp2_sub(X3, X3, T4);
	sm9_fp2_sub(T3, T3, X3);
	sm9_fp2_mul(T3, T3, T2);
	sm9_fp2_mul(T4, T4, Y1);
	sm9_fp2_sub(Y3, T3, T4);

	sm9_fp2_copy(R->X, X3);
	sm9_fp2_copy(R->Y, Y3);
	sm9_fp2_copy(R->Z, Z3);
}

void sm9_twist_point_sub(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q)
{
	SM9_TWIST_POINT _T, *T = &_T;
	sm9_twist_point_neg(T, Q);
	sm9_twist_point_add_full(R, P, T);
}

void sm9_twist_point_add_full(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q)
{
	const sm9_fp_t *X1 = P->X;
	const sm9_fp_t *Y1 = P->Y;
	const sm9_fp_t *Z1 = P->Z;
	const sm9_fp_t *X2 = Q->X;
	const sm9_fp_t *Y2 = Q->Y;
	const sm9_fp_t *Z2 = Q->Z;
	sm9_fp2_t T1, T2, T3, T4, T5, T6, T7, T8;

	if (sm9_twist_point_is_at_infinity(Q)) {
		sm9_twist_point_copy(R, P);
		return;
	}
	if (sm9_twist_point_is_at_infinity(P)) {
		sm9_twist_point_copy(R, Q);
		return;
	}

	sm9_fp2_sqr(T1, Z1);
	sm9_fp2_sqr(T2, Z2);
	sm9_fp2_mul(T3, X2, T1);
	sm9_fp2_mul(T4, X1, T2);
	sm9_fp2_add(T5, T3, T4);
	sm9_fp2_sub(T3, T3, T4);
	sm9_fp2_mul(T1, T1, Z1);
	sm9_fp2_mul(T1, T1, Y2);
	sm9_fp2_mul(T2, T2, Z2);
	sm9_fp2_mul(T2, T2, Y1);
	sm9_fp2_add(T6, T1, T2);
	sm9_fp2_sub(T1, T1, T2);

	if (sm9_fp2_is_zero(T1) && sm9_fp2_is_zero(T3)) {
		sm9_twist_point_dbl(R, P);
		return;
	}
	if (sm9_fp2_is_zero(T1) && sm9_fp2_is_zero(T6)) {
		sm9_twist_point_set_infinity(R);
		return;
	}

	sm9_fp2_sqr(T6, T1);
	sm9_fp2_mul(T7, T3, Z1);
	sm9_fp2_mul(T7, T7, Z2);
	sm9_fp2_sqr(T8, T3);
	sm9_fp2_mul(T5, T5, T8);
	sm9_fp2_mul(T3, T3, T8);
	sm9_fp2_mul(T4, T4, T8);
	sm9_fp2_sub(T6, T6, T5);
	sm9_fp2_sub(T4, T4, T6);
	sm9_fp2_mul(T1, T1, T4);
	sm9_fp2_mul(T2, T2, T3);
	sm9_fp2_sub(T1, T1, T2);

	sm9_fp2_copy(R->X, T6);
	sm9_fp2_copy(R->Y, T1);
	sm9_fp2_copy(R->Z, T7);
}

void sm9_twist_point_mul(SM9_TWIST_POINT *R, const sm9_bn_t k, const SM9_TWIST_POINT *P)
{
	SM9_TWIST_POINT _Q, *Q = &_Q;
	char kbits[256];
	int i;

	sm9_bn_to_bits(k, kbits);
	sm9_twist_point_set_infinity(Q);
	for (i = 0; i < 256; i++) {
		sm9_twist_point_dbl(Q, Q);
		if (kbits[i] == '1') {
			sm9_twist_point_add_full(Q, Q, P);
		}
	}
	sm9_twist_point_copy(R, Q);
}

void sm9_twist_point_mul_generator(SM9_TWIST_POINT *R, const sm9_bn_t k)
{
	// sm9_twist_point_mul(R, k, SM9_P2);
	sm9_twist_point_mul(R, k, SM9_MONT_P2);
}

// g_line = lw[0] + lw[1] * w^2 + lw[2] * w^3, R = 2P
void sm9_eval_g_tangent(SM9_TWIST_POINT *R, sm9_fp2_t lw[3],
	const SM9_TWIST_POINT *P, const SM9_AFFINE_POINT *Q)
{
	const sm9_fp_t *X1 = P->X;
	const sm9_fp_t *Y1 = P->Y;
	const sm9_fp_t *Z1 = P->Z;

	sm9_fp2_t X3, Y3, Z3, A, B, C, D, T1;

	sm9_fp2_sqr(T1, Z1);
	sm9_fp2_sqr(A, X1);
	sm9_fp2_sqr(B, Y1);
	sm9_fp2_sqr(C, B);
	sm9_fp2_add(D, X1, B);
	sm9_fp2_sqr(D, D);
	sm9_fp2_sub(D, D, A);
	sm9_fp2_sub(D, D, C);
	sm9_fp2_dbl(D, D);
	sm9_fp2_add(Z3, Y1, Z1);
	sm9_fp2_sqr(Z3, Z3);
	sm9_fp2_sub(Z3, Z3, B);
	sm9_fp2_sub(Z3, Z3, T1);
	sm9_fp2_dbl(lw[0], B);
	sm9_fp2_dbl(lw[0], lw[0]);
	sm9_fp2_add(lw[0], lw[0], A);
	sm9_fp2_tri(A, A);
	sm9_fp2_sqr(B, A);
	sm9_fp2_dbl(X3, D);
	sm9_fp2_sub(X3, B, X3);
	sm9_fp2_add(lw[0], lw[0], B);
	sm9_fp2_sub(Y3, D, X3);
	sm9_fp2_mul(Y3, Y3, A);
	sm9_fp2_dbl(C, C);
	sm9_fp2_dbl(C, C);
	sm9_fp2_dbl(C, C);
	sm9_fp2_sub(Y3, Y3, C);
	sm9_fp2_mul(lw[2], Z3, T1);
	sm9_fp2_dbl(lw[2], lw[2]);
	sm9_fp2_mul(lw[1], A, T1);
	sm9_fp2_dbl(lw[1], lw[1]);
	sm9_fp2_neg(lw[1], lw[1]);
	sm9_fp2_add(A, X1, A);
	sm9_fp2_sqr(A, A);
	sm9_fp2_sub(lw[0], A, lw[0]);
	sm9_fp2_mul_fp(lw[1], lw[1], Q->X);
	sm9_fp2_mul_fp(lw[2], lw[2], Q->Y);

	sm9_fp2_copy(R->X, X3);
	sm9_fp2_copy(R->Y, Y3);
	sm9_fp2_copy(R->Z, Z3);
}

// void sm9_eval_g_tangent(sm9_fp12_t num, sm9_fp12_t den, const SM9_TWIST_POINT *P, const SM9_POINT *Q)
// {
// 	sm9_fp_t x;
// 	sm9_fp_t y;
// 	sm9_point_get_xy(Q, x, y);

// 	const sm9_fp_t *XP = P->X;
// 	const sm9_fp_t *YP = P->Y;
// 	const sm9_fp_t *ZP = P->Z;
// 	const uint64_t *xQ = x;
// 	const uint64_t *yQ = y;

// 	sm9_fp_t *a0 = num[0][0];
// 	sm9_fp_t *a1 = num[0][1];
// 	sm9_fp_t *a4 = num[2][0];
// 	sm9_fp_t *b1 = den[0][1];

// 	sm9_fp2_t t0;
// 	sm9_fp2_t t1;
// 	sm9_fp2_t t2;


// 	sm9_fp12_set_zero(num);
// 	sm9_fp12_set_zero(den);

// 	sm9_fp2_sqr(t0, ZP);
// 	sm9_fp2_mul(t1, t0, ZP);
// 	sm9_fp2_mul(b1, t1, YP);

// 	sm9_fp2_mul_fp(t2, b1, yQ);
// 	sm9_fp2_neg(a1, t2);

// 	sm9_fp2_sqr(t1, XP);
// 	sm9_fp2_mul(t0, t0, t1);
// 	sm9_fp2_mul_fp(t0, t0, xQ);
// 	sm9_fp2_tri(t0, t0);
// 	sm9_fp2_div2(a4, t0);

// 	sm9_fp2_mul(t1, t1, XP);
// 	sm9_fp2_tri(t1, t1);
// 	sm9_fp2_div2(t1, t1);
// 	sm9_fp2_sqr(t0, YP);
// 	sm9_fp2_sub(a0, t0, t1);
// }

// g_line = lw[0] + lw[1] * w^2 + lw[2] * w^3, R = P+T
void sm9_eval_g_line(SM9_TWIST_POINT *R, sm9_fp2_t lw[3], sm9_fp2_t pre[5],
	const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *T, const SM9_AFFINE_POINT *Q)
{
	const sm9_fp_t *X1 = P->X;
	const sm9_fp_t *Y1 = P->Y;
	const sm9_fp_t *Z1 = P->Z;
	const sm9_fp_t *X2 = T->X;
	const sm9_fp_t *Y2 = T->Y;
	const sm9_fp_t *Z2 = T->Z;

	sm9_fp2_t X3, Y3, Z3, T1, T2, A, B, C, D;

	sm9_fp2_sqr(T1, Z1);
	sm9_fp2_sqr(T2, Z2);
	sm9_fp2_add(Z3, Z1, Z2);
	sm9_fp2_sqr(Z3, Z3);
	sm9_fp2_sub(Z3, Z3, T1);
	sm9_fp2_sub(Z3, Z3, T2);
	sm9_fp2_mul(A, X1, T2);
	sm9_fp2_mul(B, X2, T1);
	sm9_fp2_mul(C, Y1, pre[1]);
	sm9_fp2_dbl(C, C);
	sm9_fp2_add(D, Y2, Z1);
	sm9_fp2_sqr(D, D);
	sm9_fp2_sub(D, D, pre[0]);
	sm9_fp2_sub(D, D, T1);
	sm9_fp2_mul(D, D, T1);
	sm9_fp2_sub(B, B, A);
	sm9_fp2_mul(Z3, Z3, B);
	sm9_fp2_dbl(T1, B);
	sm9_fp2_sqr(T1, T1);
	sm9_fp2_mul(X3, B, T1);
	sm9_fp2_mul(Y3, C, X3);
	sm9_fp2_mul(A, A, T1);
	sm9_fp2_sub(B, D, C);
	sm9_fp2_dbl(T2, A);
	sm9_fp2_add(X3, X3, T2);
	sm9_fp2_sqr(T2, B);
	sm9_fp2_sub(X3, T2, X3);
	sm9_fp2_sub(T2, A, X3);
	sm9_fp2_mul(T2, T2, B);
	sm9_fp2_sub(Y3, T2, Y3);
	sm9_fp2_mul(lw[2], Z3, pre[2]);
	sm9_fp2_mul(lw[1], B, pre[3]);
	sm9_fp2_mul(B, B, pre[4]);
	sm9_fp2_mul(lw[0], Y2, Z3);
	sm9_fp2_dbl(lw[0], lw[0]);
	sm9_fp2_sub(lw[0], B, lw[0]);

	sm9_fp2_copy(R->X, X3);
	sm9_fp2_copy(R->Y, Y3);
	sm9_fp2_copy(R->Z, Z3);
}

// void sm9_eval_g_line(sm9_fp12_t num, sm9_fp12_t den, const SM9_TWIST_POINT *T, const SM9_TWIST_POINT *P, const SM9_POINT *Q)
// {
// 	sm9_fp_t x;
// 	sm9_fp_t y;
// 	sm9_point_get_xy(Q, x, y);

// 	const sm9_fp_t *XT = T->X;
// 	const sm9_fp_t *YT = T->Y;
// 	const sm9_fp_t *ZT = T->Z;
// 	const sm9_fp_t *XP = P->X;
// 	const sm9_fp_t *YP = P->Y;
// 	const sm9_fp_t *ZP = P->Z;
// 	const uint64_t *xQ = x;
// 	const uint64_t *yQ = y;

// 	sm9_fp_t *a0 = num[0][0];
// 	sm9_fp_t *a1 = num[0][1];
// 	sm9_fp_t *a4 = num[2][0];
// 	sm9_fp_t *b1 = den[0][1];

// 	sm9_fp2_t T0, T1, T2, T3, T4;


// 	sm9_fp12_set_zero(num);
// 	sm9_fp12_set_zero(den);

// 	sm9_fp2_sqr(T0, ZP);
// 	sm9_fp2_mul(T1, T0, XT);
// 	sm9_fp2_mul(T0, T0, ZP);
// 	sm9_fp2_sqr(T2, ZT);
// 	sm9_fp2_mul(T3, T2, XP);
// 	sm9_fp2_mul(T2, T2, ZT);
// 	sm9_fp2_mul(T2, T2, YP);
// 	sm9_fp2_sub(T1, T1, T3);
// 	sm9_fp2_mul(T1, T1, ZT);
// 	sm9_fp2_mul(T1, T1, ZP);
// 	sm9_fp2_mul(T4, T1, T0);
// 	sm9_fp2_copy(b1, T4);
// 	sm9_fp2_mul(T1, T1, YP);
// 	sm9_fp2_mul(T3, T0, YT);
// 	sm9_fp2_sub(T3, T3, T2);
// 	sm9_fp2_mul(T0, T0, T3);
// 	sm9_fp2_mul_fp(T0, T0, xQ);
// 	sm9_fp2_copy(a4, T0);
// 	sm9_fp2_mul(T3, T3, XP);
// 	sm9_fp2_mul(T3, T3, ZP);
// 	sm9_fp2_sub(T1, T1, T3);
// 	sm9_fp2_copy(a0, T1);
// 	sm9_fp2_mul_fp(T2, T4, yQ);
// 	sm9_fp2_neg(T2, T2);
// 	sm9_fp2_copy(a1, T2);
// }

void sm9_eval_g_line_no_pre(SM9_TWIST_POINT *R, sm9_fp2_t lw[3],
	const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *T, const SM9_AFFINE_POINT *Q)
{
	const sm9_fp_t *X1 = P->X;
	const sm9_fp_t *Y1 = P->Y;
	const sm9_fp_t *Z1 = P->Z;
	const sm9_fp_t *X2 = T->X;
	const sm9_fp_t *Y2 = T->Y;
	const sm9_fp_t *Z2 = T->Z;

	sm9_fp2_t pre[5];
	sm9_fp2_sqr(pre[0], T->Y);
	sm9_fp2_mul(pre[4], T->X, T->Z);
	sm9_fp2_dbl(pre[4], pre[4]);
	sm9_fp2_sqr(pre[1], T->Z);
	sm9_fp2_mul(pre[1], pre[1], T->Z);
	sm9_fp2_mul_fp(pre[2], pre[1], Q->Y);
	sm9_fp2_dbl(pre[2], pre[2]);
	sm9_fp2_mul_fp(pre[3], pre[1], Q->X);
	sm9_fp2_dbl(pre[3], pre[3]);
	sm9_fp2_neg(pre[3], pre[3]);

	sm9_fp2_t X3, Y3, Z3, T1, T2, A, B, C, D;

	sm9_fp2_sqr(T1, Z1);
	sm9_fp2_sqr(T2, Z2);
	sm9_fp2_add(Z3, Z1, Z2);
	sm9_fp2_sqr(Z3, Z3);
	sm9_fp2_sub(Z3, Z3, T1);
	sm9_fp2_sub(Z3, Z3, T2);
	sm9_fp2_mul(A, X1, T2);
	sm9_fp2_mul(B, X2, T1);
	sm9_fp2_mul(C, Y1, pre[1]);
	sm9_fp2_dbl(C, C);
	sm9_fp2_add(D, Y2, Z1);
	sm9_fp2_sqr(D, D);
	sm9_fp2_sub(D, D, pre[0]);
	sm9_fp2_sub(D, D, T1);
	sm9_fp2_mul(D, D, T1);
	sm9_fp2_sub(B, B, A);
	sm9_fp2_mul(Z3, Z3, B);
	sm9_fp2_dbl(T1, B);
	sm9_fp2_sqr(T1, T1);
	sm9_fp2_mul(X3, B, T1);
	sm9_fp2_mul(Y3, C, X3);
	sm9_fp2_mul(A, A, T1);
	sm9_fp2_sub(B, D, C);
	sm9_fp2_dbl(T2, A);
	sm9_fp2_add(X3, X3, T2);
	sm9_fp2_sqr(T2, B);
	sm9_fp2_sub(X3, T2, X3);
	sm9_fp2_sub(T2, A, X3);
	sm9_fp2_mul(T2, T2, B);
	sm9_fp2_sub(Y3, T2, Y3);
	sm9_fp2_mul(lw[2], Z3, pre[2]);
	sm9_fp2_mul(lw[1], B, pre[3]);
	sm9_fp2_mul(B, B, pre[4]);
	sm9_fp2_mul(lw[0], Y2, Z3);
	sm9_fp2_dbl(lw[0], lw[0]);
	sm9_fp2_sub(lw[0], B, lw[0]);

	sm9_fp2_copy(R->X, X3);
	sm9_fp2_copy(R->Y, Y3);
	sm9_fp2_copy(R->Z, Z3);
}

void sm9_twist_point_pi1(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P)
{
	//const c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
	// const sm9_fp_t c = {
	// 	0x377b698b, 0xa91d8354, 0x0ddd04ed, 0x47c5c86e,
	// 	0x9c086749, 0x843c6cfa, 0xe5720bdb, 0x3f23ea58,
	// };

	// mont version
	const sm9_fp_t c = {
		0x4575299f, 0x1a98dfbd, 0x245c54fd, 0x9ec8547b,
		0x13df846c, 0xf51f5eac, 0xd5a16393, 0x9ef74015,
	};
	sm9_fp2_conjugate(R->X, P->X);
	sm9_fp2_conjugate(R->Y, P->Y);
	sm9_fp2_conjugate(R->Z, P->Z);
	sm9_fp2_mul_fp(R->Z, R->Z, c);

}

void sm9_twist_point_pi2(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P)
{
	//c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	// const sm9_fp_t c = {
	// 	0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235,
	// 	0x02a3a6f2, 0xf3000000, 0, 0,
	// };

	// mont version
	const sm9_fp_t c = {
		0xce4736ca, 0xb626197d, 0x57ed0186, 0x08296b35,
		0xfd91512a, 0x9c705db2, 0x8601c992, 0x1c753e74,
	};
	sm9_fp2_copy(R->X, P->X);
	sm9_fp2_copy(R->Y, P->Y);
	sm9_fp2_mul_fp(R->Z, P->Z, c);
}

void sm9_twist_point_neg_pi2(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P)
{
	// c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	// const sm9_fp_t c = {
	// 	0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235,
	// 	0x02a3a6f2, 0xf3000000, 0, 0,
	// };

	// mont version
	const sm9_fp_t c = {
		0xce4736ca, 0xb626197d, 0x57ed0186, 0x08296b35,
		0xfd91512a, 0x9c705db2, 0x8601c992, 0x1c753e74
	};
	sm9_fp2_copy(R->X, P->X);
	sm9_fp2_neg(R->Y, P->Y);
	sm9_fp2_mul_fp(R->Z, P->Z, c);
}


void sm9_final_exponent_hard_part(sm9_fp12_t r, const sm9_fp12_t f)
{
	// const sm9_bn_t lambda0 = {0x52998ccd, 0x3952b664, 0xdfb250a3, 0x5001a178, 0x01c26f4c, 0xa2000000, 0, 0};
	// const sm9_bn_t lambda1 = {0x45352360, 0x7951fcd9, 0xde21edb5, 0x5001a178, 0x01c26f4c, 0xa2000000, 0, 0};
	// const sm9_bn_t lambda2 = {0x45e71674, 0x3951fcd9, 0xde21edb6, 0x5001a178, 0x01c26f4c, 0xa2000000, 0, 0};
	// const sm9_bn_t lambda3 = {0x4535235f, 0x7951fcd9, 0xde21edb5, 0x5001a178, 0x01c26f4c, 0xa2000000, 0, 0};

	// sm9_fp12_t t0, t1;
	// sm9_fp12_pow(t0, f, lambda0);
	// sm9_fp12_pow(t1, f, lambda1);
	// sm9_fp12_frobenius(t1, t1);
	// sm9_fp12_mul(t1, t1, t0);
	// sm9_fp12_pow(t0, f, lambda2);
	// sm9_fp12_frobenius2(t0, t0);
	// sm9_fp12_mul(t1, t1, t0);
	// sm9_fp12_pow(t0, f, lambda3);
	// sm9_fp12_frobenius3(t0, t0);
	// sm9_fp12_mul(t1, t1, t0);
	// sm9_fp12_copy(r, t1);

	// sm9_print_bn("r[0][0][0]", r[0][0][0]);
	// sm9_print_bn("r[0][0][1]", r[0][0][1]);
	// sm9_print_bn("r[0][1][0]", r[0][1][0]);
	// sm9_print_bn("r[0][1][1]", r[0][1][1]);
	// sm9_print_bn("r[1][0][0]", r[1][0][0]);
	// sm9_print_bn("r[1][0][1]", r[1][0][1]);
	// sm9_print_bn("r[1][1][0]", r[1][1][0]);
	// sm9_print_bn("r[1][1][1]", r[1][1][1]);
	// sm9_print_bn("r[2][0][0]", r[2][0][0]);
	// sm9_print_bn("r[2][0][1]", r[2][0][1]);
	// sm9_print_bn("r[2][1][0]", r[2][1][0]);
	// sm9_print_bn("r[2][1][1]", r[2][1][1]);

	// a2 = 0xd8000000019062ed0000b98b0cb27659;
	// a3 = 0x2400000000215d941
	const sm9_bn_t a2 = {0xcb27659, 0x0000b98b, 0x019062ed, 0xd8000000, 0, 0, 0, 0};
	const sm9_bn_t a3 = {0x215d941, 0x40000000, 0x2, 0, 0, 0, 0, 0};
	const sm9_bn_t nine = {9,0,0,0,0,0,0,0};
	sm9_fp12_t t0, t1, t2, t3;
	
	sm9_fp12_pow(t0, f, a3);
	sm9_fp12_inv(t0, t0);
	sm9_fp12_frobenius(t1, t0);
	sm9_fp12_mul(t1, t0, t1);
	
	sm9_fp12_mul(t0, t0, t1);
	sm9_fp12_frobenius(t2, f);
	sm9_fp12_mul(t3, t2, f);
	sm9_fp12_pow(t3, t3, nine);
	
	sm9_fp12_mul(t0, t0, t3);
	sm9_fp12_sqr(t3, f);
	sm9_fp12_sqr(t3, t3);
	sm9_fp12_mul(t0, t0, t3);
	sm9_fp12_sqr(t2, t2);
	sm9_fp12_mul(t2, t2, t1);
	sm9_fp12_frobenius2(t1, f);
	sm9_fp12_mul(t1, t1, t2);
	
	sm9_fp12_pow(t2, t1, a2);
	sm9_fp12_mul(t0, t2, t0);
	sm9_fp12_frobenius3(t1, f);
	sm9_fp12_mul(t1, t1, t0);
	
	sm9_fp12_copy(r, t1);
}

void sm9_final_exponent(sm9_fp12_t r, const sm9_fp12_t f)
{
	sm9_fp12_t t0;
	sm9_fp12_t t1;

	sm9_fp12_frobenius6(t0, f);
	sm9_fp12_inv(t1, f);
	sm9_fp12_mul(t0, t0, t1);
	sm9_fp12_frobenius2(t1, t0);
	sm9_fp12_mul(t0, t0, t1);
	sm9_final_exponent_hard_part(t0, t0);

	sm9_fp12_copy(r, t0);
}

// Multiplication with lw[0] + lw[1] * w^2 + lw[2] * w^3
void sm9_fp12_line_mul(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp2_t lw[3])
{
	sm9_fp4_t r0, r1, r2;
	sm9_fp2_t t;

	sm9_fp4_t lw4;
	sm9_fp2_copy(lw4[0], lw[0]);
	sm9_fp2_copy(lw4[1], lw[2]);

	sm9_fp4_mul(r0, a[0], lw4);
	sm9_fp4_mul(r1, a[1], lw4);
	sm9_fp4_mul(r2, a[2], lw4);

	sm9_fp2_mul  (t, a[0][0], lw[1]);
	sm9_fp2_add  (r2[0], r2[0], t);
	sm9_fp2_mul  (t, a[0][1], lw[1]);
	sm9_fp2_add  (r2[1], r2[1], t);
	sm9_fp2_mul  (t, a[1][0], lw[1]);
	sm9_fp2_add  (r0[1], r0[1], t);
	sm9_fp2_mul_u(t, a[1][1], lw[1]);
	sm9_fp2_add  (r0[0], r0[0], t);
	sm9_fp2_mul  (t, a[2][0], lw[1]);
	sm9_fp2_add  (r1[1], r1[1], t);
	sm9_fp2_mul_u(t, a[2][1], lw[1]);
	sm9_fp2_add  (r1[0], r1[0], t);

	sm9_fp4_copy(r[0], r0);
	sm9_fp4_copy(r[1], r1);
	sm9_fp4_copy(r[2], r2);
}

void sm9_point_to_affine(SM9_AFFINE_POINT *Q, const SM9_POINT *P)
{
	sm9_fp_t z_inv;

	assert(!sm9_fp_is_zero(P->Z));

	if (sm9_fp_equ(P->Z, SM9_MONT_ONE)) {
		sm9_fp_copy(Q->X, P->X);
		sm9_fp_copy(Q->Y, P->Y);
		return;
	}

	sm9_fp_mont_inv(z_inv, P->Z);
	sm9_fp_mont_mul(Q->Y, P->Y, z_inv);
	sm9_fp_mont_sqr(z_inv, z_inv);
	sm9_fp_mont_mul(Q->X, P->X, z_inv);
	sm9_fp_mont_mul(Q->Y, Q->Y, z_inv);
}

// void sm9_fp_pairing(sm9_fp12_t r, const SM9_TWIST_POINT *Q, const SM9_POINT *P)
// {
// 	const char *abits = "00100000000000000000000000000000000000010000101100020200101000020";

// 	SM9_TWIST_POINT T;
// 	SM9_TWIST_POINT Q1;
// 	SM9_TWIST_POINT Q2;
// 	SM9_AFFINE_POINT P_;
// 	sm9_fp2_t lw[3];
// 	sm9_fp2_t pre[5]; // same for Q and -Q
// 	size_t i;

// 	sm9_fp2_copy(T.X, Q->X);
// 	sm9_fp2_copy(T.Y, Q->Y);
// 	sm9_fp2_copy(T.Z, Q->Z);

// 	sm9_point_to_affine(&P_, P);
// 	sm9_twist_point_neg(&Q1, Q);

// 	sm9_fp2_sqr(pre[0], Q->Y);
// 	sm9_fp2_mul(pre[4], Q->X, Q->Z);
// 	sm9_fp2_dbl(pre[4], pre[4]);
// 	sm9_fp2_sqr(pre[1], Q->Z);
// 	sm9_fp2_mul(pre[1], pre[1], Q->Z);
// 	sm9_fp2_mul_fp(pre[2], pre[1], P_.Y);
// 	sm9_fp2_dbl(pre[2], pre[2]);
// 	sm9_fp2_mul_fp(pre[3], pre[1], P_.X);
// 	sm9_fp2_dbl(pre[3], pre[3]);
// 	sm9_fp2_neg(pre[3], pre[3]);

// 	sm9_fp12_set_one(r);

// 	for (i = 0; i < strlen(abits); i++) {
// 		sm9_fp12_sqr(r, r);
// 		sm9_eval_g_tangent(&T, lw, &T, &P_);
// 		sm9_fp12_line_mul(r, r, lw);

// 		if (abits[i] == '1') {
// 			//sm9_fp_eval_g_line_no_pre(&T, lw, &T, Q, &P_);
// 			sm9_eval_g_line(&T, lw, pre, &T, Q, &P_);
// 			sm9_fp12_line_mul(r, r, lw);
// 		} else if (abits[i] == '2') {
// 			//sm9_fp_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
// 			sm9_eval_g_line(&T, lw, pre, &T, &Q1, &P_);
// 			sm9_fp12_line_mul(r, r, lw);
// 		}
// 	}

// 	sm9_twist_point_pi1(&Q1, Q);
// 	sm9_twist_point_neg_pi2(&Q2, Q);

// 	sm9_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
// 	sm9_fp12_line_mul(r, r, lw);

// 	sm9_eval_g_line_no_pre(&T, lw, &T, &Q2, &P_);
// 	sm9_fp12_line_mul(r, r, lw);

// 	sm9_final_exponent(r, r);
// }

void sm9_pairing(sm9_fp12_t r, const SM9_TWIST_POINT *Q, const SM9_POINT *P) {
	const char *abits = "00100000000000000000000000000000000000010000101100020200101000020";

	SM9_TWIST_POINT T;
	SM9_TWIST_POINT Q1;
	SM9_TWIST_POINT Q2;
	SM9_AFFINE_POINT P_;
	sm9_fp2_t lw[3];
	sm9_fp2_t pre[5]; // same for Q and -Q
	size_t i;

	sm9_fp2_copy(T.X, Q->X);
	sm9_fp2_copy(T.Y, Q->Y);
	sm9_fp2_copy(T.Z, Q->Z);

	sm9_point_to_affine(&P_, P);
	sm9_twist_point_neg(&Q1, Q);

	sm9_fp2_sqr(pre[0], Q->Y);
	sm9_fp2_mul(pre[4], Q->X, Q->Z);
	sm9_fp2_dbl(pre[4], pre[4]);
	sm9_fp2_sqr(pre[1], Q->Z);
	sm9_fp2_mul(pre[1], pre[1], Q->Z);
	sm9_fp2_mul_fp(pre[2], pre[1], P_.Y);
	sm9_fp2_dbl(pre[2], pre[2]);
	sm9_fp2_mul_fp(pre[3], pre[1], P_.X);
	sm9_fp2_dbl(pre[3], pre[3]);
	sm9_fp2_neg(pre[3], pre[3]);

	sm9_fp12_set_one(r);

	for (i = 0; i < strlen(abits); i++) {
		sm9_fp12_sqr(r, r);
		sm9_eval_g_tangent(&T, lw, &T, &P_);
		sm9_fp12_line_mul(r, r, lw);

		if (abits[i] == '1') {
			//sm9_fp_eval_g_line_no_pre(&T, lw, &T, Q, &P_);
			sm9_eval_g_line(&T, lw, pre, &T, Q, &P_);
			sm9_fp12_line_mul(r, r, lw);
		} else if (abits[i] == '2') {
			//sm9_fp_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
			sm9_eval_g_line(&T, lw, pre, &T, &Q1, &P_);
			sm9_fp12_line_mul(r, r, lw);
		}
	}

	sm9_twist_point_pi1(&Q1, Q);
	sm9_twist_point_neg_pi2(&Q2, Q);

	sm9_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
	sm9_fp12_line_mul(r, r, lw);

	sm9_eval_g_line_no_pre(&T, lw, &T, &Q2, &P_);
	sm9_fp12_line_mul(r, r, lw);
	
	sm9_final_exponent(r, r);
}

void sm9_fn_add(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b)
{
	sm9_bn_add(r, a, b);
	if (sm9_bn_cmp(r, SM9_N) >= 0) {
		sm9_bn_sub(r, r, SM9_N);
	}
}

void sm9_fn_sub(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b)
{
	if (sm9_bn_cmp(a, b) >= 0) {
		sm9_bn_sub(r, a, b);
	} else {
		sm9_bn_t t;
		sm9_bn_sub(t, SM9_N, b);
		sm9_bn_add(r, t, a);
	}
}

void sm9_fn_mul(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b)
{
	uint64_t s[18];
	sm9_barrett_bn_t zh, zl, q;
	uint64_t w;
	int i, j;

	/* z = a * b */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + a[i] * b[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 9; j++) {
			w += s[i + j] + zh[i] * SM9_MU_N[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 9] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[9 + i];
	}

	/* q = q * n mod (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM9_N[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}

	/* r = zl - q (mod (2^32)^9) */

	if (sm9_barrett_bn_cmp(zl, q)) {
		sm9_barrett_bn_sub(zl, zl, q);
	} else {
		sm9_barrett_bn_t c = {0,0,0,0,0,0,0,0,0x100000000};
		sm9_barrett_bn_sub(q, c, q);
		sm9_barrett_bn_add(zl, q, zl);
	}


	for (i = 0; i < 8; i++) {
		r[i] = zl[i];
	}

	r[7] += (zl[8] << 32);

	/* while r >= n do: r = r - n */
	while (sm9_bn_cmp(r, SM9_N) >= 0) {
		sm9_bn_sub(r, r, SM9_N);
	}
}

void sm9_fn_pow(sm9_fn_t r, const sm9_fn_t a, const sm9_bn_t e)
{
	sm9_fn_t t;
	uint32_t w;
	int i, j;

	assert(sm9_bn_cmp(e, SM9_N_MINUS_ONE) < 0);

	sm9_bn_set_one(t);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			sm9_fn_mul(t, t, t);
			if (w & 0x80000000)
				sm9_fn_mul(t, t, a);
			w <<= 1;
		}
	}
	sm9_bn_copy(r, t);
}

void sm9_fn_inv(sm9_fn_t r, const sm9_fn_t a)
{
	sm9_fn_t e;
	sm9_bn_sub(e, SM9_N, SM9_TWO);
	sm9_fn_pow(r, a, e);
}


// for H1() and H2()
// h = (Ha mod (n-1)) + 1;  h in [1, n-1], n is the curve order, Ha is 40 bytes from hash
void sm9_fn_from_hash(sm9_fn_t h, const uint8_t Ha[40])
{
	uint64_t s[18] = {0};
	sm9_barrett_bn_t zh, zl, q;
	uint64_t w;
	int i, j;

	/* s = Ha -> int */
	for (int i = 0; i < 10; i++) {
		for (int j = 0; j < 4; j++) {
			s[i] <<= 8;
			s[i] += Ha[4 * (9-i) + j];
		}
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 9; j++) {
			w += s[i + j] + zh[i] * SM9_MU_N_MINUS_ONE[j]; //
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 9] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[9 + i];
	}

	/* q = q * p mod (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM9_N_MINUS_ONE[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}

	/* h = zl - q (mod (2^32)^9) */

	if (sm9_barrett_bn_cmp(zl, q)) {
		sm9_barrett_bn_sub(zl, zl, q);
	} else {
		sm9_barrett_bn_t c = {0,0,0,0,0,0,0,0,0x100000000};
		sm9_barrett_bn_sub(q, c, q);
		sm9_barrett_bn_add(zl, q, zl);
	}

	for (i = 0; i < 8; i++) {
		h[i] = zl[i];
	}

	h[7] += (zl[8] << 32);

	/* while h >= (n-1) do: h = h - (n-1) */
	while (sm9_bn_cmp(h, SM9_N_MINUS_ONE) >= 0) {
		sm9_bn_sub(h, h, SM9_N_MINUS_ONE);
	}

	sm9_fn_add(h, h, SM9_ONE);
}

void sm9_fp12_to_bytes(const sm9_fp12_t a, uint8_t buf[32 * 12])
{
	sm9_fp4_to_bytes(a[2], buf);
	sm9_fp4_to_bytes(a[1], buf + 32 * 4);
	sm9_fp4_to_bytes(a[0], buf + 32 * 8);
}

int sm9_fn_from_bytes(sm9_fn_t a, const uint8_t in[32])
{
	sm9_bn_from_bytes(a, in);
	return 1;
}

int sm9_fn_from_hex(sm9_fp_t r, const char hex[64])
{
	if (sm9_bn_from_hex(r, hex) != 1) {
		error_print();
		return -1;
	}
	if (sm9_bn_cmp(r, SM9_N) >= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_point_to_uncompressed_octets(const SM9_POINT *P, uint8_t octets[65])
{
	sm9_fp_t x;
	sm9_fp_t y;
	sm9_point_get_xy(P, x, y);
	octets[0] = 0x04;
	sm9_bn_to_bytes(x, octets + 1);
	sm9_bn_to_bytes(y, octets + 32 + 1);
	return 1;
}

int sm9_point_from_uncompressed_octets(SM9_POINT *P, const uint8_t octets[65])
{
	if (octets[0] != 0x04) {
		error_print();
		return -1;
	}
	memset(P, 0, sizeof(*P));
	sm9_bn_from_bytes(P->X, octets + 1);
	sm9_fp_to_mont(P->X, P->X);
	sm9_bn_from_bytes(P->Y, octets + 32 + 1);
	sm9_fp_to_mont(P->Y, P->Y);
	sm9_fp_set_mont_one(P->Z);
	if (!sm9_point_is_on_curve(P)) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_twist_point_to_uncompressed_octets(const SM9_TWIST_POINT *P, uint8_t octets[129])
{
	octets[0] = 0x04;
	sm9_fp2_t x;
	sm9_fp2_t y;
	sm9_twist_point_get_xy(P, x, y);
	sm9_fp2_to_bytes(x, octets + 1);
	sm9_fp2_to_bytes(y, octets + 32 * 2 + 1);
	return 1;
}

int sm9_twist_point_from_uncompressed_octets(SM9_TWIST_POINT *P, const uint8_t octets[129])
{
	assert(octets[0] == 0x04);
	sm9_fp2_from_bytes(P->X, octets + 1);
	sm9_fp2_from_bytes(P->Y, octets + 32 * 2 + 1);
	sm9_fp2_set_mont_one(P->Z);
	if (!sm9_twist_point_is_on_curve(P)) return -1;
	return 1;
}
