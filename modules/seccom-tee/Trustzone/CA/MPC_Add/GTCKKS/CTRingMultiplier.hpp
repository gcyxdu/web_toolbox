/**
 * @author: heqi
 * 完成多项式上的一些运算，涉及NTT和逆NTT的内容，还有快速傅里叶变换，以及多项式上的乘法以及多项式的加法运算
 * */
#include <vector>
#include <stdio.h>
#include <cmath>
#include <cstring>
#include <stdint.h>
#include "ciphertext.hpp"
#include "stringUtils.hpp"
#include <random>
#include <complex>

using namespace std;
using namespace gtfhe;

#include <sys/time.h>

#ifndef ring_
#define ring_

struct timeval time3, time4;
namespace gtfhe
{
	class RingMultipliertest
	{
	public:
		uint64_t pVec; // 各个素数
		uint64_t prVec;
		uint64_t invp;
		uint64_t *g;  // pvec的原根
		uint64_t *gi; // pvec的原根的逆原
		uint64_t inv; // M的逆
		uint64_t N;	  // 多项式次数
		uint64_t logN;
		uint64_t M; // 二倍多项式次数
		int *rev;	// 蝶形变幻的索引
		int primeLen;
		complex<double> *ksiPows;
		long *rotGroup;

		void Modshift(uint64_t &r, unsigned __int128 a, uint64_t mod, uint64_t m){
			a %= static_cast<unsigned __int128>(mod);
			r = static_cast<uint64_t>(a) >> m;
		}

		void Shift(uint64_t &r, unsigned __int128 a, uint64_t m){
			a = static_cast<unsigned __int128>(a) >> m;
			r = static_cast<uint64_t>(a);
		}

		void mulShift(uint64_t &r, uint64_t a, uint64_t b, size_t m){
			unsigned __int128 mul = static_cast<unsigned __int128>(a) * b;
			r = static_cast<uint64_t>(mul >> m);
		}

		void mulModShift(uint64_t &r, uint64_t a, uint64_t b, uint64_t P, size_t m){
			mulMod(r, a, b, P);
			r = r >> m;
		}

		// 模乘运算
		void mulMod(uint64_t &r, uint64_t a, uint64_t b, uint64_t m)
		{
			unsigned __int128 mul = static_cast<unsigned __int128>(a) * b;
			mul %= static_cast<unsigned __int128>(m);
			r = static_cast<uint64_t>(mul);
		}

		// barrett Mul
		void mulModBarrett(uint64_t &r, uint64_t a, uint64_t b, uint64_t m, uint64_t pr)
		{
			unsigned __int128 mul = static_cast<unsigned __int128>(a) * b;
			uint64_t abot = static_cast<uint64_t>(mul);
			uint64_t atop = static_cast<uint64_t>(mul >> 64);
			// uint64_t pr = (static_cast<unsigned __int128>(1) << 2*(60+1)) / m;
			unsigned __int128 tmp = static_cast<unsigned __int128>(abot) * pr;
			tmp >>= 64;
			tmp += static_cast<unsigned __int128>(atop) * pr;
			tmp >>= 2 * (primeLen + 1) - 64;
			tmp *= m;
			tmp = mul - tmp;
			r = static_cast<uint64_t>(tmp);
			if (r > m)
				r -= m;
		}

		// 模指数运算
		uint64_t powMod(uint64_t x, uint64_t y, uint64_t modulus)
		{
			uint64_t res = 1;
			while (y > 0)
			{
				if (y & 1)
				{
					mulMod(res, res, x, modulus);
				}
				y = y >> 1;
				mulMod(x, x, x, modulus);
			}
			return res;
		}

		// 模指数运算
		uint64_t powModBarrett(uint64_t x, uint64_t y, uint64_t modulus, uint64_t pr)
		{
			uint64_t res = 1;
			while (y > 0)
			{
				if (y & 1)
				{
					mulModBarrett(res, res, x, modulus, pr);
				}
				y = y >> 1;
				mulModBarrett(x, x, x, modulus, pr);
			}
			return res;
		}

		// 素数分解
		void get_fac(vector<uint64_t> &s, uint64_t number)
		{
			while (number % 2 == 0)
			{
				s.push_back(2);
				number /= 2;
			}
			for (uint64_t i = 3; i < sqrt(number); i++)
			{
				while (number % i == 0)
				{
					s.push_back(i);
					number /= i;
				}
			}
			if (number > 2)
			{
				s.push_back(number);
			}
		}

		uint64_t inver(uint64_t x)
		{
			return pow(x, static_cast<uint64_t>(-1));
		}

		uint64_t pow(uint64_t x, uint64_t y)
		{
			uint64_t res = 1;
			while (y > 0)
			{
				if (y & 1)
				{
					res *= x;
				}
				y = y >> 1;
				x *= x;
			}
			return res;
		}

		// 生成素数原根
		uint64_t get_prime_root(uint64_t modulus)
		{
			vector<uint64_t> s;
			uint64_t phi = modulus - 1;
			get_fac(s, phi);
			for (uint64_t r = 2; r <= phi; r++)
			{
				bool flag = false;
				for (auto it = s.begin(); it != s.end(); it++)
				{
					if (powModBarrett(r, phi / (*it), modulus, prVec) == 1)
					{
						flag = true;
						break;
					}
				}
				if (flag == false)
				{
					return r;
				}
			}

			return 0;
		}

		// 费马小定理求逆元
		uint64_t invMod(uint64_t x, uint64_t m)
		{
			return powMod(x, m - 2, m);
		}

		//  寻找原根
		uint64_t findMthRootOfUnity(uint64_t M, uint64_t mod, uint64_t pr)
		{
			uint64_t res;
			res = get_prime_root(mod);
			if ((mod - 1) % M == 0)
			{
				uint64_t factor = (mod - 1) / M;
				res = powModBarrett(res, factor, mod, pr);
				return res;
			}
			else
			{
				return 0;
			}
		}

		// 素性检测
		bool primeTest(uint64_t p)
		{
			if (p < 2)
				return false;
			if (p != 2 && p % 2 == 0)
				return false;
			uint64_t s = p - 1;
			while (s % 2 == 0)
			{
				s /= 2;
			}
			for (long i = 0; i < 200; i++)
			{
				uint64_t temp1 = rand();
				temp1 = (temp1 << 32) | rand();
				temp1 = temp1 % (p - 1) + 1;
				uint64_t temp2 = s;
				uint64_t mod = powMod(temp1, temp2, p);
				while (temp2 != p - 1 && mod != 1 && mod != p - 1)
				{
					mulMod(mod, mod, mod, p);
					temp2 *= 2;
				}
				if (mod != p - 1 && temp2 % 2 == 0)
					return false;
			}
			return true;
		}

		// bit反转， 蝶形变换
		void bitreverse()
		{
			int revint[N];
			for (int i = 0; i < N; ++i)
			{
				revint[i] = 0;
				rev[i] = i;
			}
			for (int i = 0; i < N; ++i)
			{ // get rev
				revint[i] = (revint[i >> 1] >> 1) | ((i & 1) << (logN - 1));
				if (i < revint[i])
				{
					rev[revint[i]] = i;
					rev[i] = revint[i];
				}
			}
		}

		void arrayBitReverse(complex<double> *vals, size_t size)
		{
			for (long i = 1, j = 0; i < size; ++i)
			{
				long bit = size >> 1;
				for (; j >= bit; bit >>= 1)
				{
					j -= bit;
				}
				j += bit;
				if (i < j)
				{
					swap(vals[i], vals[j]);
				}
			}
		}

		void preTable(uint64_t Np, uint64_t &root, uint64_t &invroot)
		{
			if (Np == 11)
			{
				pVec = 576460752303439873;
				prVec = 9223372036854513648;
				invp = -504407556043587583;
				root = 94501300158356233;
				invroot = 351196243136101305;
				inv = 9007199254740992;
			}
			else if (Np == 12)
			{
				pVec = 576460752303439873;
				prVec = 9223372036854513648;
				invp = -504407556043587583;
				root = 324227211372304498;
				invroot = 295240848901397616;
				inv = 4503599627370496;
			}
			else if (Np == 13)
			{
				pVec = 576460752303439873;
				prVec = 9223372036854513648;
				invp = -504407556043587583;
				root = 3848444851313459;
				invroot = 409403081178837348;
				inv = 2251799813685248;
			}
			else if (Np == 14)
			{
				pVec = 576460752304439297;
				prVec = 9223372036838522864;
				invp = -471715844730093567;
				root = 191393272803421785;
				invroot = 427853369549297084;
				inv = 1125899906842624;
			}
			else if (Np == 15)
			{
				pVec = 576460752308273153;
				prVec = 9223372036777181168;
				invp = -3956388753408917503;
				root = 272758541886322648;
				invroot = 13217847085486481;
				inv = 562949953421312;
			}
			else
			{
				printf("error! cannot support this logN");
			}
		}

		// 生成素数
		int generate_prime(uint64_t Np, int primeLen, bool is_use_pretable = false)
		{
			// int pbnd = 59;

			N = 1 << Np;
			logN = Np;
			M = N << 1;
			this->primeLen = primeLen;
			rev = new int[N];
			bitreverse();
			if (primeLen > 63)
			{
				return 0;
			}

			rotGroup = new long[N >> 1]();
			long fivePows = 1;
			for (long i = 0; i < N >> 1; ++i)
			{
				rotGroup[i] = fivePows;
				fivePows *= 5;
				fivePows %= M;
			}

			ksiPows = new complex<double>[M + 1]();
			for (long j = 0; j < M; ++j)
			{
				double angle = 2.0 * M_PI * j / M;
				ksiPows[j].real(cos(angle));
				ksiPows[j].imag(sin(angle));
			}

			uint64_t primetest = (1ULL << (primeLen - 1)) + 1;

			if (!is_use_pretable)
			{
				while (true)
				{
					primetest += N << 1;
					if (primeTest(primetest))
					{
						pVec = (int64_t)primetest;
						prVec = (static_cast<unsigned __int128>(1) << 2 * (primeLen + 1)) / pVec;
						invp = inver(pVec);
						g = new uint64_t[N >> 1];
						gi = new uint64_t[N >> 1];

						uint64_t root = findMthRootOfUnity(N, pVec, prVec); // get prime N-root of mod
						uint64_t invroot = invMod(root, pVec);				// get inv prime N-root of mod

						uint64_t temp = static_cast<uint64_t>(1) << 32;
						g[0] = 1;
						mulModBarrett(g[0], g[0], temp, pVec, prVec);
						mulModBarrett(g[0], g[0], temp, pVec, prVec);
						gi[0] = g[0];

						for (int P = 1; P < N >> 1; P++)
						{
							g[P] = REDC(g[P - 1], root);
							mulModBarrett(g[P], g[P], temp, pVec, prVec);
							mulModBarrett(g[P], g[P], temp, pVec, prVec);
							gi[P] = REDC(gi[P - 1], invroot);
							mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
							mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
						}

						inv = powMod(N, pVec - 2, pVec); // inv为len的逆元（费马小定理求逆元）
						mulModBarrett(inv, inv, temp, pVec, prVec);
						mulModBarrett(inv, inv, temp, pVec, prVec);
						break;
					}
				}
			}
			else
			{
				uint64_t root;
				uint64_t invroot;
				g = new uint64_t[N >> 1];
				gi = new uint64_t[N >> 1];
				preTable(logN, root, invroot);

				uint64_t temp = static_cast<uint64_t>(1) << 32;
				g[0] = 1;
				mulModBarrett(g[0], g[0], temp, pVec, prVec);
				mulModBarrett(g[0], g[0], temp, pVec, prVec);
				gi[0] = g[0];

				for (int P = 1; P < N >> 1; P++)
				{
					g[P] = REDC(g[P - 1], root);
					mulModBarrett(g[P], g[P], temp, pVec, prVec);
					mulModBarrett(g[P], g[P], temp, pVec, prVec);
					gi[P] = REDC(gi[P - 1], invroot);
					mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
					mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
				}
			}

			return 1;
		}

		uint64_t REDC(uint64_t a, uint64_t b)
		{
			unsigned __int128 U = static_cast<unsigned __int128>(a) * b;
			uint64_t U0 = static_cast<uint64_t>(U);
			uint64_t U1 = U >> 64;
			uint64_t Q = U0 * invp;
			unsigned __int128 Hx = static_cast<unsigned __int128>(Q) * pVec;
			uint64_t H = Hx >> 64;
			uint64_t V = U1 < H ? U1 + pVec - H : U1 - H;
			return V;
		}

		void NTT(uint64_t *a)
		{
			int NLess2 = N >> 1;

			uint64_t temp_a[N];
			for (int i = 0; i < NLess2; i++)
			{
				uint64_t U1 = a[rev[2 * i]] + a[rev[2 * i + 1]];
				uint64_t U2 = a[rev[2 * i]] - a[rev[2 * i + 1]];
				temp_a[i] = U1 > pVec ? U1 - pVec : U1;
				temp_a[i + NLess2] = U2 > pVec ? U2 + pVec : U2;
			}

			memcpy(a, temp_a, sizeof(temp_a));
			for (int i = 1; i < logN; i++)
			{
				int shift = logN - 1 - i;
				for (int j = 0; j < NLess2; j++)
				{
					int P = (j >> shift) << shift;
					uint64_t odd = REDC(a[2 * j + 1], g[P]);
					// mulModBarrett(odd, a[2 * j + 1], g[P], pVec, prVec);
					uint64_t U1 = a[2 * j] + odd;
					uint64_t U2 = a[2 * j] - odd;
					temp_a[j] = U1 > pVec ? U1 - pVec : U1;
					temp_a[j + NLess2] = U2 > pVec ? U2 + pVec : U2;
				}
				memcpy(a, temp_a, sizeof(temp_a));
			}
		}

		void INTT(uint64_t *a) // NTT，type=1, or is INTT
		{
			int NLess2 = N >> 1;

			uint64_t temp_a[N];
			for (int i = 0; i < NLess2; i++)
			{
				uint64_t U1 = a[rev[2 * i]] + a[rev[2 * i + 1]];
				uint64_t U2 = a[rev[2 * i]] - a[rev[2 * i + 1]];
				temp_a[i] = U1 > pVec ? U1 - pVec : U1;
				temp_a[i + NLess2] = U2 > pVec ? U2 + pVec : U2;
			}

			memcpy(a, temp_a, sizeof(temp_a));

			for (int i = 1; i < logN; i++)
			{
				int shift = logN - 1 - i;
				for (int j = 0; j < NLess2; j++)
				{
					int P = (j >> shift) << shift;
					uint64_t odd = REDC(a[2 * j + 1], gi[P]);
					// mulModBarrett(odd, a[2 * j + 1], gi[P], pVec, prVec);
					uint64_t U1 = a[2 * j] + odd;
					uint64_t U2 = a[2 * j] - odd;
					temp_a[j] = U1 > pVec ? U1 - pVec : U1;
					temp_a[j + NLess2] = U2 > pVec ? U2 + pVec : U2;
				}
				memcpy(a, temp_a, sizeof(temp_a));
			}

			for (int i = 0; i < N; i++)
			{
				// mulModBarrett(a[i], a[i], inv, pVec, prVec);
				a[i] = REDC(a[i], inv);
			}
		}

		void fast_INTT(uint64_t *a) // NTT，type=1, or is INTT
		{
			int NLess2 = N >> 1;

			uint64_t temp_a[N];
			for (int i = 0; i < NLess2; i++)
			{
				uint64_t U1 = a[rev[2 * i]] + a[rev[2 * i + 1]];
				uint64_t U2 = a[rev[2 * i]] - a[rev[2 * i + 1]];
				temp_a[i] = U1 > pVec ? U1 - pVec : U1;
				temp_a[i + NLess2] = U2 > pVec ? U2 + pVec : U2;
			}

			memcpy(a, temp_a, sizeof(temp_a));

			for (int i = 1; i < logN; i++)
			{
				int shift = logN - 1 - i;
				for (int j = 0; j < NLess2; j++)
				{
					int P = (j >> shift) << shift;
					uint64_t odd = REDC(a[2 * j + 1], gi[P]);
					// mulModBarrett(odd, a[2 * j + 1], gi[P], pVec, prVec);
					uint64_t U1 = a[2 * j] + odd;
					uint64_t U2 = a[2 * j] - odd;
					temp_a[j] = U1 > pVec ? U1 - pVec : U1;
					temp_a[j + NLess2] = U2 > pVec ? U2 + pVec : U2;
				}
				memcpy(a, temp_a, sizeof(temp_a));
			}
		}

		void pre_handle_s(uint64_t *s)
		{
			for (int i = 0; i < N; i++)
			{
				// mulModBarrett(s[i], s[i], inv, pVec, prVec);
				s[i] = REDC(s[i], inv);
			}
		}

		// encode
		void fftSpecialInvLazy(complex<double> *vals, size_t size)
		{
			for (long len = size; len >= 1; len >>= 1)
			{
				for (long i = 0; i < size; i += len)
				{
					long lenh = len >> 1;
					long lenq = len << 2;
					long gap = M / lenq;
					for (long j = 0; j < lenh; ++j)
					{
						long idx = (lenq - (rotGroup[j] % lenq)) * gap;
						complex<double> u = vals[i + j] + vals[i + j + lenh];
						complex<double> v = vals[i + j] - vals[i + j + lenh];
						v *= ksiPows[idx];
						vals[i + j] = u;
						vals[i + j + lenh] = v;
					}
				}
			}
			arrayBitReverse(vals, size);
		}

		void fftSpecialInv(complex<double> *vals, size_t size)
		{
			fftSpecialInvLazy(vals, size);
			for (long i = 0; i < size; ++i)
			{
				vals[i] /= size;
			}
		}

		void IFFTencode(uint64_t *&a, double *v, size_t slots, size_t scale)
		{
			complex<double> *uvals = new complex<double>[slots];
			for (size_t i = 0; i < slots; i++)
			{
				uvals[i].real(v[i]);
			}

			long gap = (N >> 1) / slots;
			// printf("native vector:\n");
			// printf_vector(v, slots);

			fftSpecialInv(uvals, slots);
			// printf("IFFT:\n");
			// printf_vector(uvals, slots);

			for (long j = 0; j < slots; ++j)
			{
				uvals[j] *= 1 << scale;
			}

			a = new uint64_t[N];
			for (long j = 0, jdx = N >> 1, idx = 0; j < slots; ++j, jdx += gap, idx += gap)
			{
				long mir = uvals[j].real();
				long mii = uvals[j].imag();
				a[idx] = mir >= 0 ? (uint64_t)mir : (uint64_t)(pVec + mir);
				a[jdx] = mii >= 0 ? (uint64_t)mii : (uint64_t)(pVec + mii);
			}

			// printf("encrypt message:\n");
			// printf_ploy(a, slots);
			NTT(a);

			delete[] uvals;
		}

		void IFFTencode(uint64_t *&a, complex<double> *v, size_t slots, size_t scale)
		{
			complex<double> *uvals = new complex<double>[slots];
			copy(v, v + slots, uvals);

			long gap = (N >> 1) / slots;
			// printf("native vector:\n");
			// printf_vector(v, slots);

			fftSpecialInv(uvals, slots);
			// printf("IFFT change:\n");
			// printf_vector(uvals, slots);

			for (long j = 0; j < slots; ++j)
			{
				uvals[j] *= 1 << scale;
			}

			a = new uint64_t[N];
			for (long j = 0, jdx = N >> 1, idx = 0; j < slots; ++j, jdx += gap, idx += gap)
			{
				long mir = uvals[j].real();
				long mii = uvals[j].imag();
				a[idx] = mir >= 0 ? (uint64_t)mir : (uint64_t)(pVec + mir);
				a[jdx] = mii >= 0 ? (uint64_t)mii : (uint64_t)(pVec + mii);
			}

			// printf("encrypt message:\n");
			// printf_ploy(a, slots);

			NTT(a);

			delete[] uvals;
		}

		// decode
		void fftSpecial(complex<double> *vals, const long size)
		{
			arrayBitReverse(vals, size);
			for (long len = 2; len <= size; len <<= 1)
			{
				for (long i = 0; i < size; i += len)
				{
					long lenh = len >> 1;
					long lenq = len << 2;
					long gap = M / lenq;
					for (long j = 0; j < lenh; ++j)
					{
						long idx = ((rotGroup[j] % lenq)) * gap;
						complex<double> u = vals[i + j];
						complex<double> v = vals[i + j + lenh];
						// printf("len: %lld i: %lld j: %lld idx: %lld \n", len, i, j, idx);
						v *= ksiPows[idx];
						vals[i + j] = u + v;
						vals[i + j + lenh] = u - v;
					}
				}
			}
		}

		void IFFTdecode(uint64_t *a, complex<double> *&v, long slots, size_t scale)
		{
			uint64_t *tmp = new uint64_t[N]();
			copy(a, a + N, tmp);
			// printf("native ploy change:\n");
			// printf_ploy(tmp, slots);

			long gap = (N >> 1) / slots;
			INTT(tmp);

			uint64_t p = 1 << scale;
			uint64_t pr = pVec;
			uint64_t pr_2 = pVec / 2;
			for (long j = 0, jdx = N >> 1, idx = 0; j < slots; ++j, jdx += gap, idx += gap)
			{
				double mir = tmp[idx] <= pr_2 ? ((double)(tmp[idx]) / p) : (((double)(tmp[idx]) - (double)(pr)) / p);
				double mii = tmp[jdx] <= pr_2 ? ((double)(tmp[jdx]) / p) : (((double)(tmp[jdx]) - (double)(pr)) / p);
				v[j].real(mir);
				v[j].imag(mii);
			}

			fftSpecial(v, slots);
			// printf("change native vetor:\n");
			// printf_vector(v, slots);
		}

		// 模除操作，乘逆元
		void divMod(int64_t *a, uint64_t *b, int index)
		{ // 除模，等于乘上模的逆
			uint64_t temp = pVec >> 1;
			for (size_t i = 0; i < N; i++)
			{
				mulMod(b[i], b[i], inv, pVec);
				mulMod(b[i + N], b[i + N], inv, pVec);
				a[i] = (b[i] + b[i + N]) % pVec;
				if (a[i] > temp)
				{
					a[i] = a[i] - pVec;
				}
			}
		}

		// 暴力相乘
		void mult_raw(int64_t *c, uint64_t *a, uint64_t *b, uint64_t mod)
		{
			uint64_t temp1 = pVec >> 1;
			for (size_t i = 0; i < N; i++)
			{
				for (size_t j = 0; j < N; j++)
				{
					uint64_t temp = 0;
					mulMod(temp, a[i], b[j], mod);
					c[(i + j) % N] += temp;
					c[(i + j) % N] %= mod;
				}
			}
			for (size_t i = 0; i < N; i++)
			{
				if (c[i] > temp1)
				{
					c[i] = c[i] - pVec;
				}
			}
		}

		// 多项式暴力相乘测试
		void NTTtest1()
		{
			uint64_t *a = new uint64_t[N];
			uint64_t *b = new uint64_t[N];
			for (int i = 0; i < N; ++i) // 输入第一个多项式
			{
				a[i] = i % pVec;
				b[i] = (i + 1) % pVec; // 输入第二个多项式
			}

			int64_t *c = new int64_t[N];
			for (size_t i = 0; i < N; i++)
			{
				c[i] = 0;
			}
			mult_raw(c, a, b, pVec);
		}

		// NTT测试
		void NTTtest2()
		{
			// printf("%llu\n",pVec[0]);
			uint64_t *a = new uint64_t[N];
			uint64_t *b = new uint64_t[N];
			for (int i = 0; i < N; ++i) // 输入第一个多项式
			{
				a[i] = i % pVec;
				b[i] = (i + 1) % pVec; // 输入第二个多项式
			}

			NTT(a); // 系数表示法转点值表示法
			NTT(b);

			for (int i = 0; i < N; ++i)
				mulModBarrett(a[i], a[i], b[i], pVec, prVec); // O(n)乘法
			INTT(a);										  // 点值表示法转系数表示法
		}

		void NTTtest3()
		{
			// printf("%llu\n",pVec[0]);
			uint64_t *a = new uint64_t[N];
			uint64_t *b = new uint64_t[N];
			for (int i = 0; i < N; ++i) // 输入第一个多项式
			{
				a[i] = rand() % pVec;
				b[i] = rand() % pVec; // 输入第二个多项式
			}

			int64_t *c = new int64_t[N];
			for (size_t i = 0; i < N; i++)
			{
				c[i] = 0;
			}

			for (size_t i = 0; i < N; i++)
			{
				for (size_t j = 0; j < N; j++)
				{
					uint64_t temp = 0;
					mulMod(temp, a[i], b[j], pVec);
					c[(i + j) % N] += temp;
					c[(i + j) % N] %= pVec;
				}
			}

			NTT(a); // 系数表示法转点值表示法
			NTT(b);

			for (int i = 0; i < N; ++i)
				mulMod(a[i], a[i], b[i], pVec); // O(n)乘法
			printf("\n");
			INTT(a); // 点值表示法转系数表示法

			for (int i = 0; i < N; ++i)
			{
				printf("%lld ", c[i] - a[i]);
			}
			printf("\n");
		}

		void uintchangeint(uint64_t *a, size_t slots)
		{
			uint64_t pr_2 = pVec >> 1;
			int64_t *b = new int64_t[slots];
			for (size_t i = 0; i < slots; i++)
			{
				b[i] = a[i] >= pr_2 ? (a[i] - pVec) : a[i];
			}
			printf_ploy(b, slots);
		}

		// 多项式乘法 NTT(a) * NTT(b)
		void mult(uint64_t *&x, uint64_t *a, uint64_t *b)
		{
			x = new uint64_t[N];

			for (int i = 0; i < N; ++i)
				mulModBarrett(x[i], a[i], b[i], pVec, prVec); // O(n)乘法
		}
		
		void mult_poly(uint64_t *&x, uint64_t *a, uint64_t *b)
		{
			x = new uint64_t[N];

			for (int i = 0; i < N; ++i)
			{
				mulModBarrett(x[i], a[i], b[i], pVec, prVec); // O(n)乘法
			}
			INTT(x);
		}
		
		void fast_mult_poly(uint64_t *&x, uint64_t *a, uint64_t *b)
		{
			x = new uint64_t[N];
			for (int i = 0; i < N; ++i)
			{
				mulModBarrett(x[i], a[i], b[i], pVec, prVec); // O(n)乘法
			}
			fast_INTT(x);
		}

		// 多项式减法 a-b
		void sub(uint64_t *e, uint64_t *&b)
		{
			for (size_t i = 0; i < N; i++)
				b[i] = (pVec - b[i] + e[i]) % pVec;
		}

		// 多项式减法 a-b
		void sub(uint64_t *&c, uint64_t *a, uint64_t *b)
		{
			for (size_t i = 0; i < N; i++)
				c[i] = (pVec - b[i] + a[i]) % pVec;
		}

		void add(uint64_t *&a, uint64_t *b)
		{
			for (size_t i = 0; i < N; i++)
				a[i] = (a[i] + b[i]) % pVec;
		}

		void add(uint64_t *&c, uint64_t *a, uint64_t *b)
		{
			for (size_t i = 0; i < N; i++)
				c[i] = (a[i] + b[i]) % pVec;
		}
	};
}

#endif