#include <vector>
#include <stdio.h>
#include <cmath>
#include <cstring>
#include <stdint.h>
#include "ciphertext.hpp"
#include "stringUtils.hpp"
#include "randomgen.h"


// NTT with optimization by pretable.

using namespace std;
using namespace gtfhe;

#ifndef ring_
#define ring_
namespace gtfhe
{
	class RingMultipliertest{
	public:	
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

		void Modshift(uint64_t &r, unsigned __int128 a, uint64_t mod, uint64_t m){
			a %= static_cast<unsigned __int128>(mod);
			r = static_cast<uint64_t>(a) >> m;
		}

		// 模乘运算
		void mulMod(uint64_t &r, uint64_t a, uint64_t b, uint64_t m) {
			unsigned __int128 mul = static_cast<unsigned __int128>(a) * b;
			mul %= static_cast<unsigned __int128>(m);
			r = static_cast<uint64_t>(mul);
		}

		// barrett Mul
		void mulModBarrett(uint64_t &r, uint64_t a, uint64_t b, uint64_t m, uint64_t pr){
			unsigned __int128 mul = static_cast<unsigned __int128>(a) * b;
			uint64_t abot = static_cast<uint64_t>(mul);
            uint64_t atop = static_cast<uint64_t>(mul >> 64);
            // uint64_t pr = (static_cast<unsigned __int128>(1) << 2*(60+1)) / m;
            unsigned __int128 tmp = static_cast<unsigned __int128>(abot) * pr;
            tmp >>= 64;
            tmp += static_cast<unsigned __int128>(atop) * pr;
            tmp >>= 2*(primeLen + 1) - 64;
            tmp *= m;
            tmp = mul - tmp;
            r = static_cast<uint64_t>(tmp);
			if ( r > m ) r -= m;
		}

		// 模指数运算
		uint64_t powMod(uint64_t x, uint64_t y, uint64_t modulus) {
		    uint64_t res = 1;
		    while (y > 0) {
		        if (y & 1) {
		            mulMod(res, res, x, modulus);
		        }
		        y = y >> 1;
		        mulMod(x, x, x, modulus);
		    }
		    return res;
		}

		// 模指数运算
		uint64_t powModBarrett(uint64_t x, uint64_t y, uint64_t modulus, uint64_t pr) {
		    uint64_t res = 1;
		    while (y > 0) {
		        if (y & 1) {
		            mulModBarrett(res, res, x, modulus, pr);
		        }
		        y = y >> 1;
		        mulModBarrett(x, x, x, modulus, pr);
		    }
		    return res;
		}

		//素数分解
		void get_fac(vector<uint64_t> &s, uint64_t number){
		    while (number % 2 == 0) {
		        s.push_back(2);
		        number /= 2;
		    }
		    for (uint64_t i = 3; i < sqrt(number); i++) {
		        while (number % i == 0) {
		            s.push_back(i);
		            number /= i;
		        }
		    }
		    if (number > 2) {
		        s.push_back(number);
		    }
		}

        uint64_t inver(uint64_t x) {
            return pow(x, static_cast<uint64_t>(-1));
        }

         uint64_t pow(uint64_t x, uint64_t y) {
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

		// 生成素数原根
		uint64_t get_prime_root(uint64_t modulus){
		    vector<uint64_t> s;
		    uint64_t phi = modulus - 1;
		    get_fac(s, phi);
		    for (uint64_t r = 2; r <= phi; r++) {
		        bool flag = false;
		        for (auto it = s.begin(); it != s.end(); it++) {
		            if (powMod(r, phi / (*it), modulus) == 1) {
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

		// 费马小定理求逆元
		uint64_t invMod(uint64_t x, uint64_t m) {
		    return powMod(x, m - 2, m);
		}

		//  扩展阿基里得算法求逆元
		// int64_t exgcd(int64_t a, int64_t b, int64_t &x, int64_t &y)
		// {
		//     if(b==0)
		//     {
		//         x=1;
		//         y=0;
		//         return a;
		//     }
		//     int64_t ret=exgcd(b,a%b,x,y);
		//     int64_t t=x;
		//     x=y;
		//     y=t-a/b*(y);
		//     return ret;
		// }

		//  寻找原根
		uint64_t findMthRootOfUnity(uint64_t M, uint64_t mod, uint64_t pr) {
		    uint64_t res;
		    res = get_prime_root(mod);
		    if((mod - 1) % M == 0) {
		        uint64_t factor = (mod - 1) / M;
		        res = powModBarrett(res, factor, mod, pr);
		        return res;
		    }else{
		        return 0;
		    }
		}

		// 素性检测
		bool primeTest(uint64_t p) {
			if(p < 2) return false;
			if(p != 2 && p % 2 == 0) return false;
			uint64_t s = p - 1;
			while(s % 2 == 0) {
				s /= 2;
			}
			UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>();

			for(long i = 0; i < 200; i++) {
				uint64_t temp1 = ran->generate();
				temp1  = (temp1 << 32) | ran->generate();
				temp1 = temp1 % (p - 1) + 1;
				uint64_t temp2 = s;
				uint64_t mod = powMod(temp1,temp2,p);
				while (temp2 != p - 1 && mod != 1 && mod != p - 1) {
					mulMod(mod, mod, mod, p);
					temp2 *= 2;
				}
				if (mod != p - 1 && temp2 % 2 == 0) return false;
			}
			return true;
		}

		// // bit反转， 蝶形变换
		// void bitreverse(){
		// 	for (int i = 0; i < N; ++i)
		// 	{
		// 		rev[i] = 0;
		// 	}
		//     for (int i = 0; i < N; ++i)                                  // get rev
		//         rev[i] = (rev[i >> 1] >> 1) | ((i & 1) << (max((int)ceil(log2(N)), 1) - 1));
		// }

        // // bit反转， 蝶形变换
		// void bitreverse(){
        //     int revint[N];
		// 	for (int i = 0; i < N; ++i)
		// 	{
		// 		revint[i] = 0;
        //         rev[i] = i;
		// 	}
		//     for (int i = 0; i < N; ++i)                                  // get rev
		//         revint[i] = (revint[i >> 1] >> 1) | ((i & 1) << (max((int)ceil(log2(N)), 1) - 1));


        //     for (int i = 0; i < N; i++)
        //         if(i < revint[i]){
        //             int temp = rev[i];
        //             rev[revint[i]] = i;
        //             rev[i] = revint[i]; 
        //         }
            
		// }

		// bit反转， 蝶形变换
		void bitreverse(){
            int revint[N];
			for (int i = 0; i < N; ++i)
			{
				revint[i] = 0;
                rev[i] = i;
			}
		    for (int i = 0; i < N; ++i){				// get rev
				revint[i] = (revint[i >> 1] >> 1) | ((i & 1) << (logN - 1));
				if(i < revint[i]){
                    rev[revint[i]] = i;
                    rev[i] = revint[i]; 
                }
			}     
		}

		// // 生成素数
		// int generate_prime(uint64_t Np, int primeLen){                 
		//     // int pbnd = 59;
		//     N = 1 << Np;
        //     logN = Np;
        //     this->primeLen = primeLen;
		//     rev = new int[N];
		//     bitreverse();
		// 	if (primeLen > 63){
		// 		return 0;
		// 	}
		// 	uint64_t primetest = (1ULL << (primeLen-1)) + 1;
		// 	while(true) {
	    //             primetest += N << 1;
	    //             if(primeTest(primetest)) {
	    //                 pVec = (int64_t) primetest;
        //                 prVec = (static_cast<unsigned __int128>(1) << 2*(primeLen + 1)) / pVec;
        //                 invp = inver(pVec);
        //                 g = new uint64_t[N >> 1];
        //                 gi = new uint64_t[N >> 1]; 

        //                 uint64_t root = findMthRootOfUnity(N, pVec);                                   // get prime root of mod
	    //                 uint64_t invroot = invMod(root, pVec);                                       // get inv prime root of mod

        //                 uint64_t temp = static_cast<uint64_t>(1) << 32;
		// 				for (int P = 0; P < N >> 1; P++){
		// 					g[P] = powMod(root, P, pVec); 
		// 					mulModBarrett(g[P], g[P], temp, pVec, prVec);
		// 					mulModBarrett(g[P], g[P], temp, pVec, prVec);
		// 					gi[P] = powMod(invroot, P, pVec); 
		// 					mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
		// 					mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
		// 				}

	    //                 inv = powMod(N, pVec - 2, pVec);                            //inv为len的逆元（费马小定理求逆元）
		// 				mulModBarrett(inv, inv, temp, pVec, prVec);
		// 				mulModBarrett(inv, inv, temp, pVec, prVec);
	    //                 break;
	    //             }
	    //         }
		// 	return 1;
		// }

		void preTable(uint64_t Np, uint64_t &root, uint64_t &invroot){
			if(Np == 11){
				pVec = 576460752303439873;
				prVec = 9223372036854513648;	
 				invp = -504407556043587583;
				root = 94501300158356233;
				invroot = 351196243136101305;
				inv = 9007199254740992;
			}else if(Np == 12){
				pVec = 576460752303439873;
				prVec = 9223372036854513648;	
 				invp = -504407556043587583;
				root = 324227211372304498;
				invroot = 295240848901397616;
				inv = 4503599627370496;
			}else if(Np == 13){
				pVec = 576460752303439873;
				prVec = 9223372036854513648;	
 				invp = -504407556043587583;
				root = 3848444851313459;
				invroot = 409403081178837348;
				inv = 2251799813685248;
			}else if(Np == 14){
				pVec = 576460752304439297;
				prVec = 9223372036838522864;	
 				invp = -471715844730093567;
				root = 191393272803421785;
				invroot = 427853369549297084;
				inv = 1125899906842624;
			}else if(Np == 15){
				pVec = 576460752308273153;
				prVec = 9223372036777181168;	
 				invp = -3956388753408917503;
				root = 272758541886322648;
				invroot = 13217847085486481;
				inv = 562949953421312;
			}else{
				printf("error! cannot support this logN");
			}
		}

		// 生成素数
		int generate_prime(uint64_t Np, int primeLen, bool is_use_pretable = false){                 
		    // int pbnd = 59;
			
		    N = 1 << Np;
            logN = Np;
            this->primeLen = primeLen;
		    rev = new int[N];
		    bitreverse();
			if (primeLen > 63){
				return 0;
			}
			
			uint64_t primetest = (1ULL << (primeLen-1)) + 1;

			if (!is_use_pretable){
				while(true) {
	                primetest += N << 1;
	                if(primeTest(primetest)) {
	                    pVec = (int64_t) primetest;
                        prVec = (static_cast<unsigned __int128>(1) << 2*(primeLen + 1)) / pVec;
                        invp = inver(pVec);
                        g = new uint64_t[N >> 1];
                        gi = new uint64_t[N >> 1]; 
											
						uint64_t root = findMthRootOfUnity(N, pVec, prVec);   // get prime N-root of mod
						uint64_t invroot = invMod(root, pVec);                // get inv prime N-root of mod

						uint64_t temp = static_cast<uint64_t>(1) << 32;
						g[0] = 1;
						mulModBarrett(g[0], g[0], temp, pVec, prVec);
						mulModBarrett(g[0], g[0], temp, pVec, prVec);
						gi[0] = g[0];

						for (int P = 1; P < N >> 1; P++){
							g[P] = REDC(g[P-1], root); 
							mulModBarrett(g[P], g[P], temp, pVec, prVec);
							mulModBarrett(g[P], g[P], temp, pVec, prVec);
							gi[P] = REDC(gi[P-1], invroot); 
							mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
							mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
						}

	                    inv = powMod(N, pVec - 2, pVec);                            //inv为len的逆元（费马小定理求逆元）
						mulModBarrett(inv, inv, temp, pVec, prVec);
						mulModBarrett(inv, inv, temp, pVec, prVec);
	                    break;
	                }
	            }
			}else{
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

				for (int P = 1; P < N >> 1; P++){
					g[P] = REDC(g[P-1], root); 
					mulModBarrett(g[P], g[P], temp, pVec, prVec);
					mulModBarrett(g[P], g[P], temp, pVec, prVec);
					gi[P] = REDC(gi[P-1], invroot); 
					mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
					mulModBarrett(gi[P], gi[P], temp, pVec, prVec);
				}
			}
			
			return 1;
		}

        uint64_t REDC(uint64_t a, uint64_t b){
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

            uint64_t* temp_a = new uint64_t[N];
            for (int i = 0; i < NLess2; i++)
            {
                temp_a[i] = (a[rev[2 * i]] + a[rev[2 * i + 1]]) % pVec;
                temp_a[i + NLess2] = (a[rev[2 * i]] - a[rev[2 * i + 1]] + pVec) % pVec;
            }
            memcpy(a, temp_a, sizeof(uint64_t)*N);
            for (int i = 1; i < logN; i++){
                int shift = logN - 1 - i;
                for (int j = 0; j < NLess2; j++){
                    int P = (j >> shift) << shift; 
                    uint64_t odd = REDC(a[2 * j + 1], g[P]);
                    temp_a[j] = (a[2 * j] + odd) % pVec;
                    temp_a[j + NLess2] = (a[2 * j] - odd + pVec) % pVec;
					
                }
                memcpy(a, temp_a, sizeof(uint64_t)*N);
            }
			delete[] temp_a;
		}

        void INTT(uint64_t *a)                                             //NTT，type=1, or is INTT
		{                
            int NLess2 = N >> 1;

            uint64_t* temp_a = new uint64_t[N];
            for (int i = 0; i < NLess2; i++)
            {
                temp_a[i] = (a[rev[2 * i]] + a[rev[2 * i + 1]]) % pVec;
                temp_a[i + NLess2] = (a[rev[2 * i]] - a[rev[2 * i + 1]] + pVec) % pVec;
            }
            
            memcpy(a, temp_a, sizeof(uint64_t)*N);

            for (int i = 1; i < logN; i++){
                int shift = logN - 1 - i;
                for (int j = 0; j < NLess2; j++){
                    int P = (j >> shift) << shift;  
                    uint64_t odd = REDC(a[2 * j + 1], gi[P]);
                    temp_a[j] = (a[2 * j] + odd) % pVec;
                    temp_a[j + NLess2] = (a[2 * j] - odd + pVec) % pVec;
                }
                memcpy(a, temp_a, sizeof(uint64_t)*N);		
            }
			delete[] temp_a;
            for (int i = 0; i < N; i++)
            {
				a[i] = REDC(a[i], inv);
            }
		}

		void fast_INTT(uint64_t *a) // NTT，type=1, or is INTT
		{
			int NLess2 = N >> 1;

			uint64_t temp_a[N];
			for (int i = 0; i < NLess2; i++)
			{
				temp_a[i] = (a[rev[2 * i]] + a[rev[2 * i + 1]]) % pVec;
				temp_a[i + NLess2] = (a[rev[2 * i]] - a[rev[2 * i + 1]] + pVec) % pVec;
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
					temp_a[j] = (a[2 * j] + odd) % pVec;
					temp_a[j + NLess2] = (a[2 * j] - odd + pVec) % pVec;
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
				a[i] = i % pVec;
				b[i] = (i+1) % pVec; // 输入第二个多项式
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