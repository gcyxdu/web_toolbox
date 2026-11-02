#include <vector>
#include <stdio.h>
#include <cmath>
#include <stdint.h>
#include "ciphertext.hpp"
#include "stringUtils.hpp"
#include "randomgen.h"


using namespace std;
using namespace gtfhe;

#ifndef ring_
#define ring_
namespace gtfhe
{
	class RingMultipliertest{
	public:	
		uint64_t pVec;                            //各个素数
		uint64_t g;                               //pvec的原根
		uint64_t gi;                              //pvec的原根的逆原
		uint64_t inv;                             //M的逆
		uint64_t N;                                //多项式次数
		uint64_t M;                                //二倍多项式次数
		int *rev;                                  //蝶形变幻的索引


		// 模乘运算
		void mulMod(uint64_t &r, uint64_t a, uint64_t b, uint64_t m) {
			unsigned __int128 mul = static_cast<unsigned __int128>(a) * b;
			mul %= static_cast<unsigned __int128>(m);
			r = static_cast<uint64_t>(mul);
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
		uint64_t findMthRootOfUnity(uint64_t M, uint64_t mod) {
		    uint64_t res;
		    res = get_prime_root(mod);
		    if((mod - 1) % M == 0) {
		        uint64_t factor = (mod - 1) / M;
		        res = powMod(res, factor, mod);
		        return res;
		    }
		    else {
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

		// bit反转， 蝶形变换
		void bitreverse(){
			for (int i = 0; i < M; ++i)
			{
				rev[i] = 0;
			}
		    for (int i = 0; i < M; ++i)                                  // get rev
		        rev[i] = (rev[i >> 1] >> 1) | ((i & 1) << (max((int)ceil(log2(M)), 1) - 1));
		}

		// 生成素数
		int generate_prime(uint64_t Np, int primeLen){                 
		    // int pbnd = 59;
		    N = 1 << Np;
		    M = N << 1;
		    rev = new int[M];
		    bitreverse();
			if (primeLen > 63){
				return 0;
			}
			uint64_t primetest = (1ULL << (primeLen-1)) + 1;
			while(true) {
	                primetest += M;
	                if(primeTest(primetest)) {
	                    pVec = (int64_t) primetest;
	                    g = get_prime_root(pVec);                       // get prime root of mod
	                    gi = invMod(g, pVec);                        // get inv prime root of mod
	                    inv = powMod(M, pVec - 2, pVec);             //inv为len的逆元（费马小定理求逆元）
	                    break;
	                }
	            }
			return 1;
		}

		// NTT
		void NTT(uint64_t *a, int type)                         //NTT，type=1, or is INTT
		{
		    int n = 2*N;
		    for (int i = 0; i < n; ++i)                                    // get a at last
		        if (i < rev[i])
		            swap(a[i], a[rev[i]]);
		    for (int i = 1; i < n; i <<= 1)
		    {                                                              
		        uint64_t gn = powMod(type ? g : gi, (pVec - 1) / (i << 1), pVec); //单位原根g_n
		        for (int j = 0; j < n; j += (i << 1))                      //枚举具体区间，j也就是区间右端点
		        {
		            uint64_t g0 = 1;
		            for (int k = 0; k < i; ++k, mulMod(g0, g0, gn, pVec)) //合并，记得要取模
		            {
		                uint64_t x = a[j + k];
		                uint64_t y;
		                mulMod(y, g0, a[i + j + k], pVec);
		                a[j + k] = (x + y) % pVec;
		                a[i + j + k] = (x - y + pVec) % pVec;
		            }
		        }
		    }
		}

		// 模除操作，乘逆元
		void divMod(int64_t* a, uint64_t* b, int index){                //除模，等于乘上模的逆
		    uint64_t temp = pVec >> 1;
			for (size_t i = 0; i < N; i++)
		    {
		        mulMod(b[i], b[i], inv, pVec);
		        mulMod(b[i+N], b[i+N], inv, pVec);
		        a[i] = (b[i] + b[i+N]) % pVec;
				if(a[i] > temp){
					a[i] = a[i] - pVec;
				}
		    }
		}

		// 暴力相乘
		void mult_raw(int64_t* c, uint64_t* a, uint64_t* b, uint64_t mod){
			uint64_t temp1 = pVec >> 1;
			for (size_t i = 0; i <  N; i++)
		    {
		        for (size_t j = 0; j < N; j++)
		        {
		            uint64_t temp = 0;
		            mulMod(temp, a[i], b[j], mod);
		            c[(i+j) % N] += temp;
		            c[(i+j) % N] %= mod;
		        }
		    }
			for (size_t i = 0; i < N; i++)
			{
				if(c[i] > temp1){
					c[i] = c[i] - pVec;
				}
			}
			
		}

		// 多项式暴力相乘测试
		void NTTtest1(){
		    uint64_t *a = new uint64_t[M];
		    uint64_t *b = new uint64_t[M];
		    for (int i = 0; i < N; ++i)                            //输入第一个多项式
		    {   
		        a[i] = i % pVec;
		        b[i] = (i+1) % pVec;								//输入第二个多项式		    
		    }

		    int64_t *c = new int64_t[N];
		    for (size_t i = 0; i < N; i++)
		    {   
		        a[N+i] = 0;
		        b[N+i] = 0;
		        c[i] = 0;
		    }
		    mult_raw(c, a, b, pVec);
		}

		// NTT测试
		void NTTtest2(){
			// printf("%llu\n",pVec[0]);
		    uint64_t *a = new uint64_t[M];
		    uint64_t *b = new uint64_t[M];
		    for (int i = 0; i < N; ++i)                            //输入第一个多项式
		    {   
		        a[i] = i % pVec;
		        b[i] = (i+1) % pVec;	     						//输入第二个多项式
		    }

		    int64_t *c = new int64_t[N];
		    for (size_t i = 0; i < N; i++)
		    {   
		        a[N+i] = 0;
		        b[N+i] = 0;
		        c[i] = 0;
		    }
			
		    NTT(a, 1);                                           //系数表示法转点值表示法
			NTT(b, 1);

		    for (int i = 0; i < M; ++i)
		        mulMod(a[i], a[i], b[i], pVec);                  //O(n)乘法
		    NTT(a, 0);                                           //点值表示法转系数表示法

		    int64_t* d = new int64_t[N];
		    divMod(d, a, 0);
		}

		void NTTtest3(){
			// printf("%llu\n",pVec[0]);
		    uint64_t *a = new uint64_t[M];
		    uint64_t *b = new uint64_t[M];

			UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>();
		    for (int i = 0; i < N; ++i)                            //输入第一个多项式
		    {   
		        a[i] = ran->generate() % pVec;
		        b[i] = ran->generate() % pVec;	     						//输入第二个多项式
		    }

		    int64_t *c = new int64_t[N];
		    for (size_t i = 0; i < N; i++)
		    {   
		        a[N+i] = 0;
		        b[N+i] = 0;
		        c[i] = 0;
		    }

			mult_raw(c, a, b, pVec);
			for (size_t i = 0; i < N; i++)
			{
				printf("%lld ", c[i]);	
			}
			
		    NTT(a, 1);                                           //系数表示法转点值表示法
			NTT(b, 1);

		    for (int i = 0; i < M; ++i)
		        mulMod(a[i], a[i], b[i], pVec);                  //O(n)乘法
		    printf("\n");
			NTT(a, 0);                                           //点值表示法转系数表示法

		    int64_t* d = new int64_t[N];
		    divMod(d, a, 0);
			for (int i = 0; i < N; ++i)
		    {
		    	printf("%lld ", d[i]);
		    }
		    printf("\n");
		}


		// 多项式加法 a+b
		void add(int64_t* &a, int64_t* b){
			for (size_t i = 0; i < N; i++)
			{
				a[i] = a[i] + b[i];
				if(a[i] >= 0){
					a[i] %= pVec; 
				}else{
					a[i] = pVec - (-a[i] % pVec);
				}
			}
		}

		void add(int64_t* &c, int64_t *a, int64_t *b){
			for (size_t i = 0; i < N; i++)
			{
				c[i] = (a[i] + b[i]);
				if(c[i] < 0){
					c[i] = pVec - (-c[i] % pVec);
				}
			}
		}
		
		// 多项式减法 a-b
		void sub(int64_t* a, int64_t* &b){
            for (size_t i = 0; i < N; i++)
			{
				b[i] = (a[i] - b[i]);
				if(b[i] < 0){
					b[i] = pVec - (-b[i] % pVec);
				}
			}
        }

		// 多项式乘法 a*b
        void mult(int64_t* &x, int64_t* a, int64_t* b) { 
			uint64_t* ra = new uint64_t[M];
			uint64_t* rb = new uint64_t[M];
			for (size_t i = 0; i < N; i++)
			{
				if(a[i] >= 0){
					ra[i] = a[i] % pVec;
				}else{
					ra[i] = pVec - (-a[i] % pVec);
				}
				if(b[i] >= 0){
					rb[i] = b[i] % pVec;
				}else{
					rb[i] = pVec - (-b[i] % pVec);
				}
				ra[i+N] = 0;
				rb[i+N] = 0;
			}
			
			NTT(ra, 1);                                           //系数表示法转点值表示法
			NTT(rb, 1);
			for (int i = 0; i < M; ++i)
		        mulMod(ra[i], ra[i], rb[i], pVec);                  //O(n)乘法
		    
			NTT(ra, 0);                                           //点值表示法转系数表示法

		    x = new int64_t[N];
		    divMod(x, ra, 0);
		}

	};	
}

#endif