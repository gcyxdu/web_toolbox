#include <vector>
#include <cassert>
#include <complex>
#include <iostream>
#include "randomgen.h"

using namespace std;
using namespace gtfhe;

namespace gtfhe{
	// 版本1 生成int64的东西
	void samplesGauss(uint64_t* &e, size_t ploy_modulus_degree, double stdev, uint64_t qmod){       // 产生噪声
		e = new uint64_t[ploy_modulus_degree];
		const double pi = 4*atan(1);
	    uint64_t bignum = 0xfffffff;
	    UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>(0, bignum);
	    for (int i = 0; i < ploy_modulus_degree; i+=2)
	    {
	    	double r1 = (1 + ran->generate()) / ((double) bignum + 1);
	    	double r2 = (1 + ran->generate()) / ((double) bignum + 1);
	    	double theta = 2 * pi * r1;
	    	double rr = sqrt(-2 * log(r2)) * stdev;
	    	assert(rr < 8 * stdev);
	    	int64_t g1 = (int64_t) floor(rr * cos(theta) + 0.5);
			int64_t g2 = (int64_t) floor(rr * sin (theta) + 0.5);

	    	e[i] = g1 >= 0 ? g1 : g1 + qmod;
	    	if(i+1 < ploy_modulus_degree){
	    		e[i+1] = g2 >= 0 ? g2 : g2 + qmod;
	    	}
	    }
	}

	long bit(long a, long k)
	{
	   unsigned long aa;
	   if (a < 0)
	      aa = - ((unsigned long) a);
	   else
	      aa = a;

	   if (k < 0 || k >= 64) 
	      return 0;
	   else
	      return long((aa >> k) & 1);
	}

	void samplesHWT(uint64_t* &s, size_t ploy_modulus_degree, const long h, uint64_t qmod){        // 生成私钥
		s = new uint64_t[ploy_modulus_degree];
		long idx = 0;
		uint64_t tmp;
		sgx_read_rand((unsigned char *) &tmp, 8);
		for (int i = 0; i < ploy_modulus_degree; ++i)
		{
			s[i] = 0;
		}
		UniformRandomGenerator *ran = new StandardRandomAdapter<random_device>(0, ploy_modulus_degree);
		while(idx < h){
			long i = ran->generate() % ploy_modulus_degree;
			if(s[i] == 0){
				long hwt = (bit((int64_t) tmp, idx) == 0) ? 1 : -1;
				s[i] = hwt >= 0 ? hwt : hwt + qmod;
				idx ++;
			}
		}
	}

	void samplesZO(uint64_t* &r, size_t ploy_modulus_degree, uint64_t qmod){                        // 生成随机01系数r
		r = new uint64_t[ploy_modulus_degree];
		uint64_t tmp;
		sgx_read_rand((unsigned char *) &tmp, 8);
		for (int i = 0; i < ploy_modulus_degree; ++i)
		{
			long zo = (bit((int64_t) tmp, 2 * i) == 0) ? 0 : (bit((int64_t) tmp, 2*i + 1) == 0) ? 1 : -1;
			r[i] = zo >= 0 ? zo : zo + qmod;
		}
	}

	void samplesUniform2(uint64_t* &a, size_t ploy_modulus_degree, uint64_t qmod){    // 生成公钥 a
		a = new uint64_t[ploy_modulus_degree];
		uint64_t tmp;
		for (int i = 0; i < ploy_modulus_degree; ++i)
		{
			sgx_read_rand((unsigned char *) &tmp, 8);
			a[i] = floor(((double) tmp / (RAND_MAX)) * qmod);
		}
	}


}