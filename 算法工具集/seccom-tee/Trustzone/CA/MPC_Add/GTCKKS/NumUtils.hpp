/**
 * @desc: 实现了几个用于同态加密中的噪声和密钥生成操作的函数
 * */
#include <vector>
#include <cassert>
#include <complex>
#include <iostream>
#include <random>

using namespace std;

namespace gtfhe{
	// 版本1 生成int64的东西
    /**
     * 生成具有高斯分布的噪声样本。该噪声通常用于同态加密中的加密过程，作为扰动或噪声。
     * */
	void samplesGauss(uint64_t* &e, size_t ploy_modulus_degree, double stdev, uint64_t qmod, int seed = 0){       // 产生噪声
		e = new uint64_t[ploy_modulus_degree];
		srand(seed);
		const double pi = 4*atan(1);
	    uint64_t bignum = 0xfffffff;
	    for (int i = 0; i < ploy_modulus_degree; i+=2)
	    {
	    	double r1 = (1 + (uint64_t)rand() % bignum) / ((double) bignum + 1);
	    	double r2 = (1 + (uint64_t)rand() % bignum) / ((double) bignum + 1);
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

    /**
     * 生成 Hamming Weight（HWT）为 h 的二进制向量。这种向量用于生成密钥。
     * */
	void samplesHWT(uint64_t* &s, size_t ploy_modulus_degree, const long h, uint64_t qmod, int seed = 0){        // 生成私钥
		s = new uint64_t[ploy_modulus_degree];
		srand(seed);

		for (int i = 0; i < ploy_modulus_degree; ++i)
		{
			s[i] = 0;
		}
		long idx = 0;

		while(idx < h){
			long i = ((double) rand() / (RAND_MAX)) * ploy_modulus_degree;
			if(s[i] == 0){
				long hwt = (rand() % 2) ? 1 : -1;
				s[i] = hwt >= 0 ? hwt : hwt + qmod;
				idx ++;
			}
		}
	}
    /**
     * 生成具有 零或一 值的随机向量（即向量中的元素值只能是 0 或 1）
     * */
	void samplesZO(uint64_t* &r, size_t ploy_modulus_degree,  uint64_t qmod, int seed = 0){                        // 生成随机01系数r
		r = new uint64_t[ploy_modulus_degree];
		srand(seed);

		for (int i = 0; i < ploy_modulus_degree; ++i)
		{
			long zo = (rand() % 2) == 0 ? 0 : (rand() % 2) ? 1 : -1;
			r[i] = zo >= 0 ? zo : zo + qmod;
		}
	}

    /**
     * 生成一个均匀分布的随机向量，元素值在 [0, qmod) 之间。
     * */
	void samplesUniform2(uint64_t* &a, size_t ploy_modulus_degree, uint64_t qmod, int seed = 0){    // 生成公钥 a
		a = new uint64_t[ploy_modulus_degree];
		srand(seed);

		for (int i = 0; i < ploy_modulus_degree; ++i)
		{
			a[i] = floor(((double) rand() / (RAND_MAX)) * qmod);
		}
	}

}