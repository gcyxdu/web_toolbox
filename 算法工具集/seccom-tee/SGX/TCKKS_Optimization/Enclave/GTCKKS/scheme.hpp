#include "sgx_trts.h"
#include "stdio.h"
#include "NumUtils.hpp"
// #include "Ringmultiplier.hpp"
#include "CTRingMultiplier.hpp"
#include "ciphertext.hpp"
#include "plaintext.hpp"

using namespace gtfhe;
using namespace std;

namespace gtfhe
{
	class Scheme
    {
	public:
		RingMultipliertest multiple; // 乘法器
		size_t ploy_modulus_degree;	 // 多项式最高次数
		size_t scale = 20;			 // 放缩因子
		uint64_t qmod;				 // 大模数
		uint64_t *s;				 // 私钥
		uint64_t *a;				 // 公钥a
		uint64_t *b;				 // 公钥b
		Ciphertext *ciphers;         // 预先计算好的密码本
		size_t cur_cipher = 0;       
		size_t ciphers_num = 100;

		Scheme(){
		}

		void scheme_Init(size_t ploy_Lenth, void* s, void* a, void* b){
			this->ploy_modulus_degree = 1 << ploy_Lenth;
			this->scale = 20;
			multiple.generate_prime(ploy_Lenth, 60, true); // 生成相关的素数
			qmod = multiple.pVec;

			this->s = (uint64_t*) s;
			this->a = (uint64_t*) a;
			this->b = (uint64_t*) b;
			this->ciphers_num = 10;
			ciphers =  new Ciphertext[this->ciphers_num];
			for (size_t i = 0; i < this->ciphers_num; i++)
			{
				init_pre_cipher(ciphers[i], i);
			}
			

		}

		// 构造公私钥
		Scheme(size_t ploy_Lenth, int primeLen, size_t scale = 40, size_t ciphers_num = 100, size_t pre_s = 0){
			this->ploy_modulus_degree = 1 << ploy_Lenth;
			this->scale = scale;
			multiple.generate_prime(ploy_Lenth, primeLen, true); // 生成相关的素数
			qmod = multiple.pVec;
			samplesHWT(s, ploy_modulus_degree, 64, qmod);  // 创建私钥
			samplesUniform2(a, ploy_modulus_degree, qmod); // 创建公钥a
			uint64_t *e;
			samplesGauss(e, ploy_modulus_degree, 3.2, qmod);
			multiple.NTT(s);
			multiple.NTT(a);

			multiple.NTT(e);
			multiple.mult(b, a, s);
			multiple.sub(e, b);
			if (pre_s == 1)
			{
				multiple.pre_handle_s(s);
			}
			this->ciphers_num = ciphers_num;
			ciphers = new Ciphertext[ciphers_num];
			for (int i = 0; i < ciphers_num; i++)
			{
				init_pre_cipher(ciphers[i], i);
			}
			delete[] e;
		}

		void Simpleencode(double *v, Plaintext &plaintext, size_t slots)
		{
			plaintext.length = slots;
			plaintext.coffe_data = new uint64_t[ploy_modulus_degree];
			int64_t p = 1 << scale;
			for (size_t i = 0; i < ploy_modulus_degree; i++)
			{
				if (i < slots)
				{
					int64_t temp = (int64_t)(v[i] * p);
					plaintext.coffe_data[i] = (temp >= 0) ? (uint64_t)temp : ((uint64_t)(temp + qmod));
				}
				else
				{
					plaintext.coffe_data[i] = 0;
				}
			}
		}

		void Simpleencode(int64_t *v, Plaintext &plaintext, size_t slots)
		{
			plaintext.length = slots;
			plaintext.coffe_data = new uint64_t[ploy_modulus_degree];
			int64_t p = 1 << scale;
			for (size_t i = 0; i < ploy_modulus_degree; i++)
			{
				if (i < slots)
				{
					int64_t temp = v[i] * p;
					plaintext.coffe_data[i] = temp >= 0 ? (uint64_t)temp : ((uint64_t)(temp + qmod));
				}
				else
				{
					plaintext.coffe_data[i] = 0;
				}
			}
		}

		double *Simpledecode(uint64_t *msg, long slots)
		{
			double *res = new double[slots];
			int64_t p = 1 << scale;
			uint64_t pr_2 = qmod >> 1;
			for (size_t i = 0; i < slots; i++)
			{
				res[i] = msg[i] <= pr_2 ? ((double)(msg[i]) / p) : (((double)(msg[i]) - (double)(qmod)) / p);
			}
			return res;
		}

		void add(Ciphertext &cipher, Ciphertext cipher1, Ciphertext cipher2)
		{
			cipher.scale_factor = scale;
			cipher.length = cipher1.length;
			cipher.ploy_modulus_degree = ploy_modulus_degree;
			cipher.c0 = new uint64_t[ploy_modulus_degree];
			cipher.c1 = new uint64_t[ploy_modulus_degree];

			multiple.add(cipher.c0, cipher1.c0, cipher2.c0);
			multiple.add(cipher.c1, cipher1.c1, cipher2.c1);
		}


		void Simple_encrypt(Ciphertext &cipher, Plaintext plaintext)
		{
			cipher.scale_factor = scale;
			cipher.length = plaintext.length;
			cipher.ploy_modulus_degree = ploy_modulus_degree;
			uint64_t *r;
			samplesZO(r, ploy_modulus_degree, qmod);
			multiple.NTT(r);

			// (br + m0 + e0, ar + e1)
			// multiple.mult();
			multiple.mult_poly(cipher.c0, b, r);
			multiple.mult(cipher.c1, a, r);

			uint64_t *e0;
			uint64_t *e1;
			samplesGauss(e0, ploy_modulus_degree, 3.2, qmod);
			samplesGauss(e1, ploy_modulus_degree, 3.2, qmod);
			// multiple.NTT(e0);
			multiple.NTT(e1);

			multiple.add(cipher.c0, e0);
			multiple.add(cipher.c1, e1);

			multiple.add(cipher.c0, plaintext.coffe_data);

			delete[] r;
			delete[] e0;
			delete[] e1;
		}

		void async_encrypt(Ciphertext &cipher, Plaintext plaintext)
		{
			cipher.c0 = this->ciphers[this->cur_cipher].c0;
			cipher.c1 = this->ciphers[this->cur_cipher].c1;
			cipher.ploy_modulus_degree = this->ciphers[this->cur_cipher].ploy_modulus_degree;
			cipher.scale_factor = this->ciphers[this->cur_cipher].scale_factor;
			cipher.length = plaintext.length;
			multiple.add(cipher.c0, plaintext.coffe_data);
			this->cur_cipher = (this->cur_cipher + 1) % this->ciphers_num;
		}

		void Simple_decrypt(Plaintext &plaintext, Ciphertext cipher)
		{
			plaintext.length = cipher.length;

			multiple.mult_poly(plaintext.coffe_data, cipher.c1, s);

			multiple.add(plaintext.coffe_data, cipher.c0);
		}
		
		void fast_Simple_decrypt(Plaintext &plaintext, Ciphertext cipher)
		{
			plaintext.length = cipher.length;
			multiple.fast_mult_poly(plaintext.coffe_data, cipher.c1, s);

			multiple.add(plaintext.coffe_data, cipher.c0);
		}

		void init_pre_cipher(Ciphertext &cipher, size_t seed)
		{
			cipher.scale_factor = scale;
			cipher.ploy_modulus_degree = ploy_modulus_degree;
			uint64_t *r;
			samplesZO(r, ploy_modulus_degree, qmod);
			multiple.NTT(r);

			// (br + m0 + e0, ar + e1)
			// multiple.mult();
			multiple.mult_poly(cipher.c0, b, r);
			multiple.mult(cipher.c1, a, r);

			uint64_t *e0;
			uint64_t *e1;
			samplesGauss(e0, ploy_modulus_degree, 3.2, qmod);
			samplesGauss(e1, ploy_modulus_degree, 3.2, qmod);
			multiple.NTT(e1);

			multiple.add(cipher.c0, e0);
			multiple.add(cipher.c1, e1);
		}
	};
}