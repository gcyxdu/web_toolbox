/**
 * @desc:这段代码定义了一个同态加密的方案，里面的成员变量具体的内容都是方案的参数，同时预生成了密码本的内容
 *
 * */
#include "stdio.h"
#include "NumUtils.hpp"
#include "CTRingMultiplier.hpp"
#include "ciphertext.hpp"
#include "plaintext.hpp"
#include "tee_client_api.h"

using namespace gtfhe;
using namespace std;

/*------------------------------------------------*/
// 定义invoke调用的内容
enum {
    // 定义调用函数
    init = 0,
    send_ciphertext,
    ecall_batchtrans_information,
    decodeEncrypt,
    secure_sum
};
extern TEEC_Session g_session;
/*------------------------------------------------*/

namespace gtfhe
{
    /**----------------------在命名空间但是没有类里面的方法------------------------*/
    TEEC_Result invoke_send_ciphertext(void *c01, void *c11, void *c00, void *c10,size_t length){

        TEEC_Operation operation;
        TEEC_Result result;

        uint32_t origin;
        // 启动这次操作
        operation.started = 1;

        operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_MEMREF_TEMP_INOUT
        );

        operation.params[0].tmpref.buffer = c01;
        operation.params[0].tmpref.size = length;
        operation.params[1].tmpref.buffer = c11;
        operation.params[1].tmpref.size = length;
        operation.params[2].tmpref.buffer = c00;
        operation.params[2].tmpref.size = length;
        operation.params[3].tmpref.buffer = c10;
        operation.params[3].tmpref.size = length;

        // 打印调用前后的值的对比：
//        for(int i= 0 ; i < 10 ; ++i){
//            printf("c01:[%lu]\n",((uint64_t *)c01)[i]);
//            printf("c11:[%lu]\n",((uint64_t *)c11)[i]);
//            printf("c00:[%lu]\n",((uint64_t *)c00)[i]);
//            printf("c10:[%lu]\n",((uint64_t *)c10)[i]);
//            printf("---------------------\n");
//        }
        result = TEEC_InvokeCommand(&g_session,send_ciphertext,&operation,&origin);
        // 打印调用前后的值的对比：
        printf("\n\n\n");

//        for(int i= 0 ; i < 10 ; ++i){
//            printf("c01:[%lu]\n",((uint64_t *)c01)[i]);
//            printf("c11:[%lu]\n",((uint64_t *)c11)[i]);
//            printf("c00:[%lu]\n",((uint64_t *)c00)[i]);
//            printf("c10:[%lu]\n",((uint64_t *)c10)[i]);
//            printf("---------------------\n");
//
//        }
        if (result != TEEC_SUCCESS) {
            printf("invoke invoke_send_ciphertext failed, codes=0x%x, origin=0x%x\bn", result, origin);
            return result;
        }
        return result;
    }
    TEEC_Result invoke_ecall_batchtrans_information(void * mulMessage,size_t length){

        TEEC_Operation operation;
        TEEC_Result result;

        uint32_t origin;
        // 启动这次操作
        operation.started = 1;

        operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_NONE,
                TEEC_NONE,
                TEEC_NONE
        );

        operation.params[0].tmpref.buffer = mulMessage;
        operation.params[0].tmpref.size = length;
        result = TEEC_InvokeCommand(&g_session,ecall_batchtrans_information,&operation,&origin);

        if (result != TEEC_SUCCESS) {
            printf("invoke invoke_ecall_batchtrans_information failed, codes=0x%x, origin=0x%x\n", result, origin);
            return result;
        }
        return result;
    }
    TEEC_Result invoke_decodeEncrypt(void* batchCipher0, void* batchCipher1, void* mulMessage,size_t length){

        TEEC_Operation operation;
        TEEC_Result result;

        uint32_t origin;
        // 启动这次操作
        operation.started = 1;

        operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_NONE
        );

        operation.params[0].tmpref.buffer = batchCipher0;
        operation.params[0].tmpref.size = length;
        operation.params[1].tmpref.buffer = batchCipher1;
        operation.params[1].tmpref.size = length;
        operation.params[2].tmpref.buffer = mulMessage;
        operation.params[2].tmpref.size = length;

        result = TEEC_InvokeCommand(&g_session,decodeEncrypt,&operation,&origin);
        if (result != TEEC_SUCCESS) {
            printf("invoke invoke_decodeEncrypt failed, codes=0x%x, origin=0x%x\n", result, origin);
            return result;
        }
        return result;
    }
    /**-----------------------------------------------------*/
	class Scheme
	{
	public:
		RingMultipliertest multiple; // 乘法器
		size_t ploy_modulus_degree;	 // 多项式最高次数
		size_t scale = 40;			 // 放缩因子
		uint64_t qmod;				 // 大模数
		uint64_t *s;				 // 私钥
		uint64_t *a;				 // 公钥a
		uint64_t *b;				 // 公钥b
		Ciphertext *ciphers;   // 预先计算好的密码本
		size_t cur_cipher = 0; //
		size_t ciphers_num = 100;
		// 构造公私钥
		Scheme(size_t ploy_Lenth, int primeLen, size_t scale = 40, size_t ciphers_num = 100, size_t pre_s = 0)
		{
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
//            printf("cipher1:");
//            printf_ploy(ciphers[0].c0,ploy_modulus_degree);
//            printf_ploy(ciphers[0].c1,ploy_modulus_degree);
//            printf("cipher1:");
//
//            printf_ploy(ciphers[1].c0,ploy_modulus_degree);
//            printf_ploy(ciphers[1].c1,ploy_modulus_degree);
            delete[] e;
           /* // 打印参数：
            printf("scheme->ploy_modulus_degree:%zu\n",ploy_modulus_degree);
            printf("scheme->qmod:%lu\n",qmod);
            // 打印multiple里面的所有的内容
            printf("scheme->multiple->pVec:%lu\n",multiple.pVec);
            printf("scheme->multiple->prVec:%lu\n",multiple.prVec);
            printf("scheme->multiple->invp:%lu\n",multiple.invp);
            printf("scheme->multiple->inv:%lu\n",multiple.inv);
            printf("scheme->multiple->N:%lu\n",multiple.N);
            printf("scheme->multiple->logN:%lu\n",multiple.logN);
            printf("scheme->multiple->M:%lu\n",multiple.M);
            printf("scheme->multiple->primeLen:%d\n",multiple.primeLen);
            // s,a,b的前三个值
            printf("s,a,b:\n");
            for(int i = 0 ; i < 3 ; ++i){
                printf("%lu,%lu,%lu\n",s[i],a[i],b[i]);
            }*/
		}

		void IFFTencode(double *v, Plaintext &plaintext, size_t slots)
		{
			plaintext.length = slots;
			multiple.IFFTencode(plaintext.coffe_data, v, slots, scale);
		}

		void IFFTencode(complex<double> *v, Plaintext &plaintext, size_t slots)
		{
			plaintext.length = slots;
			multiple.IFFTencode(plaintext.coffe_data, v, slots, scale);
		}

		complex<double> *IFFTdecode(uint64_t *msg, long slots)
		{
			complex<double> *res = new complex<double>[slots]();
			multiple.IFFTdecode(msg, res, slots, scale);
			return res;
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

		// CKKS加密
		void IFFTencrypt(Ciphertext &cipher, Plaintext plaintext)
		{
			cipher.scale_factor = scale;
			cipher.length = plaintext.length;
			cipher.ploy_modulus_degree = ploy_modulus_degree;
			uint64_t *r;
			samplesZO(r, ploy_modulus_degree, qmod);
			multiple.NTT(r);

			// (br + m0 + e0, ar + e1)
			multiple.mult(cipher.c0, b, r);
			multiple.mult(cipher.c1, a, r);

			uint64_t *e0;
			uint64_t *e1;
			samplesGauss(e0, ploy_modulus_degree, 3.2, qmod);
			samplesGauss(e1, ploy_modulus_degree, 3.2, qmod);
			multiple.NTT(e0);
			multiple.NTT(e1);

			multiple.add(cipher.c0, e0);
			multiple.add(cipher.c1, e1);
			multiple.add(cipher.c0, plaintext.coffe_data);

			delete[] r;
			delete[] e0;
			delete[] e1;
		}

		void IFFTdecrypt(Plaintext &plaintext, Ciphertext cipher)
		{
			plaintext.length = cipher.length;

			multiple.mult(plaintext.coffe_data, cipher.c1, s);

			multiple.add(plaintext.coffe_data, cipher.c0);
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
        void add(Ciphertext &cipher, uint64_t* randnumber, int len)
        {
            for (size_t i = 0; i < len; i++)
            {
                cipher.c0[i] += randnumber[i];
            }

        }
        void add(Ciphertext &cipher, ::uint64_t * temp)
        {
            multiple.add(cipher.c0, temp);
        }

        // 定义两个密文文本的
		void IFFTmul(Ciphertext &cipher, Ciphertext cipher1, Ciphertext cipher2)
		{
			Plaintext plaintext1;
			Plaintext plaintext2;
			IFFTdecrypt(plaintext1, cipher1);
			IFFTdecrypt(plaintext2, cipher2);
			complex<double> *reMul1 = IFFTdecode(plaintext1.coffe_data, plaintext1.length);
			complex<double> *reMul2 = IFFTdecode(plaintext2.coffe_data, plaintext2.length);

			complex<double> *reMul = new complex<double>[plaintext1.length]();
			for (size_t i = 0; i < plaintext1.length; i++)
			{
				reMul[i] = reMul1[i] * reMul2[i];
			}
			printf("mul result:\n");
			printf_vector(reMul, plaintext1.length);

			IFFTencode(reMul, plaintext1, plaintext1.length);

			IFFTencrypt(cipher, plaintext1);
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
        void print_unsigned_int128(unsigned __int128 value) {
            uint64_t low = static_cast<uint64_t>(value);  // 低64位
            uint64_t high = static_cast<uint64_t>(value >> 64);  // 高64位

            std::cout << "High: " << high << ", Low: " << low << std::endl;
        }
		void secure_mul_protocol(Ciphertext &ciphertext3, Ciphertext ciphertext1, Ciphertext ciphertext2){
			// step 0. generate random masks
			uint64_t* P = new  uint64_t[ploy_modulus_degree];
			uint64_t scalefactor = 1 << scale;
			uint64_t* t2 = new uint64_t[ploy_modulus_degree];

			for (size_t i = 0; i < ploy_modulus_degree; i++)
			{
				P[i] = qmod - (rand() % 10000);
				t2[i] = (rand() % 10000) * (scalefactor);
			}
			uint64_t* temp1 = new uint64_t[ploy_modulus_degree];
			uint64_t* temp2 = new uint64_t[ploy_modulus_degree];
            uint64_t* p1 = new uint64_t[ploy_modulus_degree];
            uint64_t* p2 = new uint64_t[ploy_modulus_degree];
			for (size_t i = 0; i < ploy_modulus_degree; i++)
			{
                p1[i] = P[i]*(rand()%10);
                p2[i] = P[i]*(rand()%10);
				temp1[i] = ciphertext1.c0[i] + p1[i];
				temp2[i] = ciphertext2.c0[i] + p2[i];
			}
			invoke_send_ciphertext(ciphertext1.c1, ciphertext2.c1, temp1, temp2,ploy_modulus_degree * sizeof(uint64_t));
			unsigned __int128* mulMessage = new unsigned __int128[ploy_modulus_degree];
            invoke_ecall_batchtrans_information(mulMessage,ploy_modulus_degree * sizeof(unsigned __int128));
			uint64_t* batchCipher = new uint64_t[ploy_modulus_degree];
			for (size_t i = 0; i < ploy_modulus_degree; i++)
			{
				multiple.Modshift(batchCipher[i], mulMessage[i], P[i], scale);
				batchCipher[i] = ((float) batchCipher[i] / scalefactor) * scalefactor;
			}
			multiple.add(batchCipher, t2);
			ciphertext3.ploy_modulus_degree = ploy_modulus_degree;
			ciphertext3.c0 = new uint64_t[ploy_modulus_degree];
			ciphertext3.c1 = new uint64_t[ploy_modulus_degree];
			ciphertext3.scale_factor = scale;
			ciphertext3.length = ciphertext1.length;
            invoke_decodeEncrypt(ciphertext3.c0, ciphertext3.c1, batchCipher,ploy_modulus_degree * sizeof(uint64_t));
			multiple.sub(ciphertext3.c0, ciphertext3.c0, t2);
		}

        // TODO 密码本相同，seed参数未使用
		void init_pre_cipher(Ciphertext &cipher, size_t seed)
		{
			cipher.scale_factor = scale;
			cipher.ploy_modulus_degree = ploy_modulus_degree;
			uint64_t *r;
			samplesZO(r, ploy_modulus_degree, qmod);
			multiple.NTT(r);

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