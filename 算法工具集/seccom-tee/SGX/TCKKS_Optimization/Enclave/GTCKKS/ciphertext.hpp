#include <stdint.h>
#include <vector>
#include<cstring>

#ifndef ciphertext_
#define ciphertext_
namespace gtfhe{

	class Ciphertext{
    public:
    	uint64_t* c0;
        uint64_t* c1;
        size_t ploy_modulus_degree;
        size_t length;
        size_t scale_factor;

        Ciphertext(){
        }

        Ciphertext(uint64_t *t1, uint64_t *t2, size_t ploy_modulus_degree){
            c0 = t1;
            c1 = t2;
            this->ploy_modulus_degree = ploy_modulus_degree;
        }

    };

}


#endif