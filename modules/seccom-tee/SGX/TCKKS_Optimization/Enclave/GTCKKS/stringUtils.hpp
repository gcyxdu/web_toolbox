#include <stdlib.h>
#include <vector>
#include <complex>

using namespace std;

#ifndef stringutils_
#define stringutils_
namespace gtfhe
{
    void printf_vector(vector<int64_t> value){
        if (value.size() > 10)
        {
            printf("[%lld, ", value[0]);
            printf("%lld, ", value[1]);
            printf("%lld, ", value[2]);
            printf("......,");
            printf("%lld, ", value[value.size()-2]);
            printf("%lld]\n", value[value.size()-1]);
        }else{
            printf("[%lld", value[0]);
            for (int i = 1; i < value.size(); ++i)
            {
                printf(", %lld", value[i]);
            }
            printf("]\n");
        }
    }

    void printf_vector(vector<double> value){
        if (value.size() > 10)
        {
            printf("[%lf, ", value[0]);
            printf("%lf, ", value[1]);
            printf("%lf, ", value[2]);
            printf("......,");
            printf("%lf, ", value[value.size()-2]);
            printf("%lf]\n", value[value.size()-1]);
        }else{
            printf("[%lf", value[0]);
            for (int i = 1; i < value.size(); ++i)
            {
                printf(", %lf", value[i]);
            }
            printf("]\n");
        }
    }

    void printf_vector(double* value, size_t slots){
        if (slots > 10)
        {
            printf("[%lf, ", value[0]);
            printf("%lf, ", value[1]);
            printf("%lf, ", value[2]);
            printf("......,");
            printf("%lf, ", value[slots-2]);
            printf("%lf]\n", value[slots-1]);
        }else{
            printf("[%lf", value[0]);
            for (int i = 1; i < slots; ++i)
            {
                printf(", %lf", value[i]);
            }
            printf("]\n");
        }
    }

    void printf_vector(complex<double>* value, size_t slots){
        if (slots > 10)
        {
            printf("[(%f, %f), ", value[0].real(), value[0].imag());
            printf("(%f, %f), ", value[1].real(), value[1].imag());
            printf("(%f, %f), ", value[2].real(), value[2].imag());
            printf("......,");
            printf("(%f, %f), ", value[slots - 2].real(), value[slots - 2].imag());
            printf("(%f, %f)]\n", value[slots - 1].real(), value[slots - 1].imag());
        }else{
            printf("[%lf", value[0]);
            for (int i = 1; i < slots; ++i)
            {
                printf("(%f, %f), ", value[i].real(), value[i].imag());
            }
            printf("]\n");
        }
    }

    void printf_ploy(uint64_t* value, size_t ploy_modulus_degree){
        if (ploy_modulus_degree > 10)
        {
            printf("%llu ", value[0]);
            printf("+ %llux^(1) ", value[1]);
            printf("+ %llux^(2) ", value[2]);
            printf("......,");
            printf("+ %llux^(%d) ", value[ploy_modulus_degree-2], ploy_modulus_degree-2);
            printf("+ %llux^(%d)\n", value[ploy_modulus_degree-1], ploy_modulus_degree-1);
        }else{
            printf("%llu ", value[0]);
            for (int i = 1; i < ploy_modulus_degree; ++i)
            {
                printf("+ %llux^(%d) ", value[i], i);
            }
            printf("\n");
        }
    }

    void printf_ploy(int64_t* value, size_t ploy_modulus_degree){
        if (ploy_modulus_degree > 10)
        {
            printf("%lld ", value[0]);
            printf("+ %lldx^(1) ", value[1]);
            printf("+ %lldx^(2) ", value[2]);
            printf("......,");
            printf("+ %lldx^(%d) ", value[ploy_modulus_degree-2], ploy_modulus_degree-2);
            printf("+ %lldx^(%d)\n", value[ploy_modulus_degree-1], ploy_modulus_degree-1);
        }else{
            printf("%lld ", value[0]);
            for (int i = 1; i < ploy_modulus_degree; ++i)
            {
                printf("+ %lldx^(%d) ", value[i], i);
            }
            printf("\n");
        }
    }

}
#endif