#include "stringUtils.h"
#include <stdio.h>

void printf_vector_int64_t(int64_t* value, size_t size){
    if (size > 10) {
        printf("[%ld, ", value[0]);
        printf("%ld, ", value[1]);
        printf("%ld, ", value[2]);
        printf("......,");
        printf("%ld, ", value[size-2]);
        printf("%ld]\n", value[size-1]);
    } else {
        printf("[%ld", value[0]);
        for (size_t i = 1; i < size; ++i) {
            printf(", %ld", value[i]);
        }
        printf("]\n");
    }
}

void printf_vector_double(double* value, size_t size){
    if (size > 10) {
        printf("[%lf, ", value[0]);
        printf("%lf, ", value[1]);
        printf("%lf, ", value[2]);
        printf("......,");
        printf("%lf, ", value[size-2]);
        printf("%lf]\n", value[size-1]);
    } else {
        printf("[%lf", value[0]);
        for (size_t i = 1; i < size; ++i) {
            printf(", %lf", value[i]);
        }
        printf("]\n");
    }
}

void printf_ploy_int64_t(int64_t* value, size_t ploy_modulus_degree){
    if (ploy_modulus_degree > 10) {
        printf("%ld ", value[0]);
        printf("+ %ldx^(1) ", value[1]);
        printf("+ %ldx^(2) ", value[2]);
        printf("......,");
        printf("+ %ldx^(%zu) ", value[ploy_modulus_degree-2], ploy_modulus_degree-2);
        printf("+ %ldx^(%zu)\n", value[ploy_modulus_degree-1], ploy_modulus_degree-1);
    } else {
        printf("%ld ", value[0]);
        for (size_t i = 1; i < ploy_modulus_degree; ++i) {
            printf("+ %ldx^(%zu) ", value[i], i);
        }
        printf("\n");
    }
}

void printf_ploy_uint64_t(uint64_t* value, size_t ploy_modulus_degree){
    if (ploy_modulus_degree > 10) {
        printf("%lu ", value[0]);
        printf("+ %lu x^(1) ", value[1]);
        printf("+ %lu x^(2) ", value[2]);
        printf("......,");
        printf("+ %lu x^(%zu) ", value[ploy_modulus_degree-2], ploy_modulus_degree-2);
        printf("+ %lu x^(%zu)\n", value[ploy_modulus_degree-1], ploy_modulus_degree-1);
    } else {
        printf("%lu ", value[0]);
        for (size_t i = 1; i < ploy_modulus_degree; ++i) {
            printf("+ %lu x^(%zu) ", value[i], i);
        }
        printf("\n");
    }
}
