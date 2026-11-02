#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX
#include <sys/time.h>
#include <mutex>
#include <condition_variable>
#include <complex>
#include <iostream>
#include <vector>
#include <random> 
#include <atomic>  
#include "App.h"
#include "func.h"
#include "base_secure_protocols.h"
#include "epo_snn_64.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "calculate/basicSockets.h"  
#include <future>
#include <chrono>
#include <thread>
#include <cstdint>
using namespace std;




void generate_random_array_64(uint64_t* array, int size, uint32_t seed, uint64_t max_val) {
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<uint64_t> dist(0, max_val);
    for (int i = 0; i < size; i++) {
        array[i] = dist(rng);
    }
}


void get_INVSQRT_STEEP_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b);
void get_INVSQRT_FLAT_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b);
static void get_RECIP_STEEP_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b);
static void get_RECIP_BASE_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b);

uint64_t secure_truncate(uint64_t value, int shift_bits) {
    if (value < (1ULL << 63)) {
        
        return value >> shift_bits;
    } else {
        
        uint64_t complement = UINT64_MAX - value + 1;  
        uint64_t truncated = complement >> shift_bits; 
        return UINT64_MAX - truncated + 1;  
    }
}

static inline uint64_t multiply_public_fixed_share(uint64_t public_coeff, uint64_t share, int shift_bits) {
    __int128 coeff_signed = static_cast<__int128>(static_cast<int64_t>(public_coeff));
    __int128 share_signed = static_cast<__int128>(static_cast<int64_t>(share));
    __int128 product = coeff_signed * share_signed;
    __int128 magnitude = (product < 0) ? -product : product;
    __int128 shifted = magnitude >> shift_bits;
    if (product < 0) shifted = -shifted;
    return static_cast<uint64_t>(static_cast<int64_t>(shifted));
}



void generate_and_map_random(uint64_t* target_buf, uint64_t count, uint64_t seed, uint64_t scale, int bound_coeff) {
    uint64_t state = seed;
    const uint64_t MULTIPLIER = 6364136223846793005ULL;
    const uint64_t INCREMENT = 1442695040888963407ULL;
    uint64_t range_width = (uint64_t)bound_coeff * scale * 2;
    uint64_t offset = (uint64_t)bound_coeff * scale;

    for (uint64_t i = 0; i < count; i++) {
        state = state * MULTIPLIER + INCREMENT;
        uint64_t raw_val = state;
        if (raw_val == 0) raw_val = 1;
        uint64_t mod_val = raw_val % range_width;
        int64_t signed_val = (int64_t)mod_val - (int64_t)offset;
        target_buf[i] = (uint64_t)signed_val; 
    }
}

#include <cstdint>
#include <cstdio>
#include <cmath>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>


static const uint64_t SCALE_20 = 1048576;






static const uint64_t SIGMOID_A_0_6[] = { 524288 }; 
static const uint64_t SIGMOID_B_0_6[] = { 
    595794, 18446744073709455121ULL, 131565, 18446744073709474133ULL, 68443, 18446744073709496503ULL 
};
static const uint64_t SIGMOID_B_0_12[] = { 
    595794, 18446744073709455121ULL, 131565, 18446744073709474133ULL, 68443, 18446744073709496503ULL,
    47800, 18446744073709509944ULL, 37073, 18446744073709513667ULL, 30323, 18446744073709519218ULL
};


static const uint64_t SIGMOID_A_1_1[] = { 524288, 56522 }; 
static const uint64_t SIGMOID_B_1_1[] = { 307931 };

static const uint64_t SIGMOID_A_1_4[] = { 524288, 65741 }; 
static const uint64_t SIGMOID_B_1_4[] = { 260979, 70911, 19960, 6224 };

static const uint64_t SIGMOID_A_1_5[] = { 524288, 65423 }; 
static const uint64_t SIGMOID_B_1_5[] = { 262598, 70102, 20500, 5819, 1805 };

static const uint64_t SIGMOID_A_1_6[] = { 524288, 65515 };
static const uint64_t SIGMOID_B_1_6[] = { 262128, 70336, 20343, 5937, 1711, 516 };

static const uint64_t SIGMOID_A_1_12[] = { 524350, 65490 };
static const uint64_t SIGMOID_B_1_12[] = { 
    262243, 70279, 20381, 5908, 1733, 497, 150, 40, 14, 3, 2, 18446744073709551615ULL 
};


static const uint64_t SIGMOID_A_2_1[] = { 524288, 18446744073709421224ULL, 3199 }; 
static const uint64_t SIGMOID_B_2_1[] = { 861074 };

static const uint64_t SIGMOID_A_2_6[] = { 524288, 75758, 18446744073709551455ULL };
static const uint64_t SIGMOID_B_2_6[] = { 230511, 74197, 19245, 6373, 1505, 623 };

static const uint64_t SIGMOID_A_2_12[] = { 524288, 65968, 18446744073709551609ULL };
static const uint64_t SIGMOID_B_2_12[] = { 
    260771, 70462, 20328, 5930, 1722, 503, 146, 43, 12, 4, 1, 0 
};


static const uint64_t SIGMOID_A_3_12[] = { 524288, 780751, 0, 18446744073709538558ULL };
static const uint64_t SIGMOID_B_3_12[] = {
    17197, 18446744073707959095ULL, 18446744073708743198ULL, 2077890,
    18446744073707410011ULL, 1700399, 18446744073708472140ULL, 574725,
    18446744073709304346ULL, 85052, 18446744073709530860ULL, 3136
};


void get_sigmoid_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    *out_a = nullptr; *out_b = nullptr;

    if (k1 == 0) {
        if (k2 == 6) { *out_a = SIGMOID_A_0_6; *out_b = SIGMOID_B_0_6; return; }
        if (k2 == 12) { *out_a = SIGMOID_A_0_6; *out_b = SIGMOID_B_0_12; return; }
    }
    else if (k1 == 1) {
        if (k2 == 1) { *out_a = SIGMOID_A_1_1; *out_b = SIGMOID_B_1_1; return; }
        if (k2 == 4) { *out_a = SIGMOID_A_1_4; *out_b = SIGMOID_B_1_4; return; }
        if (k2 == 5) { *out_a = SIGMOID_A_1_5; *out_b = SIGMOID_B_1_5; return; }
        if (k2 == 6) { *out_a = SIGMOID_A_1_6; *out_b = SIGMOID_B_1_6; return; }
        if (k2 == 12) { *out_a = SIGMOID_A_1_12; *out_b = SIGMOID_B_1_12; return; }
    }
    else if (k1 == 2) {
        if (k2 == 1) { *out_a = SIGMOID_A_2_1; *out_b = SIGMOID_B_2_1; return; }
        if (k2 == 6) { *out_a = SIGMOID_A_2_6; *out_b = SIGMOID_B_2_6; return; }
        if (k2 == 12) { *out_a = SIGMOID_A_2_12; *out_b = SIGMOID_B_2_12; return; }
    }
    else if (k1 == 3) {
        if (k2 == 12) { *out_a = SIGMOID_A_3_12; *out_b = SIGMOID_B_3_12; return; }
    }

    
    printf("⚠️ Warning: Unsupported Sigmoid params (K1=%d, K2=%d). Using default (1,6).\n", k1, k2);
    *out_a = SIGMOID_A_1_6; *out_b = SIGMOID_B_1_6;
}

static double get_SIGMOID_L_const(int k1, int k2) {
    if (k1 == 3 && k2 == 12) return 14.0;
    return 8.0;
}





static const uint64_t EXP_A_1_8[] = { 65664, 5164 };
static const uint64_t EXP_B_1_8[] = {
    18446744073709548721ULL, 18446744073709527788ULL, 18446744073709534234ULL, 340,
    13884, 14698, 9387, 4809
};


static const uint64_t EXP_A_1_9[] = { 64646, 5080 };
static const uint64_t EXP_B_1_9[] = {
    18446744073709548739ULL, 18446744073709527827ULL, 18446744073709534192ULL, 679,
    14091, 13869, 8360, 5544, 18446744073709549454ULL
};

static const uint64_t EXP_A_1_12[] = { 713580, 50970 };
static const uint64_t EXP_B_1_12[] = {
    423940, 174451, 86830, 45304,
    23893, 12524, 6427, 3181,
    1485, 630, 232, 60
};


static const uint64_t EXP_A_2_12[] = { 713585, 50970, 0 };
static const uint64_t EXP_B_2_12[] = {
    423940, 174451, 86830, 45304,
    23893, 12524, 6427, 3181,
    1485, 630, 232, 60
};


static const uint64_t EXP_A_3_12[] = { 962421, 3397879, 312912, 6519 };
static const uint64_t EXP_B_3_12[] = {
    18446744073699805688ULL, 18446744073708522107ULL, 18446744073709316522ULL, 18446744073709480615ULL,
    18446744073709527135ULL, 18446744073709542592ULL, 18446744073709548196ULL, 18446744073709550326ULL,
    18446744073709551148ULL, 18446744073709551459ULL, 18446744073709551571ULL, 18446744073709551607ULL
};







static const uint64_t ERF_A_1_8[] = { 0, 17692716 };
static const uint64_t ERF_B_1_8[] = {
    18446744073625986879ULL, 35350416, 18446744073692600342ULL, 8241410,
    18446744073706082381ULL, 1324353, 18446744073709191618ULL, 77662
};


static const uint64_t ERF_A_1_6[] = { 0, 9002440 };
static const uint64_t ERF_B_1_6[] = {
    18446744073668382450ULL, 16780447, 18446744073702420757ULL,
    3040859, 18446744073708628600ULL, 246039
};


static const uint64_t ERF_A_1_9[] = { 0, 18446744073687962064ULL };
static const uint64_t ERF_B_1_9[] = {
    105415858, 18446744073665394696ULL, 22566719,
    18446744073698405973ULL, 5287341, 18446744073707414385ULL,
    768512, 18446744073709354824ULL, 38766
};


static const uint64_t ERF_A_1_12[] = { 500, 131083 };
static const uint64_t ERF_B_1_12[] = {
    642242, 286101, 157259, 90073,
    50913, 27779, 14412, 7083,
    3260, 1419, 567, 221
};


static const uint64_t ERF_A_2_12[] = { 0, 23043705, 0 };
static const uint64_t ERF_B_2_12[] = {
    18446744073598274300ULL, 49622739, 18446744073683107102ULL, 14839194,
    18446744073701673832ULL, 4031025, 18446744073707713113ULL, 774196,
    18446744073709279437ULL, 83334, 18446744073709533598ULL, 2865
};


static const uint64_t ERF_A_3_12[] = { 0, 151001, 0, 18446744073709551304ULL };
static const uint64_t ERF_B_3_12[] = {
    580625, 293754, 155016, 91005,
    50445, 28043, 14250, 7188,
    3190, 1467, 532, 245
};



static const uint64_t EXP_G1_A_1_8[] = { 1039111, 172250 };
static const uint64_t EXP_G1_B_1_8[] = {
    519519, 152972, 63828, 33781,
    15550, 5841, 5263, 10959
};
static const uint64_t EXP_G1_A_1_9[] = { 1040534, 172684 };
static const uint64_t EXP_G1_B_1_9[] = {
    520726, 154572, 62931, 30876,
    17039, 9576, 3502, 3486,
    8230
};
static const uint64_t EXP_G1_A_1_12[] = { 941281, 124570 };
static const uint64_t EXP_G1_B_1_12[] = {
    501426, 163903, 65734, 29091,
    13748, 6674, 3284, 1572,
    733, 306, 118, 28
};
static const uint64_t EXP_G1_A_2_12[] = { 1037491, 4710339, 442301 };
static const uint64_t EXP_G1_B_2_12[] = {
    18446744073697790460ULL, 139640, 18446744073709270073ULL, 23960,
    18446744073709521131ULL, 3634, 18446744073709547457ULL, 250,
    18446744073709551151ULL, 18446744073709551547ULL, 18446744073709551591ULL, 18446744073709551595ULL
};
static const uint64_t EXP_G1_A_3_12[] = { 1040766, 2706171, 456027, 17889 };
static const uint64_t EXP_G1_B_3_12[] = {
    18446744073705884918ULL, 18446744073709233499ULL, 18446744073709492468ULL, 18446744073709536402ULL,
    18446744073709546972ULL, 18446744073709550021ULL, 18446744073709551047ULL, 18446744073709551402ULL,
    18446744073709551541ULL, 18446744073709551589ULL, 18446744073709551608ULL, 18446744073709551614ULL
};


static const uint64_t EXP_G2_A_1_8[] = { 314, 22 };
static const uint64_t EXP_G2_B_1_8[] = {
    85, 24, 18446744073709551582ULL, 18446744073709551569ULL,
    18446744073709551607ULL, 21, 4, 18446744073709551590ULL
};
static const uint64_t EXP_G2_A_1_9[] = { 315, 22 };
static const uint64_t EXP_G2_B_1_9[] = {
    84, 23, 18446744073709551582ULL, 18446744073709551570ULL,
    18446744073709551607ULL, 20, 3, 18446744073709551593ULL,
    18446744073709551614ULL
};
static const uint64_t EXP_G2_A_1_12[] = { 175237, 9223 };
static const uint64_t EXP_G2_B_1_12[] = {
    103149, 40899, 18688, 8368,
    3496, 1328, 448, 131,
    32, 6, 1, 0
};
static const uint64_t EXP_G2_A_2_12[] = { 181964, 9577, 0 };
static const uint64_t EXP_G2_B_2_12[] = {
    107233, 42668, 19615, 8861,
    3747, 1446, 499, 150,
    38, 8, 1, 0
};
static const uint64_t EXP_G2_A_3_12[] = { 181964, 9577, 0, 0 };
static const uint64_t EXP_G2_B_3_12[] = {
    107233, 42668, 19615, 8861,
    3747, 1446, 499, 150,
    38, 8, 1, 0
};





void get_EXP_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    *out_a = nullptr; *out_b = nullptr;

    if (k1 == 1) {
        if (k2 == 8) { *out_a = EXP_A_1_8; *out_b = EXP_B_1_8; return; }
        if (k2 == 9) { *out_a = EXP_A_1_9; *out_b = EXP_B_1_9; return; }
        if (k2 == 12) { *out_a = EXP_A_1_12; *out_b = EXP_B_1_12; return; }
    }
    else if (k1 == 2) {
        if (k2 == 12) { *out_a = EXP_A_2_12; *out_b = EXP_B_2_12; return; }
    }
    else if (k1 == 3) {
        if (k2 == 12) { *out_a = EXP_A_3_12; *out_b = EXP_B_3_12; return; }
    }

    
    printf("⚠️ Warning: Unsupported EXP params (K1=%d, K2=%d). Using default (1,12).\n", k1, k2);
    *out_a = EXP_A_1_12; *out_b = EXP_B_1_12;
}

double get_EXP_L_const(int k1, int k2) {
    if (k2 == 12 && (k1 == 1 || k1 == 2)) return 14.0;
    if (k1 == 3 && k2 == 12) return 16.0;
    return 8.0;
}

void get_EXP_G1_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1) {
        if (k2 == 8) { *out_a = EXP_G1_A_1_8; *out_b = EXP_G1_B_1_8; return; }
        if (k2 == 9) { *out_a = EXP_G1_A_1_9; *out_b = EXP_G1_B_1_9; return; }
        if (k2 == 12) { *out_a = EXP_G1_A_1_12; *out_b = EXP_G1_B_1_12; return; }
    } else if (k1 == 2 && k2 == 12) {
        *out_a = EXP_G1_A_2_12; *out_b = EXP_G1_B_2_12; return;
    } else if (k1 == 3 && k2 == 12) {
        *out_a = EXP_G1_A_3_12; *out_b = EXP_G1_B_3_12; return;
    }
    *out_a = EXP_G1_A_1_12; *out_b = EXP_G1_B_1_12;
}

void get_EXP_G2_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1) {
        if (k2 == 8) { *out_a = EXP_G2_A_1_8; *out_b = EXP_G2_B_1_8; return; }
        if (k2 == 9) { *out_a = EXP_G2_A_1_9; *out_b = EXP_G2_B_1_9; return; }
        if (k2 == 12) { *out_a = EXP_G2_A_1_12; *out_b = EXP_G2_B_1_12; return; }
    } else if (k1 == 2 && k2 == 12) {
        *out_a = EXP_G2_A_2_12; *out_b = EXP_G2_B_2_12; return;
    } else if (k1 == 3 && k2 == 12) {
        *out_a = EXP_G2_A_3_12; *out_b = EXP_G2_B_3_12; return;
    }
    *out_a = EXP_G2_A_1_12; *out_b = EXP_G2_B_1_12;
}

double get_EXP_G1_L_const(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 7.55;
    if (k1 == 2 && k2 == 12) return 10.5;
    if (k1 == 3 && k2 == 12) return 8.5;
    return 6.0;
}

double get_EXP_G2_L_const(int k1, int k2) {
    if ((k1 == 1 || k1 == 2 || k1 == 3) && k2 == 12) return 19.0;
    return 5.0;
}

void get_ERF_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    *out_a = nullptr; *out_b = nullptr;

    if (k1 == 1) {
        if (k2 == 6) { *out_a = ERF_A_1_6; *out_b = ERF_B_1_6; return; }
        if (k2 == 8) { *out_a = ERF_A_1_8; *out_b = ERF_B_1_8; return; }
        if (k2 == 9) { *out_a = ERF_A_1_9; *out_b = ERF_B_1_9; return; }
        if (k2 == 12) { *out_a = ERF_A_1_12; *out_b = ERF_B_1_12; return; }
    }
    else if (k1 == 2) {
        if (k2 == 12) { *out_a = ERF_A_2_12; *out_b = ERF_B_2_12; return; }
    }
    else if (k1 == 3) {
        if (k2 == 12) { *out_a = ERF_A_3_12; *out_b = ERF_B_3_12; return; }
    }

    
    printf("⚠️ Warning: Unsupported ERF params (K1=%d, K2=%d). Using default (1,12).\n", k1, k2);
    *out_a = ERF_A_1_12; *out_b = ERF_B_1_12;
}







static const uint64_t TANH_A_0_6[] = { 0 }; 
static const uint64_t TANH_B_0_6[] = { 1294561, 18446744073709479896, 355212, 18446744073709455078, 171276, 18446744073709460711 };

static const uint64_t TANH_B_0_12[] = { 1294561, 18446744073709479896, 355212, 18446744073709455078, 171276, 18446744073709460711,
  106339, 18446744073709474098, 77366, 18446744073709486589, 61614, 18446744073709496493 };


static const uint64_t TANH_A_1_1[] = { 0, 100963 };
static const uint64_t TANH_B_1_1[] = { 780363 };

static const uint64_t TANH_A_1_6[] = { 0, 132422 };
static const uint64_t TANH_B_1_6[] = { 620141, 265490, 130407, 72066, 36393, 21497 };

static const uint64_t TANH_A_1_9[] = { 0, 130859 }; 
static const uint64_t TANH_B_1_9[] = { 628101, 261509, 133060, 70076, 37985, 20170, 11132, 5788, 3317 };

static const uint64_t TANH_A_1_12[] = { 100, 149797 };
static const uint64_t TANH_B_1_12[] = { 615294, 244370, 115225, 56309, 27747, 13702, 6771, 3342, 1656, 812, 409, 193 };


static const uint64_t TANH_A_2_1[] = { 0, 18446744073708954033, 11830 }; 
static const uint64_t TANH_B_2_1[] = { 2826141 };

static const uint64_t TANH_A_2_6[] = { 0, 792397, 18446744073709541255 };
static const uint64_t TANH_B_2_6[] = { 18446744073708134600, 514183, 59658, 100177, 23143, 28357 };

static const uint64_t TANH_A_2_12[] = { 0, 193635, 18446744073709550638 };
static const uint64_t TANH_B_2_12[] = { 433406, 286165, 125597, 73317, 36264, 21210,10446, 6273, 2956, 1895, 806, 595 };


static const uint64_t TANH_A_3_12[] = { 0, 174915, 0, 18446744073709551612ULL };
static const uint64_t TANH_B_3_12[] = { 597468, 220209, 93775, 40982, 17976, 7893, 3478, 1518, 669, 300, 125, 50 };


void get_TANH_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    *out_a = nullptr; *out_b = nullptr;

    if (k1 == 0) {
        if (k2 == 6) { *out_a = TANH_A_0_6; *out_b = TANH_B_0_6; return; }
        if (k2 == 12) { *out_a = TANH_A_0_6; *out_b = TANH_B_0_12; return; }
    }
    else if (k1 == 1) {
        if (k2 == 1) { *out_a = TANH_A_1_1; *out_b = TANH_B_1_1; return; }
        if (k2 == 6) { *out_a = TANH_A_1_6; *out_b = TANH_B_1_6; return; }
        if (k2 == 9) { *out_a = TANH_A_1_9; *out_b = TANH_B_1_9; return; }
        if (k2 == 12) { *out_a = TANH_A_1_12; *out_b = TANH_B_1_12; return; }
    }
    else if (k1 == 2) {
        if (k2 == 1) { *out_a = TANH_A_2_1; *out_b = TANH_B_2_1; return; }
        if (k2 == 6) { *out_a = TANH_A_2_6; *out_b = TANH_B_2_6; return; }
        if (k2 == 12) { *out_a = TANH_A_2_12; *out_b = TANH_B_2_12; return; }
    }
    else if (k1 == 3) {
        if (k2 == 12) { *out_a = TANH_A_3_12; *out_b = TANH_B_3_12; return; }
    }

    
    printf("⚠️ Warning: Unsupported TANH params (K1=%d, K2=%d). Using default (1,6).\n", k1, k2);
    *out_a = TANH_A_1_6; *out_b = TANH_B_1_6;
}

static double get_TANH_L_const(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 7.0;
    if (k1 == 3 && k2 == 12) return 6.0;
    return 8.0;
}








static const uint64_t INVSQRT_A_0_ALL[] = { 517341 }; 

static const uint64_t INVSQRT_B_0_1[] = { 180045 }; 
static const uint64_t INVSQRT_B_0_6[] = { 180045, 143822, 123579, 110219, 100537, 93095 };
static const uint64_t INVSQRT_B_0_12[] = { 
    180045, 143822, 123579, 110219, 100537, 93095,
    87136, 82221, 78074, 74513, 71409, 68672 
};





static const uint64_t INVSQRT_A_1_1[] = { 2004049, 484578 };
static const uint64_t INVSQRT_B_1_1[] = { 18446744073706345464ULL };
static const uint64_t INVSQRT_A_1_4_EX[] = { 
    2696479,                
    18446744073638716485ULL 
}; 
static const uint64_t INVSQRT_B_1_4_EX[] = { 
    309311829,              
    18446744073610605503ULL, 
    28266681,               
    18446744073704169271ULL  
};
static const uint64_t INVSQRT_A_1_9_INV[] = { 
    2953295,                
    18446744073709232169 
};
static const uint64_t INVSQRT_B_1_9_INV[] = {
    18446744073708166137, 
    18446744073708991153, 
    18446744073709218830, 
    18446744073709345044, 
    18446744073709402429, 
    18446744073709450384, 
    18446744073709473017, 
    18446744073709497679, 
    18446744073709508276  
};
















static const uint64_t INVSQRT_A_1_6[] = { 2268796, 18446744073709332758ULL };
static const uint64_t INVSQRT_B_1_6[] = { 
    18446744073708616999ULL, 18446744073709138135ULL, 18446744073709303657ULL, 
    18446744073709383186ULL, 18446744073709429233ULL, 18446744073709458943ULL 
};


static const uint64_t INVSQRT_A_1_12[] = { 3492341, 18446744073708952091ULL };
static const uint64_t INVSQRT_B_1_12[] = {
    18446744073707951128ULL, 18446744073708905266ULL, 18446744073709200638ULL, 18446744073709322176ULL,
    18446744073709387209ULL, 18446744073709436341ULL, 18446744073709474919ULL, 18446744073709498452ULL,
    18446744073709509287ULL, 18446744073709516778ULL, 18446744073709527423ULL, 18446744073709539370ULL
};





static const uint64_t INVSQRT_A_2_1[] = { 1828266, 18446744073709327546ULL, 470 }; 
static const uint64_t INVSQRT_B_2_1[] = { 18446744073709109041ULL };


static const uint64_t INVSQRT_A_2_6[] = { 2765143, 18446744073709209177ULL, 480 };
static const uint64_t INVSQRT_B_2_6[] = { 
    18446744073708519124ULL, 18446744073709124920ULL, 18446744073709299258ULL, 
    18446744073709381044ULL, 18446744073709427948ULL, 18446744073709458067ULL 
};


static const uint64_t INVSQRT_A_2_12[] = { 3767246, 18446744073594710111ULL, 12775385 };
static const uint64_t INVSQRT_B_2_12[] = {
    262139902, 585496, 8453086, 298313,
    1388187, 170909, 330933, 95206,
    84781, 47871, 19522, 19516
};

static const uint64_t INVSQRT_A_3_12[] = { 4450438, 18446744073601804500ULL, 35614233, 18446744073706914670ULL };
static const uint64_t INVSQRT_B_3_12[] = {
    90935930, 10698460, 2894406, 1088570,
    486235, 239019, 122761, 63001,
    30958, 13971, 5592, 2013
};


void get_INVSQRT_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    *out_a = nullptr; *out_b = nullptr;

    if (k1 == 0) {
        *out_a = INVSQRT_A_0_ALL;
        if (k2 == 1) *out_b = INVSQRT_B_0_1;
        else if (k2 == 6) *out_b = INVSQRT_B_0_6;
        else if (k2 == 12) *out_b = INVSQRT_B_0_12;
    }
    else if (k1 == 1) {
        if (k2 == 1) { *out_a = INVSQRT_A_1_1; *out_b = INVSQRT_B_1_1; }
        else if (k2 == 6) { *out_a = INVSQRT_A_1_6; *out_b = INVSQRT_B_1_6; }
        else if (k2 == 4) { *out_a = INVSQRT_A_1_4_EX; *out_b = INVSQRT_B_1_4_EX; }
        else if (k2 == 9) { *out_a = INVSQRT_A_1_9_INV; *out_b = INVSQRT_B_1_9_INV; }
        else if (k2 == 12) { *out_a = INVSQRT_A_1_12; *out_b = INVSQRT_B_1_12; }
    }
    else if (k1 == 2) {
        if (k2 == 1) { *out_a = INVSQRT_A_2_1; *out_b = INVSQRT_B_2_1; }
        else if (k2 == 6) { *out_a = INVSQRT_A_2_6; *out_b = INVSQRT_B_2_6; }
        else if (k2 == 12) { *out_a = INVSQRT_A_2_12; *out_b = INVSQRT_B_2_12; }
    }
    else if (k1 == 3) {
        if (k2 == 12) { *out_a = INVSQRT_A_3_12; *out_b = INVSQRT_B_3_12; }
    }

    if (*out_a == nullptr) {
        printf("⚠️ Warning: Unsupported InvSqrt params (K1=%d, K2=%d). Using default (0,6).\n", k1, k2);
        *out_a = INVSQRT_A_0_ALL; *out_b = INVSQRT_B_0_6;
    }
}

void private_approx_sigmoid_base_csp1(
    const CommPorts& ports, 
    const uint64_t* input, 
    uint64_t* output, 
    int size, 
    int k1, 
    int k2, 
    uint64_t MOD
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_sigmoid_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20; uint64_t mask_scale = 1ULL << s; int b_len = k2;
    uint64_t* x1 = new uint64_t[size];
    for(int i=0; i<size; i++) x1[i] = input[i]; 
    
    
    uint64_t* t1 = new uint64_t[size]; 
    generate_and_map_random(t1, size, 67890, mask_scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    
    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false; 
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&](){ std::unique_lock<std::mutex> lock(start_mtx); start_cv.wait(lock, [&]{ return start_signal; }); };

    std::thread th1, th2, th3; 
    
    
    th3 = std::thread([&]() {
        wait_for_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        
        
        ecall_calculate_sigmoid_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u1, v1, size * b_len, t2_share1, t3_share1
        );

        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.done_net; }); }
        
        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = get_SIGMOID_L_const(k1, k2);

        #pragma omp parallel for if(enable_omp)
        for(int i=0; i<size; i++) {
            
            uint64_t d1 = shared.recv_buf[i] + (x1[i] + t1[i]);
            double delta_double = (int64_t)d1 * inv_scale;

            
            uint64_t trig_sum = 0;
            for(int k=0; k<b_len; k++) {
                double K_val = M_PI * (k + 1) / L_const;
                double angle = K_val * delta_double;
                double s_val, c_val;
                #ifdef __linux__
                    sincos(angle, &s_val, &c_val);
                #else
                    s_val = sin(angle); c_val = cos(angle);
                #endif
                double v1_v = (int64_t)v1[k*size + i] * inv_scale;
                double u1_v = (int64_t)u1[k*size + i] * inv_scale;
                
                double val = s_val * v1_v - c_val * u1_v; 
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            
            uint64_t poly_sum = 0; 
            if (k1 >= 1) {
                poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            }
            if (k1 >= 2) {
                
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s) + 3 * multiply_public_fixed_share(d1, t2_share1[i], s) - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    
    th1 = std::thread([&]() {
        wait_for_gun(); 
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    
    th2 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* st = new uint64_t[size];
        for(int i=0; i<size; i++) st[i] = x1[i] + t1[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    th1.join(); th2.join(); th3.join();

    for(int i=0; i<size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] x1; delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1; if (t3_share1) delete[] t3_share1;
}
void private_approx_tanh_base_csp1(
    const CommPorts& ports, 
    const uint64_t* input, 
    uint64_t* output, 
    int size, 
    int k1, 
    int k2, 
    uint64_t MOD
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_TANH_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20; uint64_t mask_scale = 1ULL << s; int b_len = k2;
    uint64_t* x1 = new uint64_t[size];
    for(int i=0; i<size; i++) x1[i] = input[i]; 
    
    
    uint64_t* t1 = new uint64_t[size]; 
    generate_and_map_random(t1, size, 67890, mask_scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    
    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false; 
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&](){ std::unique_lock<std::mutex> lock(start_mtx); start_cv.wait(lock, [&]{ return start_signal; }); };

    std::thread th1, th2, th3; 
    
    
    th3 = std::thread([&]() {
        wait_for_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        
        
        ecall_calculate_tanh_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u1, v1, size * b_len, t2_share1, t3_share1
        );

        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.done_net; }); }
        
        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = get_TANH_L_const(k1, k2);

        #pragma omp parallel for if(enable_omp)
        for(int i=0; i<size; i++) {
            uint64_t d1 = shared.recv_buf[i] + (x1[i] + t1[i]);
            double delta_double = (int64_t)d1 * inv_scale;

            
            uint64_t trig_sum = 0;
            for(int k=0; k<b_len; k++) {
                double K_val = M_PI * (k + 1) / L_const;
                double angle = K_val * delta_double;
                double s_val, c_val;
                #ifdef __linux__
                    sincos(angle, &s_val, &c_val);
                #else
                    s_val = sin(angle); c_val = cos(angle);
                #endif
                double v1_v = (int64_t)v1[k*size + i] * inv_scale;
                double u1_v = (int64_t)u1[k*size + i] * inv_scale;
                
                double val = s_val * v1_v - c_val * u1_v; 
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            
            uint64_t poly_sum = 0; 
            if (k1 >= 1) {
                poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            }
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s) + 3 * multiply_public_fixed_share(d1, t2_share1[i], s) - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    
    th1 = std::thread([&]() {
        wait_for_gun(); 
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    
    th2 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* st = new uint64_t[size];
        for(int i=0; i<size; i++) st[i] = x1[i] + t1[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    th1.join(); th2.join(); th3.join();

    for(int i=0; i<size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] x1; delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1; if (t3_share1) delete[] t3_share1;
}
void private_approx_erf_base_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output, 
    int size, int k1, int k2, uint64_t MOD
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_ERF_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20; uint64_t mask_scale = 1ULL << s; int b_len = k2;
    uint64_t* x1 = new uint64_t[size];
    for(int i=0; i<size; i++) x1[i] = input[i]; 
    
    uint64_t* t1 = new uint64_t[size]; 
    generate_and_map_random(t1, size, 67890, mask_scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false; 
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&](){ std::unique_lock<std::mutex> lock(start_mtx); start_cv.wait(lock, [&]{ return start_signal; }); };

    std::thread th1, th2, th3; 
    
    th3 = std::thread([&]() {
        wait_for_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        
        
        ecall_calculate_erf_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u1, v1, size * b_len, t2_share1, t3_share1
        );

        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.done_net; }); }
        
        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = 8.0;

        #pragma omp parallel for if(enable_omp)
        for(int i=0; i<size; i++) {
            uint64_t d1 = shared.recv_buf[i] + (x1[i] + t1[i]);
            double delta_double = (int64_t)d1 * inv_scale;

            uint64_t trig_sum = 0;
            for(int k=0; k<b_len; k++) {
                double K_val = M_PI * (k + 1) / L_const;
                double angle = K_val * delta_double;
                double s_val = sin(angle); double c_val = cos(angle);
                double v1_v = (int64_t)v1[k*size + i] * inv_scale;
                double u1_v = (int64_t)u1[k*size + i] * inv_scale;
                double val = s_val * v1_v - c_val * u1_v; 
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            uint64_t poly_sum = 0; 
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share1[i], s)
                                  - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    th1 = std::thread([&]() {
        wait_for_gun(); 
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    th2 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* st = new uint64_t[size];
        for(int i=0; i<size; i++) st[i] = x1[i] + t1[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();
    th1.join(); th2.join(); th3.join();

    for(int i=0; i<size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] x1; delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1; if (t3_share1) delete[] t3_share1;
}
void private_approx_exp_base_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output, 
    int size, int k1, int k2, uint64_t MOD
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_EXP_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20;
    uint64_t mask_scale = 1ULL << s;
    int b_len = k2;

    uint64_t* x1 = new uint64_t[size];
    for(int i = 0; i < size; i++) x1[i] = input[i];

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, mask_scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex start_mtx;
    std::condition_variable start_cv;
    bool start_signal = false;
    auto wait_for_gun = [&]() {
        std::unique_lock<std::mutex> lock(start_mtx);
        start_cv.wait(lock, [&]{ return start_signal; });
    };

    std::thread th1, th2, th3;

    th3 = std::thread([&]() {
        wait_for_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];

        ecall_calculate_exp_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u1, v1, size * b_len, t2_share1, t3_share1
        );

        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.done_net; });
        }

        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = get_EXP_L_const(k1, k2);

        #pragma omp parallel for if(enable_omp)
        for(int i = 0; i < size; i++) {
            uint64_t d1 = shared.recv_buf[i] + (x1[i] + t1[i]);
            double delta_double = (int64_t)d1 * inv_scale;

            uint64_t trig_sum = 0;
            for(int k = 0; k < b_len; k++) {
                double K_val = M_PI * (k + 1) / L_const;
                double angle = K_val * delta_double;
                double s_val = sin(angle);
                double c_val = cos(angle);
                double v1_v = (int64_t)v1[k * size + i] * inv_scale;
                double u1_v = (int64_t)u1[k * size + i] * inv_scale;
                double val = s_val * v1_v - c_val * u1_v;
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            uint64_t poly_sum = 0;
            if (k1 >= 1) {
                poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            }
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d1_t1 = multiply_public_fixed_share(d1, t1[i], s);
                uint64_t x2_share = 0 - 2 * d1_t1 + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                uint64_t d2_t1 = multiply_public_fixed_share(d2, t1[i], s);
                uint64_t d1_t2 = multiply_public_fixed_share(d1, t2_share1[i], s);
                uint64_t x3_share = 0 - 3 * d2_t1 + 3 * d1_t2 - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }

                        shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u1;
        delete[] v1;
    });

    th1 = std::thread([&]() {
        wait_for_gun();
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.done_net = true;
        }
        shared.cv.notify_all();
    });

    th2 = std::thread([&]() {
        wait_for_gun();
        uint64_t* st = new uint64_t[size];
        for(int i = 0; i < size; i++) st[i] = x1[i] + t1[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();
    th1.join();
    th2.join();
    th3.join();

    for(int i = 0; i < size; i++) {
        output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];
    }

    
    delete[] x1;
    delete[] t1;
    delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

enum class ExpSegmentKind {
    G1,
    G2
};

static void private_approx_exp_segment_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD, ExpSegmentKind segment
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    double L_const = 0.0;
    if (segment == ExpSegmentKind::G1) {
        get_EXP_G1_coeffs(k1, k2, &current_a, &current_b);
        L_const = get_EXP_G1_L_const(k1, k2);
    } else {
        get_EXP_G2_coeffs(k1, k2, &current_a, &current_b);
        L_const = get_EXP_G2_L_const(k1, k2);
    }

    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const int b_len = k2;

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);
    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx;
    std::condition_variable gun_cv;
    bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        if (segment == ExpSegmentKind::G1) {
            ecall_calculate_exp_g1_shares_unified(
                global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1);
        } else {
            ecall_calculate_exp_g2_shares_unified(
                global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1);
        }

        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        const double inv_scale = 1.0 / (double)scale;
        const bool enable_omp = (size * b_len > 150000);
        #pragma omp parallel for if(enable_omp)
        for (int i = 0; i < size; i++) {
            uint64_t d1 = shared.recv_buf[i] + (input[i] + t1[i]);
            double delta_double = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_double;
                double s_val = sin(angle);
                double c_val = cos(angle);
                double v1_v = (int64_t)v1[k * size + i] * inv_scale;
                double u1_v = (int64_t)u1[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((s_val * v1_v - c_val * u1_v) * scale));
            }

            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share1[i], s)
                                  - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u1;
        delete[] v1;
    });

    std::thread th_recv([&]() {
        wait_gun();
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input[i] + t1[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join();
    th_recv.join();
    th_send.join();

    for (int i = 0; i < size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] t1;
    delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

void private_approx_exp_g1_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_exp_segment_csp1(ports, input, output, size, k1, k2, MOD, ExpSegmentKind::G1);
}

void private_approx_exp_g2_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_exp_segment_csp1(ports, input, output, size, k1, k2, MOD, ExpSegmentKind::G2);
}

enum class HybridFuncKind {
    InvSqrt,
    Reciprocal
};

static double get_hybrid_base_l(HybridFuncKind kind, int k1, int k2) {
    if (kind == HybridFuncKind::InvSqrt) {
        if (k1 == 1 && k2 == 12) return 5.0;
        if (k1 == 2 && k2 == 12) return 9.0;
        if (k1 == 3 && k2 == 12) return 4.5;
    } else {
        if (k1 == 1 && k2 == 12) return 4.5;
        if (k1 == 2 && k2 == 12) return 8.5;
        if (k1 == 3 && k2 == 12) return 4.5;
    }
    return 8.0;
}

static void private_approx_hybrid_unified_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD,
    HybridFuncKind kind
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    if (kind == HybridFuncKind::InvSqrt) {
        get_INVSQRT_coeffs(k1, k2, &current_a, &current_b);
    } else {
        get_RECIP_BASE_coeffs(k1, k2, &current_a, &current_b);
    }

    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const int b_len = k2;

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);
    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx;
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx;
    std::condition_variable gun_cv;
    bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        if (kind == HybridFuncKind::InvSqrt) {
            ecall_calculate_invsqrt_shares_unified(
                global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1);
        } else {
            ecall_calculate_reciprocal_shares_unified(
                global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1);
        }

        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        const double inv_scale = 1.0 / (double)scale;
        const double L_const = get_hybrid_base_l(kind, k1, k2);
        const bool enable_omp = (size * b_len > 150000);
        #pragma omp parallel for if(enable_omp)
        for (int i = 0; i < size; i++) {
            uint64_t d1 = shared.recv_buf[i] + (input[i] + t1[i]);
            double delta_d = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle), cv_v = cos(angle);
                double v1v = (int64_t)v1[k * size + i] * inv_scale;
                double u1v = (int64_t)u1[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((sv * v1v - cv_v * u1v) * scale));
            }

            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share1[i], s)
                                  - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u1;
        delete[] v1;
    });

    std::thread th_recv([&]() {
        wait_gun();
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input[i] + t1[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join();
    th_recv.join();
    th_send.join();

    for (int i = 0; i < size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] t1;
    delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

void private_approx_invsqrt_base_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_hybrid_unified_csp1(ports, input, output, size, k1, k2, MOD, HybridFuncKind::InvSqrt);
}

void private_approx_inv_base_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_hybrid_unified_csp1(ports, input, output, size, k1, k2, MOD, HybridFuncKind::Reciprocal);
}

enum class BoundedPlusKind {
    Sigmoid,
    Tanh,
    Erf
};

static void private_approx_bounded_plus_csp1(
    const CommPorts& ports,
    const uint64_t* input,
    uint64_t* output,
    int size,
    int k1,
    int k2,
    uint64_t MOD,
    BoundedPlusKind kind,
    int64_t bound_int
) {
    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    uint64_t* mid = new uint64_t[size];
    uint64_t* left_cmp = new uint64_t[size];
    uint64_t* right_cmp = new uint64_t[size];
    uint64_t* x_plus_b = new uint64_t[size];
    uint64_t* x_minus_b = new uint64_t[size];

    for (int i = 0; i < size; i++) {
        x_plus_b[i] = input[i];
        x_minus_b[i] = input[i];
    }

    std::thread th_mid([&]() {
        if (kind == BoundedPlusKind::Sigmoid) {
            private_approx_sigmoid_base_csp1(ports, input, mid, size, k1, k2, UINT64_MAX);
        } else if (kind == BoundedPlusKind::Tanh) {
            private_approx_tanh_base_csp1(ports, input, mid, size, k1, k2, UINT64_MAX);
        } else {
            private_approx_erf_base_csp1(ports, input, mid, size, k1, k2, UINT64_MAX);
        }
    });
    std::thread th_left([&]() {
        ODReLU_CSP1_4Threads_64(ports.aux_client, ports.aux_server, x_plus_b, left_cmp, size);
    });
    std::thread th_right([&]() {
        ODReLU_CSP1_4Threads_64_v2(ports.aux_client_1, ports.aux_server_1, x_minus_b, right_cmp, size);
    });
    th_mid.join();
    th_left.join();
    th_right.join();

    uint64_t* left_scaled = new uint64_t[size];
    uint64_t* right_scaled = new uint64_t[size];
    uint64_t* mid_gate = new uint64_t[size];
    uint64_t* one_minus_right = new uint64_t[size];
    uint64_t* term_mid = new uint64_t[size];
    for (int i = 0; i < size; i++) {
        left_scaled[i] = left_cmp[i] * scale;
        right_scaled[i] = right_cmp[i] * scale;
        mid_gate[i] = left_scaled[i] - right_scaled[i];
        one_minus_right[i] = 0 - right_scaled[i];
    }

    secure_multiply_batch_dualport(
        ports.main_client, ports.main_server, false,
        mid_gate, mid, term_mid, size, s, UINT64_MAX);

    for (int i = 0; i < size; i++) {
        uint64_t term = secure_truncate(term_mid[i], s);
        uint64_t left_value = (kind == BoundedPlusKind::Sigmoid) ? 0 : (uint64_t)(-(int64_t)scale);
        uint64_t right_value = scale;
        uint64_t left_const = multiply_public_fixed_share(left_value, 0 - left_scaled[i], s);
        uint64_t right_const = multiply_public_fixed_share(right_value, right_scaled[i], s);
        uint64_t sum = left_const + term + right_const;
        output[i] = (MOD != 0) ? sum % MOD : sum;
    }

    delete[] mid;
    delete[] left_cmp;
    delete[] right_cmp;
    delete[] x_plus_b;
    delete[] x_minus_b;
    delete[] left_scaled;
    delete[] right_scaled;
    delete[] mid_gate;
    delete[] one_minus_right;
    delete[] term_mid;
}

void private_approx_sigmoid_plus_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_bounded_plus_csp1(ports, input, output, size, k1, k2, MOD, BoundedPlusKind::Sigmoid, 8);
}

void private_approx_tanh_plus_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_bounded_plus_csp1(ports, input, output, size, k1, k2, MOD, BoundedPlusKind::Tanh, 8);
}

void private_approx_erf_plus_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_bounded_plus_csp1(ports, input, output, size, k1, k2, MOD, BoundedPlusKind::Erf, 8);
}

void private_approx_exp_plus_csp1(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;

    uint64_t* exp_near = new uint64_t[size];
    uint64_t* exp_far = new uint64_t[size];
    uint64_t* t_cmp = new uint64_t[size];
    uint64_t* x_minus_alpha = new uint64_t[size];
    for (int i = 0; i < size; i++) {
        x_minus_alpha[i] = input[i];
    }

    CommPorts aux_ports = ports;
    aux_ports.main_server = ports.aux_server;
    aux_ports.main_client = ports.aux_client;

    std::thread th_near([&]() {
        private_approx_exp_g1_csp1(ports, input, exp_near, size, k1, k2, UINT64_MAX);
    });
    std::thread th_far([&]() {
        private_approx_exp_g2_csp1(aux_ports, input, exp_far, size, k1, k2, UINT64_MAX);
    });
    std::thread th_cmp([&]() {
        ODReLU_CSP1_4Threads_64(ports.aux_client_1, ports.aux_server_1, x_minus_alpha, t_cmp, size);
    });
    th_near.join();
    th_far.join();
    th_cmp.join();

    uint64_t* diff_full = new uint64_t[size];
    uint64_t* mux_share = new uint64_t[size];
    for (int i = 0; i < size; i++) {
        t_cmp[i] *= scale;
        diff_full[i] = exp_near[i] - exp_far[i];
    }

    secure_multiply_batch_dualport(ports.main_client, ports.main_server, false,
                                   t_cmp, diff_full, mux_share, size, s, UINT64_MAX);
    for (int i = 0; i < size; i++) {
        uint64_t result = exp_far[i] + secure_truncate(mux_share[i], s);
        output[i] = (MOD != 0) ? result % MOD : result;
    }

    delete[] exp_near;
    delete[] exp_far;
    delete[] t_cmp;
    delete[] x_minus_alpha;
    delete[] diff_full;
    delete[] mux_share;
}


void private_approx_silu_2rounds_csp1(
    const CommPorts& ports, const uint64_t* input_x, uint64_t* output_y,
    int size, int k1, int k2, uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();
    uint64_t s = 20;
    uint64_t scale = 1ULL << s;

    
    uint64_t* S_share = new uint64_t[size];  
    uint64_t* t1_share = new uint64_t[size];
    uint64_t* t2_share = new uint64_t[size];
    uint64_t* x_plus_12 = new uint64_t[size];
    uint64_t* x_minus_12 = new uint64_t[size];

    for(int i=0; i<size; i++) {
        x_plus_12[i] = input_x[i];  
        x_minus_12[i] = input_x[i];
    }

    
    
    
    std::thread th_sig([&]() {
        const uint64_t *current_a = nullptr, *current_b = nullptr;
        get_sigmoid_coeffs(k1, k2, &current_a, &current_b);
        int b_len = k2;
        
        uint64_t* t1 = new uint64_t[size];
        generate_and_map_random(t1, size, 67890, scale, 100);

        uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
        uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

        uint64_t* recv_buf = new uint64_t[size]; 
        std::mutex mtx; std::condition_variable cv; bool done_net = false;

        std::thread t_sig_calc([&]() {
            uint64_t* u1 = new uint64_t[size * b_len];
            uint64_t* v1 = new uint64_t[size * b_len];
            ecall_calculate_sigmoid_shares_unified(
                global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
            );
            { std::unique_lock<std::mutex> lock(mtx); cv.wait(lock, [&]() { return done_net; }); }
            
            double inv_scale = 1.0 / (double)scale;
            const double L_const = 8.0;

            #pragma omp parallel for
            for(int i=0; i<size; i++) {
                uint64_t d1 = recv_buf[i] + (input_x[i] + t1[i]);
                double delta_double = (int64_t)d1 * inv_scale;

                uint64_t trig_sum = 0;
                for(int k=0; k<b_len; k++) {
                    double K_val = M_PI * (k + 1) / L_const;
                    double angle = K_val * delta_double;
                    double s_val = sin(angle); double c_val = cos(angle);
                    double v1_v = (int64_t)v1[k*size + i] * inv_scale;
                    double u1_v = (int64_t)u1[k*size + i] * inv_scale;
                    double val = s_val * v1_v - c_val * u1_v;
                    trig_sum += (uint64_t)((int64_t)std::round(val * scale));
                }
                uint64_t poly_sum = 0; 
                if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
                if (k1 >= 2) {
                    uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                    poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
                }
                if (k1 >= 3) {
                    uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                    uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s)
                                      + 3 * multiply_public_fixed_share(d1, t2_share1[i], s)
                                      - t3_share1[i];
                    poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
                }
                S_share[i] = poly_sum + trig_sum;
            }
            delete[] u1; delete[] v1;
        });

        std::thread t_sig_recv([&]() {
            ports.main_server->recvMsg(recv_buf, size * sizeof(uint64_t), 0);
            { std::lock_guard<std::mutex> lock(mtx); done_net = true; }
            cv.notify_all();
        });

        std::thread t_sig_send([&]() {
            uint64_t* st = new uint64_t[size];
            for(int i=0; i<size; i++) st[i] = input_x[i] + t1[i];
            ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
            delete[] st;
        });

        t_sig_calc.join(); t_sig_recv.join(); t_sig_send.join();
        delete[] t1; delete[] recv_buf;
        if(t2_share1) delete[] t2_share1; if(t3_share1) delete[] t3_share1;
    });

    std::thread th_odrelu1([&]() {
        ODReLU_CSP1_4Threads_64(ports.aux_client, ports.aux_server, x_plus_12, t1_share, size);
    });

    std::thread th_odrelu2([&]() {
        ODReLU_CSP1_4Threads_64(ports.aux_client_1, ports.aux_server_1, x_minus_12, t2_share, size);
    });

    th_sig.join(); th_odrelu1.join(); th_odrelu2.join();

    
    
    for(int i=0; i<size; i++) {
        t1_share[i] = t1_share[i] * scale;
        t2_share[i] = t2_share[i] * scale;
    }

    
    uint64_t* t_diff = new uint64_t[size];
    for(int i=0; i<size; i++) {
        t_diff[i] = t1_share[i] - t2_share[i];
    }

    
    
    
    uint64_t* term_A = new uint64_t[size];
    uint64_t* term_B = new uint64_t[size];

    
    uint64_t half_s = s / 2;  

    uint64_t* t_diff_trunc = new uint64_t[size];
    uint64_t* input_x_trunc_3smp = new uint64_t[size];
    uint64_t* S_share_trunc = new uint64_t[size];
    uint64_t* t2_trunc = new uint64_t[size];
    uint64_t* input_x_trunc_smp = new uint64_t[size];

    for(int i=0; i<size; i++) {
        t_diff_trunc[i] = secure_truncate(t_diff[i], half_s);
        input_x_trunc_3smp[i] = secure_truncate(input_x[i], half_s);
        S_share_trunc[i] = secure_truncate(S_share[i], half_s);
        t2_trunc[i] = secure_truncate(t2_share[i], half_s);
        input_x_trunc_smp[i] = secure_truncate(input_x[i], half_s);
    }

    std::thread th_3smp([&]() {
        
        secure_triple_multiply_batch_dualport(ports.main_client, ports.main_server, false,
                                              t_diff_trunc, input_x_trunc_3smp, S_share_trunc, term_A, size, s, UINT64_MAX);
        
        for(int i=0; i<size; i++) {
            term_A[i] = secure_truncate(term_A[i], half_s);
        }
    });

    std::thread th_smp([&]() {
        
        secure_multiply_batch_dualport(ports.aux_client, ports.aux_server, false,
                                       t2_trunc, input_x_trunc_smp, term_B, size, s, UINT64_MAX);
        
    });

    th_3smp.join(); th_smp.join();

    
    delete[] t_diff_trunc;
    delete[] input_x_trunc_3smp;
    delete[] S_share_trunc;
    delete[] t2_trunc;
    delete[] input_x_trunc_smp;

    
    
    for(int i=0; i<size; i++) {
        uint64_t sum = term_A[i] + term_B[i];
        output_y[i] = (MOD != 0) ? sum % MOD : sum;
    }

    delete[] S_share; delete[] t1_share; delete[] t2_share;
    delete[] x_plus_12; delete[] x_minus_12; delete[] t_diff;
    delete[] term_A; delete[] term_B;
}

static void calculate_hybrid_rsqrt_steep_csp1(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_INVSQRT_STEEP_coeffs(k1, k2, &current_a, &current_b);  
    int b_len = k2;
    uint64_t s = 20;

    
    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx; std::condition_variable gun_cv; bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        ecall_calculate_invsqrt_steep_shares(
            global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
        );
        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        double inv_scale = 1.0 / (double)scale;
        const double L_const = 8.0;

        #pragma omp parallel for
        for(int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
            double delta_d = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for(int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle), cv_v = cos(angle);
                double v1v = (int64_t)v1[k * size + i] * inv_scale;
                double u1v = (int64_t)u1[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((sv * v1v - cv_v * u1v) * scale));
            }
            
            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s) + 3 * multiply_public_fixed_share(d1, t2_share1[i], s) - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for(int i = 0; i < size; i++) st[i] = input_x[i] + t1[i];
        net_send->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        net_recv->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join(); th_send.join(); th_recv.join();

    delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}


static void calculate_hybrid_rsqrt_flat_csp1(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_INVSQRT_FLAT_coeffs(k1, k2, &current_a, &current_b);  
    int b_len = k2;
    uint64_t s = 20;

    
    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx; std::condition_variable gun_cv; bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        ecall_calculate_invsqrt_flat_shares(
            global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
        );
        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        double inv_scale = 1.0 / (double)scale;
        const double L_const = 1280.0;  
        #pragma omp parallel for
        for(int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
            double delta_d = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for(int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle), cv_v = cos(angle);
                double v1v = (int64_t)v1[k * size + i] * inv_scale;
                double u1v = (int64_t)u1[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((sv * v1v - cv_v * u1v) * scale));
            }
            
            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s) + 3 * multiply_public_fixed_share(d1, t2_share1[i], s) - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for(int i = 0; i < size; i++) st[i] = input_x[i] + t1[i];
        net_send->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        net_recv->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join(); th_send.join(); th_recv.join();

    delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

void private_approx_invsqrt_plus_csp1(
    const CommPorts& ports, const uint64_t* input_x, uint64_t* output_y,
    int size, int k1_steep, int k1_flat, int k2, uint64_t MOD
) {
    uint64_t s = 20;
    uint64_t scale = 1ULL << s;

    
    uint64_t C_0_5004 = (uint64_t)(0.500438180 * scale);
    uint64_t C_1_5013 = (uint64_t)(1.50131454 * scale);
    uint64_t C_0_9991 = (uint64_t)(0.999124984 * scale);
    uint64_t C_1_5000 = (uint64_t)(1.5000086 * scale);

    uint64_t* E1_share = new uint64_t[size];
    uint64_t* E2_share = new uint64_t[size];
    uint64_t* t_cmp = new uint64_t[size];
    uint64_t* x_minus_8 = new uint64_t[size];

    for(int i=0; i<size; i++) {
        x_minus_8[i] = input_x[i]; 
    }

    
    
    
    std::thread th_h1([&]() {
        calculate_hybrid_rsqrt_steep_csp1(ports.main_client, ports.main_server, input_x, E1_share, size, k1_steep, k2, scale);
    });
    std::thread th_h2([&]() {
        calculate_hybrid_rsqrt_flat_csp1(ports.aux_client, ports.aux_server, input_x, E2_share, size, k1_flat, k2, scale);
    });
    std::thread th_cmp([&]() {
        ODReLU_CSP1_4Threads_64(ports.aux_client_1, ports.aux_server_1, x_minus_8, t_cmp, size);
    });
    th_h1.join(); th_h2.join(); th_cmp.join();

    
    
    for(int i=0; i<size; i++) {
        t_cmp[i] = t_cmp[i] * scale;
    }

    uint64_t* E_diff = new uint64_t[size];
    for(int i=0; i<size; i++) E_diff[i] = E2_share[i] - E1_share[i];

    
    
    
    uint64_t* mux_term = new uint64_t[size];
    uint64_t* y_0 = new uint64_t[size];

    uint64_t half_s = s / 2;
    uint64_t* t_cmp_trunc = new uint64_t[size];
    uint64_t* E_diff_trunc = new uint64_t[size];
    for(int i=0; i<size; i++) {
        t_cmp_trunc[i] = secure_truncate(t_cmp[i], half_s);
        E_diff_trunc[i] = secure_truncate(E_diff[i], half_s);
    }

    
    secure_multiply_batch_dualport(ports.main_client, ports.main_server, false,
                                   t_cmp_trunc, E_diff_trunc, mux_term, size, s, UINT64_MAX);

    delete[] t_cmp_trunc;
    delete[] E_diff_trunc;

    for(int i=0; i<size; i++) {
        y_0[i] = E1_share[i] + mux_term[i];
    }

    
    
    
    
    
    uint64_t C_combined = secure_truncate(C_0_9991 * C_0_5004, s);

    uint64_t* x0_share = new uint64_t[size];
    uint64_t* x0_prime_share = new uint64_t[size];
    for(int i=0; i<size; i++) {
        x0_share[i]       = multiply_public_fixed_share(C_0_5004, input_x[i], s);
        x0_prime_share[i] = multiply_public_fixed_share(C_combined, input_x[i], s);
    }

    uint64_t* y3_share = new uint64_t[size];
    uint64_t* cross_share = new uint64_t[size];

    
    uint64_t* y_0_trunc = new uint64_t[size];

    
    for(int i=0; i<size; i++) {
        y_0_trunc[i] = secure_truncate(y_0[i], half_s);
    }

    secure_cube_opt_batch_dualport_csp1(ports.main_client, ports.main_server, false,
                                        y_0_trunc, y3_share, size, s, UINT64_MAX);
    
    for(int i=0; i<size; i++) {
        y3_share[i] = secure_truncate(y3_share[i], half_s);
    }

    
    secure_multiply_batch_dualport(ports.main_client, ports.main_server, false,
                                   x0_share, y3_share, cross_share, size, s, UINT64_MAX);

    
    for(int i=0; i<size; i++) {
        cross_share[i] = secure_truncate(cross_share[i], s);
    }
    

    for(int i=0; i<size; i++) {
        uint64_t scaled_y = multiply_public_fixed_share(C_1_5013, y_0[i], s);
        y_0[i] = scaled_y - cross_share[i];
    }

    
    for(int i=0; i<size; i++) {
        y_0_trunc[i] = secure_truncate(y_0[i], half_s);
    }

    secure_cube_opt_batch_dualport_csp1(ports.main_client, ports.main_server, false,
                                        y_0_trunc, y3_share, size, s, UINT64_MAX);
    
    for(int i=0; i<size; i++) {
        y3_share[i] = secure_truncate(y3_share[i], half_s);
    }

    
    secure_multiply_batch_dualport(ports.main_client, ports.main_server, false,
                                   x0_prime_share, y3_share, cross_share, size, s, UINT64_MAX);

    
    for(int i=0; i<size; i++) {
        cross_share[i] = secure_truncate(cross_share[i], s);
    }
    

    for(int i=0; i<size; i++) {
        uint64_t scaled_y = multiply_public_fixed_share(C_1_5000, y_0[i], s);
        uint64_t final_y = scaled_y - cross_share[i];
        output_y[i] = (MOD != 0) ? final_y % MOD : final_y;
    }

    delete[] y_0_trunc;
    delete[] E1_share; delete[] E2_share; delete[] t_cmp; delete[] x_minus_8;
    delete[] E_diff; delete[] mux_term; delete[] y_0; delete[] x0_share;
    delete[] x0_prime_share; delete[] y3_share; delete[] cross_share;
}



static const uint64_t INVSQRT_STEEP_1_8_A[] = { 2868183, 18446744073709235478ULL };
static const uint64_t INVSQRT_STEEP_1_8_B[] = {
    18446744073708257638ULL, 18446744073708999558ULL, 18446744073709249300ULL, 18446744073709349212ULL, 18446744073709420674ULL, 18446744073709453125ULL,
    18446744073709486009ULL, 18446744073709499693ULL
};


static const uint64_t INVSQRT_STEEP_1_12_A[] = { 3424932, 18446744073709144458ULL };
static const uint64_t INVSQRT_STEEP_1_12_B[] = {
    18446744073708011611ULL, 18446744073708768491ULL, 18446744073709166779ULL, 18446744073709235077ULL, 18446744073709370663ULL, 18446744073709378535ULL,
    18446744073709449653ULL, 18446744073709445035ULL, 18446744073709488903ULL, 18446744073709481233ULL, 18446744073709508142ULL, 18446744073709495279ULL
};

static const uint64_t INVSQRT_STEEP_2_12_A[] = { 4095200, 18446744073583542404ULL, 15710499 };
static const uint64_t INVSQRT_STEEP_2_12_B[] = {
    256614962, 18446744073708974587ULL, 8804174, 18446744073709333994ULL, 1647286, 18446744073709440013ULL,
    482569, 18446744073709486706ULL, 164497, 18446744073709510001ULL, 50633, 18446744073709505364ULL
};


static const uint64_t INVSQRT_STEEP_3_12_A[] = { 4277660, 18446744073609606507ULL, 23148626, 18446744073708210776ULL };
static const uint64_t INVSQRT_STEEP_3_12_B[] = {
    114741439, 32009574, 3839147, 3625225, 695516, 917783,
    197944, 309264, 66750, 115536, 23262, 43564
};


static const uint64_t INVSQRT_FLAT_1_8_A[] = { 70005, 18446744073709551594ULL };
static const uint64_t INVSQRT_FLAT_1_8_B[] = {
    18446744073709551219ULL, 115, 54, 18446744073709551347ULL, 1070, 617,
    18446744073709551430ULL, 2
};


static const uint64_t INVSQRT_FLAT_1_12_A[] = { 300186ULL, 18446744073709551396ULL };
static const uint64_t INVSQRT_FLAT_1_12_B[] = {
    18446744073709392100ULL, 18446744073709481456ULL, 18446744073709510276ULL, 18446744073709522219ULL, 18446744073709529047ULL, 18446744073709534751ULL,
    18446744073709538986ULL, 18446744073709540955ULL, 18446744073709541686ULL, 18446744073709543172ULL, 18446744073709544693ULL, 18446744073709546675ULL
};

static const uint64_t INVSQRT_FLAT_2_12_A[] = { 319186ULL, 18446744073709551396ULL, 0 };
static const uint64_t INVSQRT_FLAT_2_12_B[] = {
    18446744073709392032ULL, 18446744073709481390ULL, 18446744073709510185ULL, 18446744073709522128ULL, 18446744073709529025ULL, 18446744073709534735ULL,
    18446744073709538931ULL, 18446744073709540930ULL, 18446744073709541660ULL, 18446744073709543131ULL, 18446744073709544709ULL, 18446744073709546578ULL
};


static const uint64_t INVSQRT_FLAT_3_12_A[] = { 311650ULL, 18446744073709551396ULL, 0, 0 };
static const uint64_t INVSQRT_FLAT_3_12_B[] = {
    18446744073709392100ULL, 18446744073709481456ULL, 18446744073709510276ULL, 18446744073709522219ULL, 18446744073709529047ULL, 18446744073709534751ULL,
    18446744073709538986ULL, 18446744073709540955ULL, 18446744073709541686ULL, 18446744073709543172ULL, 18446744073709544693ULL, 18446744073709546675ULL
};



static const uint64_t RECIP_STEEP_1_8_A[] = { 7302750, 18446744073708636921ULL };
static const uint64_t RECIP_STEEP_1_8_B[] = {
    18446744073705390564ULL, 18446744073707580372ULL, 18446744073708423472ULL, 18446744073708750666ULL, 18446744073709017682ULL, 18446744073709131966ULL,
    18446744073709264455ULL, 18446744073709315875ULL
};

static const uint64_t RECIP_STEEP_1_12_A[] = { 9491941, 18446744073708377084ULL };
static const uint64_t RECIP_STEEP_1_12_B[] = {
    18446744073703929147ULL, 18446744073706924146ULL, 18446744073707944001ULL, 18446744073708431294ULL, 18446744073708739547ULL, 18446744073708929201ULL,
    18446744073709076574ULL, 18446744073709175358ULL, 18446744073709261680ULL, 18446744073709322604ULL, 18446744073709379603ULL, 18446744073709437025ULL
};

static const uint64_t RECIP_STEEP_2_12_A[] = { 7967772, 18446744073697559059ULL, 1377013 };
static const uint64_t RECIP_STEEP_3_12_A[] = { 13271220, 18446744073235118928ULL, 89777768, 18446744073705716695ULL };
static const uint64_t RECIP_STEEP_2_12_B[] = {
    18072361, 18446744073707477241ULL, 18446744073709093662ULL, 18446744073708672756ULL, 18446744073709103277ULL, 18446744073709092624ULL,
    18446744073709267888ULL, 18446744073709305407ULL, 18446744073709410287ULL, 18446744073709439180ULL, 18446744073709496594ULL, 18446744073709523952ULL
};

static const uint64_t RECIP_STEEP_3_12_B[] = {
    714535137, 91159492, 24347828, 10147358, 4479922, 2486683,
    1276906, 794953, 418005, 271291, 127898, 76473
};


static const uint64_t RECIP_BASE_1_12_A[] = { 11761511, 18446744073707006816ULL };
static const uint64_t RECIP_BASE_1_12_B[] = {
    18446744073702718070ULL, 18446744073706486925ULL, 18446744073707733046ULL, 18446744073708344256ULL,
    18446744073708699271ULL, 18446744073708925897ULL, 18446744073709080298ULL, 18446744073709191231ULL,
    18446744073709274402ULL, 18446744073709337896ULL, 18446744073709383292ULL, 18446744073709390332ULL
};

static const uint64_t RECIP_BASE_2_12_A[] = { 13197649, 18446744072894182333ULL, 95976905 };
static const uint64_t RECIP_BASE_2_12_B[] = {
    1770478873, 1437692, 60392925, 783659,
    11047352, 515288, 3095788, 350112,
    986331, 234759, 300501, 184678
};

static const uint64_t RECIP_BASE_3_12_A[] = { 17458833, 18446744072847746021ULL, 285978902, 18446744073688369796ULL };
static const uint64_t RECIP_BASE_3_12_B[] = {
    736748861, 88521550, 24647899, 9567571,
    4414265, 2252303, 1220807, 684765,
    389789, 221553, 124400, 73957
};


static const uint64_t RECIP_FLAT_1_8_A[] = { 6517, 18446744073709551613ULL };
static const uint64_t RECIP_FLAT_1_8_B[] = {
    18446744073709551458ULL, 47, 22, 18446744073709551507ULL, 365, 234,
    18446744073709551540ULL, 1
};


static const uint64_t RECIP_FLAT_1_12_A[] = { 69500ULL, 18446744073709551560ULL };
static const uint64_t RECIP_FLAT_1_12_B[] = {
    18446744073709509856ULL, 18446744073709531995ULL, 18446744073709539696ULL, 18446744073709543451ULL, 18446744073709545506ULL, 18446744073709546794ULL,
    18446744073709547749ULL, 18446744073709548572ULL, 18446744073709549359ULL, 18446744073709550127ULL, 18446744073709550689ULL, 18446744073709551117ULL
};

static const uint64_t RECIP_FLAT_2_12_A[] = { 69468ULL, 18446744073709551560ULL, 0 };
static const uint64_t RECIP_FLAT_2_12_B[] = {
    18446744073709509856ULL, 18446744073709531995ULL, 18446744073709539696ULL, 18446744073709543451ULL, 18446744073709545506ULL, 18446744073709546794ULL,
    18446744073709547749ULL, 18446744073709548572ULL, 18446744073709549359ULL, 18446744073709550127ULL, 18446744073709550689ULL, 18446744073709551117ULL
};

static const uint64_t RECIP_FLAT_3_12_A[] = { 69228ULL, 18446744073709551560ULL, 0, 0 };
static const uint64_t RECIP_FLAT_3_12_B[] = {
    18446744073709509856ULL, 18446744073709531995ULL, 18446744073709539696ULL, 18446744073709543451ULL, 18446744073709545506ULL, 18446744073709546794ULL,
    18446744073709547749ULL, 18446744073709548572ULL, 18446744073709549359ULL, 18446744073709550127ULL, 18446744073709550689ULL, 18446744073709551117ULL
};

static void get_RECIP_STEEP_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 8) { *out_a = RECIP_STEEP_1_8_A; *out_b = RECIP_STEEP_1_8_B; }
    else if (k1 == 1 && k2 == 12) { *out_a = RECIP_STEEP_1_12_A; *out_b = RECIP_STEEP_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = RECIP_STEEP_2_12_A; *out_b = RECIP_STEEP_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = RECIP_STEEP_3_12_A; *out_b = RECIP_STEEP_3_12_B; }
    else {
        printf("⚠️  [RECIP_STEEP] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = RECIP_STEEP_1_12_A; *out_b = RECIP_STEEP_1_12_B;
    }
}

static void get_RECIP_BASE_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 12) { *out_a = RECIP_BASE_1_12_A; *out_b = RECIP_BASE_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = RECIP_BASE_2_12_A; *out_b = RECIP_BASE_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = RECIP_BASE_3_12_A; *out_b = RECIP_BASE_3_12_B; }
    else {
        printf("⚠️  [RECIP_BASE] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = RECIP_BASE_1_12_A; *out_b = RECIP_BASE_1_12_B;
    }
}

static void get_RECIP_FLAT_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 8) { *out_a = RECIP_FLAT_1_8_A; *out_b = RECIP_FLAT_1_8_B; }
    else if (k1 == 1 && k2 == 12) { *out_a = RECIP_FLAT_1_12_A; *out_b = RECIP_FLAT_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = RECIP_FLAT_2_12_A; *out_b = RECIP_FLAT_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = RECIP_FLAT_3_12_A; *out_b = RECIP_FLAT_3_12_B; }
    else {
        printf("⚠️  [RECIP_FLAT] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = RECIP_FLAT_1_12_A; *out_b = RECIP_FLAT_1_12_B;
    }
}


void get_INVSQRT_STEEP_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 8) { *out_a = INVSQRT_STEEP_1_8_A; *out_b = INVSQRT_STEEP_1_8_B; }
    else if (k1 == 1 && k2 == 12) { *out_a = INVSQRT_STEEP_1_12_A; *out_b = INVSQRT_STEEP_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = INVSQRT_STEEP_2_12_A; *out_b = INVSQRT_STEEP_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = INVSQRT_STEEP_3_12_A; *out_b = INVSQRT_STEEP_3_12_B; }
    else {
        printf("⚠️  [INVSQRT_STEEP] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = INVSQRT_STEEP_1_12_A; *out_b = INVSQRT_STEEP_1_12_B;
    }
}


void get_INVSQRT_FLAT_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 8) { *out_a = INVSQRT_FLAT_1_8_A; *out_b = INVSQRT_FLAT_1_8_B; }
    else if (k1 == 1 && k2 == 12) { *out_a = INVSQRT_FLAT_1_12_A; *out_b = INVSQRT_FLAT_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = INVSQRT_FLAT_2_12_A; *out_b = INVSQRT_FLAT_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = INVSQRT_FLAT_3_12_A; *out_b = INVSQRT_FLAT_3_12_B; }
    else {
        printf("⚠️  [INVSQRT_FLAT] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = INVSQRT_FLAT_1_12_A; *out_b = INVSQRT_FLAT_1_12_B;
    }
}



static void calculate_hybrid_reciprocal_steep_csp1(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_RECIP_STEEP_coeffs(k1, k2, &current_a, &current_b);
    int b_len = k2;
    uint64_t s = 20;

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx; std::condition_variable gun_cv; bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        ecall_calculate_reciprocal_steep_shares(
            global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
        );
        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        double inv_scale = 1.0 / (double)scale;
        const double L_const = 8.0;
        #pragma omp parallel for
        for(int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
            double delta_d = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for(int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle), cv_v = cos(angle);
                double v1v = (int64_t)v1[k * size + i] * inv_scale;
                double u1v = (int64_t)u1[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((sv * v1v - cv_v * u1v) * scale));
            }
            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += secure_truncate(current_a[1] * (0 - t1[i]), s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * secure_truncate(d1 * t1[i], s) + t2_share1[i];
                poly_sum += secure_truncate(current_a[2] * x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = secure_truncate(d1 * d1, s);
                uint64_t x3_share = 0 - 3 * secure_truncate(d2 * t1[i], s) + 3 * secure_truncate(d1 * t2_share1[i], s) - t3_share1[i];
                poly_sum += secure_truncate(current_a[3] * x3_share, s);
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for(int i = 0; i < size; i++) st[i] = input_x[i] + t1[i];
        net_send->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        net_recv->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join(); th_send.join(); th_recv.join();

    delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}

static void calculate_hybrid_reciprocal_flat_csp1(
    BSNet* net_send, BSNet* net_recv,
    const uint64_t* input_x, uint64_t* out_share,
    int size, int k1, int k2, uint64_t scale
) {
    
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_RECIP_FLAT_coeffs(k1, k2, &current_a, &current_b);
    int b_len = k2;
    uint64_t s = 20;

    uint64_t* t1 = new uint64_t[size];
    generate_and_map_random(t1, size, 67890, scale, 100);

    uint64_t* t2_share1 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share1 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size];

    std::mutex gun_mtx; std::condition_variable gun_cv; bool gun = false;
    auto wait_gun = [&]() {
        std::unique_lock<std::mutex> lk(gun_mtx);
        gun_cv.wait(lk, [&] { return gun; });
    };

    std::thread th_calc([&]() {
        wait_gun();
        uint64_t* u1 = new uint64_t[size * b_len];
        uint64_t* v1 = new uint64_t[size * b_len];
        ecall_calculate_reciprocal_flat_shares(
            global_eid1, size, k1, k2, scale, u1, v1, size * b_len, t2_share1, t3_share1
        );
        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        double inv_scale = 1.0 / (double)scale;
        const double L_const = 1216.0;  
        #pragma omp parallel for
        for(int i = 0; i < size; i++) {
            uint64_t d1 = (input_x[i] + t1[i]) + shared.recv_buf[i];
            double delta_d = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for(int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle), cv_v = cos(angle);
                double v1v = (int64_t)v1[k * size + i] * inv_scale;
                double u1v = (int64_t)u1[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((sv * v1v - cv_v * u1v) * scale));
            }
            uint64_t poly_sum = 0;
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], 0 - t1[i], s);
            if (k1 >= 2) {
                uint64_t x2_share = 0 - 2 * multiply_public_fixed_share(d1, t1[i], s) + t2_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x3_share = 0 - 3 * multiply_public_fixed_share(d2, t1[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share1[i], s)
                                  - t3_share1[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            out_share[i] = poly_sum + trig_sum;
        }
        delete[] u1; delete[] v1;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for(int i = 0; i < size; i++) st[i] = input_x[i] + t1[i];
        net_send->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        net_recv->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join(); th_send.join(); th_recv.join();

    delete[] t1; delete[] shared.recv_buf;
    if (t2_share1) delete[] t2_share1;
    if (t3_share1) delete[] t3_share1;
}


void private_approx_inv_plus_csp1(
    const CommPorts& ports, const uint64_t* input_x, uint64_t* output_y,
    int size, int steep_k1, int steep_flat_k1, int steep_k2, uint64_t MOD
) {
    uint64_t s = 20;
    uint64_t scale = 1ULL << s;
    uint64_t half_s = s / 2;
    const int flat_k1 = steep_flat_k1;
    const int flat_k2 = steep_k2;

    uint64_t* E1_share  = new uint64_t[size];
    uint64_t* E2_share  = new uint64_t[size];
    uint64_t* t_cmp     = new uint64_t[size];
    uint64_t* x_minus_8 = new uint64_t[size];

    for(int i = 0; i < size; i++) {
        x_minus_8[i] = input_x[i];
    }

    std::thread th_h1([&]() {
        calculate_hybrid_reciprocal_steep_csp1(
            ports.main_client, ports.main_server, input_x, E1_share, size, steep_k1, steep_k2, scale);
    });

    std::thread th_h2([&]() {
        calculate_hybrid_reciprocal_flat_csp1(
            ports.aux_client, ports.aux_server, input_x, E2_share, size, flat_k1, flat_k2, scale);
    });

    std::thread th_cmp([&]() {
        ODReLU_CSP1_4Threads_64(ports.aux_client_1, ports.aux_server_1, x_minus_8, t_cmp, size);
    });

    th_h1.join(); th_h2.join(); th_cmp.join();

    for(int i = 0; i < size; i++) {
        t_cmp[i] = t_cmp[i] * scale;
    }

    
    
    uint64_t* mux_a = new uint64_t[size * 2];
    uint64_t* mux_b = new uint64_t[size * 2];
    uint64_t* mux_out = new uint64_t[size * 2];
    uint64_t* y_curr = new uint64_t[size];
    uint64_t* one_minus_t_cmp = new uint64_t[size];

    for(int i = 0; i < size; i++) {
        one_minus_t_cmp[i] = (uint64_t)0 - t_cmp[i];
        mux_a[i] = one_minus_t_cmp[i];
        mux_b[i] = E1_share[i];
        mux_a[size + i] = t_cmp[i];
        mux_b[size + i] = E2_share[i];
    }

    secure_multiply_batch_dualport(ports.main_client, ports.main_server, false,
                                   mux_a, mux_b, mux_out, size * 2, s, UINT64_MAX);

    for(int i = 0; i < size; i++) {
        uint64_t term_front = secure_truncate(mux_out[i], s);
        uint64_t term_back = secure_truncate(mux_out[size + i], s);
        y_curr[i] = term_front + term_back;
    }

    delete[] one_minus_t_cmp;
    delete[] mux_a;
    delete[] mux_b;
    delete[] mux_out;

    uint64_t* xy2_share = new uint64_t[size];
    uint64_t* input_x_trunc = new uint64_t[size];
    uint64_t* y_curr_trunc = new uint64_t[size];
    const uint64_t xy2_pre_trunc_bits = 6;
    const uint64_t xy2_post_trunc_bits = 3 * (s - xy2_pre_trunc_bits) - s;

    for(int i = 0; i < size; i++) {
        input_x_trunc[i] = secure_truncate(input_x[i], (int)xy2_pre_trunc_bits);
        y_curr_trunc[i] = secure_truncate(y_curr[i], (int)xy2_pre_trunc_bits);
    }

    secure_xy2_opt_batch_dualport_csp1(
        ports.main_server, ports.main_client, false,
        input_x_trunc, y_curr_trunc, xy2_share,
        (uint64_t)size, s, UINT64_MAX
    );
    for(int i = 0; i < size; i++) {
        xy2_share[i] = secure_truncate(xy2_share[i], (int)xy2_post_trunc_bits);
        y_curr[i] = (y_curr[i] + y_curr[i]) - xy2_share[i];
    }

    for(int i = 0; i < size; i++) {
        y_curr_trunc[i] = secure_truncate(y_curr[i], (int)xy2_pre_trunc_bits);
    }

    secure_xy2_opt_batch_dualport_csp1(
        ports.main_server, ports.main_client, false,
        input_x_trunc, y_curr_trunc, xy2_share,
        (uint64_t)size, s, UINT64_MAX
    );
    for(int i = 0; i < size; i++) {
        xy2_share[i] = secure_truncate(xy2_share[i], (int)xy2_post_trunc_bits);
        y_curr[i] = (y_curr[i] + y_curr[i]) - xy2_share[i];
    }

    for(int i = 0; i < size; i++) {
        y_curr_trunc[i] = secure_truncate(y_curr[i], (int)xy2_pre_trunc_bits);
    }

    secure_xy2_opt_batch_dualport_csp1(
        ports.main_server, ports.main_client, false,
        input_x_trunc, y_curr_trunc, xy2_share,
        (uint64_t)size, s, UINT64_MAX
    );
    for(int i = 0; i < size; i++) {
        xy2_share[i] = secure_truncate(xy2_share[i], (int)xy2_post_trunc_bits);
        uint64_t final_y = (y_curr[i] + y_curr[i]) - xy2_share[i];
        output_y[i] = (MOD != 0) ? final_y % MOD : final_y;
    }

    delete[] input_x_trunc;
    delete[] y_curr_trunc;
    delete[] E1_share;
    delete[] E2_share;
    delete[] t_cmp;
    delete[] x_minus_8;
    delete[] y_curr;
    delete[] xy2_share;
}
