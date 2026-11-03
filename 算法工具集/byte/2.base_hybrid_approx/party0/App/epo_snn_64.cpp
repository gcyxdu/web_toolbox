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
#include <algorithm>  
#include "App.h"
#include "epo_snn_64.h"
#include "base_secure_protocols.h"
#include "func.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "calculate/basicSockets.h"  
#include <future>
#include <chrono>
#include <thread>
#include <cstdint>
using namespace std;
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <random>

#include <vector>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <omp.h>

#include <chrono>
#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <mutex>
#include <condition_variable>





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

static const uint64_t SIGMOID_A_1_12[] = { 524288, 65490 };
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

static const uint64_t EXP_A_1_12[] = { 713575, 50970 };
static const uint64_t EXP_B_1_12[] = {
    423940, 174451, 86830, 45304,
    23893, 12524, 6427, 3181,
    1485, 630, 232, 60
};


static const uint64_t EXP_A_2_12[] = { 713581, 50970, 0 };
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
static const uint64_t EXP_G1_A_1_12[] = { 1040558, 172628 };
static const uint64_t EXP_G1_B_1_12[] = {
    521840, 155252, 62927, 30006,
    15355, 9805, 5923, 3504,
    2922, 1850, 1088, 1079
};
static const uint64_t EXP_G1_A_2_12[] = { 1048332, 4846163, 501155 };
static const uint64_t EXP_G1_B_2_12[] = {
    18446744073698634062ULL, 159198, 18446744073709277612ULL, 28509,
    18446744073709517412ULL, 5052, 18446744073709545719ULL, 454,
    18446744073709550682ULL, 18446744073709551423ULL, 18446744073709551523ULL, 18446744073709551502ULL
};
static const uint64_t EXP_G1_A_3_12[] = { 1048436, 2830428, 506715, 21161 };
static const uint64_t EXP_G1_B_3_12[] = {
    18446744073705955916ULL, 18446744073709233801ULL, 18446744073709490199ULL, 18446744073709534193ULL,
    18446744073709545709ULL, 18446744073709549167ULL, 18446744073709550581ULL, 18446744073709551091ULL,
    18446744073709551378ULL, 18446744073709551479ULL, 18446744073709551558ULL, 18446744073709551579ULL
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
static const uint64_t EXP_G2_A_1_12[] = { 216574, 12032 };
static const uint64_t EXP_G2_B_1_12[] = {
    127259, 50247, 22862, 10220,
    4283, 1643, 565, 170,
    43, 9, 1, 0
};
static const uint64_t EXP_G2_A_2_12[] = { 184199, 9776, 48 };
static const uint64_t EXP_G2_B_2_12[] = {
    104673, 45625, 22224, 11052,
    5188, 2301, 925, 340,
    107, 29, 6, 1
};
static const uint64_t EXP_G2_A_3_12[] = { 184199, 9776, 48, 0 };
static const uint64_t EXP_G2_B_3_12[] = {
    104673, 45625, 22224, 11052,
    5188, 2301, 925, 340,
    107, 29, 6, 1
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


static const uint64_t ERF_A_1_12[] = { 0, 23043680 };
static const uint64_t ERF_B_1_12[] = {
    18446744073598274300ULL, 49622739, 18446744073683107102ULL, 14839194,
    18446744073701673832ULL, 4031025, 18446744073707713113ULL, 774196,
    18446744073709279437ULL, 83334, 18446744073709533598ULL, 2865
};


static const uint64_t ERF_A_2_12[] = { 0, 23043705, 0 };
static const uint64_t ERF_B_2_12[] = {
    18446744073598274300ULL, 49622739, 18446744073683107102ULL, 14839194,
    18446744073701673832ULL, 4031025, 18446744073707713113ULL, 774196,
    18446744073709279437ULL, 83334, 18446744073709533598ULL, 2865
};


static const uint64_t ERF_A_3_12[] = { 0, 18446744073695793065ULL, 0, 594625 };
static const uint64_t ERF_B_3_12[] = {
    322297, 37785370, 18446744073685762552ULL, 14088117,
    18446744073701899376ULL, 3965340, 18446744073707730410ULL, 770401,
    18446744073709280032ULL, 83299, 18446744073709533587ULL, 2867
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
    if (k1 == 2 && k2 == 12) return 9.5;
    if (k1 == 3 && k2 == 12) return 8.0;
    return 6.0;
}

double get_EXP_G2_L_const(int k1, int k2) {
    if (k1 == 1 && k2 == 12) return 18.0;
    if ((k1 == 2 || k1 == 3) && k2 == 12) return 21.0;
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


static const uint64_t INVSQRT_A_1_12[] = { 3392341, 18446744073708952091ULL };
static const uint64_t INVSQRT_B_1_12[] = {
    18446744073707951128ULL, 18446744073708905266ULL, 18446744073709200638ULL, 18446744073709322176ULL,
    18446744073709387209ULL, 18446744073709436341ULL, 18446744073709474919ULL, 18446744073709498452ULL,
    18446744073709509287ULL, 18446744073709516778ULL, 18446744073709527423ULL, 18446744073709539370ULL
};





static const uint64_t INVSQRT_A_2_1[] = { 128266, 18446744073709327546ULL, 470 }; 
static const uint64_t INVSQRT_B_2_1[] = { 18446744073709109041ULL };


static const uint64_t INVSQRT_A_2_6[] = { 2765143, 18446744073709209177ULL, 480 };
static const uint64_t INVSQRT_B_2_6[] = { 
    18446744073708519124ULL, 18446744073709124920ULL, 18446744073709299258ULL, 
    18446744073709381044ULL, 18446744073709427948ULL, 18446744073709458067ULL 
};


static const uint64_t INVSQRT_A_2_12[] = { 3821246, 18446744073594710111ULL, 12775385 };
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


void private_approx_sigmoid_base_csp0(
    const CommPorts& ports, 
    const uint64_t* input, 
    uint64_t* output, 
    int size, 
    int k1, 
    int k2, 
    uint64_t MOD
) {
    struct FuncStats {
        long online_wall = 0;   
        long th5_total = 0;
        long net_send_time = 0; 
        long net_recv_time = 0; 
        long total_func = 0;    
    } stats;

    auto start_all = std::chrono::high_resolution_clock::now();

    
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_sigmoid_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20; 
    uint64_t mask_scale = 1ULL << s; 
    int b_len = k2;

    uint64_t* x0 = new uint64_t[size];
    for(int i=0; i<size; i++) x0[i] = input[i]; 
    
    
    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 12345, mask_scale, 100);

    
    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    
    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; 
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size]; 

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&]() { 
        std::unique_lock<std::mutex> lock(start_mtx); 
        start_cv.wait(lock, [&]{ return start_signal; }); 
    };

    
    std::thread th1, th2, th3;

    
    th3 = std::thread([&]() {
        wait_for_gun(); 
        auto t5_start = std::chrono::high_resolution_clock::now();
        
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        
        
        ecall_calculate_sigmoid_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u0, v0, size * b_len, t2_share0, t3_share0
        );

        
        { 
            std::unique_lock<std::mutex> lock(shared.mtx); 
            shared.cv.wait(lock, [&]() { return shared.done_net; }); 
        }
        
        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = get_SIGMOID_L_const(k1, k2);

        #pragma omp parallel for if(enable_omp)
        for(int i=0; i<size; i++) {
            
            uint64_t d1 = (x0[i] + t0[i]) + shared.recv_buf[i];
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
                double v0_v = (int64_t)v0[k*size + i] * inv_scale;
                double u0_v = (int64_t)u0[k*size + i] * inv_scale;
                
                
                double val = s_val * v0_v - c_val * u0_v;
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            
            uint64_t poly_sum = current_a[0]; 
            if (k1 >= 1) {
                poly_sum += multiply_public_fixed_share(current_a[1], d1 - t0[i], s);
            }
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                
                uint64_t x2_share = d2 - 2 * multiply_public_fixed_share(d1, t0[i], s) + t2_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                
                uint64_t x3_share = d3 - 3 * multiply_public_fixed_share(d2, t0[i], s) + 3 * multiply_public_fixed_share(d1, t2_share0[i], s) - t3_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u0; delete[] v0;
    });

    
    th1 = std::thread([&]() {
        wait_for_gun(); 
        long bytes = size * sizeof(uint64_t);
        uint64_t* st = new uint64_t[size];
        for(int i=0; i<size; i++) st[i] = x0[i] + t0[i];
        ports.main_client->sendMsg(st, bytes, 0);
        delete[] st;
    });

    
    th2 = std::thread([&]() {
        wait_for_gun(); 
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    
    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    th1.join(); th2.join(); th3.join();

    
    for(int i=0; i<size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] x0; delete[] t0; delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0; if (t3_share0) delete[] t3_share0;
}
void private_approx_tanh_base_csp0(
    const CommPorts& ports, 
    const uint64_t* input, 
    uint64_t* output, 
    int size, 
    int k1, 
    int k2, 
    uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();

    
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_TANH_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20; 
    uint64_t mask_scale = 1ULL << s; 
    int b_len = k2;

    uint64_t* x0 = new uint64_t[size];
    for(int i=0; i<size; i++) x0[i] = input[i]; 
    
    
    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 12345, mask_scale, 100);

    
    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    
    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; 
        std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size]; 

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&]() { 
        std::unique_lock<std::mutex> lock(start_mtx); 
        start_cv.wait(lock, [&]{ return start_signal; }); 
    };

    
    std::thread th1, th2, th3;

    
    th3 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        
        
        ecall_calculate_tanh_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u0, v0, size * b_len, t2_share0, t3_share0
        );

        
        { 
            std::unique_lock<std::mutex> lock(shared.mtx); 
            shared.cv.wait(lock, [&]() { return shared.done_net; }); 
        }
        
        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = get_TANH_L_const(k1, k2);

        #pragma omp parallel for if(enable_omp)
        for(int i=0; i<size; i++) {
            
            uint64_t d1 = (x0[i] + t0[i]) + shared.recv_buf[i];
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
                double v0_v = (int64_t)v0[k*size + i] * inv_scale;
                double u0_v = (int64_t)u0[k*size + i] * inv_scale;
                
                
                double val = s_val * v0_v - c_val * u0_v;
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            
            uint64_t poly_sum = current_a[0]; 
            if (k1 >= 1) {
                poly_sum += multiply_public_fixed_share(current_a[1], d1 - t0[i], s);
            }
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x2_share = d2 - 2 * multiply_public_fixed_share(d1, t0[i], s) + t2_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                
                uint64_t x3_share = d3 - 3 * multiply_public_fixed_share(d2, t0[i], s) + 3 * multiply_public_fixed_share(d1, t2_share0[i], s) - t3_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u0; delete[] v0;
    });

    
    th1 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* st = new uint64_t[size];
        for(int i=0; i<size; i++) st[i] = x0[i] + t0[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    
    th2 = std::thread([&]() {
        wait_for_gun(); 
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();

    th1.join(); th2.join(); th3.join();

    
    for(int i=0; i<size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] x0; delete[] t0; delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0; if (t3_share0) delete[] t3_share0;
}
void private_approx_erf_base_csp0(
    const CommPorts& ports, const uint64_t* input, uint64_t* output, 
    int size, int k1, int k2, uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();

    
    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_ERF_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20; uint64_t mask_scale = 1ULL << s; int b_len = k2;

    uint64_t* x0 = new uint64_t[size];
    for(int i=0; i<size; i++) x0[i] = input[i]; 
    
    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 12345, mask_scale, 100);

    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

    struct SharedState {
        uint64_t* recv_buf = nullptr;
        bool done_net = false;
        std::mutex mtx; std::condition_variable cv;
    } shared;
    shared.recv_buf = new uint64_t[size]; 

    std::mutex start_mtx; std::condition_variable start_cv; bool start_signal = false;
    auto wait_for_gun = [&]() { std::unique_lock<std::mutex> lock(start_mtx); start_cv.wait(lock, [&]{ return start_signal; }); };

    std::thread th1, th2, th3;

    th3 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        
        
        ecall_calculate_erf_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u0, v0, size * b_len, t2_share0, t3_share0
        );

        { std::unique_lock<std::mutex> lock(shared.mtx); shared.cv.wait(lock, [&]() { return shared.done_net; }); }
        
        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = 8.0;

        #pragma omp parallel for if(enable_omp)
        for(int i=0; i<size; i++) {
            uint64_t d1 = (x0[i] + t0[i]) + shared.recv_buf[i];
            double delta_double = (int64_t)d1 * inv_scale;

            uint64_t trig_sum = 0;
            for(int k=0; k<b_len; k++) {
                double K_val = M_PI * (k + 1) / L_const;
                double angle = K_val * delta_double;
                double s_val = sin(angle); double c_val = cos(angle);
                double v0_v = (int64_t)v0[k*size + i] * inv_scale;
                double u0_v = (int64_t)u0[k*size + i] * inv_scale;
                double val = s_val * v0_v - c_val * u0_v;
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            uint64_t poly_sum = current_a[0]; 
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], d1 - t0[i], s);
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x2_share = d2 - 2 * multiply_public_fixed_share(d1, t0[i], s) + t2_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                uint64_t x3_share = d3 - 3 * multiply_public_fixed_share(d2, t0[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share0[i], s)
                                  - t3_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u0; delete[] v0;
    });

    th1 = std::thread([&]() {
        wait_for_gun(); 
        uint64_t* st = new uint64_t[size];
        for(int i=0; i<size; i++) st[i] = x0[i] + t0[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    th2 = std::thread([&]() {
        wait_for_gun(); 
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lock(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lock(start_mtx); start_signal = true; }
    start_cv.notify_all();
    th1.join(); th2.join(); th3.join();

    for(int i=0; i<size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] x0; delete[] t0; delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0; if (t3_share0) delete[] t3_share0;
}
void private_approx_exp_base_csp0(
    const CommPorts& ports, const uint64_t* input, uint64_t* output, 
    int size, int k1, int k2, uint64_t MOD
) {
    auto start_all = std::chrono::high_resolution_clock::now();

    const uint64_t *current_a = nullptr, *current_b = nullptr;
    get_EXP_coeffs(k1, k2, &current_a, &current_b);

    uint64_t s = 20;
    uint64_t mask_scale = 1ULL << s;
    int b_len = k2;

    uint64_t* x0 = new uint64_t[size];
    for (int i = 0; i < size; i++) x0[i] = input[i];

    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 12345, mask_scale, 100);

    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

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
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];

        ecall_calculate_exp_shares_unified(
            global_eid1, size, k1, k2, mask_scale, u0, v0, size * b_len, t2_share0, t3_share0
        );

        {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.cv.wait(lock, [&]() { return shared.done_net; });
        }

        double inv_scale = 1.0 / (double)mask_scale;
        bool enable_omp = (size * b_len > 150000);
        const double L_const = get_EXP_L_const(k1, k2);

        #pragma omp parallel for if(enable_omp)
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (x0[i] + t0[i]) + shared.recv_buf[i];
            double delta_double = (int64_t)d1 * inv_scale;

            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double K_val = M_PI * (k + 1) / L_const;
                double angle = K_val * delta_double;
                double s_val = sin(angle);
                double c_val = cos(angle);
                double v0_v = (int64_t)v0[k * size + i] * inv_scale;
                double u0_v = (int64_t)u0[k * size + i] * inv_scale;
                double val = s_val * v0_v - c_val * u0_v;
                trig_sum += (uint64_t)((int64_t)std::round(val * mask_scale));
            }

            uint64_t poly_sum = current_a[0];
            if (k1 >= 1) {
                poly_sum += multiply_public_fixed_share(current_a[1], d1 - t0[i], s);
            }
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d1_t0 = multiply_public_fixed_share(d1, t0[i], s);
                uint64_t x2_share = d2 - 2 * d1_t0 + t2_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                uint64_t d2_t0 = multiply_public_fixed_share(d2, t0[i], s);
                uint64_t d1_t2 = multiply_public_fixed_share(d1, t2_share0[i], s);
                uint64_t x3_share = d3 - 3 * d2_t0 + 3 * d1_t2 - t3_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }

                        shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u0;
        delete[] v0;
    });

    th1 = std::thread([&]() {
        wait_for_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = x0[i] + t0[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    th2 = std::thread([&]() {
        wait_for_gun();
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        {
            std::lock_guard<std::mutex> lock(shared.mtx);
            shared.done_net = true;
        }
        shared.cv.notify_all();
    });

    {
        std::lock_guard<std::mutex> lock(start_mtx);
        start_signal = true;
    }
    start_cv.notify_all();
    th1.join();
    th2.join();
    th3.join();

    for (int i = 0; i < size; i++) {
        output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];
    }

    
    delete[] x0;
    delete[] t0;
    delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0;
    if (t3_share0) delete[] t3_share0;
}

enum class ExpSegmentKind {
    G1,
    G2
};

static void private_approx_exp_segment_csp0(
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

    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size, 12345, scale, 100);
    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

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
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        if (segment == ExpSegmentKind::G1) {
            ecall_calculate_exp_g1_shares_unified(
                global_eid1, size, k1, k2, scale, u0, v0, size * b_len, t2_share0, t3_share0);
        } else {
            ecall_calculate_exp_g2_shares_unified(
                global_eid1, size, k1, k2, scale, u0, v0, size * b_len, t2_share0, t3_share0);
        }

        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        const double inv_scale = 1.0 / (double)scale;
        const bool enable_omp = (size * b_len > 150000);
        #pragma omp parallel for if(enable_omp)
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (input[i] + t0[i]) + shared.recv_buf[i];
            double delta_double = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_double;
                double s_val = sin(angle);
                double c_val = cos(angle);
                double v0_v = (int64_t)v0[k * size + i] * inv_scale;
                double u0_v = (int64_t)u0[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((s_val * v0_v - c_val * u0_v) * scale));
            }

            uint64_t poly_sum = current_a[0];
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], d1 - t0[i], s);
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x2_share = d2 - 2 * multiply_public_fixed_share(d1, t0[i], s) + t2_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                uint64_t x3_share = d3 - 3 * multiply_public_fixed_share(d2, t0[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share0[i], s)
                                  - t3_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u0;
        delete[] v0;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input[i] + t0[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join();
    th_send.join();
    th_recv.join();

    for (int i = 0; i < size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] t0;
    delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0;
    if (t3_share0) delete[] t3_share0;
}

void private_approx_exp_g1_csp0(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_exp_segment_csp0(ports, input, output, size, k1, k2, MOD, ExpSegmentKind::G1);
}

void private_approx_exp_g2_csp0(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    private_approx_exp_segment_csp0(ports, input, output, size, k1, k2, MOD, ExpSegmentKind::G2);
}

static const uint64_t RECIP_STEEP_1_12_A[] = { 9372541, 18446744073708377084ULL };
static const uint64_t RECIP_STEEP_1_12_B[] = {
    18446744073703929147ULL, 18446744073706924146ULL, 18446744073707944001ULL, 18446744073708431294ULL,
    18446744073708739547ULL, 18446744073708929201ULL, 18446744073709076574ULL, 18446744073709175358ULL,
    18446744073709261680ULL, 18446744073709322604ULL, 18446744073709379603ULL, 18446744073709437025ULL
};

static const uint64_t RECIP_STEEP_2_12_A[] = { 7912272, 18446744073697559059ULL, 1377013 };
static const uint64_t RECIP_STEEP_2_12_B[] = {
    18072361, 18446744073707477241ULL, 18446744073709093662ULL, 18446744073708672756ULL,
    18446744073709103277ULL, 18446744073709092624ULL, 18446744073709267888ULL, 18446744073709305407ULL,
    18446744073709410287ULL, 18446744073709439180ULL, 18446744073709496594ULL, 18446744073709523952ULL
};

static const uint64_t RECIP_STEEP_3_12_A[] = { 13271220, 18446744073235118928ULL, 89777768, 18446744073705716695ULL };
static const uint64_t RECIP_STEEP_3_12_B[] = {
    714535137, 91159492, 24347828, 10147358,
    4479922, 2486683, 1276906, 794953,
    418005, 271291, 127898, 76473
};

static void get_RECIP_STEEP_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 12) { *out_a = RECIP_STEEP_1_12_A; *out_b = RECIP_STEEP_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = RECIP_STEEP_2_12_A; *out_b = RECIP_STEEP_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = RECIP_STEEP_3_12_A; *out_b = RECIP_STEEP_3_12_B; }
    else {
        printf("⚠️  [RECIP_STEEP] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = RECIP_STEEP_1_12_A; *out_b = RECIP_STEEP_1_12_B;
    }
}

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

static void get_RECIP_BASE_coeffs(int k1, int k2, const uint64_t** out_a, const uint64_t** out_b) {
    if (k1 == 1 && k2 == 12) { *out_a = RECIP_BASE_1_12_A; *out_b = RECIP_BASE_1_12_B; }
    else if (k1 == 2 && k2 == 12) { *out_a = RECIP_BASE_2_12_A; *out_b = RECIP_BASE_2_12_B; }
    else if (k1 == 3 && k2 == 12) { *out_a = RECIP_BASE_3_12_A; *out_b = RECIP_BASE_3_12_B; }
    else {
        printf("⚠️  [RECIP_BASE] 不支持 (K1=%d, K2=%d)，回退默认 (1,12)。\n", k1, k2);
        *out_a = RECIP_BASE_1_12_A; *out_b = RECIP_BASE_1_12_B;
    }
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

static void private_approx_hybrid_unified_csp0(
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
        get_RECIP_STEEP_coeffs(k1, k2, &current_a, &current_b);
    }

    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const int b_len = k2;

    uint64_t* t0 = new uint64_t[size];
    generate_and_map_random(t0, size,
                            kind == HybridFuncKind::Reciprocal ? 23456 : 12345,
                            scale, 100);
    uint64_t* t2_share0 = (k1 >= 2) ? new uint64_t[size] : nullptr;
    uint64_t* t3_share0 = (k1 >= 3) ? new uint64_t[size] : nullptr;

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
        uint64_t* u0 = new uint64_t[size * b_len];
        uint64_t* v0 = new uint64_t[size * b_len];
        if (kind == HybridFuncKind::InvSqrt) {
            ecall_calculate_invsqrt_shares_unified(
                global_eid1, size, k1, k2, scale, u0, v0, size * b_len, t2_share0, t3_share0);
        } else {
            ecall_calculate_reciprocal_steep_shares(
                global_eid1, size, k1, k2, scale, u0, v0, size * b_len, t2_share0, t3_share0);
        }

        { std::unique_lock<std::mutex> lk(shared.mtx); shared.cv.wait(lk, [&] { return shared.done_net; }); }

        const double inv_scale = 1.0 / (double)scale;
        const double L_const = (kind == HybridFuncKind::Reciprocal) ? 8.0 : get_hybrid_base_l(kind, k1, k2);
        const bool enable_omp = (size * b_len > 150000);
        #pragma omp parallel for if(enable_omp)
        for (int i = 0; i < size; i++) {
            uint64_t d1 = (input[i] + t0[i]) + shared.recv_buf[i];
            double delta_d = (int64_t)d1 * inv_scale;
            uint64_t trig_sum = 0;
            for (int k = 0; k < b_len; k++) {
                double angle = M_PI * (k + 1) / L_const * delta_d;
                double sv = sin(angle), cv_v = cos(angle);
                double v0v = (int64_t)v0[k * size + i] * inv_scale;
                double u0v = (int64_t)u0[k * size + i] * inv_scale;
                trig_sum += (uint64_t)((int64_t)std::round((sv * v0v - cv_v * u0v) * scale));
            }

            uint64_t poly_sum = current_a[0];
            if (k1 >= 1) poly_sum += multiply_public_fixed_share(current_a[1], d1 - t0[i], s);
            if (k1 >= 2) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t x2_share = d2 - 2 * multiply_public_fixed_share(d1, t0[i], s) + t2_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[2], x2_share, s);
            }
            if (k1 >= 3) {
                uint64_t d2 = multiply_public_fixed_share(d1, d1, s);
                uint64_t d3 = multiply_public_fixed_share(d2, d1, s);
                uint64_t x3_share = d3 - 3 * multiply_public_fixed_share(d2, t0[i], s)
                                  + 3 * multiply_public_fixed_share(d1, t2_share0[i], s)
                                  - t3_share0[i];
                poly_sum += multiply_public_fixed_share(current_a[3], x3_share, s);
            }
            shared.recv_buf[i] = poly_sum + trig_sum;
        }
        delete[] u0;
        delete[] v0;
    });

    std::thread th_send([&]() {
        wait_gun();
        uint64_t* st = new uint64_t[size];
        for (int i = 0; i < size; i++) st[i] = input[i] + t0[i];
        ports.main_client->sendMsg(st, size * sizeof(uint64_t), 0);
        delete[] st;
    });

    std::thread th_recv([&]() {
        wait_gun();
        ports.main_server->recvMsg(shared.recv_buf, size * sizeof(uint64_t), 0);
        { std::lock_guard<std::mutex> lk(shared.mtx); shared.done_net = true; }
        shared.cv.notify_all();
    });

    { std::lock_guard<std::mutex> lk(gun_mtx); gun = true; }
    gun_cv.notify_all();
    th_calc.join();
    th_send.join();
    th_recv.join();

    for (int i = 0; i < size; i++) output[i] = (MOD != 0) ? shared.recv_buf[i] % MOD : shared.recv_buf[i];

    delete[] t0;
    delete[] shared.recv_buf;
    if (t2_share0) delete[] t2_share0;
    if (t3_share0) delete[] t3_share0;
}

void private_approx_invsqrt_base_csp0(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    const uint64_t s = 20;
    const uint64_t scale = 1ULL << s;
    const uint64_t half_s = s / 2;
    const uint64_t C_0_5004 = (uint64_t)(0.500438180 * scale);
    const uint64_t C_1_5013 = (uint64_t)(1.50131454 * scale);
    const uint64_t C_0_9991 = (uint64_t)(0.999124984 * scale);
    const uint64_t C_1_5000 = (uint64_t)(1.5000086 * scale);

    private_approx_hybrid_unified_csp0(ports, input, output, size, k1, k2, UINT64_MAX, HybridFuncKind::InvSqrt);

    uint64_t C_combined = secure_truncate(C_0_9991 * C_0_5004, s);
    uint64_t* x0_share = new uint64_t[size];
    uint64_t* x0_prime_share = new uint64_t[size];
    uint64_t* y3_share = new uint64_t[size];
    uint64_t* cross_share = new uint64_t[size];
    uint64_t* y_trunc = new uint64_t[size];

    for (int i = 0; i < size; i++) {
        x0_share[i] = multiply_public_fixed_share(C_0_5004, input[i], s);
        x0_prime_share[i] = multiply_public_fixed_share(C_combined, input[i], s);
        y_trunc[i] = secure_truncate(output[i], half_s);
    }

    secure_cube_opt_batch_dualport_csp0(ports.main_client, ports.main_server, true,
                                        y_trunc, y3_share, size, s, UINT64_MAX);
    for (int i = 0; i < size; i++) y3_share[i] = secure_truncate(y3_share[i], half_s);

    secure_multiply_batch_dualport(ports.main_client, ports.main_server, true,
                                   x0_share, y3_share, cross_share, size, s, UINT64_MAX);
    for (int i = 0; i < size; i++) {
        cross_share[i] = secure_truncate(cross_share[i], s);
        output[i] = multiply_public_fixed_share(C_1_5013, output[i], s) - cross_share[i];
        y_trunc[i] = secure_truncate(output[i], half_s);
    }

    secure_cube_opt_batch_dualport_csp0(ports.main_client, ports.main_server, true,
                                        y_trunc, y3_share, size, s, UINT64_MAX);
    for (int i = 0; i < size; i++) y3_share[i] = secure_truncate(y3_share[i], half_s);

    secure_multiply_batch_dualport(ports.main_client, ports.main_server, true,
                                   x0_prime_share, y3_share, cross_share, size, s, UINT64_MAX);
    for (int i = 0; i < size; i++) {
        cross_share[i] = secure_truncate(cross_share[i], s);
        uint64_t final_y = multiply_public_fixed_share(C_1_5000, output[i], s) - cross_share[i];
        output[i] = (MOD != 0) ? final_y % MOD : final_y;
    }

    delete[] x0_share;
    delete[] x0_prime_share;
    delete[] y3_share;
    delete[] cross_share;
    delete[] y_trunc;
}

void private_approx_inv_base_csp0(
    const CommPorts& ports, const uint64_t* input, uint64_t* output,
    int size, int k1, int k2, uint64_t MOD
) {
    const uint64_t s = 20;
    const uint64_t xy2_pre_trunc_bits = 6;
    const uint64_t xy2_post_trunc_bits = 3 * (s - xy2_pre_trunc_bits) - s;

    private_approx_hybrid_unified_csp0(ports, input, output, size, k1, k2, UINT64_MAX, HybridFuncKind::Reciprocal);

    uint64_t* xy2_share = new uint64_t[size];
    uint64_t* input_trunc = new uint64_t[size];
    uint64_t* y_trunc = new uint64_t[size];
    for (int i = 0; i < size; i++) input_trunc[i] = secure_truncate(input[i], (int)xy2_pre_trunc_bits);

    for (int iter = 0; iter < 3; iter++) {
        for (int i = 0; i < size; i++) y_trunc[i] = secure_truncate(output[i], (int)xy2_pre_trunc_bits);
        secure_xy2_opt_batch_dualport_csp0(
            ports.main_server, ports.main_client, true,
            input_trunc, y_trunc, xy2_share, (uint64_t)size, s, UINT64_MAX);
        for (int i = 0; i < size; i++) {
            xy2_share[i] = secure_truncate(xy2_share[i], (int)xy2_post_trunc_bits);
            uint64_t next_y = (output[i] + output[i]) - xy2_share[i];
            output[i] = (iter == 2 && MOD != 0) ? next_y % MOD : next_y;
        }
    }

    delete[] xy2_share;
    delete[] input_trunc;
    delete[] y_trunc;
}
