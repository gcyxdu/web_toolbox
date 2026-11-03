/* 系统头文件 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>

/* 本地头文件 */
#include "gmssl_ta.h"
#include "tee_core_api.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include "tee_object_api.h"
#include "tee_ext_api.h"
#include "tee_time_api.h"

/* GMSSL 头文件 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm9.h>

#include <gmssl/pkcs8.h>
#define TEST_COUNT 20
SM2_KEY sm2_global_key = {
    .public_key = {
        .x = {0x34, 0x8A, 0x5C, 0xB8, 0x90, 0x8A, 0x8C, 0xB9, 0x58, 0x9B, 0xE5, 0xAC, 0xBB, 0xA3, 0xD6, 0x26, 0xBA, 0xF0, 0x55, 0x19, 0xFC, 0xD3, 0x43, 0xDE, 0xAF, 0xBB, 0xDE, 0x04, 0x3C, 0xBE, 0x21, 0xB5},
        .y = {0x58, 0x6E, 0xED, 0xD5, 0x11, 0x2E, 0x66, 0x89, 0x0D, 0xDD, 0x00, 0x1E, 0x48, 0xBD, 0xA0, 0xE2, 0x51, 0x3A, 0xE0, 0x99, 0x33, 0x2B, 0xD3, 0x9C, 0xC0, 0x78, 0x2E, 0x62, 0x3A, 0x2A, 0x32, 0x76}
    },
    .private_key = {0x11, 0x54, 0xD5, 0xCE, 0x6C, 0x59, 0x8F, 0x96, 0x69, 0x70, 0xF8, 0xE2, 0xD5, 0x9B, 0x70, 0xCE, 0xCB, 0x2F, 0x7B, 0x33, 0xC9, 0x72, 0x16, 0x94, 0x13, 0xB9, 0xA3, 0xE2, 0x47, 0xA4, 0x73, 0xC1}    
};
uint8_t sm2_sig[SM2_MAX_SIGNATURE_SIZE] = {0x30, 0x44, 0x02, 0x20, 0x77, 0x99, 0xB8, 0xAE, 0xED, 0x14, 0x92, 0xD4, 0xD3, 0x43, 0x95, 0x95, 0xD6, 0x2E, 0x02, 0x0C, 0xD9, 0x0B, 0x24, 0xBD, 0xA6, 0xCB, 0xE9, 0x96, 0xF8, 0x8E, 0xDE, 0x84, 0x7D, 0x22, 0x8B, 0x38, 0x02, 0x20, 0x5D, 0x98, 0x20, 0x27, 0x5D, 0xFA, 0x22, 0x40, 0xA9, 0x32, 0x1F, 0x24, 0xE0, 0x46, 0x5A, 0x4E, 0x7D, 0x19, 0xD1, 0x5C, 0x33, 0x88, 0xCB, 0x96, 0x8B, 0xA8, 0xF8, 0xEF, 0xD6, 0x05, 0x33, 0x39};
uint8_t sm9_sig[1000] = {0x30, 0x66, 0x04, 0x20, 0x62, 0xF2, 0x07, 0xF9, 0x9E, 0x41, 0x92, 0xE4, 0xB9, 0x39, 0x39, 0xD1, 0x97, 0x89, 0xC4, 0xFF, 0x3E, 0xA8, 0x1C, 0x24, 0xE6, 0x17, 0xE1, 0x8E, 0x6C, 0xAC, 0x97, 0xCC, 0x90, 0xCF, 0xB6, 0x18, 0x03, 0x42, 0x00, 0x04, 0x3E, 0xE1, 0xBA, 0x1A, 0xA2, 0x01, 0x05, 0x41, 0xED, 0x80, 0xA2, 0x58, 0x03, 0xCC, 0x97, 0xB2, 0x8A, 0xC0, 0x11, 0x92, 0x46, 0x56, 0x86, 0xBD, 0x24, 0x94, 0x50, 0xF2, 0x31, 0x06, 0xF2, 0x4D, 0x35, 0x9B, 0x73, 0x2F, 0x49, 0x34, 0x68, 0x45, 0x9D, 0xD7, 0x0A, 0xDC, 0xB6, 0x84, 0x10, 0x11, 0xE0, 0x0D, 0x08, 0xC3, 0x3F, 0xBA, 0xC9, 0x07, 0x12, 0xA0, 0x4D, 0x44, 0xB0, 0xE2, 0x18, 0xE7};
size_t sm9_siglen = 104;
SM9_SIGN_KEY sm9_global_key = {
    .Ppubs = {
        .X = {{
            0x6E0361CA, 0x9C6E0D0B, 0x8412B32C, 0x9A2AB1AA, 0x96CA8971, 0xABC8BEF9, 0x3C23A4A8, 0x47BFA501
        }, {
            0xC05A36A1, 0xE9E23F84, 0xAD9150BD, 0x7C8EA20A, 0x1D6BF9CF, 0x4C748FCD, 0xC7816794, 0x0D380986 
        }},
        .Y = {{
            0xAE18B889, 0x664E7103, 0x4A305653, 0x344A7169, 0xD1F08C2A, 0xD75E4067, 0x0D228BDB, 0x66DEC57A
        }, {
            0x6D5B7EFC, 0xFD3B5CBB, 0xCCD6DFB7, 0x2380D23D, 0x5360C8FC, 0x3DA0E90D, 0xBFFAB324, 0x57835A2E
        }},
        .Z = {{
            0xBEC018C8, 0xBBE4A07A, 0x6644F243, 0x33BAB901, 0x863865BC, 0x38E24E29, 0x446E9C70, 0x84077478
        }, {
            0xEA577A8B, 0x72ACA27D, 0xE73CE825, 0x7BDF1E6A, 0x03696553, 0xEFBA2F52, 0x7BB44D14, 0x07A39D43
        }}
    },
    .ds = {
        .X = {0xD190B442, 0x56C4A62D, 0x8EC8D51C, 0xD4488203, 0x19A39B5A, 0x6A0BDA1F, 0xE2487C0F, 0x364880DA},
        .Y = {0x56E8A3D3, 0x8740C8EB, 0x111A4978, 0x0745C919, 0x1B874963, 0x689792F5, 0x6BF93E06, 0xAAF2C152},
        .Z = {0xB82D5487, 0x7ACAC134, 0xEF8F63FF, 0xF2C0682D, 0x8E760EF0, 0xB690C1E2, 0xF8F873A0, 0x0CA8C69D}
    }
};
SM9_SIGN_MASTER_KEY sm9_mpk = {
    .Ppubs = {
        .X = {{
            0x6E0361CA, 0x9C6E0D0B, 0x8412B32C, 0x9A2AB1AA, 0x96CA8971, 0xABC8BEF9, 0x3C23A4A8, 0x47BFA501
        }, {
            0xC05A36A1, 0xE9E23F84, 0xAD9150BD, 0x7C8EA20A, 0x1D6BF9CF, 0x4C748FCD, 0xC7816794, 0x0D380986 
        }},
        .Y = {{
            0xAE18B889, 0x664E7103, 0x4A305653, 0x344A7169, 0xD1F08C2A, 0xD75E4067, 0x0D228BDB, 0x66DEC57A
        }, {
            0x6D5B7EFC, 0xFD3B5CBB, 0xCCD6DFB7, 0x2380D23D, 0x5360C8FC, 0x3DA0E90D, 0xBFFAB324, 0x57835A2E
        }},
        .Z = {{
            0xBEC018C8, 0xBBE4A07A, 0x6644F243, 0x33BAB901, 0x863865BC, 0x38E24E29, 0x446E9C70, 0x84077478
        }, {
            0xEA577A8B, 0x72ACA27D, 0xE73CE825, 0x7BDF1E6A, 0x03696553, 0xEFBA2F52, 0x7BB44D14, 0x07A39D43
        }}
    },
    .ks = {0x1F2DC5F4, 0x348A1D5B, 0x340F319F, 0x80CE0B66, 0x87E02CF4, 0x45CB54C5, 0x8459D785, 0x000130E7}
};
uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
uint8_t IDA[5] = {0x41, 0x6C, 0x69, 0x63, 0x65};
/*-----------------------------------------------------------------------*/

/**
 * SM2签名和验签，核心功能
 * */
int _test_sm2(void)
{
    int ret;
    SM2_KEY sm2_key;
    SM2_SIGN_CTX sign_ctx;
    uint8_t msg[] = "Hello World!";
    uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0};
    size_t siglen;

    if (sm2_key_generate(&sm2_key) != 1)
    {
        error_print();
        return -1;
    }
    // sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

    if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1 || sm2_sign_finish(&sign_ctx, sig, &siglen) != 1)
    {
        error_print();
        return -1;
    }
    // format_bytes(stderr, 0, 4, "signature", sig, siglen);
    // sm2_signature_print(stderr, 0, 4, "signature", sig, siglen);

    if (sm2_verify_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_verify_update(&sign_ctx, msg, sizeof(msg)) != 1 || (ret = sm2_verify_finish(&sign_ctx, sig, siglen)) != 1)
    {
        error_print();
        return -1;
    }
    // format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");

    // FIXME: 还应该增加验证不通过的测试
    // 还应该增加底层的参数
    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
}

/**
 * SM2签名和验签，核心功能
 * */
int _test_sm2_sign()
{
    int ret;
    // SM2_KEY sm2_key;
    SM2_SIGN_CTX sign_ctx;
    uint8_t msg[] = "Hello World!";
    uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0};
    size_t siglen;
    // TEE_Time start_time, end_time;

    // TEE_GetSystemTime(&start_time);
    if (sm2_sign_init(&sign_ctx, &sm2_global_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1 || sm2_sign_finish(&sign_ctx, sig, &siglen) != 1)
    {
        error_print();
        return -1;
    }
    // TEE_GetSystemTime(&end_time);
    // *total_duration_us += (end_time.seconds - start_time.seconds) * 1000000 + (end_time.millis - start_time.millis) * 1000;
    // format_bytes(stderr, 0, 4, "signature", sig, siglen);
    // sm2_signature_print(stderr, 0, 4, "signature", sig, siglen);

    // if (sm2_verify_init(&sign_ctx, &sm2_global_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_verify_update(&sign_ctx, msg, sizeof(msg)) != 1 || (ret = sm2_verify_finish(&sign_ctx, sig, siglen)) != 1)
    // {
    //     error_print();
    //     return -1;
    // }
    // format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");

    // FIXME: 还应该增加验证不通过的测试
    // 还应该增加底层的参数
    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
}
/**
 * SM2签名和验签，核心功能
 * */
int _test_sm2_verify(size_t siglen)
{
    int ret;
    // SM2_KEY sm2_key;
    // size_t siglen;
    uint8_t msg[] = "Hello World!";
    SM2_SIGN_CTX sign_ctx;
    // TEE_Time start_time, end_time;

    // if (sm2_key_generate(&sm2_key) != 1)
    // {
    //     error_print();
    //     return -1;
    // }
    // sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

    // if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1 || sm2_sign_finish(&sign_ctx, sig, &siglen) != 1)
    // {
    //     error_print();
    //     return -1;
    // }
    // format_bytes(stderr, 0, 4, "signature", sig, siglen);
    // sm2_signature_print(stderr, 0, 4, "signature", sig, siglen);

    // TEE_GetSystemTime(&start_time);
    if (sm2_verify_init(&sign_ctx, &sm2_global_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_verify_update(&sign_ctx, msg, sizeof(msg)) != 1 || (ret = sm2_verify_finish(&sign_ctx, sm2_sig, siglen)) != 1)
    {
        error_print();
        return -1;
    }
    // TEE_GetSystemTime(&end_time);
    // *total_duration_us += (end_time.seconds - start_time.seconds) * 1000000 + (end_time.millis - start_time.millis) * 1000;
    // format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");

    // FIXME: 还应该增加验证不通过的测试
    // 还应该增加底层的参数
    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
}
/**
 * SM3 密码哈希算法的测试代码
 * */
int _test_sm3(void)
{
    const char *testhex[] = {
        /* 0 "abc" */
        "616263",
        /* 1 "abcd" 16 times */
        "6162636461626364616263646162636461626364616263646162636461626364"
        "6162636461626364616263646162636461626364616263646162636461626364",
        /* 2 p.57 ZA */
        "0090"
        "414C494345313233405941484F4F2E434F4D"
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
        "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A"
        "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",
        /* 3 p.59 ZA */
        "0090"
        "414C494345313233405941484F4F2E434F4D"
        "000000000000000000000000000000000000000000000000000000000000000000"
        "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"
        "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"
        "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"
        "0165961645281A8626607B917F657D7E9382F1EA5CD931F40F6627F357542653B2"
        "01686522130D590FB8DE635D8FCA715CC6BF3D05BEF3F75DA5D543454448166612",
        /* 4 p.72 ZA */
        "0090"
        "414C494345313233405941484F4F2E434F4D"
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
        "3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655"
        "3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B",
        /* 5 p.72 ZB */
        "0088"
        "42494C4C343536405941484F4F2E434F4D"
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
        "245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43"
        "53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C",
        /* 6 p.75 ZA */
        "0090"
        "414C494345313233405941484F4F2E434F4D"
        "000000000000000000000000000000000000000000000000000000000000000000"
        "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"
        "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"
        "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"
        "008E3BDB2E11F9193388F1F901CCC857BF49CFC065FB38B9069CAAE6D5AFC3592F"
        "004555122AAC0075F42E0A8BBD2C0665C789120DF19D77B4E3EE4712F598040415",
        /* 7 p.76 ZB */
        "0088"
        "42494C4C343536405941484F4F2E434F4D"
        "000000000000000000000000000000000000000000000000000000000000000000"
        "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"
        "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"
        "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"
        "0034297DD83AB14D5B393B6712F32B2F2E938D4690B095424B89DA880C52D4A7D9"
        "0199BBF11AC95A0EA34BBD00CA50B93EC24ACB68335D20BA5DCFE3B33BDBD2B62D",
        /* 8 TopsecCA cert ZA */
        "0080"
        "31323334353637383132333435363738"
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
        "D69C2F1EEC3BFB6B95B30C28085C77B125D77A9C39525D8190768F37D6B205B5"
        "89DCD316BBE7D89A9DC21917F17799E698531F5E6E3E10BD31370B259C3F81C3",
        /* 9 */
        "4D38D2958CA7FD2CFAE3AF04486959CF92C8EF48E8B83A05C112E739D5F181D0"
        "3082020CA003020102020900"
        "AF28725D98D33143300C06082A811CCF"
        "550183750500307D310B300906035504"
        "060C02636E310B300906035504080C02"
        "626A310B300906035504070C02626A31"
        "0F300D060355040A0C06746F70736563"
        "310F300D060355040B0C06746F707365"
        "633111300F06035504030C08546F7073"
        "65634341311F301D06092A864886F70D"
        "0109010C10626A40746F707365632E63"
        "6F6D2E636E301E170D31323036323430"
        "37353433395A170D3332303632303037"
        "353433395A307D310B30090603550406"
        "0C02636E310B300906035504080C0262"
        "6A310B300906035504070C02626A310F"
        "300D060355040A0C06746F7073656331"
        "0F300D060355040B0C06746F70736563"
        "3111300F06035504030C08546F707365"
        "634341311F301D06092A864886F70D01"
        "09010C10626A40746F707365632E636F"
        "6D2E636E3059301306072A8648CE3D02"
        "0106082A811CCF5501822D03420004D6"
        "9C2F1EEC3BFB6B95B30C28085C77B125"
        "D77A9C39525D8190768F37D6B205B589"
        "DCD316BBE7D89A9DC21917F17799E698"
        "531F5E6E3E10BD31370B259C3F81C3A3"
        "733071300F0603551D130101FF040530"
        "030101FF301D0603551D0E041604148E"
        "5D90347858BAAAD870D8BDFBA6A85E7B"
        "563B64301F0603551D23041830168014"
        "8E5D90347858BAAAD870D8BDFBA6A85E"
        "7B563B64300B0603551D0F0404030201"
        "06301106096086480186F84201010404"
        "03020057",
    };

    const char *dgsthex[] = {
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        "F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A",
        "26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5",
        "E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31",
        "6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67",
        "329c2f6030cc7e0ca3af6c97b76243ca250338ad3d3dc3a8b322d1cfdf98c2b7",
        /*"ECF0080215977B2E5D6D61B98A99442F03E8803DC39E349F8DCA5621A9ACDF2B",*/
        "557BAD30E183559AEEC3B2256E1C7C11F870D22B165D015ACF9465B09B87B527",
        "4D38D2958CA7FD2CFAE3AF04486959CF92C8EF48E8B83A05C112E739D5F181D0",
        "C3B02E500A8B60B77DEDCF6F4C11BEF8D56E5CDE708C72065654FD7B2167915A",
    };

    // int err = 0; // 未使用，注释掉
    uint8_t testbuf[sizeof(testhex) / 2 + 1000];
    uint8_t dgstbuf[32];
    size_t testbuflen, dgstbuflen;
    uint8_t dgst[32];
    size_t i;

    for (i = 0; i < sizeof(testhex) / sizeof(testhex[0]); i++)
    {
        hex_to_bytes(testhex[i], strlen(testhex[i]), testbuf, &testbuflen);
        hex_to_bytes(dgsthex[i], strlen(dgsthex[i]), dgstbuf, &dgstbuflen);

        sm3_digest(testbuf, testbuflen, dgst);

        if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0)
        {
            int n;
            // fprintf(stderr, "sm3 test %zu failed\n", i+1); // 删除打印以提升性能
            // fprintf(stderr, "error calculating SM3 on %s\n", testhex[i]);
            // fprintf(stderr, " digest(corret) = ");
            // for (n = 0; n < (int)sizeof(dgst); n++) {
            //     fprintf(stderr, "%02X", dgst[n]);
            // }
            // fprintf(stderr, "\n");
            // fprintf(stderr, " digest(error)  = %s\n", dgsthex[i]);
            return -1;
        }
    }

    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
}
/**
 * SM4 分组密码算法 的测试函数
 * */
int _test_sm4(void)
{
    const uint8_t user_key[16] = {
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0xfe,
        0xdc,
        0xba,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    };
    const uint32_t rk[32] = {
        0xf12186f9,
        0x41662b61,
        0x5a6ab19a,
        0x7ba92077,
        0x367360f4,
        0x776a0c61,
        0xb6bb89b3,
        0x24763151,
        0xa520307c,
        0xb7584dbd,
        0xc30753ed,
        0x7ee55b57,
        0x6988608c,
        0x30d895b7,
        0x44ba14af,
        0x104495a1,
        0xd120b428,
        0x73b55fa3,
        0xcc874966,
        0x92244439,
        0xe89e641f,
        0x98ca015a,
        0xc7159060,
        0x99e1fd2e,
        0xb79bd80c,
        0x1d2115b0,
        0x0e228aeb,
        0xf1780c81,
        0x428d3654,
        0x62293496,
        0x01cf72e5,
        0x9124a012,
    };
    const uint8_t plaintext[16] = {
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0xfe,
        0xdc,
        0xba,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    };
    const uint8_t ciphertext[16] = {
        0x68,
        0x1e,
        0xdf,
        0x34,
        0xd2,
        0x06,
        0x96,
        0x5e,
        0x86,
        0xb3,
        0xe9,
        0x4f,
        0x53,
        0x6e,
        0x42,
        0x46,
    };
    const uint8_t ciphertext1m[16] = {
        0x59,
        0x52,
        0x98,
        0xc7,
        0xc6,
        0xfd,
        0x27,
        0x1f,
        0x04,
        0x02,
        0xf8,
        0x04,
        0xc3,
        0x3d,
        0x3f,
        0x66,
    };

    SM4_KEY key;
    unsigned char buf[16];
    int i;

    /* test key scheduling */
    sm4_set_encrypt_key(&key, user_key);

    if (memcmp(key.rk, rk, sizeof(rk)) != 0)
    {
        // fprintf(stderr, "sm4 key scheduling not passed!\n"); // 删除打印以提升性能
        return -1;
    }

    /* test encrypt once */
    sm4_encrypt(&key, plaintext, buf);
    if (memcmp(buf, ciphertext, sizeof(ciphertext)) != 0)
    {
        // fprintf(stderr, "sm4 encrypt not pass!\n"); // 删除打印以提升性能
        return -1;
    }

    /* test encrypt 1000000 times */
    memcpy(buf, plaintext, sizeof(plaintext));
    for (i = 0; i < 1000000; i++)
    {
        sm4_encrypt(&key, buf, buf);
    }
    if (memcmp(buf, ciphertext1m, sizeof(ciphertext1m)) != 0)
    {
        // fprintf(stderr, "sm4 encrypt 1000000 times not pass!\n"); // 删除打印以提升性能
        return -1;
    }

    /* test decrypt */
    memset(&key, 0, sizeof(key));
    memset(buf, 0, sizeof(buf));
    sm4_set_decrypt_key(&key, user_key);
    sm4_decrypt(&key, ciphertext, buf);
    if (memcmp(buf, plaintext, sizeof(plaintext)) != 0)
    {
        // fprintf(stderr, "sm4 decrypt not pass!\n"); // 删除打印以提升性能
        return -1;
    }

    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
}

/**
 * SM9的签名算法
 * */
#define hex_ks "000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"
#define hex_ds "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820-78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"

int _test_sm9()
{
    SM9_SIGN_CTX ctx;
    SM9_SIGN_KEY key;
    SM9_SIGN_MASTER_KEY mpk;
    SM9_POINT ds;
    uint8_t sig[1000] = {0};
    size_t siglen = 0;
    int j = 1;

    sm9_bn_from_hex(mpk.ks, hex_ks);
    sm9_twist_point_mul_generator(&(mpk.Ppubs), mpk.ks);
    if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &key) < 0)
        goto err;
    ++j;
    sm9_point_from_hex(&ds, hex_ds);
    if (!sm9_point_equ(&(key.ds), &ds))
        goto err;
    ++j;

    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx, data, sizeof(data));
    if (sm9_sign_finish(&ctx, &key, sig, &siglen) < 0)
        goto err;
    ++j;

    sm9_verify_init(&ctx);
    sm9_verify_update(&ctx, data, sizeof(data));
    if (sm9_verify_finish(&ctx, sig, siglen, &mpk, (char *)IDA, sizeof(IDA)) != 1)
        goto err;
    ++j;

    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
err:
    // printf("%s test %d failed\n", __FUNCTION__, j); // 删除打印以提升性能
    error_print();
    return -1;
}

int _test_sm9_sign()
{
    SM9_SIGN_CTX ctx;
    SM9_SIGN_KEY key;
    SM9_SIGN_MASTER_KEY mpk;
    uint8_t sig[1000] = {0};
    size_t siglen = 0;
    int j = 1;
    // TEE_Time start_time, end_time;

    // sm9_bn_from_hex(mpk.ks, hex_ks); sm9_twist_point_mul_generator(&(mpk.Ppubs), mpk.ks);
    // if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &key) < 0) goto err;
    // ++j;
    // sm9_point_from_hex(&ds, hex_ds); if (!sm9_point_equ(&(key.ds), &ds)) goto err; ++j;

    // TEE_GetSystemTime(&start_time);
    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx, data, sizeof(data));
    if (sm9_sign_finish(&ctx, &key, sig, &siglen) < 0)
        goto err;
    // ++j;
    // TEE_GetSystemTime(&end_time);
    // *total_duration_us += (end_time.seconds - start_time.seconds) * 1000000 + (end_time.millis - start_time.millis) * 1000;

    // sm9_verify_init(&ctx);
    // sm9_verify_update(&ctx, data, sizeof(data));
    // if (sm9_verify_finish(&ctx, sig, siglen, &mpk, (char *)IDA, sizeof(IDA)) != 1) goto err;
    // ++j;

    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
err:
    // printf("%s test %d failed\n", __FUNCTION__, j); // 删除打印以提升性能
    error_print();
    return -1;
}

int _test_sm9_verify(size_t siglen)
{
    SM9_SIGN_CTX ctx;
    SM9_SIGN_KEY key;
    SM9_SIGN_MASTER_KEY mpk;
    SM9_POINT ds;
    uint8_t sig[1000] = {0};
    // size_t siglen = 0;
    int j = 1;

    // sm9_bn_from_hex(mpk.ks, hex_ks);
    // sm9_twist_point_mul_generator(&(mpk.Ppubs), mpk.ks);
    // if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &key) < 0)
    //     goto err;
    // ++j;
    // sm9_point_from_hex(&ds, hex_ds);
    // if (!sm9_point_equ(&(key.ds), &ds))
    //     goto err;
    // ++j;

    // sm9_sign_init(&ctx);
    // sm9_sign_update(&ctx, data, sizeof(data));
    // if (sm9_sign_finish(&ctx, &key, sig, &siglen) < 0)
    //     goto err;
    // ++j;

    sm9_verify_init(&ctx);
    sm9_verify_update(&ctx, data, sizeof(data));
    if (sm9_verify_finish(&ctx, sm9_sig, siglen, &sm9_mpk, (char *)IDA, sizeof(IDA)) != 1)
        goto err;
    ++j;

    // printf("%s() ok\n", __FUNCTION__); // 删除打印以提升性能
    return 1;
err:
    // printf("%s test %d failed\n", __FUNCTION__, j); // 删除打印以提升性能
    error_print();
    return -1;
}

/*-----------------------------------------------------------------------*/

TEE_Result Cmd_test_sm2_do_sign(uint32_t paramTypes __attribute__((unused)), TEE_Param params[PARAMS_IDX4] __attribute__((unused)))
{
    // _test_sm2_do_sign();
    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm2(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;

    for (int i = 0; i < test_count; i++)
    {
        // 记录开始时间
        TEE_Time start_time, end_time;
        TEE_GetSystemTime(&start_time);

        // 执行签名验签流程
        int result = _test_sm2();

        // 记录结束时间
        TEE_GetSystemTime(&end_time);

        // 计算耗时（微秒）
        uint32_t duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                               (end_time.millis - start_time.millis) * 1000;

        if (result == 1)
        {
            success_count++;
            total_duration_us += duration_us;
        }
    }

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm2_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // if (sm2_key_generate(&sm2_global_key) != 1)
    // {
    //     error_print();
    //     return -1;
    // }
    // sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_global_key);

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;

    for (int i = 0; i < test_count; i++)
    {
        // 记录开始时间
        TEE_Time start_time, end_time;
        TEE_GetSystemTime(&start_time);

        // 执行签名验签流程
        int result = _test_sm2_sign();

        // 记录结束时间
        TEE_GetSystemTime(&end_time);

        // 计算耗时（微秒）
        uint32_t duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                               (end_time.millis - start_time.millis) * 1000;

        if (result == 1)
        {
            success_count++;
            total_duration_us += duration_us;
        }
    }

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm2_verify(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // if (sm2_key_generate(&sm2_global_key) != 1)
    // {
    //     error_print();
    //     return -1;
    // }
    // sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_global_key);

    // SM2_SIGN_CTX sign_ctx;
    
    size_t siglen = strlen(sm2_sig);
    // uint8_t msg[] = "Hello World!";
    // if (sm2_sign_init(&sign_ctx, &sm2_global_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1 || sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1 || sm2_sign_finish(&sign_ctx, sm2_sig, &siglen) != 1)
    // {
    //     error_print();
    //     return -1;
    // }

    // format_bytes(stderr, 0, 4, "signature", sm2_sig, siglen);
    // sm2_signature_print(stderr, 0, 4, "signature", sm2_sig, siglen);

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;

    // 记录开始时间
    TEE_Time start_time, end_time;
    TEE_GetSystemTime(&start_time);
    for (int i = 0; i < test_count; i++)
    {
        // 执行签名验签流程
        int result = _test_sm2_verify(siglen);

        if (result == 1)
        {
            success_count++;
        }
    }
    // 记录结束时间
    TEE_GetSystemTime(&end_time);

    // 计算耗时（微秒）
    total_duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                            (end_time.millis - start_time.millis) * 1000;

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm3(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 先执行原有的SM3测试
    // int result = _test_sm3();
    // if (result != 1)
    // {
    //     params[0].value.a = 0; // 失败标志
    //     params[0].value.b = 0; // 耗时设为0
    //     return TEE_SUCCESS;
    // }

    // 测试一百万次SM3哈希计算
    // uint8_t test_data[64] = {0};
    uint8_t hash_result[32];
    int i;

    // 初始化测试数据
    // for (i = 0; i < 64; i++)
    // {
    //     test_data[i] = i % 256;
    // }
    uint8_t test_data[64] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63};

    // 记录开始时间
    TEE_Time start_time, end_time;
    TEE_GetSystemTime(&start_time);

    // 测试一百万次SM3哈希计算
    for (i = 0; i < 1000000; i++)
    {
        sm3_digest(test_data, sizeof(test_data), hash_result);
    }

    // 记录结束时间
    TEE_GetSystemTime(&end_time);

    // 计算耗时（微秒）
    uint32_t duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                           (end_time.millis - start_time.millis) * 1000;

    // 返回结果和耗时
    params[0].value.a = 1;           // 成功标志
    params[0].value.b = duration_us; // 耗时（微秒）

    return TEE_SUCCESS;
}

TEE_Result Cmd_test_sm4(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 先执行原有的SM4测试
    // int result = _test_sm4();
    // if (result != 1)
    // {
    //     params[0].value.a = 0; // 失败标志
    //     params[0].value.b = 0; // 耗时设为0
    //     return TEE_SUCCESS;
    // }

    // 测试一百万次SM4加密计算
    const uint8_t user_key[16] = {
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0xfe,
        0xdc,
        0xba,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    };
    const uint8_t plaintext[16] = {
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0xfe,
        0xdc,
        0xba,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    };

    SM4_KEY key = {
        .rk = {0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
		0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
		0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
		0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
		0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
		0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
		0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
		0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,}
    };
    unsigned char buf[16];
    int i;

    // 设置加密密钥
    // sm4_set_encrypt_key(&key, user_key);
    
    memcpy(buf, plaintext, sizeof(plaintext));

    // 记录开始时间
    TEE_Time start_time, end_time;
    TEE_GetSystemTime(&start_time);

    // 测试一百万次SM4加密计算
    for (i = 0; i < 1000000; i++)
    {
        sm4_encrypt(&key, buf, buf);
    }

    // 记录结束时间
    TEE_GetSystemTime(&end_time);

    // 计算耗时（微秒）
    uint32_t duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                           (end_time.millis - start_time.millis) * 1000;

    // 返回结果和耗时
    params[0].value.a = 1;           // 成功标志
    params[0].value.b = duration_us; // 耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm9(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;


    // 记录开始时间
    TEE_Time start_time, end_time;
    TEE_GetSystemTime(&start_time);
    for (int i = 0; i < test_count; i++)
    {
        // 执行签名验签流程
        int result = _test_sm9();

        if (result == 1)
        {
            success_count++;
        }
    }
    // 记录结束时间
    TEE_GetSystemTime(&end_time);
    total_duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                               (end_time.millis - start_time.millis) * 1000;

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm9_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // SM9_POINT ds;
    // sm9_bn_from_hex(sm9_mpk.ks, hex_ks);
    // sm9_twist_point_mul_generator(&(sm9_mpk.Ppubs), sm9_mpk.ks);
    // if (sm9_sign_master_key_extract_key(&sm9_mpk, (char *)IDA, sizeof(IDA), &sm9_global_key) < 0)
    // {
    //     error_print();
    //     return -1;
    // }
    // sm9_point_from_hex(&ds, hex_ds);
    // if (!sm9_point_equ(&(sm9_global_key.ds), &ds))
    // {
    //     error_print();
    //     return -1;
    // }

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;

    // 记录开始时间
    TEE_Time start_time, end_time;
    TEE_GetSystemTime(&start_time);
    for (int i = 0; i < test_count; i++)
    {
        // 执行签名验签流程
        int result = _test_sm9_sign();

        if (result == 1)
        {
            success_count++;
        }
    }

    // 记录结束时间
    TEE_GetSystemTime(&end_time);

    // 计算耗时（微秒）
    total_duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                            (end_time.millis - start_time.millis) * 1000;

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm9_verify(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;

    // SM9_POINT ds;
    // SM9_SIGN_CTX ctx;

    // uint8_t siglen = strlen(sm9_sig);
    // sm9_bn_from_hex(sm9_mpk.ks, hex_ks);
    // sm9_twist_point_mul_generator(&(sm9_mpk.Ppubs), sm9_mpk.ks);
    // if (sm9_sign_master_key_extract_key(&sm9_mpk, (char *)IDA, sizeof(IDA), &sm9_global_key) < 0)
    // {
    //     error_print();
    //     return -1;
    // }
    // sm9_point_from_hex(&ds, hex_ds);
    // if (!sm9_point_equ(&(sm9_global_key.ds), &ds))
    // {
    //     error_print();
    //     return -1;
    // }

    // sm9_sign_init(&ctx);
    // sm9_sign_update(&ctx, data, sizeof(data));
    // if (sm9_sign_finish(&ctx, &sm9_global_key, sm9_sig, &siglen) < 0)
    // {
    //     error_print();
    //     return -1;
    // }

    // 记录开始时间
    TEE_Time start_time, end_time;
    TEE_GetSystemTime(&start_time);
    for (int i = 0; i < test_count; i++)
    {
        // 执行签名验签流程
        int result = _test_sm9_verify(sm9_siglen);

        

        if (result == 1)
        {
            success_count++;
        }
    }
    // 记录结束时间
    TEE_GetSystemTime(&end_time);
    // 计算耗时（微秒）
    total_duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                            (end_time.millis - start_time.millis) * 1000;

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}
TEE_Result Cmd_test_sm9_z256_sign(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    // 检查参数类型
    if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(paramTypes, 0))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    const int test_count = 10; // 测试10次取平均值
    uint32_t total_duration_us = 0;
    int success_count = 0;

    for (int i = 0; i < test_count; i++)
    {
        // 记录开始时间
        TEE_Time start_time, end_time;
        TEE_GetSystemTime(&start_time);

        // 执行签名验签流程
        int result = _test_sm9();

        // 记录结束时间
        TEE_GetSystemTime(&end_time);

        // 计算耗时（微秒）
        uint32_t duration_us = (end_time.seconds - start_time.seconds) * 1000000 +
                               (end_time.millis - start_time.millis) * 1000;

        if (result == 1)
        {
            success_count++;
            total_duration_us += duration_us;
        }
    }

    // 计算平均耗时
    uint32_t avg_duration_us = success_count > 0 ? total_duration_us / success_count : 0;

    // 返回结果和平均耗时
    params[0].value.a = (success_count == test_count) ? 1 : 0; // 成功标志（全部成功才为1）
    params[0].value.b = avg_duration_us;                       // 平均耗时（微秒）

    return TEE_SUCCESS;
}

/**-----------------------------------TA中必须定义的宏--------------------------------------*/
TEE_Result TA_CreateEntryPoint(void)
{
    // SLogTrace 可能是自定义函数，注意
    // SLogTrace("----- TA_CreateEntryPoint ----- "); // 删除打印以提升性能
    if (addcaller_ca_exec(CLIENT_APPLICATION_NAME, "root") == TEE_SUCCESS)
    {
        // SLogTrace("TA_CreateEntryPoint: AddCaller_CA_exec ok."); // 删除打印以提升性能
    }
    else
    {
        // SLogError("TA_CreateEntryPoint: AddCaller_CA_exec failed."); // 删除打印以提升性能
        return TEE_ERROR_GENERIC;
    }
    // SLogTrace("返回打印了TEE_SUCCESS"); // 删除打印以提升性能
    return TEE_SUCCESS;
}

// 打开一个session的进入点.
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[PARAMS_IDX4], void **sessionContext)
{
    TEE_Result ret = TEE_SUCCESS;
    // SLogTrace("---- TA_OpenSessionEntryPoint -------- "); // 删除打印以提升性能
    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    return ret;
}
// 传递调用参数的函数
TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmdId,
                                      uint32_t paramTypes, TEE_Param params[PARAMS_IDX4])
{
    TEE_Result ret = 0;
    // clock_t start_time, end_time;  // 未使用，注释掉
    // double duration_ms = 0.0;       // 未使用，注释掉

    // SLogTrace("---- TA_InvokeCommandEntryPoint ---- cmdid: %d ----", cmdId); // 删除打印以提升性能
    (void)sessionContext;
    switch (cmdId)
    {

    case test_sm2:
        ret = Cmd_test_sm2(paramTypes, params);
        break;
    case test_sm2_sign:
        ret = Cmd_test_sm2_sign(paramTypes, params);
        // SLogTrace("执行test_sm2_sign"); // 删除打印以提升性能
        break;
    case test_sm2_verify:
        ret = Cmd_test_sm2_verify(paramTypes, params);
        break;
    case test_sm3:
        ret = Cmd_test_sm3(paramTypes, params);
        // SLogTrace("执行test_sm3"); // 删除打印以提升性能
        break;
    case test_sm4:
        ret = Cmd_test_sm4(paramTypes, params);
        // SLogTrace("执行test_sm4"); // 删除打印以提升性能
        break;
    case test_sm9:
        ret = Cmd_test_sm9(paramTypes, params);
        // SLogTrace("执行test_sm9_z256_sign"); // 删除打印以提升性能
        break;
    case test_sm9_sign:
        ret = Cmd_test_sm9_sign(paramTypes, params);
        // SLogTrace("执行test_sm9_z256_sign"); // 删除打印以提升性能
        break;
    case test_sm9_verify:
        ret = Cmd_test_sm9_verify(paramTypes, params);
        // SLogTrace("执行test_sm9_z256_sign"); // 删除打印以提升性能
        break;

    default:
        // SLogTrace("Unknown cmdId: %d", cmdId); // 删除打印以提升性能
        ret = TEE_ERROR_NOT_SUPPORTED;
        break;
    }

    return ret;
}
// 在这里对于持久保存的对象进行销毁，或者进行创建工作
void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    // SLogTrace("---- TA_CloseSessionEntryPoint ----- "); // 删除打印以提升性能
}

void TA_DestroyEntryPoint(void)
{
    // SLogTrace("---- TA_DestroyEntryPoint ---- "); // 删除打印以提升性能
}

/*-----------------------------------------------------------------------*/
