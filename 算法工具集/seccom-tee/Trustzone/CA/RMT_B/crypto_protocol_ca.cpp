#include <libgen.h>
#include "crypto_protocol_ca.h"
#include <cstring>
#include <sys/time.h>
#include "iostream"
#include <string>
#include <sstream>
#include <fstream>
#include <random>
#include "utils/she.h" //REE侧的TEE
#include "utils/sheFloat.h"
#include "../common/config_loader.hpp"
// 后续加入的TEE的内容
#include "tee_client_api.h"
#include "string"

/*-------------------------------------------*/
// da21c465-11dd-4c8d-862b-f0cbc4aff4df
static const TEEC_UUID TA_uuid = {
        0xda21c465, 0x11dd, 0x4c8d,
        { 0x86, 0x2b, 0xf0, 0xcb, 0xc4, 0xaf, 0xf4, 0xdf }
};
TEEC_Context g_context;
TEEC_Session g_session;

/*------------------常量内容------------------*/
#define __DEBUG__ 1
enum {
    sheRescale = 0,
    sheRescaleNeg,
    keySynthronize,
    reluCipherMulTEE,
    sheGenerateRandomKeysTee2,
};

/**---------------------------------------------------------*/
using namespace std;
namespace {

struct AppConfig {
    std::string ta_path;
    std::string input_dir;
    std::size_t combined_str_len;
    int k;
    int test_times;
};

AppConfig g_app_config;

AppConfig LoadAppConfig() {
    const auto config = seccom::LoadFlatYamlFile(
        seccom::JoinPath(seccom::GetExecutableDir(), "config.yaml"));
    return AppConfig{
        config.Require("ta_path"),
        config.Require("input_dir"),
        config.GetSizeT("combined_str_len", 60000),
        config.GetInt("k", 1000000),
        config.GetInt("test_times", 1000),
    };
}

}  // namespace

TEEC_Result TeecInit(void)
{

    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;

    result = TEEC_InitializeContext(nullptr, &g_context);
    if (result != TEEC_SUCCESS) {
        cout<<("teec initial failed")<<endl;
        return result;
    }

    /* pass TA's FULLPATH to TEE, then OpenSession. */
    /* CA MUST use the TEEC_LOGIN_IDENTIFY mode to login. */
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT);
    g_context.ta_path = reinterpret_cast<uint8_t *>(
        const_cast<char *>(g_app_config.ta_path.c_str()));

    result = TEEC_OpenSession(&g_context, &g_session, &TA_uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("open session failed: result:%x orgin: %u.\n", (int)result, origin);
        TEEC_FinalizeContext(&g_context);
        return result;
    }

    TEEC_Debug("teec init OK.");
    return result;
}

void TeecClose(void)
{
    TEEC_CloseSession(&g_session);
    TEEC_FinalizeContext(&g_context);

    TEEC_Debug("teec uninit OK.");
}

TEEC_Result invoke_sheRescale(BIGNUM *output, BIGNUM *input, int k, int kTimes){

    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT,
            TEEC_VALUE_INPUT
    );

    char *str2 = BN_bn2dec(input);
    size_t len2 = strlen(str2) + 1;
    char *buffer2 = (char *)malloc(len2);

    // 申请的buff1长度是buffer2的十倍长
    char * buffer1 = (char * )malloc(len2 * 1.5);

    memcpy(buffer2, str2, len2);
    // 释放不需要的str
    OPENSSL_free(str2);

    operation.params[0].tmpref.buffer = buffer1;
    operation.params[0].tmpref.size = len2 * 1.5;
    operation.params[1].tmpref.buffer = buffer2;
    operation.params[1].tmpref.size = len2;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;
    result = TEEC_InvokeCommand(&g_session,sheRescale,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke invoke_sheRescale failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    // 接收返回的参数
    if (!BN_dec2bn(&output, (char*)operation.params[0].tmpref.buffer)){
        cout << "Failed to convert decimal string to BIGNUM" <<endl;
    }
    TEEC_Debug("invoke invoke_sheRescale is successed.");
    free(buffer2);
    free(buffer1);
    return result;
}
TEEC_Result invoke_sheRescaleNeg(BIGNUM *output, BIGNUM *input, int k, int kTimes){

    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT,
            TEEC_VALUE_INPUT
    );

    char *str2 = BN_bn2dec(input);
    size_t len2 = strlen(str2) + 1;
    char *buffer2 = (char *)malloc(len2);

    memcpy(buffer2, str2, len2);
    // 释放不需要的str
    OPENSSL_free(str2);

    char * buffer1 = (char *)malloc(len2 * 1.5);

    operation.params[0].tmpref.buffer = buffer1;
    operation.params[0].tmpref.size = len2 * 1.5;
    operation.params[1].tmpref.buffer = buffer2;
    operation.params[1].tmpref.size = len2;
    operation.params[2].value.a = k;
    operation.params[3].value.a = kTimes;

    result = TEEC_InvokeCommand(&g_session,sheRescaleNeg,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        cout <<"invoke_sheRescaleNeg失败"<< endl;
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    // 接收返回的参数
    if (!BN_dec2bn(&output, (char*)operation.params[0].tmpref.buffer)){
        cout << "Failed to convert decimal string to BIGNUM" <<endl;
    }
    TEEC_Debug("invoke GenerateRandomCmd is successed.");
    free(buffer2);
    free(buffer1);
    return result;
}
static bool process_response_from_tee(char *combined_str, BIGNUM **p, BIGNUM **q, BIGNUM **l,
                                      BIGNUM **n, BIGNUM **e_negative1, BIGNUM **l_2,
                                      BIGNUM **cipher_zero, BIGNUM **cipher_one, const char *SEPARATOR) {
    // 使用 strtok 分割字符串
    char *token;
    char *str = strdup(combined_str); // 使用 strdup 复制一份，strtok 会修改原字符串

    // 分割并转换为 BIGNUM
    token = strtok(str, SEPARATOR); // 分割第一个部分（p）
    if (!BN_dec2bn(p, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第二部分（q）
    if (!BN_dec2bn(q, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第三部分（l）
    if (!BN_dec2bn(l, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第四部分（n）
    if (!BN_dec2bn(n, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第五部分（e_negative1）
    if (!BN_dec2bn(e_negative1, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第六部分（l_2）
    if (!BN_dec2bn(l_2, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第七部分（cipher_zero）
    if (!BN_dec2bn(cipher_zero, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    token = strtok(NULL, SEPARATOR); // 分割第八部分（cipher_one）
    if (!BN_dec2bn(cipher_one, token)) {
        free(str);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    // 释放临时字符串
    free(str);

    return TEEC_SUCCESS;
}
TEEC_Result invoke_keySynthronize(BIGNUM *p, BIGNUM *q, BIGNUM *l, BIGNUM *n, BIGNUM *e_negative1, BIGNUM *l_2, BIGNUM *cipher_zero, BIGNUM *cipher_one){

    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t origin;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );

    char * SEPARATOR = "||";

    char *combined_str = (char *)malloc(g_app_config.combined_str_len);
    if (combined_str == NULL) {
        TEEC_Error("Memory allocation failed");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    operation.params[0].tmpref.buffer = combined_str;
    operation.params[0].tmpref.size = g_app_config.combined_str_len;

    result = TEEC_InvokeCommand(&g_session, keySynthronize, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        cout <<"invoke_keySynthronize失败"<<endl;
        TEEC_Error("invoke_keySynthronize failed, codes=0x%x, origin=0x%x", result, origin);
    }
    // 分割之后重新传递值
    bool ok = process_response_from_tee(combined_str, &p, &q, &l, &n, &e_negative1, &l_2,
                                        &cipher_zero, &cipher_one, SEPARATOR);
    free(combined_str);
    return result;
}

TEEC_Result invoke_reluCipherMulTEE(BIGNUM *output, BIGNUM *Eb, BIGNUM *Em, int k, int EmTimes){
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT
    );
    char *str2 = BN_bn2dec(Eb);
    char *str3 = BN_bn2dec(Em);

    // 分配内存并复制十进制字符串到缓冲区
    size_t len2 = strlen(str2) + 1;
    size_t len3 = strlen(str3) + 1;

    // 需要使用自己申请的内存,这里的空间能不能重新申请个差不多大的
    char *buffer2 = (char *)malloc(len2);
    char *buffer3 = (char *)malloc(len3);

    memcpy(buffer2, str2, len2);
    memcpy(buffer3, str3, len3);
    // 释放不需要的str
    OPENSSL_free(str2);
    OPENSSL_free(str3);
    char * buffer1 = (char *)malloc(max(len2,len3) * 1.5);

    operation.params[0].tmpref.buffer = buffer1;
    operation.params[1].tmpref.buffer = buffer2;
    operation.params[2].tmpref.buffer = buffer3;
    operation.params[0].tmpref.size = max(len2,len3) * 1.5;
    operation.params[1].tmpref.size = len2;
    operation.params[2].tmpref.size = len3;
    operation.params[3].value.a = k;
    operation.params[3].value.b = EmTimes;


    result = TEEC_InvokeCommand(&g_session,reluCipherMulTEE,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        cout << "invoke_reluCipherMulTEE 失败" << endl;
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    // 数值返回回来
    if (!BN_dec2bn(&output, (char*)operation.params[0].tmpref.buffer)){
        cout << "Failed to convert decimal string to BIGNUM" <<endl;
    }

    free(buffer1);
    free(buffer2);
    free(buffer3);

    TEEC_Debug("invoke GenerateRandomCmd is successed.")

    return result;
}
TEEC_Result invoke_SHEgenerateRandomKeysTee2(){
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );

    result = TEEC_InvokeCommand(&g_session,sheGenerateRandomKeysTee2,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    TEEC_Debug("invoke GenerateRandomCmd is successed.")
    return result;
}

/**---------------------------------------------------------*/

extern SHE_key KEY;

void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
void sheRefreshNeg(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx);
void reluCipherMul(BIGNUM *Eres, BIGNUM *Eb, BIGNUM *Em, int EmKTimes, SHE_key *key, int k, BN_CTX *ctx);
void BN_printf(BIGNUM *num);
/*---------------------------------------------------------*/
void timeStart(struct timeval *timePointer)
{
    gettimeofday(timePointer, NULL);
}
void timeEnd(struct timeval *timePointer1, struct timeval *timePointer2)
{
    float timeuse;
    gettimeofday(timePointer2, NULL);
    timeuse = (timePointer2->tv_sec - timePointer1->tv_sec) * 1000000 + timePointer2->tv_usec - timePointer1->tv_usec;
    printf("cost time(s):%f\n", timeuse / 1000000);
}

void keySynthronizeREE(SHE_key *key)
{
    invoke_keySynthronize(key->p, key->q, key->l, key->n, key->e_negative1, key->l_2, key->cipher_zero, key->cipher_one);
}

// 搞一个随机生成浮点数的函数
double getRandomDouble(double min, double max)
{
    // 创建一个随机数引擎，可以用不同的发生器来生成不同分布的随机数
    std::random_device rd;
    std::mt19937 gen(rd()); // 使用 Mersenne Twister 发生器

    // 创建一个均匀分布的浮点数分布，范围在 [min, max)
    std::uniform_real_distribution<double> dis(min, max);

    // 生成随机浮点数
    double random_double = dis(gen);
    return random_double;
}

void sheRefresh(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx)
{
    double r1 = getRandomDouble(0.0, 3.0);
    BN_CTX_start(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *kr1 = BN_CTX_get(ctx);
    int64_t kr1Int = (int64_t)(r1 * k);
    SHECipher tmp3;
    tmp3.cipher = tmp1;
    tmp3.kTimes = 0;
    BN_set_word(kr1, kr1Int);
    sheADDConstant(&tmp3, r1, input, k, key, ctx);
    // 进入TEE,tmp1输入，tmp2输出,输出tmp2的空间够么？所以加个复制
    BN_copy(tmp2, key->n); // 这个是为了保证出来有空间
    invoke_sheRescale(tmp2, tmp3.cipher, k, tmp3.kTimes);
    BN_mod_sub(output->cipher, tmp2, kr1, key->n, ctx); // 出来的那个不能是0，否则0减去会有问题
    output->kTimes = 1;
    BN_CTX_end(ctx);
}

// input 可以和output相同
// 比如E(k^5x)+k^5r进去TEE，TEE解密再加密出来为E(-k(x+r)),那么REE应该计算E(-k(x+r))+kr
void sheRefreshNeg(SHECipher *output, SHECipher *input, int k, SHE_key *key, BN_CTX *ctx)
{
    double r1 = getRandomDouble(0.0, 3.0);
    BN_CTX_start(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    BIGNUM *kr1 = BN_CTX_get(ctx);
    int64_t kr1Int = (int64_t)(r1 * k);
    SHECipher tmp3;
    tmp3.cipher = tmp1;
    tmp3.kTimes = 0;
    BN_set_word(kr1, kr1Int);
    sheADDConstant(&tmp3, r1, input, k, key, ctx);
    // 进入TEE,tmp1输入，tmp2输出,输出tmp2的空间够么？所以加个复制
    BN_copy(tmp2, key->n); // 这个是为了保证出来有空间
    invoke_sheRescaleNeg(tmp2, tmp3.cipher, k, tmp3.kTimes);
    BN_mod_add(output->cipher, tmp2, kr1, key->n, ctx);
    output->kTimes = 1;
    BN_CTX_end(ctx);
}


void reluCipherMul(BIGNUM *Eres, BIGNUM *Eb, BIGNUM *Em, int EmKTimes, SHE_key *key, int k, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *r1 = BN_CTX_get(ctx);
    BIGNUM *r2 = BN_CTX_get(ctx);
    BIGNUM *tmp1Big = BN_CTX_get(ctx);
    BIGNUM *tmp2Big = BN_CTX_get(ctx);
    BIGNUM *tmp3Big = BN_CTX_get(ctx);
    BIGNUM *tmp4Big = BN_CTX_get(ctx);
    BIGNUM *res = BN_CTX_get(ctx);
    SHECipher tmp1;
    BN_copy(tmp1Big, Em);
    sheInitC(&tmp1, tmp1Big, EmKTimes);
    SHECipher tmp2;
    sheInitC(&tmp2, tmp2Big, 0);

    sheRefresh(&tmp1, &tmp1, k, key, ctx); // 变成只有一倍扩张,扰动前的变量需要保存，因为后面恢复需要
    int r1_int = rand() % 10 + 1;
    r1_int = 10;
    int r2_int = rand() % 8 + 1;
    r2_int = 5;
    BN_set_word(r1, r1_int); // 掩盖Eb
    BN_set_word(r2, r2_int);

    BN_sub(tmp3Big, Eb, r1); // 扰动Eb
    BN_sub(tmp2.cipher, tmp1.cipher, r2); // tmp2为扰动后的Em，tmp1为扰动前扩大次数为1的m
    tmp2.kTimes = 1;
    BN_copy(res, key->n);
    invoke_reluCipherMulTEE(res , tmp3Big, tmp2.cipher, k, tmp2.kTimes); // res就是(b-r1)(km+r2)
    BN_mod_mul(tmp3Big, Eb, r2, key->n, ctx); // Eb*r2
    BN_mod_add(tmp4Big, res, tmp3Big, key->n, ctx);

    BN_mod_mul(tmp3Big, tmp1.cipher, r1, key->n, ctx); // Ekm_*r1

    BN_mod_add(res, tmp4Big, tmp3Big, key->n, ctx);

    BN_mul(tmp3Big, r2, r1, ctx); // r1*r2
    BN_mod_sub(tmp4Big, res, tmp3Big, key->n, ctx);

    BN_copy(Eres, tmp4Big);
    BN_CTX_end(ctx);
}

string readNextStringFromFile() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_number = dist(gen);
    string input_filename = seccom::JoinPath(g_app_config.input_dir, std::to_string(random_number) + ".txt");

    static ifstream file(input_filename);
    static bool fileEnded = false;

    if (fileEnded) {
        file.clear();  // 清除 EOF 标志
        file.seekg(0, ios::beg);  // 重新回到文件开头
        fileEnded = false;
    }

    string value;
    if (file >> value) {
        return value;  // 直接返回字符串
    } else {
        // 重新读取文件
        fileEnded = true;
        return readNextStringFromFile();
    }
}

int sheTestTimePerformance(int k, SHE_key *key)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *random_plain1 = BN_CTX_get(ctx);
    BIGNUM *random_plain2 = BN_CTX_get(ctx);
    BIGNUM *cipher1 = BN_CTX_get(ctx);
    BIGNUM *cipher2 = BN_CTX_get(ctx);

    BIGNUM *decrypted_random1 = BN_CTX_get(ctx);
    BIGNUM *decrypted_random2 = BN_CTX_get(ctx);
    BIGNUM *tmp_result1 = BN_CTX_get(ctx);
    BIGNUM *tmp_result2 = BN_CTX_get(ctx);
    int depth = 0;
    int testTimes = g_app_config.test_times;

    clientInteraction();
    goto exit;

    exit:
    return ret;

    // TODO
    string  plain1 = readNextStringFromFile();
    string  plain2 = readNextStringFromFile();

    // 将字符串转换为 BIGNUM
    if (!BN_dec2bn(&random_plain1, plain1.c_str())) {
        cout << "转换 plain1 失败" << endl;
    }
    if (!BN_dec2bn(&random_plain2, plain2.c_str())) {
        cout << "转换 plain2 失败" << endl;
    }

    BN_set_word(random_plain2, 300000000000);

    // cout << "明文: ";
    bn_printfDec(random_plain1);

    she_encryptBignumSupportNegative2(cipher1, random_plain1, key, ctx);
    she_encryptBignumSupportNegative2(cipher2, random_plain2, key, ctx);
    she_decryptBignum(decrypted_random1, cipher1, key, ctx);
    she_decryptBignum(decrypted_random2, cipher2, key, ctx);

    // cout << "密文(部分): " << endl;
    bn_printfHex(cipher1);

    // cout << "\n重复1000次测试用时: " << endl;
    struct timeval t1;
    struct timeval t2;
    // cout << "加密用时：" << endl;
    // timeStart(&t1);
    for (int i = 0; i < testTimes; ++i)
        she_encryptBignumSupportNegative2(cipher1, random_plain1, key, ctx);
    // timeEnd(&t1, &t2);
    // cout << "解密用时：" << endl;
    // timeStart(&t1);
    for (int i = 0; i < testTimes; ++i)
        she_decryptBignum(decrypted_random1, cipher1, key, ctx);
    // timeEnd(&t1, &t2);
    // cout << "密文加法用时：" << endl;
    // timeStart(&t1);
    for (int i = 0; i < testTimes; ++i)
        BN_mod_add(tmp_result1, cipher1, cipher2, key->n, ctx);
    // timeEnd(&t1, &t2);
    // cout << "明密文乘法用时：" << endl;
    // timeStart(&t1);
    for (int i = 0; i < testTimes; ++i)
        BN_mod_mul(tmp_result1, random_plain1, cipher2, key->n, ctx);
    // timeEnd(&t1, &t2);
    // cout << "密文乘法用时：" << endl;
    if (depth == 0)
    {
        // timeStart(&t1);
        for (int i = 0; i < testTimes; ++i)
            reluCipherMul(tmp_result1, cipher1, cipher2, 2, key, k, ctx);
        // timeEnd(&t1, &t2);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    ret = 1;
    end:
    if (!ret)
    {
        printf("EfficiencyTest Error\n");
    }
    return ret;
}

/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    try {
        g_app_config = LoadAppConfig();
    } catch (const std::exception &ex) {
        std::cerr << "load config failed: " << ex.what() << std::endl;
        return -1;
    }
    if (TEEC_SUCCESS != TeecInit()) {
        std::cout << "TeecInit Failed!" << std::endl;
        return -1;
    }
    int k = g_app_config.k;
    invoke_SHEgenerateRandomKeysTee2();
    she_generateRandomKeysTee2(); // REE侧的初始化，用来方便测试用的
    keySynthronizeREE(&KEY);
    sheTestTimePerformance(k, &KEY);

    return 0;
}


void BN_printf(BIGNUM *num)
{
    char *tmp = NULL;
    tmp = BN_bn2dec(num);
    printf("%s", tmp);
    // printf("\n");
}

