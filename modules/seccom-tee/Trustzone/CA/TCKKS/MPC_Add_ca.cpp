#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "MPC_Add_ca.h"
#include <sys/time.h>

#include <vector>
#include <iostream>
#include <fstream>
#include "GTCKKS/CTRingMultiplier.hpp"
#include "GTCKKS/scheme.hpp"
#include "GTCKKS/plaintext.hpp"

#include "tee_client_api.h"
#include "string"
#include "../common/config_loader.hpp"

using namespace std;
using namespace gtfhe;

// da21c465-11dd-4c8d-862b-f0cbc4aff4df
static const TEEC_UUID TA_uuid = {
        0xda21c465, 0x11dd, 0x4c8d,
        { 0x86, 0x2b, 0xf0, 0xcb, 0xc4, 0xaf, 0xf4, 0xdf }
};

/*---------------常量内容----------------*/
#define __DEBUG__ 1

/*-------------------------------------------*/
TEEC_Context g_context;
TEEC_Session g_session;
// #define N 3
struct timeval time1, time2;
float timeuse;

namespace {

struct AppConfig {
    std::string ta_path;
    std::string input_dir;
    int cipher_mul_log_n;
};

AppConfig g_app_config;

AppConfig LoadAppConfig() {
    const auto config = seccom::LoadFlatYamlFile(
        seccom::JoinPath(seccom::GetExecutableDir(), "config.yaml"));
    return AppConfig{
        config.Require("ta_path"),
        config.Require("input_dir"),
        config.GetInt("cipher_mul_log_n", 13),
    };
}

}  // namespace

/*-------------------------------------------*/
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
// 关闭链接
void TeecClose(void)
{
    TEEC_CloseSession(&g_session);
    TEEC_FinalizeContext(&g_context);

    TEEC_Debug("teec uninit OK.");
}

/**
 * @param PARTY_FLAG logN是公私钥的长度
 * */
TEEC_Result invoke_init(size_t logN,uint64_t * s,uint64_t * a,uint64_t * b,int addLength){

    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT
    );
    // sgx地方的密钥和这里是相同的，是一模一样的这是真的抽象啊
//    printf_ploy(s,(1 << logN));
//    printf_ploy(a,(1 << logN));
//    printf_ploy(b,(1 << logN));


    operation.params[0].tmpref.buffer = s;
    operation.params[0].tmpref.size = (1 << logN) * sizeof(uint64_t);
    operation.params[1].tmpref.buffer = a;
    operation.params[1].tmpref.size = (1 << logN) * sizeof(uint64_t);
    operation.params[2].tmpref.buffer = b;
    operation.params[2].tmpref.size = (1 << logN) * sizeof(uint64_t);
    operation.params[3].value.a = logN;
    operation.params[3].value.b = addLength;

    result = TEEC_InvokeCommand(&g_session,init,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    return result;
}
// 写的c0传入的是c1
TEEC_Result invoke_secure_add(size_t logN,void * c0, void * c1, void* batchCipher0, void* batchCipher1){

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
    operation.params[0].tmpref.buffer = c0;
    operation.params[0].tmpref.size = (1 << logN) * sizeof(uint64_t);
    operation.params[1].tmpref.buffer = c1;
    operation.params[1].tmpref.size = (1 << logN) * sizeof(uint64_t);
    operation.params[2].tmpref.buffer = batchCipher0;
    operation.params[2].tmpref.size = (1 << logN) * sizeof(uint64_t);
    operation.params[3].tmpref.buffer = batchCipher1;
    operation.params[3].tmpref.size = (1 << logN) * sizeof(uint64_t);

    result = TEEC_InvokeCommand(&g_session,secure_sum,&operation,&origin);



    if (result != TEEC_SUCCESS) {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    return result;
}
/*-------------------------------------------*/
void fast_Simple_decrypt_test(size_t logN)
{
    printf("************** enc test start **************\n");
    size_t slots = 1 << (logN);
    double *a = new double[slots];

    for (size_t i = 0; i < slots; i++)
    {
        a[i] = rand() % 1000 / 1000.0 * 10.0 + 100;
    }
    printf("plaintext1:\n");
    printf_vector(a, slots);

    // 2. scheme test
    Scheme scheme(logN, 60, 30, 100, 1);

    Plaintext plaintext1;
    Ciphertext ciphertext1;
    // linux独有函数，包括<sys/time>头文件也是独有
    gettimeofday(&time1, nullptr);

    scheme.Simpleencode(a, plaintext1, slots);
    gettimeofday(&time2, nullptr);
    scheme.async_encrypt(ciphertext1, plaintext1);
    printf(" async_encrypt time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000);

    gettimeofday(&time1, nullptr);
    scheme.fast_Simple_decrypt(plaintext1, ciphertext1);

    scheme.Simpledecode(plaintext1.coffe_data, plaintext1.length);

    gettimeofday(&time2, nullptr);
    printf(" fast_Simple_decrypt time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000);

    printf("decrypt:\n");
    printf_vector(scheme.Simpledecode(plaintext1.coffe_data, plaintext1.length), plaintext1.length);
    printf("************** dec test end **************\n");
}
static string input_filename;
void init_filePath(){

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_number = dist(gen);
    input_filename = seccom::JoinPath(
        g_app_config.input_dir, std::to_string(random_number) + ".txt");
    cout << "选择的文件" << input_filename << endl;
    return;
}
// 读取文件中下一个浮点数函数-3.0 - 3.0
double readNextDoubleFromFile(){

    static ifstream file(input_filename);
    static bool fileEnded = false;

    if (fileEnded) {
        file.clear();  // 清除 EOF 标志
        file.seekg(0, ios::beg);  // 重新回到文件开头
        fileEnded = false;
    }

    double value;
    if (file >> value) {
        return value;
    } else {
        // 文件读取充值到开头
        fileEnded = true;
        return readNextDoubleFromFile();
    }
}

void CipherMulPlain_test(size_t logN){
    size_t scale = 20;
    gettimeofday(&time1, nullptr);
    Scheme scheme(logN, 60, scale, 10, 1);
    gettimeofday(&time2, nullptr);
    printf("scheme initial time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double (time2.tv_usec - time1.tv_usec) / 1000 );
    // TODO 使用了Enclave
    invoke_init(logN, scheme.s, scheme.a, scheme.b,0);

    size_t slots = 1 << logN;
    double* a = new double[slots];
    double* b = new double[slots];

    for (size_t i = 0; i < slots; i++)
    {
        // 修改这里是从文件读取数据
        a[i] = readNextDoubleFromFile() * 1.0 - 1;
        b[i] = readNextDoubleFromFile() * 1.0 - 10;
    }
    printf("plaintext1:\n");
    printf_vector(a, slots);
    printf("plaintext2:\n");
    printf_vector(b, slots);


    Plaintext plaintext1, plaintext2;
    scheme.Simpleencode(a, plaintext1, slots);
    scheme.Simpleencode(b, plaintext2, slots);

    Ciphertext ciphertext1, ciphertext2;
    scheme.async_encrypt(ciphertext1, plaintext1);
    scheme.async_encrypt(ciphertext2, plaintext2);


    gettimeofday(&time1, nullptr);

    // secure multiple protocol
    Ciphertext ciphertext3;
    // TODO
    printf("进入方法 secure_mul_protocol..");
    scheme.secure_mul_protocol(ciphertext3, ciphertext1, ciphertext2);
    gettimeofday(&time2, nullptr);
    scheme.fast_Simple_decrypt(plaintext1, ciphertext3);
    printf_vector(scheme.Simpledecode(plaintext1.coffe_data, plaintext1.length), plaintext1.length);
    printf("secureMul time: %fms\n",
           (double)(time2.tv_sec - time1.tv_sec) * 1000 + double(time2.tv_usec - time1.tv_usec) / 1000);

    printf("************** mul test end **************\n");

}
/*-------------------------------------------*/
void SecureAdd(size_t logN, int len){
    size_t scale = 20;
    gettimeofday(&time1, nullptr);
    Scheme scheme(logN, 60, scale, 10, 1);
    gettimeofday(&time2, nullptr);
    printf("scheme initial time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double (time2.tv_usec - time1.tv_usec) / 1000 );

    invoke_init(logN, scheme.s, scheme.a, scheme.b,len);

    size_t slots = 1 << logN;
    double* a = new double[len];
    double a_sum_true = 0.0;

    for (size_t i = 0; i < len; i++)
    {
        a[i] = rand() % 1000 / 1000.0 * 1.0;
        a_sum_true += a[i];
    }
    printf("plaintext1:\n");
    printf_vector(a, len);
    cout << "True sum: " << a_sum_true << endl;


    Plaintext plaintext1;
    scheme.Simpleencode(a, plaintext1, slots);

    Ciphertext ciphertext1;
    scheme.async_encrypt(ciphertext1, plaintext1);

    gettimeofday(&time1, nullptr);

    // 1.1 生成随机掩码
    uint64_t* rand_number = new  uint64_t[len];
    uint64_t rand_number_num = 0;
    for (size_t i = 0; i < len; i++)
    {
        rand_number[i] = rand() % (1<<20);
        rand_number_num += rand_number[i];
    }
    // 1.2 添加随机掩码
    scheme.add(ciphertext1, rand_number, len);

    // 1.3 TEE解密求和
    uint64_t* temp1 = new uint64_t[scheme.ploy_modulus_degree];
    uint64_t* temp2 = new uint64_t[scheme.ploy_modulus_degree];

    invoke_secure_add(logN,ciphertext1.c0, ciphertext1.c1, temp1, temp2);

    Ciphertext ciphertext2;
    ciphertext2.ploy_modulus_degree = scheme.ploy_modulus_degree;
    ciphertext2.c0 = temp1;
    ciphertext2.c1 = temp2;
    ciphertext2.scale_factor = scale;
    ciphertext2.length = 1;

    ciphertext2.c0[0] -= rand_number_num;

    gettimeofday(&time2, nullptr);
    printf("secureAdd time: %fms\n", (double)(time2.tv_sec - time1.tv_sec) * 1000 + double (time2.tv_usec - time1.tv_usec) / 1000 );

    scheme.fast_Simple_decrypt(plaintext1, ciphertext2);
    cout << "Decrypt sum:";
    printf_vector(scheme.Simpledecode(plaintext1.coffe_data, plaintext1.length), plaintext1.length);

    printf("********************end********************\n\n");

}

int main(int argc, char *argv[]){
    (void)(argc);
    (void)(argv);
    try {
        g_app_config = LoadAppConfig();
    } catch (const std::exception &ex) {
        std::cerr << "load config failed: " << ex.what() << std::endl;
        return -1;
    }
    init_filePath();
    // 初始化 TEEC
    if (TEEC_SUCCESS != TeecInit()) {
        std::cout << "TeecInit Failed!" << std::endl;
        return -1;
    }
    CipherMulPlain_test(g_app_config.cipher_mul_log_n);

    TeecClose();
    return 0;
}
