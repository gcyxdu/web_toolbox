#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "gmssl_ca.h"
#include "iostream"
#include <iomanip>

#include "tee_client_api.h"
#include <chrono>
#include <functional>
#include <map>
#include "../common/config_loader.hpp"

/*-------------------------------------------*/

// da21c465-11dd-4c8d-862b-f0cbc4aff4df
static const TEEC_UUID TA_uuid = {
        0xda21c465, 0x11dd, 0x4c8d,
        { 0x86, 0x2b, 0xf0, 0xcb, 0xc4, 0xaf, 0xf4, 0xdf }
};
/*-------------------------------------------*/
TEEC_Context g_context;
TEEC_Session g_session;
/*---------------常量内容----------------*/
#define __DEBUG__ 1

namespace {

struct AppConfig {
    std::string ta_path;
};

AppConfig g_app_config;

AppConfig LoadAppConfig() {
    const auto config = seccom::LoadFlatYamlFile(
        seccom::JoinPath(seccom::GetExecutableDir(), "config.yaml"));
    return AppConfig{config.Require("ta_path")};
}

}  // namespace


enum {
    // cmd_test_sm2_sign = 0,
    // cmd_test_sm3,
    // cmd_test_sm4,
    // cmd_test_sm9_z256_sign
    cmd_test_sm2 = 0,
    cmd_test_sm2_sign,
    cmd_test_sm2_verify,
    cmd_test_sm3,
    cmd_test_sm4,
    cmd_test_sm9,
    cmd_test_sm9_sign,
    cmd_test_sm9_verify
};
/*-------------------------------------------*/
using namespace std;

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
// 关闭链接
void TeecClose(void)
{
        TEEC_CloseSession(&g_session);
        TEEC_FinalizeContext(&g_context);

        TEEC_Debug("teec uninit OK.");
}

/*-------------------------------------------*/

TEEC_Result _test_sm2(uint32_t *success_flag, uint32_t *duration_us)
{
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_InvokeCommand(&g_session, cmd_test_sm2, &operation, &origin);
    if (result != TEEC_SUCCESS)
    {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 获取TA返回的结果
    if (success_flag)
        *success_flag = operation.params[0].value.a;
    if (duration_us)
        *duration_us = operation.params[0].value.b;

    return result;
}
TEEC_Result  _test_sm2_sign(uint32_t* success_flag, uint32_t* duration_us){
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_OUTPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );

    result = TEEC_InvokeCommand(&g_session,cmd_test_sm2_sign,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    
    // 获取TA返回的结果
    if (success_flag) *success_flag = operation.params[0].value.a;
    if (duration_us) *duration_us = operation.params[0].value.b;
    
    return result;
}
TEEC_Result _test_sm2_verify(uint32_t *success_flag, uint32_t *duration_us)
{
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_InvokeCommand(&g_session, cmd_test_sm2_verify, &operation, &origin);
    if (result != TEEC_SUCCESS)
    {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 获取TA返回的结果
    if (success_flag)
        *success_flag = operation.params[0].value.a;
    if (duration_us)
        *duration_us = operation.params[0].value.b;

    return result;
}
TEEC_Result _test_sm9(uint32_t *success_flag, uint32_t *duration_us)
{
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_InvokeCommand(&g_session, cmd_test_sm9, &operation, &origin);
    if (result != TEEC_SUCCESS)
    {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 获取TA返回的结果
    if (success_flag)
        *success_flag = operation.params[0].value.a;
    if (duration_us)
        *duration_us = operation.params[0].value.b;

    return result;
}
TEEC_Result _test_sm9_sign(uint32_t *success_flag, uint32_t *duration_us)
{
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_InvokeCommand(&g_session, cmd_test_sm9_sign, &operation, &origin);
    if (result != TEEC_SUCCESS)
    {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 获取TA返回的结果
    if (success_flag)
        *success_flag = operation.params[0].value.a;
    if (duration_us)
        *duration_us = operation.params[0].value.b;

    return result;
}
TEEC_Result _test_sm9_verify(uint32_t *success_flag, uint32_t *duration_us)
{
    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_InvokeCommand(&g_session, cmd_test_sm9_verify, &operation, &origin);
    if (result != TEEC_SUCCESS)
    {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    // 获取TA返回的结果
    if (success_flag)
        *success_flag = operation.params[0].value.a;
    if (duration_us)
        *duration_us = operation.params[0].value.b;

    return result;
}
// TEEC_Result  _test_sm9_z256_sign(uint32_t* success_flag, uint32_t* duration_us){
//     TEEC_Operation operation;
//     TEEC_Result result;

//     uint32_t origin;
//     // 启动这次操作
//     operation.started = 1;

//     operation.paramTypes = TEEC_PARAM_TYPES(
//             TEEC_VALUE_OUTPUT,
//             TEEC_NONE,
//             TEEC_NONE,
//             TEEC_NONE
//     );

//     result = TEEC_InvokeCommand(&g_session,cmd_test_sm9_z256_sign,&operation,&origin);
//     if (result != TEEC_SUCCESS) {
//         printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
//         return result;
//     }
    
//     // 获取TA返回的结果
//     if (success_flag) *success_flag = operation.params[0].value.a;
//     if (duration_us) *duration_us = operation.params[0].value.b;
    
//     return result;
// }

TEEC_Result _test_sm3(uint32_t* success_flag, uint32_t* duration_us){
    TEEC_Operation operation = {0};
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_OUTPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );

    result = TEEC_InvokeCommand(&g_session,cmd_test_sm3,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    
    // 获取TA返回的结果
    if (success_flag) *success_flag = operation.params[0].value.a;
    if (duration_us) *duration_us = operation.params[0].value.b;
    
    return result;
}

TEEC_Result _test_sm4(uint32_t* success_flag, uint32_t* duration_us){
    TEEC_Operation operation = {0};
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_OUTPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
    );

    result = TEEC_InvokeCommand(&g_session,cmd_test_sm4,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke invoke_init failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }
    
    // 获取TA返回的结果
    if (success_flag) *success_flag = operation.params[0].value.a;
    if (duration_us) *duration_us = operation.params[0].value.b;
    
    return result;
}

/*-------------------------------------------*/
//using namespace std::chrono;  // 引入 chrono 命名空间

// 性能测试函数：统计1秒内能跑多少次完整流程
void performance_test_sm2_sign() {
    cout << "\n===== SM2 签名性能测试 =====" << endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time;
    int count = 0;
    uint32_t total_duration_us = 0;
    uint32_t success_count = 0;
    
    // 运行1秒
    while (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() < 1000) {
        uint32_t success_flag, duration_us;
        TEEC_Result result = _test_sm2_sign(&success_flag, &duration_us);
        
        if (result == TEEC_SUCCESS && success_flag == 1) {
            success_count++;
            total_duration_us += duration_us;
        }
        count++;
        
        end_time = std::chrono::high_resolution_clock::now();
    }
    
    auto total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    double avg_duration_us = success_count > 0 ? (double)total_duration_us / success_count : 0;
    
    cout << "测试时间: " << total_time_ms << " ms" << endl;
    cout << "TEE调用次数: " << count << endl;
    cout << "成功TEE调用次数: " << success_count << endl;
    cout << "实际签名次数: " << (count * 10) << endl;
    cout << "成功签名次数: " << (success_count * 10) << endl;
    cout << "每秒签名次数: " << (success_count * 10 * 1000.0 / total_time_ms) << " 次/秒" << endl;
    cout << "平均单次耗时: " << fixed << setprecision(2) << avg_duration_us << " μs" << endl;
}

// 性能测试函数：统计1秒内能跑多少次完整流程
void performance_test_sm2_verify()
{
    cout << "\n===== SM2 验签性能测试 =====" << endl;

    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time;
    int count = 0;
    uint32_t total_duration_us = 0;
    uint32_t success_count = 0;

    // 运行1秒
    while (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() < 1000)
    {
        uint32_t success_flag, duration_us;
        TEEC_Result result = _test_sm2_verify(&success_flag, &duration_us);

        if (result == TEEC_SUCCESS && success_flag == 1)
        {
            success_count++;
            total_duration_us += duration_us;
        }
        count++;

        end_time = std::chrono::high_resolution_clock::now();
    }

    auto total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    double avg_duration_us = success_count > 0 ? (double)total_duration_us / success_count : 0;

    cout << "测试时间: " << total_time_ms << " ms" << endl;
    cout << "TEE调用次数: " << count << endl;
    cout << "成功TEE调用次数: " << success_count << endl;
    cout << "实际验签次数: " << (count * 10) << endl;
    cout << "成功验签次数: " << (success_count * 10) << endl;
    cout << "每秒验签次数: " << (success_count * 10 * 1000.0 / total_time_ms) << " 次/秒" << endl;
    cout << "平均单次耗时: " << fixed << setprecision(2) << avg_duration_us << " μs" << endl;
}

void performance_test_sm9_sign() {
    cout << "\n===== SM9 签名性能测试 =====" << endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time;
    int count = 0;
    uint32_t total_duration_us = 0;
    uint32_t success_count = 0;
    
    // 运行1秒
    while (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() < 1000) {
        uint32_t success_flag, duration_us;
        TEEC_Result result = _test_sm9_sign(&success_flag, &duration_us);
        
        if (result == TEEC_SUCCESS && success_flag == 1) {
            success_count++;
            total_duration_us += duration_us;
        }
        count++;
        
        end_time = std::chrono::high_resolution_clock::now();
    }
    
    auto total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    double avg_duration_us = success_count > 0 ? (double)total_duration_us / success_count : 0;
    
    cout << "测试时间: " << total_time_ms << " ms" << endl;
    cout << "TEE调用次数: " << count << endl;
    cout << "成功TEE调用次数: " << success_count << endl;
    cout << "实际签名次数: " << (count * 10) << endl;
    cout << "成功签名次数: " << (success_count * 10) << endl;
    cout << "每秒签名次数: " << (success_count * 10 * 1000.0 / total_time_ms) << " 次/秒" << endl;
    cout << "平均单次耗时: " << fixed << setprecision(2) << avg_duration_us << " μs" << endl;
}

void performance_test_sm9_verify()
{
    cout << "\n===== SM9 验签性能测试 =====" << endl;

    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time;
    int count = 0;
    uint32_t total_duration_us = 0;
    uint32_t success_count = 0;

    // 运行1秒
    while (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() < 1000)
    {
        uint32_t success_flag, duration_us;
        TEEC_Result result = _test_sm9_verify(&success_flag, &duration_us);

        if (result == TEEC_SUCCESS && success_flag == 1)
        {
            success_count++;
            total_duration_us += duration_us;
        }
        count++;

        end_time = std::chrono::high_resolution_clock::now();
    }

    auto total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    double avg_duration_us = success_count > 0 ? (double)total_duration_us / success_count : 0;

    cout << "测试时间: " << total_time_ms << " ms" << endl;
    cout << "TEE调用次数: " << count << endl;
    cout << "成功TEE调用次数: " << success_count << endl;
    cout << "实际验签次数: " << (count * 10) << endl;
    cout << "成功验签次数: " << (success_count * 10) << endl;
    cout << "每秒验签次数: " << (success_count * 10 * 1000.0 / total_time_ms) << " 次/秒" << endl;
    cout << "平均单次耗时: " << fixed << setprecision(2) << avg_duration_us << " μs" << endl;
}

// 单次测试函数（显示TA侧10次平均结果）
void single_test_sm2() {
    cout << "\n===== SM2 单次测试 (TA侧10次平均) =====" << endl;
    
    uint32_t success_flag, avg_duration_us;
    TEEC_Result result = _test_sm2(&success_flag, &avg_duration_us);
    
    if (result == TEEC_SUCCESS) {
        cout << "测试结果: " << (success_flag ? "成功" : "失败") << endl;
        cout << "平均耗时: " << avg_duration_us << " μs" << endl;
        cout << "每秒可执行: " << (1000000.0 / avg_duration_us) << " 次" << endl;
    } else {
        cout << "测试失败，错误码: 0x" << hex << result << endl;
    }
}

void single_test_sm9() {
    cout << "\n===== SM9 单次测试 (TA侧10次平均) =====" << endl;
    
    uint32_t success_flag, avg_duration_us;
    TEEC_Result result = _test_sm9(&success_flag, &avg_duration_us);
    
    if (result == TEEC_SUCCESS) {
        cout << "测试结果: " << (success_flag ? "成功" : "失败") << endl;
        cout << "平均耗时: " << avg_duration_us << " μs" << endl;
        cout << "每秒可执行: " << (1000000.0 / avg_duration_us) << " 次" << endl;
    } else {
        cout << "测试失败，错误码: 0x" << hex << result << endl;
    }
}

// SM3简单测试函数
void test_sm3() {
    cout << "\n===== SM3 64字节哈希性能测试 =====" << endl;
    
    uint32_t success_flag, duration_us;
    TEEC_Result result = _test_sm3(&success_flag, &duration_us);
    
    if (result == TEEC_SUCCESS) {
        cout << "测试结果: " << (success_flag ? "成功" : "失败") << endl;
        cout << "一百万次哈希总耗时: " << duration_us << " μs" << endl;
        cout << "平均单次哈希耗时: " << (duration_us / 1000000.0) << " μs" << endl;
        cout << "每秒可执行哈希次数: " << (1000000.0 * 1000000 / duration_us) << " 次/秒" << endl;
        cout << "64字节数据吞吐量: " << (64 * 1000000.0 / duration_us) << " MB/s" << endl;
    } else {
        cout << "SM3测试失败，错误码: 0x" << hex << result << endl;
    }
}

// SM4简单测试函数
void test_sm4() {
    cout << "\n===== SM4 加密性能测试 =====" << endl;
    
    uint32_t success_flag, duration_us;
    TEEC_Result result = _test_sm4(&success_flag, &duration_us);
    
    if (result == TEEC_SUCCESS) {
        cout << "测试结果: " << (success_flag ? "成功" : "失败") << endl;
        cout << "一百万次加密总耗时: " << duration_us << " μs" << endl;
        cout << "平均单次加密耗时: " << (duration_us / 1000000.0) << " μs" << endl;
        cout << "每秒可执行加密次数: " << (1000000.0 * 1000000 / duration_us) << " 次/秒" << endl;
        cout << "16字节数据吞吐量: " << (16 * 1000000.0 / duration_us) << " MB/s" << endl;
    } else {
        cout << "SM4测试失败，错误码: 0x" << hex << result << endl;
    }
}

// 显示菜单
void showMenu() {
    cout << "\n===== 密码学性能测试菜单 =====" << endl;
    cout << "1. SM2 签名验签性能测试 (10次平均)" << endl;
    cout << "2. SM3 哈希性能测试 (一百万次)" << endl;
    cout << "3. SM4 加密性能测试 (一百万次)" << endl;
    cout << "4. SM9 签名验签性能测试 (10次平均)" << endl;
    cout << "5. SM2 1秒内签名次数测试" << endl;
    cout << "6. SM2 1秒内验签次数测试" << endl;
    cout << "7. SM9 1秒内签名次数测试" << endl;
    cout << "8. SM9 1秒内验签次数测试" << endl;
    cout << "0. 退出" << endl;
    cout << "=========================" << endl;
    cout << "请输入选项: ";
}
using namespace std::chrono;
void timed_run(const string& name, function<void()> func) {
    auto start = high_resolution_clock::now();
    func();
    auto end = high_resolution_clock::now();
    
    // 计算微秒级时间
    auto duration_us = duration_cast<microseconds>(end - start).count();
    // 计算纳秒级时间
    auto duration_ns = duration_cast<nanoseconds>(end - start).count();
    
    // 根据时间长度选择合适的显示单位
    if (duration_us >= 1000) {
        // 大于等于1ms，显示毫秒
        auto duration_ms = duration_us / 1000.0;
        cout << name << " finished in " << fixed << setprecision(3) << duration_ms << " ms" << endl;
    } else if (duration_us >= 1) {
        // 大于等于1μs，显示微秒
        cout << name << " finished in " << duration_us << " μs" << endl;
    } else {
        // 小于1μs，显示纳秒
        cout << name << " finished in " << duration_ns << " ns" << endl;
    }
}

int main(int argc, char *argv[]) {
        try {
                g_app_config = LoadAppConfig();
            } catch (const std::exception &ex) {
                std::cerr << "load config failed: " << ex.what() << std::endl;
                return -1;
            }
    (void)(argc); // 忽略参数
    (void)(argv); // 忽略参数

        // 初始化 TEEC
        if (TEEC_SUCCESS != TeecInit()) {
                std::cout << "TeecInit Failed!" << std::endl;
                return -1;
            }
        cout << "TeecInit SUCCESS" << endl;

    // 测试函数映射表
        map<int, pair<string, function<void()>>> testFunctions = {
            {1, {"SM2 单次测试", single_test_sm2}},
            {2, {"SM3 测试", test_sm3}},
            {3, {"SM4 测试", test_sm4}},
            {4, {"SM9 单次测试", single_test_sm9}},
            {5, {"SM2 1秒内签名次数测试", performance_test_sm2_sign}},
            {6, {"SM2 1秒内验签次数测试", performance_test_sm2_verify}},
            {7, {"SM9 1秒内签名次数测试", performance_test_sm9_sign}},
            {8, {"SM9 1秒内验签次数测试", performance_test_sm9_verify}}};
        int choice;
        do
        {
            showMenu();
            cin >> choice;

            // 处理输入错误
            if (cin.fail())
            {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "无效输入，请输入数字选项!" << endl;
                continue;
            }

            // 执行选择的测试
            switch (choice)
            {
            case 0:
                cout << "退出测试程序..." << endl;
                break;
            case 9:
                cout << "\n===== 执行所有测试 =====" << endl;
                for (const auto& test : testFunctions) {
                    timed_run(test.second.first, test.second.second);
                }
                break;
            default:
                if (testFunctions.find(choice) != testFunctions.end()) {
                    const auto& test = testFunctions[choice];
                    cout << "\n===== 执行 " << test.first << " =====" << endl;
                    timed_run(test.first, test.second);
                } else {
                    cout << "无效选项，请重新选择!" << endl;
                }
        }
    } while (choice != 0);

        // 关闭 TEEC
        TeecClose();

        return 0;
}
