#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "MPC_ca.h"
#include "utils/examples.h"
#include "utils/func.h"
#include "thread"
#include "../common/config_loader.hpp"
// 后续加入的TEE的内容
#include "tee_client_api.h"



/*-------------------------------------------*/
using namespace std;
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
/*-------------------------------------------*/
// 初始化TEE的g_context以及g_session
/* initialize context and opensession */
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

void printMenu()
{
    std::cout << "******************菜单******************" << std::endl;
    std::cout << "退出程序请输入：0" << std::endl;

    std::cout << "执行安全多方数据求积功能测试请输入：1" << std::endl;

    std::cout << "执行安全多方数据求积性能测试请输入：2" << std::endl;

    std::cout << "执行安全多方数据求商功能测试请输入：3" << std::endl;

    std::cout << "执行安全多方数据求商性能测试请输入：4" << std::endl;

    std::cout << "执行安全多方数据求方差功能测试请输入：5" << std::endl;

    std::cout << "执行安全多方数据求方差性能测试请输入：6" << std::endl;

    std::cout << "执行欧氏距离功能测试请输入：7" << std::endl;

    std::cout << "执行欧氏距离性能测试请输入：8" << std::endl;

    std::cout << "执行皮尔逊相关系数功能测试请输入：9" << std::endl;

    std::cout << "执行皮尔逊相关系数性能测试请输入：10" << std::endl;

    std::cout << "执行秘密比较功能测试请输入：11" << std::endl;

    std::cout << "执行秘密比较性能测试请输入：12" << std::endl;

    std::cout << "执行数据分箱功能测试请输入：13" << std::endl;

    std::cout << "执行数据分箱性能测试请输入：14" << std::endl;

    std::cout << "执行距离相关系数功能测试请输入：15" << std::endl;

    std::cout << "执行距离相关系数性能测试请输入：16" << std::endl;

    std::cout << std::endl;
}

/*-------------------------------------------*/
void serverThread(int choice) {
    // 设置为 PARTY1
    setThreadName("SERVER");
    // 创建 server 监听
    initializeCommunication(SERVER_PORT);

    switch (choice)
    {
        case 0:
            cout << "程序退出中..." << endl;
            break;
        case 1:
            testMulFunction();
            break;
        case 2:
            testMulPerformance();
            break;
        case 3:
            testDivFunction();
            break;
        case 4:
            testDivPerformance();
            break;
        case 5:
            testVarianceFunction();
            break;
        case 6:
            testVariancePerformance();
            break;
        case 7:
            testEculidDistanceFunction();
            break;
        case 8:
            testEculidDistancePerformance();
            break;
        case 9:
            testPearsonFunction();
            break;
        case 10:
            testPearsonPerformance();
            break;
        case 11:
            testCompareFunction();
            break;
        case 12:
            testComparePerformance();
            break;
        case 13:
            testDataBinFunction();
            break;
        case 14:
            testDataBinPerformance();
            break;
        case 15:
            testDistCorCoeffFunction();
            break;
        case 16:
            testDistCorCoeffPerformance();
            break;
        default:
            cout << "非法命令，请重新输入" << endl;
            break;
    }
}

void cliThread(int choice) {
    // 设置为 PARTY0
    setThreadName("CLI");
    // 创建 cli 连接
    initializeCommunication(SERVER_IP, SERVER_PORT);


    switch (choice)
    {
        case 0:
            break;
        case 1:
            testMulFunction();
            break;
        case 2:
            testMulPerformance();
            break;
        case 3:
            testDivFunction();
            break;
        case 4:
            testDivPerformance();
            break;
        case 5:
            testVarianceFunction();
            break;
        case 6:
            testVariancePerformance();
            break;
        case 7:
            testEculidDistanceFunction();
            break;
        case 8:
            testEculidDistancePerformance();
            break;
        case 9:
            testPearsonFunction();
            break;
        case 10:
            testPearsonPerformance();
            break;
        case 11:
            testCompareFunction();
            break;
        case 12:
            testComparePerformance();
            break;
        case 13:
            testDataBinFunction();
            break;
        case 14:
            testDataBinPerformance();
            break;
        case 15:
            testDistCorCoeffFunction();
            break;
        case 16:
            testDistCorCoeffPerformance();
            break;
        default:
            break;
    }
}
/*-------------------------------------------*/


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
    cout << "TeecInit SUCCESS" <<endl;


    int choice;
    do
    {
        printMenu();

        std::cin >> choice;
        std::thread server(serverThread,choice);
        std::thread cli(cliThread,choice);

        server.join();
        cli.join();

    } while (choice != 0);

    // 关闭 TEEC
    TeecClose();

    return 0;
}
