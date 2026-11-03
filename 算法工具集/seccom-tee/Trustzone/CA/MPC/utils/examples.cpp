#include "examples.h"
#include "algorithm"
#include "../../common/config_loader.hpp"
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <random>   // 用于 std::random_device, std::mt19937, std::uniform_int_distribution
#include <iostream> // 用于 std::cout (如果你要输出随机数的话)

using namespace std;

namespace {

const std::string &GetMpcDataRoot() {
    static const std::string data_root = seccom::LoadFlatYamlFile(
        seccom::JoinPath(seccom::GetExecutableDir(), "config.yaml"))
        .Require("mpc_data_root");
    return data_root;
}

std::string BuildMpcDataPath(int random_num, const std::string &thread_name,
                             const std::string &relative_path) {
    return seccom::JoinPath(
        seccom::JoinPath(
            seccom::JoinPath(GetMpcDataRoot(), "Group_" + std::to_string(random_num)),
            thread_name),
        relative_path);
}

}  // namespace

struct timeval ts, te;
std::mutex mtx;  // 用于同步线程访问共享资源
std::condition_variable cv;  // 线程a等待的条件变量
int finish_a = 0;
int finish_b = 0;

/**
 * 测试乘法正确性
 */
void testMulFunction() {

    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "**************************多方数据求积功能测试**********************" << std::endl;
    int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector <uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testMulData/dataX.txt"), lineNum);
    vector <uint64_t> y = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testMulData/dataY.txt"), lineNum);

    assert(x.size() == y.size());

    size_t size = x.size();
    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; });
            finish_a = 0;
        }
        cout << "-----------------------------" << threadName << "-----------------------------" << endl;
        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据数目为：" << size << endl;
        cout << "秘密共享数据分片x为：" << endl;
        int limit = 10;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t) x[i] << "\t";
            else
                break;
        }
        cout << endl;

        cout << "秘密共享数据分片y为：" << endl;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t) y[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "----------------------------------------------------------------------------" << endl;
        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

    uint64_t z[size];
    funcMulMPC(x.data(), y.data(), z, size);
    {
        std::unique_lock <std::mutex> lock(mtx);
        cout << threadName << "开始执行" <<endl;
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_b == 1; }); 
            finish_b = 0;
        }
        cout << threadName << "乘法方案输出结果为：" << endl;
        printArray(z, size);
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if (threadName == "SERVER") {
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

}

/**
 * 测试乘法性能
 */
void testMulPerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "**************************多方数据求积性能测试**********************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size], y[size], z[size];
    for (int32_t i = 0; i < size; i++) {
        x[i] = i;
        y[i] = i;
    }

    gettimeofday(&ts, NULL);

    funcMulMPC(x, y, z, size);

    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "乘法方案进行" << size << "次计算所需的时间为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试除法正确性
 */
void testDivFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "****************除法功能测试**********************" << std::endl;

     int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector <uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testDivData/dataX.txt"), lineNum);
    vector <uint64_t> y = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testDivData/dataY.txt"), lineNum);

    assert(x.size() == y.size());

    size_t size = x.size();
    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI"){
            cv.wait(lock, [] { return finish_a == 1; }); 
            finish_a = 0;

        }
        cout << "-----------------------------" << threadName << "-----------------------------" << endl;
        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据数目为：" << size << endl;

        cout << "秘密共享数据分片x：" << endl;
        int limit = 10;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t) x[i] << "\t";
            else
                break;
        }
        cout << endl;

        cout << "秘密共享数据分片y：" << endl;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t) y[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "----------------------------------------------------------------------------" << endl;
        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印

            cv.notify_one();
        }
    }

    uint64_t z[size];
    funcCommonDiv(x.data(), y.data(), z, size);
    {
        std::unique_lock<std::mutex> lock(mtx);
        if(threadName == "CLI"){
            cv.wait(lock, [] { return finish_b == 1; }); 
            finish_b = 0;
        }
        cout << threadName <<"除法计算方案的输出结果为：" << endl;
        printArray(z, size);
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if(threadName == "SERVER"){
            finish_b = 1;
            cv.notify_one();
        }
    }

}

/**
 * 测试除法性能
 */
void testDivPerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "****************除法性能测试**********************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size], y[size], z[size];
    for (int32_t i = 0; i < size; i++) {
        x[i] = i;
        y[i] = i;
    }

    gettimeofday(&ts, NULL);

    funcCommonDiv(x, y, z, size);

    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "除法计算方案进行" << size << "次计算所需的时间为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试欧氏距离正确性
 */
void testEculidDistanceFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "**************************欧氏距离功能测试************************" << std::endl;

    int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);

    vector<uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testEculidDistanceData/dataX.txt"), lineNum);
    vector<uint64_t> y = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testEculidDistanceData/dataY.txt"), lineNum);

    assert(x.size() == y.size());

    size_t size = x.size();

    {
        std::unique_lock<std::mutex> lock(mtx);
        if(threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; }); 
            finish_a = 0;
        }
        cout << "-----------------------------" << threadName <<"-----------------------------"<< endl;
        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据维度为：" << size << endl;
        cout << "秘密共享数据分片x：" << endl;
        int limit = 10;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)x[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "秘密共享数据分片y：" << endl;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)y[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "----------------------------------------------------------------------------"<<endl;
        if(threadName == "SERVER"){
            finish_a = 1; // 让线程B开始打印

            cv.notify_one();
        }
    }

    uint64_t z;

    funcEuclidDistance(x.data(), y.data(), &z, size);

    {

        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_b == 1; }); 
            finish_b = 0;
        }
        cout << threadName << "欧氏距离方案输出结果为：" << (int64_t) z << endl;
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if (threadName == "SERVER") {
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }
   
}

/**
 * 测试欧氏距离性能
 */
void testEculidDistancePerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "**************************欧氏距离性能测试************************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size], y[size], z;
    for (int32_t i = 0; i < size; i++) {
        x[i] = i * 100;
        y[i] = i * 100;
    }

    gettimeofday(&ts, NULL);

    funcEuclidDistance(x, y, &z, size);

    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "欧氏距离方案进行" << size << "次计算所需的时间为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试比较操作正确性
 */
void testCompareFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "**************************秘密比较功能测试**************************" << std::endl;

     int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector<uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testCompareData/dataX.txt"), lineNum);
    vector<uint64_t> y = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testCompareData/dataY.txt"), lineNum);

    assert(x.size() == y.size());

    size_t size = x.size();

    {
        std::unique_lock<std::mutex> lock(mtx);
        if(threadName == "CLI"){
            cv.wait(lock, [] { return finish_a == 1; }); 
            finish_a = 0;
        }
        cout << "-----------------------------" << threadName <<"-----------------------------"<<endl;

        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据数目为：" << size << endl;
        cout << "秘密共享数据分片x：" << endl;
        cout << "x:" << endl;
        int limit = 10;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)x[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "秘密共享数据分片y：" << endl;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)y[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "----------------------------------------------------------------------------"<<endl;
        if(threadName == "SERVER"){
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

    uint64_t z[size];
    funcSecretCompare(x.data(), y.data(), z, size);
    {
        std::unique_lock<std::mutex> lock(mtx);
        if(threadName == "CLI"){
            cv.wait(lock, [] { return finish_b == 1; }); 
            finish_b = 0;
        }
        cout << threadName <<"秘密比较方案的输出结果为：" << endl;
        printArray(z, size);
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if(threadName == "SERVER"){
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

}

/**
 * 测试比较操作性能
 */
void testComparePerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "**************************秘密比较性能测试**************************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size], y[size];
    for (int32_t i = 0; i < size; i++) {
        x[i] = i + 100;
        y[i] = i * 2;
    }
    uint64_t z[size];

    gettimeofday(&ts, NULL);

    funcSecretCompare(x, y, z, size);

    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "秘密比较方案进行" << size << "次计算所需的时间为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试方差正确性
 */
void testVarianceFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "****************方差功能测试**********************" << std::endl;

     int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector<uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testVarianceData/data.txt"), lineNum);
    size_t size = x.size();


    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; }); 
            finish_a = 0;

        }
        cout << "-----------------------------" << threadName << "-----------------------------" << endl;
        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据数目为：" << size << endl;

        cout << "需要计算方差的输入数据为：" << endl;
        int limit = 10;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)x[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "----------------------------------------------------------------------------" << endl;
        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

    uint64_t z;
    funcVariance(x.data(), &z, size);

    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_b == 1; }); 
            finish_b = 0;
        }
        cout << threadName <<"方差计算结果分片为：" << z << endl;
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if (threadName == "SERVER") {
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

}

/**
 * 测试方差性能
 */
void testVariancePerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "****************方差性能测试**********************" << std::endl;

    int32_t size = 300;
    uint64_t x[size];
    uint64_t z;
    for (int32_t i = 0; i < size; i++) {
        x[i] = i + 100;
    }

    gettimeofday(&ts, NULL);

    funcVariance(x, &z, size);

    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "数据总个数为" << size << "时，进行方差计算的时间开销为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试皮尔逊相关系数正确性
 */
void testPearsonFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "******************皮尔逊相关系数功能测试******************" << std::endl;

     int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector<uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testPearsonData/dataX.txt"), lineNum);
    vector<uint64_t> y = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testPearsonData/dataY.txt"), lineNum);

    assert(x.size() == y.size());

    size_t size = x.size() - 1;


    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; }); 

            finish_a = 0;
        }
        cout << "-----------------------------" << threadName << "-----------------------------" << endl;
        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据维度为：" << size << endl;

        cout << "秘密共享数据分片x：" << endl;
        int limit = 10;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)x[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "x的标准差分片为：" << x[size] << endl;

        cout << "秘密共享数据分片y：" << endl;
        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t)y[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "y的标准差分片为：" << y[size] << endl;
        cout << "----------------------------------------------------------------------------" << endl;
        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

    uint64_t z;
    cout << threadName + "开始执行funcPearson()" << endl;
    funcPearson(x.data(), y.data(), &z, size);

    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_b == 1; }); 

            finish_b = 0;
        }
        cout << threadName <<"皮尔逊相关系数计算结果分片为：" << z << endl;
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if (threadName == "SERVER") {
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

}

/**
 * 测试皮尔逊相关系数性能
 */
void testPearsonPerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "******************皮尔逊相关系数性能测试******************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size + 1], y[size + 1];
    uint64_t z;

    for (int32_t i = 0; i < size; i++) {
        x[i] = i + 4;
        y[i] = i + 4;
    }

    x[size] = 100;
    y[size] = 231;

    gettimeofday(&ts, NULL);

    funcPearson(x, y, &z, size);

    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "数据总个数为" << size << "时，进行皮尔逊相关系数的时间开销为：" << timeconsume << "ms" << endl << endl;
}

/**
 *  测试距离相关系数正确性
 */
void testDistCorCoeffFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "***********************距离相关系数功能测试******************" << std::endl;

    int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector<uint64_t> A = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testDistCorCoefData/dataA.txt"), lineNum);
    vector<uint64_t> B = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testDistCorCoefData/dataB.txt"), lineNum);

    assert(A.size() == B.size());

    size_t len = A.size() - 1;
    size_t size = (size_t)(sqrt(len));

    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; });
            finish_a = 0;
        }
        cout << "-----------------------------" << threadName << "-----------------------------" << endl;
        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据维度为：" << size << endl;
        cout << "秘密共享数据分片A：" << endl;

        int limit = 10;
        for (size_t i = 0; i < len; i++) {
            if (i < limit)
                cout << (int64_t)A[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "A的标准差分片为：" << A[len] << endl;

        cout << "秘密共享数据分片B：" << endl;
        for (size_t i = 0; i < len; i++) {
            if (i < limit)
                cout << (int64_t)B[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "B的标准差分片为：" << B[len] << endl;
        cout << "----------------------------------------------------------------------------" << endl;
        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }

    uint64_t dcovAA = A[len] * size;
    uint64_t dcovBB = B[len] * size;
    uint64_t res;
    funcDistCorr(A.data(), B.data(), &dcovAA, &dcovBB, &res, size);

    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_b == 1; });
            finish_b = 0;
        }
        cout << threadName << "距离相关系数计算结果分片为：" << res << endl;
        if (threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if (threadName == "SERVER") {
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }
}

/**
 * 测试距离相关系数性能
 */
void testDistCorCoeffPerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "***********************距离相关系数性能测试******************" << std::endl;

    uint64_t A[25];
    uint64_t B[25];
    for (size_t i = 0; i < 25; i++) {
        A[i] = 0;
        B[i] = 0;
    }

    uint64_t dcovAA = 0;
    uint64_t dcovBB = 0;

    uint64_t res;

    gettimeofday(&ts, NULL);
    funcDistCorr(A, B, &dcovAA, &dcovBB, &res, 5);
    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "距离相关系数计算所需时间为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试排序正确性
 */
void testSortFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "***********************排序功能测试******************" << std::endl;
    int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);

    vector<uint64_t> x;
    if(threadName == "CLI"){
        x = readLineFromFile(
                BuildMpcDataPath(random_num, threadName, "testSortData/dataX.txt"), lineNum);
    }else if(threadName == "SERVER"){
        x = readLineFromFile(
                BuildMpcDataPath(random_num, threadName, "testSortData/dataY.txt"), lineNum);
    }
    size_t size = x.size();

    cout << threadName <<"当前测试数据组号为：" << random_num << endl;
    cout << "测试数据数目为：" << size << endl;
    cout << threadName <<"秘密共享数据分片x：" << endl;
    int limit = 10;
    for (size_t i = 0; i < size; i++) {
        if(i  < limit)
            cout << (int64_t)x[i] << "\t";
        else
            break;
    }
    cout << endl;

    uint64_t z[size];
    funcSecretSort(x.data(), z, size);


    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; });
            finish_a = 0;
        }
        cout << threadName <<"排序后的结果为：" << endl;
        printArray(z, size);
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");

        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }
}

/**
 * 测试排序性能
 */
void testSortPerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "***********************排序性能测试******************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size];
    for (int32_t i = 0; i < size; i++) {
        x[i] = rand() % 1000;
    }

    uint64_t z[size];

    gettimeofday(&ts, NULL);
    funcSecretSort(x, z, size);
    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "数据总个数为" << size << "时，进行排序计算的时间开销为：" << timeconsume << "ms" << endl << endl;
}

/**
 * 测试数据分箱正确性
 */
void testDataBinFunction() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "***********************数据分箱功能测试******************" << std::endl;

     int lineNum = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 999);
    int random_num = dist(gen);
    vector <uint64_t> x = readLineFromFile(
            BuildMpcDataPath(random_num, threadName, "testDataBinData/dataX.txt"),
            lineNum);

    size_t size = x.size();
    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_a == 1; });
            finish_a = 0;
        }
        cout << "-----------------------------" << threadName << "-----------------------------" << endl;

        cout << "当前测试数据组号为：" << random_num << endl;
        cout << "测试数据数目为：" << size << endl;

        cout << "秘密共享数据分片x：" << endl;
        int limit = 10;

        for (size_t i = 0; i < size; i++) {
            if(i  < limit)
                cout << (int64_t) x[i] << "\t";
            else
                break;
        }
        cout << endl;
        cout << "----------------------------------------------------------------------------" << endl;
        if (threadName == "SERVER") {
            finish_a = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }
    uint64_t z[size];
    funcDataBin(x.data(), z, size);
    {
        std::unique_lock <std::mutex> lock(mtx);
        if (threadName == "CLI") {
            cv.wait(lock, [] { return finish_b == 1; });
            finish_b = 0;
        }

        cout << threadName <<"数据分箱后的结果为：" << endl;
        printArray(z, size);
        if(threadName == "CLI")
            printf("\n测试功能结束，功能测试正常\n");
        if (threadName == "SERVER") {
            finish_b = 1; // 让线程B开始打印
            cv.notify_one();
        }
    }
}

/**
 * 测试数据分箱性能
 */
void testDataBinPerformance() {
    string threadName = getThreadName();

    if (threadName == "SERVER")
        std::cout << "***********************数据分箱性能测试******************" << std::endl;

    int32_t size = 1000;
    uint64_t x[size];
    for (int32_t i = 0; i < size; i++) {
        x[i] = rand() % 1000;
    }

    uint64_t z[size];

    gettimeofday(&ts, NULL);
    funcDataBin(x, z, size);
    gettimeofday(&te, NULL);

    double timeconsume = (te.tv_sec - ts.tv_sec) * 1000.0 + (te.tv_usec - ts.tv_usec) / 1000.0;
    if (threadName == "SERVER")
        cout << "数据总个数为" << size << "时，进行数据分箱计算的总时间开销为：" << timeconsume << "ms" << endl << endl;
}
