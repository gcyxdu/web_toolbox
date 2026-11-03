#include "func.h"
#include <random>
#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstring>
#include <map>
#include "tee_client_api.h"


using std::bitset;
using std::random_shuffle;
using std::swap;

std::mt19937_64 rd_cli(1);
std::mt19937_64 rd_server(1);
std::mt19937_64 rd(1);
std::mt19937 rdForCompare(1);

BSNet *bsnet_server;
BSNet *bsnet_cli;

using std::cout;
using std::endl;

std::map<std::thread::id, std::string> threadNames;
extern TEEC_Context g_context;
extern TEEC_Session g_session;
// invoke的函数编号
enum {
    // 定义调用函数
    GenAndOutBeaverTribles = 0,

};

/*--------------------------------------------------------------------------*/
/**
 * @param PARTY_FLAG 0是代表CLI，而1是代表server
 * */
TEEC_Result invoke_GenAndOutBeaverTribles(uint64_t *arr, size_t len,int PARTY_FLAG){

    TEEC_Operation operation;
    TEEC_Result result;

    uint32_t origin;
    // 启动这次操作
    operation.started = 1;

    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_VALUE_INPUT,
            TEEC_NONE,
            TEEC_NONE
    );

    // 这里的arr能不能直接传递
    operation.params[0].tmpref.buffer = arr;
    // 这里的len就是size的值
    operation.params[0].tmpref.size = len;
    operation.params[1].value.a = PARTY_FLAG;

    result = TEEC_InvokeCommand(&g_session,GenAndOutBeaverTribles,&operation,&origin);
    if (result != TEEC_SUCCESS) {
        TEEC_Error("invoke GenerateRandomCmd failed, codes=0x%x, origin=0x%x", result, origin);
        return result;
    }

    return result;
}

/*--------------------------------------------------------------------------*/

/**
 * 给线程设置姓名
 * */
void setThreadName(const std::string& name) {
    threadNames[std::this_thread::get_id()] = name;
}

/**
 * 获取线程名
 * */
std::string getThreadName() {
    auto it = threadNames.find(std::this_thread::get_id());
    if (it != threadNames.end()) {
        return it->second;
    }
    return "Unknown"; // Default if no name is set
}
/**
 * 初始化通信函数 host: 服务器地址 port: 服务器端口号
 */
void initializeCommunication(const char *host, unsigned int port)
{
    bsnet_cli = new BSNet(host, port);
    bsnet_cli->connectNow();
}

/**
 * 初始化通信函数，传入端口号来创建BSNet对象并开始监听
 */
void initializeCommunication(unsigned int port)
{
    bsnet_server = new BSNet(port);
    bsnet_server->listenNow();
}

/**
 * 初始化随机数生成器
 */
void initializeRandGen(const uint64_t &seed)
{
    rd.seed(seed);
}

/**
 * 生成随机数序列并存储到数组r中，序列长度为len
 */
void generateRand(uint64_t *r, int32_t len)
{
    for (int32_t i = 0; i < len; i++)
    {
        r[i] = rd();
    }
}

/**
 * 生成指定长度的随机数，并将其添加到给定的数组中
 */
void generateRand(vector<uint64_t> &vec, int32_t len)
{
    for (int32_t i = 0; i < len; i++)
    {
        vec.push_back(rd());
    }
}

void funcMulMPC(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)
{
    // 1. 获取乘法三元组
    uint64_t tribles_rand_num = size * 3;
    uint64_t *triblesbuff = (uint64_t *)malloc(sizeof (uint64_t) * tribles_rand_num);
    memset(triblesbuff, 0, sizeof(uint64_t) * tribles_rand_num);

    // 获取当前线程名字
    std::string threadName = getThreadName();
    if(threadName == "SERVER")
        invoke_GenAndOutBeaverTribles(triblesbuff, sizeof(uint64_t) * tribles_rand_num,1);
    if(threadName == "CLI")
        invoke_GenAndOutBeaverTribles(triblesbuff, sizeof(uint64_t) * tribles_rand_num,0);


    // 2.计算需要传递给对方的数据分片
    uint64_t doubleSize = size * 2;
    uint64_t dpart[size], epart[size], cpart[size];
    uint64_t sendpart[doubleSize], recvpart[doubleSize];
    uint64_t r0[size], r1[size];

    for (int32_t i = 0; i < size; i++)
    {
        uint64_t tribleIndex = 3 * i;

        if(threadName == "CLI"){
            r0[i] = rd_cli();
            r1[i] = rd_cli();
        }else if(threadName == "SERVER"){
            r0[i] = rd_server();
            r1[i] = rd_server();
        }
        dpart[i] = x[i] - triblesbuff[tribleIndex] - r0[i];
        epart[i] = y[i] - triblesbuff[tribleIndex + 1] - r1[i];
        cpart[i] = triblesbuff[tribleIndex + 2];
    }

    // 3.发送中间计算数据
    memcpy(sendpart, dpart, sizeof(dpart));
    memcpy(sendpart + size, epart, sizeof(epart));

    if (threadName == "CLI")
    {
        thread *threads = new thread[2];
        threads[0] = thread(&BSNet::sendMsg, bsnet_cli, &sendpart[0], sizeof(sendpart), 0);
        threads[1] = thread(&BSNet::recvMsg, bsnet_cli, &recvpart[0], sizeof(recvpart), 0);
        for (int32_t i = 0; i < 2; i++)
        {
            threads[i].join();
        }
        delete[] threads;
    }

    if (threadName == "SERVER")
    {
        thread *threads = new thread[2];
        threads[0] = thread(&BSNet::recvMsg, bsnet_server, &recvpart[0], sizeof(recvpart), 0);
        threads[1] = thread(&BSNet::sendMsg, bsnet_server, &sendpart[0], sizeof(sendpart), 0);
        for (int32_t i = 0; i < 2; i++)
        {
            threads[i].join();
        }
        delete[] threads;
    }

    // 4.计算乘法分片
    uint64_t d[size], e[size];
    if (threadName == "CLI")
    {
        for (int32_t i = 0; i < size; i++)
        {
            d[i] = dpart[i] + recvpart[i] + 2 * r0[i];
            e[i] = epart[i] + recvpart[size + i] + 2 * r1[i];
            z[i] = cpart[i] + e[i] * x[i] + d[i] * y[i] - e[i] * d[i];
        }
    }

    if (threadName == "SERVER")
    {
        for (int32_t i = 0; i < size; i++)
        {
            d[i] = dpart[i] + recvpart[i] + 2 * r0[i];
            e[i] = epart[i] + recvpart[size + i] + 2 * r1[i];
            z[i] = cpart[i] + e[i] * x[i] + d[i] * y[i];
        }
    }
}

void funcMSBA2B(const uint64_t *a, uint64_t *z, int32_t size)
{
    const int cChoose[]{1, -1};
    uint64_t r1[size]{0}, r2[size]{0};
    int c[size];
    uint64_t tmpr1, tmpr2;

    std::string threadName = getThreadName();
    if (threadName == "CLI")
    {
        for (int32_t i = 0; i < size; i++)
        {
            // TODO 随机数生成器
            tmpr1 = rdForCompare();
            tmpr2 = rdForCompare();
            r2[i] = tmpr1;
            r1[i] = r2[i] + tmpr2;
            c[i] = cChoose[rdForCompare() & 1];

            r1[i] *= c[i];

            if (c[i] == 1)
            {
                z[i] = 1;
            }
            else
            {
                z[i] = 0;
            }
        }
    }

    uint64_t res[size];

    funcMulMPC(a, r1, res, size);

    if (threadName == "CLI")
    {
        for (int32_t i = 0; i < size; i++)
        {
            res[i] = res[i] + c[i] * r2[i];
        }
        bsnet_cli->sendMsg(res, sizeof(res), 0);
    }

    if (threadName == "SERVER")
    {
        uint64_t res_recv[size];
        bsnet_server->recvMsg(res_recv, sizeof(res_recv), 0);

        for (int32_t i = 0; i < size; i++)
        {
            res[i] += res_recv[i];
            if ((res[i] >> 63) == 1)
            {
                z[i] = 0;
            }
            else
            {
                z[i] = 1;
            }
        }
    }
}

void funcDeRELUMPC(const uint64_t *a, uint64_t *z, int32_t size)
{
    uint64_t temp[size], tempMul[size];
    // MSBA2B协议，对于输入的秘密共享份额a，计算其原始值的最高比特位并转换为布尔共享存储至z中
    funcMSBA2B(a, temp, size);

    uint64_t anotherPart[size];
    memset(anotherPart, 0, sizeof(anotherPart));
    // 修改为判断线程名字


    std::string threadName = getThreadName();
    if (threadName == "CLI")
    {
        funcMulMPC(temp, anotherPart, tempMul, size);
    }

    if (threadName == "SERVER")
    {
        funcMulMPC(anotherPart, temp, tempMul, size);
    }

    for (int32_t i = 0; i < size; i++)
    {
        z[i] = temp[i] - 2 * tempMul[i];
        if (threadName == "CLI")
        {
            z[i] = -z[i] - rd_cli();
        }
        else if (threadName == "SERVER")
        {
            z[i] = 1 - z[i] + rd_server();
        }
        else
        {
            cout << "Error:Current Party not equals PARTY0 or PARTY1 !" << endl;
        }
    }
}

void calDivCoeff(const uint64_t *x, uint64_t *z, int32_t size)
{
    // z = 0 shares if x < 0  z = 1 shares if x >= 0
    funcDeRELUMPC(x, z, size);

    // 将 0 -> -1, 1 -> 1, 通过函数f(x) = 2x-1
    std::string threadName = getThreadName();

    for (int32_t i = 0; i < size; i++)
    {
        z[i] = (z[i] << 1);

        if (threadName == "CLI")
        {
            z[i] -= 1;
        }
    }
}
void funcDiv(const uint64_t *x, const uint64_t *y, uint64_t *q, int32_t size)
{
    uint64_t ul[size];
    std::string threadName = getThreadName();
    if (threadName == "CLI")
    {
        for (int32_t i = 0; i < size; i++)
        {
            ul[i] = rd_cli();
        }
    }
    if (threadName == "SERVER")
    {
        for (int32_t i = 0; i < size; i++)
        {
            ul[i] = -rd_server();
        }
    }

    uint64_t zi[size];
    uint64_t ki[64 * size];
    uint64_t beta[size];
    uint64_t a = 1;
    uint64_t v[size];
    uint64_t muly[size];

    for (int i = 15; i >= 0; i--)
    {
        for (int32_t j = 0; j < size; j++)
        {
            muly[j] = (a << i) * y[j];
            zi[j] = x[j] - ul[j] - muly[j];
        }
        funcDeRELUMPC(zi, beta, size);

        funcMulMPC(beta, muly, v, size);

        for (int32_t j = 0; j < size; j++)
        {
            ki[64 * j + i] = (a << i) * beta[j];
            ul[j] = ul[j] + v[j];
        }
    }

    for (int32_t j = 0; j < size; j++)
    {
        q[j] = 0;
        uint64_t kiIndex = 64 * j;
        for (int32_t i = 0; i < 16; i++)
        {
            q[j] += ki[kiIndex + i];
        }
    }
}

void funcCommonDiv(const uint64_t *x, const uint64_t *y, uint64_t *q, int32_t size)
{
    // 计算除数和被除数需要乘以的系数
    uint64_t zx[size], zy[size];
    calDivCoeff(x, zx, size);
    calDivCoeff(y, zy, size);

    // 将除数和被除数乘以系数
    uint64_t rectx[size], recty[size];
    funcMulMPC(x, zx, rectx, size);
    funcMulMPC(y, zy, recty, size);

    // 调用除法
    uint64_t tempQ[size];
    funcDiv(rectx, recty, tempQ, size);

    // 将结果乘以系数
    uint64_t midQ[size];
    funcMulMPC(tempQ, zx, midQ, size);
    funcMulMPC(midQ, zy, q, size);
}

/**
 * 计算（X，Y）间的欧几里得距离，计算结果保存在z中
 */
void funcEuclidDistance(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)
{
    uint64_t aerfa[size];
    uint64_t beta[size];
    uint64_t gamma[size];
    funcMulMPC(x, x, aerfa, size);
    funcMulMPC(y, y, beta, size);
    funcMulMPC(x, y, gamma, size);

    z[0] = 0;
    for (size_t i = 0; i < size; i++)
    {
        z[0] += aerfa[i] + beta[i] - 2 * gamma[i];
    }
}

void funcSecretCompare(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size){
    uint64_t xSuby[size];
    for (int32_t i = 0; i < size; i++)
    {
        xSuby[i] = x[i] - y[i];
    }
    uint64_t temp[size], tempMul[size];
    funcMSBA2B(xSuby, temp, size);
    uint64_t anotherPart[size];
    memset(anotherPart, 0, sizeof(anotherPart));
    std::string threadName = getThreadName();
    if (threadName == "CLI")
    {
        funcMulMPC(temp, anotherPart, tempMul, size);
    }

    if (threadName == "SERVER"){
        funcMulMPC(anotherPart, temp, tempMul, size);
    }
    for (int32_t i = 0; i < size; i++){
        z[i] = temp[i] - 2 * tempMul[i];
        if (threadName == "CLI"){
            z[i] = -z[i] - rd_cli();
        }
        else if (threadName == "SERVER"){
            z[i] = 1 - z[i] + rd_server();
        }else
        {
            cout << "Error:Current Party not equals PARTY0 or PARTY1 !" << endl;
        }
    }
}

void funcVariance(const uint64_t *x, uint64_t *z, int32_t size)
{
    // 1.发送自己的数据长度/接收对方的数据长度
    int32_t sizeRecv;
    std::string threadName = getThreadName();

    if (threadName == "CLI")
    {
        thread *threads = new thread[2];
        threads[0] = thread(&BSNet::sendMsg, bsnet_cli, &size, sizeof(size), 0);
        threads[1] = thread(&BSNet::recvMsg, bsnet_cli, &sizeRecv, sizeof(sizeRecv), 0);

        for (int32_t i = 0; i < 2; i++)
        {
            threads[i].join();
        }
        delete[] threads;
    }
    if (threadName == "SERVER")
    {
        thread *threads = new thread[2];
        threads[0] = thread(&BSNet::recvMsg, bsnet_server, &sizeRecv, sizeof(sizeRecv), 0);
        threads[1] = thread(&BSNet::sendMsg, bsnet_server, &size, sizeof(size), 0);
        for (int32_t i = 0; i < 2; i++)
        {
            threads[i].join();
        }
        delete[] threads;
    }

    uint64_t N = size + sizeRecv;

    // 2.每一方计算平方和以及平均值分片
    uint64_t quadraticSum = 0;
    uint64_t sum = 0;
    for (int32_t i = 0; i < size; i++)
    {
        quadraticSum += (x[i] * x[i]);
        sum += x[i];
    }

    // 3.每一方计算的平方和平均值和元素和平均值
    quadraticSum /= N;
    sum /= N;

    uint64_t squareOfMean;
    funcMulMPC(&sum, &sum, &squareOfMean, 1);

    z[0] = quadraticSum - squareOfMean;
}

/**
 * 计算Array(x,y)的协方差并将结果存储到z中
 */
void funcCovariance(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)
{
    // 首先计算E(XY)
    uint64_t EXY = 0;
    uint64_t XY[size];
    funcMulMPC(x, y, XY, size);

    // 计算E(X)，E(Y)
    uint64_t EX = 0, EY = 0;

    for (int32_t i = 0; i < size; i++)
    {
        EXY += XY[i];
        EX += x[i];
        EY += y[i];
    }

    uint64_t EXEY;
    funcMulMPC(&EX, &EY, &EXEY, 1);
    ::string threadName = getThreadName();
    // EXY /= size
    uint64_t divisor0 = 0, divisor1 = 0;
    if (threadName == "CLI")
    {
        divisor0 = size;
        divisor1 = size * size;
    }

    uint64_t tmpE[]{EXY, EXEY};
    uint64_t div[]{divisor0, divisor1};
    uint64_t mean[2];

    funcDiv(tmpE, div, mean, 2);

    z[0] = mean[0] - mean[1];
}

/**
 * 计算x，y间的皮尔逊相关系数并将结果存储到z中
 */
void funcPearson(const uint64_t *x, const uint64_t *y, uint64_t *z, int32_t size)
{
    // 1.计算协方差
    uint64_t covariance;
    funcCovariance(x, y, &covariance, size);
    covariance = covariance << 10;

    // 2.计算标准差的乘积
    uint64_t stdvMul;
    funcMulMPC(&x[size], &y[size], &stdvMul, 1);

    // 3.计算皮尔逊相关系数
    funcCommonDiv(&covariance, &stdvMul, z, 1);
}

/**
 * A，B，dcovAA，dcovBB为数据预处理后的数据，进一步计算距离相关系数并存储在res中
 */
void funcDistCorr(const uint64_t *A, const uint64_t *B, const uint64_t *dcovAA, const uint64_t *dcovBB, uint64_t *res, int32_t size)
{
    // A和B都是方阵，尺寸为Size*Size
    uint64_t len = size * size;
    uint64_t Z[len];
    funcMulMPC(A, B, Z, len);

    uint64_t dcovAB = 0;
    for (size_t i = 0; i < len; i++)
    {
        dcovAB += Z[i];
    }
    dcovAB = (dcovAB << 10);

    // 进行1次乘法调用
    uint64_t dcovAABB;

    funcMulMPC(dcovAA, dcovBB, &dcovAABB, 1);

    // 进行1次除法调用
    funcDiv(&dcovAB, &dcovAABB, res, 1);
}


/**
 * 数据分箱比较
 */
bool databinCompare(const uint64_t *x, const uint64_t *y, uint64_t *z)
{
    uint64_t x_sub_y;
    x_sub_y = x[0] - y[0];
    funcDeRELUMPC(&x_sub_y, z, 1);

    uint64_t r, send_z, recv_z;

    string threadName = getThreadName();
    if(threadName == "CLI"){
        r = rd_cli();
    }else if(threadName == "SERVER"){
        r = rd_server();
    }
    send_z = z[0] - r;
    if (threadName == "CLI")
    {
        thread *threads = new thread[2];
        threads[0] = thread(&BSNet::sendMsg, bsnet_cli, &send_z, sizeof(send_z), 0);
        threads[1] = thread(&BSNet::recvMsg, bsnet_cli, &recv_z, sizeof(recv_z), 0);

        for (int32_t i = 0; i < 2; i++)
        {
            threads[i].join();
        }
        delete[] threads;
    }
    if (threadName == "SERVER")
    {
        thread *threads = new thread[2];
        threads[0] = thread(&BSNet::recvMsg, bsnet_server, &recv_z, sizeof(recv_z), 0);
        threads[1] = thread(&BSNet::sendMsg, bsnet_server, &send_z, sizeof(send_z), 0);

        for (int32_t i = 0; i < 2; i++)
        {
            threads[i].join();
        }
        delete[] threads;
    }

    z[0] = z[0] + recv_z + r;
    if (z[0] == 1)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int64_t partitionData(uint64_t *A, int64_t start, int64_t end)
{
    // 选择末尾元素作为轴
    uint64_t pivot = A[end];
    int64_t pIndex = start;
    uint64_t res;

    for (size_t i = start; i < end; i++)
    {

        if (databinCompare(&A[i], &pivot, &res) == false)
        {
            swap(A[i], A[pIndex]);
            pIndex++;
        }
    }
    swap(A[end], A[pIndex]);
    return pIndex;
}

void quicksortSharingData(uint64_t *A, int64_t start, int64_t end)
{
    if (start >= end)
    {
        return;
    }

    int64_t pivot = partitionData(A, start, end);

    // 排序左侧
    quicksortSharingData(A, start, pivot - 1);

    // 排序右侧
    quicksortSharingData(A, pivot + 1, end);
}
/**
 * 排序
 * 1.使用官方快速排序
 * 2.使用官方堆排序（稳定排序）
 * 3.使用自定义排序算法
 */
void funcSecretSort(const uint64_t *x, uint64_t *z, int32_t size)
{
    memcpy(z, x, size * sizeof(uint64_t));

    // 官方快速排序
    // std::sort(z,z+size, sortCompare);

    // 官方堆排序
    // std::stable_sort(z, z + size, sortCompare);

    // 手写快排
    quicksortSharingData(z, 0, size - 1);
}

void funcDataBin(const uint64_t *x, uint64_t *z, int32_t size)
{
    memcpy(z, x, size * sizeof(uint64_t));

    quicksortSharingData(z, 0, size - 1);
}