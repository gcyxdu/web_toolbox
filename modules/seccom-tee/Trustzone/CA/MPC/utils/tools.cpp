#include "tools.h"

/**
 * 计算矩阵a与矩阵b的乘积结果放至矩阵c中
 */
void matrixMulEigen(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c)
{

    uint64_t left_matrix_row_major[rows * common_dim];
    uint64_t right_matrix_col_major[common_dim * columns];
    size_t offset = 0;

    for (int i = 0; i < rows; i++)
    {
        offset = i * common_dim;
        for (int j = 0; j < common_dim; j++)
        {
            left_matrix_row_major[offset + j] = a[offset + j];
        }
    }

    for (int i = 0; i < common_dim; i++)
    {
        offset = i * columns;
        for (int j = 0; j < columns; j++)
        {
            right_matrix_col_major[j * common_dim + i] = b[offset + j];
        }
    }

    uint64_t ra, rb, rc;
    uint64_t cumu_ele;
    for (int r = 0; r < rows; r++)
    {
        ra = r * common_dim;
        rc = r * columns;
        for (int col = 0; col < columns; col++)
        {
            rb = col * common_dim;
            cumu_ele = 0;
            for (int com = 0; com < common_dim; com++)
            {
                cumu_ele += left_matrix_row_major[ra + com] * right_matrix_col_major[rb + com];
            }
            c[rc + col] = cumu_ele;
        }
    }
}

/**
 * 打印数据a中的前len个元素
 */
#define LIMIT 10
void printArray(uint64_t *a, size_t len)
{
    printf("[");
    for (size_t i = 0; i < len; i++)
    {
        if(i < LIMIT)
            std::cout << (int64_t)a[i] << "\t";
        else
            break;
    }
    printf("]");
    std::cout << std::endl;
}

/**
 * 将array中[strat, end)的元素相加
 */
uint64_t sumArray(uint64_t *array, size_t start, size_t end)
{
    uint64_t res = 0;
    for (size_t i = start; i < end; i++)
    {
        res += array[i];
    }
    return res;
}

/**
 * 计算：x = x % m
 */
uint64_t mod(const uint64_t &x, const uint64_t &m)
{
    int64_t x_ = (int64_t)(x);
    x_ %= 67;
    if (x_ < 0)
    {
        return m + x_;
    }
    else
    {
        return x_;
    }
}

/**
 * 计算：y = x % m
 */
void mod(const uint64_t *x, uint64_t *y, const uint64_t &m, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        y[i] = mod(x[i], m);
    }
}

/**
 * 打印日志信息
 */
void log_print(const string &msg)
{
#if (LOG_DEBUG)
    std::cout << msg << std::endl;
#endif
}

/**
 * 向量加法计算，计算结果存储在输入数组a中
 */
void arrayAddInline(uint64_t *a, uint64_t *b, int32_t len)
{
    for (int32_t i = 0; i < len; i++)
    {
        a[i] = a[i] + b[i];
    }
}

/**
 * 向量加法计算，计算结果存储在输入数组a中
 */
void arrayAddInline(vector<uint64_t> &a, vector<uint64_t> &b, int32_t len)
{
    for (int32_t i = 0; i < len; i++)
    {
        a[i] = a[i] + b[i];
    }
}

/**
 * 向量减法计算，计算结果存储在输入数组a中
 */
void arraySubtractInline(uint64_t *a, uint64_t *b, int32_t len)
{
    for (int32_t i = 0; i < len; i++)
    {
        a[i] = a[i] - b[i];
    }
}

/**
 * 向量减法计算，计算结果存储在输入数组a中
 */
void arraySubtractInline(vector<uint64_t> &a, vector<uint64_t> &b, int32_t len)
{
    for (int32_t i = 0; i < len; i++)
    {
        a[i] = a[i] - b[i];
    }
}

/**
 * 从指定文件的指定行以uint64_t类型读取数据
 */
vector<uint64_t> readLineFromFile(const std::string &filepath, int lineNum)
{
    std::ifstream file(filepath);
    std::string line;
    int currentLine = 0;

    // 逐行读取文件，直到找到目标行或者到达文件末尾
    while (std::getline(file, line) && currentLine < lineNum)
    {
        currentLine++;
    }

    file.close();

    std::vector<uint64_t> result;

    // 如果找到目标行，则将该行中的整数提取出来存储到数组中
    if (currentLine == lineNum)
    {
        std::istringstream iss(line);
        uint64_t num;
        while (iss >> num)
        {
            result.push_back(num);
        }
    }

    if(result.empty()){
        std::cout << "当前读取数据结果为空，请检查文件路径或行数是否正确" << std::endl;
    }

    return result;
}