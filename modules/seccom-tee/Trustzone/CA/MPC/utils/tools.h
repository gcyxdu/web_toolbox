#pragma once


#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>

#include <string>

using std::string;
using std::vector;

/**
 * 矩阵乘法
 */
void matrixMulEigen(size_t rows, size_t common_dim, size_t columns,
                    const uint64_t *a, const uint64_t *b, uint64_t *c);

/**
 * 打印数组
 */
void printArray(uint64_t *a, size_t len);

/**
 * 将array中[strat, end)的元素相加
 */
uint64_t sumArray(uint64_t *array, size_t start, size_t end);

/**
 * 计算：x = x % m
 */
uint64_t mod(const uint64_t &x, const uint64_t &m);

/**
 * 计算：y = x % m
 */
void mod(const uint64_t *x, uint64_t *y, const uint64_t &m, size_t size);

/**
 * 打印信息
 */
void log_print(const string &msg);

/**
 * 向量加法计算，计算结果存储在输入数组a中
 */
void arrayAddInline(uint64_t *a, uint64_t *b, int32_t len);

/**
 * 向量加法计算，计算结果存储在输入数组a中
 */
void arrayAddInline(vector<uint64_t> &a, vector<uint64_t> &b, int32_t len);

/**
 * 向量减法计算，计算结果存储在输入数组a中
 */
void arraySubtractInline(uint64_t *a, uint64_t *b, int32_t len);

/**
 * 向量减法计算，计算结果存储在输入数组a中
 */
void arraySubtractInline(vector<uint64_t> &a, vector<uint64_t> &b, int32_t len);

/**
 * 从指定文件的指定行以uint64_t类型读取数据
 */
vector<uint64_t> readLineFromFile(const std::string &filepath, int lineNum);