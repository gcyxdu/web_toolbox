#pragma once

#include "func.h"
#include <assert.h>
#include <cmath>
#include <sys/time.h>


/**
 * 测试乘法正确性
 */
void testMulFunction();

/**
 * 测试乘法性能
 */
void testMulPerformance();

/**
 * 测试除法正确性
 * TODO 没有测试正确性
 */
void testDivFunction();

/**
 * 测试除法性能
 */
void testDivPerformance();

/**
 * 测试欧氏距离正确性
 */
void testEculidDistanceFunction();

/**
 * 测试欧氏距离性能
 */
void testEculidDistancePerformance();

/**
 * 测试比较操作正确性
 */
void testCompareFunction();

/**
 * 测试比较操作性能
 */
void testComparePerformance();

/**
 * 测试方差正确性
 */
void testVarianceFunction();
/**
 * 测试方差性能
 */
void testVariancePerformance();

/**
 * 测试皮尔逊相关系数正确性
 */
void testPearsonFunction();

/**
 * 测试皮尔逊相关系数性能
 */
void testPearsonPerformance();

/**
 *  测试距离相关系数正确性
 */
void testDistCorCoeffFunction();

/**
 * 测试距离相关系数性能
 */
void testDistCorCoeffPerformance();


/**
 * 测试排序正确性
 */
void testSortFunction();

/**
 * 测试排序性能
 */
void testSortPerformance();

/**
 * 测试数据分箱正确性
 */
void testDataBinFunction();

/**
 * 测试数据分箱性能
 */
void testDataBinPerformance();