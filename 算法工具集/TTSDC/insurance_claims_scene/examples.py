"""
Helper functions for SEAL encryption examples.
Based on examples.h from Microsoft SEAL library.
SEAL加密示例的辅助函数。
基于Microsoft SEAL库的examples.h。
"""

from typing import List, TypeVar, Union
import sys

T = TypeVar('T')


def print_example_banner(title: str) -> None:
    """
    Helper function: Prints the name of the example in a fancy banner.
    辅助函数：以花式横幅打印示例名称。
    """
    if title:
        title_length = len(title)
        banner_length = title_length + 2 * 10
        banner_top = "+" + "-" * (banner_length - 2) + "+"
        banner_middle = "|" + " " * 9 + title + " " * 9 + "|"
        
        print()
        print(banner_top)
        print(banner_middle)
        print(banner_top)


def print_parameters(context) -> None:
    """
    Helper function: Prints the parameters in a SEALContext.
    Note: This is a placeholder for Python SEAL context if available.
    辅助函数：打印SEALContext中的参数。
    注意：如果可用，这是Python SEAL上下文的占位符。
    """
    # This would need to be adapted based on the Python SEAL library API
    # 这需要根据Python SEAL库API进行调整
    print("/")
    print("| Encryption parameters :")
    # Additional implementation would depend on the Python SEAL library
    print("\\")


def print_vector(vec: List[Union[int, float]], print_size: int = 4, prec: int = 3) -> None:
    """
    Helper function: Prints a vector of floating-point values.
    辅助函数：打印浮点数值向量。
    
    Args:
        vec: Vector to print
        # 要打印的向量
        print_size: Number of elements to print from beginning and end
        # 从开头和结尾打印的元素数量
        prec: Precision for floating point numbers
        # 浮点数的精度
    """
    slot_count = len(vec)
    
    print()
    if slot_count <= 2 * print_size:
        print("    [", end='')
        for i in range(slot_count):
            if isinstance(vec[i], float):
                print(f" {vec[i]:.{prec}f}", end='')
            else:
                print(f" {vec[i]}", end='')
            if i != slot_count - 1:
                print(",", end='')
        print(" ]")
    else:
        print("    [", end='')
        for i in range(print_size):
            if isinstance(vec[i], float):
                print(f" {vec[i]:.{prec}f},", end='')
            else:
                print(f" {vec[i]},", end='')
        if len(vec) > 2 * print_size:
            print(" ...,", end='')
        for i in range(slot_count - print_size, slot_count):
            if isinstance(vec[i], float):
                print(f" {vec[i]:.{prec}f}", end='')
            else:
                print(f" {vec[i]}", end='')
            if i != slot_count - 1:
                print(",", end='')
        print(" ]")
    print()


def print_matrix(matrix: List[Union[int, float]], row_size: int) -> None:
    """
    Helper function: Prints a matrix of values.
    辅助函数：打印值矩阵。
    
    Args:
        matrix: Matrix to print (as a flat list)
        # 要打印的矩阵（作为平面列表）
        row_size: Number of columns per row
        # 每行的列数
    """
    print_size = 5
    
    print()
    print("    [", end='')
    for i in range(print_size):
        if i < len(matrix):
            print(f"{matrix[i]:3d},", end='')
    print(" ...,", end='')
    for i in range(row_size - print_size, row_size):
        if i < len(matrix):
            print(f"{matrix[i]:3d}", end='')
            if i != row_size - 1:
                print(",", end='')
    print(" ]")
    
    print("    [", end='')
    for i in range(row_size, row_size + print_size):
        if i < len(matrix):
            print(f"{matrix[i]:3d},", end='')
    print(" ...,", end='')
    for i in range(2 * row_size - print_size, 2 * row_size):
        if i < len(matrix):
            print(f"{matrix[i]:3d}", end='')
            if i != 2 * row_size - 1:
                print(",", end='')
    print(" ]")
    print()


def print_line(line_number: int) -> None:
    """
    Helper function: Print line number.
    辅助函数：打印行号。
    """
    print(f"Line {line_number:3d} --> ", end='')


def uint64_to_hex_string(value: int) -> str:
    """
    Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
    辅助函数：将值转换为十六进制字符串，例如，uint64_t(17) --> "11"。
    """
    return f"{value:016x}"

