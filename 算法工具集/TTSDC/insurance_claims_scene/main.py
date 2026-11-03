#!/usr/bin/env python3
"""
Main Python file converted from main.cpp
Implements secure decision tree inference using SEAL-Python
主Python文件，从main.cpp转换而来
实现使用SEAL-Python的安全决策树推理
"""

import sys
import os
import time
import math
import random
from typing import List, Optional, Dict
from collections import defaultdict

# Import SEAL-Python
# 导入SEAL-Python库
from seal import *

# Import local modules
# 导入本地模块
from bfs_dectree import DecTree
from examples import print_vector

# Global time tracking (similar to C++ timeval structs)
# 全局时间跟踪（类似于C++的timeval结构体）
time1 = 0.0
time2 = 0.0
timeuse = 0.0


def random_float(start: float, end: float) -> float:
    """Generate a random float between start and end."""
    # 生成一个在start和end之间的随机浮点数
    return start + (end - start) * random.random()


def random_int(min_val: int, max_val: int) -> int:
    """Generate a random integer between min and max."""
    # 生成一个在min和max之间的随机整数
    random.seed(1234)  # Use fixed seed like C++ version
    # 使用固定种子，与C++版本保持一致
    return random.randint(min_val, max_val)


class TreeNode:
    """Tree node for path sum calculation."""
    # 用于路径和计算的树节点
    
    def __init__(self, left_w: float, right_w: float):
        """Initialize a tree node."""
        # 初始化一个树节点
        self.left_weight: float = left_w
        self.right_weight: float = right_w
        self.left: Optional['TreeNode'] = None
        self.right: Optional['TreeNode'] = None


class Tree:
    """Tree class for path sum calculation."""
    # 用于路径和计算的树类
    
    def __init__(self):
        """Initialize the tree."""
        # 初始化树
        self.root: Optional[TreeNode] = None
        self.sumweight: List[int] = []

    def build_tree(self, values: List[int], yes_or_no: bool, structure_index: List[int]) -> None:
        """Build the tree from values and structure index."""
        # 根据值和结构索引构建树
        if not values:
            return
        if yes_or_no:
            self.root = self._build_recursive(values, 1, structure_index)
        else:
            self.root = self._build_reverse_recursive(values, 1, structure_index)

    def print_tree(self, node: Optional[TreeNode]) -> None:
        """Print the tree structure."""
        # 打印树结构
        if node is not None:
            print(f", Left Weight: {node.left_weight}, Right Weight: {node.right_weight}")
            self.print_tree(node.left)
            self.print_tree(node.right)

    def sum_paths(self, weight: int, node: Optional[TreeNode], current_sum: int) -> None:
        """Calculate sum of paths recursively."""
        # 递归计算路径和
        if node is None:
            print("1 ", end='')
            return

        # Update the sum of the current path
        # 更新当前路径的和
        current_sum += weight

        if node.left is None and node.right is None:
            self.sumweight.append(current_sum + int(node.left_weight))
            self.sumweight.append(current_sum + int(node.right_weight))
        elif node.left is None:
            self.sumweight.append(current_sum + int(node.left_weight))
            self.sum_paths(int(node.right_weight), node.right, current_sum)
        elif node.right is None:
            self.sum_paths(int(node.left_weight), node.left, current_sum)
            self.sumweight.append(current_sum + int(node.right_weight))
        else:
            self.sum_paths(int(node.left_weight), node.left, current_sum)
            self.sum_paths(int(node.right_weight), node.right, current_sum)

    def _build_recursive(self, values: List[int], index: int, structure_index: List[int]) -> Optional[TreeNode]:
        """Build tree recursively (normal mode)."""
        # 递归构建树（正常模式）
        nodes: Dict[int, TreeNode] = {}

        # Create all nodes and store them in a dictionary
        # 创建所有节点并将它们存储在字典中
        for i in range(len(structure_index)):
            idx = structure_index[i]
            left_weight = float(values[i])
            right_weight = 1.0 - left_weight
            nodes[idx] = TreeNode(left_weight, right_weight)

        # Connect the left and right child nodes for each node
        for i in range(len(structure_index)):
            idx = structure_index[i]
            currentNode = nodes.get(idx)
            if currentNode is None:
                continue

            # Calculate the indices of the left and right child nodes
            leftIndex = 2 * idx
            rightIndex = 2 * idx + 1

            # Associate the existing left and right child nodes with the current node
            if leftIndex in nodes:
                currentNode.left = nodes[leftIndex]
            if rightIndex in nodes:
                currentNode.right = nodes[rightIndex]

        # Return the root node, assuming the root node's index is 1
        # 返回根节点，假设根节点的索引为1
        return nodes.get(1)

    def _build_reverse_recursive(self, values: List[int], index: int, structure_index: List[int]) -> Optional[TreeNode]:
        """Build tree recursively (reverse mode)."""
        # 递归构建树（反向模式）
        nodes: Dict[int, TreeNode] = {}

        # Create all nodes and store them in a dictionary
        # 创建所有节点并将它们存储在字典中
        for i in range(len(structure_index)):
            idx = structure_index[i]
            left_weight = -float(values[i])
            right_weight = -left_weight
            nodes[idx] = TreeNode(left_weight, right_weight)

        # Connect the left and right child nodes for each node
        for i in range(len(structure_index)):
            idx = structure_index[i]
            currentNode = nodes.get(idx)
            if currentNode is None:
                continue

            # Calculate the indices of the left and right child nodes
            leftIndex = 2 * idx
            rightIndex = 2 * idx + 1

            # Associate the existing left and right child nodes with the current node
            if leftIndex in nodes:
                currentNode.left = nodes[leftIndex]
            if rightIndex in nodes:
                currentNode.right = nodes[rightIndex]

        # Return to the root node, assuming the root node has an index of 1
        # 返回到根节点，假设根节点的索引为1
        return nodes.get(1)


def test_tree_sum_path(values: List[int], yes_or_no: bool, structure_index: List[int]) -> List[int]:
    """Test tree sum path calculation."""
    # 测试树路径和计算
    tree = Tree()
    tree.build_tree(values, yes_or_no, structure_index)
    tree.sum_paths(0, tree.root, 0)
    return tree.sumweight


def test_path_sum_correct():
    """Test path sum correctness."""
    # 测试路径和的正确性
    compare_bit = [0, 0, 1, 1, 1, 1, 0]
    random_bit = [10, 20, 11, 41, 81, 2, 3]
    result = [compare_bit[i] + random_bit[i] for i in range(len(compare_bit))]

    structures = [1, 2, 3, 6, 7, 12, 13]
    aa = test_tree_sum_path(random_bit, False, structures)
    bb = test_tree_sum_path(result, True, structures)
    cc = test_tree_sum_path(compare_bit, True, structures)

    for i in range(len(compare_bit)):
        if aa[i] + bb[i] != cc[i]:
            print("PathSum is false")
            return
    print("PathSum is true")


class Client:
    """Client class for homomorphic encryption operations."""
    # 用于同态加密操作的客户端类
    
    def __init__(self, Np: int):
        """Initialize the client with encryption parameters."""
        # 使用加密参数初始化客户端
        self.poly_modulus_degree: int = 0
        self.M: int = 0  # Feature vector dimensionality
        # 特征向量维度
        self.plain_0: Optional[Plaintext] = None
        self.cipher0_1: Optional[Ciphertext] = None
        self.cipher0_2: Optional[Ciphertext] = None
        self.cipher0_3: Optional[Ciphertext] = None
        
        self.context: Optional[SEALContext] = None
        self.keygen: Optional[KeyGenerator] = None
        self.public_key: Optional[PublicKey] = None
        self.relin_keys: Optional[RelinKeys] = None
        self.gal_keys: Optional[GaloisKeys] = None
        self.encryptor: Optional[Encryptor] = None
        self.evaluator: Optional[Evaluator] = None
        self.decryptor: Optional[Decryptor] = None
        self.encoder: Optional[BatchEncoder] = None
        
        self.client_initial_keys(Np)

    def client_initial_keys(self, Np: int) -> None:
        """Initialize encryption keys and parameters."""
        # 初始化加密密钥和参数
        parms = EncryptionParameters(scheme_type.bfv)
        self.poly_modulus_degree = 1 << Np
        parms.set_poly_modulus_degree(self.poly_modulus_degree)
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(self.poly_modulus_degree))
        parms.set_plain_modulus(PlainModulus.Batching(self.poly_modulus_degree, 50))

        # Initialize SEALContext
        # 初始化SEALContext
        self.context = SEALContext(parms)

        # Initialize KeyGenerator, Encryptor, Evaluator, Decryptor, and Encoder
        # 初始化密钥生成器、加密器、评估器、解密器和编码器
        self.keygen = KeyGenerator(self.context)
        self.public_key = self.keygen.create_public_key()
        self.relin_keys = self.keygen.create_relin_keys()
        self.gal_keys = self.keygen.create_galois_keys()

        self.encryptor = Encryptor(self.context, self.public_key)
        self.evaluator = Evaluator(self.context)
        self.decryptor = Decryptor(self.context, self.keygen.secret_key())
        self.encoder = BatchEncoder(self.context)

    def client_load_vector(self, M_size: int, x: List[int]) -> Ciphertext:
        """Load and encrypt a feature vector."""
        # 加载并加密特征向量
        self.M = M_size
        # Here, repeatedly expand the X vector to fill the entire vector
        # 在这里，重复扩展X向量以填充整个向量
        j = 0
        x_expanded = x.copy()
        for i in range(len(x), self.poly_modulus_degree):
            x_expanded.append(x[j])
            j = (j + 1) % self.M

        x_plain = self.encoder.encode(x_expanded)
        x_encrypted = self.encryptor.encrypt(x_plain)

        # Create zero vector
        # 创建零向量
        zero_vector = [0] * self.poly_modulus_degree
        self.plain_0 = self.encoder.encode(zero_vector)
        self.cipher0_1 = self.encryptor.encrypt(self.plain_0)
        self.cipher0_2 = self.encryptor.encrypt(self.plain_0)
        self.cipher0_3 = self.encryptor.encrypt(self.plain_0)

        return x_encrypted

    def client_secure_feature_selection(self, x_encrypt: List[Ciphertext], pack_tree_num: int) -> Ciphertext:
        """Secure feature selection."""
        # 安全特征选择
        x_decrypt = [0] * self.poly_modulus_degree

        length = self.poly_modulus_degree // self.M - 1

        for i in range(pack_tree_num):
            temp = self.decryptor.decrypt(x_encrypt[i])
            temp_vec = self.encoder.decode(temp)
            temp_sum = 0
            for j in range(self.poly_modulus_degree):
                if j < length * self.M:
                    temp_sum += temp_vec[j]
                    if (j + 1) % self.M == 0:
                        x_decrypt[j + 1 - self.M + i] = temp_sum
                        temp_sum = 0

        x_plain = self.encoder.encode(x_decrypt)
        # For BFV, we need to encrypt the plaintext first, or use add_plain if available
        # 对于BFV，我们需要先加密明文，或者如果可用则使用add_plain
        try:
            # Try add_plain method (may not exist in all seal-python versions)
            # 尝试add_plain方法（可能在某些seal-python版本中不存在）
            x_cipher = self.evaluator.add_plain(self.cipher0_1, x_plain)
        except AttributeError:
            # Fallback: encrypt the plaintext first, then add
            # 备用方案：先加密明文，然后相加
            x_plain_encrypted = self.encryptor.encrypt(x_plain)
            x_cipher = self.evaluator.add(self.cipher0_1, x_plain_encrypted)
        return x_cipher

    def client_decrypt_compare_result(self, x_encrypted: Ciphertext, sign: bool) -> Ciphertext:
        """Decrypt and compare result."""
        # 解密并比较结果
        x_plain = self.decryptor.decrypt(x_encrypted)
        x = self.encoder.decode(x_plain)

        I1 = []
        if sign:
            for i in range(self.poly_modulus_degree):
                if x[i] < 0 and i % self.M == 0:
                    I1.append(0)
                else:
                    I1.append(1)
        else:
            for i in range(self.poly_modulus_degree):
                if x[i] < 0:
                    I1.append(0)
                else:
                    I1.append(1)

        I1_plain = self.encoder.encode(I1)
        try:
            I1_encrypted = self.evaluator.add_plain(self.cipher0_2, I1_plain)
        except AttributeError:
            I1_plain_encrypted = self.encryptor.encrypt(I1_plain)
            I1_encrypted = self.evaluator.add(self.cipher0_2, I1_plain_encrypted)
        return I1_encrypted

    def client_construct_path_sum(self, I1_encrypted: Ciphertext, length: int, structure_index: List[int]) -> Ciphertext:
        """Construct path sum on client side."""
        # 在客户端构建路径和
        x_plain = self.decryptor.decrypt(I1_encrypted)
        x = self.encoder.decode(x_plain)

        Extract_x = []
        for i in range(self.poly_modulus_degree):
            if (i % self.M == 0) and (len(Extract_x) < length):
                Extract_x.append(x[i])

        ClientPathSum = test_tree_sum_path(Extract_x, True, structure_index)

        ClientPathSum_plain = self.encoder.encode(ClientPathSum)
        try:
            I1_encrypted = self.evaluator.add_plain(self.cipher0_3, ClientPathSum_plain)
        except AttributeError:
            ClientPathSum_encrypted = self.encryptor.encrypt(ClientPathSum_plain)
            I1_encrypted = self.evaluator.add(self.cipher0_3, ClientPathSum_encrypted)
        return I1_encrypted


class Server:
    """Server class for homomorphic encryption operations."""
    # 用于同态加密操作的服务器类
    
    def __init__(self, Np: int, M: int, Node_y: List[int], weight: List[int], 
                 index: List[int], istrueNode: List[int], isSwap: List[int]):
        """Initialize the server with model parameters."""
        # 使用模型参数初始化服务器
        parms = EncryptionParameters(scheme_type.bfv)
        self.poly_modulus_degree = 1 << Np
        parms.set_poly_modulus_degree(self.poly_modulus_degree)
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(self.poly_modulus_degree))
        parms.set_plain_modulus(PlainModulus.Batching(self.poly_modulus_degree, 50))

        # Initialize SEALContext
        # 初始化SEALContext
        context = SEALContext(parms)

        # Initialize the encoder
        # 初始化编码器
        self.encoder = BatchEncoder(context)

        self.y = Node_y
        self.istrueNode = istrueNode
        self.isSwap = isSwap
        self.M = M
        self.decNodeNumber = len(index)

        # Extract the feature index vector
        # 提取特征索引向量
        S = []
        j = 0
        for i in range(1, self.poly_modulus_degree + 1):
            if j < len(index):
                if (i - 1) % M == index[j]:
                    S.append(1)
                else:
                    S.append(0)
            else:
                S.append(0)
            if i % M == 0:
                j += 1

        # Encode model parameters
        # 编码模型参数
        self.y_plain = self.encoder.encode(self.y)
        self.weight_plain = self.encoder.encode(weight)
        temp = self.encoder.encode(S)
        self.S_plain = [temp]

        # Initialize pointers (will be set later)
        # 初始化指针（稍后设置）
        self.public_key: Optional[PublicKey] = None
        self.relin_keys: Optional[RelinKeys] = None
        self.gal_keys: Optional[GaloisKeys] = None
        self.encryptor: Optional[Encryptor] = None
        self.evaluator: Optional[Evaluator] = None

        # Initialize plaintexts
        # 初始化明文
        self.A_plain: Optional[Plaintext] = None
        self.B_plain: Optional[Plaintext] = None
        self.R_plain: Optional[Plaintext] = None
        self.C1_plain: Optional[Plaintext] = None
        self.R1_plain: Optional[Plaintext] = None
        self.A1_plain: Optional[Plaintext] = None
        self.B1_plain: Optional[Plaintext] = None
        self.R2_plain: Optional[Plaintext] = None
        self.C2_plain: Optional[Plaintext] = None
        self.T2_plain: Optional[Plaintext] = None
        self.Random_sum_plain: Optional[Plaintext] = None

        # Initialize vectors
        self.Random_plain: List[Plaintext] = []
        self.SeverPathSum_plain: List[Plaintext] = []
        
        self.T2sum: int = 0
        self.lengthPath: int = 0

    def server_initial_cryptosystem(self, public_key: PublicKey, relin_keys: RelinKeys, 
                                    gal_keys: GaloisKeys, encryptor: Encryptor, 
                                    evaluator: Evaluator) -> None:
        """Initialize crypto system with client keys."""
        # 使用客户端密钥初始化密码系统
        self.public_key = public_key
        self.relin_keys = relin_keys
        self.gal_keys = gal_keys
        self.encryptor = encryptor
        self.evaluator = evaluator

    def server_initial_system(self, structure_index: List[int], pack_tree_num: int, 
                             if_interactive: bool) -> None:
        """Initialize server system with masks and parameters."""
        # 使用掩码和参数初始化服务器系统
        A, B, R, C1, R1 = [], [], [], [], []
        A1, B1, R2, C2 = [], [], [], []
        Extract_R1, T2, RandomSum = [], [], []

        # 1. Generate parameters for the first secure comparison
        # 1. 为第一次安全比较生成参数
        for i in range(self.poly_modulus_degree):
            A.append(int(random_float(1.0, 100.0)))
            B.append(A[-1] - int(random_float(1.0, A[-1])))
            R.append(-1 if random_int(0, 10000) >= 5000 else 1)
            C1.append(0)
            R1.append(int(random_float(1.0, 1000.0)))
            T2.append(random_int(0, 1000))
            RandomSum.append(0)
            self.T2sum += T2[i]

        for i in range(pack_tree_num):
            # Extract the corresponding vector
            # 提取对应的向量
            Extract_R1 = extract_vector(R1, i, self.decNodeNumber, self.M)

            # Server sums the masked paths
            # 服务器对掩码路径求和
            SeverPathSum = test_tree_sum_path(Extract_R1, False, structure_index)
            self.lengthPath = len(SeverPathSum)

            # Encode the masks
            # 编码掩码
            temp = self.encoder.encode(SeverPathSum)
            self.SeverPathSum_plain.append(temp)

            # If interactive feature selection
            # 如果是交互式特征选择
            if if_interactive:
                temp_sum = 0
                RandomforSelect = []
                for j in range(self.poly_modulus_degree):
                    random_value = int(random_float(1.0, 10000.0))
                    RandomforSelect.append(random_value)

                    if j < self.decNodeNumber * self.M:
                        temp_sum -= random_value
                        if (j + 1) % self.M == 0:
                            RandomSum[j + 1 - self.M + i] = temp_sum
                            temp_sum = 0

                temp = self.encoder.encode(RandomforSelect)
                self.Random_plain.append(temp)

        self.T2sum = 0
        for i in range(self.lengthPath):
            self.T2sum += T2[i]

        if if_interactive:
            self.Random_sum_plain = self.encoder.encode(RandomSum)

        # Parameters for the second secure comparison
        # 第二次安全比较的参数
        for i in range(self.poly_modulus_degree):
            A1.append(int(random_float(1.0, 100.0)))
            B1.append(A1[-1] - int(random_float(1.0, A1[-1])))
            R2.append(-1 if random_int(0, 10000) >= 5000 else 1)
            C2.append(1 if R2[-1] == -1 else 0)

        # Precompute BR - ARY
        # 预计算 BR - ARY
        for i in range(self.poly_modulus_degree):
            A[i] *= R[i]  # Calculate AR
            # 计算 AR
            B[i] *= R[i]  # Calculate BR
            # 计算 BR
            B[i] = B[i] - A[i] * self.y[i]  # Calculate BR - ARY
            # 计算 BR - ARY

        # Pre-update
        # 预更新
        for i in range(self.poly_modulus_degree):
            R[i] *= self.isSwap[i]
            if self.istrueNode[i] == 0:
                R[i] = 0
            if ((self.istrueNode[i] == 1 and R[i] == -1) or 
                (self.istrueNode[i] == 0 and self.isSwap[i] == -1)):
                C1[i] = 1

        for i in range(self.poly_modulus_degree):
            A1[i] *= (-R2[i])  # Calculate AR
            # 计算 AR
            B1[i] *= R2[i]     # Calculate BR
            # 计算 BR

        # Encode all parameters
        # 编码所有参数
        self.A_plain = self.encoder.encode(A)
        self.B_plain = self.encoder.encode(B)
        self.R_plain = self.encoder.encode(R)
        self.C1_plain = self.encoder.encode(C1)
        self.R1_plain = self.encoder.encode(R1)
        self.A1_plain = self.encoder.encode(A1)
        self.B1_plain = self.encoder.encode(B1)
        self.R2_plain = self.encoder.encode(R2)
        self.C2_plain = self.encoder.encode(C2)
        self.T2_plain = self.encoder.encode(T2)

    def server_I_secure_feature_selection(self, x_encrypted: Ciphertext, index: int) -> Ciphertext:
        """Non-interactive secure feature selection."""
        # 非交互式安全特征选择
        # Use multiply_plain and assign result (similar to multiply_plain_inplace)
        # 使用multiply_plain并分配结果（类似于multiply_plain_inplace）
        x_encrypted = self.evaluator.multiply_plain(x_encrypted, self.S_plain[index])
        Mis2Power = (self.M > 0) and ((self.M & (self.M - 1)) == 0)
        
        # Note: For BFV scheme, we use rotate_rows; for CKKS, rotate_vector
        # 注意：对于BFV方案，我们使用rotate_rows；对于CKKS，使用rotate_vector
        # Try rotate_rows first (BFV), fallback to rotate_vector if not available
        # 首先尝试rotate_rows（BFV），如果不可用则回退到rotate_vector
        try:
            rotate_func = self.evaluator.rotate_rows
        except AttributeError:
            rotate_func = self.evaluator.rotate_vector
        
        if Mis2Power:
            logM = int(math.log2(self.M))
            for i in range(logM + 1):
                galois_element = int(2 ** i)
                x1_encrypted = rotate_func(x_encrypted, galois_element, self.gal_keys)
                x_encrypted = self.evaluator.add(x_encrypted, x1_encrypted)
        else:
            x1_encrypted = rotate_func(x_encrypted, 1, self.gal_keys)
            x2_encrypted = self.evaluator.add(x_encrypted, x1_encrypted)
            if self.M % 2 == 0:
                x_encrypted = x2_encrypted

            logM = int(math.ceil(math.log2(self.M)))
            temp = self.M

            for i in range(1, logM - 1):
                temp = temp - int(temp / 2)
                galois_element = int(2 ** i)
                if temp % 2 == 0:
                    x_encrypted = rotate_func(x_encrypted, galois_element, self.gal_keys)
                    x_encrypted = self.evaluator.add(x_encrypted, x2_encrypted)
                x1_encrypted = rotate_func(x2_encrypted, galois_element, self.gal_keys)
                x2_encrypted = self.evaluator.add(x2_encrypted, x1_encrypted)
            
            galois_element = int(2 ** (logM - 1))
            x_encrypted = rotate_func(x_encrypted, galois_element, self.gal_keys)
            x_encrypted = self.evaluator.add(x_encrypted, x2_encrypted)
        
        return x_encrypted

    def server_II_secure_feature_selection(self, x_cipher: Ciphertext, pack_tree_num: int) -> List[Ciphertext]:
        """Interactive secure feature selection."""
        # 交互式安全特征选择
        result = []
        for i in range(pack_tree_num):
            temp = self.evaluator.multiply_plain(x_cipher, self.S_plain[i])
            temp = self.evaluator.add_plain(temp, self.Random_plain[i])
            result.append(temp)
        return result

    def server_recover_selected_feature(self, x_cipher: Ciphertext) -> Ciphertext:
        """Recover selected feature by removing mask."""
        # 通过移除掩码来恢复选定的特征
        x_cipher = self.evaluator.add_plain(x_cipher, self.Random_sum_plain)
        return x_cipher

    def server_secure_compare(self, x_encrypted: Ciphertext, A_plain: Plaintext, 
                              B_plain: Plaintext) -> Ciphertext:
        """Secure comparison: perturb the difference."""
        # 安全比较：扰动差值
        x_encrypted = self.evaluator.multiply_plain(x_encrypted, A_plain)
        x_encrypted = self.evaluator.add_plain(x_encrypted, B_plain)
        return x_encrypted

    def server_recover_vector(self, I1_encrypted: Ciphertext, R_plain: Plaintext, 
                              C1_plain: Plaintext) -> Ciphertext:
        """Recover comparison result vector."""
        # 恢复比较结果向量
        I1_encrypted = self.evaluator.multiply_plain(I1_encrypted, R_plain)
        I1_encrypted = self.evaluator.add_plain(I1_encrypted, C1_plain)
        return I1_encrypted

    def server_calculate_weight(self, I1_encrypted: Ciphertext, T2_plain: Plaintext) -> Ciphertext:
        """Calculate weight and add mask."""
        # 计算权重并添加掩码
        I1_encrypted = self.evaluator.multiply_plain(I1_encrypted, self.weight_plain)
        I1_encrypted = self.evaluator.add_plain(I1_encrypted, T2_plain)
        return I1_encrypted


def extract_vector(a: List[int], index: int, length: int, dim: int) -> List[int]:
    """Extract vector elements at specific index."""
    # 在特定索引处提取向量元素
    result = []
    for i in range(length):
        result.append(a[i * dim + index])
    return result


def encode_vector(a: List[int], M: int, length: int) -> List[int]:
    """Encode vector by inserting zeros."""
    # 通过插入零来编码向量
    result = []
    for i in range(len(a)):
        result.append(a[i])
        for j in range(1, M):
            result.append(0)
    
    for i in range(len(a) * M, length):
        result.append(0)
    
    return result


def extract_vector_from_encoded(x: List[int], M: int) -> List[int]:
    """Extract vector from encoded format."""
    # 从编码格式中提取向量
    result = []
    for i in range(len(x)):
        if i % M == 0:
            result.append(x[i])
    return result


def plain_relu(x: List[int], y: List[int]) -> List[int]:
    """Plain ReLU operation."""
    # 普通ReLU操作
    result = []
    for i in range(len(x)):
        if x[i] - y[i] < 0:
            result.append(0)
        else:
            result.append(1)
    return result


def recover_plain_relu(x: List[int], Extract_trueNode: List[int], 
                       Extract_swapCondition: List[int]) -> List[int]:
    """Recover plain ReLU result."""
    # 恢复普通ReLU结果
    for i in range(len(Extract_trueNode)):
        if Extract_trueNode[i] == 0 and Extract_swapCondition[i] == -1:
            x[i] = 1
        elif Extract_trueNode[i] == 0 and Extract_swapCondition[i] == 1:
            x[i] = 0
        elif Extract_trueNode[i] == 1 and Extract_swapCondition[i] == -1:
            x[i] = 1 - x[i]
    return x


def calculate_path(node_index: List[int], x: List[int]) -> List[int]:
    """Calculate path from root node to result."""
    # 计算从根节点到结果的路径
    path = []
    current = node_index[0]
    path.append(current)

    for i in range(len(x)):
        if i < len(node_index) and node_index[i] == current:
            if x[i] == 0:
                current = 2 * current
            else:
                current = 2 * current + 1
            
            if current not in node_index:
                break
            path.append(current)
    
    return path


def main():
    """Main function."""
    # 主函数
    # Dataset configuration
    # 数据集配置
    filename = [
        "UCI_dectrees/wine",      # i = 0; M = 7
        # i = 0; M = 7
        "UCI_dectrees/iris",       # i = 1; M = 3
        # i = 1; M = 3
        "UCI_dectrees/breast",     # i = 2; M = 12
        # i = 2; M = 12
        "UCI_dectrees/digits",     # i = 3; M = 47
        # i = 3; M = 47
        "UCI_dectrees/diabetes",  # i = 4; M = 10
        # i = 4; M = 10
        "UCI_dectrees/linnerud",   # i = 5; M = 3
        # i = 5; M = 3
        "UCI_dectrees/boston"      # i = 6; M = 13
        # i = 6; M = 13
    ]
    M_ARRAYS = [7, 3, 12, 47, 10, 3, 13]

    if len(sys.argv) < 2:
        print("Usage: python main.py <dataset_index>")
        sys.exit(1)

    i = int(sys.argv[1])
    assert 0 <= i <= 6, "Dataset index must be between 0 and 6"

    M = M_ARRAYS[i]
    
    # Extract dataset name
    # 提取数据集名称
    dataname = os.path.basename(filename[i])
    print(f"\nDataset: {dataname}")
    
    # Note: NON_INTERACTIVE_MODE would be controlled by a flag
    # 注意：NON_INTERACTIVE_MODE将由标志控制
    # For now, we'll use interactive mode (the else branch in C++ code)
    # 目前，我们将使用交互模式（C++代码中的else分支）
    print("******** Interactive scheme ********")

    Np = 13
    tree = DecTree()
    length = (1 << Np) // M - 1
    PackTreeNum = 1

    # Generate random input vector
    # 生成随机输入向量
    x = []
    for j in range(M):
        x.append(int(random_float(1.0, 1000.0)))

    # 1. Process the tree model
    # 1. 处理树模型
    tree.read_from_file(filename[i], x)
    tree.pack_hidden_mod(length)

    # 2. Extract model parameters
    # 2. 提取模型参数
    y = encode_vector(tree.Extract_thresholds, M, 1 << Np)
    index = tree.Extract_attributes
    weight = tree.Extract_weights
    isSwap = encode_vector(tree.Extract_swapCondition, M, 1 << Np)
    istrueNode = encode_vector(tree.Extract_trueNode, M, 1 << Np)
    structureIndex = tree.Extract_nodeIndex

    # 3. Initialize server
    # 3. 初始化服务器
    server = Server(Np, M, y, weight, index, istrueNode, isSwap)
    for j in range(PackTreeNum - 1):
        server.S_plain.append(server.S_plain[0])

    # 4. Initialize systems
    # 4. 初始化系统
    server.server_initial_system(structureIndex, PackTreeNum, True)
    client = Client(Np)

    # 5. Load and encrypt client data
    # 5. 加载并加密客户端数据
    x_encrypted = client.client_load_vector(M, x)

    # 6. Initialize server crypto system with client keys
    # 6. 使用客户端密钥初始化服务器密码系统
    server.server_initial_cryptosystem(
        client.public_key, client.relin_keys, client.gal_keys,
        client.encryptor, client.evaluator
    )

    # 7. Secure feature selection (interactive mode)
    # 7. 安全特征选择（交互模式）
    X_cipher = server.server_II_secure_feature_selection(x_encrypted, PackTreeNum)
    x_encrypted = client.client_secure_feature_selection(X_cipher, PackTreeNum)
    x_encrypted = server.server_recover_selected_feature(x_encrypted)

    # 8. Secure comparison
    # 8. 安全比较
    x_encrypted = server.server_secure_compare(x_encrypted, server.A_plain, server.B_plain)
    I1_encrypted = client.client_decrypt_compare_result(x_encrypted, True)
    I1_encrypted = server.server_recover_vector(I1_encrypted, server.R_plain, server.C1_plain)

    # 9. Path evaluation
    # 9. 路径评估
    I1_encrypted = server.evaluator.add_plain(I1_encrypted, server.R1_plain)
    I1_encrypted = client.client_construct_path_sum(I1_encrypted, length, structureIndex)
    I1_encrypted = server.evaluator.add_plain(I1_encrypted, server.SeverPathSum_plain[0])

    # 10. Second secure comparison
    # 10. 第二次安全比较
    I1_encrypted = server.server_secure_compare(I1_encrypted, server.A1_plain, server.B1_plain)
    I1_encrypted = client.client_decrypt_compare_result(I1_encrypted, False)
    I1_encrypted = server.server_recover_vector(I1_encrypted, server.R2_plain, server.C2_plain)

    # 11. Calculate final result
    # 11. 计算最终结果
    I1_encrypted = server.server_calculate_weight(I1_encrypted, server.T2_plain)
    
    # 12. Decrypt and get result
    # 12. 解密并获取结果
    x_plain = client.decryptor.decrypt(I1_encrypted)
    x_result = client.encoder.decode(x_plain)

    result = 0
    for j in range(server.lengthPath):
        result += x_result[j]
    result -= server.T2sum
    
    print(f"Ciphertext prediction result: {result}")
    print("Done!")


if __name__ == "__main__":
    main()

