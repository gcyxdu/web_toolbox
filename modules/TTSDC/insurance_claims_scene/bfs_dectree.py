r"""
\file 		dectree.py
\author 	kiss@encrypto.cs.tu-darmstadt.de
\copyright	Decision Tree
文件：dectree.py
作者：kiss@encrypto.cs.tu-darmstadt.de
版权：决策树
			Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
\brief		DecTree class for reading in decision trees generated from scikit-learn.
简介：DecTree类，用于读取从scikit-learn生成的决策树。
"""

import os
import sys
import random
import math
import re
from typing import List, Optional, Tuple

# Import print_vector from examples, but only when needed to avoid circular imports
# 从examples导入print_vector，仅在需要时导入以避免循环导入
try:
    from examples import print_vector
except ImportError:
    # Fallback if examples module is not available
    # 如果examples模块不可用时的备用方案
    def print_vector(vec: List[int], print_size: int = 24, prec: int = 0) -> None:
        """Simple print_vector fallback."""
        # 简单的print_vector备用函数
        print(vec[:print_size] if len(vec) > print_size else vec)


def largest_power_of_two(N: int) -> int:
    """Calculate the largest power of two less than or equal to N."""
    # 计算小于等于N的最大2的幂
    # If N is 0, return 0
    # 如果N为0，返回0
    if N == 0:
        return 0

    # Fill the higher bits with 1 through step-by-step bitwise operations
    # 通过逐步位运算将高位填充为1
    N |= (N >> 1)
    N |= (N >> 2)
    N |= (N >> 4)
    N |= (N >> 8)
    N |= (N >> 16)
    N |= (N >> 32)  # For a 64-bit integer, additionally process the upper 32 bits
    # 对于64位整数，额外处理高32位

    # N + 1 is the smallest power of two greater than N, and shifting it right by one bit yields the largest power of two less than or equal to N
    # N + 1是大于N的最小2的幂，将其右移一位得到小于等于N的最大2的幂
    return (N + 1) >> 1


def rotate_right(vec: List[int], k: int) -> None:
    """Rotate vector to the right by k positions."""
    # 将向量向右旋转k个位置
    # If the vector is empty or the number of rotations is 0, return immediately
    # 如果向量为空或旋转次数为0，立即返回
    if not vec or k == 0:
        return

    # Calculate the actual number of rotations to avoid k being larger than the size of the vector
    # 计算实际旋转次数，避免k大于向量大小
    k = k % len(vec)

    # Reverse the entire vector
    # 反转整个向量
    vec.reverse()

    # Reverse the first k elements
    # 反转前k个元素
    vec[:k] = reversed(vec[:k])

    # Reverse the remaining elements
    # 反转剩余元素
    vec[k:] = reversed(vec[k:])


def is_index_in_vector(vec: List[int], index: int) -> bool:
    """Check if index is in vector."""
    # 检查索引是否在向量中
    return index in vec


def contains(vec: List[int], value: int) -> bool:
    """Check if value is in vector."""
    # 检查值是否在向量中
    return value in vec


class Node:
    """Node class for decision tree."""
    # 决策树的节点类
    
    def __init__(self):
        """Initialize a node with default values."""
        # 使用默认值初始化节点
        self.left: Optional['Node'] = None
        self.right: Optional['Node'] = None
        self.parent: Optional['Node'] = None
        self.level: int = 0
        self.leaf: bool = False
        self.threshold: int = 0
        self.classification: int = 0
        self.attribute_index: int = 0
        self.nodeIndex: int = 1
        self.TrueNode: bool = False
        self.is_swap: int = 1

    def __copy__(self):
        """Create a copy of the node. Note: parent is not copied to avoid circular references."""
        # 创建节点的副本。注意：不复制父节点以避免循环引用
        new_node = Node()
        if self.left is not None:
            new_node.left = self.left.__copy__()
            if new_node.left:
                new_node.left.parent = new_node
        if self.right is not None:
            new_node.right = self.right.__copy__()
            if new_node.right:
                new_node.right.parent = new_node
        # Don't copy parent to avoid circular references - parent should be set by the caller
        # 不复制父节点以避免循环引用 - 父节点应由调用者设置
        new_node.level = self.level
        new_node.leaf = self.leaf
        new_node.threshold = self.threshold
        new_node.attribute_index = self.attribute_index
        new_node.classification = self.classification
        new_node.nodeIndex = self.nodeIndex
        new_node.TrueNode = self.TrueNode
        new_node.is_swap = self.is_swap
        return new_node


class DecTree:
    """Decision Tree class for reading in decision trees generated from scikit-learn."""
    # 决策树类，用于读取从scikit-learn生成的决策树
    
    def __init__(self):
        """Initialize the decision tree."""
        # 初始化决策树
        self.node_vec: List[Optional[Node]] = []
        self.decnode_vec: List[Optional[Node]] = []
        self.dummyTreeNode: Optional[Node] = None
        self.Extract_attributes: List[int] = []
        self.Extract_thresholds: List[int] = []
        self.Extract_weights: List[int] = []
        self.Extract_nodeIndex: List[int] = []
        self.Extract_swapCondition: List[int] = []
        self.Extract_trueNode: List[int] = []
        self.attributes: List[int] = []
        self.thresholds: List[int] = []
        
        # STATISTICS FOR DECISION TREES
        # 决策树的统计信息
        self.num_attributes: int = 0
        self.num_dec_nodes: int = 0
        self.depth: int = 0
        self.num_of_leaves: int = 0
        self.dummy_non_full: int = 0

    def add_node(self, node: Node) -> None:
        """Add a node to the tree."""
        # 向树中添加节点
        self.node_vec.append(node)

    def add_decnode(self, node: Node) -> None:
        """Add a decision node to the tree."""
        # 向树中添加决策节点
        self.decnode_vec.append(node)

    def add_edge(self, n1: Node, n2: Node) -> None:
        """Add an edge between two nodes."""
        # 在两个节点之间添加边
        if n2.parent is None:
            n2.parent = n1
            n2.level = n1.level + 1
        if n1.left is None:
            n1.left = n2
            n2.nodeIndex = n1.nodeIndex * 2
        elif n1.right is None:
            n1.right = n2
            n2.nodeIndex = n1.nodeIndex * 2 + 1

    def read_from_file(self, string_file: str, x: List[int]) -> None:
        """Read decision tree from a file."""
        # 从文件读取决策树
        print(string_file)
        
        node1: int = 0
        node2: int = 0
        index: int = 0
        thres: float = 0.0
        
        with open(string_file, 'r') as file:
            for line in file:
                tokens = tokenize(line)
                if len(tokens) < 2:
                    continue
                    
                if tokens[1] == "label=\"gini":
                    if len(tokens) < 7:
                        continue
                    node1 = int(tokens[0])
                    self.add_node(Node())
                    self.node_vec[node1].leaf = True
                    self.num_of_leaves += 1
                    self.node_vec[node1].classification = int(tokens[6])
                    
                elif tokens[1] == "label=\"X":
                    if len(tokens) < 5:
                        continue
                    node1 = int(tokens[0])
                    node = Node()
                    index = int(tokens[2])
                    node.attribute_index = index
                    # tokens[4] might contain the threshold value, possibly with newline characters
                    # tokens[4]可能包含阈值，可能包含换行符
                    thres_str = tokens[4].split('\n')[0] if '\n' in tokens[4] else tokens[4]
                    thres = float(thres_str)
                    node.threshold = int(thres * 100)
                    self.num_dec_nodes += 1
                    self.add_node(node)
                    self.add_decnode(node)
                    
                    if index not in self.attributes:
                        self.num_attributes += 1
                    self.attributes.append(index)
                    self.thresholds.append(node.threshold)
                    
                elif tokens[1] == "->":
                    if len(tokens) < 3:
                        continue
                    node1 = int(tokens[0])
                    node2 = int(tokens[2])
                    self.add_edge(self.node_vec[node1], self.node_vec[node2])

        for i in range(len(self.node_vec)):
            node = self.node_vec[i]
            if node.leaf:
                if node.level > self.depth:
                    self.depth = node.level

        for i in range(len(self.node_vec)):
            node = self.node_vec[i]
            if node.leaf:
                self.dummy_non_full += self.depth - node.level

        total_number_of_edges = 0
        for i in range(len(self.node_vec)):
            node = self.node_vec[i]
            if node.leaf:
                total_number_of_edges += node.level

        self.evaluate(x)

    def evaluate(self, inputs: List[int]) -> None:
        """Evaluate the original model."""
        # 评估原始模型
        this_node = self.node_vec[0]
        print("Output the prediction path\n")
        i = 1
        while not this_node.leaf:
            print(f"{i} ", end='')
            if inputs[this_node.attribute_index] < this_node.threshold:
                print(f"x: {inputs[this_node.attribute_index]} y: {this_node.threshold}\n")
                this_node = this_node.left
                i = 2 * i
            else:
                print(f"x: {inputs[this_node.attribute_index]} y: {this_node.threshold}\n")
                this_node = this_node.right
                i = 2 * i + 1
        print()
        print(f"True prediction results: {this_node.classification}")

    def print_tree(self, node: Optional[Node], depth: int = 0) -> None:
        """Print the tree structure."""
        if node is None:
            return

        # Print the indentation and attributes of the current node
        # 打印当前节点的缩进和属性
        indent = "       " * depth

        if node.leaf:
            # Print the information of the leaf node
            # 打印叶子节点的信息
            print(f"{indent}Level {node.level} Leaf Node: Classification = {node.classification}")
        else:
            # Print the information of the decision node
            # 打印决策节点的信息
            print(f"{indent}Level {node.level} Decision Node: Attribute Index = {node.attribute_index}, Threshold = {node.threshold}, Whether it is a virtual node = {node.TrueNode}")

        # Recursively print the left and right child nodes
        # 递归打印左右子节点
        self.print_tree(node.left, depth + 1)
        self.print_tree(node.right, depth + 1)

    def copy_node(self, dummyTree: Node, TrueTree: Optional[Node]) -> None:
        """Copy node structure."""
        # 复制节点结构
        if TrueTree is None:
            return

        if TrueTree.left is not None:
            node = TrueTree.left
            dummyTree.left = node
            node.parent = dummyTree
            dummyTree.left.TrueNode = True

        if TrueTree.right is not None:
            node = TrueTree.right
            dummyTree.right = node
            node.parent = dummyTree
            dummyTree.right.TrueNode = True

        self.copy_node(dummyTree.left, TrueTree.left)
        self.copy_node(dummyTree.right, TrueTree.right)

    def add_dummy_node(self, dummyTree: Node, AllNodeIndex: List[int], index: int) -> None:
        """Add dummy nodes to the tree."""
        # 向树中添加虚拟节点
        if dummyTree.leaf:
            return

        # If the current node is an empty node but a corresponding node exists in AllNodeIndex, add a virtual node
        # 如果当前节点是空节点但AllNodeIndex中存在对应节点，则添加虚拟节点
        if dummyTree.left.leaf and is_index_in_vector(AllNodeIndex, 2 * index):
            # Construct a virtual decision node
            # 构建虚拟决策节点
            NewDecnode = Node()
            NewDecnode.level = dummyTree.left.level
            NewDecnode.leaf = False
            NewDecnode.threshold = random.randint(0, 99)
            NewDecnode.attribute_index = random.randint(0, self.num_attributes - 1) if self.num_attributes > 0 else 0
            NewDecnode.nodeIndex = 2 * index
            NewDecnode.TrueNode = False

            # Construct the left node of the virtual decision node, directly inheriting
            # 构建虚拟决策节点的左节点，直接继承
            node = dummyTree.left
            node.level = dummyTree.left.level + 1

            # Construct the right node of the virtual decision node, with randomization
            # 构建虚拟决策节点的右节点，随机化
            newLeaf = Node()
            newLeaf.leaf = True
            newLeaf.level = dummyTree.left.level + 1
            newLeaf.classification = random.randint(0, 499)

            dummyTree.left = NewDecnode
            NewDecnode.parent = dummyTree
            NewDecnode.left = node
            node.parent = NewDecnode
            NewDecnode.right = newLeaf
            newLeaf.parent = NewDecnode

        if dummyTree.right.leaf and is_index_in_vector(AllNodeIndex, 2 * index + 1):
            # Construct a virtual decision node
            # 构建虚拟决策节点
            NewDecnode = Node()
            NewDecnode.level = dummyTree.right.level
            NewDecnode.leaf = False
            NewDecnode.threshold = random.randint(0, 99)
            NewDecnode.attribute_index = random.randint(0, self.num_attributes - 1) if self.num_attributes > 0 else 0
            NewDecnode.nodeIndex = 2 * index + 1
            NewDecnode.TrueNode = False

            # Construct the left node of the virtual decision node, directly inheriting
            node = dummyTree.right
            node.level = dummyTree.right.level + 1

            # Construct the right node of the virtual decision node, with randomization
            newLeaf = Node()
            newLeaf.leaf = True
            newLeaf.level = dummyTree.right.level + 1
            newLeaf.classification = random.randint(0, 499)

            dummyTree.right = NewDecnode
            NewDecnode.parent = dummyTree
            NewDecnode.left = node
            node.parent = NewDecnode
            NewDecnode.right = newLeaf
            newLeaf.parent = NewDecnode

        self.add_dummy_node(dummyTree.left, AllNodeIndex, 2 * index)
        self.add_dummy_node(dummyTree.right, AllNodeIndex, 2 * index + 1)

    def random_swap(self, dummyTree: Node) -> None:
        """Randomly swap left and right children of nodes."""
        # 随机交换节点的左右子节点
        if dummyTree.leaf:
            return

        # Create a random number generator using the default random engine
        # 使用默认随机引擎创建随机数生成器
        random.seed(1234)
        
        # Generate a random number
        # 生成随机数
        randomValue = random.random()

        # Perform the swap with a random probability
        # 以随机概率执行交换
        if randomValue < 0.5:
            dummyTree.is_swap = -1
        if dummyTree.is_swap == -1:
            node = dummyTree.left
            dummyTree.left = dummyTree.right
            dummyTree.right = node

        self.random_swap(dummyTree.left)
        self.random_swap(dummyTree.right)

    def breadth_first_read(self, dummyTree: Node) -> None:
        """Breadth-first read of the tree."""
        # 广度优先读取树
        if dummyTree is None:
            print("Tree is empty.")
            return

        q = [dummyTree]
        
        # Breadth-first traversal
        # 广度优先遍历
        i = 0
        while q:
            currentNode = q.pop(0)

            self.Extract_attributes.append(currentNode.attribute_index)
            self.Extract_thresholds.append(currentNode.threshold)
            self.Extract_swapCondition.append(currentNode.is_swap)
            self.Extract_trueNode.append(1 if currentNode.TrueNode else 0)

            # If there is a left child node, add it to the queue
            # 如果有左子节点，将其添加到队列
            if not currentNode.left.leaf:
                q.append(currentNode.left)

            # If there is a right child node, add it to the queue
            # 如果有右子节点，将其添加到队列
            if not currentNode.right.leaf:
                q.append(currentNode.right)

    def depthfirst_read(self, dummyTree: Node, index: int = 1) -> None:
        """Depth-first read of the tree."""
        # 深度优先读取树
        if dummyTree.leaf:
            self.Extract_weights.append(dummyTree.classification)
            return
        self.Extract_nodeIndex.append(index)

        self.depthfirst_read(dummyTree.left, index * 2)
        self.depthfirst_read(dummyTree.right, index * 2 + 1)

    def pack_hidden_mod(self, length: int) -> None:
        """Pack hidden model by adding dummy nodes."""
        # 通过添加虚拟节点来打包隐藏模型
        if self.node_vec[0] is None:
            print("Tree is empty.")
            return
            
        print(f"Total number of nodes {length} ", end='')
        dummyNumber = length - self.num_dec_nodes
        print(f"Number of virtual nodes {dummyNumber} ", end='')

        TrueNodeIndex: List[int] = []
        AllNodeIndex: List[int] = []

        for i in range(len(self.node_vec)):
            node = self.node_vec[i]
            if not node.leaf:
                TrueNodeIndex.append(node.nodeIndex)

        AllNodeIndex = TrueNodeIndex.copy()

        for i in range(length):
            if i < len(AllNodeIndex):
                if not is_index_in_vector(AllNodeIndex, AllNodeIndex[i] * 2):
                    if dummyNumber > 0:
                        AllNodeIndex.append(AllNodeIndex[i] * 2)
                        dummyNumber -= 1

                if not is_index_in_vector(AllNodeIndex, AllNodeIndex[i] * 2 + 1):
                    if dummyNumber > 0:
                        AllNodeIndex.append(AllNodeIndex[i] * 2 + 1)
                        dummyNumber -= 1

        print()

        DummyTree = self.node_vec[0]
        DummyTree.TrueNode = True

        # Copy the real node
        # 复制真实节点
        self.copy_node(DummyTree, self.node_vec[0])

        # Add dummy nodes
        # 添加虚拟节点
        self.add_dummy_node(DummyTree, AllNodeIndex, 1)

        # Random permutation
        # 随机排列
        self.random_swap(DummyTree)

        self.depthfirst_read(DummyTree)
        self.breadth_first_read(DummyTree)

        self.Extract_nodeIndex.sort()

    def output_model(self) -> None:
        """Output model parameters."""
        # 输出模型参数
        print("Feature index: ", end='')
        print_vector(self.Extract_attributes, 24, 0)

        print("\nModel threshold: ", end='')
        print_vector(self.Extract_thresholds, 24, 0)

        print("\nModel weights: ", end='')
        print_vector(self.Extract_weights, 24, 0)

        print("\nNode index status: ", end='')
        print_vector(self.Extract_nodeIndex, 24, 0)

        print("\nNode swap status: ", end='')
        print_vector(self.Extract_swapCondition, 24, 0)

        print("\nTrue node status: ", end='')
        print_vector(self.Extract_trueNode, 24, 0)


def tokenize(line: str) -> List[str]:
    """
    Takes a string in the Format "i i i ..." separated by ' '
    Tokenize by spaces, brackets, and backslashes.
    接受格式为"i i i ..."的字符串，用' '分隔
    通过空格、括号和反斜杠进行分词。
    """
    tokens = []
    # Remove leading/trailing whitespace and newlines
    # 移除前导/尾随空白和换行符
    line = line.strip()
    if not line:
        return tokens
    
    # First, split by literal \n to handle newlines in label attributes
    # Then split by spaces, brackets, and backslashes
    # Split on spaces, brackets, backslashes, and newlines
    # 首先，按字面量\n分割以处理标签属性中的换行符
    # 然后按空格、括号和反斜杠分割
    # 在空格、括号、反斜杠和换行符上分割
    tokens = re.split(r'[ \[\]]+|\\\\|\\n', line)
    # Also split on literal newline characters
    # 也按字面量换行符分割
    temp_tokens = []
    for t in tokens:
        if '\n' in t:
            temp_tokens.extend(t.split('\n'))
        else:
            temp_tokens.append(t)
    tokens = temp_tokens
    # Filter out empty strings
    # 过滤空字符串
    tokens = [t for t in tokens if t and t.strip()]
    return tokens


def erase_sub_str(mainStr: str, toErase: str) -> str:
    """Erase first occurrence of given substring from main string."""
    # 从主字符串中删除给定子字符串的第一次出现
    pos = mainStr.find(toErase)
    if pos != -1:
        mainStr = mainStr[:pos] + mainStr[pos + len(toErase):]
    return mainStr

