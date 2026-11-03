from typing import List, Optional
from BuildingBlocks.util import Util
from BuildingBlocks.alias import Alias
from BuildingBlocks.alias_class import AliasPlain

class Node:
    def __init__(self, is_leaf: bool):
        self.is_leaf = is_leaf

class LeafNode(Node):
    def __init__(self, x_dataset: List[int], w_dataset: List[int]):
        super().__init__(is_leaf=True)
        self.x_dataset = x_dataset
        self.w_dataset = w_dataset

class InternalNode(Node):
    def __init__(
        self,
        v_node: int,
        l_node: int,
        u_node: int,
        a_node: List[AliasPlain],
        w_a_node: int,
        left: Optional[Node],
        right: Optional[Node],
    ):
        super().__init__(is_leaf=False)
        self.v_node = v_node
        self.l_node = l_node
        self.u_node = u_node
        self.A_node = a_node
        self.w_A_node = w_a_node
        self.left = left
        self.right = right

class BSTPlain:
    @staticmethod
    def bst_building(x_dataset: List[int], w_dataset: List[int]):
        """Recursive BST construction (Python equivalent of Java bSTBuilding)"""
        result = Util.median(x_dataset)
        l_node, median, u_node = result[0], result[1], result[2]

        if median == u_node:
            return LeafNode(x_dataset, w_dataset)

        w_node = sum(w_dataset)
        alias_plain = Alias.construct_alias(x_dataset, w_dataset)

        left_x, left_w, right_x, right_w = [], [], [], []
        for x, w in zip(x_dataset, w_dataset):
            if x <= median:
                left_x.append(x)
                left_w.append(w)
            else:
                right_x.append(x)
                right_w.append(w)

        left_node = BSTPlain.bst_building(left_x, left_w) if left_x else None
        right_node = BSTPlain.bst_building(right_x, right_w) if right_x else None

        return InternalNode(
            v_node=median,
            l_node=l_node,
            u_node=u_node,
            a_node=alias_plain,
            w_a_node=w_node,
            left=left_node,
            right=right_node,
        )
