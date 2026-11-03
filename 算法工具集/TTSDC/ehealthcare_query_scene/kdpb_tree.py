import random
from typing import List, Optional
from util_plain import UtilPlain
from kdpb_class import Record, LeafNode, Node, InternalNode

class KDPBTree:
    @staticmethod
    def tree_building(datalist: List[Record]) -> Node:
        d = len(datalist[0].data)
        l = len(datalist[0].attribute)

        if len(datalist) == 1:
            record = datalist[0]
            vector = UtilPlain.record_to_vector(record)
            return LeafNode(vector)
        else:
            rnd = random.random()
            index_and_proporation = UtilPlain.choose_cutting_dim_val(datalist)

            cd = int(index_and_proporation[0])
            proportion = index_and_proporation[1]

            if (proportion < 0.8 and cd == -1) or rnd > 0.5:
                pivots = UtilPlain.choose_pivot(datalist)
                pivot1, pivot2 = pivots[0], pivots[1]

                data_list_left, data_list_right = [], []
                for record in datalist:
                    dis1 = UtilPlain.dis_between_two_data(record.data, pivot1)
                    dis2 = UtilPlain.dis_between_two_data(record.data, pivot2)

                    if dis1 <= dis2:
                        data_list_left.append(record)
                    else:
                        data_list_right.append(record)
                
                internal_node_record = UtilPlain.pivot_to_vector(pivot1, pivot2, l)
                left_sub_tree = KDPBTree.tree_building(data_list_left)
                right_sub_tree = KDPBTree.tree_building(data_list_right)

                internal_node = InternalNode(internal_node_record, left_sub_tree, right_sub_tree)
                return internal_node
            else:
                data_list_left, data_list_right = [], []
                for record in datalist:
                    if record.attribute[cd] == 2:
                        data_list_left.append(record)
                    elif record.attribute[cd] == 4:
                        data_list_right.append(record)
                    else:
                        data_list_left.append(record)
                        data_list_right.append(record)
                
                internal_node_record = UtilPlain.cutting_value_to_vector(cd, 3, l, d)
                left_sub_tree = KDPBTree.tree_building(data_list_left)
                right_sub_tree = KDPBTree.tree_building(data_list_right)

                internal_node = InternalNode(internal_node_record, left_sub_tree, right_sub_tree)
                return internal_node

    @staticmethod
    def full_binary_tree(data_record: List[int], height: int, num: int, d: int, l: int) -> Node:
        if height == 1:
            if num == 2 ** height - 1:
                return LeafNode(data_record)
            else:
                dummy = UtilPlain.gene_dummy_value(d, l)
                return LeafNode(dummy)
        else:
            cd = 0
            val = -1
            internal_node_record = UtilPlain.cutting_value_to_vector(cd, val, l, d)
            left_subtree = KDPBTree.full_binary_tree(data_record, height - 1, 2 * num, d, l)
            right_subtree = KDPBTree.full_binary_tree(data_record, height - 1, 2 * num + 1, d, l)
            return InternalNode(internal_node_record, left_subtree, right_subtree)
        
    @staticmethod
    def extend_tree(node: Node, height: int, current_height: int, d: int, l: int) -> Node:
        internal_node = InternalNode(node)
        if internal_node.left_node.is_leaf:
            if current_height != height - 1:
                data_record = internal_node.left_node.data_record
                new_left_node = KDPBTree.full_binary_tree(data_record, height - current_height, 1, d, l)
            else:
                new_left_node = internal_node.left_node
        else:
            new_left_node = KDPBTree.extend_tree(internal_node.left_node, height, current_height + 1, d, l)

        if internal_node.right_node.is_leaf:
            if current_height != height - 1:
                dataRecord = internal_node.right_node.data_record
                new_right_node = KDPBTree.full_binary_tree(dataRecord, height - current_height, 1, d, l)
            else:
                new_right_node = internal_node.right_node
        else:
            new_right_node = KDPBTree.extend_tree(internal_node.right_node, height, current_height + 1, d, l)

        return InternalNode(internal_node.internal_node_record, new_left_node, new_right_node)

    @staticmethod
    def height_tree(node: Node) -> int:
        if node.is_leaf:
            return 1
        else:
            internal_node = InternalNode(node)
            return 1 + max(KDPBTree.height_tree(internal_node.left_node),
                           KDPBTree.height_tree(internal_node.right_node))

    @staticmethod
    def count_leaf_node(node: Node) -> int:
        if node.is_leaf:
            return 1
        else:
            internalNode = InternalNode(node)
            return KDPBTree.count_leaf_node(internalNode.left_node) + KDPBTree.count_leaf_node(internalNode.right_node)