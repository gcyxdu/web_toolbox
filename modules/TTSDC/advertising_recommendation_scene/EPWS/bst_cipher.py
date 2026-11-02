from typing import List, Optional, Tuple
import random
from dataclasses import dataclass
from BuildingBlocks.ase import ASE, Shares
from BuildingBlocks.private_algorithms import PrivateAlgorithms
from BuildingBlocks.alias import Alias
from BuildingBlocks.alias_class import AliasCipher
from EPWS.bst_plain import Node, InternalNode, LeafNode
from EPWS.key import Key


class CandidateResult:
    def __init__(self, x_dataset_shares: List[Shares], w_dataset_shares: List[Shares], alias_cipher_shares: List[List[AliasCipher]], alias_w_shares: List[Shares]):
        self.x_dataset_shares = x_dataset_shares
        self.w_dataset_shares = w_dataset_shares
        self.alias_cipher_shares = alias_cipher_shares
        self.alias_w_shares = alias_w_shares

class NodeCipher:
    def __init__(self, is_leaf: bool):
        self.is_leaf = is_leaf

class LeafNodeCipher(NodeCipher):
    def __init__(self, x_data_binary_shares: List[List[Shares]], x_dataset_shares: List[Shares], w_dataset_shares: List[Shares]):
        super().__init__(is_leaf=True)
        self.x_data_binary_shares = x_data_binary_shares
        self.x_dataset_shares = x_dataset_shares
        self.w_dataset_shares = w_dataset_shares

class InternalNodeCipher(NodeCipher):
    def __init__(self, b_shares_node: Shares, v_shares_node: List[Shares], l_shares_node: List[Shares],
                    u_shares_node: List[Shares], alias_cipher_node: List[AliasCipher], w_shares_a_node: Shares, left: NodeCipher, right: NodeCipher):
        super().__init__(is_leaf=False)
        self.b_shares_node = b_shares_node
        self.v_shares_node = v_shares_node
        self.l_shares_node = l_shares_node
        self.u_shares_node = u_shares_node
        self.alias_cipher_node = alias_cipher_node
        self.w_shares_a_node = w_shares_a_node
        self.left = left
        self.right = right

class BSTCipher:
    # -------------------------------
    # Encryption
    # -------------------------------
    @staticmethod
    def bst_enc(node: Node, beta: int):
        bit_length = beta

        if node.is_leaf:
            leaf_node: LeafNode = node
            x_dataset_shares = ASE.share_list_shares(leaf_node.x_dataset)
            w_dataset_shares = ASE.share_list_shares(leaf_node.w_dataset)
            x_data_binary_shares = PrivateAlgorithms.to_bin_and_enc_batch(leaf_node.x_dataset, bit_length)

            return LeafNodeCipher(x_data_binary_shares, x_dataset_shares, w_dataset_shares)
        else:
            internal_node: InternalNode = node
            v_node = internal_node.v_node
            l_node = internal_node.l_node
            u_node = internal_node.u_node
            A_node = internal_node.A_node
            w_A_node = internal_node.w_A_node
            left = internal_node.left
            right = internal_node.right

            b_shares_node = ASE.share_int(1)
            v_shares_node = PrivateAlgorithms.to_bin_and_enc(v_node, bit_length)
            l_shares_node = PrivateAlgorithms.to_bin_and_enc(l_node, bit_length)
            u_shares_node = PrivateAlgorithms.to_bin_and_enc(u_node, bit_length)
            alias_cipher_node = Alias.alias_enc(A_node)
            w_shares_a_node = ASE.share_int(w_A_node)

            left_cipher = BSTCipher.bst_enc(left, bit_length) if left else None
            right_cipher = BSTCipher.bst_enc(right, bit_length) if right else None

            return InternalNodeCipher(
                b_shares_node, v_shares_node, l_shares_node, u_shares_node,
                alias_cipher_node, w_shares_a_node, left_cipher, right_cipher
            )

    # -------------------------------
    # Query Encryption
    # -------------------------------
    @staticmethod
    def query_enc(l: int, u: int, bit_length: int):
        l_binary_shares = PrivateAlgorithms.to_bin_and_enc(l, bit_length)
        u_binary_shares = PrivateAlgorithms.to_bin_and_enc(u, bit_length)
        return [l_binary_shares, u_binary_shares]

    # -------------------------------
    # Helper function
    # -------------------------------
    @staticmethod
    def identity_lv(b_shares: Shares, l_shares: List[Shares], v_shares: List[Shares], key: Key):
        result = []
        for i in range(len(l_shares)):
            tmp1 = ASE.ase_mul(b_shares, l_shares[i], key)
            tmp2 = ASE.ase_sub_by_int(1, b_shares)
            tmp2 = ASE.ase_mul(tmp2, v_shares[i], key)
            tmp2 = ASE.ase_add(tmp1, tmp2)
            result.append(tmp2)
        return result

    # -------------------------------
    # Cipher search
    # -------------------------------
    @staticmethod
    def bst_search_cipher(tree_cipher: NodeCipher, query_shares: List[List[Shares]], key: Key) -> Tuple[CandidateResult, int]:
        c_x_shares = []
        c_w_shares = []
        alias_x_shares = []
        alias_w_shares = []

        comm_size_mul = 384
        comm_size_recover = 128
        num_mul = num_recover = 0

        stack = [tree_cipher]

        while stack:
            node = stack.pop()

            if node.is_leaf:
                leaf_node: LeafNodeCipher = node
                for i, x_bin_shares in enumerate(leaf_node.x_data_binary_shares):
                    flag = PrivateAlgorithms.prct(query_shares[0], query_shares[1], x_bin_shares, x_bin_shares, key)
                    num_mul += 4 * key.beta + 2
                    num_recover += 1
                    if flag:
                        c_x_shares.append(leaf_node.x_dataset_shares[i])
                        c_w_shares.append(leaf_node.w_dataset_shares[i])
            else:
                internal_node: InternalNodeCipher = node
                flag = PrivateAlgorithms.prct(query_shares[0], query_shares[1],
                                        internal_node.l_shares_node, internal_node.u_shares_node, key)
                num_mul += 4 * key.beta + 2
                num_recover += 1

                if flag:
                    alias_x_shares.append(internal_node.alias_cipher_node)
                    alias_w_shares.append(internal_node.w_shares_a_node)
                else:
                    # check left
                    if internal_node.left:
                        z1 = BSTCipher.identity_lv(internal_node.b_shares_node, internal_node.l_shares_node,
                                                   internal_node.v_shares_node, key)
                        z2 = BSTCipher.identity_lv(internal_node.b_shares_node, internal_node.v_shares_node,
                                                   internal_node.u_shares_node, key)
                        cmp_flag = PrivateAlgorithms.pbdc(z2, z1, key)
                        if not cmp_flag:
                            stack.append(internal_node.left)

                    # check right
                    if internal_node.right:
                        z1 = BSTCipher.identity_lv(internal_node.b_shares_node, internal_node.v_shares_node,
                                                   internal_node.l_shares_node, key)
                        z2 = BSTCipher.identity_lv(internal_node.b_shares_node, internal_node.u_shares_node,
                                                   internal_node.v_shares_node, key)
                        cmp_flag = PrivateAlgorithms.pbdc(z2, z1, key)
                        if not cmp_flag:
                            stack.append(internal_node.right)

        total_comm = num_mul * comm_size_mul + num_recover * comm_size_recover
        return CandidateResult(c_x_shares, c_w_shares, alias_x_shares, alias_w_shares), total_comm

    # -------------------------------
    # Result verification
    # -------------------------------
    @staticmethod
    def result_verify(candidate_result: CandidateResult, delta: int, eta: int, key: Key) -> Tuple[Shares, int]:
        comm_size_of_ase_mul = 192
        comm_size_of_ase_recover = 64
        comm_size_of_share = 64
        num_of_ase_mul = 0
        num_of_ase_recover = 0
        num_of_share = 0
        total_comm = 0

        c_x_shares = candidate_result.x_dataset_shares
        c_w_shares = candidate_result.w_dataset_shares
        alias_x_shares = candidate_result.alias_cipher_shares
        alias_w_shares = candidate_result.alias_w_shares
        w_shares = []

        if len(c_w_shares) == 0 and len(alias_w_shares) == 0:
            print("the size of cWShares and aliasWShares are zero")
            return ASE.share_int(0), 0
        elif len(c_w_shares) == 0:
            for alias_w_share in alias_w_shares:
                w_shares.append(alias_w_share)
        elif len(c_w_shares) == 0:
            for c_w_share in c_w_shares:
                w_shares.append(c_w_share)
        else:
            for c_w_share in c_w_shares:
                w_shares.append(c_w_share)
            for alias_w_share in alias_w_shares:
                w_shares.append(alias_w_share)

        w_sum_shares = []
        w_sum_shares.append(w_shares[0])
        for i in range(1, len(w_shares), 1):
            tmp = ASE.ase_add(w_sum_shares[i - 1], w_shares[i])
            w_sum_shares.append(tmp)
        
        r_shares = PrivateAlgorithms.purdg(delta, key)
        num_of_share += 8 * key.delta
        num_of_ase_mul += delta

        loc = 0
        r_mul_w_sum_shares = ASE.ase_mul(r_shares, w_sum_shares[-1], key)
        num_of_ase_mul += 1

        for i in range(len(w_sum_shares)):
            tmp = ASE.ase_scale_int(w_sum_shares[i], 2**delta)
            z_shares = ASE.ase_sub(r_mul_w_sum_shares, tmp)
            flag = PrivateAlgorithms.padc(z_shares, eta)
            num_of_share += 5

            if flag == True:
                loc = i
        
        if len(c_w_shares) == 0:
            alias_cipher = alias_x_shares[loc]
            num_of_share = num_of_share + 5 * len(alias_cipher) + 8 * key.delta + 5
            num_of_ase_mul = num_of_ase_mul + 4 * len(alias_cipher) + key.delta + 4

            total_comm = num_of_share * comm_size_of_share + num_of_ase_recover * comm_size_of_ase_recover + num_of_ase_mul * comm_size_of_ase_mul
            
            return Alias.alias_sampling(alias_cipher, key, delta, eta), total_comm
        elif len(alias_w_shares) == 0:
            total_comm = num_of_share * comm_size_of_share + num_of_ase_recover * comm_size_of_ase_recover + num_of_ase_mul * comm_size_of_ase_mul

            return c_x_shares[loc], total_comm
        else:
            if loc <= len(c_w_shares) - 1:
                total_comm = num_of_share * comm_size_of_share + num_of_ase_recover * comm_size_of_ase_recover + num_of_ase_mul * comm_size_of_ase_mul
                return c_x_shares[loc], total_comm
            else: 
                alias_cipher = alias_x_shares[loc - len(c_w_shares)]
                num_of_share = num_of_share + 5 * len(alias_cipher) + 8 * key.delta + 5
                num_of_ase_mul = num_of_ase_mul + 4 * len(alias_cipher) + key.delta + 4

                total_comm = num_of_share * comm_size_of_share + num_of_ase_recover * comm_size_of_ase_recover + num_of_ase_mul * comm_size_of_ase_mul

                return Alias.alias_sampling(alias_cipher, key, delta, eta), total_comm
        
