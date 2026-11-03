import random
from kdpb_class import *
from paillier import Paillier
from util_plain import UtilPlain
from util_cipher import UtilCipher
from typing import List
from aes import AESSuite
import secrets

class KDPBTreeCipher:
    @staticmethod
    def encrypt_tree(node: Node, paillier: Paillier) -> EncryptNode:
        if node.is_leaf == True:
            leaf_node: LeafNode = node
            data_record = leaf_node.data_record
            encrypt_data_record = paillier.encrypt_vector(data_record)
            return EncryptLeafNode(encrypt_data_record)
        else:
            internal_node: InternalNode = node
            encrypt_uL = paillier.encrypt_vector(internal_node.internal_node_record.uL)
            encrypt_uR = paillier.encrypt_vector(internal_node.internal_node_record.uR)

            encrypt_lL = paillier.encrypt(-1)
            encrypt_lR = paillier.encrypt(1)

            encrypt_left_subtree = KDPBTreeCipher.encrypt_tree(internal_node.left_node, paillier)
            encrypt_right_subtree = KDPBTreeCipher.encrypt_tree(internal_node.right_node, paillier)

            return EncryptInternalNode(encrypt_uL, encrypt_lL, encrypt_uR, encrypt_lR, encrypt_left_subtree, encrypt_right_subtree)
        
    @staticmethod
    def generate_token(record: Record, tau: int, cipher_zero1: Ciphertext, cipher_zero2: Ciphertext, paillier: Paillier) -> QueryToken:
        query_token = UtilPlain.query_to_vector(record, tau)
        filteration_token = paillier.encrypt_vector_by_ciphertexts(query_token.filteration_record, cipher_zero1, cipher_zero2)
        verification_token = paillier.encrypt_vector_by_ciphertexts(query_token.verification_record, cipher_zero1, cipher_zero2)

        return QueryToken(filteration_token, verification_token)
    
    @staticmethod
    def filteration_query(encrypt_node: EncryptNode, query_token: QueryToken, paillier: Paillier, cipher_minus_one: Ciphertext, k: int) -> List[EncryptNode]:
        candidate_node_set, node_this_layer, flag_this_layer = [], [], []
        cipher_one = paillier.encrypt(1)
        cipher_zero = paillier.encrypt(0)
        node_this_layer.append(encrypt_node)
        flag_this_layer.append(cipher_one)

        filteration_token = query_token.filteration_token
        verification_token = query_token.verification_token

        while len(node_this_layer) > 0:
            flag_one_node_list, flag_zero_node_list = [], []
            node_next_layer, flag_next_layer = [], []
            for i in range(len(node_this_layer)):
                node = node_this_layer[i]
                encrypt_internal_node: EncryptInternalNode = node
                
                encrypt_uL = encrypt_internal_node.encrypt_uL
                encrypt_uR = encrypt_internal_node.encrypt_uR
                encrypt_lL = encrypt_internal_node.encrypt_lL
                encrypt_lR = encrypt_internal_node.encrypt_lR

                encrypt_flag = flag_this_layer[i]

                encrypt_lL_mul_filteration_token = UtilCipher.scalar_product_over_cipher(filteration_token, encrypt_uL, paillier)
                encrypt_lR_mul_filteration_token = UtilCipher.scalar_product_over_cipher(filteration_token, encrypt_uR, paillier)

                sign_L = UtilCipher.sign_computation_protocol(encrypt_lL_mul_filteration_token, paillier, cipher_minus_one)
                sign_R = UtilCipher.sign_computation_protocol(encrypt_lR_mul_filteration_token, paillier, cipher_minus_one)

                encrypt_sign_L = paillier.encrypt(sign_L)
                encrypt_sign_R = paillier.encrypt(sign_R)

                flag_left = UtilCipher.flag_sign_protocol(encrypt_sign_L, encrypt_lL, encrypt_flag, paillier, cipher_minus_one)
                flag_right = UtilCipher.flag_sign_protocol(encrypt_sign_R, encrypt_lR, encrypt_flag, paillier, cipher_minus_one)

                if flag_left == 1: 
                    flag_one_node_list.append(encrypt_internal_node.left_node)
                else:
                    flag_zero_node_list.append(encrypt_internal_node.left_node)
                
                if flag_right == 1: 
                    flag_one_node_list.append(encrypt_internal_node.right_node)
                else:
                    flag_zero_node_list.append(encrypt_internal_node.right_node)

            for flag_one_node in flag_one_node_list:
                if flag_one_node.is_leaf:
                    encrypt_leaf_node: EncryptLeafNode = flag_one_node
                    candidate_node_set.append(encrypt_leaf_node)
                else:
                    encrypt_internal_node: EncryptInternalNode = flag_one_node
                    node_next_layer.append(encrypt_internal_node)
                    flag_next_layer.append(cipher_one)
            
            for i in range(len(flag_one_node_list) * k):
                if i < len(flag_zero_node_list):
                    if flag_zero_node_list[i].is_leaf:
                        encrypt_leaf_node: EncryptLeafNode = flag_zero_node_list[i]
                        candidate_node_set.append(encrypt_leaf_node)
                    else:
                        encrypt_internal_node: EncryptInternalNode = flag_zero_node_list[i]
                        node_next_layer.append(encrypt_internal_node)
                        flag_next_layer.append(cipher_zero)

            node_this_layer.clear()
            node_this_layer.extend(node_next_layer)
            flag_this_layer.clear()
            flag_this_layer.extend(flag_next_layer)
        return candidate_node_set

    @staticmethod
    def verification_query(candidate_node_set: List[EncryptNode], query_token: QueryToken, paillier: Paillier, cipher_minus_one: Ciphertext, secret_key: str) -> List[List[int]]:
        verification_token = query_token.verification_token
        # k1 = parameters.k1
        rnd = random.SystemRandom()
        final_result = []
        aes = AESSuite(secret_key)

        for candidate_node in candidate_node_set:
            encrypt_leaf_node: EncryptLeafNode = candidate_node
            encrypt_data_record = encrypt_leaf_node.encrypt_data_record
            d = len(encrypt_data_record)

            c = paillier.scalar_product_ciphertext(encrypt_data_record, verification_token)
            sign_data = UtilCipher.sign_computation_protocol(c, paillier, cipher_minus_one)

            if sign_data == -1:
                rand_vector = [rnd.getrandbits(32) for _ in range(d)]
                encrypt_sum_vector = paillier.add_vector(rand_vector, encrypt_data_record)

                string_rand_vector = KDPBTreeCipher.array_to_string(rand_vector)
                AES_rand_vector = aes.encrypt(string_rand_vector)
                plain_rand_vector = aes.decrypt(AES_rand_vector)
                sum_vector = paillier.decrypt_vector(encrypt_sum_vector)
                recover_rand_vector = KDPBTreeCipher.string_to_array(plain_rand_vector)
                result = Paillier.substract_vectors(sum_vector, recover_rand_vector)
                final_result.append(result)
        
        return final_result

    @staticmethod
    def array_to_string(array: List[int]) -> str:
        return ','.join(str(x) for x in array)

    @staticmethod
    def string_to_array(s: str) -> List[int]:
        if not s:
            return []
        return [int(x) for x in s.split(',') if x]

    @staticmethod
    def print_array(a: List[int]):
        print(','.join(str(x) for x in a))


# ----------------------------
# 下面是测试 main 部分
if __name__ == "__main__":
    array_list = [1, 2]
    KDPBTreeCipher.print_array(array_list)

    array_list1 = [3, 4]
    KDPBTreeCipher.print_array(array_list1)

    array_list.clear()
    KDPBTreeCipher.print_array(array_list)

    array_list.extend(array_list1)
    KDPBTreeCipher.print_array(array_list)
    KDPBTreeCipher.print_array(array_list1)

    print(".................")
    array = [1, 10]
    s = KDPBTreeCipher.array_to_string(array)
    print(s)

    print("........................")
    array1 = KDPBTreeCipher.string_to_array(s)
    for item in array1:
        print(item)