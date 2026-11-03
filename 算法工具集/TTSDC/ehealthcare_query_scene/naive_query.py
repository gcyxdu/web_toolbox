import random
from typing import List
from paillier import Paillier
# from she import SHE
from util_plain import UtilPlain
from util_cipher import UtilCipher
from kdpb_class import Record, QueryToken
from kdpb_tree_cipher import KDPBTreeCipher
from aes import AESSuite
from heu.phe import Ciphertext

class NaiveQuery:

    @staticmethod
    def encrypt_data(data_list: List[Record], paillier: Paillier) -> List[List[Ciphertext]]:
        encrypt_data_array = []

        for record in data_list:
            query_vector = UtilPlain.record_to_vector(record)
            encrypt_query_vector = paillier.encrypt_vector(query_vector)
            encrypt_data_array.append(encrypt_query_vector)

        return encrypt_data_array

    @staticmethod
    def search_naive_method(
        encrypt_data_array: List[List[Ciphertext]],
        query_token: QueryToken,
        paillier: Paillier,
        cipher_minus_one: Ciphertext,
        secret_key: str
    ) -> List[List[int]]:
        verification_token = query_token.verification_token
        k = paillier.k
        final_result = []

        for encrypt_data_record in encrypt_data_array:
            d = len(encrypt_data_record)
            c = paillier.scalar_product_ciphertext(encrypt_data_record, verification_token)
            sign_data = UtilCipher.sign_computation_protocol(c, paillier, cipher_minus_one)

            if sign_data == -1:
                rand_vector = [random.getrandbits(k) for _ in range(d)]

                encrypt_sum_vector = paillier.add_vector(rand_vector, encrypt_data_record)

                string_rand_vector = KDPBTreeCipher.array_to_string(rand_vector)
                aes_rand_vector = AESSuite.encrypt(string_rand_vector)
                plain_rand_vector = AESSuite.decrypt(aes_rand_vector)

                sum_vector = paillier.decrypt_vector(encrypt_sum_vector)
                recover_rand_vector = KDPBTreeCipher.string_to_array(plain_rand_vector)

                result = Paillier.substract_vectors(sum_vector, recover_rand_vector)
                final_result.append(result)

        return final_result
