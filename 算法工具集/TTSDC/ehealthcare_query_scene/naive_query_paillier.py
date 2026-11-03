import random
import time
from typing import List
from data import Data
from util_plain import UtilPlain
from kdpb_tree_cipher import KDPBTreeCipher
from aes import AESSuite
from heu.phe import Ciphertext
from paillier import Paillier

class NaiveQueryPaillier:
    SecretKey = "ssshhhhhhhhhhh!!ssshhhhhhhhhhh!!"
    paillier = Paillier(2048)

    @staticmethod
    def key_gen():
        k = 512
        NaiveQueryPaillier.paillier = Paillier(k)

    @staticmethod
    def encrypt_database_naive(n: int, d: int, l: int) -> float:
        database = Data.gen_synthetic_data(n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        NaiveQueryPaillier.key_gen()

        cycle = 100
        t1 = time.time() * 1000
        for _ in range(cycle):
            query_vector = UtilPlain.record_to_vector(record_list[0])
            encrypt_query_vector = NaiveQueryPaillier.encrypt_vector(query_vector)
        t2 = time.time() * 1000

        t = (t2 - t1) / cycle
        return t * len(record_list)

    @staticmethod
    def generate_token(d: int, l: int) -> float:
        n = 100
        database = Data.gen_synthetic_data(n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        NaiveQueryPaillier.key_gen()

        cycle = 1000
        t1 = time.time() * 1000
        for _ in range(cycle):
            query_vector = UtilPlain.record_to_vector(record_list[0])
            encrypt_query_vector = NaiveQueryPaillier.encrypt_vector(query_vector)
        t2 = time.time() * 1000

        t = (t2 - t1) / cycle
        return t

    @staticmethod
    def query_naive(n: int, d: int, l: int) -> float:
        database = Data.gen_synthetic_data(n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        NaiveQueryPaillier.key_gen()

        data_vector = UtilPlain.record_to_vector(record_list[0])
        query_vector = UtilPlain.record_to_vector(record_list[1])

        encrypt_data_vector = NaiveQueryPaillier.encrypt_vector(data_vector)
        encrypt_query_vector = NaiveQueryPaillier.encrypt_vector(query_vector)

        cycle = 100
        t1 = time.time() * 1000
        for _ in range(cycle):
            NaiveQueryPaillier.verify_record(encrypt_data_vector, encrypt_query_vector, d)
        t2 = time.time() * 1000

        t = (t2 - t1) / cycle
        return t * len(record_list)

    @staticmethod
    def verify_record(encrypt_data_vector: List[Ciphertext], encrypt_query_vector: List[Ciphertext], real_d: int):
        d = len(encrypt_data_vector)
        cipher_element_wise_mul = [None] * d
        encrypt_scalar_product = None

        for i in range(d):
            cipher_element_wise_mul[i] = NaiveQueryPaillier.multiply_two_numbers(
                encrypt_data_vector[i], encrypt_query_vector[i])
            if i == 0:
                encrypt_scalar_product = cipher_element_wise_mul[i]
            else:
                encrypt_scalar_product = NaiveQueryPaillier.paillier.add(encrypt_scalar_product, cipher_element_wise_mul[i])

        beta = 40
        ra = random.getrandbits(beta)
        rb = random.getrandbits(beta)

        cipher_rb = NaiveQueryPaillier.paillier.encrypt(rb)
        encrypt_ra_mul_scalar_product = NaiveQueryPaillier.paillier.mul(encrypt_scalar_product, ra)
        encrypt_ra_mul_scalar_product_plus_ra = NaiveQueryPaillier.paillier.add(encrypt_ra_mul_scalar_product, cipher_rb)

        rand_vector = [random.getrandbits(beta) for _ in range(real_d)]
        encrypt_rand_vector = [NaiveQueryPaillier.paillier.encrypt(r) for r in rand_vector]
        encrypt_vector_plus_rand_vector = [NaiveQueryPaillier.paillier.add(encrypt_rand_vector[i], encrypt_data_vector[i]) for i in range(real_d)]

        string_rand_vector = KDPBTreeCipher.array_to_string(rand_vector)
        aes = AESSuite(NaiveQueryPaillier.SecretKey)
        aes_rand_vector = aes.encrypt(string_rand_vector)

        ra_mul_scalar_product_plus_ra = NaiveQueryPaillier.paillier.decrypt(encrypt_ra_mul_scalar_product_plus_ra)
        vector_plus_rand_vector = NaiveQueryPaillier.decrypt_vector(encrypt_vector_plus_rand_vector)

    @staticmethod
    def encrypt_vector(vector: List[int]) -> List[Ciphertext]:
        return [NaiveQueryPaillier.paillier.encrypt(v) for v in vector]

    @staticmethod
    def decrypt_vector(encrypt_vector: List[Ciphertext]) -> List[int]:
        return [NaiveQueryPaillier.paillier.decrypt(c) for c in encrypt_vector]

    @staticmethod
    def multiply_two_numbers(cipher_a: Ciphertext, cipher_b: Ciphertext) -> Ciphertext:
        return NaiveQueryPaillier.paillier.mul_cipher(cipher_a, cipher_b)

if __name__ == "__main__":
    nqp = NaiveQueryPaillier()
    nqp.key_gen()
    c1 = nqp.paillier.encrypt(5)
    c = nqp.paillier.decrypt(nqp.paillier.mul(c1, -1))
    print(c)
    c2 = nqp.paillier.encrypt(7)
    res = NaiveQueryPaillier.multiply_two_numbers(c1, c2)
    res = nqp.paillier.decrypt(res)
    print(res)