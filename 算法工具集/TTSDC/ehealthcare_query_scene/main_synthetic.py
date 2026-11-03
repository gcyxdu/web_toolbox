import random
import time
from typing import List
from paillier import Paillier
from data import Data
from kdpb_class import Record
from kdpb_tree import KDPBTree
from kdpb_tree_cipher import KDPBTreeCipher
from naive_query import NaiveQuery
from naive_query_paillier import NaiveQueryPaillier

class MainSynthetic:
    secret_key = "ssshhhhhhhhhhh!!ssshhhhhhhhhhh!!"
    k = 512
    l = 4
    beta = 5

    paillier = None
    cipher_zero1 = None
    cipher_zero2 = None
    cipher_minus_one = None

    tau = 100
    cycle = 50

    @staticmethod
    def key_gen():
        MainSynthetic.paillier = Paillier(MainSynthetic.k)
        MainSynthetic.cipher_zero1 = MainSynthetic.paillier.encrypt(0)
        MainSynthetic.cipher_zero2 = MainSynthetic.paillier.encrypt(0)
        MainSynthetic.cipher_minus_one = MainSynthetic.paillier.encrypt(-1)

    @staticmethod
    def extract_attribute_vector(att_vector: List[int]) -> List[int]:
        new_attr_vector = []
        for val in att_vector:
            if val == 0:
                new_attr_vector.append(2 if random.random() > 0.5 else 4)
            else:
                new_attr_vector.append(val)
        return new_attr_vector

    @staticmethod
    def eval_encrypt_database(n: int, d: int, l: int) -> float:
        MainSynthetic.key_gen()
        database = Data.gen_synthetic_data(n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        cycle = 1
        total_time = 0.0

        for _ in range(cycle):
            t1 = time.time() * 1000
            root = KDPBTree.tree_building(record_list)
            encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainSynthetic.paillier)
            t2 = time.time() * 1000
            total_time += (t2 - t1)

        return total_time / cycle

    @staticmethod
    def eval_token_gen(d: int, l: int) -> float:
        n = 4000
        cycle = 10000
        tau = 10
        total_time = 0.0

        MainSynthetic.key_gen()
        database = Data.gen_synthetic_data(n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        root = KDPBTree.tree_building(record_list)
        encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainSynthetic.paillier)

        for i in range(cycle):
            loc = random.randint(0, n - 1)
            query_record = record_list[loc]
            att_vector = MainSynthetic.extract_attribute_vector(query_record.attribute)
            new_query_record = Record(query_record.data, att_vector)

            t1 = time.time_ns()
            query_token = KDPBTreeCipher.generate_token(new_query_record, tau,
                                                       MainSynthetic.cipher_zero1,
                                                       MainSynthetic.cipher_zero2,
                                                       MainSynthetic.paillier)
            t2 = time.time_ns()

            if i >= 0.8 * cycle:
                total_time += (t2 - t1)

        return 5 * total_time / cycle / 1_000_000

    @staticmethod
    def eval_query(n: int, d: int, l: int, tau: int) -> float:
        cycle = 1000
        total_time = 0.0

        MainSynthetic.key_gen()
        database = Data.gen_synthetic_data(n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        root = KDPBTree.tree_building(record_list)
        encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainSynthetic.paillier)

        for _ in range(cycle):
            loc = random.randint(0, n - 1)
            query_record = record_list[loc]
            att_vector = MainSynthetic.extract_attribute_vector(query_record.attribute)
            new_query_record = Record(query_record.data, att_vector)

            query_token = KDPBTreeCipher.generate_token(new_query_record, tau,
                                                       MainSynthetic.cipher_zero1,
                                                       MainSynthetic.cipher_zero2,
                                                       MainSynthetic.paillier)

            t1 = time.time() * 1000
            candi_array = KDPBTreeCipher.filteration_query(encrypt_root, query_token,
                                                         MainSynthetic.paillier,
                                                         MainSynthetic.cipher_minus_one,
                                                         MainSynthetic.beta)
            final_result = KDPBTreeCipher.verification_query(candi_array, query_token,
                                                            MainSynthetic.paillier,
                                                            MainSynthetic.cipher_minus_one,
                                                            MainSynthetic.secret_key)
            t2 = time.time() * 1000
            total_time += (t2 - t1)

        return total_time / cycle

    @staticmethod
    def eval_query_filter_and_without_filter(n: int, d: int, l: int) -> float:
        cycle = 100
        total_time = 0.0

        for _ in range(cycle):
            MainSynthetic.key_gen()
            database = Data.gen_synthetic_data(n, d)
            record_list = Data.add_attribute_on_datalist(database, l)

            root = KDPBTree.tree_building(record_list)
            encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainSynthetic.paillier)

            encrypt_dat_array_list = NaiveQuery.encrypt_data(record_list, MainSynthetic.paillier)

            loc = random.randint(0, n - 1)
            query_record = record_list[loc]
            att_vector = MainSynthetic.extract_attribute_vector(query_record.attribute)
            new_query_record = Record(query_record.data, att_vector)
            tau = 10

            query_token = KDPBTreeCipher.generate_token(new_query_record, tau,
                                                       MainSynthetic.cipher_zero1,
                                                       MainSynthetic.cipher_zero2,
                                                       MainSynthetic.paillier)

            t1 = time.time() * 1000
            candi_array = KDPBTreeCipher.filteration_query(encrypt_root, query_token,
                                                         MainSynthetic.paillier,
                                                         MainSynthetic.cipher_minus_one,
                                                         MainSynthetic.beta)
            final_result_ours = KDPBTreeCipher.verification_query(candi_array, query_token,
                                                                 MainSynthetic.paillier,
                                                                 MainSynthetic.cipher_minus_one,
                                                                 MainSynthetic.secret_key)
            t2 = time.time() * 1000
            print("time of our scheme:", t2 - t1)
            print("Num of query result in our scheme:", len(final_result_ours))

            t1 = time.time() * 1000
            final_result_naive = NaiveQuery.search_naive_method(encrypt_dat_array_list, query_token,
                                                              MainSynthetic.paillier,
                                                              MainSynthetic.cipher_minus_one,
                                                              MainSynthetic.secret_key)
            t2 = time.time() * 1000
            print("time of Naive scheme:", t2 - t1)
            print("Num of query result in Naive scheme:", len(final_result_naive))

            total_time = t2 - t1

        return total_time
    
    @staticmethod
    def database_encryption_with_ND():
        n_list = [5000, 10000, 15000, 20000, 25000]
        d_list = [4, 6, 8]
        
        print("Computation cost of database encryption with n and d")
        print("\t", end="")
        for n in n_list:
            print(f"n = {n}\t", end="")
        print()

        for d in d_list:
            print(f"d = {d}\t", end="")
            for n in n_list:
                time_taken = MainSynthetic.eval_encrypt_database(n, d, MainSynthetic.l)
                print(f"{time_taken:.6f}\t", end="")
            print()
        
        for d in d_list:
            print(f"d = {d}\t", end="")
            for n in n_list:
                time_taken = NaiveQueryPaillier.encrypt_database_naive(n, d, MainSynthetic.l)
                print(f"{time_taken:.6f}\t", end="")
            print()

    @staticmethod
    def database_token_gen_with_ND():
        d_list = [4, 6, 8]
        
        print("Computation cost of token generation time with n and d")
        print("\t", end="")
        for d in d_list:
            print(f"d = {d}\t", end="")
        print()
        
        print("\t", end="")
        for d in d_list:
            time_taken = MainSynthetic.eval_token_gen(d, MainSynthetic.l)
            print(f"{time_taken:.6f}\t", end="")
        print()
        
        print("\t", end="")
        for d in d_list:
            time_taken = NaiveQueryPaillier.generate_token(d, MainSynthetic.l)
            print(f"{time_taken:.6f}\t", end="")
        print()

    @staticmethod
    def query_with_ND():
        n_list = [5000, 10000, 15000, 20000, 25000]
        d_list = [4, 6, 8]
        tau = 1
        
        print("Computation cost of query time with n and d")
        print("\t", end="")
        for n in n_list:
            print(f"n = {n}\t", end="")
        print()

        for d in d_list:
            print(f"d = {d}\t", end="")
            for n in n_list:
                time_taken = MainSynthetic.eval_query(n, d, MainSynthetic.l, tau)
                print(f"{time_taken:.6f}\t", end="")
            print()
        
        for d in d_list:
            print(f"d = {d}\t", end="")
            for n in n_list:
                time_taken = NaiveQueryPaillier.query_naive(n, d, MainSynthetic.l)
                print(f"{time_taken:.6f}\t", end="")
            print()

    @staticmethod
    def query_with_TauD():
        n = 15000
        d_list = [4, 6, 8]
        tau_list = [1, 2, 3, 4, 5]
        
        print("Computation cost of query time with tau and d")
        print("\t", end="")
        for tau in tau_list:
            print(f"tau = {tau}\t", end="")
        print()

        for d in d_list:
            print(f"d = {d}\t", end="")
            for tau in tau_list:
                time_taken = MainSynthetic.eval_query(n, d, MainSynthetic.l, tau)
                print(f"{time_taken:.6f}\t", end="")
            print()
        
        for d in d_list:
            print(f"d = {d}\t", end="")
            for tau in tau_list:
                time_taken = NaiveQueryPaillier.query_naive(n, d, MainSynthetic.l)
                print(f"{time_taken:.6f}\t", end="")
            print()

    @staticmethod
    def main():
        MainSynthetic.database_encryption_with_ND()
        MainSynthetic.database_token_gen_with_ND()
        MainSynthetic.query_with_ND()
        MainSynthetic.query_with_TauD()


if __name__ == "__main__":
    MainSynthetic.main()