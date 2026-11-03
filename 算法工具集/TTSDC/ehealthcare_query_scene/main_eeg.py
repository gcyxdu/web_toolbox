import time
import random
from typing import List
from paillier import Paillier
from naive_query import NaiveQuery
from naive_query_paillier import NaiveQueryPaillier
from data import Data
from util_plain import UtilPlain
from kdpb_tree import KDPBTree
from kdpb_tree_cipher import KDPBTreeCipher
from kdpb_class import Record
from main_synthetic import MainSynthetic

class MainEEG:
    secret_key = "ssshhhhhhhhhhh!!ssshhhhhhhhhhh!!"
    file_string = "EEGEyeState.txt"
    split_string = ","

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
        MainEEG.paillier = Paillier(MainEEG.k)
        MainEEG.cipher_zero1 = MainEEG.paillier.encrypt(0)
        MainEEG.cipher_zero2 = MainEEG.paillier.encrypt(0)
        MainEEG.cipher_minus_one = MainEEG.paillier.encrypt(-1)

    @staticmethod
    def extract_attribute_vector(att_vector: List[int]) -> List[int]:
        new_vec = []
        for v in att_vector:
            if v == 0:
                new_vec.append(2 if random.random() > 0.5 else 4)
            else:
                new_vec.append(v)
        return new_vec

    @staticmethod
    def eval_encrypt_database(n: int, d: int, l: int) -> float:
        MainEEG.key_gen()
        database = Data.read_data(MainEEG.file_string, MainEEG.split_string, n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        t1 = time.time()
        root = KDPBTree.tree_building(record_list)
        encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainEEG.paillier)
        t2 = time.time()

        return (t2 - t1) * 1000  # 转换为毫秒

    # --------------------------- Token 生成评估 ---------------------------
    @staticmethod
    def eval_token_gen(d: int, l: int) -> float:
        n, cycle, tau = 4000, 10000, 10
        total_time = 0.0

        MainEEG.key_gen()
        database = Data.read_data(MainEEG.file_string, MainEEG.split_string, n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        root = KDPBTree.tree_building(record_list)
        encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainEEG.paillier)

        for i in range(cycle):
            loc = int(n * random.random())
            query_record = record_list[loc]
            att_vec = MainEEG.extract_attribute_vector(query_record.attribute)
            new_query = Record(query_record.data, att_vec)

            t1 = time.perf_counter_ns()
            token = KDPBTreeCipher.generate_token(
                new_query, tau, MainEEG.cipher_zero1, MainEEG.cipher_zero2, MainEEG.paillier
            )
            t2 = time.perf_counter_ns()

            if i >= 0.8 * cycle:
                total_time += t2 - t1

        return 5 * total_time / cycle / 1_000_000  # 毫秒

    # --------------------------- 查询评估 ---------------------------
    @staticmethod
    def eval_query(n: int, d: int, l: int, tau: int) -> float:
        MainEEG.key_gen()
        database = Data.read_data(MainEEG.file_string, MainEEG.split_string, n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        root = KDPBTree.tree_building(record_list)
        encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainEEG.paillier)

        total_time = 0.0
        for _ in range(MainEEG.cycle):
            loc = int(n * random.random())
            query_record = record_list[loc]
            att_vec = MainEEG.extract_attribute_vector(query_record.attribute)
            new_query = Record(query_record.data, att_vec)

            token = KDPBTreeCipher.generate_token(
                new_query, tau, MainEEG.cipher_zero1, MainEEG.cipher_zero2, MainEEG.paillier
            )

            t1 = time.time()
            candi = KDPBTreeCipher.filteration_query(
                encrypt_root, token, MainEEG.paillier, MainEEG.cipher_minus_one, MainEEG.beta
            )
            result = KDPBTreeCipher.verification_query(
                candi, token, MainEEG.paillier, MainEEG.cipher_minus_one, MainEEG.secret_key
            )
            t2 = time.time()
            total_time += t2 - t1

        return total_time / MainEEG.cycle * 1000  # 毫秒

    # --------------------------- Query 对比测试 ---------------------------
    @staticmethod
    def eval_query_filter_and_without_filter(n: int, d: int, l: int) -> float:
        MainEEG.key_gen()
        database = Data.read_data(MainEEG.file_string, MainEEG.split_string, n, d)
        record_list = Data.add_attribute_on_datalist(database, l)

        root = KDPBTree.tree_building(record_list)
        encrypt_root = KDPBTreeCipher.encrypt_tree(root, MainEEG.paillier)

        encrypt_data = NaiveQuery.encrypt_data(record_list, MainEEG.paillier)

        loc = int(n * random.random())
        query_record = record_list[loc]
        att_vec = MainEEG.extract_attribute_vector(query_record.attribute)
        new_query = Record(query_record.data, att_vec)
        tau = 10

        token = KDPBTreeCipher.generate_token(
            new_query, tau, MainEEG.cipher_zero1, MainEEG.cipher_zero2, MainEEG.paillier
        )

        t1 = time.time()
        candi = KDPBTreeCipher.filteration_query(
            encrypt_root, token, MainEEG.paillier, MainEEG.cipher_minus_one, MainEEG.beta
        )
        final_res_ours = KDPBTreeCipher.verification_query(
            candi, token, MainEEG.paillier, MainEEG.cipher_minus_one, MainEEG.secret_key
        )
        t2 = time.time()

        print(f"time of our scheme: {(t2 - t1) * 1000:.2f} ms")
        print(f"Num of query result in our scheme: {len(final_res_ours)}")

        for res in final_res_ours:
            UtilPlain.print_vector(res)

        t1 = time.time()
        final_res_naive = NaiveQuery.search_naive_method(
            encrypt_data, token, MainEEG.paillier, MainEEG.cipher_minus_one, MainEEG.secret_key
        )
        t2 = time.time()

        print(f"time of Naive scheme: {(t2 - t1) * 1000:.2f} ms")
        print(f"Num of query result in Naive scheme: {len(final_res_naive)}")

        return (t2 - t1) * 1000

    # --------------------------- 参数循环测试 ---------------------------
    @staticmethod
    def database_encryption_with_ND():
        n_list = [6000, 8000, 10000, 12000, 14000]
        d_list = [4, 6, 8]
        print("Computation cost of database encryption with n and d")
        print("\t", end="")
        for n in n_list:
            print(f"n = {n}\t", end="")
        print()

        for d in d_list:
            print(f"d = {d}\t", end="", flush=True)
            for n in n_list:
                t = MainEEG.eval_encrypt_database(n, d, MainEEG.l)
                print(f"{t:.4f}\t", end="", flush=True)
            print()

        for d in d_list:
            print(f"d = {d}\t", end="", flush=True)
            for n in n_list:
                t = NaiveQueryPaillier.encrypt_database_naive(n, d, MainEEG.l)
                print(f"{t:.4f}\t", end="", flush=True)
            print()

    @staticmethod
    def database_token_gen_with_ND():
        d_list = [4, 6, 8]
        print("Computation cost of token generation time with n and d")
        print("\t", end="")
        for d in d_list:
            print(f"d = {d}\t", end="", flush=True)
        print()

        print("\t", end="")
        for d in d_list:
            t = MainEEG.eval_token_gen(d, MainEEG.l)
            print(f"{t:.4f}\t", end="", flush=True)
        print()

        print("\t", end="")
        for d in d_list:
            t = NaiveQueryPaillier.generate_token(d, MainEEG.l)
            print(f"{t:.4f}\t", end="", flush=True)
        print()

    @staticmethod
    def query_with_ND():
        n_list = [6000, 8000, 10000, 12000, 14000]
        d_list = [4, 6, 8]
        tau = 1
        print("Computation cost of query time with n and d")
        print("\t", end="")
        for n in n_list:
            print(f"n = {n}\t", end="", flush=True)
        print()

        for d in d_list:
            print(f"d = {d}\t", end="", flush=True)
            for n in n_list:
                t = MainEEG.eval_query(n, d, MainEEG.l, tau)
                print(f"{t:.4f}\t", end="", flush=True)
            print()

        for d in d_list:
            print(f"d = {d}\t", end="", flush=True)
            for n in n_list:
                t = NaiveQueryPaillier.query_naive(n, d, MainEEG.l)
                print(f"{t:.4f}\t", end="", flush=True)
            print()

    @staticmethod
    def query_with_TauD():
        n = 14000
        d_list = [4, 6, 8]
        tau_list = [1, 2, 3, 4, 5]
        print("Computation cost of query time with tau and d")
        print("\t", end="")
        for tau in tau_list:
            print(f"tau = {tau}\t", end="", flush=True)
        print()

        for d in d_list:
            print(f"d = {d}\t", end="")
            for tau in tau_list:
                t = MainEEG.eval_query(n, d, MainEEG.l, tau)
                print(f"{t:.4f}\t", end="", flush=True)
            print()

        for d in d_list:
            print(f"d = {d}\t", end="", flush=True)
            for tau in tau_list:
                t = NaiveQueryPaillier.query_naive(n, d, MainEEG.l)
                print(f"{t:.4f}\t", end="", flush=True)
            print()


if __name__ == "__main__":
    MainEEG.database_encryption_with_ND()
    MainEEG.database_token_gen_with_ND()
    MainEEG.query_with_ND()
    MainEEG.query_with_TauD()
    MainSynthetic.main()