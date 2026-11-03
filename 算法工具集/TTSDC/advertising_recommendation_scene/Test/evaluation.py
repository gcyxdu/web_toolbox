import random
import time
from typing import List, Tuple
import secretflow as sf

from BuildingBlocks.data_processing import DataProcessing
from BuildingBlocks.ase import Shares
from EPWS.bst_cipher import BSTCipher, NodeCipher, InternalNodeCipher, CandidateResult
from EPWS.bst_plain import BSTPlain
from EPWS.key import Key


class Evaluation:
    key: Key = None
    query_comm: float = 0.0

    @staticmethod
    def outsourcing(x_dataset: List[int], w_dataset: List[int], beta_val: int) -> NodeCipher:
        delta_val = 20
        eta = 30
        key = Key.init_key(beta_val, delta_val, eta)

        tree = BSTPlain.bst_building(x_dataset, w_dataset)
        tree_cipher = BSTCipher.bst_enc(tree, key.beta)
        return tree_cipher

    @staticmethod
    def size_of_bst_cipher(tree_cipher: NodeCipher, beta: int) -> int:
        node_stack = [tree_cipher]
        size_of_each_share = 192  # bits, 6×64-bit data
        num_shares = 0
        num_node = 0

        while node_stack:
            node = node_stack.pop()
            num_node += 1

            if node.is_leaf:
                num_shares += beta + 2
            else:
                internal_node_cipher: InternalNodeCipher = node
                alias_ciphers = internal_node_cipher.alias_cipher_node
                num_shares += beta * 3 + 2 + len(alias_ciphers) * 4

                if internal_node_cipher.left:
                    node_stack.append(internal_node_cipher.left)
                if internal_node_cipher.right:
                    node_stack.append(internal_node_cipher.right)

        bit_size_of_tree = num_shares * size_of_each_share + num_node
        return bit_size_of_tree

    @staticmethod
    def query_processing(tree_cipher: NodeCipher, query_cipher: List[List[Shares]]) -> Tuple[Shares, float]:
        query_comm = 0.0
        candidate_result, total_comm = BSTCipher.bst_search_cipher(tree_cipher, query_cipher, Evaluation.key)
        query_comm += total_comm
        result, total_comm = BSTCipher.result_verify(candidate_result, Evaluation.key.delta, Evaluation.key.eta, Evaluation.key)
        query_comm += total_comm
        return result, query_comm

    # ========== Evaluation Routines ==========

    @staticmethod
    def outsourcing_eval_with_n():
        filename = "cleanData.txt"
        split_string = ","
        cycle = 50
        n_values = [20000, 30000, 40000, 50000, 60000]
        beta_val = 16
        
        sf.shutdown()
        sf.init(parties=['owner', 'servers'], address='local')
        owner = sf.PYU('owner')
        servers = sf.PYU('servers')

        for n_val in n_values:
            database = owner(DataProcessing.read_data_limited)(filename, split_string, n_val)
            x_dataset = owner(lambda db: [row[1] for row in db])(database)
            w_dataset = owner(lambda db: [row[0] for row in db])(database)

            total_time = 0.0
            bit_size_of_tree = 0.0

            for _ in range(cycle):
                start = time.time()
                node_cipher = owner(Evaluation.outsourcing)(x_dataset, w_dataset, beta_val)
                node_cipher_to_servers = node_cipher.to(servers)
                end = time.time()

                total_time += (end - start) * 1000
                bit_size_of_tree += sf.reveal(owner(Evaluation.size_of_bst_cipher)(node_cipher, beta_val))
            
            avg_time = total_time / cycle
            avg_size_mb = bit_size_of_tree / cycle / 1024 / 1024 / 8
            print(f"n = {n_val}; Outsourcing time: {avg_time:.2f} ms, Size of tree: {avg_size_mb:.4f} MB")

    @staticmethod
    def outsourcing_eval_with_beta():
        filename = "cleanData.txt"
        split_string = ","
        cycle = 50
        n_val = 30000
        betas = [16, 19, 22, 25, 28]

        sf.shutdown()
        sf.init(parties=['owner', 'servers'], address='local')
        owner = sf.PYU('owner')
        servers = sf.PYU('servers')

        database = owner(DataProcessing.read_data_limited)(filename, split_string, n_val)
        x_dataset = owner(lambda db: [row[1] for row in db])(database)
        w_dataset = owner(lambda db: [row[0] for row in db])(database)

        for beta_val in betas:
            total_time = 0.0
            bit_size_of_tree = 0.0

            for _ in range(cycle):
                start = time.time()
                node_cipher = owner(Evaluation.outsourcing)(x_dataset, w_dataset, beta_val)
                node_cipher_to_servers = node_cipher.to(servers)
                end = time.time()

                total_time += (end - start) * 1000
                bit_size_of_tree += sf.reveal(owner(Evaluation.size_of_bst_cipher)(node_cipher, beta_val))

            avg_time = total_time / cycle
            avg_size_mb = bit_size_of_tree / cycle / 1024 / 1024 / 8
            print(f"beta = {beta_val}; Outsourcing time: {avg_time:.2f} ms, Size of tree: {avg_size_mb:.4f} MB")

    @staticmethod
    def query_enc_with_beta():
        rnd = random.Random()
        betas = [16, 19, 22, 25, 28]
        size_of_each_share = 192
        cycle = 1000

        sf.shutdown()
        sf.init(parties=['query_user', 'servers'], address='local')
        query_user = sf.PYU('query_user')
        servers = sf.PYU('servers')

        for beta_val in betas:
            l = abs(rnd.randint(0, 2**16))
            u = l + 10

            start = time.time()
            for _ in range(cycle):
                query_cipher = query_user(BSTCipher.query_enc)(l, u, beta_val)
                query_cipher_to_servers = query_cipher.to(servers)
            end = time.time()

            avg_time = (end - start) * 1000 / cycle
            bit_size = 2 * beta_val * size_of_each_share / 8

            print(f"beta = {beta_val}; Query encryption time: {avg_time:.2f} ms, Size: {bit_size:.2f} B")

    @staticmethod
    def query_processing_eval_with_n():
        rnd = random.Random()
        filename = "cleanData.txt"
        split_string = ","
        cycle = 10
        n_values = [20000, 30000, 40000, 50000, 60000]
        beta_val = 16
        delta = 20
        eta = 30

        sf.shutdown()
        sf.init(parties=['owner', 'query_user', 'servers'], address='local')
        owner = sf.PYU('owner')
        query_user = sf.PYU('query_user')
        servers = sf.PYU('servers')        

        Evaluation.key = Key.init_key(beta_val, delta, eta)

        for n_val in n_values:
            database = owner(DataProcessing.read_data_limited)(filename, split_string, n_val)
            x_dataset = owner(lambda db: [row[1] for row in db])(database)
            w_dataset = owner(lambda db: [row[0] for row in db])(database)

            node_cipher = owner(Evaluation.outsourcing)(x_dataset, w_dataset, beta_val).to(servers)

            total_time = 0.0
            total_comm = 0.0

            for _ in range(cycle):
                l = 1500
                u = l + 500
                query_cipher = query_user(BSTCipher.query_enc)(l, u, beta_val).to(servers)

                start = time.time()
                result_shares, query_comm = servers(Evaluation.query_processing)(node_cipher, query_cipher)
                result_shares_to_query_user = result_shares.to(query_user)
                Evaluation.query_comm = sf.reveal(query_comm)
                end = time.time()

                total_time += (end - start) * 1000
                total_comm += Evaluation.query_comm / 1024 / 8

            avg_time = total_time / cycle
            avg_comm_mb = total_comm / cycle / 1024
            print(f"n = {n_val}; Query time: {avg_time:.2f} ms, Comm: {avg_comm_mb:.4f} MB")

    @staticmethod
    def query_processing_eval_with_beta():
        filename = "cleanData.txt"
        split_string = ","
        cycle = 10
        n_val = 30000
        betas = [16, 19, 22, 25, 28]

        sf.shutdown()
        sf.init(parties=['owner', 'query_user', 'servers'], address='local')
        owner = sf.PYU('owner')
        query_user = sf.PYU('query_user')
        servers = sf.PYU('servers') 

        for beta_val in betas:
            delta = 20
            eta = 30

            Evaluation.key = Key.init_key(beta_val, delta, eta)

            database = owner(DataProcessing.read_data_limited)(filename, split_string, n_val)
            x_dataset = owner(lambda db: [row[1] for row in db])(database)
            w_dataset = owner(lambda db: [row[0] for row in db])(database)

            node_cipher = owner(Evaluation.outsourcing)(x_dataset, w_dataset, beta_val).to(servers)

            total_time = 0.0
            total_comm = 0.0

            for _ in range(cycle):
                l = 1500
                u = l + 500
                query_cipher = query_user(BSTCipher.query_enc)(l, u, beta_val).to(servers)

                start = time.time()
                result_shares, query_comm = servers(Evaluation.query_processing)(node_cipher, query_cipher)
                result_shares_to_query_user = result_shares.to(query_user)
                Evaluation.query_comm = sf.reveal(query_comm)
                end = time.time()

                total_time += (end - start) * 1000
                total_comm += Evaluation.query_comm / 1024 / 8

            avg_time = total_time / cycle
            avg_comm_mb = total_comm / cycle / 1024
            print(f"beta = {beta_val}; Query time: {avg_time:.2f} ms, Comm: {avg_comm_mb:.4f} MB")

    @staticmethod
    def query_processing_eval_with_range():
        filename = "cleanData.txt"
        split_string = ","
        cycle = 10
        n_val = 30000
        beta_val = 16
        delta = 20
        eta = 30

        sf.shutdown()
        sf.init(parties=['owner', 'query_user', 'servers'], address='local')
        owner = sf.PYU('owner')
        query_user = sf.PYU('query_user')
        servers = sf.PYU('servers') 

        Evaluation.key = Key.init_key(beta_val, delta, eta)

        ranges = [200, 400, 600, 800, 1000]

        for r in ranges:
            database = owner(DataProcessing.read_data_limited)(filename, split_string, n_val)
            x_dataset = owner(lambda db: [row[1] for row in db])(database)
            w_dataset = owner(lambda db: [row[0] for row in db])(database)

            node_cipher = owner(Evaluation.outsourcing)(x_dataset, w_dataset, beta_val).to(servers)

            total_time = 0.0
            total_comm = 0.0

            for _ in range(cycle):
                l = 1500
                u = l + r
                query_cipher = query_user(BSTCipher.query_enc)(l, u, beta_val).to(servers)

                start = time.time()
                result_shares, query_comm = servers(Evaluation.query_processing)(node_cipher, query_cipher)
                result_shares_to_query_user = result_shares.to(query_user)
                Evaluation.query_comm = sf.reveal(query_comm)
                end = time.time()

                total_time += (end - start) * 1000
                total_comm += Evaluation.query_comm / 1024 / 8

            avg_time = total_time / cycle
            avg_comm_mb = total_comm / cycle / 1024
            print(f"range = {r}; Query time: {avg_time:.2f} ms, Comm: {avg_comm_mb:.4f} MB")


if __name__ == "__main__":
    print('The version of SecretFlow: {}\n'.format(sf.__version__))

    print("Outsourcing time with N")
    # Evaluation.outsourcing_eval_with_n()

    print("Outsourcing time with beta")
    # Evaluation.outsourcing_eval_with_beta()

    print("Query encryption time with beta")
    Evaluation.query_enc_with_beta()

    print("Query processing with N")
    Evaluation.query_processing_eval_with_n()

    print("Query processing with beta")
    Evaluation.query_processing_eval_with_beta()

    print("Query processing with range")
    Evaluation.query_processing_eval_with_range()
