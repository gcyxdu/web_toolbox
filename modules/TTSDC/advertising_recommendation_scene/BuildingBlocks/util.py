import random
import hashlib
from typing import List
from BuildingBlocks.ase import ASE
from BuildingBlocks.alias_class import AliasPlain

class Util:
    @staticmethod
    def gen_randnum(key: bytes) -> int:
        sid = random.randint(0, 2**31 - 1)
        sid_str = str(sid).encode()
        r = ASE.hmac_sha256(key, sid_str)
        return r

    @staticmethod
    def gen_randnum_vec(n: int, key: bytes) -> List[int]:
        sid = random.randint(0, 2**31 - 1)
        sid_str = str(sid)
        vec = []
        for i in range(n):
            data = f"{sid_str}{i}".encode()
            r = ASE.hmac_sha256(key, data)
            vec.append(r)
        return vec

    @staticmethod
    def big_integer_add(a: List[int], b: List[int], mod_val: int) -> List[int]:
        return [(a[i] + b[i]) % mod_val for i in range(len(a))]

    @staticmethod
    def negative_big_vec(a: List[int], mod_val: int) -> List[int]:
        return [(-x) % mod_val for x in a]

    @staticmethod
    def print_bigint_vec(vec: List[int]):
        print(",".join(str(v) for v in vec))

    @staticmethod
    def print_int_vec(vec: List[int]):
        print(",".join(str(v) for v in vec))

    @staticmethod
    def int_to_binary(x: int, bit_length: int) -> List[int]:
        bits = [0] * bit_length
        i = 0
        while x != 0 and i < bit_length:
            bits[i] = x % 2
            x //= 2
            i += 1
        return bits

    @staticmethod
    def median(x_dataset: List[int]) -> List[int]:
        sorted_x = sorted(x_dataset)
        n = len(sorted_x)
        if n % 2 == 1:
            median_loc = (n - 1) // 2
        else:
            median_loc = (n - 2) // 2
        return [sorted_x[0], sorted_x[median_loc], sorted_x[-1]]

    @staticmethod
    def gen_rand_list(n: int, max_val: int) -> List[int]:
        return [abs(random.randint(0, 2**31 - 1) % max_val) for _ in range(n)]

    @staticmethod
    def print_two_list(x: List[int], y: List[int]):
        print("x\tw")
        for xi, yi in zip(x, y):
            print(f"{xi}\t{yi}")

    @staticmethod
    def print_alias(alias_plain: List[AliasPlain]):
        print("ele1\twgt1\tele2\twgt2")
        for a in alias_plain:
            print(f"{a.ele1}\t{a.wgt1}\t{a.ele2}\t{a.wgt2}")
