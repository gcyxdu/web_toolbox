import random
from typing import List

class Key:
    def __init__(self, n: int, modVal: int, kappa: int, beta: int, delta: int, eta: int,
                 pair_key: List[bytes], key: List[bytes]):
        self.n = n
        self.modVal = modVal
        self.kappa = kappa
        self.beta = beta
        self.delta = delta
        self.eta = eta
        self.pair_key = pair_key
        self.key = key

    @staticmethod
    def generate_random_string(bitLength: int) -> str:
        template = "abcdefghijklmnopqrstuvwxyz"
        chars = [random.choice(template) for _ in range(bitLength)]
        return ''.join(chars)

    @staticmethod
    def init_key(beta: int, delta: int, eta: int) -> "Key":
        n = 64
        modVal = 2 ** n
        kappa = 256
        pair_key: List[bytes] = []
        key: List[bytes] = []

        bitLength = kappa // 8

        for _ in range(3):
            key_str = Key.generate_random_string(bitLength)
            key_bytes = key_str.encode('utf-8')
            pair_key.append(key_bytes)

        for _ in range(3):
            key_str = Key.generate_random_string(bitLength)
            key_bytes = key_str.encode('utf-8')
            key.append(key_bytes)

        sk = Key(n, modVal, kappa, beta, delta, eta, pair_key, key)
        return sk
