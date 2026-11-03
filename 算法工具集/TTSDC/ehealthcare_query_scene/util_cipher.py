import random
from paillier import Paillier
from typing import List
from heu.phe import Ciphertext

class UtilCipher:
    security_key = "qwerasdfqwerasdsqwerasdfqwerasds"
    
    def __init__(self, k: int):
        self.paillier = Paillier(k)
        self.ciphertext_zero1 = self.paillier.encrypt(0)
        self.ciphertext_zero2 = self.paillier.encrypt(0)
        self.ciphertext_minus_one = self.paillier.encrypt(-1)
        self.rnd = random.SystemRandom()

    @staticmethod
    def sign_computation_protocol(c: Ciphertext, paillier: Paillier, ciphertext_minus_one: Ciphertext) -> int:
        rnd = random.SystemRandom()

        while True:
            r1 = rnd.getrandbits(32)
            r2 = rnd.getrandbits(32)
            if r1 > r2:
                break

        result = paillier.add(paillier.mul(c, r1), paillier.mul(ciphertext_minus_one, r2))

        m = paillier.decrypt(result)

        sign = -1 if m < 0 else 1
        return sign
    
    @staticmethod
    def flag_sign_protocol(c: Ciphertext, encrypt_label: Ciphertext, encrypt_flag: Ciphertext, paillier: Paillier, ciphertext_minus_one: Ciphertext):
        rnd = random.SystemRandom()
        encrypt_one = paillier.encrypt(1)

        c = paillier.add(c, paillier.mul(encrypt_label, -1))

        r1 = rnd.getrandbits(32)
        r2 = rnd.getrandbits(32)

        result = paillier.add(paillier.mul(c, r1), paillier.mul(paillier.sub(encrypt_flag, encrypt_one), r2))

        m = paillier.decrypt(result)
        flag = 1 if m == 0 else 0
        return flag

    @staticmethod
    def scalar_product_over_cipher(v1: List[Ciphertext], v2: List[Ciphertext], paillier: Paillier):
        return paillier.scalar_product_ciphertext(v1, v2)
