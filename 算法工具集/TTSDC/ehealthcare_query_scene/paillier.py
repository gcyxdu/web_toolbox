from typing import List
from heu import phe
import secrets
import random
from heu.phe import Ciphertext, Plaintext, SchemaType

class Paillier:
    def __init__(self, k: int):
        self.k = k
        self.kit = phe.setup(SchemaType.ZPaillier, k)
        self.encryptor = self.kit.encryptor()
        self.evaluator = self.kit.evaluator()
        self.decryptor = self.kit.decryptor()

    def encrypt(self, cleartext: int) -> Ciphertext:
        return self.encryptor.encrypt_raw(cleartext)
    
    def decrypt(self, ciphertext: Ciphertext) -> int:
        return self.decryptor.decrypt_raw(ciphertext)
    
    def encrypt_vector(self, vector: List[int]) -> List[Ciphertext]:
        return [self.encrypt(v) for v in vector]
    
    def decrypt_vector(self, cipher_vector: List[Ciphertext]) -> List[int]:
        return [self.decrypt(cipher) for cipher in cipher_vector]
    
    def add(self, a, b) -> Ciphertext:
        return self.evaluator.add(a, b)
    
    def sub(self, a, b) -> Ciphertext:
        return self.evaluator.sub(a, b)
    
    def add_vector(self, clear_vector: List[int], cipher_vector: List[Ciphertext]) -> List[Ciphertext]: 
        encode_v = [self.kit.bigint_encoder().encode(v) for v in clear_vector]
        return [self.add(c1, c2) for (c1, c2) in zip(encode_v, cipher_vector)]
    
    def mul(self, cipher: Ciphertext, scalar: int) -> Ciphertext:
        return self.evaluator.mul(cipher, scalar)
    
    def mul_cipher(self, cipher_a: Ciphertext, cipher_b: Ciphertext) -> Ciphertext:
        beta = 40
        ra = random.getrandbits(beta)
        rb = random.getrandbits(beta)

        cipher_ra = self.encrypt(ra)
        cipher_rb = self.encrypt(rb)

        cipher_a_plus_ra = self.add(cipher_a, cipher_ra)
        cipher_b_plus_rb = self.add(cipher_b, cipher_rb)

        a_plus_ra = self.decrypt(cipher_a_plus_ra)
        b_plus_rb = self.decrypt(cipher_b_plus_rb)

        a_plus_ra_mul_b_plus_rb = a_plus_ra * b_plus_rb
        cipher_a_plus_ra_mul_b_plus_rb = self.encrypt(a_plus_ra_mul_b_plus_rb)

        cipher_a_mul_rb = self.mul(cipher_a, rb)
        cipher_b_mul_ra = self.mul(cipher_b, ra)

        ra_mul_rb = ra * rb
        cipher_ra_mul_rb = self.encrypt(ra_mul_rb)

        cipher_a_mul_b = self.sub(cipher_a_plus_ra_mul_b_plus_rb, cipher_a_mul_rb)
        cipher_a_mul_b = self.sub(cipher_a_mul_b, cipher_b_mul_ra)
        cipher_a_mul_b = self.sub(cipher_a_mul_b, cipher_ra_mul_rb)

        return cipher_a_mul_b
    
    def scalar_product_ciphertext(self, cv1: List[Ciphertext], cv2: List[Ciphertext]) -> Ciphertext:
        ciphertext = self.encrypt(0)
        for (cv1, cv2) in zip(cv1, cv2):
            ciphertext = self.add(ciphertext, self.mul_cipher(cv1, cv2))
        return ciphertext
    
    def encrypt_by_ciphertexts(self, val: int, cipher_zero1: Ciphertext, cipher_zero2: Ciphertext) -> Ciphertext:
        rnd = secrets.SystemRandom()
        r1 = rnd.getrandbits(32)
        r2 = rnd.getrandbits(32)
        
        cipher = self.encrypt(val)
        c = self.add(cipher, self.add(self.mul(cipher_zero1, r1), self.mul(cipher_zero2, r2)))
        return c
    
    def encrypt_vector_by_ciphertexts(self, vector: List[int], cipher_zero1: Ciphertext, cipher_zero2: Ciphertext) -> List[Ciphertext]:
        return [self.encrypt_by_ciphertexts(v, cipher_zero1, cipher_zero2) for v in vector]
    
    def substract_vectors(v1: List[int], v2: List[int]) -> List[int]:
        return [int(a - b) for a, b in zip(v1, v2)]