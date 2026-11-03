import secrets
import random
import hmac
import hashlib
from typing import List, Sequence
from EPWS.key import Key


class Shares:
    def __init__(self, s1: int, s2: int, s3: int):
        self.s1 = s1
        self.s2 = s2
        self.s3 = s3


class VecShares:
    def __init__(self, s1_vec: List[int], s2_vec: List[int], s3_vec: List[int]):
        self.s1_vec = s1_vec
        self.s2_vec = s2_vec
        self.s3_vec = s3_vec


class ASE:
    n: int = 64
    mod_value: int = 2 ** n
    srnd = secrets.SystemRandom()

    @staticmethod
    def share_int(x: int) -> Shares:
        s1 = ASE.srnd.getrandbits(ASE.n)
        s2 = ASE.srnd.getrandbits(ASE.n)
        s3 = (x - s1 - s2) % ASE.mod_value
        return Shares(s1, s2, s3)
    
    @staticmethod
    def share_list(x_vec: List[int]) -> VecShares:
        n = len(x_vec)
        s1_vec = []
        s2_vec = []
        s3_vec = []

        for i in range(n):
            shares = ASE.share_int(x_vec[i])
            s1_vec[i] = shares.s1
            s2_vec[i] = shares.s2
            s3_vec[i] = shares.s3

        return VecShares(s1_vec, s2_vec, s3_vec)
    
    @staticmethod
    def share_list_shares(x: List[int]) -> List[Shares]:
        shares = [ASE.share_int(x[i]) for i in range(len(x))]
        return shares

    @staticmethod
    def recover(x_shares: Shares) -> int:
        x = (x_shares.s1 + x_shares.s2 + x_shares.s3) % ASE.mod_value
        if x < (ASE.mod_value // 2):
            return x
        else:
            return x - ASE.mod_value

    @staticmethod
    def ase_add(x: Shares, y: Shares) -> Shares:
        s1 = (x.s1 + y.s1) % ASE.mod_value
        s2 = (x.s2 + y.s2) % ASE.mod_value
        s3 = (x.s3 + y.s3) % ASE.mod_value
        return Shares(s1, s2, s3)

    @staticmethod
    def ase_add_int(x: Shares, y: int) -> Shares:
        s1 = (x.s1 +y) % ASE.mod_value
        return Shares(s1, x.s2, x.s3)

    @staticmethod
    def ase_sub(x: Shares, y: Shares) -> Shares:
        s1 = (x.s1 - y.s1) % ASE.mod_value
        s2 = (x.s2 - y.s2) % ASE.mod_value
        s3 = (x.s3 - y.s3) % ASE.mod_value
        return Shares(s1, s2, s3)

    @staticmethod
    def ase_sub_by_int(x: int, y: Shares) -> Shares:
        s1 = (x - y.s1) % ASE.mod_value
        return Shares(s1, (-y.s2) % ASE.mod_value, (-y.s3) % ASE.mod_value)

    @staticmethod
    def ase_scale_int(x: Shares, y: int) -> Shares:
        s1 = (x.s1 * y) % ASE.mod_value
        s2 = (x.s2 * y) % ASE.mod_value
        s3 = (x.s3 * y) % ASE.mod_value
        return Shares(s1, s2, s3)

    # ---- HMAC SHA256 -> BigInteger mod mod_value ----
    @staticmethod
    def hmac_sha256(key_bytes: bytes, content: bytes) -> int:
        mac = hmac.new(key_bytes, content, hashlib.sha256).digest()
        mac_int = int.from_bytes(mac, byteorder='big', signed=False)
        return mac_int % ASE.mod_value

    # ---- ASE_mul: multiplication with PRF-based randomization ----
    @staticmethod
    def ase_mul(x: Shares, y: Shares, key: Key) -> Shares:
        s1 = (x.s1 * y.s1) % ASE.mod_value
        s1 = (s1 + (x.s1 * y.s2) % ASE.mod_value) % ASE.mod_value
        s1 = (s1 + (x.s2 * y.s1) % ASE.mod_value) % ASE.mod_value

        s2 = (x.s2 * y.s2) % ASE.mod_value
        s2 = (s2 + (x.s2 * y.s3) % ASE.mod_value) % ASE.mod_value
        s2 = (s2 + (x.s3 * y.s2) % ASE.mod_value) % ASE.mod_value

        s3 = (x.s3 * y.s3) % ASE.mod_value
        s3 = (s3 + (x.s3 * y.s1) % ASE.mod_value) % ASE.mod_value
        s3 = (s3 + (x.s1 * y.s3) % ASE.mod_value) % ASE.mod_value

        return Shares(s1, s2, s3)
    
    @staticmethod
    def ase_mul_without_random(x: Shares, y: Shares, key: Key) -> Shares:
        s1 = (x.s1 * y.s1) % ASE.mod_value
        s1 = (s1 + (x.s1 * y.s2) % ASE.mod_value) % ASE.mod_value
        s1 = (s1 + (x.s2 * y.s1) % ASE.mod_value) % ASE.mod_value

        s2 = (x.s2 * y.s2) % ASE.mod_value
        s2 = (s2 + (x.s2 * y.s3) % ASE.mod_value) % ASE.mod_value
        s2 = (s2 + (x.s3 * y.s2) % ASE.mod_value) % ASE.mod_value

        s3 = (x.s3 * y.s3) % ASE.mod_value
        s3 = (s3 + (x.s3 * y.s1) % ASE.mod_value) % ASE.mod_value
        s3 = (s3 + (x.s1 * y.s3) % ASE.mod_value) % ASE.mod_value

        return Shares(s1, s2, s3)
