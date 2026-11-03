import secrets
import random
from dataclasses import dataclass
from BuildingBlocks.ase import ASE, Shares
from EPWS.key import Key

class ThreePSS:
    
    n: int = 64
    mod_value: int = 2 ** n
    srnd = secrets.SystemRandom()

    @staticmethod
    def three_pss_add(x_shares: Shares, y_shares: Shares) -> Shares:
        s1 = (x_shares.s1 + y_shares.s1) % ThreePSS.mod_value
        s2 = (x_shares.s2 + y_shares.s2) % ThreePSS.mod_value
        s3 = (x_shares.s3 + y_shares.s3) % ThreePSS.mod_value

        s1 = (x_shares.s1 + y_shares.s1) % ThreePSS.mod_value
        s2 = (x_shares.s2 + y_shares.s2) % ThreePSS.mod_value
        s3 = (x_shares.s3 + y_shares.s3) % ThreePSS.mod_value
        return Shares(s1, s2, s3)

    @staticmethod
    def three_pss_add_int(x_shares: Shares, y: int) -> Shares:
        s1 = (x_shares.s1 + y) % ThreePSS.mod_value
        s1 = (x_shares.s1 + y) % ThreePSS.mod_value
        return Shares(s1, x_shares.s2, x_shares.s3)

    @staticmethod
    def three_pss_sub(x_shares: Shares, y_shares: Shares) -> Shares:
        s1 = (x_shares.s1 - y_shares.s1) % ThreePSS.mod_value
        s2 = (x_shares.s2 - y_shares.s2) % ThreePSS.mod_value
        s3 = (x_shares.s3 - y_shares.s3) % ThreePSS.mod_value

        s1 = (x_shares.s1 - y_shares.s1) % ThreePSS.mod_value
        s2 = (x_shares.s2 - y_shares.s2) % ThreePSS.mod_value
        s3 = (x_shares.s3 - y_shares.s3) % ThreePSS.mod_value
        return Shares(s1, s2, s3)

    @staticmethod
    def three_pss_sub_by_int(x: int, y_shares: Shares) -> Shares:
        s1 = (x - y_shares.s1) % ThreePSS.mod_value
        s1 = (x - y_shares.s1) % ThreePSS.mod_value
        s2 = (-y_shares.s2) % ThreePSS.mod_value
        s3 = (-y_shares.s3) % ThreePSS.mod_value
        return Shares(s1, s2, s3)

    @staticmethod
    def three_pss_scale_int(x_shares: Shares, y: int) -> Shares:
        s1 = (x_shares.s1 * y) % ThreePSS.mod_value
        s2 = (x_shares.s2 * y) % ThreePSS.mod_value
        s3 = (x_shares.s3 * y) % ThreePSS.mod_value

        s1 = (x_shares.s1 * y) % ThreePSS.mod_value
        s2 = (x_shares.s2 * y) % ThreePSS.mod_value
        s3 = (x_shares.s3 * y) % ThreePSS.mod_value
        return Shares(s1, s2, s3)

    @staticmethod
    def three_pss_mul(x_shares: Shares, y_shares: Shares, key: Key) -> Shares:
        s1 = (x_shares.s1 * y_shares.s1) % ThreePSS.mod_value
        s1 = (s1 + x_shares.s1 * y_shares.s2) % ThreePSS.mod_value
        s1 = (s1 + x_shares.s2 * y_shares.s1) % ThreePSS.mod_value

        s2 = (x_shares.s2 * y_shares.s2) % ThreePSS.mod_value
        s2 = (s2 + x_shares.s2 * y_shares.s3) % ThreePSS.mod_value
        s2 = (s2 + x_shares.s3 * y_shares.s2) % ThreePSS.mod_value

        s3 = (x_shares.s3 * y_shares.s3) % ThreePSS.mod_value
        s3 = (s3 + x_shares.s3 * y_shares.s1) % ThreePSS.mod_value
        s3 = (s3 + x_shares.s1 * y_shares.s3) % ThreePSS.mod_value

        sid = random.randint(0, 2**31 - 1)
        sid_bytes = str(sid).encode('utf-8')

        r = [ASE.hmac_sha256(key.pair_key[i], sid_bytes) for i in range(3)]
        s1_ply = (s1 + r[0] - r[2]) % ThreePSS.mod_value
        s2_ply = (s2 + r[1] - r[0]) % ThreePSS.mod_value
        s3_ply = (s3 + r[2] - r[1]) % ThreePSS.mod_value
        return Shares(s1_ply, s2_ply, s2_ply)
