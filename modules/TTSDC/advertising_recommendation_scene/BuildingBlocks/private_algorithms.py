import random
import secrets
from typing import List, Sequence, Tuple
from BuildingBlocks.ase import Shares, VecShares, ASE
from EPWS.key import Key
from BuildingBlocks.util import Util

class PrivateAlgorithms:
    @staticmethod
    def pivg(num_records: int, key: Key) -> VecShares:
        v = [0] * num_records
        loc = abs(random.randint(0, 2**31 - 1) % num_records)
        v[loc] = 1

        v_vecshares = ASE.share_list(v)

        r = Util.gen_randnum(key.pair_key[1])
        r = Util.gen_randnum(key.pair_key[1])

        r2 = Util.gen_randnum_vec(num_records, key.pair_key[1])
        r2 = Util.gen_randnum_vec(num_records, key.pair_key[1])
        r3 = Util.gen_randnum_vec(num_records, key.pair_key[1])
        r3 = Util.gen_randnum_vec(num_records, key.pair_key[1])

        r1 = Util.big_integer_add(r2, r3, ASE.mod_value)
        r1 = Util.negative_big_vec(r1, ASE.mod_value)

        v1plyply = Util.big_integer_add(v_vecshares.s1_vec, r1, ASE.mod_value)
        v2plyply = Util.big_integer_add(v_vecshares.s2_vec, r2, ASE.mod_value)
        v3plyply = Util.big_integer_add(v_vecshares.s3_vec, r3, ASE.mod_value)

        vply_vecshares = VecShares(v1plyply, v2plyply, v3plyply)
        return vply_vecshares

    @staticmethod
    def purdg(delta: int, key: Key) -> Shares:
        bit_length = delta

        r1 = [0] * bit_length
        r1_shares = [None] * bit_length
        for i in range(bit_length):
            tmp = abs(random.randint(0, 2**31 - 1) % 2)
            r1[i] = tmp
            r1_shares[i] = ASE.share_int(tmp)

        r2 = [0] * bit_length
        r2_shares = [None] * bit_length
        for i in range(bit_length):
            tmp = abs(random.randint(0, 2**31 - 1) % 2)
            r2[i] = tmp
            r2_shares[i] = ASE.share_int(tmp)

        tmp1 = ASE.ase_add(r1_shares[0], r2_shares[0])
        tmp2 = ASE.ase_mul(r1_shares[0], r2_shares[0], key)
        tmp2 = ASE.ase_scale_int(tmp2, -2)
        tmp2 = ASE.ase_add(tmp1, tmp2)
        z = ASE.ase_scale_int(tmp2, 1 << 0)

        for i in range(1, bit_length):
            tmp1 = ASE.ase_add(r1_shares[i], r2_shares[i])
            tmp2 = ASE.ase_mul(r1_shares[i], r2_shares[i], key)
            tmp2 = ASE.ase_scale_int(tmp2, -2)
            tmp2 = ASE.ase_add(tmp1, tmp2)
            tmp2 = ASE.ase_scale_int(tmp2, 1 << i)
            z = ASE.ase_add(z, tmp2)

        return z

    @staticmethod
    def prdg(key: Key) -> Shares:
        r1 = secrets.randbits(ASE.n) % ASE.mod_value
        r2 = secrets.randbits(ASE.n) % ASE.mod_value
        r3 = secrets.randbits(ASE.n) % ASE.mod_value
        return Shares(r1, r2, r3)

    @staticmethod
    def pbdc(x: List[Shares], y: List[Shares], key: Key) -> bool:
        beta = len(x)
        w = [None] * beta

        for i in range(beta):
            tmp1 = ASE.ase_add(x[i], y[i])
            tmp2 = ASE.ase_mul(x[i], y[i], key)
            tmp2 = ASE.ase_scale_int(tmp2, -2)
            w[i] = ASE.ase_add(tmp1, tmp2)

        sum_w = [None] * (beta - 1) if beta >= 2 else []
        tmp = w[beta - 1]
        for j in range(beta - 2, -1, -1):
            sum_w[j] = tmp
            if j > 0:
                tmp = ASE.ase_add(tmp, w[j])

        tmp1 = ASE.ase_sub(x[0], y[0])
        tmp1 = ASE.ase_add(tmp1, ASE.share_int(1))
        product_c = ASE.ase_add(tmp1, sum_w[0] if sum_w else ASE.share_int(0))

        # multiply for each bit
        for i in range(beta):
            tmp1 = ASE.ase_sub(x[i], y[i])
            tmp1 = ASE.ase_add(tmp1, ASE.share_int(1))
            if i != beta - 1:
                tmp1 = ASE.ase_add(tmp1, sum_w[i])
            product_c = ASE.ase_mul(tmp1, product_c, key)

        r_shares = PrivateAlgorithms.prdg(key)
        r_shares = PrivateAlgorithms.prdg(key)
        r_shares = ASE.ase_mul(r_shares, product_c, key)

        r = ASE.recover(r_shares)
        return r == 0

    @staticmethod
    def pbdc_prct(x: List[Shares], y: List[Shares], key: Key) -> Shares:
        beta = len(x)
        w = [None] * beta

        for i in range(beta):
            tmp1 = ASE.ase_add(x[i], y[i])
            tmp2 = ASE.ase_mul(x[i], y[i], key)
            tmp2 = ASE.ase_scale_int(tmp2, -2)
            w[i] = ASE.ase_add(tmp1, tmp2)

        sum_w = [None] * (beta - 1) if beta >= 2 else []
        tmp = w[beta - 1]
        for j in range(beta - 2, -1, -1):
            sum_w[j] = tmp
            if j > 0:
                tmp = ASE.ase_add(tmp, w[j])

        tmp1 = ASE.ase_sub(x[0], y[0])
        tmp1 = ASE.ase_add(tmp1, ASE.share_int(1))
        product_c = ASE.ase_add(tmp1, sum_w[0] if sum_w else ASE.share_int(0))

        for i in range(beta):
            tmp1 = ASE.ase_sub(x[i], y[i])
            tmp1 = ASE.ase_add(tmp1, ASE.share_int(1))
            if i != beta - 1:
                tmp1 = ASE.ase_add(tmp1, sum_w[i])
            product_c = ASE.ase_mul(tmp1, product_c, key)

        return product_c

    @staticmethod
    def prct(l: List[Shares], u: List[Shares], l_node: List[Shares], u_node: List[Shares], key: Key) -> bool:
        c1 = PrivateAlgorithms.pbdc_prct(l_node, l, key)
        c2 = PrivateAlgorithms.pbdc_prct(u, u_node, key)

        r_shares = PrivateAlgorithms.prdg(key)
        r_shares = ASE.ase_mul(r_shares, c1, key)
        r_shares = ASE.ase_mul(r_shares, c2, key)

        r = ASE.recover(r_shares)
        return r != 0

    @staticmethod
    def padc(x_shares: Shares, eta: int) -> bool:
        new_x_shares = PrivateAlgorithms.re_share(x_shares, eta)

        r = random.random()
        alpha = random.random()
        if random.randint(0, 1) == 0:
            alpha = -alpha

        x1 = float(new_x_shares.s1)
        z1 = x1 - r

        z3 = (z1 + float(new_x_shares.s3)) * alpha

        z2 = (float(new_x_shares.s2) - r) * alpha

        z = z2 + z3

        gamma1 = 1 if z < 0 else 0
        gamma3 = 1 if alpha < 0 else 0

        gamma = gamma1 + gamma3 - 2 * gamma1 * gamma3
        return gamma == 1

    @staticmethod
    def padc_alias_sampling(x_shares: Shares, eta: int) -> Tuple[Shares, Shares]:
        new_x_shares = PrivateAlgorithms.re_share(x_shares, eta)

        r = random.random()
        alpha = random.random()
        if random.randint(0, 1) == 0:
            alpha = -alpha

        x1 = float(new_x_shares.s1)
        z1 = x1 - r
        z3 = (z1 + float(new_x_shares.s3)) * alpha
        z2 = (float(new_x_shares.s2) - r) * alpha
        z = z2 + z3

        gamma1 = 1 if z < 0 else 0
        gamma3 = 1 if alpha < 0 else 0

        gamma1_share = Shares(gamma1, 0, 0)
        gamma3_share = Shares(0, 0, gamma3)
        return [gamma1_share, gamma3_share]

    @staticmethod
    def re_share(x: Shares, eta: int) -> Shares:
        u1 = secrets.randbits(eta) % ASE.mod_value
        u2 = secrets.randbits(eta) % ASE.mod_value

        x1_minus_u1 = (x.s1 - u1) % ASE.mod_value
        x2_minus_u2 = (x.s2 - u2) % ASE.mod_value

        x3 = (x.s3 + x1_minus_u1 + x2_minus_u2) % ASE.mod_value
        return Shares(u1, u2, x3)

    @staticmethod
    def to_bin_and_enc(x: int, beta: int) -> List[Shares]:
        x_binary = Util.int_to_binary(x, beta)
        x_binary_shares = [ASE.share_int(bit) for bit in x_binary]
        return x_binary_shares

    @staticmethod
    def to_bin_and_enc_batch(x_list: List[int], beta: int) -> List[List[Shares]]:
        x_list_shares = []
        for v in x_list:
            x_list_shares.append(PrivateAlgorithms.to_bin_and_enc(v, beta))
        return x_list_shares

if __name__ == "__main__":
    example_key = Key([b'k0', b'k1', b'k2'])

    vvec = PrivateAlgorithms.pivg(5, example_key)
    print("pivg:", vvec)

    z = PrivateAlgorithms.purdg(8, example_key)
    print("purdg z (shares):", z)

    r = PrivateAlgorithms.prdg(example_key)
    print("prdg:", r)

    bits_shares = PrivateAlgorithms.to_bin_and_enc(13, 6)
    print("to_bin_and_enc(13):", bits_shares)
