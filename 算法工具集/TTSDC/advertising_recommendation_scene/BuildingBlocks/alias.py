from typing import List
from collections import deque
from math import pow
from EPWS.key import Key
from BuildingBlocks.ase import ASE, Shares, VecShares
from BuildingBlocks.private_algorithms import PrivateAlgorithms
from BuildingBlocks.alias_class import AliasPlain, AliasCipher

class Alias:
    @staticmethod
    def construct_alias(x_dataset: List[int], w_dataset: List[int]) -> List[AliasPlain]:
        alias_plain = []
        wSum = sum(w_dataset)
        n = len(x_dataset)

        nlXData = deque()
        nlWData = deque()
        gXData = deque()
        gWData = deque()

        for x, w in zip(x_dataset, w_dataset):
            if w * n <= wSum:
                nlXData.append(x)
                nlWData.append(n * w)
            else:
                gXData.append(x)
                gWData.append(n * w)

        while nlXData and gXData:
            ele1 = nlXData.popleft()
            wgt1 = nlWData.popleft()

            if wgt1 < wSum:
                ele2 = gXData.popleft()
                wgt2 = wSum - wgt1
                wgt2Ply = gWData.popleft() - wgt2

                if wgt2Ply <= wSum:
                    nlXData.append(ele2)
                    nlWData.append(wgt2Ply)
                else:
                    gXData.append(ele2)
                    gWData.append(wgt2Ply)
            else:
                ele2 = ele1
                wgt2 = 0

            alias_plain.append(AliasPlain(ele1, wgt1, ele2, wgt2))

        while nlXData:
            ele1 = nlXData.popleft()
            wgt1 = nlWData.popleft()
            alias_plain.append(AliasPlain(ele1, wgt1, ele1, 0))

        return alias_plain

    @staticmethod
    def alias_enc(alias_plain: List[AliasPlain]) -> List[AliasCipher]:
        alias_ciphers = []
        for a in alias_plain:
            ele1_shares = ASE.share_int(a.ele1)
            wgt1_shares = ASE.share_int(a.wgt1)
            ele2_shares = ASE.share_int(a.ele2)
            wgt2_shares = ASE.share_int(a.wgt2)
            alias_ciphers.append(AliasCipher(ele1_shares, wgt1_shares, ele2_shares, wgt2_shares))
        return alias_ciphers

    @staticmethod
    def alias_sampling(alias_ciphers: List[AliasCipher], key: Key, delta: int, eta: int) -> Shares:
        n = len(alias_ciphers)
        bitLength = delta
        vec_shares = PrivateAlgorithms.pivg(n, key)

        ele1_shares = ASE.share_int(0)
        wgt1_shares = ASE.share_int(0)
        ele2_shares = ASE.share_int(0)
        wgt2_shares = ASE.share_int(0)

        for i in range(n):
            vec_share = Shares(vec_shares.s1_vec[i], vec_shares.s2_vec[i], vec_shares.s3_vec[i])
            ele1_shares = ASE.ase_add(ele1_shares, ASE.ase_mul(vec_share, alias_ciphers[i].ele1_shares, key))
            wgt1_shares = ASE.ase_add(wgt1_shares, ASE.ase_mul(vec_share, alias_ciphers[i].wgt1_shares, key))
            ele2_shares = ASE.ase_add(ele2_shares, ASE.ase_mul(vec_share, alias_ciphers[i].ele2_shares, key))
            wgt2_shares = ASE.ase_add(wgt2_shares, ASE.ase_mul(vec_share, alias_ciphers[i].wgt2_shares, key))

        r_shares = PrivateAlgorithms.purdg(bitLength, key)
        wgt_shares = ASE.ase_add(wgt1_shares, wgt2_shares)
        z1_shares = ASE.ase_mul(r_shares, wgt_shares, key)
        z2_shares = ASE.ase_scale_int(wgt1_shares, pow(2, bitLength))
        z_shares = ASE.ase_sub(z2_shares, z1_shares)

        gamma_shares = PrivateAlgorithms.padc_alias_sampling(z_shares, eta)
        gamma1_add_gamma3 = ASE.ase_add(gamma_shares[0], gamma_shares[1])
        gamma1_mul_gamma3 = ASE.ase_mul(gamma_shares[0], gamma_shares[1], key)
        gamma1_mul_gamma3 = ASE.ase_scale_int(gamma1_mul_gamma3, -2)
        gamma1_or_gamma3 = ASE.ase_add(gamma1_add_gamma3, gamma1_mul_gamma3)

        tmp1 = ASE.ase_mul(alias_ciphers[0].ele1_shares, gamma1_or_gamma3, key)
        tmp2 = ASE.ase_sub_by_int(1, gamma1_or_gamma3)
        tmp2 = ASE.ase_mul(tmp2, alias_ciphers[0].ele2_shares, key)
        tmp1 = ASE.ase_add(tmp1, tmp2)

        return tmp1


if __name__ == "__main__":
    from BuildingBlocks.util import Util
    alias = Alias()
    n = 20
    max_val = 100
    x_dataset = Util.gen_rand_list(n, max_val)
    w_dataset = Util.gen_rand_list(n, max_val)
    Util.print_two_list(x_dataset, w_dataset)

    aliasPlain = Alias.construct_alias(x_dataset, w_dataset)
    Util.print_alias(aliasPlain)