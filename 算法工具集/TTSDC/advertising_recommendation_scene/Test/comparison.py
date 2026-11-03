import random
import time
from decimal import Decimal
from typing import List
from BuildingBlocks.ase import ASE
from BuildingBlocks.three_pss import ThreePSS
from EPWS.key import Key
from heu import phe

class Comparison:
    kit = phe.setup(phe.SchemaType.ZPaillier, 2048)
    encryptor = kit.encryptor()
    evaluator = kit.evaluator()
    decryptor = kit.decryptor()
    key = None

    @staticmethod
    def enc_comparison():
        time_ase = 0.0
        time_tpss = 0.0
        time_paillier = 0.0

        rnd = random.Random()
        cycle = 1000

        data1 = [0] * cycle
        data2 = [0] * cycle

        for i in range(cycle):
            m1 = rnd.randint(-1000, 1000)
            data1[i] = abs(m1)

            m2 = rnd.randint(-1000, 1000)
            data2[i] = abs(m2)

        # ASE performance
        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ASE.share_int(data1[i])
        end = time.perf_counter_ns()
        time_ase = (end - start) / 1e9  # 秒
        time_tpss = time_ase

        # Paillier performance
        start = time.perf_counter_ns()
        for i in range(cycle):
            c = Comparison.encryptor.encrypt_raw(data1[i])
        end = time.perf_counter_ns()
        time_paillier = (end - start) / 1e9

        print(f"time_ase: {time_ase:.6f}")
        print(f"time_tpss: {time_tpss:.6f}")
        print(f"time_paillier: {time_paillier:.6f}")

    @staticmethod
    def add_comparison():
        time_ase = 0.0
        time_tpss = 0.0
        time_paillier = 0.0

        rnd = random.Random()
        cycle = 1000

        data1_share = [None] * cycle
        data2_share = [None] * cycle
        c1 = [None] * cycle
        c2 = [None] * cycle

        for i in range(cycle):
            m1 = rnd.randint(-1000, 1000)
            data1_share[i] = ASE.share_int(m1)
            c1[i] = Comparison.encryptor.encrypt_raw(m1)

            m2 = rnd.randint(-1000, 1000)
            data2_share[i] = ASE.share_int(m2)
            c2[i] = Comparison.encryptor.encrypt_raw(m2)

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ASE.ase_add(data1_share[i], data2_share[i])
        end = time.perf_counter_ns()
        time_ase = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ThreePSS.three_pss_add(data1_share[i], data2_share[i])
        end = time.perf_counter_ns()
        time_tpss = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            c = Comparison.evaluator.add(c1[i], c2[i])
        end = time.perf_counter_ns()
        time_paillier = (end - start) / 1e9

        print(f"time_ase: {time_ase:.6f}")
        print(f"time_tpss: {time_tpss:.6f}")
        print(f"time_paillier: {time_paillier:.6f}")

    @staticmethod
    def scale_int_comparison():
        time_ase = 0.0
        time_tpss = 0.0
        time_paillier = 0.0

        rnd = random.Random()
        cycle = 1000

        data1_share = [None] * cycle
        c1 = [None] * cycle
        data2 = [0] * cycle

        for i in range(cycle):
            m1 = rnd.randint(-1000, 1000)
            data1_share[i] = ASE.share_int(m1)
            c1[i] = Comparison.encryptor.encrypt_raw(m1)

            m2 = rnd.randint(-1000, 1000)
            data2[i] = m2

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ASE.ase_scale_int(data1_share[i], data2[i])
        end = time.perf_counter_ns()
        time_ase = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ThreePSS.three_pss_scale_int(data1_share[i], data2[i])
        end = time.perf_counter_ns()
        time_tpss = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            c = Comparison.evaluator.mul(c1[i], data2[i])
        end = time.perf_counter_ns()
        time_paillier = (end - start) / 1e9

        print(f"time_ase: {time_ase:.6f}")
        print(f"time_tpss: {time_tpss:.6f}")
        print(f"time_paillier: {time_paillier:.6f}")

    @staticmethod
    def paillier_cipher_mul(c1: phe.Ciphertext, c2: phe.Ciphertext) -> phe.Ciphertext:
        rnd = random.SystemRandom()
        r1 = rnd.getrandbits(63)
        r2 = rnd.getrandbits(63)

        cr1 = Comparison.encryptor.encrypt_raw(r1)
        cr2 = Comparison.encryptor.encrypt_raw(r2)
        cm1pr1 = Comparison.evaluator.add(c1, cr1)
        cm2pr2 = Comparison.evaluator.add(c2, cr2)

        m1pr1 = Comparison.decryptor.decrypt_raw(cm1pr1)
        m2pr2 = Comparison.decryptor.decrypt_raw(cm2pr2)

        m1pr1_mul_m2pr2 = m1pr1 * m2pr2
        cr1pr1_mul_m2pr2 = Comparison.encryptor.encrypt_raw(m1pr1_mul_m2pr2)

        cm1r2 = Comparison.evaluator.mul(c1, r2)
        cm2r1 = Comparison.evaluator.mul(c2, r1)

        r1r2 = r1 * r2
        cr1r2 = Comparison.encryptor.encrypt_raw(r1r2)
        cm1m2 = Comparison.evaluator.add(cr1pr1_mul_m2pr2, Comparison.evaluator.mul(cm1r2, -1))
        cm1m2 = Comparison.evaluator.add(cm1m2, Comparison.evaluator.mul(cm2r1, -1))
        cm1m2 = Comparison.evaluator.add(cm1m2, Comparison.evaluator.mul(cr1r2, -1))

        return cm1m2
    
    @staticmethod
    def mul_comparison():
        time_ase = 0.0
        time_ase_without_noise = 0.0
        time_tpss = 0.0
        time_paillier = 0.0

        rnd = random.Random()
        cycle = 1000

        data1_share = [None] * cycle
        data2_share = [None] * cycle
        c1 = [None] * cycle
        c2 = [None] * cycle

        for i in range(cycle):
            m1 = abs(rnd.randint(-1000, 1000))
            m2 = abs(rnd.randint(-1000, 1000))
            data1_share[i] = ASE.share_int(m1)
            c1[i] = Comparison.encryptor.encrypt_raw(m1)
            data2_share[i] = ASE.share_int(m2)
            c2[i] = Comparison.encryptor.encrypt_raw(m2)

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ASE.ase_mul(data1_share[i], data2_share[i], Comparison.key)
        end = time.perf_counter_ns()
        time_ase = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ASE.ase_mul_without_random(data1_share[i], data2_share[i], Comparison.key)
        end = time.perf_counter_ns()
        time_ase_without_noise = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            xShares = ThreePSS.three_pss_mul(data1_share[i], data2_share[i], Comparison.key)
        end = time.perf_counter_ns()
        time_tpss = (end - start) / 1e9

        start = time.perf_counter_ns()
        for i in range(cycle):
            c = Comparison.paillier_cipher_mul(c1[i], c2[i])
        end = time.perf_counter_ns()
        time_paillier = (end - start) / 1e9

        print(f"time_ase: {time_ase:.6f}")
        print(f"time_ase_without_noise: {time_ase_without_noise:.6f}")
        print(f"time_tpss: {time_tpss:.6f}")
        print(f"time_paillier: {time_paillier:.6f}")

    @staticmethod
    def dec_comparison():
        time_ase = 0.0
        time_tpss = 0.0
        time_paillier = 0.0

        rnd = random.Random()
        cycle = 1000
        data1_share = [None] * cycle
        c1 = [None] * cycle

        for i in range(cycle):
            m1 = abs(rnd.randint(-1000, 1000))
            data1_share[i] = ASE.share_int(m1)
            c1[i] = Comparison.encryptor.encrypt_raw(m1)

        start = time.perf_counter_ns()
        for i in range(cycle):
            x = ASE.recover(data1_share[i])
            pass
        end = time.perf_counter_ns()
        time_ase = (end - start) / 1e9
        time_tpss = time_ase

        start = time.perf_counter_ns()
        for i in range(cycle):
            c = Comparison.decryptor.decrypt_raw(c1[i])
            pass
        end = time.perf_counter_ns()
        time_paillier = (end - start) / 1e9

        print(f"time_ase: {time_ase:.6f}")
        print(f"time_tpss: {time_tpss:.6f}")
        print(f"time_paillier: {time_paillier:.6f}")

    @staticmethod
    def main():
        beta = 10
        delta = 10
        eta = 30
        Comparison.key = Key.init_key(beta, delta, eta)

        print("1. Computational Cost of Encryption:")
        Comparison.enc_comparison()

        print("2. Computational Cost of Addition:")
        Comparison.add_comparison()

        print("3. Computational Cost of Scalar Product:")
        Comparison.scale_int_comparison()

        print("4. Computational Cost of multiplication:")
        Comparison.mul_comparison()

        print("5. Computational Cost of decryption:")
        Comparison.dec_comparison()


if __name__ == "__main__":
    Comparison.main()
