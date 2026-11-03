import random


class Query:
    CERTAINTY = 80
    k1 = 512
    k2 = 200
    k3 = 32
    k4 = 32
    
    alpha = None
    p = None
    s = None
    sinverse = None
    alphasquare = None
    
    def __init__(self):
        # Generate alpha - a prime with k2 bits
        # 生成alpha - 一个k2位的素数
        self.alpha = self._generate_prime(self.k2, self.CERTAINTY)
        
        # Generate p - a prime with k1 bits
        # 生成p - 一个k1位的素数
        self.p = self._generate_prime(self.k1, self.CERTAINTY)
        
        # Generate s - a random number from Zp* (coprime with p)
        # 生成s - 一个来自Zp*的随机数（与p互质）
        self.s = self.getRandomFromZp()
        self.sinverse = pow(self.s, -1, self.p)
        self.alphasquare = self.alpha * self.alpha
        
        # Set class variables
        # 设置类变量
        Query.alpha = self.alpha
        Query.p = self.p
        Query.s = self.s
        Query.sinverse = self.sinverse
        Query.alphasquare = self.alphasquare
    
    def _is_prime(self, n, k=64):
        """Miller-Rabin primality test"""
        # Miller-Rabin素数测试
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def _generate_prime(self, bits, certainty):
        """Generate a prime number with specified bit length"""
        # 生成指定位长度的素数
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << (bits - 1)) | 1
            if self._is_prime(candidate, certainty):
                return candidate
    
    def getRandomFromZp(self):
        """Get a random number from Zp* (coprime with p)"""
        # 从Zp*获取随机数（与p互质）
        import math
        modLength = self.p.bit_length()
        while True:
            r = random.getrandbits(modLength)
            if r < self.p and math.gcd(r, self.p) == 1:
                return r
    
    @staticmethod
    def getC(x):
        """Encrypt user query vector"""
        # 加密用户查询向量
        C = []
        xx = list(x) + [0, 0]  # Add two zeros at the end
        # 在末尾添加两个零
        
        for i in range(len(xx)):
            # C[i] = s * (xx[i] * alpha + random) mod p
            # C[i] = s * (xx[i] * alpha + random) mod p
            random_term = random.getrandbits(Query.k3)
            inner = xx[i] * Query.alpha + random_term
            C_i = (Query.s * inner) % Query.p
            C.append(C_i)
        
        return C
    
    @staticmethod
    def getD(BLI, BLII, C):
        """Compute encrypted inner product"""
        # 计算加密的内积
        D = []
        for i in range(len(BLI)):
            D_row = [None, None]
            D_row[0] = Query.getInnerProduct(C, BLI[i])
            D_row[1] = Query.getInnerProduct(C, BLII[i])
            D.append(D_row)
        return D
    
    @staticmethod
    def getInnerProduct(C, y):
        """Compute inner product in encrypted form"""
        # 以加密形式计算内积
        D = 0
        yy = list(y) + [0, 0]  # Add two zeros at the end
        # 在末尾添加两个零
        
        for i in range(len(yy)):
            if yy[i] == 0:
                random_term = random.getrandbits(Query.k4)
                D = (D + random_term * C[i]) % Query.p
            else:
                D = (D + yy[i] * Query.alpha * C[i]) % Query.p
        
        return D
    
    @staticmethod
    def getR(D):
        """Decrypt the prediction result"""
        # 解密预测结果
        E = (Query.sinverse * D) % Query.p
        E_mod_alpha2 = E % Query.alphasquare
        R = (E - E_mod_alpha2) // Query.alphasquare
        return R

