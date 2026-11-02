"""
HEU ZPaillier 加密器
使用 HEU (Homomorphic Encryption Unit) 的 ZPaillier 算法替代原生 Paillier 实现
适用于整数数据的同态加密
"""

from heu import phe


class Encrypter:
    """
    使用 HEU ZPaillier 的加密器
    所有医疗中心共享同一个公钥，只有 EhealthcareProvider 拥有私钥
    """
    # 类变量（静态变量）
    kit = None
    encryptor = None
    evaluator = None
    decryptor = None
    bitLength = None
    
    # 为了向后兼容，保留 SK 属性（但不实际使用）
    SK = None
    
    def __init__(self, bitLengthVal, certainty, nuOfParts):
        """
        初始化 HEU ZPaillier 加密器
        
        Args:
            bitLengthVal: 密钥长度（位）
            certainty: 素数测试的确定性（HEU 内部处理）
            nuOfParts: 医疗中心数量（保留用于兼容性，但不影响密钥生成）
        """
        self.bitLength = bitLengthVal
        
        # 初始化 HEU ZPaillier
        # 所有医疗中心使用同一个 kit（共享公钥）
        Encrypter.kit = phe.setup(phe.SchemaType.ZPaillier, bitLengthVal)
        
        # 创建加密器、评估器和解密器
        Encrypter.encryptor = Encrypter.kit.encryptor()
        Encrypter.evaluator = Encrypter.kit.evaluator()
        Encrypter.decryptor = Encrypter.kit.decryptor()
        
        # 为了向后兼容，创建 SK 数组（实际不使用）
        Encrypter.SK = [None] * nuOfParts
        for i in range(nuOfParts):
            Encrypter.SK[i] = i  # 只用于标识，不用于加密
        
        print("****************************Encryption Algorithm Parameters******************************")
        print(f"Parameters: Using HEU ZPaillier (key size: {bitLengthVal} bits)")
        print(f"Parameters: All medical centers share the same public key")
        print(f"Parameters: Only EhealthcareProvider has the secret key for decryption")
        print(" ")
    
    @staticmethod
    def Encryption(m, SK=None):
        """
        加密整数数组
        
        Args:
            m: 要加密的整数数组（Python list of int）
            SK: 保留参数（向后兼容），但实际不使用
        
        Returns:
            密文数组（HEU Ciphertext 对象列表）
        """
        if Encrypter.encryptor is None:
            raise RuntimeError("Encrypter not initialized. Call __init__ first.")
        
        c = []
        for i in range(len(m)):
            # 使用 HEU ZPaillier 加密
            c_i = Encrypter.encryptor.encrypt_raw(m[i])
            c.append(c_i)
        
        return c
    
    @staticmethod
    def Decryption(c):
        """
        解密密文数组
        
        Args:
            c: 密文数组（HEU Ciphertext 对象列表）
        
        Returns:
            解密后的整数数组
        """
        if Encrypter.decryptor is None:
            raise RuntimeError("Encrypter not initialized. Call __init__ first.")
        
        m = []
        for i in range(len(c)):
            # 使用 HEU ZPaillier 解密
            m_i = Encrypter.decryptor.decrypt_raw(c[i])
            m.append(m_i)
        
        return m
    
    @staticmethod
    def add_ciphertexts(c1, c2):
        """
        同态加法：将两个密文相加
        
        Args:
            c1: 第一个密文（HEU Ciphertext 对象）
            c2: 第二个密文（HEU Ciphertext 对象）
        
        Returns:
            相加后的密文
        """
        if Encrypter.evaluator is None:
            raise RuntimeError("Encrypter not initialized. Call __init__ first.")
        
        return Encrypter.evaluator.add(c1, c2)
