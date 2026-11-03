import time
from .DataProcessor import DataProcessor
from .Encrypter import Encrypter


class MedicalCenters:
    def __init__(self, filepath, collectAttributes, SK):
        process = DataProcessor()
        
        self.originSet = process.readFile(filepath)
        numOfins = len(self.originSet)
        self.extractSet = process.vectorExtract(self.originSet, 0, 8, numOfins)
        label = process.getLable(self.originSet, 9, 9, numOfins)
        self.extendSet = process.vectorExtend(self.extractSet)
        
        training_Encryption1 = time.time() * 1000  # milliseconds
        
        self.e = process.getE(collectAttributes)
        self.NX = process.getNX(self.extendSet)
        self.NY = process.getNY(label)
        self.NZ = process.getNZ(self.extendSet, label)
        self.ND = process.getND(self.NY, self.e)
        self.NL = process.getNL(numOfins, self.e)
        
        # Convert to BigInteger (Python int is already arbitrary precision)
        # 转换为大整数（Python int已经是任意精度）
        self.BNX = process.getBigInteger(self.NX)
        self.BNY = process.getBigInteger(self.NY)
        self.BNZ = process.getBigInteger(self.NZ)
        self.BND = process.getBigInteger(self.ND)
        self.BNL = process.getBigInteger(self.NL)
        
        # Encrypt statistics
        # 加密统计信息
        self.ENX = Encrypter.Encryption(self.BNX, SK)
        self.ENY = Encrypter.Encryption(self.BNY, SK)
        self.ENZ = Encrypter.Encryption(self.BNZ, SK)
        self.END = Encrypter.Encryption(self.BND, SK)
        self.ENL = Encrypter.Encryption(self.BNL, SK)
        
        print("****************************Local Training Data******************************")
        print(f"Plaintext: NX is {self.BNX}")
        print(f"Plaintext: NY is {self.BNY}")
        print(f"Plaintext: NZ is {self.BNZ}")
        print(f"Plaintext: ND is {self.BND}")
        print(f"Plaintext: NL is {self.BNL}")
        print(" ")
        
        print("*************************Ciphertext Local Training Data***************************")
        print(f"Ciphertext: ENX is {self.ENX}")
        print(f"Ciphertext: ENY is {self.ENY}")
        print(f"Ciphertext: ENZ is {self.ENZ}")
        print(f"Ciphertext: END is {self.END}")
        print(f"Ciphertext: ENL is {self.ENL}")
        print(" ")
        
        training_Encryption2 = time.time() * 1000
        self.training_Encryption = training_Encryption2 - training_Encryption1
        
        # Calculate communication overhead
        # 计算通信开销
        self.CENX = process.getCommunicationOne(self.ENX)
        self.CENY = process.getCommunicationOne(self.ENY)
        self.CENZ = process.getCommunicationOne(self.ENZ)
        self.CEND = process.getCommunicationOne(self.END)
        self.CENL = process.getCommunicationOne(self.ENL)

