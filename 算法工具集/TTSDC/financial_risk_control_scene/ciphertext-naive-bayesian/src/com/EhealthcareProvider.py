import time
from .DataProcessor import DataProcessor
from .Encrypter import Encrypter
from .Query import Query


class EhealthcareProvider:
    def __init__(self, MCs, u):
        processEP = DataProcessor()
        
        aggregationTime1 = time.time() * 1000  # milliseconds
        
        # Aggregate encrypted statistics
        # 聚合加密统计信息
        self.ESNX = processEP.getESNX(MCs)
        self.ESNY = processEP.getESNY(MCs)
        self.ESNZ = processEP.getESNZ(MCs)
        self.ESND = processEP.getESND(MCs)
        self.ESNL = processEP.getESNL(MCs)
        
        # Decrypt aggregated statistics
        # 解密聚合的统计信息
        self.DSNX = Encrypter.Decryption(self.ESNX)
        self.DSNY = Encrypter.Decryption(self.ESNY)
        self.DSNZ = Encrypter.Decryption(self.ESNZ)
        self.DSND = Encrypter.Decryption(self.ESND)
        self.DSNL = Encrypter.Decryption(self.ESNL)
        
        aggregationTime2 = time.time() * 1000
        self.aggregationTime = aggregationTime2 - aggregationTime1
        
        # Convert to int arrays
        # 转换为整数数组
        self.SNX = processEP.getInt(self.DSNX)
        self.SNY = processEP.getInt(self.DSNY)
        self.SNZ = processEP.getInt(self.DSNZ)
        self.SND = processEP.getInt(self.DSND)
        self.SNL = processEP.getInt(self.DSNL)
        
        # Calculate probabilities
        # 计算概率
        self.X_1_Y_1 = processEP.getX_1_Y_1(self.SNZ, self.SND)
        self.X_1_Y_0 = processEP.getX_1_Y_0(self.SNX, self.SNZ, self.SND, self.SNL)
        self.X_0_Y_1 = processEP.getX_0_Y_1(self.X_1_Y_1)
        self.X_0_Y_0 = processEP.getX_0_Y_0(self.X_1_Y_0)
        self.Y_1 = processEP.getY_1(self.SNY, self.SNL)
        self.Y_0 = processEP.getY_0(self.Y_1)
        
        # Compute log probabilities
        # 计算对数概率
        self.L_X_1_Y_1 = processEP.getLog(self.X_1_Y_1)
        self.L_X_1_Y_0 = processEP.getLog(self.X_1_Y_0)
        self.L_X_0_Y_1 = processEP.getLog(self.X_0_Y_1)
        self.L_X_0_Y_0 = processEP.getLog(self.X_0_Y_0)
        self.L_Y_1 = processEP.getLog(self.Y_1)
        self.L_Y_0 = processEP.getLog(self.Y_0)
        
        # Generate prediction vectors
        # 生成预测向量
        self.LI = processEP.getPredictionvectors(self.L_X_1_Y_1, self.L_X_0_Y_1, self.L_Y_1)
        self.LII = processEP.getPredictionvectors(self.L_X_1_Y_0, self.L_X_0_Y_0, self.L_Y_0)
        
        # Convert to BigInteger arrays for encrypted query processing
        # 转换为大整数数组用于加密查询处理
        self.BLI = []
        self.BLII = []
        for i in range(len(self.LI)):
            self.BLI.append(processEP.getBigInteger(self.LI[i]))
            self.BLII.append(processEP.getBigInteger(self.LII[i]))
        
        # Process encrypted queries
        # 处理加密查询
        responseTime1 = time.time_ns()  # nanoseconds
        self.D = []
        for i in range(len(u.x)):
            D_row = Query.getD(self.BLI, self.BLII, u.C[i])
            self.D.append(D_row)
        
        print(f"Response: ciphertext query response is ({self.D[0]})")
        print(" ")
        responseTime2 = time.time_ns()
        self.responseTime = responseTime2 - responseTime1
        
        self.communicationEP = processEP.getCommunicationTheree(self.D)

