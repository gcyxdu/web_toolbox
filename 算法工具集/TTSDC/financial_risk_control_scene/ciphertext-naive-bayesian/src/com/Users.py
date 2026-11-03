import time
from .DataProcessor import DataProcessor
from .Query import Query


class Users:
    def __init__(self, filepath):
        processU = DataProcessor()
        
        self.sypVector = processU.readFile(filepath)
        self.extractsymptom = processU.vectorExtract(self.sypVector, 0, 8, 200)
        self.sypLabels = processU.getLable(self.sypVector, 9, 9, 200)
        self.extVector = processU.vectorExtend(self.extractsymptom)
        self.paddingVector = processU.getUPaddingVector(self.extVector)
        
        # Convert to BigInteger arrays
        # 转换为大整数数组
        self.x = []
        for i in range(len(self.paddingVector)):
            self.x.append(processU.getBigInteger(self.paddingVector[i]))
        
        # Encrypt queries
        # 加密查询
        generateRequestTime1 = time.time_ns()  # nanoseconds
        self.C = []
        for i in range(len(self.x)):
            C_i = Query.getC(self.x[i])
            self.C.append(C_i)
        generateRequestTime2 = time.time_ns()
        self.generateRequestTime = generateRequestTime2 - generateRequestTime1
        
        print("************************Query**************************")
        print(f"Request: attribute vector is {self.extractsymptom[0]}")
        print(f"Request: ciphertext query request is {self.C[0]}")
        
        # Initialize result array
        # 初始化结果数组
        self.R = []
        for i in range(len(self.x)):
            row = []
            for j in range(len(self.sypLabels[0])):
                row.append([None, None])
            self.R.append(row)
        
        self.communicationU = processU.getCommunicationTwo(self.C)

