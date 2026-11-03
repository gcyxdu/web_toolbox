import csv
import math


class DataProcessor:
    dimension = 90  # Fixed dimension for ciphertext version
    
    # get BigInteger (Python中int本身就是任意精度，这里直接返回list)
    # 获取大整数（Python中int本身就是任意精度，这里直接返回list）
    def getBigInteger(self, V):
        """Convert int list to big integers (in Python, int is already arbitrary precision)"""
        # 将整数列表转换为大整数（在Python中，int已经是任意精度）
        return [int(x) for x in V]
    
    # get Int
    # 获取整数
    def getInt(self, BV):
        """Convert big integers to int list"""
        # 将大整数转换为整数列表
        return [int(x) for x in BV]
    
    # *****************************************************************************************
    # read the data set to a 2-dimensional array
    # 将数据集读取为2维数组
    def readFile(self, filepath):
        try:
            intItem = []
            with open(filepath, 'r') as f:
                reader = csv.reader(f)
                for line in reader:
                    if line:  # Skip empty lines
                        row = [int(x) for x in line]
                        intItem.append(row)
            return intItem
        except Exception as e:
            print(f"Error reading file: {e}")
            return []
    
    # choose attributes from datasets
    # 从数据集中选择属性
    def vectorExtract(self, originVector, minDimension, maxDimension, nuOfinstances):
        """Extract specific columns from the original vector"""
        # 从原始向量中提取特定列
        extractVector = []
        num_cols = maxDimension - minDimension + 1
        
        for i in range(nuOfinstances):
            row = []
            k = minDimension
            for j in range(num_cols):
                row.append(originVector[i][k])
                k += 1
            extractVector.append(row)
        
        return extractVector
    
    # extend the original vectors to 90-dimensional vectors
    # 将原始向量扩展到90维向量
    def vectorExtend(self, extractVector):
        """Extend vectors to fixed 90 dimensions"""
        # 将向量扩展到固定的90维
        if len(extractVector) == 0 or len(extractVector[0]) == 0:
            return []
        
        extendVector = []
        num_features = len(extractVector[0]) * 10
        
        for i in range(len(extractVector)):
            row = [0] * num_features
            for j in range(len(extractVector[0])):
                if extractVector[i][j] != 0:
                    idx = extractVector[i][j] + 10 * j - 1
                    if 0 <= idx < num_features:
                        row[idx] = 1
            extendVector.append(row)
        
        # Truncate or pad to exactly 90 dimensions
        # 截断或填充到恰好90维
        testOnly = []
        for i in range(len(extendVector)):
            row = [0] * self.dimension
            for j in range(min(self.dimension, len(extendVector[0]))):
                row[j] = extendVector[i][j]
            testOnly.append(row)
        
        return testOnly
    
    # get the labels of the instances
    # 获取实例的标签
    def getLable(self, originVector, minDimension, maxDimension, nuOfinstances):
        """Extract labels from the original vector"""
        # 从原始向量中提取标签
        label = []
        num_labels = maxDimension - minDimension + 1
        
        for i in range(nuOfinstances):
            row = []
            last_col = originVector[i][len(originVector[0]) - 1]
            if last_col == 2:
                label_value = 1
            else:
                label_value = 0
            
            for j in range(num_labels):
                row.append(label_value)
            label.append(row)
        
        return label
    
    # *************************************************************************************************************
    # get e (limited to 90 dimensions)
    # 获取e（限制为90维）
    def getE(self, collectAttributes):
        """Generate mask vector e"""
        # 生成掩码向量e
        e = [1] * (len(collectAttributes) * 10)
        teste = [1] * self.dimension
        
        for i in range(len(collectAttributes)):
            for j in range(i * 10, (i + 1) * 10):
                e[j] = e[j] * collectAttributes[i]
        
        for i in range(self.dimension):
            teste[i] = e[i]
        
        return teste
    
    # get NX
    # 获取NX
    def getNX(self, extendVector):
        if len(extendVector) == 0:
            return []
        
        NX = [0] * len(extendVector[0])
        
        for i in range(len(extendVector)):
            for j in range(len(NX)):
                NX[j] = NX[j] + extendVector[i][j]
        
        return NX
    
    # get NY
    # 获取NY
    def getNY(self, label):
        if len(label) == 0:
            return []
        
        NY = [0] * len(label[0])
        
        for i in range(len(label)):
            for j in range(len(label[0])):
                NY[j] = NY[j] + label[i][j]
        
        return NY
    
    # get NZ
    # 获取NZ
    def getNZ(self, extendVector, label):
        if len(extendVector) == 0 or len(label) == 0:
            return []
        
        NZZ = []
        for i in range(len(extendVector)):
            row = [0] * (len(extendVector[0]) * len(label[0]))
            for j in range(len(row)):
                for t in range(len(label[0])):
                    idx = j % len(extendVector[0])
                    row[j] = extendVector[i][idx] * label[i][t]
            NZZ.append(row)
        
        NZ = [0] * (len(extendVector[0]) * len(label[0]))
        for i in range(len(NZZ)):
            for j in range(len(NZ)):
                NZ[j] = NZ[j] + NZZ[i][j]
        
        return NZ
    
    # get ND
    # 获取ND
    def getND(self, TNY, TE):
        ND = []
        for i in range(len(TNY)):
            for j in range(len(TE)):
                ND.append(TNY[i] * TE[j])
        return ND
    
    # get NL
    # 获取NL
    def getNL(self, nuOfins, TE):
        NL = [0] * (len(TE) + 1)
        NL[len(TE)] = nuOfins
        
        for i in range(len(TE)):
            NL[i] = TE[i] * nuOfins
        
        return NL
    
    # *****************************************************************************************
    # get SNX (plaintext aggregation)
    # 获取SNX（明文聚合）
    def getSNX(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNX = [0] * len(MCs[0].NX)
        
        for i in range(len(SNX)):
            for j in range(len(MCs)):
                SNX[i] = SNX[i] + MCs[j].NX[i]
        
        return SNX
    
    # get ESNX (ciphertext aggregation)
    # 获取ESNX（密文聚合）
    def getESNX(self, MCs):
        """Aggregate encrypted NX from multiple medical centers using HEU ZPaillier"""
        # 使用HEU ZPaillier从多个医疗中心聚合加密的NX
        if len(MCs) == 0:
            return []
        
        from .Encrypter import Encrypter
        
        # 初始化聚合结果：第一个医疗中心的密文
        # Initialize aggregation result: ciphertext from the first medical center
        ESNX = list(MCs[0].ENX)
        
        # 使用 HEU evaluator.add 进行同态加法聚合
        # Use HEU evaluator.add for homomorphic addition aggregation
        for i in range(len(ESNX)):
            for j in range(1, len(MCs)):  # 从第二个医疗中心开始
                # From the second medical center onwards
                ESNX[i] = Encrypter.evaluator.add(ESNX[i], MCs[j].ENX[i])
        
        return ESNX
    
    # get SNY (plaintext aggregation)
    # 获取SNY（明文聚合）
    def getSNY(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNY = [0] * len(MCs[0].NY)
        
        for i in range(len(SNY)):
            for j in range(len(MCs)):
                SNY[i] = SNY[i] + MCs[j].NY[i]
        
        return SNY
    
    # get ESNY (ciphertext aggregation)
    # 获取ESNY（密文聚合）
    def getESNY(self, MCs):
        """Aggregate encrypted NY from multiple medical centers using HEU ZPaillier"""
        # 使用HEU ZPaillier从多个医疗中心聚合加密的NY
        if len(MCs) == 0:
            return []
        
        from .Encrypter import Encrypter
        
        ESNY = list(MCs[0].ENY)
        
        for i in range(len(ESNY)):
            for j in range(1, len(MCs)):
                ESNY[i] = Encrypter.evaluator.add(ESNY[i], MCs[j].ENY[i])
        
        return ESNY
    
    # get SNZ (plaintext aggregation)
    # 获取SNZ（明文聚合）
    def getSNZ(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNZ = [0] * len(MCs[0].NZ)
        
        for i in range(len(SNZ)):
            for j in range(len(MCs)):
                SNZ[i] = SNZ[i] + MCs[j].NZ[i]
        
        return SNZ
    
    # get ESNZ (ciphertext aggregation)
    # 获取ESNZ（密文聚合）
    def getESNZ(self, MCs):
        """Aggregate encrypted NZ from multiple medical centers using HEU ZPaillier"""
        # 使用HEU ZPaillier从多个医疗中心聚合加密的NZ
        if len(MCs) == 0:
            return []
        
        from .Encrypter import Encrypter
        
        ESNZ = list(MCs[0].ENZ)
        
        for i in range(len(ESNZ)):
            for j in range(1, len(MCs)):
                ESNZ[i] = Encrypter.evaluator.add(ESNZ[i], MCs[j].ENZ[i])
        
        return ESNZ
    
    # get SND (plaintext aggregation)
    # 获取SND（明文聚合）
    def getSND(self, MCs):
        if len(MCs) == 0:
            return []
        
        SND = [0] * len(MCs[0].ND)
        
        for i in range(len(SND)):
            for j in range(len(MCs)):
                SND[i] = SND[i] + MCs[j].ND[i]
        
        return SND
    
    # get ESND (ciphertext aggregation)
    # 获取ESND（密文聚合）
    def getESND(self, MCs):
        """Aggregate encrypted ND from multiple medical centers using HEU ZPaillier"""
        # 使用HEU ZPaillier从多个医疗中心聚合加密的ND
        if len(MCs) == 0:
            return []
        
        from .Encrypter import Encrypter
        
        ESND = list(MCs[0].END)
        
        for i in range(len(ESND)):
            for j in range(1, len(MCs)):
                ESND[i] = Encrypter.evaluator.add(ESND[i], MCs[j].END[i])
        
        return ESND
    
    # get SNL (plaintext aggregation)
    # 获取SNL（明文聚合）
    def getSNL(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNL = [0] * len(MCs[0].NL)
        
        for i in range(len(SNL)):
            for j in range(len(MCs)):
                SNL[i] = SNL[i] + MCs[j].NL[i]
        
        return SNL
    
    # get ESNL (ciphertext aggregation)
    # 获取ESNL（密文聚合）
    def getESNL(self, MCs):
        """Aggregate encrypted NL from multiple medical centers using HEU ZPaillier"""
        # 使用HEU ZPaillier从多个医疗中心聚合加密的NL
        if len(MCs) == 0:
            return []
        
        from .Encrypter import Encrypter
        
        ESNL = list(MCs[0].ENL)
        
        for i in range(len(ESNL)):
            for j in range(1, len(MCs)):
                ESNL[i] = Encrypter.evaluator.add(ESNL[i], MCs[j].ENL[i])
        
        return ESNL
    
    # get Pr(x=1|y=1)
    # 获取Pr(x=1|y=1)
    def getX_1_Y_1(self, SNZ, SND):
        X_1_Y_1 = []
        for i in range(len(SNZ)):
            X_1_Y_1.append(float(SNZ[i]) / float(SND[i]) + 0.00000000000000000000001)
        return X_1_Y_1
    
    # get Pr(x=0|y=1)
    # 获取Pr(x=0|y=1)
    def getX_0_Y_1(self, X_1_Y_1):
        X_0_Y_1 = []
        for i in range(len(X_1_Y_1)):
            X_0_Y_1.append(1 - X_1_Y_1[i])
        return X_0_Y_1
    
    # get Pr(x=1|y=0)
    # 获取Pr(x=1|y=0)
    def getX_1_Y_0(self, SNX, SNZ, SND, SNL):
        X_1_Y_0 = [0.0] * len(SNZ)
        numOfDisease = len(SNZ) // len(SNX)
        
        for i in range(numOfDisease):
            for k in range(len(SNX)):
                j = i * len(SNX) + k
                if j < len(SNZ):
                    X_1_Y_0[j] = float(SNX[k] - SNZ[j]) / float(SNL[k] - SND[j]) + 0.00000000000000000000001
        
        return X_1_Y_0
    
    # get Pr(x=0|y=0)
    # 获取Pr(x=0|y=0)
    def getX_0_Y_0(self, X_1_Y_0):
        X_0_Y_0 = []
        for i in range(len(X_1_Y_0)):
            X_0_Y_0.append(1 - X_1_Y_0[i])
        return X_0_Y_0
    
    # get Pr(y=1)
    # 获取Pr(y=1)
    def getY_1(self, SNY, SNL):
        Y_1 = []
        for i in range(len(SNY)):
            Y_1.append(float(SNY[i]) / SNL[len(SNL) - 1])
        return Y_1
    
    # get Pr(y=0)
    # 获取Pr(y=0)
    def getY_0(self, Y_1):
        Y_0 = []
        for i in range(len(Y_1)):
            Y_0.append(1 - Y_1[i])
        return Y_0
    
    # Compute the log (returns int array scaled by 10000)
    # 计算对数（返回按10000缩放的整数数组）
    def getLog(self, temp):
        """Compute log and return as integer array (scaled by 10000)"""
        # 计算对数并返回整数数组（按10000缩放）
        L_result = []
        for i in range(len(temp)):
            log_val = math.log(temp[i]) / math.log(0.5)
            L_result.append(int(math.floor(log_val * 10000)))
        return L_result
    
    # Get prediction vectors (returns int array)
    # 获取预测向量（返回整数数组）
    def getPredictionvectors(self, X_1, X_0, Y):
        """Generate prediction vectors as integer arrays"""
        # 生成整数数组形式的预测向量
        dimension = len(X_1) // len(Y)
        LI = []
        
        for i in range(len(Y)):
            row = [0] * (2 * dimension + 1)
            for j in range(len(X_1)):
                row[j % dimension] = X_1[j]
                row[dimension + (j % dimension)] = X_0[j]
            row[2 * dimension] = Y[i]
            LI.append(row)
        
        return LI
    
    # **********************************************************************************************************
    # get Users' padding vector
    # 获取用户的填充向量
    def getUPaddingVector(self, extendVector):
        if len(extendVector) == 0:
            return []
        
        padVector = []
        for i in range(len(extendVector)):
            row = [0] * (2 * len(extendVector[0]) + 1)
            for j in range(len(extendVector[0])):
                row[j] = extendVector[i][j]
            for j in range(len(extendVector[0]), 2 * len(extendVector[0])):
                k = j - len(extendVector[0])
                row[j] = 1 - extendVector[i][k]
            row[2 * len(extendVector[0])] = 1
            padVector.append(row)
        
        return padVector
    
    # **************************************************************************************************************
    # Prediction
    # 预测
    def Prediction(self, paddingVector, predictionVector1, predictionVector2):
        results = []
        
        for i in range(len(paddingVector)):
            row = []
            for j in range(len(predictionVector1)):
                temp1 = 0.0
                temp2 = 0.0
                
                for k in range(len(predictionVector1[0])):
                    temp1 = temp1 + paddingVector[i][k] * predictionVector1[j][k]
                    temp2 = temp2 + paddingVector[i][k] * predictionVector2[j][k]
                
                if temp1 < temp2:
                    row.append(1)
                else:
                    row.append(0)
            results.append(row)
        
        return results
    
    # **************************************************************************************************************
    # Communication overhead calculation
    # 通信开销计算
    def getCommunicationOne(self, temp):
        """Calculate communication overhead of one-dimensional array (HEU Ciphertext objects)"""
        # 计算一维数组的通信开销（HEU密文对象）
        space = 0
        for i in range(len(temp)):
            # HEU Ciphertext 对象可能没有 bit_length() 方法
            # HEU Ciphertext object may not have bit_length() method
            # 尝试获取大小，如果失败则使用默认估算
            # Try to get size, if failed use default estimation
            try:
                # 尝试获取密文的大小（可能需要序列化）
                # Try to get ciphertext size (may need serialization)
                import sys
                space += sys.getsizeof(temp[i])
            except:
                # 如果无法获取，使用默认估算（假设每个密文约 256 字节）
                # If unable to get, use default estimation (assume each ciphertext is about 256 bytes)
                space += 256
        return space
    
    def getCommunicationTwo(self, temp):
        """Calculate communication overhead of two-dimensional array"""
        # 计算二维数组的通信开销
        space = 0
        for i in range(len(temp)):
            for j in range(len(temp[0])):
                space += temp[i][j].bit_length()
        return space
    
    def getCommunicationTheree(self, temp):
        """Calculate communication overhead of three-dimensional array"""
        # 计算三维数组的通信开销
        space = 0
        for i in range(len(temp)):
            for j in range(len(temp[0])):
                for k in range(len(temp[0][0])):
                    space += temp[i][j][k].bit_length()
        return space

