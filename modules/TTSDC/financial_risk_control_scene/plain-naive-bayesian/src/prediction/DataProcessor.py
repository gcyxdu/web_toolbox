import csv
import math


class DataProcessor:
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
                        # 跳过空行
                        row = [int(x) for x in line]
                        intItem.append(row)
            return intItem
        except Exception as e:
            print(f"Error reading file: {e}")
            return []
    
    # extend the original vectors to 90-dimensional vectors
    # 将原始向量扩展到90维向量
    def vectorExtend(self, originVector):
        if len(originVector) == 0 or len(originVector[0]) == 0:
            return []
        
        extendVector = []
        num_features = (len(originVector[0]) - 1) * 10
        
        for i in range(len(originVector)):
            row = [0] * num_features
            for j in range(len(originVector[0]) - 1):
                if originVector[i][j] != 0:
                    idx = originVector[i][j] + 10 * j - 1
                    if 0 <= idx < num_features:
                        row[idx] = 1
            extendVector.append(row)
        
        return extendVector
    
    # get the labels of the instances
    # 获取实例的标签
    def getLable(self, originVector, minDimension, maxDimension):
        if len(originVector) == 0:
            return []
        
        label = []
        num_labels = maxDimension - minDimension + 1
        
        for i in range(len(originVector)):
            row = []
            # Extract label from the last column
            # 从最后一列提取标签
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
    # get e
    # 获取e
    def getE(self, collectAttributes):
        e = [1] * (len(collectAttributes) * 10)
        
        for i in range(len(collectAttributes)):
            for j in range(i * 10, (i + 1) * 10):
                e[j] = e[j] * collectAttributes[i]
        
        return e
    
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
            row = []
            for j in range(len(extendVector[0]) * len(label[0])):
                val = 0
                for t in range(len(label[0])):
                    idx = j // len(label[0])
                    if idx < len(extendVector[0]):
                        val = extendVector[i][idx] * label[i][t]
                row.append(val)
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
    # get SNX
    # 获取SNX
    def getSNX(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNX = [0] * len(MCs[0].NX)
        
        for i in range(len(SNX)):
            for j in range(len(MCs)):
                SNX[i] = SNX[i] + MCs[j].NX[i]
        
        return SNX
    
    # get SNY
    # 获取SNY
    def getSNY(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNY = [0] * len(MCs[0].NY)
        
        for i in range(len(SNY)):
            for j in range(len(MCs)):
                SNY[i] = SNY[i] + MCs[j].NY[i]
        
        return SNY
    
    # get SNZ
    # 获取SNZ
    def getSNZ(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNZ = [0] * len(MCs[0].NZ)
        
        for i in range(len(SNZ)):
            for j in range(len(MCs)):
                SNZ[i] = SNZ[i] + MCs[j].NZ[i]
        
        return SNZ
    
    # get SND
    # 获取SND
    def getSND(self, MCs):
        if len(MCs) == 0:
            return []
        
        SND = [0] * len(MCs[0].ND)
        
        for i in range(len(SND)):
            for j in range(len(MCs)):
                SND[i] = SND[i] + MCs[j].ND[i]
        
        return SND
    
    # get SNL
    # 获取SNL
    def getSNL(self, MCs):
        if len(MCs) == 0:
            return []
        
        SNL = [0] * len(MCs[0].NL)
        
        for i in range(len(SNL)):
            for j in range(len(MCs)):
                SNL[i] = SNL[i] + MCs[j].NL[i]
        
        return SNL
    
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
    
    # Compute the log
    # 计算对数
    def getLog(self, temp):
        L_result = []
        for i in range(len(temp)):
            L_result.append(math.log(temp[i]) / math.log(0.5))
        return L_result
    
    # Get prediction vectors
    # 获取预测向量
    def getPredictionvectors(self, X_1, X_0, Y):
        dimension = len(X_1) // len(Y)
        LI = []
        
        for i in range(len(Y)):
            row = [0.0] * (2 * dimension + 1)
            for j in range(dimension * i, dimension * (i + 1)):
                if j < len(X_1):
                    row[j - dimension * i] = X_1[j]
                    row[dimension + (j - dimension * i)] = X_0[j]
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

