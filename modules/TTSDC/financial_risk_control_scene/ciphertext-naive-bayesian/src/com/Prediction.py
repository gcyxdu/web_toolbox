import os
import sys
import time

# Add parent directory to path to allow imports
# 将父目录添加到路径中以便导入模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from com.Encrypter import Encrypter
from com.Query import Query
from com.MedicalCenters import MedicalCenters
from com.EhealthcareProvider import EhealthcareProvider
from com.Users import Users
from com.DataProcessor import DataProcessor


def main():
    # Initialize encryption parameters
    # 初始化加密参数
    Training = Encrypter(1024, 64, 3)  # bit-length of N, Certainty, number of MCs
    # N的位长度，确定性，医疗中心数量
    query = Query()
    
    # Get the directory where CSV files are located
    # 获取CSV文件所在的目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_dir = os.path.join(os.path.dirname(os.path.dirname(script_dir)))
    
    me1 = [0, 0, 1, 1, 1, 1, 1, 1, 1]
    print("                              MedicalCenter 1")
    M1 = MedicalCenters(os.path.join(csv_dir, "data", "MC1.csv"), me1, Encrypter.SK[0])
    
    me2 = [1, 1, 1, 1, 1, 1, 1, 0, 0]
    print("                              MedicalCenter 2")
    M2 = MedicalCenters(os.path.join(csv_dir, "data", "MC2.csv"), me2, Encrypter.SK[1])
    
    me3 = [1, 1, 1, 1, 1, 1, 1, 1, 1]
    print("                              MedicalCenter 3")
    M3 = MedicalCenters(os.path.join(csv_dir, "data", "MC3.csv"), me3, Encrypter.SK[2])
    
    MCs = [M1, M2, M3]
    
    U = Users(os.path.join(csv_dir, "data", "Users.csv"))
    
    EP = EhealthcareProvider(MCs, U)
    
    # Decrypt query responses
    # 解密查询响应
    readResponseTime1 = time.time_ns()
    for i in range(len(U.R)):
        for j in range(len(U.R[0])):
            for k in range(len(U.R[0][0])):
                U.R[i][j][k] = Query.getR(EP.D[i][j][k])
    
    for i in range(len(U.R)):
        for j in range(len(U.R[0])):
            if U.R[i][j][0] < U.R[i][j][1]:
                # Disease risk is 1
                # 疾病风险为1
                pass
            else:
                # Disease risk is 0
                # 疾病风险为0
                pass
    
    readResponseTime2 = time.time_ns()
    readResponseTime = readResponseTime2 - readResponseTime1
    
    # Print computation cost
    # 打印计算成本
    print("********************************Computation Cost**********************************")
    totalEncryptionTime = 0
    for i in range(len(MCs)):
        print(f"Training: the encryption time of MC{i + 1} is {MCs[i].training_Encryption}ms")
        totalEncryptionTime = totalEncryptionTime + MCs[i].training_Encryption
    print(f"Training: the aggregation and training time of EP is {EP.aggregationTime}ms")
    print(f"Total training time is {totalEncryptionTime + EP.aggregationTime}ms")
    
    print(" ")
    print(f"Prediction: the time of generating query request is {U.generateRequestTime}ns")
    print(f"Prediction: the time of generating query response is {EP.responseTime}ns")
    print(f"Prediction: the time of reading query response is {readResponseTime}ns")
    total_prediction_time = (U.generateRequestTime + EP.responseTime + readResponseTime) / 1000000
    print(f"Total prediction time is {total_prediction_time:.6f}ms")
    print(" ")
    
    # Verify the accuracy
    # 验证准确性
    prediction = DataProcessor()
    results = prediction.Prediction(U.paddingVector, EP.LI, EP.LII)
    
    print(" ")
    print("********************************Actual Label**********************************")
    for i in range(len(U.sypLabels)):
        for j in range(len(U.sypLabels[0])):
            print(U.sypLabels[i][j], end=" ")
    
    print(" ")
    print("********************************Prediction Result**********************************")
    for i in range(len(results)):
        for j in range(len(results[0])):
            print(results[i][j], end=" ")
    
    amount = len(results)
    accuracyCount = 0
    for i in range(len(results)):
        for j in range(len(results[0])):
            if results[i][j] == U.sypLabels[i][j]:
                accuracyCount += 1
    
    print(" ")
    print(f"Result: accuracyCount is {accuracyCount}")
    accuracy = float(accuracyCount) / amount
    print(f"Result: accuracy is {accuracy:.2%}")


if __name__ == "__main__":
    main()

