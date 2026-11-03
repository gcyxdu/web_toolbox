import os
import sys

# Add parent directory to path to allow imports
# 将父目录添加到路径中以便导入模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prediction.MedicalCenters import MedicalCenters
from prediction.EhealthcareProvider import EhealthcareProvider
from prediction.Users import Users
from prediction.DataProcessor import DataProcessor


def main():
    # Get the directory where CSV files are located (two levels up from this script)
    # 获取CSV文件所在的目录（从脚本向上两级）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_dir = os.path.join(os.path.dirname(os.path.dirname(script_dir)))
    
    me1 = [0, 0, 1, 1, 1, 1, 1, 1, 1]
    M1 = MedicalCenters(os.path.join(csv_dir, "data", "MC1.csv"), me1)
    
    me2 = [1, 1, 1, 1, 1, 1, 1, 0, 0]
    M2 = MedicalCenters(os.path.join(csv_dir, "data", "MC2.csv"), me2)
    
    me3 = [1, 1, 1, 1, 1, 1, 1, 1, 1]
    M3 = MedicalCenters(os.path.join(csv_dir, "data", "MC3.csv"), me3)
    
    MCs = [M1, M2, M3]
    
    EP = EhealthcareProvider(MCs)
    
    U = Users(os.path.join(csv_dir, "data", "Users.csv"))
    
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
    print("Result: accuracyCount is", accuracyCount)
    accuracy = float(accuracyCount) / amount
    print(f"Result: accuracy is {accuracy:.2%}")


if __name__ == "__main__":
    main()

