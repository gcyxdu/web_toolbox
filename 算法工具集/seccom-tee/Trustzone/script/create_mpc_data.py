import os
import random
import shutil

# 定义文件夹结构
structure = {
    "CLI": {
        "testCompareData": ["dataX.txt", "dataY.txt"],
        "testDataBinData": ["dataX.txt"],
        "testDistCorCoefData": ["dataA.txt", "dataB.txt"],
        "testDivData": ["dataX.txt", "dataY.txt"],
        "testEculidDistanceData": ["dataX.txt", "dataY.txt"],
        "testMulData": ["dataX.txt", "dataY.txt"],
        "testPearsonData": ["dataX.txt", "dataY.txt"],
        "testSortData": ["dataX.txt"],
        "testVarianceData": ["data.txt"]
    },
    "SERVER": {
        "testCompareData": ["dataX.txt", "dataY.txt"],
        "testDataBinData": ["dataX.txt"],
        "testDistCorCoefData": ["dataA.txt", "dataB.txt"],
        "testDivData": ["dataX.txt", "dataY.txt"],
        "testEculidDistanceData": ["dataX.txt", "dataY.txt"],
        "testMulData": ["dataX.txt", "dataY.txt"],
        "testPearsonData": ["dataX.txt", "dataY.txt"],
        "testSortData": ["dataX.txt", "dataY.txt"],
        "testVarianceData": ["data.txt"]
    }
}

# 创建数据存储的根目录
data_root = "MPC_data"
os.makedirs(data_root, exist_ok=True)

# 生成 1000 组文件夹
for i in range(1, 1001):
    group_folder = os.path.join(data_root, f"Group_{i}")
    os.makedirs(group_folder, exist_ok=True)

    # 在该组数据文件夹内创建 CLI 和 SERVER 结构
    for parent_folder, sub_folders in structure.items():
        parent_path = os.path.join(group_folder, parent_folder)
        os.makedirs(parent_path, exist_ok=True)

        for sub_folder, files in sub_folders.items():
            sub_folder_path = os.path.join(parent_path, sub_folder)
            os.makedirs(sub_folder_path, exist_ok=True)

            # 创建并填充数据文件
            for file in files:
                file_path = os.path.join(sub_folder_path, file)
                with open(file_path, 'w') as f:
                    random_numbers = [str(random.randint(-5000, 5000)) for _ in range(1000)]
                    f.write(' '.join(random_numbers))

    print(f"已生成第 {i} 组数据: {group_folder}")

print("所有数据集已生成完毕！")

