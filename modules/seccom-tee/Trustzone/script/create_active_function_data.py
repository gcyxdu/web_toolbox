import os
import random

# 顶层目录
base_dir = "active_function_data"
sub_dirs = ["Relu", "Sigmoid", "Softmax"]

# 确保顶层目录存在
os.makedirs(base_dir, exist_ok=True)

# 随机数范围
min_val, max_val = -3.0, 3.0

# 创建子目录并生成文件
for sub_dir in sub_dirs:
    dir_path = os.path.join(base_dir, sub_dir)
    os.makedirs(dir_path, exist_ok=True)  # 创建子目录
    
    for i in range(1000):  # 生成 1000 个文件
        file_path = os.path.join(dir_path, f"{i}.txt")
        
        # 生成 10000 个随机数，并用空格隔开
        numbers = [str(round(random.uniform(min_val, max_val), 6)) for _ in range(10000)]
        content = " ".join(numbers)

        # 写入文件
        with open(file_path, "w") as f:
            f.write(content)
        
        # 可选：打印进度
        if i % 1000 == 0:
            print(f"Created {file_path}")

print("所有文件创建完成！")

