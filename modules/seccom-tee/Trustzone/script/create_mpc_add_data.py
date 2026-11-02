import os
import random

def generate_files():
    # 创建 TCKKS 目录
    dir_name = "MPC_add"
    os.makedirs(dir_name, exist_ok=True)

    # 生成 1000 个 txt 文件
    for i in range(1000):
        file_path = os.path.join(dir_name, f"{i}.txt")
        with open(file_path, "w") as f:
            numbers = [str(random.randint(0, 1000000)) for _ in range(1000)]
            f.write(" ".join(numbers))

    print(f"1000 个 txt 文件已生成，存放在 {dir_name} 目录下。")

if __name__ == "__main__":
    generate_files()
