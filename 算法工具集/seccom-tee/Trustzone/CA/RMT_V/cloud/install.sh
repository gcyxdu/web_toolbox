#!/bin/bash

# 获取当前脚本所在目录
current_dir=$(pwd)

# 进入当前目录下的 build 目录
cd "$current_dir/build" || exit 1

# 执行 make clean 清空 build 目录
echo "清空 build 目录..."
make clean

# 执行 cmake ..
echo "执行 cmake .."
cmake ..

# 执行 make
echo "执行 make"
make

# 返回到上层目录
cd "$current_dir" || exit 1

# 执行拷贝操作
echo "拷贝 teec_RMT_V 到 /vendor/bin/"
cp teec_* /vendor/bin/

# 打印安装成功信息
echo "install ok!"
