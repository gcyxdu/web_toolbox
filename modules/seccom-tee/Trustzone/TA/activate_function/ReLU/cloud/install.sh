#!/bin/bash

# Step 1: 删除当前目录下所有 .sec 结尾的文件和 libcombine.so 文件
echo "Deleting .sec files and libcombine.so..."
rm -f *.sec
rm -f libcombine.so

# Step 2: 清空 build 目录
echo "Cleaning build directory..."
rm -rf build/*

# Step 3: 进入 build 目录并执行 cmake 和 make
echo "Entering build directory and building..."
cd build
cmake ..
make

# Step 4: 返回上一层目录并执行复制操作
echo "Returning to previous directory and copying .sec files..."
cd ..
cp -rf *.sec /data/

# Step 5: 打印安装完成
echo "install ok!"

