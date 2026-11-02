# 编译器
CXX = g++

# 编译选项
CXXFLAGS = -std=c++11 -Wall -Wextra -I. `pkg-config --cflags openssl`

# 链接选项
LDFLAGS = `pkg-config --libs openssl`

# 目标文件
TARGET = server

# 源文件
SRCS = server.cpp layer.cpp network.cpp she.cpp

# 依赖文件
DEPS = layer.h network.h she.h

# 目标文件
OBJS = $(SRCS:.cpp=.o)

# 默认目标
all: $(TARGET)

# 链接目标文件
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

# 编译源文件
%.o: %.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 清理目标文件和中间文件
clean:
	rm -f $(TARGET) $(OBJS)
