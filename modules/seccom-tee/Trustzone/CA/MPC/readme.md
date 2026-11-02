## 分布式多方安全计算求相似度系数和求和部分

### 文件夹说明
- cloud是负责存放编译后结果以及部分脚本的文件夹
- utils存放的是公共的一些工具类，具体是由下面组成
  - func.cpp:存放整体的实现函数
  - basicSockets.cpp:使用<netinet/tcp.h>和<arpa/inet.h>实现的手写的Socket操作， 负责两方里面两方的通信工作
  - tools.cpp:工具函数
  - examples.cpp:负责测试求相似度系数以及求和部分

