#include "basicSockets.h"

#include <string.h>
#include <cstdio>
#include <netinet/tcp.h>
#include <thread>

#define Sockwrite(sock, data, size) write(sock, data, size)
#define Sockread(sock, buff, bufferSize) read(sock, buff, bufferSize)

int socket_calls = 0;
int thread_calls = 0;

/**
 * 输入服务器端的ip地址和端口号，创建客户端
 */
BSNet::BSNet(const char *host, unsigned int port)
{
    this->port = port;
    this->host = host;
    this->is_JustServer = false;

    for (size_t i = 0; i < NUMCONNECTIONS; i++)
    {
        this->socketFd[i] = -1;
    }
}

/**
 * 输入端口号，创建服务端
 */
BSNet::BSNet(unsigned int port)
{
    this->port = port;
    this->host = "";
    this->is_JustServer = true;

    for (size_t i = 0; i < NUMCONNECTIONS; i++)
    {
        this->socketFd[i] = -1;
    }
}

BSNet::~BSNet()
{
    for (size_t i = 0; i < NUMCONNECTIONS; i++)
    {
        close(this->socketFd[i]);
    }
}

/**
 * 服务器端开始监听连接请求
 */
bool BSNet::listenNow()
{
    int serverSockFd;
    socklen_t clilen;

    struct sockaddr_in serv_addr, cli_addr[NUMCONNECTIONS];

    serverSockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSockFd < 0)
    {
        std::cout << "[MPCAssist NET]: ERROR opening socket" << std::endl;
        return false;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(this->port);

    int yes = 1;

    if (-1 == (setsockopt(serverSockFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))))
    {
        perror("setsockopt");
        exit(1);
    }

    int testCounter = 0;
    while (bind(serverSockFd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 && testCounter < 10)
    {
        std::cout << "[MPCAssist NET]: ERROR on binding: " << port << std::endl;
        std::cout << "[MPCAssist NET]: Count: " << testCounter << std::endl;
        perror("Binding");
        testCounter++;
        sleep(2);
    }

    // 绑定失败
    if (testCounter == 10)
    {
        return false;
    }

    if (-1 == listen(serverSockFd, 10))
    {
        perror("listen error");
    }

    for (int conn = 0; conn < NUMCONNECTIONS; conn++)
    {
        clilen = sizeof(cli_addr[conn]);
        std::cout << "[MPCAssist NET]: Server listening on port" << this->port << std::endl;
        this->socketFd[conn] = accept(serverSockFd, (struct sockaddr *)&cli_addr[conn], &clilen);
        if (this->socketFd[conn] < 0)
        {
            std::cout << "\n\n\n[MPCAssist NET]: ERROR on accept\n\n\n"
                      << std::endl;
            return false;
        }
        int flag = 1;
        int result = setsockopt(this->socketFd[conn], IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        if (result < 0)
        {
            std::cout << "[MPCAssist NET]: error setting NODELAY. exiting" << std::endl;
            exit(-1);
        }
    }
    close(serverSockFd);
    return true;
}

/**
 * 客户端发起连接请求
 */
bool BSNet::connectNow()
{
    // 休眠一段时间，确保服务器端准备完成
    std::this_thread::sleep_for(std::chrono::seconds(2));

    struct sockaddr_in serv_addr[NUMCONNECTIONS];
    struct hostent *server;
    int n;

    if (is_JustServer)
    {
        std::cout << "[MPCAssist NET]: ERROR: Nerver got a host... please use the second constructor" << std::endl;
        return false;
    }

    for (int conn = 0; conn < NUMCONNECTIONS; conn++)
    {
        socketFd[conn] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketFd[conn] < 0)
        {
            std::cout << ("[MPCAssist NET]: ERROR opening socket") << std::endl;
        }

        int flag = 1;
        int result = setsockopt(socketFd[conn], IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        if (result < 0)
        {
            std::cout << "[MPCAssist NET]: error setting NODELAY. exiting" << std::endl;
            exit(-1);
        }

        memset(&serv_addr[conn], 0, sizeof(serv_addr[conn]));
        serv_addr[conn].sin_family = AF_INET;
        serv_addr[conn].sin_addr.s_addr = inet_addr(host);
        serv_addr[conn].sin_port = htons(port);

        int count = 0;
        std::cout << "[MPCAssist NET]: Trying to connect to server" << std::endl;
        std::cout << "[MPCAssist NET]: IP Address: " << host << "|| Port" << port << std::endl;

        while (connect(socketFd[conn], (struct sockaddr *)&serv_addr[conn], sizeof(serv_addr[conn])) < 0)
        {
            count++;
            if (count % 50 == 0)
            {
                std::cout << "[MPCAssist NET]:  Not managing to connect. " << "Count=" << count << std::endl;
            }
            sleep(1);
        }
    }
    return true;
}

/**
 * 发送消息
 */
bool BSNet::sendMsg(void *data, int size, int conn)
{
    socket_calls++;
    int left = size;
    int n;
    while (left > 0)
    {
        n = Sockwrite(this->socketFd[conn], &((char *)data)[size - left], left);
        if (n < 0)
        {
            std::cout << "[MPCAssist NET]: ERROR writing to socket" << std::endl;
            return false;
        }
        left -= n;
    }

    return true;
}

/**
 * 接收消息
 */
bool BSNet::recvMsg(void *buff, int size, int conn)
{
    socket_calls++;
    int left = size;
    int n;
    while (left > 0)
    {
        n = Sockread(this->socketFd[conn], &((char *)buff)[size - left], left);
        if (n < 0)
        {
            std::cout << "[MPCAssist NET]: ERROR reading from socket" << std::endl;
            std::cout << "[MPCAssist NET]: Size = " << size << ", Left = " << left << ", n = " << n << std::endl;
            return false;
        }
        if (n == 0)
        {
            break;
        }
        left -= n;
    }
    return true;
}