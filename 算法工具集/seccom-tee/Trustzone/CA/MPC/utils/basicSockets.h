#pragma once

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>

using std::thread;

#define NUMCONNECTIONS 1

class BSNet
{
private:
    const char *host;
    unsigned int port;
    bool is_JustServer;
    int socketFd[NUMCONNECTIONS];

public:
    BSNet(const char *host, unsigned int port);

    BSNet(unsigned int port);

    bool listenNow();

    bool connectNow();

    bool sendMsg(void *data, int size, int conn);

    bool recvMsg(void *buff, int size, int conn);

    virtual ~BSNet();
};