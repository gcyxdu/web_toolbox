#pragma once

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <cmath>

using std::thread;

#define NUMCONNECTIONS 1




#define ENABLE_NET_SIM false


#define SIM_BANDWIDTH_MBPS 1000.0
#define SIM_LATENCY_MS     0.05

class BSNet
{
private:
    char* host;
    unsigned int port;
    bool is_JustServer;
    int socketFd[NUMCONNECTIONS];

    double sim_bandwidth_bytes_per_sec = 0;
    long sim_latency_microsec = 0;

public:
    BSNet(char* host, unsigned int port);
    BSNet(unsigned int port);
    bool listenNow();
    bool connectNow();
    bool sendMsg(void* data, int size, int conn);
    bool recvMsg(void* buff, int size, int conn);
    bool startServer();
    void setNetworkEmulation(double bandwidth_mbps, double latency_ms);
    virtual ~BSNet();
};

struct BSNetStatsSnapshot {
    unsigned long long send_calls;
    unsigned long long recv_calls;
    unsigned long long send_bytes;
    unsigned long long recv_bytes;
};

void reset_bsnet_stats();
BSNetStatsSnapshot get_bsnet_stats();
