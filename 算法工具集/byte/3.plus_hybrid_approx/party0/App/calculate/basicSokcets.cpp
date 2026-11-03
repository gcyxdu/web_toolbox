#include "basicSockets.h"

#include <string.h>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <netinet/tcp.h>
#include <thread>
#include <cmath>
#include <atomic>

#define Sockwrite(sock, data, size) write(sock, data, size)
#define Sockread(sock, buff, bufferSize) read(sock, buff, bufferSize)

int socket_calls = 0;
int thread_calls = 0;

namespace {
std::atomic<unsigned long long> g_send_calls{0};
std::atomic<unsigned long long> g_recv_calls{0};
std::atomic<unsigned long long> g_send_bytes{0};
std::atomic<unsigned long long> g_recv_bytes{0};

struct NetSimConfig {
    bool enabled = false;
    double bandwidth_mbps = 0.0;
    double bandwidth_bytes_per_sec = 0.0;
    long latency_microsec = 0;
};

static bool parse_env_bool(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || *raw == '\0') {
        return fallback;
    }
    if (strcmp(raw, "1") == 0 || strcmp(raw, "true") == 0 || strcmp(raw, "TRUE") == 0 ||
        strcmp(raw, "on") == 0 || strcmp(raw, "ON") == 0 || strcmp(raw, "yes") == 0 ||
        strcmp(raw, "YES") == 0) {
        return true;
    }
    if (strcmp(raw, "0") == 0 || strcmp(raw, "false") == 0 || strcmp(raw, "FALSE") == 0 ||
        strcmp(raw, "off") == 0 || strcmp(raw, "OFF") == 0 || strcmp(raw, "no") == 0 ||
        strcmp(raw, "NO") == 0) {
        return false;
    }
    return fallback;
}

static double parse_env_double(const char* name, double fallback) {
    const char* raw = std::getenv(name);
    if (!raw || *raw == '\0') {
        return fallback;
    }
    errno = 0;
    char* end = nullptr;
    double value = std::strtod(raw, &end);
    if (end == raw || *end != '\0' || errno == ERANGE || value < 0.0) {
        return fallback;
    }
    return value;
}

static NetSimConfig load_net_sim_config() {
    NetSimConfig cfg;
    cfg.enabled = parse_env_bool("NET_SIM_ENABLE", ENABLE_NET_SIM);
    if (!cfg.enabled) {
        return cfg;
    }

    cfg.bandwidth_mbps = parse_env_double("NET_SIM_BANDWIDTH_MBPS", SIM_BANDWIDTH_MBPS);
    if (cfg.bandwidth_mbps > 0.0) {
        cfg.bandwidth_bytes_per_sec = cfg.bandwidth_mbps * 1000.0 * 1000.0 / 8.0;
    }

    const double latency_ms = parse_env_double("NET_SIM_LATENCY_MS", SIM_LATENCY_MS);
    if (latency_ms > 0.0) {
        cfg.latency_microsec = static_cast<long>(std::llround(latency_ms * 1000.0));
    }
    return cfg;
}

static const NetSimConfig& get_net_sim_config() {
    static const NetSimConfig cfg = load_net_sim_config();
    return cfg;
}

static void log_net_sim_config_once() {
    static bool logged = false;
    if (logged) {
        return;
    }
    logged = true;

    const NetSimConfig& cfg = get_net_sim_config();
    if (!cfg.enabled) {
        printf("[NET_SIM] disabled\n");
        return;
    }

    printf("[NET_SIM] enabled bandwidth=%.3f Mbps latency=%.3f ms\n",
           cfg.bandwidth_mbps,
           static_cast<double>(cfg.latency_microsec) / 1000.0);
}

static void apply_network_delay(long latency_microsec, double bandwidth_bytes_per_sec, int size) {
    long long delay_us = latency_microsec;
    if (bandwidth_bytes_per_sec > 0.0 && size > 0) {
        const double serialization_us =
            (static_cast<double>(size) * 1000000.0) / bandwidth_bytes_per_sec;
        delay_us += static_cast<long long>(std::llround(serialization_us));
    }
    if (delay_us > 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
    }
}
}

void reset_bsnet_stats() {
    g_send_calls.store(0);
    g_recv_calls.store(0);
    g_send_bytes.store(0);
    g_recv_bytes.store(0);
}

BSNetStatsSnapshot get_bsnet_stats() {
    BSNetStatsSnapshot snapshot;
    snapshot.send_calls = g_send_calls.load();
    snapshot.recv_calls = g_recv_calls.load();
    snapshot.send_bytes = g_send_bytes.load();
    snapshot.recv_bytes = g_recv_bytes.load();
    return snapshot;
}

BSNet::BSNet(char* host, unsigned int port){
    this->port = port;
    this->host = host;
    this->is_JustServer = false;
    const NetSimConfig& cfg = get_net_sim_config();
    if (cfg.enabled) {
        setNetworkEmulation(cfg.bandwidth_mbps, static_cast<double>(cfg.latency_microsec) / 1000.0);
    } else {
        setNetworkEmulation(0.0, 0.0);
    }
    log_net_sim_config_once();

    for (size_t i = 0; i < NUMCONNECTIONS; i++)
    {
        this->socketFd[i] = -1;
    }
}

BSNet::BSNet(unsigned int port){
    this->port = port;
    this->host = (char*)"";
    this->is_JustServer = true;
    const NetSimConfig& cfg = get_net_sim_config();
    if (cfg.enabled) {
        setNetworkEmulation(cfg.bandwidth_mbps, static_cast<double>(cfg.latency_microsec) / 1000.0);
    } else {
        setNetworkEmulation(0.0, 0.0);
    }
    log_net_sim_config_once();

    for (size_t i = 0; i < NUMCONNECTIONS; i++)
    {
        this->socketFd[i] = -1;
    }
}

BSNet::~BSNet(){
    for (size_t i = 0; i < NUMCONNECTIONS; i++)
    {
        close(this->socketFd[i]);
    }
}

void BSNet::setNetworkEmulation(double bandwidth_mbps, double latency_ms) {
    if (bandwidth_mbps > 0.0) {
        this->sim_bandwidth_bytes_per_sec = bandwidth_mbps * 1000.0 * 1000.0 / 8.0;
    } else {
        this->sim_bandwidth_bytes_per_sec = 0.0;
    }
    if (latency_ms > 0.0) {
        this->sim_latency_microsec = static_cast<long>(std::llround(latency_ms * 1000.0));
    } else {
        this->sim_latency_microsec = 0;
    }
}

bool BSNet::listenNow(){
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
    while (bind(serverSockFd, (struct sockaddr*)& serv_addr, sizeof(serv_addr)) < 0 && testCounter < 10)
    {
        std::cout << "[MPCAssist NET]: ERROR on binding: " << port << std::endl;
        perror("Binding");
        testCounter++;
        sleep(2);
    }

    if (testCounter == 10) return false;

    if(-1 == listen(serverSockFd, 10)){
        perror("listen error");
    }

    for (int conn = 0; conn < NUMCONNECTIONS; conn++)
    {
        clilen = sizeof(cli_addr[conn]);
        std::cout << "[MPCAssist NET]: Server listening on port" << this->port << std::endl;
        this->socketFd[conn] = accept(serverSockFd, (struct sockaddr*)&cli_addr[conn], &clilen);
        if (this->socketFd[conn] < 0)
        {
            std::cout << "\n\n\n[MPCAssist NET]: ERROR on accept\n\n\n" << std::endl;
            return false;
        }
        int flag = 1;
        int result = setsockopt(this->socketFd[conn], IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(int));
        if(result < 0){
            exit(-1);
        }
    }
    close(serverSockFd);
    return true;
}

bool BSNet::connectNow(){
    std::this_thread::sleep_for(std::chrono::seconds(2));

    struct sockaddr_in serv_addr[NUMCONNECTIONS];

    if (is_JustServer) return false;

    for (int conn = 0; conn < NUMCONNECTIONS; conn++)
    {
        socketFd[conn] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        int flag = 1;
        int result = setsockopt(socketFd[conn], IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
        if (result < 0) exit(-1);

        memset(&serv_addr[conn], 0, sizeof(serv_addr[conn]));
        serv_addr[conn].sin_family = AF_INET;
        serv_addr[conn].sin_addr.s_addr = inet_addr(host);
        serv_addr[conn].sin_port = htons(port);

        int count = 0;
        std::cout << "[MPCAssist NET]: Trying to connect to " << host << ":" << port << std::endl;

        while (connect(socketFd[conn], (struct sockaddr*)&serv_addr[conn],sizeof(serv_addr[conn]))< 0)
        {
            count++;
            if (count % 50 == 0) std::cout << "Count=" << count << std::endl;
            sleep(1);
        }
    }
    return true;
}

bool BSNet::sendMsg(void* data, int size, int conn){
    socket_calls++;
    g_send_calls.fetch_add(1);
    g_send_bytes.fetch_add(static_cast<unsigned long long>(size));
    int left = size;
    int n;

    while (left > 0)
    {
        n = Sockwrite(this->socketFd[conn], &((char*)data)[size - left], left);
        if (n < 0) {
            std::cout << "[NET ERROR] write() failed" << std::endl;
            return false;
        }
        left -= n;
    }
    if (this->sim_bandwidth_bytes_per_sec > 0.0) {
        apply_network_delay(0, this->sim_bandwidth_bytes_per_sec, size);
    }

    return true;
}

bool BSNet::recvMsg(void* buff, int size, int conn){
    if (this->sim_latency_microsec > 0) {
        apply_network_delay(this->sim_latency_microsec, 0.0, 0);
    }

    socket_calls++;
    g_recv_calls.fetch_add(1);
    g_recv_bytes.fetch_add(static_cast<unsigned long long>(size));
    int left = size;
    int n;

    while (left > 0)
    {
        n = Sockread(this->socketFd[conn], &((char*)buff)[size-left], left);

        if (n < 0) {
            std::cout << "[NET ERROR] read() failed" << std::endl;
            return false;
        }
        if (n == 0) return false;

        left -= n;
    }

    if (this->sim_bandwidth_bytes_per_sec > 0.0) {
        apply_network_delay(0, this->sim_bandwidth_bytes_per_sec, size);
    }
    return true;
}
