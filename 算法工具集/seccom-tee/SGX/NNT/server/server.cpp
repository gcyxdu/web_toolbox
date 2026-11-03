#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "network.h"
#include "she.h"

using namespace std;
extern SHE_key KEY;

Network *_global_network;
double bestaccuracy = 0.0;

void testAccuracy(const char *testPath, int testNumImages, const char *weightPath, int i);

void timeStart(struct timeval *timePointer) {
    gettimeofday(timePointer, NULL);
}

void timeEnd(struct timeval *timePointer1, struct timeval *timePointer2) {
    float timeuse;
    gettimeofday(timePointer2, NULL);
    timeuse = (timePointer2->tv_sec - timePointer1->tv_sec) * 1000000 + timePointer2->tv_usec - timePointer1->tv_usec;
    printf("cost time: %fs\n", timeuse / 1000000);
}

void initNetwork(int networkInputs, int networkOutputs, int *LayNum, int num) {
    cout << "Initializing the global model" << endl;
    _global_network = new Network(networkInputs, networkOutputs);
    for (int k = 0; k < num - 1; ++k) {
        _global_network->addLayer(LayNum[k + 1]);
    }

    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<> dis(-0.5, 0.5);
    for (int k = 0; k < _global_network->mNumLayers; ++k) {
        Layer *tmp = _global_network->mLayers[k];
        for (int i = 0; i < tmp->mNumNodes; ++i) {
            for (int j = 0; j < tmp->mNumInputNodes + 1; ++j) {
                tmp->mWeights[i][j] = dis(gen);
            }
        }
    }
}

char *getEncryptedWeight(int WSeqNum, int rowSeqNum, int colSeqNum) {
    int k = 1000000;
    int64_t tmp1;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);
    Layer *tmp3 = _global_network->mLayers[WSeqNum];
    int bColumnNum = tmp3->mNumInputNodes;
    if (colSeqNum == bColumnNum) {
        tmp1 = (int64_t)(tmp3->mWeights[rowSeqNum][colSeqNum] * k * k);
    } else {
        tmp1 = (int64_t)(tmp3->mWeights[rowSeqNum][colSeqNum] * k);
    }
    if (tmp1 < 0) {
        BN_set_word(tmp2, -tmp1);
        BN_set_negative(tmp2, 1);
    } else {
        BN_set_word(tmp2, tmp1);
    }
    char *cipherStr = new char[Q_BITS / 4 + 1000];
    she_encryptTeeStringBignum2(cipherStr, tmp2);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return cipherStr;
}

void encryptWeights(vector<string> &encryptedWeights) {
    char *cipherStr;
    for (int i = 0; i < _global_network->mNumLayers; ++i) {
        Layer *layer = _global_network->mLayers[i];
        for (int m = 0; m < layer->mNumNodes; m++) {
            for (int n = 0; n < layer->mNumInputNodes + 1; n++) {
                cipherStr = getEncryptedWeight(i, m, n);
                encryptedWeights.push_back(string(cipherStr));
                OPENSSL_free(cipherStr);
            }
        }
    }
    cout << endl << "Weights encrypted successfully." << endl;
}

void sendEncryptedWeights(int client_socket, const vector<string> &encryptedWeights) {
    // size_t numberOfStrings = encryptedWeights.size();
    // std::cout << "Number of strings in encryptedWeights: " << numberOfStrings << std::endl;
    for (const string &weight : encryptedWeights) {
        uint32_t length = htonl(weight.size());
        send(client_socket, &length, sizeof(length), 0);
        send(client_socket, weight.c_str(), weight.size(), 0);
    }
    cout << "Send encrypted weights successfully." << endl;
}

void initializeClientWeights(vector<vector<vector<vector<BIGNUM *>>>> &clientWeights, int clientCount) {
    clientWeights.resize(clientCount);
    for (int clientIdx = 0; clientIdx < clientCount; ++clientIdx) {
        clientWeights[clientIdx].resize(_global_network->mNumLayers);
        for (int layerIdx = 0; layerIdx < _global_network->mNumLayers; ++layerIdx) {
            int numNodes = _global_network->mLayers[layerIdx]->mNumNodes;
            int numWeights = _global_network->mLayers[layerIdx]->mNumInputNodes + 1;
            clientWeights[clientIdx][layerIdx].resize(numNodes);
            for (int nodeIdx = 0; nodeIdx < numNodes; ++nodeIdx) {
                clientWeights[clientIdx][layerIdx][nodeIdx].resize(numWeights);
                for (int weightIdx = 0; weightIdx < numWeights; ++weightIdx) {
                    clientWeights[clientIdx][layerIdx][nodeIdx][weightIdx] = BN_new();
                }
            }
        }
    }
}

void clearClientWeights(vector<vector<vector<vector<BIGNUM *>>>> &clientWeights, int clientCount) {
    for (int clientIdx = 0; clientIdx < clientCount; ++clientIdx) {
        for (int layerIdx = 0; layerIdx < _global_network->mNumLayers; ++layerIdx) {
            for (int nodeIdx = 0; nodeIdx < _global_network->mLayers[layerIdx]->mNumNodes; ++nodeIdx) {
                for (int weightIdx = 0; weightIdx < (_global_network->mLayers[layerIdx]->mNumInputNodes + 1);
                     ++weightIdx) {
                    BN_free(clientWeights[clientIdx][layerIdx][nodeIdx][weightIdx]);
                }
            }
        }
    }
}

void clearSocketBuffer(int client_socket) {
    char buffer[1024];
    int flags = fcntl(client_socket, F_GETFL, 0);
    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

    while (recv(client_socket, buffer, sizeof(buffer), 0) > 0) {
    }

    fcntl(client_socket, F_SETFL, flags);
}

void waitForAck(int client_socket, int clientIdx) {
    char buffer[4];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        if (strcmp(buffer, "ACK") == 0) {
            cout << "Received ACK from client" << clientIdx + 1 << endl;
        } else {
            cout << "Unexpected message: " << buffer << endl;
        }
    } else if (bytes_received == 0) {
        cout << "client" << clientIdx + 1 << " closed the connection." << endl;
    } else {
        perror("recv");
    }
}

void receiveProcessedWeights(int client_socket, vector<vector<vector<vector<BIGNUM *>>>> &clientWeights,
                             int clientIdx) {
    char buffer[Q_BITS / 4 + 1000];
    int bytes_received;
    int layerIndex = 0, nodeIndex = 0, weightIndex = 0;

    int idx = 0;
    int totalWeights = 0;
    for (int i = 0; i < _global_network->mNumLayers; i++) {
        totalWeights += _global_network->mLayers[i]->mNumNodes * (_global_network->mLayers[i]->mNumInputNodes + 1);
    }
    // cout << "totalWeights: " << totalWeights << endl;

    cout << "Starting recv from client" << clientIdx + 1 << endl;
    while (idx < totalWeights) {
        uint32_t length;
        if (recv(client_socket, &length, sizeof(length), 0) <= 0) {
            perror("recv length");
            break;
        }
        length = ntohl(length);

        size_t total_received = 0;
        while (total_received < length) {
            bytes_received = recv(client_socket, buffer + total_received, length - total_received, 0);
            if (bytes_received <= 0) {
                perror("recv data");
                break;
            }
            total_received += bytes_received;
        }

        buffer[length] = '\0';
        BIGNUM *bn = BN_new();
        BN_hex2bn(&bn, buffer);

        if (layerIndex >= _global_network->mNumLayers || nodeIndex >= _global_network->mLayers[layerIndex]->mNumNodes ||
            weightIndex >= (_global_network->mLayers[layerIndex]->mNumInputNodes + 1)) {
            printf("Index out of range: layerIndex: %d, nodeIndex: %d, weightIndex: %d\n", layerIndex, nodeIndex,
                   weightIndex);
            BN_free(bn);
            break;
        }

        BN_copy(clientWeights[clientIdx][layerIndex][nodeIndex][weightIndex], bn);
        BN_free(bn);

        weightIndex++;
        if (weightIndex >= _global_network->mLayers[layerIndex]->mNumInputNodes + 1) {
            weightIndex = 0;
            nodeIndex++;
            if (nodeIndex >= _global_network->mLayers[layerIndex]->mNumNodes) {
                nodeIndex = 0;
                layerIndex++;
            }
        }
        idx++;
    }

    if (bytes_received < 0) {
        perror("recv");
    } else if (bytes_received == 0) {
        printf("Connection closed by the client\n");
    }
    cout << "Ending recv from client" << clientIdx + 1 << endl;

    clearSocketBuffer(client_socket);
    const char *ack = "ACK";
    if (send(client_socket, ack, strlen(ack), 0) == -1) {
        perror("send");
    }
}

void aggregateWeights(int clientCount, vector<vector<vector<vector<BIGNUM *>>>> &clientWeights) {
    int k = 1000000;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *plain = BN_CTX_get(ctx);
    int64_t tmp1 = 0;
    double tmp2;

    cout << "Starting aggregation" << endl;
    for (int i = 0; i < _global_network->mNumLayers; ++i) {
        Layer *layer = _global_network->mLayers[i];
        int bColumnNum = layer->mNumInputNodes;
        for (int m = 0; m < layer->mNumNodes; m++) {
            for (int n = 0; n < layer->mNumInputNodes + 1; n++) {
                double sum = 0.0;
                for (int c = 0; c < clientCount; ++c) {
                    she_decryptBignum(plain, clientWeights[c][i][m][n], &KEY, ctx);
                    if (!plain) {
                        cerr << "Error: she_decryptBignum returned null" << endl;
                    }
                    int result = BN_bn2lebinpad(plain, (unsigned char *)&tmp1, sizeof(int64_t));
                    if (result == -1) {
                        cerr << "BN_bn2lebinpad failed" << endl;
                    }

                    if (BN_is_negative(plain)) {
                        tmp1 = -tmp1;
                    }

                    if (n == bColumnNum) {
                        tmp2 = ((double)tmp1) / k;
                        tmp2 = tmp2 / k;
                    } else {
                        tmp2 = ((double)tmp1) / k;
                    }
                    sum += tmp2;
                }
                layer->mWeights[m][n] = sum / clientCount;
            }
        }
    }
    cout << "Ending aggregation" << endl;

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void serverInteraction(int port, int clientCount, int globalEpoch, int localEpoch, double lr, int testNumImages,
                       const char *testPath, const char *weightPath) {
    int server_fd, client_sockets[clientCount];
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, clientCount) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    srand(time(0));
    int randomNumber = rand() % 10000;
    char fullPath[256];
    snprintf(fullPath, sizeof(fullPath), "%s_%04d", weightPath, randomNumber);

    vector<vector<vector<vector<BIGNUM *>>>> clientWeights;
    initializeClientWeights(clientWeights, clientCount);

    for (int i = 0; i < clientCount; ++i) {
        if ((client_sockets[i] = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Accept");
            exit(EXIT_FAILURE);
        }

        send(client_sockets[i], &globalEpoch, sizeof(globalEpoch), 0);
        send(client_sockets[i], &localEpoch, sizeof(localEpoch), 0);
        send(client_sockets[i], &lr, sizeof(lr), 0);
    }

    for (int iteration = 0; iteration < globalEpoch / localEpoch; ++iteration) {
        vector<string> encryptedWeights;
        encryptWeights(encryptedWeights);

        for (int i = 0; i < clientCount; ++i) {
            sendEncryptedWeights(client_sockets[i], encryptedWeights);
        }

        for (int i = 0; i < clientCount; ++i) {
            waitForAck(client_sockets[i], i);
        }

        for (int i = 0; i < clientCount; ++i) {
            receiveProcessedWeights(client_sockets[i], clientWeights, i);
        }

        aggregateWeights(clientCount, clientWeights);
        testAccuracy(testPath, testNumImages, fullPath, iteration);

        encryptedWeights.clear();
    }

    for (int i = 0; i < clientCount; ++i) {
        close(client_sockets[i]);
    }

    close(server_fd);
    clearClientWeights(clientWeights, clientCount);
}

int readInXY(const char *path, double ***X, int **Y, int num, int inputDim) {
    ifstream readdata;
    double **tmpx = new double *[num];
    int *tmpy = new int[num];
    for (int i = 0; i < num; ++i) {
        tmpx[i] = new double[inputDim];
    }
    readdata.open(path);
    if (readdata.is_open()) {
        for (int j = 0; j < num; ++j) {
            string oneLine;
            getline(readdata, oneLine);
            stringstream ss(oneLine);
            ss >> tmpy[j];
            for (int i = 0; i < inputDim; ++i) {
                ss >> tmpx[j][i];
            }
        }
    } else {
        cout << "open file failed." << endl;
        return 0;
    }
    readdata.close();
    *X = tmpx;
    *Y = tmpy;
    return 1;
}

int validate(Network *network, int imageNum, double **TEST_X, int *TEST_Y) {
    int rightNum = 0;
    double *tempInput = new double[network->mNumInputs];
    int label;
    network->mTrain = false;
    for (int i = 0; i < imageNum; ++i) {
        if (i % (imageNum / 10) == 0 && i != imageNum - 1)
            cout << setfill('=') << setw(2) << ">" << (i / (imageNum / 10)) * 10 << "%" << flush;
        if (i == imageNum - 1)
            cout << "====>100%" << endl;
        for (int n = 0; n < network->mNumInputs; ++n) {
            tempInput[n] = TEST_X[i][n];
        }
        label = TEST_Y[i];

        network->compute(tempInput, label);
        double *out = network->mOutputs;
        int typeId;
        if (out[0] > 0.5) {
            typeId = 1;
        } else {
            typeId = 0;
        }
        if (typeId == label) {
            rightNum++;
        }
    }
    delete[] tempInput;
    return rightNum;
}

// 保存各层权重到文件
void saveWeight(string file, Network *network) {
    ofstream outfile(file);
    if (!outfile.is_open()) {
        cout << "open weight file failed!" << endl;
        exit(-1);
    }
    for (int i = 0; i < network->mNumLayers; ++i) {
        Layer *layer = network->mLayers[i];
        for (int m = 0; m < layer->mNumNodes; ++m) {
            for (int n = 0; n < layer->mNumInputNodes + 1; ++n) {
                outfile << layer->mWeights[m][n] << " ";
            }
        }
    }
    outfile.close();
    cout << "save weight file to <" << file << "> done." << endl;
}

void testAccuracy(const char *testPath, int testNumImages, const char *weightPath, int i) {
    double **TEST_X;
    int *TEST_Y;

    int networkInputs = _global_network->mNumInputs;
    readInXY(testPath, &TEST_X, &TEST_Y, testNumImages, networkInputs);

    cout << "\nvalidate...";
    int correct = validate(_global_network, testNumImages, TEST_X, TEST_Y);
    cout << "validate accuracy: " << (double)correct / testNumImages * 100 << "%, true: " << correct
         << ", total: " << testNumImages << endl;

    double currAccuracy = (double)correct / testNumImages;
    if (currAccuracy > 0.9 && currAccuracy > bestaccuracy) {
        bestaccuracy = currAccuracy;
        saveWeight(weightPath, _global_network);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <dataset_name>" << endl;
        return 1;
    }
    const char *datasetName = argv[1];

    she_generateRandomKeysTee2();

    int networkInputs = 0;
    int testNumImages = 0;
    const char *testPath = nullptr;
    const char *weightPath = nullptr;

    if (strcmp(datasetName, "WIBreast") == 0) {
        networkInputs = 30;
        testNumImages = 114;
        testPath = "../dataset/WIBreastData/breast_cancer_test.txt";
        weightPath = "../dataset/WIBreastData/weight/trained.weight";
    } else if (strcmp(datasetName, "stroke") == 0) {
        networkInputs = 10;
        testNumImages = 240;
        testPath = "../dataset/strokeData/stroke_test.txt";
        weightPath = "../dataset/strokeData/weight/trained.weight";
    } else if (strcmp(datasetName, "bank") == 0) {
        networkInputs = 16;
        testNumImages = 200;
        testPath = "../dataset/bankData/bank_test.txt";
        weightPath = "../dataset/bankData/weight/trained.weight";
    } else {
        cerr << "Unknown dataset name: " << datasetName << endl;
        return 1;
    }

    int networkOutputs = 1;
    int LayNum[] = {networkInputs, 5, networkOutputs};
    int numLayers = sizeof(LayNum) / sizeof(LayNum[0]);

    initNetwork(networkInputs, networkOutputs, LayNum, numLayers);

    int port = 13006;
    int clientCount = 3;
    int globalEpoch = 9;
    int localEpoch = 3;
    double lr = 0.3;

    struct timeval t1, t2;
    timeStart(&t1);
    serverInteraction(port, clientCount, globalEpoch, localEpoch, lr, testNumImages, testPath, weightPath);
    timeEnd(&t1, &t2);

    return 0;
}
