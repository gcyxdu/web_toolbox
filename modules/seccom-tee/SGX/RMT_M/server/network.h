#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <vector>
#include "layer.h"

class Network {
public:
    Network(int numInputs, int numOutputs);
    ~Network();
    void addLayer(int numNodes, ACTIVATION activate = SIGMOID);
    void forwardNetwork(double *input, int label);
    void backwardNetwork();
    void compute(double *input, int label);

public:
    bool mTrain;
    int mEpoches;
    int mNumInputs;
    int mNumOutputs;
    int mNumLayers;
    double mLearningRate;
    double mErrorSum;
    double *mInputs;
    double *mOutputs;
    int mSum;
    std::vector<Layer *> mLayers;
};

#endif
