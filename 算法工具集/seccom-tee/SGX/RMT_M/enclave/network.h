#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <vector>
#include "layer.h"

class Network {
public:
    Network(int numInputs, int numOutputs);
    ~Network();
    void compute(double *inputs, int label = 10);
    void addLayer(int numNodes, ACTIVATION activate = SIGMOID);

private:
    void forwardNetwork(double *inputs, int label);

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
    vector<Layer *> mLayers;
};

#endif
