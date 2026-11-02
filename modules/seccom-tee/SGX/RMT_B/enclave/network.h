#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <vector>
#include "layer.h"

class Network {
public:
    Network(int epoches, float learningRate, int numInputs, int numOutputs);
    ~Network();
    void addLayer(int numNodes, ACTIVATION activate = SIGMOID);

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
