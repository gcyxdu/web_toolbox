// network.cpp
#include "network.h"

Network::Network(int epoches, float learningRate, int numInputs, int numOutputs)
    : mEpoches(epoches), mNumInputs(numInputs), mNumOutputs(numOutputs), mLearningRate(learningRate) {
    mNumLayers = 0;
    mErrorSum = 0;
    mInputs = NULL;
    mOutputs = NULL;
}

Network::~Network() {
    for (int i = 0; i < mNumLayers; ++i) {
        if (mLayers[i]) {
            delete mLayers[i];
        }
    }
}

void Network::addLayer(int numNodes, ACTIVATION activate) {
    int numInputNodes = (mNumLayers > 0) ? mLayers[mNumLayers - 1]->mNumNodes : mNumInputs;
    mLayers.push_back(new Layer(numNodes, numInputNodes, activate));
    mNumLayers++;
}
