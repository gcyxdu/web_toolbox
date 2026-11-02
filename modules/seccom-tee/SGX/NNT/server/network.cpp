// network.cpp
#include "network.h"
#include <cmath>
#include <cstring>

Network::Network(int numInputs, int numOutputs) : mNumInputs(numInputs), mNumOutputs(numOutputs) {
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

void Network::forwardNetwork(double *input, int label) {
    for (int i = 0; i < mNumLayers; ++i) {
        mLayers[i]->forwardLayer(input);
        input = mLayers[i]->mOutputs;
    }
    mOutputs = input;

    if (!mTrain)
        return;

    double *delta = mLayers[mNumLayers - 1]->mDelta;
    double err;
    delta[0] = label - mOutputs[0];
    err = -(label * log(mOutputs[0]) + (1 - label) * log(1 - mOutputs[0]));
    mErrorSum += err;
}

void Network::backwardNetwork() {
    double *prevOutput = nullptr;
    double *prevDelta = nullptr;
    for (int i = mNumLayers - 1; i >= 0; --i) {
        if (i > 0) {
            prevOutput = mLayers[i - 1]->mOutputs;
            prevDelta = mLayers[i - 1]->mDelta;
            memset(prevDelta, 0, mLayers[i - 1]->mNumNodes * sizeof(double));
        } else {
            prevOutput = mInputs;
            prevDelta = nullptr;
        }
        mLayers[i]->backwardLayer(prevOutput, prevDelta, mLearningRate);
    }
}

void Network::compute(double *input, int label) {
    mInputs = input;
    forwardNetwork(mInputs, label);
    if (!mTrain) {
        return;
    }
    backwardNetwork();
}
