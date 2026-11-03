
#include "network.h"

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

void Network::forwardNetwork(double* inputs, int label) {
    for (int i = 0; i < mNumLayers; ++i) {
        mLayers[i]->forwardLayer(inputs);
        inputs = mLayers[i]->mOutputs;
    }
    mOutputs = inputs;
    if (!mTrain)
        return;
}

void Network::compute(double* inputs, int label) {
    mInputs = inputs;
    forwardNetwork(inputs, label);
    if (!mTrain) {
        return;
    }
}
