// layer.cpp
#include "layer.h"

Layer::Layer(int numNodes, int numInputNodes, ACTIVATION activ)
    : mNumNodes(numNodes), mNumInputNodes(numInputNodes), mActivate(activ) {
    mWeights = new double *[mNumNodes];
    mOutputs = new double[mNumNodes];
    mDelta = new double[mNumNodes];
    init();
}

Layer::~Layer() {
    for (int i = 0; i < mNumNodes; ++i) {
        delete[] mWeights[i];
    }
    delete[] mOutputs;
    delete[] mDelta;
    delete[] mWeights;
}

void Layer::init() {
    for (int i = 0; i < mNumNodes; ++i) {
        mWeights[i] = new double[mNumInputNodes + 1];
    }
}
