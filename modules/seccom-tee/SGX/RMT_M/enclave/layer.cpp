
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

void Layer::forwardLayer(double *inputs) {
    for (int m = 0; m < mNumNodes; ++m) {
        double *curWeights = mWeights[m];
        double tmp1 = 0;
        int n;
        for (n = 0; n < mNumInputNodes; ++n) {
            tmp1 += curWeights[n] * inputs[n];
        }
        tmp1 += curWeights[n];
        mOutputs[m] = tmp1;
    }
}
