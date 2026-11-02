// layer.cpp
#include "layer.h"
#include <cmath>
#include <iostream>

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

double Layer::active(double z, ACTIVATION activate) {
    switch (activate) {
        case SIGMOID:
            return (1.0 / (1.0 + exp(-z)));
        case RELU:
            return z * (z > 0);
        case SOFTMAX:
            return z;
        default:
            std::cout << "no activation" << std::endl;
            return z;
    }
}

void Layer::forwardLayer(double *input) {
    for (int i = 0; i < mNumNodes; ++i) {
        double *curWeight = mWeights[i];
        double y = 0;
        int j = 0;
        for (; j < mNumInputNodes; ++j) {
            y += curWeight[j] * input[j];
        }
        y += curWeight[j];

        mOutputs[i] = active(y, mActivate);
    }

    double sum = 0.0;
    for (int i = 0; i < mNumNodes; ++i) {
        sum += exp(mOutputs[i]);
    }
    for (int i = 0; i < mNumNodes; ++i) {
        mOutputs[i] = exp(mOutputs[i]) / sum;
    }
}

void Layer::backwardLayer(double *prevOutput, double *prevDelta, double learningRate) {
    for (int i = 0; i < mNumNodes; ++i) {
        double *curWeights = mWeights[i];
        int j = 0;
        for (; j < mNumInputNodes; j++) {
            if (prevDelta) {
                prevDelta[j] += curWeights[j] * mDelta[i];
            }
            curWeights[j] += mDelta[i] * learningRate * prevOutput[j];
        }
        curWeights[j] += mDelta[i] * learningRate;
    }
}
