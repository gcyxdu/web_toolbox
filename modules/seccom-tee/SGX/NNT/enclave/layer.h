// layer.h
#ifndef __LAYER_H__
#define __LAYER_H__

using namespace std;
typedef enum { SIGMOID, RELU, LEAKY } ACTIVATION;

class Layer {
public:
    Layer(int numNodes, int numInputNodes, ACTIVATION activate = SIGMOID);
    ~Layer();
    void forwardLayer(double *inputs);
    void init();

public:
    int mNumNodes;
    int mNumInputNodes;
    ACTIVATION mActivate;
    double **mWeights;
    double *mOutputs;
    double *mDelta;
};

#endif
