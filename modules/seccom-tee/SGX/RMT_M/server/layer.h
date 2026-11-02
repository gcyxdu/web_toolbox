// layer.h
#ifndef __LAYER_H__
#define __LAYER_H__

typedef enum { SIGMOID, RELU, LEAKY, SOFTMAX } ACTIVATION;

class Layer {
public:
    Layer(int numNodes, int numInputNodes, ACTIVATION activate = SIGMOID);
    ~Layer();
    void init();
    void forwardLayer(double *inputs);
    void backwardLayer(double *prevOutput, double *prevDelta, double learningRate);

private:
    inline double active(double x, ACTIVATION activate);

public:
    int mNumNodes;
    int mNumInputNodes;
    ACTIVATION mActivate;
    double **mWeights;
    double *mOutputs;
    double *mDelta;
};

#endif
