/**
 * 没有什么用处的明文操作的类，没有其他的方法
 * */
#include <array>
#include <vector>
using namespace std;


#ifndef plaintext_
#define plaintext_
namespace gtfhe{

    class Plaintext{
    public:
        uint64_t* coffe_data;
        size_t length;

        Plaintext(){}

    };
}


#endif