#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Plaintext结构体，替代C++中的类
typedef struct {
    uint64_t* coffe_data;
    size_t length;
} Plaintext;

#ifdef __cplusplus
}
#endif

#endif // PLAINTEXT_H
