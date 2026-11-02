#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "yacl/base/exception.h"

namespace secretflow::experiment::comparison {

struct ArithShare {
  uint64_t value = 0;  // share in Z_{2^bitlen}
  size_t bitlen = 0;
};

struct BoolShare {
  bool value = false;  // xor-share bit
};

struct BoolWordShare {
  uint64_t value = 0;  // xor-share word (bitlen bits used)
  size_t bitlen = 0;
};

inline uint64_t RingMask(size_t bitlen) {
  YACL_ENFORCE(bitlen >= 1 && bitlen <= 64, "bitlen must be in [1,64], got {}",
               bitlen);
  if (bitlen == 64) {
    return std::numeric_limits<uint64_t>::max();
  }
  return (uint64_t{1} << bitlen) - 1;
}

inline uint64_t AddMod(uint64_t a, uint64_t b, size_t bitlen) {
  return (a + b) & RingMask(bitlen);
}

inline uint64_t SubMod(uint64_t a, uint64_t b, size_t bitlen) {
  return (a - b) & RingMask(bitlen);
}

inline bool GetBit(uint64_t v, size_t idx) {
  return ((v >> idx) & 1ULL) != 0;
}

}  // namespace secretflow::experiment::comparison
