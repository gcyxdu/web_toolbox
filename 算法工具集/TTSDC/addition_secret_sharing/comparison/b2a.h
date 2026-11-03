#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "yacl/link/context.h"

#include "experiment/mpc/comparison/ot_helper.h"
#include "experiment/mpc/comparison/types.h"

namespace secretflow::experiment::comparison {

// B2A: convert Bool xor-sharing to Arith additive sharing over Z_{2^ring_bitlen}.
// Uses OT exactly as described in your B2A figure (P0 sender, P1 receiver).
class B2AConverter final {
 public:
  B2AConverter(std::shared_ptr<yacl::link::Context> lctx, size_t ring_bitlen);

  // Convert a single bit BoolShare -> arithmetic share (0/1) in Z_{2^ring_bitlen}.
  ArithShare ConvertBit(const BoolShare& xb);

  // Convert an l-bit BoolWordShare (xor) -> arithmetic share in Z_{2^l}.
  // (This follows the "l OTs, weight 2^i" scheme in your image.)
  ArithShare ConvertWord(const BoolWordShare& xw);

 private:
  void CheckTwoPartyOrThrow() const;

 private:
  std::shared_ptr<yacl::link::Context> lctx_;
  size_t ring_bitlen_ = 0;
  uint64_t mask_ = 0;
  OtHelper ot_;
};

}  // namespace secretflow::experiment::comparison
