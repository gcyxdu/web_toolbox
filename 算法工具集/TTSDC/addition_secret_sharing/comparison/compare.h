#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "yacl/base/buffer.h"
#include "yacl/link/context.h"

#include "experiment/mpc/comparison/and.h"
#include "experiment/mpc/comparison/b2a.h"
#include "experiment/mpc/comparison/types.h"

namespace secretflow::experiment::comparison {

// Two-party secure compare (z=1 if x<y else 0) using:
// 1) compute (x-y)^A shares
// 2) carry-chain with Boolean ANDs (per your figure)
// 3) B2A on the final bit
class TwoPartySSCompare final {
 public:
  TwoPartySSCompare(std::shared_ptr<yacl::link::Context> lctx, size_t bitlen);

  // Share private input x owned by owner_rank.
  ArithShare ShareInput(uint64_t x, size_t owner_rank);

  // Reveal arithmetic share to both.
  uint64_t RevealToAll(const ArithShare& a);

  // Secure compare: returns arithmetic share of z in Z_{2^bitlen} (z in {0,1}).
  ArithShare LessThan(const ArithShare& x, const ArithShare& y);

 private:
  void CheckTwoPartyOrThrow() const;

  static yacl::Buffer PackU64(uint64_t v);
  static uint64_t UnpackU64(const yacl::Buffer& buf);

 private:
  std::shared_ptr<yacl::link::Context> lctx_;
  size_t bitlen_ = 0;
  uint64_t mask_ = 0;

  BooleanAnd and_;
  B2AConverter b2a_;
};

}  // namespace secretflow::experiment::comparison
