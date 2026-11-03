#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/link/context.h"

namespace secretflow::experiment::addition {

// Additive share over ring Z_{2^l}.
struct ArithShare {
  uint64_t value = 0;
  size_t bitlen = 0;
};

// Two-party additive secret sharing addition protocol over Z_{2^l}.
class TwoPartySSAdd final {
 public:
  TwoPartySSAdd(std::shared_ptr<yacl::link::Context> lctx, size_t bitlen);

  size_t BitLen() const { return bitlen_; }
  uint64_t Mask() const { return mask_; }

  // Local ring ops
  static uint64_t RingMask(size_t bitlen);
  static uint64_t AddMod(uint64_t a, uint64_t b, size_t bitlen);
  static uint64_t SubMod(uint64_t a, uint64_t b, size_t bitlen);

  // Secret-share a private input x owned by owner_rank (0/1).
  // Both parties call. Owner provides x; non-owner can pass any value.
  ArithShare ShareInput(uint64_t x, size_t owner_rank);

  // Local add of two shares (no communication).
  ArithShare Add(const ArithShare& a, const ArithShare& b) const;

  // Reveal secret to both parties (both parties call, both get cleartext).
  uint64_t RevealToAll(const ArithShare& a);

 private:
  void CheckTwoPartyOrThrow() const;

  static yacl::Buffer PackU64(uint64_t v);
  static uint64_t UnpackU64(const yacl::Buffer& buf);

  std::shared_ptr<yacl::link::Context> lctx_;
  size_t bitlen_ = 0;
  uint64_t mask_ = 0;
};

}  // namespace secretflow::experiment::addition
