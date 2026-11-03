#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/link/context.h"

#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"

namespace secretflow::experiment::multiplication {

// Additive share over ring Z_{2^l}.
struct ArithShare {
  uint64_t value = 0;
  size_t bitlen = 0;
};

// Beaver triple share (a_i, b_i, c_i) where c = a*b over Z_{2^l}.
struct BeaverTripleShare {
  uint64_t a = 0;
  uint64_t b = 0;
  uint64_t c = 0;
  size_t bitlen = 0;
};

class TwoPartySSMul final {
 public:
  TwoPartySSMul(std::shared_ptr<yacl::link::Context> lctx, size_t bitlen);

  size_t BitLen() const { return bitlen_; }
  uint64_t Mask() const { return mask_; }

  // Local ring ops
  static uint64_t RingMask(size_t bitlen);
  static uint64_t AddMod(uint64_t a, uint64_t b, size_t bitlen);
  static uint64_t SubMod(uint64_t a, uint64_t b, size_t bitlen);

  // Share private input x owned by owner_rank (0/1).
  // Both parties call. Owner provides x; non-owner can pass any value.
  ArithShare ShareInput(uint64_t x, size_t owner_rank);

  // Multiply two secret shared values using Beaver triple where triple is
  // generated via OT (offline inside this call).
  ArithShare Mul(const ArithShare& x, const ArithShare& y);

  // Reveal to both parties.
  uint64_t RevealToAll(const ArithShare& a);

 private:
  void CheckTwoPartyOrThrow() const;

  // -------------------------
  // Packing helpers
  // -------------------------
  static yacl::Buffer PackU64(uint64_t v);
  static uint64_t UnpackU64(const yacl::Buffer& buf);

  static yacl::Buffer PackU64x2(uint64_t a, uint64_t b);
  static void UnpackU64x2(const yacl::Buffer& buf, uint64_t* a, uint64_t* b);

  // -------------------------
  // Ring multiplication mod 2^l
  // -------------------------
  uint64_t MulMod(uint64_t a, uint64_t b) const;

  // -------------------------
  // OT infra (base OT + IKNP)
  // -------------------------
  static constexpr uint32_t kKappa = 128;  // IKNP base OT count

  void SetupBaseOtsOnce();

  // Derive a 64-bit pad from a 128-bit OT key (uses yacl::crypto::FillPRand).
  static uint64_t DerivePad64(yacl::crypto::Block key);

  // One batch of 1-out-of-2 “message OT” of uint64 over Z_{2^l},
  // implemented via IKNP Key-OT + PRG masking + sending ciphertext pairs.
  //
  // Sender inputs: m0[i], m1[i]; Receiver inputs: choice bits.
  //
  // - If sender_rank==0, direction is P0(sender)->P1(receiver).
  // - If sender_rank==1, direction is P1(sender)->P0(receiver).
  //
  // Return: receiver gets chosen messages; sender gets nothing from this API
  // (sender can compute its own share separately).
  std::vector<uint64_t> MessageOtRecvU64(const yacl::dynamic_bitset<uint128_t>& choices,
                                        size_t sender_rank);

  void MessageOtSendU64(absl::Span<const uint64_t> m0,
                        absl::Span<const uint64_t> m1,
                        size_t sender_rank);

  // OT-based multiplication share:
  // Compute shares w0, w1 such that w0+w1 = u*v (mod 2^l),
  // where sender holds u and receiver holds v.
  //
  // Both parties call with:
  // - if Rank()==sender_rank: u_or_v is u
  // - else: u_or_v is v
  //
  // Returns this party’s share.
  uint64_t OtMulShare(uint64_t u_or_v, size_t sender_rank);

  // Generate one Beaver triple share using 2 OT-muls for cross terms.
  BeaverTripleShare GenBeaverTriple();

 private:
  std::shared_ptr<yacl::link::Context> lctx_;
  size_t bitlen_ = 0;
  uint64_t mask_ = 0;

  // base OT stores for two directions:
  // dir 0->1: sender=0 uses base_recv_01_, receiver=1 uses base_send_01_
  // dir 1->0: sender=1 uses base_recv_10_, receiver=0 uses base_send_10_
  bool base_ot_ready_ = false;

  // Only one of these is valid on a given rank for a given direction, but we
  // store both types and populate according to Rank().
  yacl::crypto::OtRecvStore base_recv_01_;
  yacl::crypto::OtSendStore base_send_01_;

  yacl::crypto::OtRecvStore base_recv_10_;
  yacl::crypto::OtSendStore base_send_10_;
};

}  // namespace secretflow::experiment::multiplication
