#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/buffer.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/link/context.h"

#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"

namespace secretflow::experiment::comparison {

// IKNP outputs Key-OT/ROT keys; we wrap it into "message OT" by
// PRG(key)->pad and sending ciphertext pairs via link::Context.
class OtHelper final {
 public:
  static constexpr uint32_t kKappa = 128;

  explicit OtHelper(std::shared_ptr<yacl::link::Context> lctx);

  // Message OT over uint64 ring values (receiver obtains chosen messages).
  // sender_rank indicates direction (0->1 or 1->0).
  void SendU64(size_t sender_rank, absl::Span<const uint64_t> m0,
               absl::Span<const uint64_t> m1, std::string_view tag_prefix);

  std::vector<uint64_t> RecvU64(size_t sender_rank,
                                const yacl::dynamic_bitset<uint128_t>& choices,
                                std::string_view tag_prefix);

 private:
  void CheckTwoPartyOrThrow() const;
  void SetupBaseOtsOnce();

  static uint64_t DerivePad64(yacl::crypto::Block key);

  static yacl::Buffer PackU64Pairs(absl::Span<const uint64_t> c0,
                                   absl::Span<const uint64_t> c1);
  static void UnpackU64Pairs(const yacl::Buffer& buf, size_t n,
                             std::vector<uint64_t>* c0,
                             std::vector<uint64_t>* c1);

 private:
  std::shared_ptr<yacl::link::Context> lctx_;
  bool base_ot_ready_ = false;

  // Direction 0->1
  yacl::crypto::OtRecvStore base_recv_01_;  // on rank0
  yacl::crypto::OtSendStore base_send_01_;  // on rank1

  // Direction 1->0
  yacl::crypto::OtRecvStore base_recv_10_;  // on rank1
  yacl::crypto::OtSendStore base_send_10_;  // on rank0
};

}  // namespace secretflow::experiment::comparison
