#include "experiment/mpc/comparison/ot_helper.h"

#include <cstring>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace secretflow::experiment::comparison {

OtHelper::OtHelper(std::shared_ptr<yacl::link::Context> lctx)
    : lctx_(std::move(lctx)) {
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  CheckTwoPartyOrThrow();

  // Make async sends non-blocking in tests/bench
  lctx_->SetThrottleWindowSize(0);

  SetupBaseOtsOnce();
}

void OtHelper::CheckTwoPartyOrThrow() const {
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  YACL_ENFORCE(lctx_->WorldSize() == 2, "requires WorldSize()==2, got {}",
               lctx_->WorldSize());
  YACL_ENFORCE(lctx_->Rank() < 2, "invalid rank {}", lctx_->Rank());
}

void OtHelper::SetupBaseOtsOnce() {
  if (base_ot_ready_) return;

  const size_t rank = lctx_->Rank();

  auto make_choices = [&](uint32_t nbits) {
    yacl::dynamic_bitset<uint128_t> ch(nbits);
    for (uint32_t i = 0; i < nbits; ++i) {
      ch[i] = (yacl::crypto::SecureRandU64() & 1) != 0;
    }
    return ch;
  };

  if (rank == 0) {
    // For direction 0->1: ext-sender needs OtRecvStore
    auto ch01 = make_choices(kKappa);
    base_recv_01_ = yacl::crypto::BaseOtRecv(lctx_, ch01, kKappa);

    // For direction 1->0: ext-receiver needs OtSendStore
    base_send_10_ = yacl::crypto::BaseOtSend(lctx_, kKappa);
  } else {
    // For direction 0->1: ext-receiver needs OtSendStore
    base_send_01_ = yacl::crypto::BaseOtSend(lctx_, kKappa);

    // For direction 1->0: ext-sender needs OtRecvStore
    auto ch10 = make_choices(kKappa);
    base_recv_10_ = yacl::crypto::BaseOtRecv(lctx_, ch10, kKappa);
  }

  base_ot_ready_ = true;
}

uint64_t OtHelper::DerivePad64(yacl::crypto::Block key) {
  uint64_t pad = 0;
  (void)yacl::crypto::FillPRand(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR,
      static_cast<uint128_t>(key),
      /*iv=*/0,
      /*count=*/0,
      reinterpret_cast<char*>(&pad),
      sizeof(pad));
  return pad;
}

yacl::Buffer OtHelper::PackU64Pairs(absl::Span<const uint64_t> c0,
                                   absl::Span<const uint64_t> c1) {
  YACL_ENFORCE(c0.size() == c1.size());
  const size_t n = c0.size();
  yacl::Buffer buf(static_cast<int64_t>(2ULL * n * sizeof(uint64_t)));
  auto* out = reinterpret_cast<uint8_t*>(buf.data<void>());
  for (size_t i = 0; i < n; ++i) {
    std::memcpy(out + (2ULL * i + 0) * sizeof(uint64_t), &c0[i], sizeof(uint64_t));
    std::memcpy(out + (2ULL * i + 1) * sizeof(uint64_t), &c1[i], sizeof(uint64_t));
  }
  return buf;
}

void OtHelper::UnpackU64Pairs(const yacl::Buffer& buf, size_t n,
                             std::vector<uint64_t>* c0,
                             std::vector<uint64_t>* c1) {
  YACL_ENFORCE(c0 != nullptr && c1 != nullptr);
  YACL_ENFORCE(buf.size() == static_cast<int64_t>(2ULL * n * sizeof(uint64_t)),
               "ciphertext size mismatch");
  c0->assign(n, 0);
  c1->assign(n, 0);
  const auto* in = reinterpret_cast<const uint8_t*>(buf.data<const void>());
  for (size_t i = 0; i < n; ++i) {
    std::memcpy(&(*c0)[i], in + (2ULL * i + 0) * sizeof(uint64_t), sizeof(uint64_t));
    std::memcpy(&(*c1)[i], in + (2ULL * i + 1) * sizeof(uint64_t), sizeof(uint64_t));
  }
}

void OtHelper::SendU64(size_t sender_rank, absl::Span<const uint64_t> m0,
                       absl::Span<const uint64_t> m1,
                       std::string_view tag_prefix) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(sender_rank < 2);
  YACL_ENFORCE(m0.size() == m1.size(), "m0/m1 size mismatch");
  YACL_ENFORCE(lctx_->Rank() == sender_rank, "SendU64 called on non-sender");

  const size_t n = m0.size();
  const size_t peer = lctx_->NextRank();

  // 1) IKNP Key-OT extension: sender obtains (k0,k1)
  std::vector<std::array<uint128_t, 2>> keys(n);
  if (sender_rank == 0) {
    yacl::crypto::IknpOtExtSend(lctx_, base_recv_01_, absl::MakeSpan(keys), false);
  } else {
    yacl::crypto::IknpOtExtSend(lctx_, base_recv_10_, absl::MakeSpan(keys), false);
  }

  // 2) Mask messages and send ciphertext pairs
  std::vector<uint64_t> c0(n), c1(n);
  for (size_t i = 0; i < n; ++i) {
    const uint64_t p0 = DerivePad64(keys[i][0]);
    const uint64_t p1 = DerivePad64(keys[i][1]);
    c0[i] = m0[i] ^ p0;
    c1[i] = m1[i] ^ p1;
  }

  const std::string tag =
      std::string(tag_prefix) + "/" + lctx_->NextId();
  lctx_->SendAsync(peer, PackU64Pairs(absl::MakeSpan(c0), absl::MakeSpan(c1)), tag);
}

std::vector<uint64_t> OtHelper::RecvU64(
    size_t sender_rank, const yacl::dynamic_bitset<uint128_t>& choices,
    std::string_view tag_prefix) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(sender_rank < 2);
  YACL_ENFORCE(lctx_->Rank() != sender_rank, "RecvU64 called on sender");

  const size_t n = choices.size();
  const size_t peer = lctx_->NextRank();

  // 1) IKNP Key-OT extension: receiver obtains k_choice
  std::vector<uint128_t> rkeys(n);
  if (sender_rank == 0) {
    yacl::crypto::IknpOtExtRecv(lctx_, base_send_01_, choices,
                               absl::MakeSpan(rkeys), false);
  } else {
    yacl::crypto::IknpOtExtRecv(lctx_, base_send_10_, choices,
                               absl::MakeSpan(rkeys), false);
  }

  // 2) Receive ciphertext pairs and decrypt chosen
  const std::string tag =
      std::string(tag_prefix) + "/" + lctx_->NextId();
  yacl::Buffer ct_buf = lctx_->Recv(peer, tag);

  std::vector<uint64_t> c0, c1;
  UnpackU64Pairs(ct_buf, n, &c0, &c1);

  std::vector<uint64_t> out(n);
  for (size_t i = 0; i < n; ++i) {
    const uint64_t pad = DerivePad64(rkeys[i]);
    out[i] = (choices[i] ? c1[i] : c0[i]) ^ pad;
  }
  return out;
}

}  // namespace secretflow::experiment::comparison
