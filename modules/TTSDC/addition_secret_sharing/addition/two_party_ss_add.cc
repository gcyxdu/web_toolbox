#include "experiment/mpc/addition/two_party_ss_add.h"

#include <cstring>
#include <limits>

#include "yacl/crypto/rand.h"

namespace secretflow::experiment::addition {

namespace {

inline uint64_t ApplyMask(uint64_t v, uint64_t mask) { return v & mask; }

}  // namespace

TwoPartySSAdd::TwoPartySSAdd(std::shared_ptr<yacl::link::Context> lctx,
                             size_t bitlen)
    : lctx_(std::move(lctx)), bitlen_(bitlen), mask_(RingMask(bitlen)) {
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  CheckTwoPartyOrThrow();
}

void TwoPartySSAdd::CheckTwoPartyOrThrow() const {
  YACL_ENFORCE(bitlen_ >= 1 && bitlen_ <= 64, "bitlen must be in [1,64], got {}",
               bitlen_);
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  YACL_ENFORCE(lctx_->WorldSize() == 2, "requires WorldSize()==2, got {}",
               lctx_->WorldSize());
  YACL_ENFORCE(lctx_->Rank() < 2, "invalid rank {}", lctx_->Rank());
}

uint64_t TwoPartySSAdd::RingMask(size_t bitlen) {
  YACL_ENFORCE(bitlen >= 1 && bitlen <= 64, "bitlen must be in [1,64], got {}",
               bitlen);
  if (bitlen == 64) {
    return std::numeric_limits<uint64_t>::max();
  }
  return (uint64_t{1} << bitlen) - 1;
}

uint64_t TwoPartySSAdd::AddMod(uint64_t a, uint64_t b, size_t bitlen) {
  const uint64_t mask = RingMask(bitlen);
  return (a + b) & mask;
}

uint64_t TwoPartySSAdd::SubMod(uint64_t a, uint64_t b, size_t bitlen) {
  const uint64_t mask = RingMask(bitlen);
  return (a - b) & mask;
}

yacl::Buffer TwoPartySSAdd::PackU64(uint64_t v) {
  yacl::Buffer buf(static_cast<int64_t>(sizeof(uint64_t)));
  std::memcpy(buf.data<void>(), &v, sizeof(uint64_t));
  return buf;
}

uint64_t TwoPartySSAdd::UnpackU64(const yacl::Buffer& buf) {
  YACL_ENFORCE(buf.size() == static_cast<int64_t>(sizeof(uint64_t)),
               "buffer size mismatch, expect {}, got {}", sizeof(uint64_t),
               buf.size());
  uint64_t v = 0;
  std::memcpy(&v, buf.data<const void>(), sizeof(uint64_t));
  return v;
}

ArithShare TwoPartySSAdd::ShareInput(uint64_t x, size_t owner_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(owner_rank < 2, "owner_rank must be 0 or 1");

  const size_t my_rank = lctx_->Rank();
  const size_t peer = lctx_->NextRank();  // in 2-party: peer = 1-rank

  // Both parties must call NextId() in the same order for consistent tags.
  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_add/share_input/" + round_id;

  if (my_rank == owner_rank) {
    // r <-R Z_{2^l}
    uint64_t r = yacl::crypto::SecureRandU64();
    r = ApplyMask(r, mask_);

    const uint64_t x_m = ApplyMask(x, mask_);
    const uint64_t other = SubMod(x_m, r, bitlen_);

    // Send other's share to peer. Use Buffer&& overload: SendAsync(dst, Buffer&&, tag)
    lctx_->SendAsync(peer, PackU64(other), tag);
    return ArithShare{r, bitlen_};
  } else {
    // Receive share from owner.
    yacl::Buffer buf = lctx_->Recv(owner_rank, tag);
    const uint64_t s = ApplyMask(UnpackU64(buf), mask_);
    return ArithShare{s, bitlen_};
  }
}

ArithShare TwoPartySSAdd::Add(const ArithShare& a, const ArithShare& b) const {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(a.bitlen == bitlen_ && b.bitlen == bitlen_,
               "bitlen mismatch: a={}, b={}, self={}", a.bitlen, b.bitlen,
               bitlen_);

  const uint64_t v = AddMod(ApplyMask(a.value, mask_), ApplyMask(b.value, mask_),
                            bitlen_);
  return ArithShare{v, bitlen_};
}

uint64_t TwoPartySSAdd::RevealToAll(const ArithShare& a) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(a.bitlen == bitlen_, "bitlen mismatch: a={}, self={}", a.bitlen,
               bitlen_);

  const size_t peer = lctx_->NextRank();
  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_add/reveal/" + round_id;

  const uint64_t my_s = ApplyMask(a.value, mask_);

  // Both parties send then recv: use SendAsync to avoid deadlock.
  lctx_->SendAsync(peer, PackU64(my_s), tag);

  yacl::Buffer peer_buf = lctx_->Recv(peer, tag);
  const uint64_t peer_s = ApplyMask(UnpackU64(peer_buf), mask_);

  return AddMod(my_s, peer_s, bitlen_);
}

}  // namespace secretflow::experiment::addition
