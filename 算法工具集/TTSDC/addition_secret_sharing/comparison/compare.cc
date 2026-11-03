#include "experiment/mpc/comparison/compare.h"

#include <cstring>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand.h"

namespace secretflow::experiment::comparison {

TwoPartySSCompare::TwoPartySSCompare(std::shared_ptr<yacl::link::Context> lctx,
                                     size_t bitlen)
    : lctx_(std::move(lctx)),
      bitlen_(bitlen),
      mask_(RingMask(bitlen)),
      and_(lctx_),
      b2a_(lctx_, bitlen) {
  YACL_ENFORCE(lctx_ != nullptr);
  CheckTwoPartyOrThrow();
  lctx_->SetThrottleWindowSize(0);
}

void TwoPartySSCompare::CheckTwoPartyOrThrow() const {
  YACL_ENFORCE(bitlen_ >= 1 && bitlen_ <= 64);
  YACL_ENFORCE(lctx_->WorldSize() == 2);
}

yacl::Buffer TwoPartySSCompare::PackU64(uint64_t v) {
  yacl::Buffer buf(static_cast<int64_t>(sizeof(uint64_t)));
  std::memcpy(buf.data<void>(), &v, sizeof(uint64_t));
  return buf;
}

uint64_t TwoPartySSCompare::UnpackU64(const yacl::Buffer& buf) {
  YACL_ENFORCE(buf.size() == static_cast<int64_t>(sizeof(uint64_t)));
  uint64_t v = 0;
  std::memcpy(&v, buf.data<const void>(), sizeof(uint64_t));
  return v;
}

ArithShare TwoPartySSCompare::ShareInput(uint64_t x, size_t owner_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(owner_rank < 2);

  const size_t my_rank = lctx_->Rank();
  const size_t peer = lctx_->NextRank();
  const std::string tag =
      std::string("cmp/share_input/") + lctx_->NextId();

  if (my_rank == owner_rank) {
    uint64_t r = yacl::crypto::SecureRandU64() & mask_;
    const uint64_t xm = x & mask_;
    const uint64_t other = SubMod(xm, r, bitlen_);
    lctx_->SendAsync(peer, PackU64(other), tag);
    return ArithShare{r, bitlen_};
  } else {
    yacl::Buffer buf = lctx_->Recv(owner_rank, tag);
    uint64_t s = UnpackU64(buf) & mask_;
    return ArithShare{s, bitlen_};
  }
}

uint64_t TwoPartySSCompare::RevealToAll(const ArithShare& a) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(a.bitlen == bitlen_);

  const size_t peer = lctx_->NextRank();
  const std::string tag =
      std::string("cmp/reveal/") + lctx_->NextId();

  const uint64_t my_s = a.value & mask_;
  lctx_->SendAsync(peer, PackU64(my_s), tag);
  yacl::Buffer peer_buf = lctx_->Recv(peer, tag);

  const uint64_t peer_s = UnpackU64(peer_buf) & mask_;
  return AddMod(my_s, peer_s, bitlen_);
}

ArithShare TwoPartySSCompare::LessThan(const ArithShare& x,
                                      const ArithShare& y) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(x.bitlen == bitlen_ && y.bitlen == bitlen_);

  // Step1: (x - y)^A shares
  const uint64_t ai = SubMod(x.value & mask_, y.value & mask_, bitlen_);
  const uint64_t p_or_q = ai;  // rank0 sees p, rank1 sees q

  // If bitlen==1: a1^B = w1^B (no carry)
  if (bitlen_ == 1) {
    const bool bit0 = GetBit(p_or_q, 0);
    // w1^B: (p1,q1) => each party holds its local bit
    BoolShare w{bit0};
    // Convert to arithmetic bit share in Z_{2^bitlen_}
    return b2a_.ConvertBit(w);
  }

  // Build helper to create shares per the figure:
  // w_k^B:  <w>_0 = p_k, <w>_1 = q_k
  // p_k^B:  <p>_0 = p_k, <p>_1 = 0
  // q_k^B:  <q>_0 = 0,   <q>_1 = q_k
  auto MakeW = [&](size_t k1) -> BoolShare {
    const bool b = GetBit(p_or_q, k1 - 1);
    return BoolShare{b};
  };
  auto MakeP = [&](size_t k1) -> BoolShare {
    const bool b = GetBit(p_or_q, k1 - 1);
    if (lctx_->Rank() == 0) return BoolShare{b};
    return BoolShare{false};
  };
  auto MakeQ = [&](size_t k1) -> BoolShare {
    const bool b = GetBit(p_or_q, k1 - 1);
    if (lctx_->Rank() == 1) return BoolShare{b};
    return BoolShare{false};
  };

  // k=1: c1 = AND(p1,q1)
  BoolShare c = and_.And(MakeP(1), MakeQ(1));

  // k in [2, l-1]:
  if (bitlen_ >= 3) {
    for (size_t k = 2; k <= bitlen_ - 1; ++k) {
      // d_k = AND(p_k,q_k) XOR 1
      BoolShare dk = and_.And(MakeP(k), MakeQ(k));
      dk = and_.XorConst(dk, true);

      // e_k = AND(w_k, c_{k-1}) XOR 1
      BoolShare ek = and_.And(MakeW(k), c);
      ek = and_.XorConst(ek, true);

      // c_k = AND(e_k, d_k) XOR 1
      BoolShare ck = and_.And(ek, dk);
      ck = and_.XorConst(ck, true);

      c = ck;
    }
  }

  // k = l: a_l = w_l XOR c_{l-1}
  BoolShare wl = MakeW(bitlen_);
  BoolShare al = and_.Xor(wl, c);

  // Step: B2A(a_l)
  return b2a_.ConvertBit(al);
}

}  // namespace secretflow::experiment::comparison
