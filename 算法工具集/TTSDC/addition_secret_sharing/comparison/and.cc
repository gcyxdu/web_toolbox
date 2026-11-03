#include "experiment/mpc/comparison/and.h"

#include <cstring>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand.h"

namespace secretflow::experiment::comparison {

BooleanAnd::BooleanAnd(std::shared_ptr<yacl::link::Context> lctx)
    : lctx_(std::move(lctx)), ot_(lctx_) {
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  CheckTwoPartyOrThrow();
  lctx_->SetThrottleWindowSize(0);
}

void BooleanAnd::CheckTwoPartyOrThrow() const {
  YACL_ENFORCE(lctx_ != nullptr);
  YACL_ENFORCE(lctx_->WorldSize() == 2, "requires 2 parties");
}

BoolShare BooleanAnd::Xor(const BoolShare& a, const BoolShare& b) const {
  return BoolShare{a.value ^ b.value};
}

BoolShare BooleanAnd::XorConst(const BoolShare& a, bool c) const {
  // represent public bit c as (c,0)
  if (lctx_->Rank() == 0) {
    return BoolShare{a.value ^ c};
  }
  return a;
}

yacl::Buffer BooleanAnd::Pack2Bits(bool b0, bool b1) {
  uint8_t v = 0;
  v |= static_cast<uint8_t>(b0 ? 1 : 0);
  v |= static_cast<uint8_t>(b1 ? 2 : 0);
  yacl::Buffer buf(1);
  std::memcpy(buf.data<void>(), &v, 1);
  return buf;
}

void BooleanAnd::Unpack2Bits(const yacl::Buffer& buf, bool* b0, bool* b1) {
  YACL_ENFORCE(b0 != nullptr && b1 != nullptr);
  YACL_ENFORCE(buf.size() == 1, "bad buf size");
  uint8_t v = 0;
  std::memcpy(&v, buf.data<const void>(), 1);
  *b0 = (v & 1) != 0;
  *b1 = (v & 2) != 0;
}

bool BooleanAnd::OtMulBitShare(bool u_or_v, size_t sender_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(sender_rank < 2);

  const size_t rank = lctx_->Rank();
  const bool val = u_or_v;

  // OT-mul in GF(2):
  // sender picks random r, sends m0=r, m1=r XOR u
  // receiver selects v, obtains m_v
  // shares: sender=r, receiver=m_v => XOR = u&v
  if (rank == sender_rank) {
    const bool r = (yacl::crypto::SecureRandU64() & 1) != 0;
    const uint64_t m0 = static_cast<uint64_t>(r ? 1 : 0);
    const uint64_t m1 = static_cast<uint64_t>((r ^ val) ? 1 : 0);

    std::array<uint64_t, 1> a0{m0};
    std::array<uint64_t, 1> a1{m1};
    ot_.SendU64(sender_rank, absl::MakeSpan(a0), absl::MakeSpan(a1), "and/otmul_bit");
    return r;
  } else {
    yacl::dynamic_bitset<uint128_t> ch(1);
    ch[0] = val;  // receiver's selection v
    auto got = ot_.RecvU64(sender_rank, ch, "and/otmul_bit");
    YACL_ENFORCE(got.size() == 1);
    return (got[0] & 1ULL) != 0;
  }
}

BooleanAnd::TripleShare BooleanAnd::GenTriple() {
  CheckTwoPartyOrThrow();
  const size_t rank = lctx_->Rank();

  // random shares a_i, b_i
  const bool ai = (yacl::crypto::SecureRandU64() & 1) != 0;
  const bool bi = (yacl::crypto::SecureRandU64() & 1) != 0;

  const bool local = ai & bi;

  // cross terms:
  // t01 = a0 & b1 (sender=0 holds a0, receiver=1 holds b1)
  // t10 = a1 & b0 (sender=1 holds a1, receiver=0 holds b0)
  bool share_t01 = false;
  bool share_t10 = false;

  if (rank == 0) {
    share_t01 = OtMulBitShare(ai, /*sender_rank=*/0);  // sender uses a0
    share_t10 = OtMulBitShare(bi, /*sender_rank=*/1);  // receiver uses b0
  } else {
    share_t01 = OtMulBitShare(bi, /*sender_rank=*/0);  // receiver uses b1
    share_t10 = OtMulBitShare(ai, /*sender_rank=*/1);  // sender uses a1
  }

  const bool ci = local ^ share_t01 ^ share_t10;
  return TripleShare{ai, bi, ci};
}

BoolShare BooleanAnd::And(const BoolShare& x, const BoolShare& y) {
  CheckTwoPartyOrThrow();

  // Offline: triple
  const auto tri = GenTriple();

  // Online:
  // d_i = x_i XOR a_i
  // e_i = y_i XOR b_i
  const bool di = x.value ^ tri.a;
  const bool ei = y.value ^ tri.b;

  // Open d,e (broadcast)
  const size_t peer = lctx_->NextRank();
  const std::string tag = std::string("and/open_de/") + lctx_->NextId();

  lctx_->SendAsync(peer, Pack2Bits(di, ei), tag);
  yacl::Buffer buf = lctx_->Recv(peer, tag);

  bool dj = false, ej = false;
  Unpack2Bits(buf, &dj, &ej);

  const bool d = di ^ dj;
  const bool e = ei ^ ej;

  // z0 = (e & a0) XOR (d & b0) XOR c0
  // z1 = (d & e) XOR (e & a1) XOR (d & b1) XOR c1
  bool zi = tri.c ^ (e & tri.a) ^ (d & tri.b);
  if (lctx_->Rank() == 1) {
    zi ^= (d & e);
  }
  return BoolShare{zi};
}

}  // namespace secretflow::experiment::comparison
