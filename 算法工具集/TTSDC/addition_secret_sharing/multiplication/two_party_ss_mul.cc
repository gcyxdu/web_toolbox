#include "experiment/mpc/multiplication/two_party_ss_mul.h"

#include <cstring>
#include <limits>

#include "yacl/crypto/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace secretflow::experiment::multiplication {

namespace {

inline uint64_t ApplyMask(uint64_t v, uint64_t mask) { return v & mask; }

}  // namespace

TwoPartySSMul::TwoPartySSMul(std::shared_ptr<yacl::link::Context> lctx,
                             size_t bitlen)
    : lctx_(std::move(lctx)), bitlen_(bitlen), mask_(RingMask(bitlen)) {
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  CheckTwoPartyOrThrow();

  // Avoid SendAsync throttling block in tests/bench.
  lctx_->SetThrottleWindowSize(0);

  SetupBaseOtsOnce();
}

void TwoPartySSMul::CheckTwoPartyOrThrow() const {
  YACL_ENFORCE(bitlen_ >= 1 && bitlen_ <= 64, "bitlen must be in [1,64], got {}",
               bitlen_);
  YACL_ENFORCE(lctx_ != nullptr, "lctx is null");
  YACL_ENFORCE(lctx_->WorldSize() == 2, "requires WorldSize()==2, got {}",
               lctx_->WorldSize());
  YACL_ENFORCE(lctx_->Rank() < 2, "invalid rank {}", lctx_->Rank());
}

uint64_t TwoPartySSMul::RingMask(size_t bitlen) {
  YACL_ENFORCE(bitlen >= 1 && bitlen <= 64, "bitlen must be in [1,64], got {}",
               bitlen);
  if (bitlen == 64) return std::numeric_limits<uint64_t>::max();
  return (uint64_t{1} << bitlen) - 1;
}

uint64_t TwoPartySSMul::AddMod(uint64_t a, uint64_t b, size_t bitlen) {
  const uint64_t mask = RingMask(bitlen);
  return (a + b) & mask;
}

uint64_t TwoPartySSMul::SubMod(uint64_t a, uint64_t b, size_t bitlen) {
  const uint64_t mask = RingMask(bitlen);
  return (a - b) & mask;
}

uint64_t TwoPartySSMul::MulMod(uint64_t a, uint64_t b) const {
  // Multiply in 128 then mod 2^l (mask).
  __uint128_t p = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
  uint64_t lo = static_cast<uint64_t>(p);
  return ApplyMask(lo, mask_);
}

yacl::Buffer TwoPartySSMul::PackU64(uint64_t v) {
  yacl::Buffer buf(static_cast<int64_t>(sizeof(uint64_t)));
  std::memcpy(buf.data<void>(), &v, sizeof(uint64_t));
  return buf;
}

uint64_t TwoPartySSMul::UnpackU64(const yacl::Buffer& buf) {
  YACL_ENFORCE(buf.size() == static_cast<int64_t>(sizeof(uint64_t)),
               "buffer size mismatch, expect {}, got {}", sizeof(uint64_t),
               buf.size());
  uint64_t v = 0;
  std::memcpy(&v, buf.data<const void>(), sizeof(uint64_t));
  return v;
}

yacl::Buffer TwoPartySSMul::PackU64x2(uint64_t a, uint64_t b) {
  yacl::Buffer buf(static_cast<int64_t>(2 * sizeof(uint64_t)));
  std::memcpy(buf.data<void>(), &a, sizeof(uint64_t));
  std::memcpy(reinterpret_cast<uint8_t*>(buf.data<void>()) + sizeof(uint64_t),
              &b, sizeof(uint64_t));
  return buf;
}

void TwoPartySSMul::UnpackU64x2(const yacl::Buffer& buf, uint64_t* a, uint64_t* b) {
  YACL_ENFORCE(a != nullptr && b != nullptr);
  YACL_ENFORCE(buf.size() == static_cast<int64_t>(2 * sizeof(uint64_t)),
               "buffer size mismatch, expect {}, got {}", 2 * sizeof(uint64_t),
               buf.size());
  std::memcpy(a, buf.data<const void>(), sizeof(uint64_t));
  std::memcpy(b,
              reinterpret_cast<const uint8_t*>(buf.data<const void>()) + sizeof(uint64_t),
              sizeof(uint64_t));
}

ArithShare TwoPartySSMul::ShareInput(uint64_t x, size_t owner_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(owner_rank < 2, "owner_rank must be 0 or 1");

  const size_t my_rank = lctx_->Rank();
  const size_t peer = lctx_->NextRank();

  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_mul/share_input/" + round_id;

  if (my_rank == owner_rank) {
    uint64_t r = yacl::crypto::SecureRandU64();
    r = ApplyMask(r, mask_);

    const uint64_t x_m = ApplyMask(x, mask_);
    const uint64_t other = SubMod(x_m, r, bitlen_);

    lctx_->SendAsync(peer, PackU64(other), tag);
    return ArithShare{r, bitlen_};
  } else {
    yacl::Buffer buf = lctx_->Recv(owner_rank, tag);
    uint64_t s = ApplyMask(UnpackU64(buf), mask_);
    return ArithShare{s, bitlen_};
  }
}

uint64_t TwoPartySSMul::RevealToAll(const ArithShare& a) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(a.bitlen == bitlen_, "bitlen mismatch");

  const size_t peer = lctx_->NextRank();
  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_mul/reveal/" + round_id;

  const uint64_t my_s = ApplyMask(a.value, mask_);
  lctx_->SendAsync(peer, PackU64(my_s), tag);

  yacl::Buffer peer_buf = lctx_->Recv(peer, tag);
  const uint64_t peer_s = ApplyMask(UnpackU64(peer_buf), mask_);

  return AddMod(my_s, peer_s, bitlen_);
}

// -------------------------
// Base OT setup
// -------------------------

void TwoPartySSMul::SetupBaseOtsOnce() {
  if (base_ot_ready_) return;

  const size_t rank = lctx_->Rank();

  // Build random choices bitset for BaseOtRecv side.
  auto make_choices = [&](uint32_t nbits) {
    yacl::dynamic_bitset<uint128_t> ch(nbits);
    for (uint32_t i = 0; i < nbits; ++i) {
      ch[i] = (yacl::crypto::SecureRandU64() & 1) != 0;
    }
    return ch;
  };

  if (rank == 0) {
    // Direction 0->1: rank0 is ext-sender => needs OtRecvStore (BaseOtRecv).
    auto ch01 = make_choices(kKappa);
    base_recv_01_ = yacl::crypto::BaseOtRecv(lctx_, ch01, kKappa);
    // Direction 1->0: rank0 is ext-receiver => needs OtSendStore (BaseOtSend).
    base_send_10_ = yacl::crypto::BaseOtSend(lctx_, kKappa);
  } else {
    // Direction 0->1: rank1 is ext-receiver => needs OtSendStore (BaseOtSend).
    base_send_01_ = yacl::crypto::BaseOtSend(lctx_, kKappa);
    // Direction 1->0: rank1 is ext-sender => needs OtRecvStore (BaseOtRecv).
    auto ch10 = make_choices(kKappa);
    base_recv_10_ = yacl::crypto::BaseOtRecv(lctx_, ch10, kKappa);
  }

  base_ot_ready_ = true;
}

// -------------------------
// Pad derivation
// -------------------------

uint64_t TwoPartySSMul::DerivePad64(yacl::crypto::Block key) {
  uint64_t pad = 0;
  // Deterministically derive 64 bits from key via PRG.
  // Uses interface from yacl/crypto/tools/prg.h
  (void)yacl::crypto::FillPRand(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR,
      static_cast<uint128_t>(key),
      /*iv=*/0,
      /*count=*/0,
      reinterpret_cast<char*>(&pad),
      sizeof(pad));
  return pad;
}

// -------------------------
// Message OT (U64) via IKNP key-OT + masking
// -------------------------

void TwoPartySSMul::MessageOtSendU64(absl::Span<const uint64_t> m0,
                                    absl::Span<const uint64_t> m1,
                                    size_t sender_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(m0.size() == m1.size(), "m0/m1 size mismatch");
  YACL_ENFORCE(sender_rank < 2);

  const size_t rank = lctx_->Rank();
  const size_t peer = lctx_->NextRank();
  const uint32_t n = static_cast<uint32_t>(m0.size());

  YACL_ENFORCE(rank == sender_rank, "MessageOtSendU64 called on non-sender");

  // 1) Extend keys
  std::vector<std::array<uint128_t, 2>> keys(n);
  if (sender_rank == 0) {
    yacl::crypto::IknpOtExtSend(lctx_, base_recv_01_, absl::MakeSpan(keys), false);
  } else {
    yacl::crypto::IknpOtExtSend(lctx_, base_recv_10_, absl::MakeSpan(keys), false);
  }

  // 2) Mask and send ciphertext pairs
  yacl::Buffer ct_buf(static_cast<int64_t>(2ULL * n * sizeof(uint64_t)));
  auto* out = reinterpret_cast<uint8_t*>(ct_buf.data<void>());

  for (uint32_t i = 0; i < n; ++i) {
    const uint64_t p0 = DerivePad64(keys[i][0]);
    const uint64_t p1 = DerivePad64(keys[i][1]);

    const uint64_t c0 = ApplyMask(m0[i], mask_) ^ p0;
    const uint64_t c1 = ApplyMask(m1[i], mask_) ^ p1;

    std::memcpy(out + (2ULL * i + 0) * sizeof(uint64_t), &c0, sizeof(uint64_t));
    std::memcpy(out + (2ULL * i + 1) * sizeof(uint64_t), &c1, sizeof(uint64_t));
  }

  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_mul/msg_ot/u64/" + round_id;

  lctx_->SendAsync(peer, std::move(ct_buf), tag);
}

std::vector<uint64_t> TwoPartySSMul::MessageOtRecvU64(
    const yacl::dynamic_bitset<uint128_t>& choices, size_t sender_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(sender_rank < 2);

  const size_t rank = lctx_->Rank();
  const size_t peer = lctx_->NextRank();
  const uint32_t n = static_cast<uint32_t>(choices.size());

  YACL_ENFORCE(rank != sender_rank, "MessageOtRecvU64 called on sender");

  // 1) Extend receiver keys
  std::vector<uint128_t> rkeys(n);
  if (sender_rank == 0) {
    yacl::crypto::IknpOtExtRecv(lctx_, base_send_01_, choices, absl::MakeSpan(rkeys), false);
  } else {
    yacl::crypto::IknpOtExtRecv(lctx_, base_send_10_, choices, absl::MakeSpan(rkeys), false);
  }

  // 2) Receive ciphertext and decrypt chosen
  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_mul/msg_ot/u64/" + round_id;

  yacl::Buffer ct_buf = lctx_->Recv(peer, tag);
  YACL_ENFORCE(ct_buf.size() == static_cast<int64_t>(2ULL * n * sizeof(uint64_t)),
               "ciphertext size mismatch");

  const auto* in = reinterpret_cast<const uint8_t*>(ct_buf.data<const void>());

  std::vector<uint64_t> chosen(n);
  for (uint32_t i = 0; i < n; ++i) {
    uint64_t c0 = 0, c1 = 0;
    std::memcpy(&c0, in + (2ULL * i + 0) * sizeof(uint64_t), sizeof(uint64_t));
    std::memcpy(&c1, in + (2ULL * i + 1) * sizeof(uint64_t), sizeof(uint64_t));

    const bool b = choices[i];
    const uint64_t pad = DerivePad64(rkeys[i]);
    const uint64_t m = (b ? c1 : c0) ^ pad;
    chosen[i] = ApplyMask(m, mask_);
  }

  return chosen;
}

// -------------------------
// OT-based multiplication share (u*v)
// -------------------------

uint64_t TwoPartySSMul::OtMulShare(uint64_t u_or_v, size_t sender_rank) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(sender_rank < 2);

  const size_t rank = lctx_->Rank();
  const uint64_t val = ApplyMask(u_or_v, mask_);

  // We implement the correct OT-mul variant:
  // For bit i of v:
  //   Sender picks r_i, sets m0=r_i, m1=r_i + u*2^i.
  // Receiver gets m_{v_i}. Sender share = -sum r_i, Receiver share = sum m_{v_i}.
  // Then shares sum to u*v mod 2^l.
  const uint32_t n = static_cast<uint32_t>(bitlen_);

  if (rank == sender_rank) {
    // Sender side
    std::vector<uint64_t> r(n), m0(n), m1(n);
    uint64_t sum_r = 0;

    for (uint32_t i = 0; i < n; ++i) {
      r[i] = ApplyMask(yacl::crypto::SecureRandU64(), mask_);
      sum_r = AddMod(sum_r, r[i], bitlen_);

      const uint64_t term = ApplyMask((i == 64 ? 0ULL : (val << i)), mask_);
      m0[i] = r[i];
      m1[i] = AddMod(r[i], term, bitlen_);
    }

    MessageOtSendU64(absl::MakeSpan(m0), absl::MakeSpan(m1), sender_rank);

    // sender share = -sum_r mod
    return SubMod(0, sum_r, bitlen_);
  } else {
    // Receiver side: choices are bits of v
    yacl::dynamic_bitset<uint128_t> choices(bitlen_);
    for (size_t i = 0; i < bitlen_; ++i) {
      choices[i] = ((val >> i) & 1ULL) != 0;
    }

    auto chosen = MessageOtRecvU64(choices, sender_rank);

    uint64_t sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
      sum = AddMod(sum, chosen[i], bitlen_);
    }
    return sum;
  }
}

// -------------------------
// Beaver triple generation via OT
// -------------------------

BeaverTripleShare TwoPartySSMul::GenBeaverTriple() {
  CheckTwoPartyOrThrow();

  const size_t rank = lctx_->Rank();

  // Random shares a_i, b_i
  uint64_t ai = ApplyMask(yacl::crypto::SecureRandU64(), mask_);
  uint64_t bi = ApplyMask(yacl::crypto::SecureRandU64(), mask_);

  // Local term a_i*b_i
  uint64_t local = MulMod(ai, bi);

  // Cross terms:
  // t01 = a0*b1 : sender_rank=0, sender holds a0, receiver holds b1
  // t10 = a1*b0 : sender_rank=1, sender holds a1, receiver holds b0
  uint64_t share_t01 = 0;
  uint64_t share_t10 = 0;

  if (rank == 0) {
    share_t01 = OtMulShare(ai, /*sender_rank=*/0);  // sender uses a0
    share_t10 = OtMulShare(bi, /*sender_rank=*/1);  // receiver uses b0
  } else {
    share_t01 = OtMulShare(bi, /*sender_rank=*/0);  // receiver uses b1
    share_t10 = OtMulShare(ai, /*sender_rank=*/1);  // sender uses a1
  }

  uint64_t ci = AddMod(local, AddMod(share_t01, share_t10, bitlen_), bitlen_);
  return BeaverTripleShare{ai, bi, ci, bitlen_};
}

// -------------------------
// Online multiplication using Beaver
// -------------------------

ArithShare TwoPartySSMul::Mul(const ArithShare& x, const ArithShare& y) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(x.bitlen == bitlen_ && y.bitlen == bitlen_, "bitlen mismatch");

  auto tri = GenBeaverTriple();

  const uint64_t xi = ApplyMask(x.value, mask_);
  const uint64_t yi = ApplyMask(y.value, mask_);

  // d_i = x_i - a_i, e_i = y_i - b_i
  const uint64_t di = SubMod(xi, tri.a, bitlen_);
  const uint64_t ei = SubMod(yi, tri.b, bitlen_);

  // Open d,e: both parties send then recv (avoid deadlock).
  const size_t peer = lctx_->NextRank();
  const std::string round_id = lctx_->NextId();
  const std::string tag = "tp_ss_mul/open_de/" + round_id;

  lctx_->SendAsync(peer, PackU64x2(di, ei), tag);
  yacl::Buffer buf = lctx_->Recv(peer, tag);

  uint64_t dj = 0, ej = 0;
  UnpackU64x2(buf, &dj, &ej);

  const uint64_t d = AddMod(di, ApplyMask(dj, mask_), bitlen_);
  const uint64_t e = AddMod(ei, ApplyMask(ej, mask_), bitlen_);

  // z_i = c_i + d*b_i + e*a_i + (i==0 ? d*e : 0)
  uint64_t zi = tri.c;
  zi = AddMod(zi, MulMod(d, tri.b), bitlen_);
  zi = AddMod(zi, MulMod(e, tri.a), bitlen_);
  if (lctx_->Rank() == 0) {
    zi = AddMod(zi, MulMod(d, e), bitlen_);
  }

  return ArithShare{ApplyMask(zi, mask_), bitlen_};
}

}  // namespace secretflow::experiment::multiplication
