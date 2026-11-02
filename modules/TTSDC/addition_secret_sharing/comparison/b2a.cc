#include "experiment/mpc/comparison/b2a.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/rand.h"

namespace secretflow::experiment::comparison {

B2AConverter::B2AConverter(std::shared_ptr<yacl::link::Context> lctx,
                           size_t ring_bitlen)
    : lctx_(std::move(lctx)),
      ring_bitlen_(ring_bitlen),
      mask_(RingMask(ring_bitlen)),
      ot_(lctx_) {
  YACL_ENFORCE(lctx_ != nullptr);
  CheckTwoPartyOrThrow();
}

void B2AConverter::CheckTwoPartyOrThrow() const {
  YACL_ENFORCE(ring_bitlen_ >= 1 && ring_bitlen_ <= 64);
  YACL_ENFORCE(lctx_->WorldSize() == 2);
}

ArithShare B2AConverter::ConvertBit(const BoolShare& xb) {
  CheckTwoPartyOrThrow();

  // Scheme:
  // P0 holds x0, P1 holds x1, x = x0 XOR x1 (bit).
  // P0 picks r in Z_{2^L}; messages:
  //   s0 = x0*1 - r
  //   s1 = (1 XOR x0)*1 - r
  // P1 selects x1 and receives x - r.
  const size_t rank = lctx_->Rank();

  if (rank == 0) {
    const uint64_t r = yacl::crypto::SecureRandU64() & mask_;
    const bool x0 = xb.value;

    const uint64_t t0 = x0 ? 1ULL : 0ULL;
    const uint64_t t1 = (x0 ^ true) ? 1ULL : 0ULL;

    const uint64_t s0 = SubMod(t0, r, ring_bitlen_);
    const uint64_t s1 = SubMod(t1, r, ring_bitlen_);

    std::array<uint64_t, 1> m0{s0};
    std::array<uint64_t, 1> m1{s1};

    ot_.SendU64(/*sender_rank=*/0, absl::MakeSpan(m0), absl::MakeSpan(m1),
                "b2a/bit");
    return ArithShare{r, ring_bitlen_};
  } else {
    yacl::dynamic_bitset<uint128_t> ch(1);
    ch[0] = xb.value;  // x1
    auto got = ot_.RecvU64(/*sender_rank=*/0, ch, "b2a/bit");
    YACL_ENFORCE(got.size() == 1);
    return ArithShare{got[0] & mask_, ring_bitlen_};
  }
}

ArithShare B2AConverter::ConvertWord(const BoolWordShare& xw) {
  CheckTwoPartyOrThrow();
  YACL_ENFORCE(xw.bitlen >= 1 && xw.bitlen <= 64);
  YACL_ENFORCE(xw.bitlen == ring_bitlen_,
               "ConvertWord expects xw.bitlen == ring_bitlen");

  const size_t rank = lctx_->Rank();
  const size_t L = ring_bitlen_;

  if (rank == 0) {
    uint64_t sum_r = 0;

    std::vector<uint64_t> m0(L), m1(L);
    for (size_t i = 0; i < L; ++i) {
      const uint64_t ri = yacl::crypto::SecureRandU64() & mask_;
      sum_r = AddMod(sum_r, ri, L);

      const bool x0_i = GetBit(xw.value, i);
      const uint64_t weight = (i == 63) ? (1ULL << 63) : (1ULL << i);

      const uint64_t t0 = x0_i ? weight : 0ULL;
      const uint64_t t1 = (x0_i ^ true) ? weight : 0ULL;

      m0[i] = SubMod(t0, ri, L);
      m1[i] = SubMod(t1, ri, L);
    }

    ot_.SendU64(/*sender_rank=*/0, absl::MakeSpan(m0), absl::MakeSpan(m1),
                "b2a/word");
    return ArithShare{sum_r, L};
  } else {
    yacl::dynamic_bitset<uint128_t> ch(L);
    for (size_t i = 0; i < L; ++i) {
      ch[i] = GetBit(xw.value, i);  // x1[i]
    }

    auto got = ot_.RecvU64(/*sender_rank=*/0, ch, "b2a/word");

    uint64_t sum = 0;
    for (size_t i = 0; i < L; ++i) {
      sum = AddMod(sum, got[i] & mask_, L);
    }
    return ArithShare{sum, L};
  }
}

}  // namespace secretflow::experiment::comparison
