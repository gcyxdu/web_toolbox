#include "experiment/mpc/multiplication/two_party_ss_mul.h"

#include <exception>
#include <future>
#include <thread>

#include "gtest/gtest.h"
#include "yacl/link/test_util.h"

namespace secretflow::experiment::multiplication {

static uint64_t MulExpect(uint64_t x, uint64_t y, size_t bitlen) {
  uint64_t mask = TwoPartySSMul::RingMask(bitlen);
  __uint128_t p = static_cast<__uint128_t>(x & mask) * static_cast<__uint128_t>(y & mask);
  return static_cast<uint64_t>(p) & mask;
}

static void PartyThread(std::shared_ptr<yacl::link::Context> ctx, size_t bitlen,
                        uint64_t x, uint64_t y,
                        std::promise<uint64_t>* out,
                        std::exception_ptr* eptr) {
  try {
    TwoPartySSMul prot(ctx, bitlen);

    // Let rank0 own x, rank1 own y
    auto sx = prot.ShareInput(ctx->Rank() == 0 ? x : 0, 0);
    auto sy = prot.ShareInput(ctx->Rank() == 1 ? y : 0, 1);

    auto sz = prot.Mul(sx, sy);
    uint64_t z = prot.RevealToAll(sz);

    out->set_value(z);
  } catch (...) {
    *eptr = std::current_exception();
    try { out->set_value(0); } catch (...) {}
  }
}

TEST(TwoPartySSMulE2E, MulReveal_8bit) {
  auto ctxs = yacl::link::test::SetupWorld("tp_mul_8", 2);
  ASSERT_EQ(ctxs.size(), 2u);

  const size_t bitlen = 8;
  const uint64_t x = 250;
  const uint64_t y = 10;
  const uint64_t expect = MulExpect(x, y, bitlen);

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  std::thread t0(PartyThread, ctxs[0], bitlen, x, y, &p0, &e0);
  std::thread t1(PartyThread, ctxs[1], bitlen, x, y, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

TEST(TwoPartySSMulE2E, MulReveal_64bit) {
  auto ctxs = yacl::link::test::SetupWorld("tp_mul_64", 2);

  const size_t bitlen = 64;
  const uint64_t x = 0xFFFFFFFFFFFFFFF0ULL;
  const uint64_t y = 0x123456789ABCDEF0ULL;
  const uint64_t expect = MulExpect(x, y, bitlen);

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  std::thread t0(PartyThread, ctxs[0], bitlen, x, y, &p0, &e0);
  std::thread t1(PartyThread, ctxs[1], bitlen, x, y, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

TEST(TwoPartySSMulE2E, MulReveal_32bit_RandomLike) {
  auto ctxs = yacl::link::test::SetupWorld("tp_mul_32", 2);

  const size_t bitlen = 32;
  const uint64_t x = 0xDEADBEEF;
  const uint64_t y = 0x01020304;
  const uint64_t expect = MulExpect(x, y, bitlen);

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  std::thread t0(PartyThread, ctxs[0], bitlen, x, y, &p0, &e0);
  std::thread t1(PartyThread, ctxs[1], bitlen, x, y, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

}  // namespace secretflow::experiment::multiplication
