#include "experiment/mpc/comparison/compare.h"

#include <exception>
#include <future>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "yacl/link/test_util.h"

namespace secretflow::experiment::comparison {

static void PartyRun(std::shared_ptr<yacl::link::Context> ctx, size_t bitlen,
                     uint64_t x, uint64_t y,
                     std::promise<uint64_t>* out,
                     std::exception_ptr* eptr) {
  try {
    TwoPartySSCompare prot(ctx, bitlen);

    // rank0 owns x, rank1 owns y
    auto sx = prot.ShareInput(ctx->Rank() == 0 ? x : 0, 0);
    auto sy = prot.ShareInput(ctx->Rank() == 1 ? y : 0, 1);

    auto sz = prot.LessThan(sx, sy);
    uint64_t z = prot.RevealToAll(sz);
    out->set_value(z & 1ULL);
  } catch (...) {
    *eptr = std::current_exception();
    try { out->set_value(0); } catch (...) {}
  }
}

TEST(TwoPartySSCompareE2E, BasicCases_32bit) {
  auto ctxs = yacl::link::test::SetupWorld("cmp_32", 2);
  const size_t bitlen = 32;

  struct Case { uint64_t x; uint64_t y; };
  // Use values well within [0, 2^{bitlen-1}) to match the common signed-safe range
  // assumed by this carry-chain based scheme.
  std::vector<Case> cases = {
      {10, 20},
      {20, 10},
      {123456, 123456},
      {1, 1000000},
      {1000000, 1},
  };

  for (const auto& tc : cases) {
    std::promise<uint64_t> p0, p1;
    auto f0 = p0.get_future();
    auto f1 = p1.get_future();
    std::exception_ptr e0, e1;

    std::thread t0(PartyRun, ctxs[0], bitlen, tc.x, tc.y, &p0, &e0);
    std::thread t1(PartyRun, ctxs[1], bitlen, tc.x, tc.y, &p1, &e1);
    t0.join();
    t1.join();

    if (e0) std::rethrow_exception(e0);
    if (e1) std::rethrow_exception(e1);

    const uint64_t expect = (tc.x < tc.y) ? 1ULL : 0ULL;
    EXPECT_EQ(f0.get(), expect);
    EXPECT_EQ(f1.get(), expect);
  }
}

TEST(TwoPartySSCompareE2E, BasicCases_8bit) {
  auto ctxs = yacl::link::test::SetupWorld("cmp_8", 2);
  const size_t bitlen = 8;

  const uint64_t x = 50;
  const uint64_t y = 100;
  const uint64_t expect = 1;

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  std::thread t0(PartyRun, ctxs[0], bitlen, x, y, &p0, &e0);
  std::thread t1(PartyRun, ctxs[1], bitlen, x, y, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

}  // namespace secretflow::experiment::comparison
