#include "experiment/mpc/addition/two_party_ss_add.h"

#include <exception>
#include <future>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "yacl/link/test_util.h"

namespace secretflow::experiment::addition {

static void RunParty(std::shared_ptr<yacl::link::Context> ctx, size_t bitlen,
                     uint64_t x, uint64_t y, size_t x_owner, size_t y_owner,
                     std::promise<uint64_t>* out, std::exception_ptr* eptr) {
  try {
    TwoPartySSAdd prot(ctx, bitlen);

    const uint64_t x_in = (ctx->Rank() == x_owner) ? x : 0;
    const uint64_t y_in = (ctx->Rank() == y_owner) ? y : 0;

    auto sx = prot.ShareInput(x_in, x_owner);
    auto sy = prot.ShareInput(y_in, y_owner);
    auto sz = prot.Add(sx, sy);
    uint64_t z = prot.RevealToAll(sz);
    out->set_value(z);
  } catch (...) {
    *eptr = std::current_exception();
    try {
      out->set_value(0);
    } catch (...) {
    }
  }
}

TEST(TwoPartySSAddE2E, AddReveal_64bit) {
  auto ctxs = yacl::link::test::SetupWorld("tp_add_64", 2);
  ASSERT_EQ(ctxs.size(), 2u);

  const size_t bitlen = 64;
  const uint64_t x = 0xFFFFFFFFFFFFFFF0ULL;
  const uint64_t y = 0x30ULL;
  const uint64_t expect = x + y;  // uint64 overflow is mod 2^64.

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  std::thread t0(RunParty, ctxs[0], bitlen, x, y, 0, 1, &p0, &e0);
  std::thread t1(RunParty, ctxs[1], bitlen, x, y, 0, 1, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

TEST(TwoPartySSAddE2E, AddReveal_8bit) {
  auto ctxs = yacl::link::test::SetupWorld("tp_add_8", 2);

  const size_t bitlen = 8;
  const uint64_t mask = TwoPartySSAdd::RingMask(bitlen);

  const uint64_t x = 250;  // 0xFA
  const uint64_t y = 10;   // 0x0A
  const uint64_t expect = (x + y) & mask;  // 260 mod 256 => 4

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  std::thread t0(RunParty, ctxs[0], bitlen, x, y, 0, 1, &p0, &e0);
  std::thread t1(RunParty, ctxs[1], bitlen, x, y, 0, 1, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

TEST(TwoPartySSAddE2E, AddReveal_SwappedOwners_16bit) {
  auto ctxs = yacl::link::test::SetupWorld("tp_add_swap", 2);

  const size_t bitlen = 16;
  const uint64_t mask = TwoPartySSAdd::RingMask(bitlen);

  const uint64_t x = 0xBEEF;
  const uint64_t y = 0x0102;
  const uint64_t expect = (x + y) & mask;

  std::promise<uint64_t> p0, p1;
  auto f0 = p0.get_future();
  auto f1 = p1.get_future();
  std::exception_ptr e0, e1;

  // Swap owners: x owner = 1, y owner = 0.
  std::thread t0(RunParty, ctxs[0], bitlen, x, y, 1, 0, &p0, &e0);
  std::thread t1(RunParty, ctxs[1], bitlen, x, y, 1, 0, &p1, &e1);
  t0.join();
  t1.join();

  if (e0) std::rethrow_exception(e0);
  if (e1) std::rethrow_exception(e1);

  EXPECT_EQ(f0.get(), expect);
  EXPECT_EQ(f1.get(), expect);
}

}  // namespace secretflow::experiment::addition