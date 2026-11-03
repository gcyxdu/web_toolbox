#include "experiment/mpc/multiplication/two_party_ss_mul.h"

#include <exception>
#include <future>
#include <thread>

#include "benchmark/benchmark.h"
#include "yacl/link/test_util.h"

namespace secretflow::experiment::multiplication {

static uint64_t MulExpect(uint64_t x, uint64_t y, size_t bitlen) {
  uint64_t mask = TwoPartySSMul::RingMask(bitlen);
  __uint128_t p = static_cast<__uint128_t>(x & mask) * static_cast<__uint128_t>(y & mask);
  return static_cast<uint64_t>(p) & mask;
}

static void BM_LocalMulMod(benchmark::State& state) {
  const size_t bitlen = static_cast<size_t>(state.range(0));
  uint64_t mask = TwoPartySSMul::RingMask(bitlen);

  uint64_t a = 0x1234567890ABCDEFULL & mask;
  uint64_t b = 0x0FEDCBA098765432ULL & mask;

  for (auto _ : state) {
    __uint128_t p = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    uint64_t c = static_cast<uint64_t>(p) & mask;
    benchmark::DoNotOptimize(c);
    a ^= c;
  }
}
BENCHMARK(BM_LocalMulMod)->Arg(8)->Arg(16)->Arg(32)->Arg(64);

static void BM_EndToEndMul(benchmark::State& state) {
  const size_t bitlen = static_cast<size_t>(state.range(0));
  auto ctxs = yacl::link::test::SetupWorld("tp_mul_bench", 2);

  const uint64_t x = 0xBEEF1234ULL;
  const uint64_t y = 0x01020304ULL;
  const uint64_t expect = MulExpect(x, y, bitlen);

  for (auto _ : state) {
    std::promise<uint64_t> p0, p1;
    auto f0 = p0.get_future();
    auto f1 = p1.get_future();
    std::exception_ptr e0, e1;

    auto run = [&](int idx, std::promise<uint64_t>* out, std::exception_ptr* eptr) {
      try {
        TwoPartySSMul prot(ctxs[idx], bitlen);
        auto sx = prot.ShareInput(ctxs[idx]->Rank() == 0 ? x : 0, 0);
        auto sy = prot.ShareInput(ctxs[idx]->Rank() == 1 ? y : 0, 1);
        auto sz = prot.Mul(sx, sy);
        out->set_value(prot.RevealToAll(sz));
      } catch (...) {
        *eptr = std::current_exception();
        try { out->set_value(0); } catch (...) {}
      }
    };

    std::thread t0(run, 0, &p0, &e0);
    std::thread t1(run, 1, &p1, &e1);
    t0.join();
    t1.join();

    if (e0) std::rethrow_exception(e0);
    if (e1) std::rethrow_exception(e1);

    auto z0 = f0.get();
    auto z1 = f1.get();
    benchmark::DoNotOptimize(z0);
    benchmark::DoNotOptimize(z1);

    // sanity check (kept cheap)
    if (z0 != expect || z1 != expect) {
      state.SkipWithError("wrong result");
      break;
    }
  }
}
BENCHMARK(BM_EndToEndMul)->Arg(8)->Arg(16)->Arg(32)->Arg(64);

}  // namespace secretflow::experiment::multiplication

BENCHMARK_MAIN();
