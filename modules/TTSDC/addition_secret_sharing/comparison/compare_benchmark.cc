#include "experiment/mpc/comparison/compare.h"

#include <exception>
#include <future>
#include <thread>

#include "benchmark/benchmark.h"
#include "yacl/link/test_util.h"

namespace secretflow::experiment::comparison {

static void BM_EndToEndCompare(benchmark::State& state) {
  const size_t bitlen = static_cast<size_t>(state.range(0));
  auto ctxs = yacl::link::test::SetupWorld("cmp_bench", 2);

  // Keep values in a safe signed range to match the scheme’s typical assumption.
  const uint64_t x = 100000;
  const uint64_t y = 200000;
  const uint64_t expect = 1;

  for (auto _ : state) {
    std::promise<uint64_t> p0, p1;
    auto f0 = p0.get_future();
    auto f1 = p1.get_future();
    std::exception_ptr e0, e1;

    auto run = [&](int idx, std::promise<uint64_t>* out, std::exception_ptr* eptr) {
      try {
        TwoPartySSCompare prot(ctxs[idx], bitlen);
        auto sx = prot.ShareInput(ctxs[idx]->Rank() == 0 ? x : 0, 0);
        auto sy = prot.ShareInput(ctxs[idx]->Rank() == 1 ? y : 0, 1);
        auto sz = prot.LessThan(sx, sy);
        out->set_value(prot.RevealToAll(sz) & 1ULL);
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

    if (z0 != expect || z1 != expect) {
      state.SkipWithError("wrong compare result");
      break;
    }
  }
}

BENCHMARK(BM_EndToEndCompare)->Arg(8)->Arg(16)->Arg(32);

}  // namespace secretflow::experiment::comparison

BENCHMARK_MAIN();
