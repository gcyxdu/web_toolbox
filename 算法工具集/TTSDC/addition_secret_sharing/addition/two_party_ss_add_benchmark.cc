#include "experiment/mpc/addition/two_party_ss_add.h"

#include <exception>
#include <future>
#include <thread>

#include "benchmark/benchmark.h"
#include "yacl/link/test_util.h"

namespace secretflow::experiment::addition {

static void BM_LocalAddMod(benchmark::State& state) {  
  const size_t bitlen = static_cast<size_t>(state.range(0));
  uint64_t a = 0x1234567890ABCDEFULL;
  uint64_t b = 0x0FEDCBA098765432ULL;

  for (auto _ : state) {
    const uint64_t c = TwoPartySSAdd::AddMod(a, b, bitlen);
    benchmark::DoNotOptimize(c);
    a ^= c;
  }
}
BENCHMARK(BM_LocalAddMod)->Arg(8)->Arg(16)->Arg(32)->Arg(64);

static void BM_EndToEndAdd(benchmark::State& state) {
  const size_t bitlen = static_cast<size_t>(state.range(0));
  auto ctxs = yacl::link::test::SetupWorld("tp_add_bench", 2);

  // Use fixed inputs to reduce noise; protocol still exercises link.
  const uint64_t x = 0xBEEF1234ULL;
  const uint64_t y = 0x01020304ULL;

  for (auto _ : state) {
    std::promise<uint64_t> p0, p1;
    auto f0 = p0.get_future();
    auto f1 = p1.get_future();
    std::exception_ptr e0, e1;

    auto run = [&](int idx, std::promise<uint64_t>* out,
                   std::exception_ptr* ep) {
      try {
        TwoPartySSAdd prot(ctxs[idx], bitlen);
        const uint64_t x_in = (ctxs[idx]->Rank() == 0) ? x : 0;
        const uint64_t y_in = (ctxs[idx]->Rank() == 1) ? y : 0;
        auto sx = prot.ShareInput(x_in, 0);
        auto sy = prot.ShareInput(y_in, 1);
        auto sz = prot.Add(sx, sy);
        out->set_value(prot.RevealToAll(sz));
      } catch (...) {
        *ep = std::current_exception();
        try {
          out->set_value(0);
        } catch (...) {
        }
      }
    };

    std::thread t0(run, 0, &p0, &e0);
    std::thread t1(run, 1, &p1, &e1);
    t0.join();
    t1.join();

    if (e0) std::rethrow_exception(e0);
    if (e1) std::rethrow_exception(e1);

    benchmark::DoNotOptimize(f0.get());
    benchmark::DoNotOptimize(f1.get());
  }
}
BENCHMARK(BM_EndToEndAdd)->Arg(8)->Arg(16)->Arg(32)->Arg(64);

}  // namespace secretflow::experiment::addition

BENCHMARK_MAIN();