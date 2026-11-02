#pragma once

#include <memory>

#include "yacl/link/context.h"

#include "experiment/mpc/comparison/ot_helper.h"
#include "experiment/mpc/comparison/types.h"

namespace secretflow::experiment::comparison {

// Boolean AND on xor-sharing bits, using Boolean Beaver triple online.
// Beaver triple (a,b,c=a&b) is generated offline via OT for cross terms.
class BooleanAnd final {
 public:
  explicit BooleanAnd(std::shared_ptr<yacl::link::Context> lctx);

  // XOR-share semantics:
  //   open(x) = x0 XOR x1
  BoolShare Xor(const BoolShare& a, const BoolShare& b) const;
  BoolShare XorConst(const BoolShare& a, bool c) const;  // public XOR with c

  // Secure AND gate.
  BoolShare And(const BoolShare& x, const BoolShare& y);

 private:
  struct TripleShare {
    bool a = false;
    bool b = false;
    bool c = false;  // share so that c0 XOR c1 = (a0 XOR a1) & (b0 XOR b1)
  };

  void CheckTwoPartyOrThrow() const;

  // OT-mul share for bits:
  // Compute shares t0,t1 such that t0 XOR t1 = u & v (GF(2)).
  // sender_rank holds u, other holds v.
  bool OtMulBitShare(bool u_or_v, size_t sender_rank);

  TripleShare GenTriple();

  // pack/unpack 2 bits for opening (d,e)
  static yacl::Buffer Pack2Bits(bool b0, bool b1);
  static void Unpack2Bits(const yacl::Buffer& buf, bool* b0, bool* b1);

 private:
  std::shared_ptr<yacl::link::Context> lctx_;
  OtHelper ot_;
};

}  // namespace secretflow::experiment::comparison
