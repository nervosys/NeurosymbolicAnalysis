// The shield, specified and proved — the symbolic half of the worked example in
// `crates/sda-engine/tests/neurosymbolic_pipeline.rs`, written so a real prover
// can rule on it.
//
// Three obligations on purpose:
//   * `clamp` returns a value in range          — discharged
//   * `clamp` is total                          — discharged (no panic, no loop)
//   * `unchecked` returns a value in range      — FAILS, and must
//
// The failure is the point. A fixture where everything passes cannot show what a
// prover's refutation looks like, and a refutation is what becomes a `Confirmed`
// verdict on the `sda` side.
use vstd::prelude::*;

verus! {

pub const LIMIT: i32 = 100;

pub open spec fn in_range(v: i32) -> bool {
    -LIMIT <= v && v <= LIMIT
}

/// The guard. Every command handed to the actuator goes through this.
pub fn clamp(command: i32) -> (result: i32)
    ensures
        in_range(result),
        in_range(command) ==> result == command,
{
    if command > LIMIT {
        LIMIT
    } else if command < -LIMIT {
        -LIMIT
    } else {
        command
    }
}

/// The same postcondition, without the guard. Verus must refuse this.
pub fn unchecked(command: i32) -> (result: i32)
    ensures
        in_range(result),
{
    command
}

fn main() {
}

}
