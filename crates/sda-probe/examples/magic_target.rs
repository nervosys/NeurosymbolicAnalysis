//! A target whose defect sits behind a magic value, reachable only with coverage
//! feedback.
//!
//! Each correct byte opens a new probe location, so a guided campaign keeps that
//! input and works forward one byte at a time. Blind generation would need
//! roughly 2^16 attempts to reach the same place.
//!
//! Two magic bytes, not four, on purpose: this fuzzer executes the target as a
//! *process* per input, which caps throughput at a few tens of runs per second.
//! A four-byte chain needs tens of thousands of runs — perfectly reachable in a
//! real campaign, too slow to serve as a demonstration. See the throughput note
//! in `sda_engine::fuzz`.

use std::io::Read;

fn main() {
    sda_probe::init();

    let mut input = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut input);
    sda_probe::cov(file!(), line!());

    if input.len() >= 4 {
        sda_probe::cov(file!(), line!());
        if sda_probe::cmp_eq!(input[0], b'F') {
            sda_probe::cov(file!(), line!());
            if sda_probe::cmp_eq!(input[1], b'U') {
                sda_probe::cov(file!(), line!());
                // The defect: an index derived from the input, never checked
                // against the buffer it indexes.
                let index = 64 + input.len();
                sda_probe::check_bounds(file!(), line!(), index, input.len());
            }
        }
    }

    sda_probe::flush();
}

