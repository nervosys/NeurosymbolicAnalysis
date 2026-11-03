//! A deliberately defective target, instrumented with `sda-probe`.
//!
//! Stands in for a firmware build on a toolchain with no sanitizer runtime,
//! which is the case this instrumentation exists for. Run it through the dynamic
//! engine and its coverage and faults reach the correlation engine exactly as a
//! real target's would:
//!
//! ```text
//! cargo build --example instrumented -p sda-probe
//! sda scan crates/sda-probe --artifact target/debug/examples/instrumented
//! ```

/// Reads from a buffer without checking the index — the defect under test.
fn read_sample(buffer: &[u8], index: usize) -> u8 {
    sda_probe::cov(file!(), line!());

    // A real bounds check would return here. This one only *reports*, then
    // carries on to demonstrate the fault reaching the engine.
    if !sda_probe::check_bounds(file!(), line!(), index, buffer.len()) {
        return 0;
    }
    buffer[index]
}

/// A path no input reaches, so the correlation engine should report any static
/// finding inside it as `unreached` rather than clean.
fn never_called(x: u32) -> u32 {
    sda_probe::cov(file!(), line!());
    x * 2
}

fn main() {
    sda_probe::init();

    let buffer = [1u8, 2, 3, 4];
    let mut total: u32 = 0;

    // Exercised heavily: enough executions for the correlation engine to treat
    // an absence of faults here as a refutation.
    for i in 0..64 {
        total += read_sample(&buffer, i % buffer.len()) as u32;
    }

    // Exercised once, out of bounds: this is the fault the engine must see.
    total += read_sample(&buffer, 99) as u32;

    sda_probe::mark("total", total as f64);
    sda_probe::value(file!(), line!(), "iterations", 65.0);

    if std::env::args().any(|a| a == "--call-everything") {
        total += never_called(total);
    }

    sda_probe::flush();
    println!("total={total}");
}
