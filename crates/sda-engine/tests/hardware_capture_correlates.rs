//! A probe stream from a target this machine cannot execute, correlated.
//!
//! Every other dynamic test in this suite observes a program the host ran. This
//! one does not: the fixture is the UART output of a freestanding Cortex-M3
//! image — `examples/firmware-cortex-m`, linked with `-nostdlib` and no compiler
//! runtime, 2,160 bytes of text — executed on an emulated Stellaris LM3S6965
//! under `qemu-system-arm` 10.0.11, with `arm-none-eabi-gcc` 14.2.1.
//!
//! That closes the gap `HANDOFF.md` called the highest-value one. The shim's own
//! header said its freestanding path "has been read carefully but never
//! assembled"; the bare-metal images had been *linked* for four architectures
//! and never *run*, so everything past the link step was
//! claim-by-construction. `examples/firmware/fake_instrumented.bat` wrote probe
//! records by hand, which is the thing this replaces.
//!
//! The capture is twelve records and every one can be checked against the source
//! by hand — see `examples/firmware-cortex-m/README.md`. The program is arranged
//! so that one function faults, one runs clean, and one is never called.

use sda_core::RuntimeEventKind;
use sda_engine::parse_probe_capture;

/// The real thing, byte for byte, as it arrived on the UART.
const CAPTURE: &str = include_str!("fixtures/qemu-lm3s6965-cortex-m3.jsonl");

fn observation() -> sda_engine::Observation {
    let (obs, summary) = parse_probe_capture(CAPTURE, "qemu-lm3s6965");
    assert_eq!(summary.records, 12, "the capture is twelve records");
    assert_eq!(
        summary.unreadable, 0,
        "the UART carried nothing but records; framing noise here would be a real finding"
    );
    obs
}

/// The shim's records survive the trip through a UART, an emulator and a file.
///
/// Not a formatting test: the C emitter is exercised on the host elsewhere. What
/// is new is that this build used `SDA_PROBE_NO_FLOAT` and a custom sink, on a
/// 32-bit target, through a byte-at-a-time transmit register.
#[test]
fn a_freestanding_target_emits_records_the_engine_can_read() {
    let obs = observation();

    // `decode` is called four times; the fourth returns early through the bounds
    // check, so its second probe is reached three times.
    assert_eq!(obs.covered("src/main.c", 64), 4, "decode entered four times");
    assert_eq!(obs.covered("src/main.c", 69), 3, "and returned normally three times");
    assert_eq!(obs.covered("src/main.c", 77), 1, "checksum ran once");

    assert!(obs.marks.contains_key("stack_bytes"), "SDA_MARK survived NO_FLOAT");
}

/// The stack figure is measured, not declared.
///
/// It used to be `SDA_MARK("stack_bytes", 1024)` — a number the program had been
/// told, reported as though it had been observed. On a part where the stack
/// grows towards `.bss` that is the difference between a margin and an accident,
/// and it is the same defect as every other entry in this repository's table:
/// something unknown, presented as something known.
///
/// The image now fills the unused stack with `0xC0DEC0DE` before `main` and
/// reports the lowest address still holding it, which is a high-water mark for
/// the whole run.
#[test]
fn the_stack_figure_is_a_measurement_and_not_a_declaration() {
    let obs = observation();
    let used = *obs.marks.get("stack_bytes").expect("the mark is in the capture");

    assert_ne!(used, 1024.0, "1024 was the declared number this replaced");
    assert!(used > 0.0, "the program used some stack");
    assert!(used < 65536.0, "and less than the 64K of SRAM the part has");

    // The painter leaves its own frame unpainted, so the reported figure carries
    // that margin. Stating the bound is the point: a measurement with a known
    // floor is still a measurement, and a reader can see how much slack it has.
    assert!(
        used >= 32.0,
        "the figure includes the 32-byte paint margin, so it cannot be smaller"
    );

    // The value this build produced. Pinned so a change is noticed and explained
    // rather than absorbed: a different compiler, optimisation level or startup
    // path moves it, and that is worth seeing.
    assert_eq!(used, 632.0, "arm-none-eabi-gcc 14.2.1 at -O1 for this image");
}

/// The fault is a real one: the fourth `decode` was handed an index past the end
/// of an eight-byte buffer, and the check fired on the target rather than in a
/// fixture someone wrote.
#[test]
fn the_bounds_fault_the_program_committed_arrives_as_a_runtime_defect() {
    let obs = observation();
    let faults: Vec<_> = obs
        .defects()
        .filter(|e| e.location.as_ref().is_some_and(|l| l.line == 66))
        .collect();
    assert_eq!(faults.len(), 1, "one fault, at the bounds check");
    assert_eq!(faults[0].kind, RuntimeEventKind::MemoryError);
    assert!(faults[0].detail.contains("past the end of the frame"));
}

/// The distinction the toolkit exists for, on real evidence: `recovery` is never
/// called, and nothing in the capture says otherwise.
#[test]
fn a_function_that_was_never_called_leaves_no_trace() {
    let obs = observation();
    assert_eq!(obs.covered("src/main.c", 88), 0, "recovery's probe never fired");
    assert!(
        !obs.measured("src/main.c", 88),
        "and no record exists for it either — unknown, not measured-at-zero"
    );
    assert!(
        obs.file_executed("src/main.c"),
        "while the file demonstrably ran, which is what makes the line's silence meaningful"
    );
}

/// Hand-placed probes cover a handful of lines, so most of the file is
/// *unmeasured* rather than *measured at zero*. Those are different claims and
/// the report may only make the weaker one.
///
/// This is what the run found. Every unreached finding used to carry
/// `executions = 0`, a metric asserting a count nobody had taken — the prose
/// beside it said "produced no coverage record", correctly, while the structured
/// evidence a machine reads said something else.
#[test]
fn an_uninstrumented_line_is_not_reported_as_measured_at_zero() {
    let obs = observation();
    assert!(obs.measured("src/main.c", 64), "a line with a probe was measured");
    assert!(
        !obs.measured("src/main.c", 63),
        "the line above it has no probe and was measured by nothing"
    );
    assert_eq!(
        obs.covered("src/main.c", 63),
        0,
        "`covered` cannot tell the two apart, which is why `measured` exists"
    );
}
