//! A native coverage-guided fuzzer.
//!
//! The correlation engine can only adjudicate code that *ran*. Before this
//! existed, the inputs driving a dynamic run had to come from a human, so most
//! static findings came back `Unreached` — untested, not clean. A fuzzer is what
//! converts those into real verdicts, which makes it less an extra feature than
//! the thing that makes the rest of the correlation useful.
//!
//! Feedback comes from the SDA probe stream, so it works on any target that
//! links `sda-probe` or the C shim — including bare-metal toolchains with no
//! sanitizer runtime and no compiler coverage flag, which is exactly the
//! population that has no other option.
//!
//! # Determinism
//!
//! Everything is driven by a seeded xorshift generator, and the same seed with
//! the same corpus produces the same campaign. That is not a nicety: a
//! compliance run has to be repeatable, and a crash you cannot reproduce is a
//! rumour rather than a finding.

use crate::dynamic::{Observation, RunSpec, run_once};
use sda_core::{Confidence, Evidence, Finding, Location, RuntimeEventKind, Severity};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A reproducible pseudo-random generator. Small, seeded, and dependency-free.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // A zero state is a fixed point for xorshift; substitute a constant.
        Rng(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

/// Values that disproportionately often sit on a boundary condition.
const INTERESTING: &[i64] = &[
    0, 1, -1, 7, 8, 15, 16, 31, 32, 63, 64, 100, 127, -128, 128, 255, 256, 511, 512, 1000, 1024,
    4096, 32767, -32768, 65535, 65536, 2147483647, -2147483648,
];

/// One input and what it achieved.
#[derive(Clone, Debug)]
pub struct Entry {
    pub data: Vec<u8>,
    /// Source locations this input reached.
    pub coverage: BTreeSet<(String, u32)>,
    /// How many times it has been chosen as a mutation base.
    pub uses: u32,
}

/// A crash or fault, with the input that produced it.
#[derive(Clone, Debug)]
pub struct Crash {
    pub input: Vec<u8>,
    pub kind: RuntimeEventKind,
    pub detail: String,
    pub location: Option<Location>,
    /// Where the reproducing input was written.
    pub saved_to: Option<PathBuf>,
}

/// What a campaign achieved.
#[derive(Clone, Debug, Default)]
pub struct FuzzReport {
    pub runs: u64,
    pub corpus_size: usize,
    /// Distinct source locations reached across the whole campaign.
    pub coverage: BTreeSet<(String, u32)>,
    pub crashes: Vec<Crash>,
    pub elapsed_ms: u64,
    /// Runs that produced no probe output at all — the sign of a target that
    /// was never instrumented, which makes the whole campaign blind.
    pub runs_without_feedback: u64,
    /// Candidate crashes that did not happen again when their input was
    /// replayed. Reported rather than hidden: on a loaded machine a slow process
    /// spawn looks exactly like a hang, and the difference matters.
    pub unreproducible: u64,
}

impl FuzzReport {
    /// Whether the campaign had coverage feedback to steer by.
    ///
    /// Without it a "fuzzer" is a random input generator: it will still find a
    /// crash that a random input happens to trigger, and it will not
    /// systematically explore anything.
    pub fn had_feedback(&self) -> bool {
        !self.coverage.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} run(s) in {} ms; corpus {}; {} distinct location(s) reached; {} crash(es).",
            self.runs,
            self.elapsed_ms,
            self.corpus_size,
            self.coverage.len(),
            self.crashes.len()
        );
        if !self.had_feedback() {
            s.push_str(
                "\nNO COVERAGE FEEDBACK: the target produced no probe records, so this campaign \
                 was blind random input generation, not guided fuzzing. Link `sda-probe` or the \
                 C shim and rebuild, or the correlation engine will report everything as unreached.",
            );
        } else if self.runs_without_feedback > self.runs / 2 {
            s.push_str(&format!(
                "\nWarning: {} of {} runs produced no probe records; feedback is sparse and \
                 exploration will be correspondingly poor.",
                self.runs_without_feedback, self.runs
            ));
        }
        if self.unreproducible > 0 {
            s.push_str(&format!(
                "\n{} candidate crash(es) did not happen again when replayed and were discarded. \
                 A timeout under load looks identical to a hang, so a candidate timeout must \
                 recur on every replay to be believed; if you expected a crash here, re-run with \
                 a longer per-execution timeout.",
                self.unreproducible
            ));
        }
        s
    }
}

/// How to run a campaign.
#[derive(Clone, Debug)]
pub struct FuzzConfig {
    pub runs: u64,
    pub seed: u64,
    /// Per-execution time budget.
    pub timeout: Duration,
    /// Overall wall-clock budget.
    pub max_duration: Duration,
    /// Where to write reproducing inputs for crashes.
    pub crash_dir: Option<PathBuf>,
    /// Largest input to generate.
    pub max_input: usize,
    /// Stop as soon as a crash is found, rather than continuing to explore.
    pub stop_on_crash: bool,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        FuzzConfig {
            runs: 1000,
            seed: 0x5DA_5EED,
            timeout: Duration::from_secs(2),
            max_duration: Duration::from_secs(60),
            crash_dir: None,
            // Deliberately modest. A large bound lets the corpus bloat, and a
            // bloated corpus mutates badly; raise it only for formats that
            // genuinely need it.
            max_input: 256,
            stop_on_crash: false,
        }
    }
}

/// Mutate `input`, returning a new candidate.
///
/// Public and deterministic so a campaign can be replayed, and so the mutation
/// strategy can be tested independently of running anything.
pub fn mutate(input: &[u8], rng: &mut Rng, max_len: usize) -> Vec<u8> {
    mutate_with_dictionary(input, rng, max_len, &[])
}

/// Mutate, with a dictionary of values the program was seen comparing against.
///
/// The dictionary is what makes this fuzzer viable. Executing a process per
/// input caps throughput at tens of runs per second, so a four-byte magic value
/// — 2^32 blind guesses — is permanently out of reach by brute force. Watching
/// the program compare its input against a constant, and then writing that
/// constant into the input, reaches it in a handful of runs instead. Knowledge
/// substitutes for the throughput this architecture cannot have.
pub fn mutate_with_dictionary(
    input: &[u8],
    rng: &mut Rng,
    max_len: usize,
    dictionary: &[u64],
) -> Vec<u8> {
    let mut out = input.to_vec();
    if out.is_empty() {
        out.push(rng.byte());
    }

    // Try the dictionary often when there is one: these are the values the
    // program actually asked about, so they are worth far more than a random byte.
    if !dictionary.is_empty() && rng.below(3) == 0 {
        let value = dictionary[rng.below(dictionary.len())];
        let at = rng.below(out.len());
        // Widths are tried separately because the instrumentation cannot know
        // whether the comparison was on a byte, a word, or a longer field.
        let width = [1usize, 2, 4, 8][rng.below(4)];
        let bytes = value.to_le_bytes();
        for k in 0..width {
            if at + k < out.len() {
                out[at + k] = bytes[k];
            }
        }
        return out;
    }

    match rng.below(8) {
        // Flip a single bit: the cheapest way to cross a comparison boundary.
        0 => {
            let i = rng.below(out.len());
            let bit = rng.below(8);
            out[i] ^= 1 << bit;
        }
        // Replace a byte outright.
        1 => {
            let i = rng.below(out.len());
            out[i] = rng.byte();
        }
        // Nudge a byte, for length fields and counters.
        2 => {
            let i = rng.below(out.len());
            let delta = (rng.below(35) as i32) - 17;
            out[i] = (out[i] as i32).wrapping_add(delta) as u8;
        }
        // Write an interesting value, little-endian.
        3 => {
            let v = INTERESTING[rng.below(INTERESTING.len())];
            let width = [1usize, 2, 4, 8][rng.below(4)];
            let i = rng.below(out.len());
            let bytes = v.to_le_bytes();
            for k in 0..width.min(bytes.len()) {
                if i + k < out.len() {
                    out[i + k] = bytes[k];
                }
            }
        }
        // Duplicate a chunk, to grow structure.
        4 if out.len() < max_len => {
            let len = (rng.below(out.len()) + 1).min(max_len - out.len());
            let from = rng.below(out.len());
            let at = rng.below(out.len());
            let chunk: Vec<u8> =
                (0..len).map(|k| out[(from + k) % out.len()]).collect();
            out.splice(at..at, chunk);
        }
        // Delete a chunk, to find the minimal trigger.
        5 if out.len() > 1 => {
            let len = rng.below(out.len() - 1) + 1;
            let at = rng.below(out.len() - len);
            out.drain(at..at + len);
        }
        // Append a few random bytes. Kept small: every byte added dilutes the
        // chance that a later mutation lands on the byte that matters.
        6 if out.len() < max_len => {
            let n = (rng.below(4) + 1).min(max_len - out.len());
            for _ in 0..n {
                out.push(rng.byte());
            }
        }
        // Several small edits at once. This is what actually walks a chain of
        // comparisons: one edit per run explores too slowly, and a huge edit
        // destroys the prefix that got the input this far.
        _ => {
            let edits = rng.below(4) + 2;
            for _ in 0..edits {
                let i = rng.below(out.len());
                match rng.below(3) {
                    0 => out[i] ^= 1 << rng.below(8),
                    1 => out[i] = rng.byte(),
                    _ => {
                        let v = INTERESTING[rng.below(INTERESTING.len())];
                        out[i] = v as u8;
                    }
                }
            }
        }
    }

    out.truncate(max_len);
    out
}

/// Splice two inputs, which recombines structure the mutator would take a long
/// time to rediscover.
pub fn splice(a: &[u8], b: &[u8], rng: &mut Rng, max_len: usize) -> Vec<u8> {
    if a.is_empty() || b.is_empty() {
        return if a.is_empty() { b.to_vec() } else { a.to_vec() };
    }
    let split_a = rng.below(a.len());
    let split_b = rng.below(b.len());
    let mut out = a[..split_a].to_vec();
    out.extend_from_slice(&b[split_b..]);
    out.truncate(max_len);
    out
}

/// Run a campaign against `program`.
pub fn campaign(
    program: &Path,
    args: &[String],
    seeds: Vec<Vec<u8>>,
    config: &FuzzConfig,
) -> sda_core::Result<(FuzzReport, Observation)> {
    let started = Instant::now();
    let mut rng = Rng::new(config.seed);
    let mut report = FuzzReport::default();
    let mut merged = Observation::default();

    // Start from the supplied seeds, or a single empty input.
    let mut corpus: Vec<Entry> = Vec::new();
    let initial = if seeds.is_empty() { vec![vec![b'0']] } else { seeds };

    for (i, data) in initial.into_iter().enumerate() {
        // The seeds spend the same budget as the mutation loop below. Without this
        // check a large corpus runs in full whatever `runs` and `max_duration` say.
        if report.runs >= config.runs || started.elapsed() >= config.max_duration {
            break;
        }
        let (entry, obs, crash) = execute(program, args, &data, config, i as u64)?;
        report.runs += 1;
        if obs.coverage.is_empty() {
            report.runs_without_feedback += 1;
        }
        merged.merge(obs);
        let crash = confirm(program, args, crash, &data, config, &mut report, i as u64);
        record_crash(&mut report, crash, &data, config);
        corpus.push(entry);
    }

    while report.runs < config.runs && started.elapsed() < config.max_duration {
        if config.stop_on_crash && !report.crashes.is_empty() {
            break;
        }

        // Favour inputs that have been used least: an input that keeps being
        // chosen and keeps finding nothing is a local minimum.
        let base = pick(&corpus, &mut rng);
        // Values the target has been seen comparing against, accumulated across
        // the whole campaign.
        let dictionary: Vec<u64> = merged.comparisons.iter().copied().collect();
        let candidate = if corpus.len() > 1 && rng.below(10) == 0 {
            let other = pick(&corpus, &mut rng);
            splice(&corpus[base].data, &corpus[other].data, &mut rng, config.max_input)
        } else {
            mutate_with_dictionary(
                &corpus[base].data,
                &mut rng,
                config.max_input,
                &dictionary,
            )
        };
        corpus[base].uses += 1;

        let (entry, obs, crash) = execute(program, args, &candidate, config, report.runs)?;
        report.runs += 1;
        if obs.coverage.is_empty() {
            report.runs_without_feedback += 1;
        }
        merged.merge(obs);

        // Keep the input only if it reached somewhere new. Without this the
        // corpus grows without bound and exploration degenerates to random.
        let new_locations: BTreeSet<(String, u32)> =
            entry.coverage.difference(&report.coverage).cloned().collect();
        if !new_locations.is_empty() {
            report.coverage.extend(new_locations);
            corpus.push(entry);
        }

        let run = report.runs;
        let crash = confirm(program, args, crash, &candidate, config, &mut report, run);
        record_crash(&mut report, crash, &candidate, config);
    }

    report.corpus_size = corpus.len();
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok((report, merged))
}

/// Choose a corpus index, preferring inputs that are small and little-used.
///
/// Size matters more than it looks. A mutation picks a byte position uniformly,
/// so the chance of hitting the one byte that matters falls as 1/len — an input
/// that has bloated to 400 bytes is a far worse mutation base than an equivalent
/// one of 8, even though both reach the same code. Left unweighted, the corpus
/// drifts toward long inputs and exploration stalls; that is exactly what
/// happened on the first run of the bundled magic-value target.
fn pick(corpus: &[Entry], rng: &mut Rng) -> usize {
    if corpus.len() == 1 {
        return 0;
    }
    // Tournament of two on (uses, length). Cheap, and enough to keep one input
    // from dominating while steadily favouring compact ones.
    let a = rng.below(corpus.len());
    let b = rng.below(corpus.len());
    let score = |e: &Entry| (e.uses as usize).saturating_mul(4) + e.data.len();
    if score(&corpus[a]) <= score(&corpus[b]) { a } else { b }
}

type Execution = (Entry, Observation, Option<(RuntimeEventKind, String, Option<Location>)>);

fn execute(
    program: &Path,
    args: &[String],
    data: &[u8],
    config: &FuzzConfig,
    run: u64,
) -> sda_core::Result<Execution> {
    let mut spec = RunSpec::new(program)
        .with_stdin(data.to_vec())
        .timeout(config.timeout)
        .id(format!("fuzz-{run}"));
    spec.args = args.to_vec();

    let (_, obs) = run_once(&spec)?;
    let coverage: BTreeSet<(String, u32)> = obs.coverage.keys().cloned().collect();

    let crash = obs
        .defects()
        .next()
        .map(|e| (e.kind, e.detail.clone(), e.location.clone()));

    Ok((Entry { data: data.to_vec(), coverage, uses: 0 }, obs, crash))
}

/// Re-run an input and report whether the same class of defect happens again.
///
/// A campaign that reports a crash is making a claim — the finding literally
/// says "a N-byte input reproduces it" — and until this existed that claim was
/// never checked. A real run reported a `critical` resource-exhaustion crash
/// whose saved reproducer, replayed five times, exited 0 in about 30 ms each
/// time: one slow process spawn on a loaded machine, promoted to a critical
/// finding. Timeouts are the common case, but any one-shot observation can be
/// environmental, so every candidate is confirmed before it is believed.
/// How many consecutive replays a candidate crash must survive to be believed.
///
/// A fault the target itself detected — a bounds check, a sanitizer report, a
/// signal — is deterministic, so one replay settles it. A timeout is not: it is
/// a statement about wall-clock time on a shared machine, and a parallel build
/// makes a healthy process look hung. Requiring a timeout to recur every time
/// costs two extra executions on a candidate that is rare by construction.
pub fn confirmations_required(kind: RuntimeEventKind) -> u64 {
    match kind {
        RuntimeEventKind::ResourceExhaustion => 3,
        _ => 1,
    }
}

fn reproduces(
    program: &Path,
    args: &[String],
    input: &[u8],
    config: &FuzzConfig,
    kind: RuntimeEventKind,
    run: u64,
) -> bool {
    // A hang is deterministic; a slow spawn is not. One confirming replay is
    // enough for a fault the target actually detected, but not for a timeout:
    // on a machine under load — a parallel build, say — the replay is as likely
    // to be slow as the original run was, and a single extra sample confirms
    // the noise instead of filtering it. Demanding that a timeout recur every
    // time costs two executions and separates the two cases.
    let attempts = confirmations_required(kind);
    for attempt in 0..attempts {
        let seen = match execute(program, args, input, config, run + attempt) {
            Ok((_, _, Some((seen, _, _)))) => seen == kind,
            _ => false,
        };
        if !seen {
            return false;
        }
    }
    true
}

/// Keep a candidate crash only if re-running its input shows the same defect.
/// A candidate that does not survive this is counted, not reported: silence
/// about a discarded critical finding would be its own kind of dishonesty.
#[allow(clippy::too_many_arguments)]
fn confirm(
    program: &Path,
    args: &[String],
    crash: Option<(RuntimeEventKind, String, Option<Location>)>,
    input: &[u8],
    config: &FuzzConfig,
    report: &mut FuzzReport,
    run: u64,
) -> Option<(RuntimeEventKind, String, Option<Location>)> {
    let (kind, detail, location) = crash?;

    // Already known: no need to pay for another execution.
    let known = report
        .crashes
        .iter()
        .any(|c| c.kind == kind && c.location == location && c.detail == detail);
    if known {
        return Some((kind, detail, location));
    }

    if reproduces(program, args, input, config, kind, run) {
        Some((kind, detail, location))
    } else {
        report.unreproducible += 1;
        None
    }
}

fn record_crash(
    report: &mut FuzzReport,
    crash: Option<(RuntimeEventKind, String, Option<Location>)>,
    input: &[u8],
    config: &FuzzConfig,
) {
    let Some((kind, detail, location)) = crash else {
        return;
    };
    // Deduplicate by what failed and where, not by input: a thousand inputs
    // hitting one bug is one bug.
    let already = report
        .crashes
        .iter()
        .any(|c| c.kind == kind && c.location == location && c.detail == detail);
    if already {
        return;
    }

    // Through the symlink guard: the target being fuzzed can commit `.sda`.
    let saved_to = config.crash_dir.as_ref().and_then(|dir| {
        let name = format!("crash-{:04}-{}.bin", report.crashes.len(), kind_slug(kind));
        let path = dir.join(name);
        sda_core::safe_write::write_refusing_symlinks(&path, input).ok()?;
        Some(path)
    });

    report.crashes.push(Crash { input: input.to_vec(), kind, detail, location, saved_to });
}

fn kind_slug(k: RuntimeEventKind) -> &'static str {
    use RuntimeEventKind::*;
    match k {
        MemoryError => "memory",
        Crash => "crash",
        DataRace => "race",
        UndefinedBehavior => "ub",
        Leak => "leak",
        ResourceExhaustion => "resource",
        _ => "other",
    }
}

/// Turn a campaign's crashes into findings.
pub fn findings_from(report: &FuzzReport, fallback: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    for crash in &report.crashes {
        let location = crash.location.clone().unwrap_or_else(|| Location::file_only(fallback));
        let mut f = Finding::new(
            "sda.fuzz",
            format!("SDA-FUZZ-{}", kind_slug(crash.kind).to_uppercase()),
            format!("fuzzing reached a {} defect", kind_slug(crash.kind)),
            Severity::Critical,
            location,
        )
        .message(format!(
            "{}{} A {}-byte input reproduces it.",
            crash.detail,
            if crash.detail.ends_with(['.', '!', '?']) { "" } else { "." },
            crash.input.len()
        ))
        // A generated input reproduced it, so this is not a suspicion.
        .confidence(Confidence::Certain)
        .phase(sda_core::AnalysisPhase::Dynamic)
        .taxonomy(sda_core::TaxonomyRef::cwe(match crash.kind {
            RuntimeEventKind::MemoryError => 787,
            RuntimeEventKind::UndefinedBehavior => 758,
            RuntimeEventKind::ResourceExhaustion => 400,
            _ => 248,
        }));

        if let Some(path) = &crash.saved_to {
            f = f.remediation(format!(
                "Reproduce with: {} < {}",
                fallback,
                path.display()
            ));
        }
        f = f.evidence(Evidence::Note {
            text: format!("input (hex, first 64 bytes): {}", hex(&crash.input, 64)),
        });
        out.push(f);
    }

    // A campaign with no feedback found whatever it found by luck. Say so, or a
    // clean result reads as "fuzzing found nothing" instead of "fuzzing was blind".
    if !report.had_feedback() && report.runs > 0 {
        out.push(
            Finding::new(
                "sda.fuzz",
                "SDA-FUZZ-NO-FEEDBACK",
                "the fuzzing campaign had no coverage feedback",
                Severity::Medium,
                Location::file_only(fallback),
            )
            .message(format!(
                "{} run(s) produced no probe records, so inputs were generated blindly rather \
                 than guided toward unexplored code. Link `sda-probe` (or `shim/sda_probe.h`) and \
                 rebuild before reading this campaign as coverage of anything.",
                report.runs
            ))
            .confidence(Confidence::Certain),
        );
    }

    out
}

fn hex(bytes: &[u8], limit: usize) -> String {
    let mut s = String::new();
    for b in bytes.iter().take(limit) {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > limit {
        s.push('…');
    }
    s
}

/// Load seed inputs from a corpus directory.
pub fn load_corpus(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, Vec<u8>)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter_map(|p| std::fs::read(&p).ok().map(|d| (p, d)))
        .collect();
    // Deterministic order, so a campaign from the same corpus replays identically.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter().map(|(_, d)| d).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A timeout is the one candidate class that is a claim about wall-clock
    /// time rather than about the program, so it is the one that machine load
    /// can manufacture. A real campaign reported a `critical`
    /// resource-exhaustion crash at 2321 ms against a 2000 ms budget while a
    /// parallel build was running; single-replay confirmation passed it,
    /// because the replay was slow for the same reason the original was.
    #[test]
    fn a_timeout_must_recur_more_than_once_to_be_believed() {
        assert_eq!(
            confirmations_required(RuntimeEventKind::ResourceExhaustion),
            3,
            "one extra sample under sustained load confirms the noise instead of filtering it"
        );

        // Faults the target itself detected are deterministic; paying for extra
        // executions on every one of them would slow the campaign for nothing.
        for kind in [
            RuntimeEventKind::MemoryError,
            RuntimeEventKind::Crash,
            RuntimeEventKind::UndefinedBehavior,
            RuntimeEventKind::SanitizerReport,
        ] {
            assert_eq!(confirmations_required(kind), 1, "{kind:?} is deterministic");
        }
    }

    #[test]
    fn the_generator_is_deterministic_and_never_sticks_at_zero() {
        let a: Vec<u64> = (0..8).map(|_| Rng::new(42).next()).collect();
        let b: Vec<u64> = (0..8).map(|_| Rng::new(42).next()).collect();
        assert_eq!(a, b);

        // A zero seed must not produce a constant stream.
        let mut z = Rng::new(0);
        let first = z.next();
        assert_ne!(first, z.next());
    }

    #[test]
    fn mutation_is_reproducible_from_a_seed() {
        let input = b"the quick brown fox".to_vec();
        let run = |seed| {
            let mut rng = Rng::new(seed);
            (0..20).map(|_| mutate(&input, &mut rng, 64)).collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7), "a campaign must replay identically");
        assert_ne!(run(7), run(8));
    }

    #[test]
    fn mutation_respects_the_length_bound() {
        let mut rng = Rng::new(3);
        let mut input = vec![b'A'; 32];
        for _ in 0..500 {
            input = mutate(&input, &mut rng, 64);
            assert!(input.len() <= 64, "mutation exceeded the bound: {}", input.len());
        }
    }

    #[test]
    fn mutation_of_an_empty_input_produces_something() {
        let mut rng = Rng::new(1);
        for _ in 0..50 {
            assert!(!mutate(&[], &mut rng, 16).is_empty());
        }
    }

    #[test]
    fn mutation_actually_changes_the_input_most_of_the_time() {
        let mut rng = Rng::new(11);
        let input = b"0123456789abcdef".to_vec();
        let changed = (0..200).filter(|_| mutate(&input, &mut rng, 64) != input).count();
        assert!(changed > 150, "only {changed}/200 mutations differed");
    }

    #[test]
    fn splicing_combines_both_parents_and_handles_empties() {
        let mut rng = Rng::new(5);
        let out = splice(b"AAAA", b"BBBB", &mut rng, 64);
        assert!(!out.is_empty());
        assert_eq!(splice(b"", b"BBBB", &mut rng, 64), b"BBBB".to_vec());
        assert_eq!(splice(b"AAAA", b"", &mut rng, 64), b"AAAA".to_vec());
    }

    /// A campaign that reports a crash claims its input reproduces it, and that
    /// claim used to go unchecked. A real run against an MSVC-built target
    /// reported a `critical` resource-exhaustion crash; replaying the saved
    /// reproducer five times gave exit 0 in ~30 ms each time. One slow process
    /// spawn had been promoted to a critical finding.
    #[test]
    fn a_candidate_that_does_not_happen_again_is_discarded_and_counted() {
        // A target that always exits cleanly: nothing it produces can reproduce.
        let program = std::path::Path::new(if cfg!(windows) { "cmd" } else { "true" });
        let args: Vec<String> =
            if cfg!(windows) { vec!["/C".into(), "exit".into(), "0".into()] } else { vec![] };

        let mut report = FuzzReport::default();
        let config = FuzzConfig { timeout: Duration::from_secs(5), ..Default::default() };
        let candidate = Some((
            RuntimeEventKind::ResourceExhaustion,
            "target did not terminate within its time budget".to_string(),
            None,
        ));

        let kept = confirm(program, &args, candidate, b"A", &config, &mut report, 0);
        assert!(kept.is_none(), "an unrepeatable failure must not become a finding");
        assert_eq!(report.unreproducible, 1, "and it must be counted, not silently dropped");

        record_crash(&mut report, kept, b"A", &config);
        assert!(report.crashes.is_empty());
        assert!(
            report.summary().contains("did not happen again"),
            "the summary must say what was discarded: {}",
            report.summary()
        );
    }

    #[test]
    fn crashes_are_deduplicated_by_defect_not_by_input() {
        let config = FuzzConfig::default();
        let mut report = FuzzReport::default();
        let crash = Some((
            RuntimeEventKind::MemoryError,
            "oob write".to_string(),
            Some(Location::new("a.c", 10, 1)),
        ));
        record_crash(&mut report, crash.clone(), b"input-one", &config);
        record_crash(&mut report, crash, b"input-two", &config);
        assert_eq!(report.crashes.len(), 1, "one bug found twice is one bug");

        // A different location is a different bug.
        record_crash(
            &mut report,
            Some((
                RuntimeEventKind::MemoryError,
                "oob write".to_string(),
                Some(Location::new("a.c", 99, 1)),
            )),
            b"input-three",
            &config,
        );
        assert_eq!(report.crashes.len(), 2);
    }

    #[test]
    fn a_campaign_without_feedback_says_it_was_blind() {
        let report = FuzzReport { runs: 500, ..Default::default() };
        assert!(!report.had_feedback());
        assert!(report.summary().contains("NO COVERAGE FEEDBACK"));

        let findings = findings_from(&report, "./target");
        let f = findings.iter().find(|f| f.rule.as_str() == "SDA-FUZZ-NO-FEEDBACK").unwrap();
        assert!(f.message.contains("sda-probe"), "it must say how to fix it");
    }

    #[test]
    fn a_campaign_with_feedback_makes_no_such_complaint() {
        let mut report = FuzzReport { runs: 10, ..Default::default() };
        report.coverage.insert(("a.c".into(), 1));
        assert!(report.had_feedback());
        assert!(!report.summary().contains("NO COVERAGE FEEDBACK"));
        assert!(findings_from(&report, "t").is_empty());
    }

    #[test]
    fn crashes_become_certain_findings_with_a_reproducer() {
        let dir = std::env::temp_dir().join("sda-fuzz-crashes");
        let _ = std::fs::remove_dir_all(&dir);
        let config = FuzzConfig { crash_dir: Some(dir.clone()), ..Default::default() };
        let mut report = FuzzReport::default();
        record_crash(
            &mut report,
            Some((
                RuntimeEventKind::MemoryError,
                "index 99 outside length 4".to_string(),
                Some(Location::new("src/a.c", 12, 3)),
            )),
            b"\x00\xffAAAA",
            &config,
        );

        let f = &findings_from(&report, "./target")[0];
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::Certain);
        assert_eq!(f.location.line, 12);
        assert!(f.remediation.as_ref().unwrap().contains("Reproduce with"));
        assert!(report.crashes[0].saved_to.as_ref().unwrap().exists());
        assert!(f.taxonomy.iter().any(|t| t.id == "CWE-787"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corpus_loads_in_a_deterministic_order() {
        let dir = std::env::temp_dir().join("sda-fuzz-corpus");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.bin"), b"second").unwrap();
        std::fs::write(dir.join("a.bin"), b"first").unwrap();

        let seeds = load_corpus(&dir);
        assert_eq!(seeds, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(load_corpus(Path::new("/no/such/dir")).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corpus_selection_prefers_the_least_used_entry() {
        let entry = |uses| Entry { data: vec![0], coverage: BTreeSet::new(), uses };
        let corpus = vec![entry(0), entry(50)];
        let mut rng = Rng::new(9);
        let picks: Vec<usize> = (0..200).map(|_| pick(&corpus, &mut rng)).collect();
        let fresh = picks.iter().filter(|i| **i == 0).count();
        assert!(fresh > 140, "the unused entry should dominate, got {fresh}/200");
    }

    #[test]
    fn corpus_selection_prefers_small_inputs_over_bloated_ones() {
        // A mutation picks a byte position uniformly, so a 400-byte input is a
        // far worse base than an 8-byte one reaching the same code. Without this
        // preference the corpus drifts long and exploration stalls.
        let sized = |len: usize| Entry {
            data: vec![0u8; len],
            coverage: BTreeSet::new(),
            uses: 0,
        };
        let corpus = vec![sized(8), sized(400)];
        let mut rng = Rng::new(4);
        let small = (0..200).filter(|_| pick(&corpus, &mut rng) == 0).count();
        assert!(small > 140, "the compact input should dominate, got {small}/200");
    }

    #[test]
    fn the_dictionary_writes_observed_comparison_values_into_the_input() {
        // The property that makes this fuzzer viable at tens of runs per second:
        // a value the program was seen comparing against gets written into the
        // input, instead of being guessed one byte at a time.
        let mut rng = Rng::new(2);
        let input = vec![0u8; 8];
        let magic = 0x46u64; // 'F'
        let hit = (0..200)
            .map(|_| mutate_with_dictionary(&input, &mut rng, 32, &[magic]))
            .filter(|out| out.contains(&(magic as u8)))
            .count();
        assert!(hit > 20, "the dictionary value should appear often, got {hit}/200");

        // With no dictionary, the same value is essentially never produced.
        let mut rng = Rng::new(2);
        let blind = (0..200)
            .map(|_| mutate_with_dictionary(&input, &mut rng, 32, &[]))
            .filter(|out| out.contains(&(magic as u8)))
            .count();
        assert!(blind < hit / 2, "blind mutation should be far worse: {blind} vs {hit}");
    }

    #[test]
    fn crash_messages_read_as_sentences() {
        let mut report = FuzzReport::default();
        record_crash(
            &mut report,
            Some((RuntimeEventKind::MemoryError, "index 69 outside length 5".into(), None)),
            b"FU\0\0\0",
            &FuzzConfig { crash_dir: None, ..Default::default() },
        );
        let f = &findings_from(&report, "t")[0];
        assert!(f.message.contains("length 5. A 5-byte input"), "got: {}", f.message);
    }

    #[test]
    fn growth_mutations_stay_modest_so_inputs_do_not_bloat() {
        let mut rng = Rng::new(21);
        let mut input = vec![b'A'; 4];
        for _ in 0..400 {
            input = mutate(&input, &mut rng, 256);
        }
        // Unbounded growth is the failure mode; the cap is 256, but a healthy
        // mutator should not sit pinned against it.
        assert!(input.len() <= 256);
    }

    #[test]
    fn a_corpus_larger_than_the_run_budget_does_not_exceed_the_budget() {
        // A target that exits cleanly, so no crash can end the campaign early.
        let program = std::path::Path::new(if cfg!(windows) { "cmd" } else { "true" });
        let args: Vec<String> =
            if cfg!(windows) { vec!["/C".into(), "exit".into(), "0".into()] } else { vec![] };

        let seeds: Vec<Vec<u8>> = (0..10u8).map(|i| vec![b'a' + i]).collect();
        let config = FuzzConfig {
            runs: 3,
            timeout: Duration::from_secs(5),
            max_duration: Duration::from_secs(60),
            ..Default::default()
        };

        let (report, _) = campaign(program, &args, seeds, &config).unwrap();
        assert!(
            report.runs <= config.runs,
            "ten seeds against a budget of three must not run ten: ran {}",
            report.runs
        );
    }
}

