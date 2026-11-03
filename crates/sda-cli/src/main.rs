//! `sda` — the StatodynamicAnalysis command-line interface.

#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use sda_core::{Report, Severity};
use sda_engine::{
    RunSpec, default_registry, discover,
    run::{RunConfig, analyze, gate, triage_order},
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sda",
    version,
    about = "Agentic-first statodynamic analysis for code and embedded AI models",
    long_about = "Statodynamic analysis fuses static evidence (what the source says) with dynamic \
                  evidence (what the built artifact does), and reports what neither established.\n\n\
                  Native Rust engines run by default with no external dependencies. Industry tools \
                  are accepted as opt-in providers via `--with`."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run analysis over a project.
    Scan(ScanArgs),
    /// List, search and audit coding-standard guidelines.
    Rules(RulesArgs),
    /// Query the analysis tool ontology.
    Tools(ToolsArgs),
    /// Inspect the project's build system and compilers.
    Build(BuildArgs),
    /// Scan AI model artifacts and manage probe campaigns.
    Ai(AiArgs),
    /// Produce a deterministic analysis plan.
    Plan(PlanArgs),
    /// Serve the MCP tool surface over stdio, for an AI agent to drive.
    Mcp,
    /// Run one iteration of the autonomous build-diagnose-patch loop.
    Swe(SweArgs),
    /// Generate inputs to drive the target into unexplored code.
    Fuzz(FuzzArgs),
    /// Check that a model's output cannot reach an effector without crossing a
    /// guard, over the architecture declared in `.sda/architecture.toml`.
    Verify(VerifyArgs),
    /// Rank files carrying findings by how often they change.
    Hotspots(HotspotsArgs),
    /// List the files that name the symbols a file defines.
    Impact(ImpactArgs),
}

/// What else is downstream of a file about to change.
///
/// The answer is a **floor**. Reach is found by matching identifier tokens
/// against the external names the subject defines, which finds every caller that
/// spells the name and misses every one that does not: a call through a function
/// pointer, a name the preprocessor assembles, a linker alias, a `dlsym` lookup.
///
/// Each omission removes a file from the answer, and that direction is the
/// dangerous one. Over-reporting costs a reviewer an afternoon; under-reporting
/// tells them a change is contained when it is not.
#[derive(clap::Args)]
struct ImpactArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    /// The file about to change, relative to `path`.
    #[arg(long)]
    file: PathBuf,
}

/// Where to start reading a report too long to read.
///
/// A scan of PX4 produces 78,211 findings. `triage_order` sorts by severity,
/// then confidence, then *path* — so the forty-two thousand `low` ones come out
/// alphabetically, which is no order at all for somebody deciding where to spend
/// an afternoon.
///
/// Churn is the cheapest evidence that helps. Twelve people touching a file
/// forty times this year says nothing about whether its findings are real, and
/// everything about whether anyone is still in a position to act on them.
#[derive(clap::Args)]
struct HotspotsArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    /// How far back to read history, in days.
    #[arg(long, default_value_t = 180)]
    days: u32,
    /// How many files to list.
    #[arg(long, default_value_t = 20)]
    top: usize,
}

#[derive(clap::Args)]
struct VerifyArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    /// A report from a taint provider, as SARIF or an `sda` JSON report.
    ///
    /// Taint refutes and never confirms: a flow from a model to an effector that
    /// crosses no guard fails the proof, while a clean run establishes nothing.
    #[arg(long)]
    taint: Option<PathBuf>,
    /// Verus `--output-json` stdout.
    ///
    /// Pair it with `--proof-log`. The JSON records *that* obligations failed
    /// and never *which*: its per-function `failed_proof_notes` is empty even
    /// for the function that failed, so the counts come from here and the
    /// locations from the diagnostic stream.
    #[arg(long)]
    proofs: Option<PathBuf>,
    /// Verus stderr, where the failing obligations are actually named.
    #[arg(long)]
    proof_log: Option<PathBuf>,
}

#[derive(clap::Args)]
struct FuzzArgs {
    /// The instrumented binary to fuzz.
    artifact: PathBuf,
    /// Project root, for correlating what the campaign reached against static findings.
    #[arg(long, default_value = ".")]
    path: PathBuf,
    /// Seed corpus directory.
    #[arg(long)]
    corpus: Option<PathBuf>,
    /// Where to write reproducing inputs.
    #[arg(long, default_value = ".sda/crashes")]
    crashes: PathBuf,
    #[arg(long, default_value_t = 1000)]
    runs: u64,
    /// PRNG seed. The same seed replays the same campaign.
    #[arg(long, default_value_t = 0x5DA_5EED)]
    seed: u64,
    /// Per-execution timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    /// Overall budget in seconds.
    #[arg(long, default_value_t = 60)]
    budget_secs: u64,
    /// Stop at the first crash instead of continuing to explore.
    #[arg(long)]
    stop_on_crash: bool,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Project root to analyze.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Enable an external provider, repeatable. Use `all` for every installed one.
    /// These run in the project: clippy, miri and verus build a Rust project, which
    /// runs its build scripts and macros, so enable them only for code you trust.
    #[arg(long = "with", value_name = "PROVIDER")]
    with: Vec<String>,
    /// Built artifact to execute, which makes the run statodynamic rather than static-only.
    #[arg(long)]
    artifact: Option<PathBuf>,
    /// Ignore the project's `.sda/` directory: its deviations, scope and
    /// catalogues. Use it to scan code you do not control, whose `.sda/` could
    /// suppress its own findings.
    #[arg(long)]
    ignore_project_config: bool,
    /// Arguments passed to the artifact.
    #[arg(long, num_args = 0.., allow_hyphen_values = true)]
    artifact_args: Vec<String>,
    /// Line execution counts from an external coverage tool: an lcov `.info`
    /// tracefile or a gcov `.gcov` listing. Repeatable. This is what lets an
    /// external dynamic tool refute a finding rather than only confirm one.
    #[arg(long = "coverage", value_name = "FILE")]
    coverage: Vec<PathBuf>,
    /// A `compile_commands.json` describing how the target builds, when it does
    /// not sit anywhere under the project root.
    ///
    /// An out-of-tree build directory is the ordinary way to build, and the only
    /// way to build a checkout you must not write into. Discovery looks in five
    /// fixed places beneath the scan root and finds nothing in that case, so
    /// every type-aware provider reports itself as needing a database that
    /// exists.
    #[arg(long = "compile-commands", value_name = "FILE")]
    compile_commands: Option<PathBuf>,
    /// How long each external tool may run before it is stopped, in seconds.
    ///
    /// A stopped tool is reported as having checked an unknown part of the
    /// target, never as clean. Raise it for a large project: clang-tidy over 184
    /// files of real C++ took about 40 minutes in one invocation.
    #[arg(long = "tool-timeout", value_name = "SECONDS")]
    tool_timeout: Option<u64>,
    /// A probe stream captured from a target this host cannot execute — a UART
    /// log, an RTT capture, a RAM region a debugger read back. Repeatable.
    ///
    /// `--artifact` runs the program here; this is for the case where the
    /// program ran on a board, under an emulator, or on another machine, and all
    /// that came back is what the shim emitted.
    #[arg(long = "observation", value_name = "FILE")]
    observation: Vec<PathBuf>,
    /// Deviation register (TOML). Overrides `.sda/deviations.toml`.
    #[arg(long)]
    deviations: Option<PathBuf>,
    /// Captured probe responses (JSON), enabling behavioural AI analysis.
    #[arg(long)]
    probe_responses: Option<PathBuf>,
    /// Name of the model the probe responses came from.
    #[arg(long)]
    probe_model: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Write the report here instead of to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Gate on this severity: exit 1 if any finding is at or above it, exit 3
    /// if nothing was scanned at all.
    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,
    /// Only show findings at or above this severity.
    #[arg(long, value_enum)]
    min_severity: Option<SeverityArg>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Severity {
        match s {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[derive(clap::Args)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Search guidelines by number, id, or text.
    Find {
        query: String,
        #[arg(long)]
        standard: Option<String>,
    },
    /// Report what a default run actually checks, and what it does not.
    Audit {
        #[arg(long)]
        standard: Option<String>,
    },
    /// Merge an authoritative guideline list over the built-in catalogue.
    Import {
        #[arg(long)]
        standard: String,
        file: PathBuf,
    },
}

#[derive(clap::Args)]
struct ToolsArgs {
    #[command(subcommand)]
    command: ToolsCommand,
}

#[derive(Subcommand)]
enum ToolsCommand {
    /// Search the ontology.
    Search { query: String },
    /// Describe one tool in full.
    Describe { id: String },
    /// Report which external tools are installed.
    Status,
    /// List capabilities nothing available covers.
    Gaps {
        #[arg(long, default_value = "c")]
        language: String,
    },
}

#[derive(clap::Args)]
struct BuildArgs {
    #[command(subcommand)]
    command: BuildCommand,
}

#[derive(Subcommand)]
enum BuildCommand {
    /// Detect build systems and compilers.
    Detect {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Build the project, optionally instrumented.
    Compile {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = ProfileArg::None)]
        profile: ProfileArg,
    },
    /// Produce a compile_commands.json, unblocking type-aware analysis.
    #[command(name = "compile-commands")]
    CompileCommands {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Approximate a database by walking the source tree, for projects whose
        /// build lives inside a vendor IDE file. Include paths and macros will
        /// be guesses.
        #[arg(long)]
        synthesize: bool,
        /// Regenerate even if a database already exists.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    None,
    Static,
    Dynamic,
}

#[derive(clap::Args)]
struct AiArgs {
    #[command(subcommand)]
    command: AiCommand,
}

#[derive(Subcommand)]
enum AiCommand {
    /// Scan model artifacts.
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Print the behavioural probe suite as JSON.
    Probes {
        /// Seed extra probes from trigger candidates, repeatable.
        #[arg(long)]
        trigger: Vec<String>,
    },
    /// Show the NIST AI RMF coverage statement.
    Rmf,
    /// List the LLM vulnerability taxonomy.
    Risks,
}

#[derive(clap::Args)]
struct PlanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    allow_external: bool,
    #[arg(long)]
    artifact: Option<PathBuf>,
}

#[derive(clap::Args)]
struct SweArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, default_value_t = 4)]
    context_lines: u32,
    /// Discard the persisted session and start a fresh attempt.
    #[arg(long)]
    reset: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(args),
        Command::Rules(args) => rules(args),
        Command::Tools(args) => tools(args),
        Command::Build(args) => build(args),
        Command::Ai(args) => ai(args),
        Command::Plan(args) => plan(args),
        Command::Mcp => sda_agent::serve().context("MCP server failed"),
        Command::Swe(args) => swe(args),
        Command::Fuzz(args) => fuzz(args),
        Command::Verify(args) => verify(args),
        Command::Hotspots(args) => hotspots(args),
        Command::Impact(args) => impact(args),
    }
}

/// List the files that name the symbols a file defines.
///
/// The caveat is printed before the list, not after it, and comes from
/// `Impact::floor_caveat` rather than from a string here — so the MCP surface,
/// when it grows this, cannot render the list without it.
fn impact(args: ImpactArgs) -> Result<()> {
    let target = discover::discover(&args.path, &discover::DiscoveryOptions::default());
    let subject = args.path.join(&args.file);
    if !subject.exists() {
        bail!("`{}` does not exist under `{}`", args.file.display(), args.path.display());
    }

    let files: Vec<PathBuf> =
        target.files_in(&[sda_core::Language::C]).iter().map(|f| f.path.clone()).collect();

    let root = target.root.clone();
    let relative = move |p: &std::path::Path| {
        p.strip_prefix(&root).unwrap_or(p).to_string_lossy().replace('\\', "/")
    };
    let found = sda_engine::impact::of_file(&subject, &files, &relative);

    println!("Files that name the symbols defined by {}\n", args.file.display());

    // This command searches out-of-scope files **on purpose**, and the opposite
    // choice from the one `hotspots` needed.
    //
    // A ranking of where to look first must not rank files the project excluded
    // from analysis. A blast radius must not hide them: a vendored directory
    // that calls into this file is exactly the caller somebody needs to know
    // about before changing it, and omitting it would push the floor *below*
    // the truth, which is the one direction this answer must never move. The
    // two commands read the same declaration and are right to disagree about
    // it — so the disagreement is stated rather than left for a reader to
    // discover from a name they did not expect to see.
    let project = sda_rules::ProjectConfig::discover(&args.path);
    if project.scope.is_some() {
        println!(
            "  This project declares an analysis scope, and this search ignored it. A caller \
             in an excluded directory still reaches this code, and leaving it out would make \
             the floor below lower than the truth. Names below may sit in files `sda scan` \
             will not report on\n"
        );
    }

    // Before the floor, because a floor is a caveat about a list and this is a
    // caveat about whether a list was ever built.
    if let Some(n) = found.nothing_searched_notice() {
        println!("  {}\n", n.reason);
    }
    println!("  {}\n", found.floor_caveat().reason);
    if let Some(n) = found.unreadable_notice() {
        println!("  {}\n", n.reason);
    }

    if found.symbols.is_empty() {
        println!(
            "  This file defines no external symbols, so nothing can reach it by name. That \
             is not the same as nothing depending on it"
        );
        return Ok(());
    }

    println!("  defines: {}\n", found.symbols.join(", "));

    if found.referenced_by.is_empty() {
        if found.nothing_searched_notice().is_none() {
            println!("  No other file names any of them.");
        }
        return Ok(());
    }

    let width = found.referenced_by.keys().map(String::len).max().unwrap_or(0);
    for (file, symbols) in &found.referenced_by {
        println!("  {file:<width$}  {}", symbols.join(", "));
    }
    Ok(())
}

/// Rank the files carrying findings by how often they change.
///
/// Two orderings exist here and only one of them is a measurement. The findings
/// are measured; the ranking is an *offer* about where to look first. The output
/// says which is which, because a list printed by a tool acquires authority it
/// has not earned, and this one is arithmetic over a team's habits.
fn hotspots(args: HotspotsArgs) -> Result<()> {
    let mut project = sda_rules::ProjectConfig::discover(&args.path);
    let mut target = discover::discover(&args.path, &discover::DiscoveryOptions::default());

    // The declared scope applies here too, and did not.
    //
    // `sda scan` removes out-of-scope files before any provider is built, so a
    // file under a `[[excluded]]` rule is never analyzed. This command ran its
    // own discovery and skipped that step, so it analyzed them anyway — and
    // then ranked them. Measured on a project excluding `legacy/`: the scan
    // reported four findings, all in `src/`, and `sda hotspots` on the same
    // tree reported twelve and put `legacy/old.c` **first**, because it had the
    // most of them.
    //
    // That is not a missing caveat. It is a ranking whose top row is a file the
    // project formally declared out of scope, with a recorded reason and a
    // named approver, presented under a heading offering the files worth
    // looking at first. A scope rule that holds in one view and not the next is
    // worse than none, because the second view is the one that looks actionable.
    let scope_notices = match (&project.scope, project.root()) {
        (Some(scope), Some(anchor)) => discover::apply_scope(&mut target, scope, anchor),
        _ => Vec::new(),
    };

    // And the deviation register, which this had no more idea about than it had
    // about scope. `RunConfig::default()` carries no deviations, so nothing in
    // this run was ever marked suppressed and every deviated finding was
    // counted as live. Same file, same argument: the project's declared
    // position has to reach the ranking, or the ranking overrules it.
    let mut config = RunConfig::default().with_notices(scope_notices);
    if let Some(register) = project.deviations.take() {
        config = config.with_deviations(register);
    }

    let registry = sda_engine::registry_for_project(&project);
    let report = sda_engine::run::analyze(&registry, &target, &config);

    // A finding suppressed by an approved deviation does not rank.
    //
    // `report.findings` keeps suppressed findings in the list, marked, because a
    // compliance record has to show what was deviated rather than hide it. This
    // counted them. Measured on a project with two files of four findings each,
    // one file's four covered by deviations with a rationale and an approver:
    // the ranking showed **8** against **4** and put the deviated file first.
    // Counted honestly they tie.
    //
    // Same shape as the scope defect this command had: a formal, recorded
    // decision honoured by the scan and overridden by the ranking. Here it is
    // worse in one way — a deviation is a claim that a finding is *accepted*,
    // and ranking on it sends somebody to look first at the code most recently
    // agreed to be fine.
    let mut per_file: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut suppressed = 0usize;
    for f in &report.findings {
        if f.is_suppressed() {
            suppressed += 1;
            continue;
        }
        *per_file.entry(f.location.file.to_string_lossy().replace('\\', "/")).or_default() += 1;
    }

    let history = sda_engine::history::read(&args.path, args.days);

    println!("Findings by file, and how often each file changed\n");

    // Before the history caveat: the engine's own reason there is nothing to
    // rank, which this surface computed and then threw away.
    //
    // `analyze` attaches `sda.discovery` when no enabled provider reads anything
    // that was found — a mistyped path, a build directory, a tree of languages
    // this does not handle — and `sda scan` prints it under NOT CHECKED. Here
    // the report was built, the notice was attached to it, and only
    // `report.findings` was ever read. So `sda hotspots ./srcc` printed a
    // heading, a remark about git, and an empty table: every line true, and
    // together they say *nothing notable here* about a scan that read nothing at
    // all. An empty ranking is the most reassuring shape an empty result can
    // take, which is why this one goes above the table and above the history
    // caveat — that caveat is about the *order* of the rows, and this is about
    // whether any row could have existed.
    // `sda.scope` joins it: both are about which files could have appeared in
    // the table at all, which is what a ranking most needs stated. The nine
    // `ext.*` notices are about providers rather than files and belong in the
    // scan report, where the whole list is.
    for e in report
        .exclusions
        .iter()
        .filter(|e| matches!(e.provider.as_str(), "sda.discovery" | "sda.scope"))
    {
        println!("  {}\n", e.reason);
    }

    // Not counted is not the same as not there: a deviation dropped silently
    // would make this table disagree with the scan's summary and give a reader
    // no way to find out why.
    if suppressed > 0 {
        println!(
            "  {suppressed} finding(s) are suppressed by approved deviations and are not \
             counted or ranked below. They remain in `sda scan`, which is the compliance \
             record; this is a list of where to look, and an accepted finding is not that\n"
        );
    }

    // The history notice goes first, not last.
    //
    // NOT CHECKED is last in a scan report because a reader must not stop before
    // it. Here the caveat *governs the table underneath it*: a ranking built
    // without history is alphabetical wearing a rank's clothing, and saying so
    // afterwards would be saying it to somebody who has already read the list.
    if let Some(notice) = history.notice() {
        println!("  {}\n", notice.reason);
    }

    // `0` is a claim; `—` is not.
    //
    // When the history was read, a file absent from it genuinely had no commits
    // in the window and `0` is a measurement. When the history could not be read
    // at all, the same `0` asserts a settled file on the strength of a query
    // that never ran — the sentence `vcs::detect` refuses about `dirty: false`.
    // A reader who skips the caveat above still must not be told a number that
    // nobody counted.
    let known = matches!(history, sda_engine::history::History::Read { .. });

    let mut rows: Vec<(usize, u32, u32, &str, &str)> = per_file
        .iter()
        .map(|(path, findings)| {
            let h = history.get(path);
            (
                *findings,
                h.map(|h| h.commits).unwrap_or(0),
                h.map(|h| h.authors).unwrap_or(0),
                h.map(|h| h.last_change.as_str()).unwrap_or("—"),
                path.as_str(),
            )
        })
        .collect();

    // Findings times commits, which is the whole of the arithmetic and is stated
    // rather than tuned. A file with many findings that nobody touches ranks
    // below one with fewer that everybody does, and a reader who disagrees with
    // that trade can sort the two columns themselves.
    rows.sort_by_key(|(findings, commits, authors, _, path)| {
        (std::cmp::Reverse(*findings * (*commits as usize).max(1)), std::cmp::Reverse(*commits), std::cmp::Reverse(*authors), path.to_string())
    });

    println!("  {:>8}  {:>7}  {:>7}  {:>10}  file", "findings", "commits", "authors", "last");
    for (findings, commits, authors, last, path) in rows.iter().take(args.top) {
        // `known` is about the history; `knows` is about this file. A tracked
        // file with no commits in the window is a measured zero. One git has
        // never seen is not — printing `0` there says a file is settled on the
        // strength of a question nobody asked, in the same column that already
        // prints `—` for its unknown date.
        let counted = known && history.knows(path);
        let commits = if counted { commits.to_string() } else { "—".to_string() };
        let authors = if counted { authors.to_string() } else { "—".to_string() };
        println!("  {findings:>8}  {commits:>7}  {authors:>7}  {last:>10}  {path}");
    }

    if rows.len() > args.top {
        println!("\n  … and {} more file(s) with findings, not shown", rows.len() - args.top);
    }

    println!(
        "\nThe findings are measured. The order is not: it is findings x commits, offered as \
         somewhere to start. Churn is not a defect and no file here is worse than another for \
         having been edited."
    );
    Ok(())
}

/// Prove interposition over the declared architecture.
///
/// Prints, in this order: what configuration applied, what could not be turned
/// into a system, the proof result, and `NOT CHECKED`. The last section is last
/// because it is the one a reader must not stop before, and it is not
/// suppressible here any more than it is in `scan`.
fn verify(args: VerifyArgs) -> Result<()> {
    let project = sda_rules::ProjectConfig::discover(&args.path);
    println!("{}", project.summary());
    for p in &project.problems {
        println!("  {p}");
    }

    let Some(decl) = &project.architecture else {
        // A project with no declaration has not failed a check; it has not made a
        // claim, and saying so is the honest report. It has not passed one either,
        // so this exits as `scan --fail-on` does when nothing was read: a green
        // step here would be a proof nobody ran.
        println!(
            "\nNo `.sda/architecture.toml` found, so interposition was not checked. This is not \
             a clean result: nothing was claimed and nothing was proved. Declare the components \
             and the dataflow between them to make the claim checkable."
        );
        std::process::exit(3);
    };

    let system = sda_engine::from_declaration(decl);
    for p in &system.problems {
        println!("  {p}");
    }

    let taint = match &args.taint {
        Some(path) => load_taint(path)?,
        None => Vec::new(),
    };
    if args.taint.is_some() {
        let with_flow = taint
            .iter()
            .filter(|f| {
                f.evidence.iter().any(|e| {
                    matches!(e, sda_core::Evidence::Trace { frames } if frames.len() >= 2)
                })
            })
            .count();
        // Both numbers, always. Refutation needs the path, and a report whose
        // findings carry only endpoints cannot contradict anything — so a run
        // that printed the total alone would let an inert instrument read as a
        // check that passed.
        println!(
            "  {} taint finding(s) loaded, {with_flow} carrying a dataflow trace",
            taint.len()
        );
    }

    let result = sda_engine::interposition::verify(&system.map, &system.flow, &taint);
    println!("\n{}", sda_engine::interposition::summarize(&result));

    let mut not_checked = result.not_checked.clone();
    let mut ledger = result.merge_into(Default::default());
    let mut proofs_failed = 0usize;

    if let Some(path) = &args.proofs {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let diagnostics = match &args.proof_log {
            Some(p) => std::fs::read_to_string(p)
                .with_context(|| format!("reading {}", p.display()))?,
            None => String::new(),
        };
        let run = sda_adapters::parse_verus(&json, &diagnostics).map_err(anyhow::Error::msg)?;
        println!(
            "\nProver: verus {} — {} obligation(s) verified, {} failed, {} located.",
            run.version,
            run.verified,
            run.errors,
            run.failures.len()
        );
        for f in &run.failures {
            let where_ = f
                .location
                .as_ref()
                .map(|l| l.display())
                .unwrap_or_else(|| "<unlocated>".to_string());
            println!("  {where_}: {}", f.statement);
        }
        // The standalone `verus` binary exits 0 on a failed proof, so if that is
        // how the report was produced, nothing upstream of here will have
        // noticed. `cargo verus verify` exits 101, so it depends on how the
        // prover was driven — which is exactly why this says so rather than
        // assuming the reader knows which they used.
        if run.errors > 0 {
            println!(
                "  Note: the standalone `verus` binary exits 0 whether or not its proofs hold \
                 (`cargo verus verify` exits 101). If this report came from the former, a CI gate \
                 on its exit code would have passed it."
            );
        }
        for p in &run.problems {
            not_checked.push(format!("sda.prover: {p}"));
        }
        if args.proof_log.is_none() && run.errors > 0 {
            not_checked.push(
                "sda.prover: --proofs was given without --proof-log, and the JSON names no \
                 failing function. The failures above are counted and cannot be located"
                    .to_string(),
            );
        }
        proofs_failed = run.errors;
        ledger.obligations.extend(run.obligations());
    }

    let adjudication = sda_engine::adjudicate(&[], &ledger, &system.map);
    not_checked.extend(adjudication.not_checked);
    if !not_checked.is_empty() {
        println!("\nNOT CHECKED — do not read a clean result as coverage of these:");
        for line in &not_checked {
            println!("  {line}");
        }
    }

    // A refuted interposition proof or a failed obligation is a failed safety
    // case, not a warning. The prover's own exit code says nothing, so this one
    // has to.
    if (!result.obligations.is_empty() && !result.is_interposed()) || proofs_failed > 0 {
        std::process::exit(1);
    }

    // A declaration with nothing to prove is the same answer as no declaration.
    if ledger.obligations.is_empty() {
        std::process::exit(3);
    }
    Ok(())
}

/// Read taint findings from an `sda` JSON report or a SARIF log.
fn load_taint(path: &std::path::Path) -> Result<Vec<sda_core::Finding>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading taint report {}", path.display()))?;
    if let Ok(report) = serde_json::from_str::<sda_core::Report>(&text) {
        return Ok(report.findings);
    }
    sda_adapters::parse_sarif(&text, "ext.taint")
        .map_err(|e| anyhow::anyhow!(e))
        .with_context(|| format!("{} is neither an sda report nor SARIF", path.display()))
}

fn fuzz(args: FuzzArgs) -> Result<()> {
    if !args.artifact.exists() {
        bail!("artifact `{}` does not exist; build it first", args.artifact.display());
    }

    let seeds = args
        .corpus
        .as_ref()
        .map(|d| sda_engine::fuzz::load_corpus(d))
        .unwrap_or_default();

    let config = sda_engine::FuzzConfig {
        runs: args.runs,
        seed: args.seed,
        timeout: std::time::Duration::from_millis(args.timeout_ms),
        max_duration: std::time::Duration::from_secs(args.budget_secs),
        crash_dir: Some(args.crashes.clone()),
        max_input: 4096,
        stop_on_crash: args.stop_on_crash,
    };

    eprintln!(
        "fuzzing {} with {} seed input(s), seed {:#x}...",
        args.artifact.display(),
        seeds.len(),
        args.seed
    );
    let (report, observation) =
        sda_engine::fuzz_campaign(&args.artifact, &[], seeds, &config)?;
    println!("{}", report.summary());

    let artifact = args.artifact.to_string_lossy().to_string();
    let mut crashes = sda_engine::fuzz::findings_from(&report, &artifact);
    // A crash location comes out of sanitizer text, which states a position and
    // no extent; the project root is known here, so the token can be bracketed
    // from source the same way a static finding's is.
    sda_engine::dynamic::span_against_source(&mut crashes, &args.path);
    for f in crashes {
        println!("\n{}: {} ({})", f.location.display(), f.rule, f.severity.as_str());
        println!("  {}", f.message);
        if let Some(r) = &f.remediation {
            println!("  {r}");
        }
    }

    // The payoff: everything the campaign reached is now evidence the
    // correlation engine can use, so static findings on those lines stop being
    // "unreached" and become confirmed or refuted.
    let mut target = discover::discover(&args.path, &discover::DiscoveryOptions::default());
    // Scope applies to the correlation for the same reason it applies to the
    // scan: a confirmed or refuted verdict about a file `sda scan` refuses to
    // report on is a finding with nowhere to go.
    let mut project = sda_rules::ProjectConfig::discover(&args.path);
    let scope_notices = match (&project.scope, project.root()) {
        (Some(scope), Some(anchor)) => discover::apply_scope(&mut target, scope, anchor),
        _ => Vec::new(),
    };
    // The deviation register too. Without it nothing is marked suppressed, and
    // `correlate`'s refusal to re-raise a settled finding never fires -- so the
    // verdict table below re-raised exactly what the process had accepted.
    let mut config = RunConfig::default().with_observation(observation).with_notices(scope_notices);
    if let Some(register) = project.deviations.take() {
        config = config.with_deviations(register);
    }
    let correlated = analyze(&default_registry(), &target, &config);

    println!("\nAfter correlating what the campaign reached:");
    // The correlation is over the *source tree*, which is a different argument
    // from the artifact that was fuzzed and can be wrong on its own. A campaign
    // that ran against a real binary while `--path` pointed at nothing prints a
    // verdict table with no rows, directly under a heading promising one.
    for e in correlated
        .exclusions
        .iter()
        .filter(|e| matches!(e.provider.as_str(), "sda.discovery" | "sda.scope"))
    {
        println!("  {}", e.reason);
    }
    for (verdict, n) in &correlated.summary.by_verdict {
        println!("  {verdict}: {n}");
    }
    if report.crashes.is_empty() {
        println!(
            "\nNo crashes. That is not a proof of safety — it means this campaign, with this \
             corpus and this budget, did not reach one."
        );
    }
    Ok(())
}

// --- scan ------------------------------------------------------------------

fn scan(args: ScanArgs) -> Result<()> {
    let mut target = discover::discover(&args.path, &discover::DiscoveryOptions::default());
    // `--artifact` used to feed only the native dynamic engine, so
    // `Target::artifact` — documented as "required by dynamic providers" — was
    // `None` for every provider on every run. An external dynamic adapter could
    // not see the binary the user had just named on the command line.
    target.artifact = args.artifact.clone();
    // Overrides discovery rather than supplementing it: the user naming a file
    // is a stronger statement than a filename matching in a directory, and
    // silently preferring the found one would be the harder failure to see.
    if let Some(db) = &args.compile_commands {
        if !db.exists() {
            bail!(
                "`{}` does not exist; generate one with `sda build compile-commands`, or with \
                 `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`",
                db.display()
            );
        }
        if let Some(found) = &target.compile_commands
            && found != db
        {
            eprintln!(
                "note: using {} rather than the {} discovery found",
                db.display(),
                found.display()
            );
        }
        target.compile_commands = Some(db.clone());
    }
    eprintln!("{}", discover::inventory(&target));

    // Project configuration is discovered before the registry is built: the
    // analyzers need the project's catalogues, not the built-in ones, or a
    // licensed guideline list sits unread and every citation stays unconfirmed.
    // A scanned tree's `.sda/` is its own say about itself: a deviation in it
    // suppresses a finding on an approver's name nobody checked. Code you do not
    // control is scanned without it.
    let mut project = if args.ignore_project_config {
        sda_rules::ProjectConfig::default()
    } else {
        sda_rules::ProjectConfig::discover(&args.path)
    };
    let _ = project.catalogs(); // records what was imported, for the summary
    if args.ignore_project_config {
        eprintln!("--ignore-project-config: using built-in catalogues, no deviations and no scope");
    } else {
        eprintln!("{}", project.summary());
    }
    for problem in &project.problems {
        eprintln!("warning: {problem}");
    }

    // Scope is applied to the file list before any provider is built, so an
    // out-of-scope file is never analyzed rather than analyzed and then
    // filtered. `scope_notices` must reach the report — see `apply_scope`.
    // Anchored at the directory the declaration governs, not at `args.path`:
    // `.sda/` is discovered upward, so scanning a subdirectory would otherwise
    // compare project-relative rules against subdirectory-relative paths.
    let scope_notices = match (&project.scope, project.root()) {
        (Some(scope), Some(anchor)) => {
            let notices = discover::apply_scope(&mut target, scope, anchor);
            if !notices.is_empty() {
                eprintln!("{}", discover::inventory(&target));
            }
            notices
        }
        _ => Vec::new(),
    };

    let mut registry = sda_engine::registry_for_project(&project);
    registry.register(std::sync::Arc::new(sda_ai::ModelScanner::new()));

    // Register the probe runner only when there is a model to probe. Its
    // "behaviour was not tested" notice is important on a project that ships a
    // model and pure noise on one that does not — and a notice that appears
    // everywhere is one people learn to skip past.
    if target.languages().contains(&sda_core::Language::ModelArtifact) {
        let mut probe = sda_ai::ProbeRunner::new();
        if let Some(p) = &args.probe_responses {
            probe = probe.with_responses(p);
        }
        if let Some(m) = &args.probe_model {
            probe = probe.with_model(m.clone());
        }
        registry.register(std::sync::Arc::new(probe));
    }

    let mut config = RunConfig::default().with_notices(scope_notices);

    // Configuration the project asked for and did not get belongs in the
    // report, for the same reason `scope_notices` does: a `warning:` on stderr
    // is not part of the artifact. `sda scan --format json > report.json`
    // keeps `exclusions` and throws stderr away, so a rejected architecture
    // component used to vanish between the terminal and the file — leaving a
    // saved interposition result computed over a graph smaller than the
    // declaration describes, with nothing in the report to say so.
    //
    // Only `unapplied`, not every problem: an accepted declaration's advisory
    // warnings are already re-derived downstream by the layer they affect, and
    // saying it twice in different words teaches people to skim this section.
    for problem in &project.unapplied {
        config.notices.push(sda_core::Exclusion {
            provider: "sda.config".into(),
            reason: problem.clone(),
        });
    }

    // A compilation database is checked for *coverage*, not merely for
    // existence.
    //
    // `--compile-commands` used to verify only that the file was there. A
    // database naming files this machine does not have — built in a container,
    // on another checkout path, or under WSL, where every entry reads
    // `/mnt/c/...` while the analyzer sees `C:/...` — was accepted in silence,
    // and the run then looked exactly like one with no database at all, except
    // that the operator believed type-aware analysis was now possible. An
    // inability to check, presented as a check.
    if let Some(db_path) = target.compile_commands.clone() {
        let reason = match sda_build::supplied_coverage(&db_path, &target.root) {
            Err(e) => Some(format!("`{}` could not be read: {e}", db_path.display())),
            Ok(c) => {
                eprintln!(
                    "compile_commands: {} entr(ies) covering {} of {} C/C++ source file(s)",
                    c.entries, c.covered, c.sources
                );
                c.shortfall(&db_path)
            }
        };
        if let Some(reason) = reason {
            config.notices.push(sda_core::Exclusion {
                provider: "sda.compile-commands".into(),
                reason,
            });
        }
    }
    if let Some(register) = project.deviations.take() {
        config = config.with_deviations(register);
    }
    // The interposition proof and the neurosymbolic adjudication run in a plain
    // scan, not only in `sda verify`. `verify` remains the place to drive them
    // with a taint report and a prover log; without those, a scan still has the
    // declaration and its own findings, which is enough to refute.
    if let Some(decl) = project.architecture.take() {
        config = config.with_architecture(decl);
    }

    // `--with ext.cppcheck=/opt/cppcheck-2.13/bin/cppcheck` points at a
    // specific binary; a bare id uses whatever is on PATH.
    let mut paths = std::collections::BTreeMap::new();
    let mut ids = Vec::new();
    for spec in &args.with {
        match spec.split_once('=') {
            Some((id, path)) => {
                paths.insert(id.to_string(), path.to_string());
                ids.push(id.to_string());
            }
            None => ids.push(spec.clone()),
        }
    }

    // Registered unconditionally, and enabled only on request. Registering used
    // to be conditional on `--with`, which made the *NOT CHECKED* section
    // shorter on a default run than on one that asked for a tool: a plain
    // `sda scan` named none of the external providers it had not run, while a
    // scan with `--with ext.miri` listed all eight of the others. That is
    // exactly inverted — the run that enables nothing is the run whose reader
    // most needs telling. Found on a 2,270-file scan of PX4-Autopilot, whose
    // report carried one exclusion.
    //
    // It costs nothing: `Registry::select` applies the selection policy before
    // it asks a provider whether it is available, so a registered-but-disabled
    // adapter is excluded by policy and never spawns its probe process.
    sda_adapters::register_configured(
        &mut registry,
        &paths,
        args.tool_timeout.map(std::time::Duration::from_secs),
    );
    if ids.iter().any(|w| w == "all") {
        config = config.with_external();
    } else {
        for id in ids {
            config.selection = config.selection.enable(id);
        }
    }

    if let Some(path) = &args.deviations {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let register = sda_rules::DeviationRegister::parse(&text)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        for r in register.rejected() {
            eprintln!("warning: deviation for `{}` rejected: {}", r.rule, r.reason);
        }
        config = config.with_deviations(register);
    }

    if let Some(artifact) = &args.artifact {
        if !artifact.exists() {
            bail!("artifact `{}` does not exist; build it first", artifact.display());
        }
        let mut spec = RunSpec::new(artifact).id("cli-run-0");
        spec.args = args.artifact_args.clone();
        eprintln!("executing {} for runtime evidence...", artifact.display());
        let engine = sda_engine::DynamicEngine::new(vec![spec]);
        match engine.observe() {
            Ok(obs) => config = config.with_observation(obs),
            // An artifact that will not launch used to abort the whole run, so a
            // scan that had already completed its static analysis — and any
            // external adapter that would have run next — produced *nothing*.
            // Found by handing `--artifact` a Linux binary on Windows: the
            // engine said "%1 is not a valid Win32 application" and threw away
            // every finding in the report.
            //
            // The inverse of this codebase's rule is still the rule: an
            // inability to check must not be presented as a clean check, and it
            // must not destroy the checks that did succeed either. So the run
            // continues static-only and says so where a clean result cannot hide
            // it — the *NOT CHECKED* section, plus a warning on stderr, because
            // the user asked for a statodynamic run and did not get one.
            Err(e) => {
                eprintln!(
                    "warning: {} could not be executed ({e}); continuing static-only",
                    artifact.display()
                );
                config.notices.push(sda_core::Exclusion {
                    provider: "sda.dynamic".into(),
                    reason: format!(
                        "the artifact `{}` could not be executed ({e}), so the native dynamic \
                         engine produced no observation and nothing it would have witnessed was \
                         checked — `--artifact` was given but no instrumented run happened. An \
                         external dynamic adapter, if one was enabled, ran independently of this",
                        artifact.display()
                    ),
                });
            }
        }
    }

    load_coverage(&args.coverage, &mut config);
    load_observations(&args.observation, &mut config);

    let report = analyze(&registry, &target, &config);
    let rendered = match args.format {
        Format::Json => report.to_json_pretty()?,
        Format::Sarif => sda_core::sarif::to_sarif_string(&report)?,
        Format::Text => render_text(&report, args.min_severity.map(Into::into)),
    };

    match &args.output {
        Some(p) => {
            std::fs::write(p, &rendered).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("report written to {}", p.display());
        }
        None => println!("{rendered}"),
    }

    if let Some(threshold) = args.fail_on {
        let (outcome, why) = gate(&report, threshold.into());
        eprintln!("gate: {why}");
        // Three exit codes, because a pipeline can only act on what it is told.
        // `1` means this code has findings; `3` means the scan never happened,
        // which needs fixing in the pipeline rather than in the code. Folding
        // the second into `0` gave a mistyped path a green build. `2` is left
        // alone: the argument parser already exits with it.
        match outcome {
            sda_engine::run::Gate::Pass => {}
            sda_engine::run::Gate::Fail => std::process::exit(1),
            sda_engine::run::Gate::NotChecked => std::process::exit(3),
        }
    }
    Ok(())
}

/// Fold external coverage reports into the run's observation.
///
/// This is the seam that lets an external dynamic tool do more than confirm.
/// Valgrind reports defects and counts no lines, so with only its evidence
/// `correlate` receives `None` and neither `Refuted` nor `Unreached` is
/// available at all. A coverage report supplies the counts, and the other three
/// verdicts light up for every external dynamic tool at once.
///
/// A file that will not parse does not abort the run, for the reason
/// `--artifact` does not: the user asked for something and did not get it, which
/// must be said out loud where a clean result cannot hide it, but it is not a
/// reason to discard the analysis that did succeed.
fn load_coverage(paths: &[PathBuf], config: &mut RunConfig) {
    // Collected, then said once. gcov writes one `.gcov` per translation unit,
    // so pointing `--coverage` at a build directory is the ordinary case: a real
    // 105-file project produced 59 of them, and 59 near-identical paragraphs went
    // into *NOT CHECKED*, burying the two entries that mattered. See
    // `provenance_of_many`.
    let mut loaded: Vec<(String, sda_engine::ExternalCoverage)> = Vec::new();
    let mut unreadable: Vec<(String, String)> = Vec::new();
    for path in expand_coverage_paths(paths) {
        match sda_engine::coverage::load(&path) {
            Ok(c) => {
                eprintln!(
                    "coverage: {} line(s) from {} ({})",
                    c.lines_measured,
                    path.display(),
                    c.format.as_str()
                );
                // `merge` sums counts, which is what repeating `--coverage` for
                // several runs of the same program should mean.
                let observation = c.observation.clone();
                match &mut config.observation {
                    Some(obs) => obs.merge(observation),
                    None => config.observation = Some(observation),
                }
                loaded.push((path.display().to_string(), c));
            }
            Err(e) => {
                eprintln!("warning: {} could not be read as coverage ({e})", path.display());
                unreadable.push((path.display().to_string(), e.to_string()));
            }
        }
    }

    // The same reasoning as the 59 paragraphs above, for the reports that failed.
    const NAME_EACH_UP_TO: usize = 3;
    if unreadable.len() <= NAME_EACH_UP_TO {
        for (path, e) in &unreadable {
            config.notices.push(sda_core::Exclusion {
                provider: "sda.coverage".into(),
                reason: format!(
                    "`{path}` was given as a coverage report and could not be read ({e}), so its \
                     execution counts are missing from this run. Any finding it would have \
                     refuted or shown unreached is reported without that evidence"
                ),
            });
        }
    } else if let Some((first, e)) = unreadable.first() {
        config.notices.push(sda_core::Exclusion {
            provider: "sda.coverage".into(),
            reason: format!(
                "{} coverage report(s) could not be read, the first of them `{first}` ({e}), so \
                 their execution counts are missing from this run. Any finding they would have \
                 refuted or shown unreached is reported without that evidence",
                unreadable.len()
            ),
        });
    }

    if let Some(reason) = sda_engine::ExternalCoverage::provenance_of_many(&loaded) {
        config.notices.push(sda_core::Exclusion { provider: "sda.coverage".into(), reason });
    }
}

/// Fold probe streams captured off-host into the run's observation.
///
/// This is the ingestion path for a target the host cannot execute. The shim
/// (`shim/sda_probe.h`) emits the same JSON-lines records whether its sink is
/// `stdio` on a workstation or a UART on a Cortex-M part, so a capture taken
/// from a board, an emulator or another machine is the same evidence a local run
/// produces — and reaches the same correlation engine.
///
/// Two things it refuses to do, and both matter more here than for `--coverage`.
///
/// **An empty capture is not an empty run.** `parse_probe_stream` skips a line
/// it cannot read, because the last line of a live stream is routinely
/// half-flushed. A file is not like that: a UART log with framing noise, a board
/// that reset before the sink was routed, or simply the wrong file all parse to
/// an observation with no coverage at all — which is the *claim* that execution
/// was measured and nothing ran, and that is what makes `Refuted` and
/// `Unreached` available. Believing it would manufacture refutations out of a
/// truncated log. So a capture with no records supplies no observation, and says
/// so where a clean result cannot hide it.
///
/// **Where it ran is part of the evidence.** A local `--artifact` run is
/// witnessed by this process; a capture is witnessed by whoever took it. The
/// notice names the file and what was in it, because "the program was executed"
/// and "someone says the program was executed" are different claims and the
/// report should not blur them.
fn load_observations(paths: &[PathBuf], config: &mut RunConfig) {
    for (i, path) in paths.iter().enumerate() {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("warning: {} could not be read ({e})", path.display());
                config.notices.push(sda_core::Exclusion {
                    provider: "sda.observation".into(),
                    reason: format!(
                        "`{}` was given as a captured probe stream and could not be read ({e}), \
                         so nothing it witnessed reached this run",
                        path.display()
                    ),
                });
                continue;
            }
        };

        let run_id = format!("capture-{i}");
        let (obs, summary) = sda_engine::parse_probe_capture(&text, &run_id);

        if summary.records == 0 {
            eprintln!(
                "warning: {} holds no probe records ({} unreadable line(s)); ignoring it",
                path.display(),
                summary.unreadable
            );
            config.notices.push(sda_core::Exclusion {
                provider: "sda.observation".into(),
                reason: format!(
                    "`{}` was given as a captured probe stream and contained no probe records \
                     ({} unreadable line(s)), so it supplied no execution evidence and was not \
                     used. It is not being read as a run in which nothing executed — that is a \
                     different claim, and this file does not support it",
                    path.display(),
                    summary.unreadable
                ),
            });
            continue;
        }

        let files: std::collections::BTreeSet<&str> =
            obs.coverage.keys().map(|(f, _)| f.as_str()).collect();
        eprintln!(
            "observation: {} record(s) from {} — {} line(s) across {} file(s), {} event(s)",
            summary.records,
            path.display(),
            obs.coverage.len(),
            files.len(),
            obs.events.len()
        );
        config.notices.push(sda_core::Exclusion {
            provider: "sda.observation".into(),
            reason: format!(
                "execution evidence for this run came from `{}`, a probe stream captured off-host \
                 rather than a program this scan executed: {} record(s), {} line(s) across {} \
                 file(s), {} runtime event(s){}. Correlation treats it as a measured run, so it \
                 is only as good as the capture",
                path.display(),
                summary.records,
                obs.coverage.len(),
                files.len(),
                obs.events.len(),
                match summary.unreadable {
                    0 => String::new(),
                    n => format!(", and {n} line(s) that were not probe records"),
                }
            ),
        });

        match &mut config.observation {
            Some(existing) => existing.merge(obs),
            None => config.observation = Some(obs),
        }
    }
}

/// Accept a directory wherever a coverage file is accepted.
///
/// `gcov` emits one `.gcov` per translation unit, so pointing at a build
/// directory is the normal case rather than a convenience, and PowerShell does
/// not glob arguments the way a POSIX shell does.
fn expand_coverage_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if !p.is_dir() {
            out.push(p.clone());
            continue;
        }
        let Ok(entries) = std::fs::read_dir(p) else {
            out.push(p.clone()); // let `load` report the i/o error against the path
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|f| {
                matches!(
                    f.extension().and_then(|e| e.to_str()),
                    Some("gcov") | Some("info")
                )
            })
            .collect();
        found.sort();
        if found.is_empty() {
            // Not silently nothing: a directory with no reports is a mistake
            // worth a message, and `load` produces one naming the path.
            out.push(p.clone());
        } else {
            out.extend(found);
        }
    }
    out
}

fn render_text(report: &Report, min: Option<Severity>) -> String {
    let mut s = String::new();
    s.push_str(&format!("StatodynamicAnalysis report for {}\n", report.target));
    s.push_str(&format!("generated {}\n", report.generated_at));
    // Directly under the timestamp, because "when" and "of what" are the same
    // question. A dirty tree says so here as well as in the machine-readable
    // half: SARIF has no field for it, and a reader of either must not take the
    // revision for the thing that was scanned.
    if let Some(v) = &report.vcs {
        s.push_str(&format!("source {}\n", v.summary()));
    }
    s.push('\n');

    let ordered = triage_order(report);
    let shown: Vec<_> = ordered
        .iter()
        .filter(|f| min.map(|m| f.severity >= m).unwrap_or(true))
        .collect();

    if shown.is_empty() {
        s.push_str("No findings at the requested severity.\n\n");
    }

    // The list is capped, and the cap has to be visible.
    //
    // It printed the first five hundred and stopped. Measured on a 200-file
    // project: 800 findings, 500 lines, and nothing anywhere saying the other
    // 300 existed. The `Summary` block below gives the totals, so a reader who
    // compares two numbers could work it out — but a reader who scrolls to the
    // end of a list and finds it ended believes they have seen the list.
    //
    // The coverage-gaps block twenty lines down already does this properly: it
    // takes twelve lines per file and writes `(+N more)`. The same obligation,
    // in the same function, understood in one place and not the other.
    const LIST_CAP: usize = 500;

    for f in shown.iter().take(LIST_CAP) {
        let verdict = report
            .correlations
            .iter()
            .find(|c| c.static_finding.as_ref() == Some(&f.id))
            .map(|c| format!(" [{}]", c.verdict.as_str()))
            .unwrap_or_default();
        s.push_str(&format!(
            "{}: {} ({}){}\n  {}\n  {} · confidence {} · {}\n\n",
            f.location.display(),
            f.rule,
            f.severity.as_str(),
            verdict,
            f.message,
            f.provider,
            f.confidence.as_str(),
            f.phase.as_str(),
        ));
    }

    if shown.len() > LIST_CAP {
        s.push_str(&format!(
            "  … and {} more finding(s) not shown. The counts below are of all of them\n\n",
            shown.len() - LIST_CAP
        ));
    }

    // And what the severity filter removed, for the same reason. `--min-severity
    // high` on a tree with eight hundred low findings prints none of them; the
    // counts below say `low: 800`, and this says which switch is why.
    if !ordered.is_empty() && shown.len() < ordered.len() {
        s.push_str(&format!(
            "  {} finding(s) are below the requested severity and are not listed\n\n",
            ordered.len() - shown.len()
        ));
    }

    s.push_str("Summary\n");
    for (severity, n) in &report.summary.by_severity {
        s.push_str(&format!("  {severity}: {n}\n"));
    }
    if report.summary.suppressed > 0 {
        s.push_str(&format!("  suppressed by deviation: {}\n", report.summary.suppressed));
    }
    if !report.summary.by_verdict.is_empty() {
        s.push_str("\nCorrelation\n");
        for (verdict, n) in &report.summary.by_verdict {
            s.push_str(&format!("  {verdict}: {n}\n"));
        }
    }

    // A flagged line that no run reached is a hole in the test suite rather than
    // a defect in the code, so it goes on its own queue. `coverage_gaps` has
    // said it "belongs on a different work queue" since it was written, and was
    // then called by nothing: the grouping existed and no report ever showed it.
    let gaps = sda_engine::correlate::coverage_gaps(&report.findings, &report.correlations);
    if !gaps.is_empty() {
        let total: usize = gaps.iter().map(|(_, lines)| lines.len()).sum();
        // "distinct" because the lines are deduplicated: two guidelines firing
        // on one line is one coverage gap, and a reader comparing this with the
        // `unreached` count above is entitled to know why they differ.
        s.push_str(&format!(
            "\nCoverage gaps — {total} distinct line(s) flagged but never reached, in {} file(s)\n",
            gaps.len()
        ));
        for (file, lines) in &gaps {
            let shown: Vec<String> = lines.iter().take(12).map(|l| l.to_string()).collect();
            let more = if lines.len() > 12 {
                format!(" (+{} more)", lines.len() - 12)
            } else {
                String::new()
            };
            s.push_str(&format!("  {file}: {}{more}\n", shown.join(", ")));
        }
    }

    // Always last, and never omitted: what this run did not establish.
    if !report.exclusions.is_empty() {
        s.push_str("\nNOT CHECKED — do not read a clean result as coverage of these:\n");
        for e in &report.exclusions {
            s.push_str(&format!("  {}: {}\n", e.provider, e.reason));
        }
    }
    s
}

// --- rules -----------------------------------------------------------------

fn rules(args: RulesArgs) -> Result<()> {
    match args.command {
        RulesCommand::Find { query, standard } => {
            let standards = resolve_standards(standard.as_deref())?;
            let mut found = 0;
            for st in standards {
                let catalog = sda_rules::Catalog::load(st);
                for r in catalog.find(&query) {
                    found += 1;
                    println!("{}", r.citation());
                    println!("  {}", r.title);
                    println!(
                        "  {} · {} · checked: {} · {}",
                        r.obligation.as_str(),
                        if r.decidability == sda_rules::Decidability::Decidable {
                            "decidable"
                        } else {
                            "UNDECIDABLE"
                        },
                        r.coverage.as_str(),
                        if r.coverage.clean_means_conformant() {
                            "a clean result is evidence of conformance"
                        } else {
                            "a clean result does NOT establish conformance"
                        }
                    );
                    println!();
                }
            }
            if found == 0 {
                println!("No guideline matched `{query}`.");
            }
        }
        RulesCommand::Audit { standard } => {
            for st in resolve_standards(standard.as_deref())? {
                let audit = sda_rules::Catalog::load(st).audit();
                println!("{}", audit.caveat());
                println!("  by coverage:");
                for (k, v) in &audit.by_coverage {
                    println!("    {k}: {v}");
                }
                println!();
            }
            // An audit that counted only guidelines would describe a conformance
            // position while saying nothing about what the project has agreed not
            // to fix. The split matters as much as the total: a departure from a
            // catalogued guideline is part of the compliance argument, and a
            // deviation of an external tool's finding is a judgement about that
            // tool's opinion, which is a different claim.
            let project = sda_rules::ProjectConfig::discover(std::path::Path::new("."));
            if let Some(reg) = &project.deviations {
                let (total, external) = (reg.len(), reg.external());
                println!(
                    "Deviations on record: {total} ({} against catalogued guidelines, \
                     {external} against external tools).",
                    total - external
                );
            }
        }
        RulesCommand::Import { standard, file } => {
            let st = sda_rules::Standard::parse(&standard)
                .with_context(|| format!("unknown standard `{standard}`"))?;
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let mut catalog = sda_rules::Catalog::load(st);
            let before = catalog.audit().unconfirmed_numbers;
            let n = catalog.import(&text).map_err(|e| anyhow::anyhow!(e))?;
            let after = catalog.audit().unconfirmed_numbers;
            println!(
                "Imported {n} guideline(s) into {}. Unconfirmed rule numbers: {before} -> {after}.",
                st.title()
            );
            println!(
                "Note: this import is in-memory. To make it permanent, place the file at \
                 `.sda/{}.toml` in your project.",
                st.as_str()
            );
        }
    }
    Ok(())
}

fn resolve_standards(name: Option<&str>) -> Result<Vec<sda_rules::Standard>> {
    match name {
        Some(s) => Ok(vec![
            sda_rules::Standard::parse(s).with_context(|| format!("unknown standard `{s}`"))?,
        ]),
        None => Ok(sda_rules::Standard::all().to_vec()),
    }
}

// --- tools -----------------------------------------------------------------

fn tools(args: ToolsArgs) -> Result<()> {
    let ontology = sda_ontology::Ontology::load();
    match args.command {
        ToolsCommand::Search { query } => {
            let hits = ontology.search(&query);
            if hits.is_empty() {
                println!("No tool matched `{query}`.");
            }
            for t in hits {
                println!("{}\n", t.brief());
            }
        }
        ToolsCommand::Describe { id } => match ontology.describe(&id) {
            Some(d) => println!("{d}"),
            None => bail!("no tool with id `{id}`"),
        },
        ToolsCommand::Status => {
            println!("Native providers (always available):");
            for t in ontology.native() {
                println!("  {} — {}", t.id, t.name);
            }
            println!("\nExternal adapters:");
            for (id, availability) in sda_adapters::availability_report() {
                let mark = match &availability {
                    sda_core::Availability::Available => "installed".to_string(),
                    sda_core::Availability::Degraded { reason } => format!("degraded: {reason}"),
                    sda_core::Availability::Unavailable { reason } => format!("absent: {reason}"),
                };
                println!("  {id} — {mark}");
            }
        }
        ToolsCommand::Gaps { language } => {
            let lang = match language.as_str() {
                "c" => sda_core::Language::C,
                "cpp" | "c++" => sda_core::Language::Cpp,
                "rust" => sda_core::Language::Rust,
                "model" | "model-artifact" => sda_core::Language::ModelArtifact,
                other => bail!("unsupported language `{other}`"),
            };
            let available: std::collections::BTreeSet<String> = ontology
                .native_ids()
                .into_iter()
                .chain(
                    sda_adapters::availability_report()
                        .into_iter()
                        .filter(|(_, a)| a.is_usable())
                        .map(|(id, _)| id),
                )
                .collect();

            let gaps = ontology.gaps(&lang, &available);
            if gaps.is_empty() {
                println!("Every catalogued capability is covered for {language}.");
            }
            for cap in gaps {
                let candidates: Vec<&str> = ontology
                    .recommend(cap, &lang)
                    .into_iter()
                    .take(3)
                    .map(|t| t.id.as_str())
                    .collect();
                println!("{}: uncovered. Candidates: {}", cap.as_str(), candidates.join(", "));
            }
        }
    }
    Ok(())
}

// --- build -----------------------------------------------------------------

fn build(args: BuildArgs) -> Result<()> {
    match args.command {
        BuildCommand::Detect { path } => {
            let ctx = sda_build::BuildContext::probe(&path);
            print!("{}", ctx.summary());
            if !ctx.supports_semantic_analysis() {
                println!(
                    "\nSemantics-level guidelines cannot be checked in this state. The plan \
                     command lists exactly how many are affected."
                );
            }
        }
        BuildCommand::Compile { path, profile } => {
            let ctx = sda_build::BuildContext::probe(&path);
            let detected = ctx.primary().context("no build system was recognised")?;
            let p = match profile {
                ProfileArg::Dynamic => Some(sda_build::BuildProfile::for_dynamic_analysis()),
                ProfileArg::Static => Some(sda_build::BuildProfile::for_static_analysis()),
                ProfileArg::None => None,
            };
            let outcome = sda_build::build(
                detected,
                ctx.compilers.first(),
                p.as_ref(),
                std::time::Duration::from_secs(1800),
            )
            .map_err(|e| anyhow::anyhow!(e))?;

            println!("{}", outcome.summary());
            for d in outcome.diagnostics.iter().take(50) {
                println!("  {}:{}:{}: {:?}: {}", d.file, d.line, d.column, d.level, d.message);
            }
            if !outcome.unsupported.is_empty() {
                println!("\nInstrumentation NOT applied by this toolchain:");
                for u in &outcome.unsupported {
                    println!("  {}: {}", u.what, u.reason);
                }
            }
            if !outcome.success {
                std::process::exit(1);
            }
        }
        BuildCommand::CompileCommands { path, synthesize, force } => {
            let ctx = sda_build::BuildContext::probe(&path);
            let detected = ctx.primary().context(
                "no build system was recognised, so there is nothing to ask for a database. \
                 Use --synthesize to approximate one from the source tree.",
            );

            let timeout = std::time::Duration::from_secs(900);
            let result = match (detected, force) {
                // An explicit regeneration skips the pre-existing shortcut.
                (Ok(d), true) => sda_build::compdb::generate(d, timeout).or_else(|e| {
                    if synthesize {
                        sda_build::compdb::synthesize(&path, ctx.compilers.first(), &[])
                            .map_err(|se| anyhow::anyhow!("{e}; synthesis also failed: {se}"))
                    } else {
                        Err(anyhow::anyhow!(e))
                    }
                }),
                (Ok(d), false) => {
                    sda_build::ensure_compile_commands(d, ctx.compilers.first(), synthesize, timeout)
                        .map_err(|e| anyhow::anyhow!(e))
                }
                // No build system at all: synthesis is the only route.
                (Err(e), _) => {
                    if synthesize {
                        sda_build::compdb::synthesize(&path, ctx.compilers.first(), &[])
                            .map_err(|se| anyhow::anyhow!(se))
                    } else {
                        Err(e)
                    }
                }
            }?;

            println!("{}", result.summary());
            if result.provenance == sda_build::Provenance::Synthesized {
                eprintln!(
                    "\nwarning: this database is an approximation. Type-aware findings derived \
                     from it may be wrong in either direction."
                );
            }
            let semantics = sda_rules::Catalog::load(sda_rules::Standard::MisraC2023)
                .by_coverage(sda_rules::Coverage::Semantics)
                .len();
            println!(
                "\n{semantics} MISRA C guideline(s) requiring type information are now reachable. \
                 Run them with:\n    sda scan {} --with ext.clang-tidy",
                path.display()
            );
        }
    }
    Ok(())
}

// --- ai --------------------------------------------------------------------

fn ai(args: AiArgs) -> Result<()> {
    match args.command {
        AiCommand::Scan { path } => {
            let scanner = sda_ai::ModelScanner::new();
            let mut target = discover::discover(&path, &discover::DiscoveryOptions::default());
            // A model under an excluded directory is excluded here too. This
            // command reports a digest and a format per artifact, so scanning
            // one the project declared out of scope prints a line about a file
            // no other command will mention.
            let project = sda_rules::ProjectConfig::discover(&path);
            let scope_notices = match (&project.scope, project.root()) {
                (Some(scope), Some(anchor)) => discover::apply_scope(&mut target, scope, anchor),
                _ => Vec::new(),
            };
            for n in &scope_notices {
                println!("  {}
", n.reason);
            }
            let artifacts = target.files_in(&[sda_core::Language::ModelArtifact]);
            if artifacts.is_empty() {
                println!("No model artifacts found under {}.", path.display());
                return Ok(());
            }
            for f in artifacts {
                let r = scanner.scan_file(&f.path)?;
                println!("{} [{}] {} bytes", r.path, r.format.as_str(), r.size);
                if let Some(d) = &r.digest {
                    println!("  sha256: {d}");
                }
                if r.format.executes_on_load() {
                    println!("  WARNING: this container executes code when loaded.");
                }
                for finding in &r.findings {
                    println!("  [{}] {}", finding.severity.as_str(), finding.message);
                }
                println!();
            }
            println!(
                "Container analysis only. No inspection of a model file can reveal a backdoor in \
                 the weights; run `sda ai probes` for the behavioural suite."
            );
        }
        AiCommand::Probes { trigger } => {
            let mut suite = sda_ai::default_suite();
            suite.extend(sda_ai::suite_for_triggers(&trigger));
            println!("{}", serde_json::to_string_pretty(&suite)?);
        }
        AiCommand::Rmf => {
            let rmf = sda_ai::Rmf::load();
            println!("{}\n", rmf.caveat());
            for f in rmf.functions() {
                println!("{f}");
                for s in rmf.function(&f) {
                    println!("  {} [{}] {}", s.id, s.evidence.as_str(), s.title);
                }
                println!();
            }
        }
        AiCommand::Risks => {
            let t = sda_ai::RiskTaxonomy::load();
            for r in t.all() {
                println!("{} [{}] {}", r.id, r.severity.as_str(), r.title);
                println!("  detectable: {}", r.phase.as_str());
                if let Some(o) = &r.owasp {
                    println!("  OWASP LLM: {o}");
                }
                if !r.rmf.is_empty() {
                    println!("  NIST AI RMF: {}", r.rmf.join(", "));
                }
                println!();
            }
        }
    }
    Ok(())
}

// --- plan and swe ----------------------------------------------------------

fn plan(args: PlanArgs) -> Result<()> {
    let mut target = discover::discover(&args.path, &discover::DiscoveryOptions::default());

    // The MCP copy of this command has applied scope since it was written, with
    // the reason in a comment beside it: *a plan over files the scan will not
    // read would propose work on nothing*. This copy never learned it. On a
    // project excluding `legacy/`, whose only C++ lived there, this printed
    // `Languages: c, cpp` and a second step the scan would never run.
    //
    // Two implementations of one command, and the argument for the correct
    // behaviour was written down in the one that had it.
    let project = sda_rules::ProjectConfig::discover(&args.path);
    let scope_notices = match (&project.scope, project.root()) {
        (Some(scope), Some(anchor)) => discover::apply_scope(&mut target, scope, anchor),
        _ => Vec::new(),
    };

    let ctx = sda_build::BuildContext::probe(&args.path);

    // Native tools ship with the toolkit, so they are always available; the
    // registry alone under-reports, because not every native capability is a
    // registered `Analyzer`.
    let available: std::collections::BTreeSet<String> = sda_ontology::Ontology::load()
        .native_ids()
        .into_iter()
        .chain(
            sda_adapters::availability_report()
                .into_iter()
                .filter(|(_, a)| a.is_usable())
                .map(|(id, _)| id),
        )
        .collect();

    let inputs = sda_agent::PlanInputs {
        available,
        allow_external: args.allow_external,
        has_artifact: args.artifact.as_ref().is_some_and(|p| p.exists()),
        has_compile_commands: ctx.database.is_some(),
        standards: target.languages().iter().flat_map(sda_rules::Standard::for_language).collect(),
    };
    println!("{}", sda_agent::plan(&target, &inputs).noting_scope(&scope_notices).render());
    Ok(())
}

fn swe(args: SweArgs) -> Result<()> {
    if args.reset {
        sda_agent::Session::reset(&args.path).map_err(|e| anyhow::anyhow!(e))?;
        println!("session reset.");
        return Ok(());
    }

    // Resume rather than start: the stall and thrash detectors compare against
    // earlier iterations, and each CLI invocation is a separate process.
    let mut session = sda_agent::Session::resume(&args.path);
    let resumed = session.len();

    let iteration = sda_agent::swe::iterate(
        &args.path,
        &mut session,
        args.context_lines,
        std::time::Duration::from_secs(1800),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    session.save(&args.path).map_err(|e| anyhow::anyhow!(e))?;
    if resumed > 0 {
        println!("iteration {} (resumed after {resumed})", iteration.number);
    }

    println!("{}", iteration.summary);
    match &iteration.next {
        Some(item) => {
            println!("\nNext: {}:{}:{}", item.file, item.line, item.column);
            println!("  {}", item.message);
            if !item.context.is_empty() {
                println!("\n{}", item.context);
            }
            println!(
                "\n{} other diagnostic(s) in this file.",
                item.siblings_in_file.saturating_sub(1)
            );
        }
        None => println!("\nNo diagnostics."),
    }
    if let Some(stop) = session.should_stop(u32::MAX) {
        println!("\nStop: {}", stop.explain());
        if !stop.succeeded() {
            std::process::exit(1);
        }
    }
    Ok(())
}

