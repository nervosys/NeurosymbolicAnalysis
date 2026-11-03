// Every command the frontend may invoke is named here, and
// `capabilities/main.json` grants exactly these to the one window. Without a
// manifest, Tauri lets the page reach any registered command and the CSP is the
// only thing in front of them; with one, a command added to `generate_handler!`
// but not here is refused at the IPC boundary until someone decides it belongs.
const COMMANDS: &[&str] = &[
    "open_document",
    "check_buffer",
    "scan",
    "not_checked",
    "glyph_markers",
    "coverage_for",
    "rule_detail",
    "set_triage",
    "stale_triage",
    "set_baseline",
    "baseline_info",
    "assign_finding",
    "comment_on_finding",
    "plan",
    "terminal_start",
    "terminal_write",
    "terminal_read",
    "terminal_resize",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("the Tauri build step");
}
