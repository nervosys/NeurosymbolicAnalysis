//! The release workflow takes a tag's notes from its `CHANGELOG.md` section and
//! refuses a tag that has none. That refusal comes after four platforms have
//! built, which is the most expensive place to learn a heading was forgotten.
//! This asks the same question at gate time, of the version being built.

#[test]
fn the_changelog_has_a_section_for_this_version() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md")).expect("CHANGELOG.md");
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));

    // The workflow's awk: the lines after the heading, up to the next `## [`.
    let section: Vec<&str> = changelog
        .lines()
        .skip_while(|l| !l.starts_with(&heading))
        .skip(1)
        .take_while(|l| !l.starts_with("## ["))
        .collect();
    assert!(
        section.iter().any(|l| !l.trim().is_empty()),
        "CHANGELOG.md has no section `{heading}`; the release workflow would refuse this tag"
    );
}
