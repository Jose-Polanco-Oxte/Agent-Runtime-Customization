//! REQ-006 structural checks: the individual decision entry and the unused
//! wrappers are gone, and the aggregate path that production uses remains.

use std::path::{Path, PathBuf};

use regex::Regex;

const COORDINATOR: &str = "src/runtime/execution/coordinator.rs";
const ORCHESTRATOR: &str = "src/runtime/decision/orchestrator.rs";
const LIFECYCLE: &str = "src/runtime/execution/lifecycle.rs";
const MAIN: &str = "src/main.rs";
const THIS_FILE: &str = "decision_apply_surface_tests.rs";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("cannot read {relative}: {error}"))
}

fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when `source` defines exactly `fn <name>` (not a longer identifier).
fn defines_fn(source: &str, name: &str) -> bool {
    let pattern = format!(r"\bfn\s+{}\b", regex::escape(name));
    Regex::new(&pattern)
        .unwrap()
        .is_match(&without_line_comments(source))
}

fn mentions_word(source: &str, name: &str) -> bool {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    Regex::new(&pattern)
        .unwrap()
        .is_match(&without_line_comments(source))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "node_modules" && name != "target" && name != "dist" {
                collect_files(&path, out);
            }
        } else if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("rs" | "ts" | "tsx")
        ) {
            out.push(path);
        }
    }
}

/// Files of the grep scope that mention `name` as a whole word (this file excluded).
fn grep_scope_matches(name: &str) -> Vec<String> {
    let mut files = Vec::new();
    for dir in [
        "src",
        "tests",
        "examples",
        "ui/decision/src",
        "ui/decision/src-tauri/src",
        "ui/decision/webdriver",
    ] {
        collect_files(&root().join(dir), &mut files);
    }
    files
        .into_iter()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) != Some(THIS_FILE))
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            mentions_word(&text, name).then(|| {
                path.strip_prefix(root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
        })
        .collect()
}

// AC-006.1 ---------------------------------------------------------------

#[test]
fn coordinator_no_longer_defines_the_individual_apply_decision_entry() {
    assert!(!defines_fn(&read(COORDINATOR), "apply_decision"));
}

#[test]
fn coordinator_no_longer_defines_the_unused_authorizations_wrapper() {
    assert!(!defines_fn(
        &read(COORDINATOR),
        "apply_aggregate_decision_with_authorizations"
    ));
}

#[test]
fn orchestrator_no_longer_defines_apply_resolution() {
    assert!(!defines_fn(&read(ORCHESTRATOR), "apply_resolution"));
}

#[test]
fn removed_symbols_have_zero_matches_in_the_grep_scope() {
    for symbol in [
        "apply_decision",
        "apply_aggregate_decision_with_authorizations",
        "apply_resolution",
    ] {
        assert_eq!(
            grep_scope_matches(symbol),
            Vec::<String>::new(),
            "`{symbol}` must have zero matches outside this file"
        );
    }
}

// AC-006.2 ---------------------------------------------------------------

#[test]
fn aggregate_entry_points_that_production_uses_still_exist() {
    let coordinator = read(COORDINATOR);
    assert!(defines_fn(&coordinator, "apply_aggregate_decision"));
    assert!(defines_fn(
        &coordinator,
        "apply_aggregate_decision_with_authorizations_outcome"
    ));
    assert!(defines_fn(
        &read(ORCHESTRATOR),
        "apply_interactive_resolution"
    ));
}

#[test]
fn lifecycle_still_calls_apply_aggregate_decision() {
    let lifecycle = without_line_comments(&read(LIFECYCLE));
    assert!(
        Regex::new(r"\.apply_aggregate_decision\(")
            .unwrap()
            .is_match(&lifecycle)
    );
}

// AC-012.6 (inspection support) -------------------------------------------

#[test]
fn main_calls_only_the_interactive_resolution_entry() {
    let main = read(MAIN);
    assert!(mentions_word(&main, "apply_interactive_resolution"));
    for removed in [
        "apply_decision",
        "apply_resolution",
        "apply_aggregate_decision_with_authorizations",
    ] {
        assert!(
            !mentions_word(&main, removed),
            "main.rs must not use {removed}"
        );
    }
}
