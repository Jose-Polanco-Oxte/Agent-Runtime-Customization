//! REQ-008 (finding #11): leftovers removed, auxiliary APIs reduced, mocks and
//! the in-memory store kept out of the default product build.
//!
//! The removal and gating criteria are about what the source contains, so most
//! tests scan `src/**/*.rs` with word-boundary regexes (a plural such as
//! `exact_authorizations` never matches `exact_authorization`). The tests that
//! construct the mocks check that gating still leaves them usable from tests.

use std::fs;
use std::path::{Path, PathBuf};

use arc::{GuardExecutionStateStore, InMemoryStateStore, MockDecisionProvider, MockProbeRunner};
use regex::Regex;

// ---------------------------------------------------------------- helpers

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = manifest_dir().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every `src/**/*.rs` file as (path relative to the manifest dir, content).
fn all_src() -> Vec<(String, String)> {
    let root = manifest_dir();
    let mut files = Vec::new();
    collect_rs(&root.join("src"), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .expect("under manifest dir")
                .to_string_lossy()
                .replace('\\', "/");
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
                .replace("\r\n", "\n");
            (relative, content)
        })
        .collect()
}

/// `file:line: text` for each line of `src/` that contains `symbol` as a whole word.
fn word_hits(symbol: &str) -> Vec<String> {
    let word = Regex::new(&format!(r"\b{}\b", regex::escape(symbol))).expect("word regex");
    let mut hits = Vec::new();
    for (file, content) in all_src() {
        for (index, line) in content.lines().enumerate() {
            if word.is_match(line) {
                hits.push(format!("{file}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    hits
}

fn assert_symbol_absent(symbol: &str) {
    let hits = word_hits(symbol);
    assert!(
        hits.is_empty(),
        "`{symbol}` must have zero matches in src/, found:\n{}",
        hits.join("\n")
    );
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with("//")
}

/// Attribute lines attached to the item that starts at `index` (doc comments skipped).
fn attributes_above<'a>(lines: &[&'a str], index: usize) -> Vec<&'a str> {
    let mut attributes = Vec::new();
    let mut cursor = index;
    while cursor > 0 {
        cursor -= 1;
        let trimmed = lines[cursor].trim();
        if trimmed.starts_with("#[") {
            attributes.push(lines[cursor]);
        } else if trimmed.starts_with("//") {
            continue;
        } else {
            break;
        }
    }
    attributes
}

/// True when the line, or an item enclosing it (module, impl, `use` list), carries
/// an attribute that matches `gate`.
fn is_gated(lines: &[&str], index: usize, gate: &Regex) -> bool {
    if attributes_above(lines, index)
        .iter()
        .any(|attribute| gate.is_match(attribute))
    {
        return true;
    }
    let own_indent = indent_of(lines[index]);
    if own_indent == 0 {
        return false;
    }
    let mut cursor = index;
    while cursor > 0 {
        cursor -= 1;
        let line = lines[cursor];
        if is_comment_or_blank(line) || line.trim().starts_with("#[") {
            continue;
        }
        if indent_of(line) < own_indent {
            return is_gated(lines, cursor, gate);
        }
    }
    false
}

/// Any gating that keeps an item out of a default build: `cfg(test)`, the
/// non-default feature, or both.
fn gate_any() -> Regex {
    Regex::new(
        r#"^\s*#\[cfg\((test|feature\s*=\s*"test-support"|any\(\s*test\s*,\s*feature\s*=\s*"test-support"\s*,?\s*\)|any\(\s*feature\s*=\s*"test-support"\s*,\s*test\s*,?\s*\))\)\]\s*$"#,
    )
    .expect("gate regex")
}

/// Gating that still lets integration tests and `main.rs` unit tests see the
/// item: it must name the `test-support` feature.
fn gate_feature() -> Regex {
    Regex::new(
        r#"^\s*#\[cfg\((feature\s*=\s*"test-support"|any\(\s*test\s*,\s*feature\s*=\s*"test-support"\s*,?\s*\)|any\(\s*feature\s*=\s*"test-support"\s*,\s*test\s*,?\s*\))\)\]\s*$"#,
    )
    .expect("feature gate regex")
}

/// Lines of `content` (comments excluded) whose text matches `pattern`, as indexes.
fn code_lines_matching(lines: &[&str], pattern: &Regex) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !line.trim().starts_with("//") && pattern.is_match(line))
        .map(|(index, _)| index)
        .collect()
}

/// Text from the first line matching `start` up to (excluding) the next line that
/// is exactly `end_marker`, which closes the item.
fn block_from(content: &str, start: &str, end_marker: &str) -> String {
    let begin = content
        .find(start)
        .unwrap_or_else(|| panic!("`{start}` not found"));
    let rest = &content[begin..];
    let end = rest
        .find(end_marker)
        .unwrap_or_else(|| panic!("end marker {end_marker:?} not found after `{start}`"));
    rest[..end].to_string()
}

// -------------------------------------------- AC-008.1: removed symbols

macro_rules! symbol_is_removed {
    ($test:ident, $symbol:literal) => {
        #[test]
        fn $test() {
            assert_symbol_absent($symbol);
        }
    };
}

symbol_is_removed!(progress_class_has_zero_matches_in_src, "ProgressClass");
symbol_is_removed!(
    is_explicit_user_choice_has_zero_matches_in_src,
    "is_explicit_user_choice"
);
symbol_is_removed!(is_retry_has_zero_matches_in_src, "is_retry");
symbol_is_removed!(
    from_exact_authorization_has_zero_matches_in_src,
    "from_exact_authorization"
);
symbol_is_removed!(
    with_evaluation_result_has_zero_matches_in_src,
    "with_evaluation_result"
);
symbol_is_removed!(with_correlation_has_zero_matches_in_src, "with_correlation");
symbol_is_removed!(
    exact_authorization_singular_has_zero_matches_in_src,
    "exact_authorization"
);
symbol_is_removed!(
    primary_authorization_has_zero_matches_in_src,
    "primary_authorization"
);

#[test]
fn surviving_plural_exact_authorizations_api_is_still_present_in_src() {
    // Guards the scan: the plural API stays and is not what the singular scan flags.
    assert!(
        !word_hits("exact_authorizations").is_empty(),
        "`exact_authorizations` is the surviving API and must still appear in src/"
    );
}

#[test]
fn surviving_decision_helpers_that_production_uses_are_kept() {
    let resolution = read("src/runtime/decision/resolution.rs");
    let orchestrator = read("src/runtime/decision/orchestrator.rs");
    assert!(
        resolution.contains("fn explicit_decision_choice"),
        "explicit_decision_choice is used by the orchestrator and must stay"
    );
    assert!(orchestrator.contains("explicit_decision_choice"));
    let context = read("src/runtime/decision/context.rs");
    assert!(
        context.contains("fn exact_authorizations(")
            && context.contains("fn from_exact_authorizations("),
        "plural accessor and constructor must stay"
    );
    assert!(
        context.contains("fn set_correlation"),
        "set_correlation must stay"
    );
    assert!(
        read("src/runtime/guard_evaluation.rs").contains("pub fn exact_authorizations("),
        "DialogRequest::exact_authorizations must stay"
    );
}

// ------------------------------------------- AC-008.2: fields and wrappers

macro_rules! store_field_is_removed {
    ($test:ident, $field:literal) => {
        #[test]
        fn $test() {
            let memory = read("src/runtime/state_store/memory.rs");
            let body = block_from(&memory, "struct StoredExactAuthorization {", "\n}\n");
            let field = Regex::new(&format!(r"(?m)^\s*(pub\s+)?{}\s*:", $field)).unwrap();
            assert!(
                !field.is_match(&body),
                "StoredExactAuthorization must not keep the unread field `{}`:\n{body}",
                $field
            );
        }
    };
}

store_field_is_removed!(in_memory_store_drops_unread_session_id_field, "session_id");
store_field_is_removed!(
    in_memory_store_drops_unread_invocation_id_field,
    "invocation_id"
);
store_field_is_removed!(
    in_memory_store_drops_unread_consumed_by_invocation_id_field,
    "consumed_by_invocation_id"
);
store_field_is_removed!(
    in_memory_store_drops_unread_decision_id_field,
    "decision_id"
);

#[test]
fn in_memory_store_keeps_the_fields_that_are_read() {
    let memory = read("src/runtime/state_store/memory.rs");
    let body = block_from(&memory, "struct StoredExactAuthorization {", "\n}\n");
    for kept in [
        "guard_id",
        "operation_fingerprint",
        "event_id",
        "tool",
        "normalized_arguments_fingerprint",
        "context",
        "expires_at_unix_ms",
        "uses_remaining",
    ] {
        let field = Regex::new(&format!(r"(?m)^\s*{kept}\s*:")).unwrap();
        assert!(field.is_match(&body), "field `{kept}` must stay:\n{body}");
    }
}

symbol_is_removed!(
    extract_from_session_id_wrapper_has_zero_matches_in_src,
    "extract_from_session_id"
);
symbol_is_removed!(
    extract_from_session_id_with_path_wrapper_has_zero_matches_in_src,
    "extract_from_session_id_with_path"
);
symbol_is_removed!(
    find_codex_rollout_in_sessions_dir_wrapper_has_zero_matches_in_src,
    "find_codex_rollout_in_sessions_dir"
);

#[test]
fn production_session_extraction_entry_points_are_kept() {
    let context = read("src/runtime/context.rs");
    assert!(context.contains("fn extract_from_session_id_with_provider_path("));
    assert!(context.contains("fn find_opened_codex_rollout_in_sessions_dir("));
    assert!(context.contains("fn extract_from_codex_session_with_path_and_roots("));
}

#[test]
fn dated_rollout_coverage_moved_to_an_inline_test_in_runtime_context() {
    // Successor of section 5 of
    // `runtime_and_schema_tests::test_m2_codex_rollout_and_decision_fail_closed`,
    // which called the removed public wrapper `find_codex_rollout_in_sessions_dir`.
    let context = read("src/runtime/context.rs");
    let tests_start = context
        .find("#[cfg(test)]\nmod tests")
        .expect("runtime/context.rs must keep its inline tests module");
    let inline = &context[tests_start..];
    let header = Regex::new(r"(?m)^\s*fn (dated_codex_rollout\w*)\(\)").unwrap();
    let captured = header
        .captures(inline)
        .expect("an inline test named `dated_codex_rollout_*` must cover the YYYY/MM/DD layout");
    let start = captured.get(0).unwrap().start();
    let rest = &inline[start..];
    let end = rest.find("\n    }\n").expect("end of inline test body");
    let body = &rest[..end];
    assert!(
        body.contains("extract_from_codex_session_with_path_and_roots("),
        "successor must go through the real resolver:\n{body}"
    );
    assert!(
        body.contains("rollout-"),
        "successor must create a rollout-<id>.jsonl file"
    );
    assert!(
        Regex::new(r"20\d{2}").unwrap().is_match(body),
        "successor must use a dated sessions/YYYY/MM/DD layout"
    );
    assert!(
        body.contains("assert"),
        "successor must assert a concrete resolution result"
    );
}

// ---------------------------------- AC-008.4: no allow hides dead items

const ISSUE_11_FILES: [&str; 10] = [
    "src/runtime/execution/observation.rs",
    "src/runtime/execution/mod.rs",
    "src/runtime/decision/resolution.rs",
    "src/runtime/decision/context.rs",
    "src/runtime/decision/mod.rs",
    "src/runtime/guard_evaluation.rs",
    "src/runtime/state_store/memory.rs",
    "src/runtime/state_store/mod.rs",
    "src/runtime/context.rs",
    "src/runtime/evaluator.rs",
];

#[test]
fn no_allow_dead_code_in_issue_11_files_except_guard_failure_context() {
    let allow_dead = Regex::new(r"allow\([^)]*dead_code").unwrap();
    let mut offenders = Vec::new();
    for file in ISSUE_11_FILES {
        let content = read(file);
        let lines: Vec<&str> = content.lines().collect();
        for index in code_lines_matching(&lines, &allow_dead) {
            // The attribute must be attached to GuardFailureContext (struct or impl).
            let mut target = index + 1;
            while target < lines.len() && lines[target].trim().starts_with("#[") {
                target += 1;
            }
            let attached = lines.get(target).map(|l| l.trim()).unwrap_or("");
            let allowed = attached.starts_with("pub struct GuardFailureContext")
                || attached.starts_with("impl GuardFailureContext");
            if !allowed {
                offenders.push(format!("{file}:{}: {}", index + 1, lines[index].trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "allow(dead_code) may only hide GuardFailureContext:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn decision_mod_has_no_unused_reexports_or_unused_import_allows() {
    let decision_mod = read("src/runtime/decision/mod.rs");
    assert!(
        !decision_mod.contains("allow(unused_imports)"),
        "decision/mod.rs must not hide unused imports"
    );
    assert!(
        !Regex::new(r"\bMAX_[A-Z_]+\b")
            .unwrap()
            .is_match(&decision_mod),
        "unused pub(crate) MAX_* re-exports must be removed from decision/mod.rs"
    );
    assert!(
        !Regex::new(r"\bvalidate_dialog_response\b")
            .unwrap()
            .is_match(&decision_mod),
        "unused validate_dialog_response re-export must be removed from decision/mod.rs"
    );
    assert!(
        decision_mod.contains("pub use messages::DecisionContractError;"),
        "DecisionContractError is part of the public surface and stays re-exported"
    );
}

// ------------------------ AC-008.3: mocks and in-memory store gated off

#[test]
fn test_support_feature_is_declared_and_not_a_default_feature() {
    let cargo = read("Cargo.toml");
    let features = Regex::new(r"(?ms)^\[features\]\s*\n(.*?)(?:^\[|\z)")
        .unwrap()
        .captures(&cargo)
        .expect("Cargo.toml must have a [features] section")
        .get(1)
        .unwrap()
        .as_str()
        .to_string();
    assert!(
        Regex::new(r"(?m)^test-support\s*=\s*\[\s*\]\s*(#.*)?$")
            .unwrap()
            .is_match(&features),
        "`test-support = []` must be declared:\n{features}"
    );
    if let Some(default) = Regex::new(r"(?ms)^default\s*=\s*\[(.*?)\]")
        .unwrap()
        .captures(&features)
    {
        assert!(
            !default.get(1).unwrap().as_str().contains("test-support"),
            "test-support must not be a default feature"
        );
    }
}

#[test]
fn self_dev_dependency_enables_test_support_for_cargo_test() {
    let cargo = read("Cargo.toml");
    let dev = Regex::new(r"(?ms)^\[dev-dependencies\]\s*\n(.*?)(?:^\[|\z)")
        .unwrap()
        .captures(&cargo)
        .expect("Cargo.toml must have a [dev-dependencies] section")
        .get(1)
        .unwrap()
        .as_str()
        .to_string();
    assert!(
        Regex::new(r#"(?m)^arc\s*=\s*\{[^}]*path\s*=\s*"\."[^}]*features\s*=\s*\[\s*"test-support"\s*\][^}]*\}"#)
            .unwrap()
            .is_match(&dev),
        "self dev-dependency with features = [\"test-support\"] is required:\n{dev}"
    );
    let normal = Regex::new(r"(?ms)^\[dependencies\]\s*\n(.*?)(?:^\[|\z)")
        .unwrap()
        .captures(&cargo)
        .expect("[dependencies]")
        .get(1)
        .unwrap()
        .as_str()
        .to_string();
    assert!(
        !Regex::new(r"(?m)^arc\s*=").unwrap().is_match(&normal),
        "arc must not depend on itself outside dev-dependencies"
    );
}

#[test]
fn test_support_feature_is_active_in_integration_tests() {
    assert!(
        cfg!(feature = "test-support"),
        "cargo test must build the package with the test-support feature"
    );
}

#[test]
fn mock_structs_are_defined_only_under_the_test_support_gate() {
    let evaluator = read("src/runtime/evaluator.rs");
    let lines: Vec<&str> = evaluator.lines().collect();
    let gate = gate_feature();
    for definition in [
        r"^\s*pub struct MockProbeRunner\b",
        r"^\s*pub struct MockDecisionProvider\b",
    ] {
        let pattern = Regex::new(definition).unwrap();
        let found = code_lines_matching(&lines, &pattern);
        assert_eq!(found.len(), 1, "exactly one definition of {definition}");
        assert!(
            is_gated(&lines, found[0], &gate),
            "{} must sit under cfg(any(test, feature = \"test-support\")) (directly or through its module)",
            lines[found[0]].trim()
        );
    }
}

#[test]
fn mock_impl_blocks_are_gated_with_their_structs() {
    let evaluator = read("src/runtime/evaluator.rs");
    let lines: Vec<&str> = evaluator.lines().collect();
    let gate = gate_any();
    let impls = Regex::new(r"^\s*impl\b.*\b(MockProbeRunner|MockDecisionProvider)\b").unwrap();
    let found = code_lines_matching(&lines, &impls);
    assert!(
        found.len() >= 4,
        "inherent and trait impls of both mocks expected"
    );
    for index in found {
        assert!(
            is_gated(&lines, index, &gate),
            "`{}` must be gated",
            lines[index].trim()
        );
    }
}

#[test]
fn in_memory_store_module_and_reexport_are_gated_by_the_feature() {
    let store_mod = read("src/runtime/state_store/mod.rs");
    let lines: Vec<&str> = store_mod.lines().collect();
    let gate = gate_feature();
    let module = Regex::new(r"^\s*(pub(\(crate\))?\s+)?mod memory\s*;").unwrap();
    let found = code_lines_matching(&lines, &module);
    assert_eq!(found.len(), 1, "`mod memory;` declaration expected once");
    assert!(
        is_gated(&lines, found[0], &gate),
        "`mod memory;` must be gated by cfg(any(test, feature = \"test-support\"))"
    );
    let reexport = Regex::new(r"\bInMemoryStateStore\b").unwrap();
    let found = code_lines_matching(&lines, &reexport);
    assert!(
        !found.is_empty(),
        "state_store must still re-export InMemoryStateStore"
    );
    for index in found {
        assert!(
            is_gated(&lines, index, &gate),
            "`{}` must be gated",
            lines[index].trim()
        );
    }
}

#[test]
fn root_reexports_of_mocks_and_in_memory_store_are_gated_by_the_feature() {
    let names =
        Regex::new(r"\b(MockProbeRunner|MockDecisionProvider|InMemoryStateStore)\b").unwrap();
    let gate = gate_feature();
    for file in ["src/lib.rs", "src/runtime/mod.rs"] {
        let content = read(file);
        let lines: Vec<&str> = content.lines().collect();
        let found = code_lines_matching(&lines, &names);
        assert!(
            !found.is_empty(),
            "{file} must still re-export the test helpers"
        );
        for index in found {
            assert!(
                is_gated(&lines, index, &gate),
                "{file}:{}: `{}` must be re-exported under cfg(any(test, feature = \"test-support\"))",
                index + 1,
                lines[index].trim()
            );
        }
    }
}

#[test]
fn every_other_use_of_mocks_and_in_memory_store_in_src_is_test_only() {
    let names =
        Regex::new(r"\b(MockProbeRunner|MockDecisionProvider|InMemoryStateStore)\b").unwrap();
    let gate = gate_any();
    let mut offenders = Vec::new();
    for (file, content) in all_src() {
        // memory.rs is gated as a whole by `mod memory;` (checked separately).
        if file == "src/runtime/state_store/memory.rs" {
            continue;
        }
        let lines: Vec<&str> = content.lines().collect();
        for index in code_lines_matching(&lines, &names) {
            if !is_gated(&lines, index, &gate) {
                offenders.push(format!("{file}:{}: {}", index + 1, lines[index].trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "product code must not reference the test helpers outside cfg(test)/test-support:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn in_memory_store_has_no_dead_code_allow_left() {
    let memory = read("src/runtime/state_store/memory.rs");
    assert!(
        !Regex::new(r"allow\([^)]*dead_code")
            .unwrap()
            .is_match(&memory),
        "memory.rs must not hide dead code after the field cleanup"
    );
}

#[test]
fn gated_test_helpers_remain_usable_from_integration_tests() {
    fn assert_state_store<T: GuardExecutionStateStore>(_: &T) {}
    let probe = MockProbeRunner::new().with_output("fixture-check", "pass");
    assert!(
        probe.calls().is_empty(),
        "a fresh mock has recorded no calls"
    );
    let _provider = MockDecisionProvider::new();
    let store = InMemoryStateStore::new();
    assert_state_store(&store);
}

// -------- AC-008.5 and AC-012.1: runtime types and the real path preserved

#[test]
fn guard_failure_context_is_defined_exported_and_used_by_the_runtime() {
    let context = read("src/runtime/decision/context.rs");
    assert!(context.contains("pub struct GuardFailureContext"));
    let production = &context[..context.find("#[cfg(test)]").expect("test module marker")];
    assert!(
        production.contains("GuardFailureContext::new("),
        "production code of decision/context.rs must construct GuardFailureContext"
    );
    assert!(
        Regex::new(r"\bGuardFailureContext\b")
            .unwrap()
            .is_match(&read("src/lib.rs")),
        "GuardFailureContext stays exported from the crate root"
    );
    assert!(
        read("src/main.rs").contains("arc::GuardFailureContext"),
        "main.rs consumes GuardFailureContext"
    );
}

#[test]
fn sqlite_state_store_is_defined_exported_and_opened_by_run_hook() {
    assert!(read("src/runtime/state_store/sqlite.rs").contains("pub struct SqliteStateStore"));
    assert!(
        Regex::new(r"\bSqliteStateStore\b")
            .unwrap()
            .is_match(&read("src/lib.rs")),
        "SqliteStateStore stays exported from the crate root"
    );
    let main = read("src/main.rs");
    let run_hook = block_from(&main, "\nfn run_hook(", "\n}\n");
    assert!(
        run_hook.contains("SqliteStateStore::open("),
        "run_hook must open the SQLite store, not an in-memory one"
    );
    assert!(
        !run_hook.contains("InMemoryStateStore"),
        "run_hook must not fall back to the in-memory store"
    );
}

#[test]
fn aggregate_decision_application_is_defined_and_called_by_the_lifecycle() {
    assert!(
        read("src/runtime/execution/coordinator.rs").contains("pub fn apply_aggregate_decision("),
        "apply_aggregate_decision must exist"
    );
    assert!(
        read("src/runtime/execution/lifecycle.rs").contains(".apply_aggregate_decision("),
        "the lifecycle path must still apply the aggregate decision"
    );
}

#[test]
fn main_does_not_call_any_removed_public_symbol() {
    let main = read("src/main.rs");
    for symbol in [
        "ProgressClass",
        "is_explicit_user_choice",
        "is_retry",
        "from_exact_authorization",
        "with_evaluation_result",
        "with_correlation",
        "exact_authorization",
        "primary_authorization",
        "extract_from_session_id",
        "extract_from_session_id_with_path",
        "find_codex_rollout_in_sessions_dir",
    ] {
        assert!(
            !Regex::new(&format!(r"\b{symbol}\b"))
                .unwrap()
                .is_match(&main),
            "main.rs must not reference removed symbol `{symbol}`"
        );
    }
}
