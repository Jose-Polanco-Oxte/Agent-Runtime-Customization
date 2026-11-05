//! REQ-009 canonical names (AC-009.1 to AC-009.4, AC-009.6): the fictitious
//! version suffixes (`V1`/`V2`/`_V1`/`_V2`/`_v2`) are gone from Rust and TypeScript
//! identifiers, with no alias left behind. Wire tokens (string literals) are
//! pinned by `json_token_golden_tests.rs`, not here.
//!
//! Every old name is assembled from a stem and a suffix at run time, and this
//! file is excluded from the scan, so it never matches itself. Matching is by
//! whole word (identifier characters are `[A-Za-z0-9_]`), like `rg -w`.
//!
//! One test per implementation slice (S1 to S7 in the REQ-009 plan). Each one
//! fails while any old name of its slice is still present in the scanned
//! sources (production or tests) and also requires the new name to be declared.

use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const SCAN_ROOTS: &[&str] = &[
    "src",
    "tests",
    "examples",
    "ui/decision/src-tauri/src",
    "ui/decision/src",
    "ui/decision/webdriver",
];

struct Source {
    /// Path relative to the repository root, with forward slashes.
    path: String,
    text: String,
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !matches!(name, "node_modules" | "target" | "dist") {
                collect(&path, out);
            }
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "ts" | "svelte")
        ) {
            out.push(path);
        }
    }
}

fn sources() -> &'static [Source] {
    static SOURCES: OnceLock<Vec<Source>> = OnceLock::new();
    SOURCES.get_or_init(|| {
        let this = Path::new(file!()).file_name().unwrap().to_owned();
        let mut paths = Vec::new();
        for root in SCAN_ROOTS {
            collect(&repo_root().join(root), &mut paths);
        }
        paths.retain(|path| path.file_name() != Some(this.as_os_str()));
        paths.sort();
        let found: Vec<Source> = paths
            .into_iter()
            .map(|path| Source {
                path: path
                    .strip_prefix(repo_root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                text: String::from_utf8_lossy(&fs::read(&path).unwrap()).into_owned(),
            })
            .collect();
        assert!(
            found.len() > 60,
            "scanner found too few files: {}",
            found.len()
        );
        found
    })
}

fn is_test_path(path: &str) -> bool {
    path.starts_with("tests/")
        || path.ends_with(".test.ts")
        || path.starts_with("ui/decision/webdriver/")
}

fn is_ident(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// A rename: the old identifier (built from parts) and the new one, if any.
struct Rename {
    old: String,
    new: Option<String>,
}

fn rename(stem: &str, suffix: &str) -> Rename {
    Rename {
        old: format!("{stem}{suffix}"),
        new: Some(stem.to_string()),
    }
}

fn renames(stems: &[&str], suffix: &str) -> Vec<Rename> {
    stems.iter().map(|stem| rename(stem, suffix)).collect()
}

fn deleted(stem: &str, suffix: &str) -> Rename {
    Rename {
        old: format!("{stem}{suffix}"),
        new: None,
    }
}

/// Whole-word occurrences of any of `olds` in the scanned sources, restricted
/// to paths accepted by `in_scope`. Returns `old -> ["path:line", ...]`.
fn word_hits(olds: &[&str], in_scope: impl Fn(&str) -> bool) -> BTreeMap<String, Vec<String>> {
    let wanted: HashSet<&str> = olds.iter().copied().collect();
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for source in sources().iter().filter(|s| in_scope(&s.path)) {
        for (index, line) in source.text.lines().enumerate() {
            for word in line
                .split(|ch: char| !is_ident(ch))
                .filter(|w| !w.is_empty())
            {
                if wanted.contains(word) {
                    hits.entry(word.to_string()).or_default().push(format!(
                        "{}:{}",
                        source.path,
                        index + 1
                    ));
                }
            }
        }
    }
    hits
}

/// Number of declarations of `name` with one of the `kinds` keywords, in files
/// accepted by `in_scope`.
fn declarations(name: &str, kinds: &[&str], in_scope: impl Fn(&str) -> bool) -> Vec<String> {
    let pattern = format!(
        r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:export\s+)?(?:async\s+)?(?:{})\s+{}\b",
        kinds.join("|"),
        regex::escape(name)
    );
    let re = Regex::new(&pattern).unwrap();
    sources()
        .iter()
        .filter(|s| in_scope(&s.path))
        .flat_map(|s| {
            re.find_iter(&s.text)
                .map(|m| {
                    format!(
                        "{}:{}",
                        s.path,
                        s.text[..m.start()].matches('\n').count() + 1
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

const ALL_KINDS: &[&str] = &[
    "struct",
    "enum",
    "type",
    "trait",
    "fn",
    "const",
    "static",
    "interface",
    "function",
];

fn anywhere(_: &str) -> bool {
    true
}

fn rust_production(path: &str) -> bool {
    path.ends_with(".rs") && !is_test_path(path) && !path.starts_with("examples/")
}

fn ts_source(path: &str) -> bool {
    path.starts_with("ui/decision/src/")
}

fn assert_slice(label: &str, list: &[Rename]) {
    let olds: Vec<&str> = list.iter().map(|r| r.old.as_str()).collect();
    let hits = word_hits(&olds, anywhere);
    let mut problems = Vec::new();
    for (old, locations) in &hits {
        let tests = locations.iter().filter(|l| is_test_path(l)).count();
        problems.push(format!(
            "`{old}` still present: {} production, {tests} test matches, e.g. {:?}",
            locations.len() - tests,
            &locations[..locations.len().min(3)]
        ));
    }
    for rename in list {
        if let Some(new) = &rename.new {
            if declarations(new, ALL_KINDS, anywhere).is_empty() {
                problems.push(format!(
                    "`{new}` is not declared (replaces `{}`)",
                    rename.old
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{label}: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Slices (name map of the plan). One test per slice.
// ---------------------------------------------------------------------------

#[test]
fn s1_aliases_and_schema_constants_use_canonical_names() {
    let mut list = renames(&["EffectiveDisposition", "EventEvaluationReport"], "V1");
    list.extend(renames(
        &[
            "DECISION_TASK_REQUEST_SCHEMA",
            "EVENT_EVALUATION_REPORT_SCHEMA",
            "FAILURE_BUNDLE_SCHEMA",
        ],
        "_V1",
    ));
    assert_slice("S1", &list);
}

#[test]
fn s2_activation_inputs_use_canonical_names() {
    let mut list = vec![Rename {
        old: format!("{}{}", "EvaluationSnapshot", "V1"),
        new: Some("ActivationSnapshot".to_string()),
    }];
    list.extend(renames(
        &[
            "MatchingGuardSnapshot",
            "GuardEvaluationSpec",
            "DecisionExecutionProfile",
            "ProbeEvaluationInput",
            "DecisionEvaluationInput",
            "SemanticDecisionEvidence",
        ],
        "V1",
    ));
    assert_slice("S2", &list);
}

#[test]
fn s3_result_types_use_canonical_names() {
    assert_slice(
        "S3",
        &renames(
            &[
                "GuardResult",
                "GuardResultState",
                "LeafResult",
                "LeafAttribution",
                "RuleReduction",
                "EvaluationFault",
                "EvaluationCompleteness",
                "ExpressionPathSegment",
            ],
            "V1",
        ),
    );
}

#[test]
fn s4_failure_cache_and_authorization_types_use_canonical_names() {
    assert_slice(
        "S4",
        &renames(
            &[
                "FailureCause",
                "FailureCauseKind",
                "FailureBundle",
                "FailedGuardFeedback",
                "ActivationCacheSummary",
                "CacheResolutionProvenance",
                "ExactOperationAuthorization",
            ],
            "V1",
        ),
    );
}

#[test]
fn s5_scheduler_and_task_internals_use_canonical_names() {
    assert_slice(
        "S5",
        &renames(
            &[
                "DecisionTaskRequest",
                "DecisionTaskResult",
                "DecisionTaskFault",
                "DecisionBatchResult",
                "ProviderEvaluationReceipt",
                "ProbeObservation",
                "ProbeTaskResult",
                "ProbeTaskFault",
                "LeafOccurrence",
                "ProbeOccurrence",
                "LeafOccurrenceResolution",
                "LeafEvaluationKind",
                "ExecutionPlanNode",
                "PendingDecision",
                "GuardEvaluationWork",
            ],
            "V1",
        ),
    );
}

#[test]
fn s6_dialog_contract_uses_canonical_names_in_rust_and_typescript() {
    let mut list = renames(
        &[
            "DialogRequest",
            "DialogResponse",
            "DialogViolationItem",
            "DialogAuthorizationItem",
            "PresentationKind",
        ],
        "V2",
    );
    list.extend(renames(
        &["DIALOG_REQUEST_SCHEMA", "DIALOG_RESPONSE_SCHEMA"],
        "_V2",
    ));
    list.extend(renames(
        &[
            "read_dialog_request",
            "serialize_dialog_response",
            "write_dialog_response",
            "unresolved_response",
        ],
        "_v2",
    ));
    assert_slice("S6", &list);
}

#[test]
fn s7_typescript_selector_is_removed_and_validator_is_renamed() {
    assert_slice(
        "S7",
        &[
            deleted("isDialogRequest", "V2"),
            rename("validateDialogRequest", "V2"),
        ],
    );
}

// ---------------------------------------------------------------------------
// AC-009.2: aliases and duplicate functions are gone, one type remains.
// ---------------------------------------------------------------------------

#[test]
fn ac_009_2_event_evaluation_report_is_one_type_without_alias() {
    let name = "EventEvaluationReport";
    let structs = declarations(name, &["struct"], rust_production);
    let aliases = declarations(name, &["type"], rust_production);
    assert_eq!(
        structs.len(),
        1,
        "one `struct {name}` expected: {structs:?}"
    );
    assert!(
        aliases.is_empty(),
        "`type {name}` alias remains: {aliases:?}"
    );
}

#[test]
fn ac_009_2_effective_disposition_is_one_enum_without_alias() {
    let name = "EffectiveDisposition";
    let enums = declarations(name, &["enum"], rust_production);
    let mut aliases = declarations(name, &["type"], rust_production);
    // The alias being deleted is the suffixed one (`type <name>V1 = <name>;`).
    let suffixed = format!("{name}{}", "V1");
    aliases.extend(declarations(&suffixed, &["type"], rust_production));
    assert_eq!(enums.len(), 1, "one `enum {name}` expected: {enums:?}");
    assert!(aliases.is_empty(), "alias of `{name}` remains: {aliases:?}");
}

#[test]
fn ac_009_2_unresolved_response_has_a_single_function() {
    let found = declarations("unresolved_response", &["fn"], rust_production);
    assert_eq!(found.len(), 1, "one `fn unresolved_response`: {found:?}");
    let wrapper = format!("{}{}", "unresolved_response", "_v2");
    let remaining = declarations(&wrapper, &["fn"], anywhere);
    assert!(
        remaining.is_empty(),
        "wrapper function remains: {remaining:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-009.3: activation inputs and per-guard state have two distinct names.
// ---------------------------------------------------------------------------

#[test]
fn ac_009_3_activation_snapshot_and_evaluation_snapshot_are_distinct_declarations() {
    let activation = declarations("ActivationSnapshot", &["struct"], rust_production);
    let per_guard = declarations("EvaluationSnapshot", &["enum", "struct"], rust_production);
    assert_eq!(
        activation.len(),
        1,
        "one ActivationSnapshot struct: {activation:?}"
    );
    assert_eq!(
        per_guard.len(),
        1,
        "one EvaluationSnapshot type: {per_guard:?}"
    );
    assert_ne!(
        activation[0].split(':').next(),
        per_guard[0].split(':').next(),
        "the two snapshot types must live in different modules"
    );
    let lib = exports(&repo_root().join("src/lib.rs"));
    for name in ["ActivationSnapshot", "EvaluationSnapshot"] {
        let count = lib
            .iter()
            .filter(|exported| exported.as_str() == name)
            .count();
        assert_eq!(count, 1, "`{name}` must be exported once from lib.rs");
    }
}

// ---------------------------------------------------------------------------
// AC-009.4: each public item is exported under one name only.
// ---------------------------------------------------------------------------

const EXPORT_ROOTS: &[&str] = &["src/lib.rs", "src/runtime/mod.rs", "src/decision_ui/mod.rs"];

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `(statement body, leaf names)` for each `pub use ...;` of a root file.
fn pub_use_statements(path: &Path) -> Vec<(String, Vec<String>)> {
    let text = strip_line_comments(&fs::read_to_string(path).unwrap());
    let re = Regex::new(r"(?s)\bpub\s+use\s+(.*?);").unwrap();
    re.captures_iter(&text)
        .map(|caps| {
            let body = caps[1].to_string();
            let inner = match (body.find('{'), body.rfind('}')) {
                (Some(open), Some(close)) => &body[open + 1..close],
                _ => body.as_str(),
            };
            let names = inner
                .split(',')
                .map(|item| item.trim())
                .filter(|item| !item.is_empty() && *item != "self" && *item != "*")
                .map(|item| item.rsplit("::").next().unwrap().trim().to_string())
                .collect();
            (body, names)
        })
        .collect()
}

fn exports(path: &Path) -> Vec<String> {
    pub_use_statements(path)
        .into_iter()
        .flat_map(|(_, names)| names)
        .collect()
}

#[test]
fn ac_009_4_no_pub_type_alias_of_another_named_item() {
    let rust_alias =
        Regex::new(r"(?m)^\s*pub(?:\([^)]*\))?\s+type\s+(\w+)\s*=\s*([\w:]+)\s*;").unwrap();
    let ts_alias = Regex::new(r"(?m)^\s*export\s+type\s+(\w+)\s*=\s*(\w+)\s*;").unwrap();
    let mut found = Vec::new();
    for source in sources().iter().filter(|s| !is_test_path(&s.path)) {
        let re = if source.path.ends_with(".rs") {
            &rust_alias
        } else {
            &ts_alias
        };
        for caps in re.captures_iter(&source.text) {
            found.push(format!("{}: {} = {}", source.path, &caps[1], &caps[2]));
        }
    }
    assert!(found.is_empty(), "alias declarations remain: {found:?}");
}

#[test]
fn ac_009_4_export_roots_have_no_pub_use_rename() {
    let mut renamed = Vec::new();
    for root in EXPORT_ROOTS {
        for (body, _) in pub_use_statements(&repo_root().join(root)) {
            if body.split_whitespace().any(|word| word == "as") {
                renamed.push(format!(
                    "{root}: pub use {}",
                    body.split_whitespace().collect::<Vec<_>>().join(" ")
                ));
            }
        }
    }
    assert!(renamed.is_empty(), "`pub use ... as` found: {renamed:?}");
}

#[test]
fn ac_009_4_each_export_root_lists_a_name_once() {
    let mut duplicated = Vec::new();
    for root in EXPORT_ROOTS {
        let mut count: HashMap<String, usize> = HashMap::new();
        for name in exports(&repo_root().join(root)) {
            *count.entry(name).or_default() += 1;
        }
        for (name, times) in count.into_iter().filter(|(_, times)| *times > 1) {
            duplicated.push(format!("{root}: {name} x{times}"));
        }
    }
    assert!(duplicated.is_empty(), "duplicate exports: {duplicated:?}");
}

// ---------------------------------------------------------------------------
// AC-009.6: TypeScript dialog names and the version selector.
// ---------------------------------------------------------------------------

#[test]
fn ac_009_6_typescript_dialog_names_have_zero_matches_in_ui_src() {
    let olds = [
        format!("{}{}", "DialogRequest", "V2"),
        format!("{}{}", "DialogViolationItem", "V2"),
        format!("{}{}", "DialogAuthorizationItem", "V2"),
        format!("{}{}", "isDialogRequest", "V2"),
        format!("{}{}", "validateDialogRequest", "V2"),
    ];
    let refs: Vec<&str> = olds.iter().map(String::as_str).collect();
    let hits = word_hits(&refs, ts_source);
    let summary: Vec<String> = hits
        .iter()
        .map(|(old, at)| {
            format!(
                "{old}: {} matches, e.g. {:?}",
                at.len(),
                &at[..at.len().min(3)]
            )
        })
        .collect();
    assert!(
        hits.is_empty(),
        "old TS names remain in ui/decision/src: {summary:?}"
    );
}

#[test]
fn ac_009_6_typescript_dialog_interfaces_are_declared_once_without_alias() {
    for name in [
        "DialogRequest",
        "DialogViolationItem",
        "DialogAuthorizationItem",
    ] {
        let interfaces = declarations(name, &["interface"], ts_source);
        let aliases = declarations(name, &["type"], ts_source);
        assert_eq!(
            interfaces.len(),
            1,
            "one `interface {name}` expected: {interfaces:?}"
        );
        assert!(
            aliases.is_empty(),
            "`type {name}` alias remains: {aliases:?}"
        );
    }
}

#[test]
fn ac_009_6_rendering_has_no_version_selector() {
    let mut found = Vec::new();
    for source in sources().iter().filter(|s| ts_source(&s.path)) {
        // The selector is any `isDialogRequest*` function, whatever its suffix.
        for (index, line) in source.text.lines().enumerate() {
            if line.contains("isDialogRequest") {
                found.push(format!("{}:{}", source.path, index + 1));
            }
        }
    }
    assert!(found.is_empty(), "selector references remain: {found:?}");
    let context = sources()
        .iter()
        .find(|s| s.path == "ui/decision/src/components/RequestContext.svelte")
        .expect("RequestContext.svelte exists");
    assert!(
        !context
            .text
            .split(|ch: char| !is_ident(ch))
            .any(|word| word == "schema"),
        "RequestContext.svelte must not branch on the schema version"
    );
}

// ---------------------------------------------------------------------------
// AC-009.1: contract audit lists no versioned production declaration.
// ---------------------------------------------------------------------------

#[test]
fn ac_009_1_contract_audit_lists_zero_versioned_declarations_and_bridge_is_aligned() {
    let output = std::env::temp_dir().join(format!("req009-inventory-{}.json", std::process::id()));
    let mut last_error = String::new();
    let mut ran = false;
    for python in ["python", "python3", "py"] {
        let result = Command::new(python)
            .args(["tools/audit-contracts.py", "--check-bridge", "--output"])
            .arg(&output)
            .current_dir(repo_root())
            .output();
        match result {
            Ok(done) => {
                ran = true;
                assert!(
                    done.status.success(),
                    "audit-contracts.py failed: {}",
                    String::from_utf8_lossy(&done.stderr)
                );
                break;
            }
            Err(error) => last_error = format!("{python}: {error}"),
        }
    }
    assert!(
        ran,
        "no Python interpreter could run the audit tool: {last_error}"
    );
    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(&output).expect("inventory written")).unwrap();
    let _ = fs::remove_file(&output);
    assert_eq!(inventory["bridge_errors"], serde_json::json!([]));
    let symbols: Vec<&str> = inventory["versioned_declarations"]
        .as_array()
        .expect("versioned_declarations is a list")
        .iter()
        .filter_map(|entry| entry["symbol"].as_str())
        .collect();
    assert!(
        symbols.is_empty(),
        "{} versioned declarations remain, e.g. {:?}",
        symbols.len(),
        &symbols[..symbols.len().min(5)]
    );
}

// ---------------------------------------------------------------------------
// Regression guards for AC-009.5: identifiers move, wire tokens and unrelated
// versioned names stay. These pass before and after every slice.
// ---------------------------------------------------------------------------

fn source(path: &str) -> &'static Source {
    sources()
        .iter()
        .find(|s| s.path == path)
        .unwrap_or_else(|| panic!("{path} is scanned"))
}

#[test]
fn wire_token_literals_survive_the_renames() {
    let guard_evaluation = &source("src/runtime/guard_evaluation.rs").text;
    for token in [
        "\"arc.decision_task.request.v1\"",
        "\"arc.event_evaluation.report.v1\"",
        "\"arc.failure_bundle.v1\"",
        "\"arc.decision.dialog.request.v2\"",
        "\"arc.decision.dialog.response.v2\"",
        "\"arc.evaluation_snapshot.v1\"",
        "\"arc.guard_evaluation.v1\"",
    ] {
        assert!(
            guard_evaluation.contains(token),
            "token {token} missing from guard_evaluation.rs"
        );
    }
    let contracts = &source("ui/decision/src/lib/contracts.ts").text;
    assert!(
        contracts.contains("\"arc.decision.dialog.request.v2\""),
        "contracts.ts keeps the request-schema literal"
    );
}

#[test]
fn versioned_names_outside_the_rename_are_left_alone() {
    let keep = [
        "ARC_INTERNAL_RECURSION",
        "ARC_FAILURE_BUNDLE",
        "DecisionOutput",
    ];
    let names: Vec<String> = keep
        .iter()
        .zip(["_V1", "_V1", "V1"])
        .map(|(stem, suffix)| format!("{stem}{suffix}"))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let hits = word_hits(&refs, anywhere);
    for name in &names {
        assert!(hits.contains_key(name), "`{name}` must remain untouched");
    }
}
