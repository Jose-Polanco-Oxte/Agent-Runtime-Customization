//! REQ-003 structure checks (AC-003.1, AC-003.3, AC-003.5): the unused
//! provider-feedback envelope/artifact contract, the removed user-decision summary field and
//! the alternative request/budget contracts have zero word matches (`rg -w`
//! semantics) in the product sources, the Tauri crate, the tests and the usage
//! guide. Symbol names are assembled from parts so this file never matches
//! itself.

use std::fs;
use std::path::{Path, PathBuf};

fn join(parts: &[&str]) -> String {
    parts.concat()
}

fn collect(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, extension, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            out.push(path);
        }
    }
}

fn scanned_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect(&root.join("src"), "rs", &mut files);
    collect(&root.join("ui/decision/src-tauri/src"), "rs", &mut files);
    collect(&root.join("tests"), "rs", &mut files);
    files.push(root.join("docs/USAGE.md"));
    let this = Path::new(file!()).file_name().unwrap().to_owned();
    files.retain(|path| path.file_name() != Some(this.as_os_str()));
    assert!(
        files.len() > 20,
        "scanner found too few files: {}",
        files.len()
    );
    files
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Lines (path:line) where `symbol` occurs with an identifier boundary before it
/// and, unless `prefix`, after it.
fn occurrences(symbol: &str, prefix: bool) -> Vec<String> {
    let mut hits = Vec::new();
    for path in scanned_files() {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            let bytes = line.as_bytes();
            let mut from = 0;
            while let Some(found) = line[from..].find(symbol) {
                let start = from + found;
                let end = start + symbol.len();
                let before_ok = start == 0 || !is_ident(bytes[start - 1]);
                let after_ok = prefix || end >= bytes.len() || !is_ident(bytes[end]);
                if before_ok && after_ok {
                    hits.push(format!("{}:{}", path.display(), index + 1));
                    break;
                }
                from = end;
            }
        }
    }
    hits
}

fn assert_absent(symbols: &[String], prefix: bool) {
    for symbol in symbols {
        let hits = occurrences(symbol, prefix);
        assert!(
            hits.is_empty(),
            "`{symbol}` must have zero matches, found {}: {:?}",
            hits.len(),
            &hits[..hits.len().min(5)]
        );
    }
}

#[test]
fn provider_feedback_envelope_artifact_contract_is_removed() {
    assert_absent(
        &[
            join(&["ProviderFeedback", "EnvelopeV1"]),
            join(&["ProviderFeedback", "PayloadV1"]),
            join(&["PROVIDER_FEEDBACK", "_SCHEMA_V1"]),
            join(&["redacted_for", "_provider"]),
        ],
        false,
    );
}

#[test]
fn envelope_disk_fallback_and_artifact_verification_are_removed() {
    assert_absent(
        &[
            join(&["write", "_artifact"]),
            join(&["verify", "_artifact"]),
            join(&["inline_or", "_artifact"]),
            join(&["render_for", "_provider"]),
            join(&["Artifact", "OutsideWorkspace"]),
            join(&["Artifact", "ParentUnavailable"]),
            join(&["Artifact", "Write"]),
            join(&["Artifact", "Read"]),
            join(&["Artifact", "HashMismatch"]),
            join(&["Text", "Serialization"]),
        ],
        false,
    );
}

#[test]
fn user_decision_summary_and_bundle_field_are_removed() {
    assert_absent(
        &[
            join(&["UserDecision", "SummaryV1"]),
            join(&["user", "_decision"]),
        ],
        false,
    );
}

#[test]
fn alternative_request_and_budget_contracts_are_removed() {
    assert_absent(
        &[
            join(&["GuardEvaluation", "RequestV1"]),
            join(&["GUARD_EVALUATION_REQUEST", "_SCHEMA_V1"]),
            join(&["Evaluation", "BudgetV1"]),
            join(&["Evaluation", "BudgetScheduleV1"]),
            join(&["Evaluation", "BudgetPhaseV1"]),
            join(&["Evaluation", "BudgetError"]),
            join(&["from", "_budget"]),
        ],
        false,
    );
    // The removed single-request evaluation entry point in all variants (budget and aggregate forms).
    assert_absent(&[join(&["evaluate_guard", "_request"])], true);
}

#[test]
fn the_retained_bounded_feedback_contract_still_exists() {
    // AC-003 keeps the bounded inline limit and the error variants the formatter uses.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard = fs::read_to_string(root.join("src/runtime/guard_evaluation.rs")).unwrap();
    assert!(guard.contains("MAX_PROVIDER_FEEDBACK_INLINE_BYTES"));
    for variant in ["Serialization(", "InvalidBundle(", "InlineTooLarge {"] {
        assert!(
            guard.contains(variant),
            "FailureBundleError must keep {variant}"
        );
    }
}
