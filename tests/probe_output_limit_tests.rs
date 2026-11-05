//! REQ-014: probe output over `MAX_PROBE_OUTPUT_BYTES` is a fault, never a silent
//! truncation (AC-014.1 to AC-014.3).
//!
//! The tests run real child processes through the production probe runners
//! (`WorkspaceProbeRunner`, `DefaultProbeRunner`), never `MockProbeRunner`, and
//! evaluate a guard through the engine entry of AC-004.3
//! (`evaluate_with_fixture_config`).
//!
//! Determinism. Every payload is a regular file in a private temp workspace that
//! the probe prints with `cmd /c type <file>` (Windows) or `cat <file>`. The
//! content is fixed by construction (`"ok\n"` plus spaces, so the retained
//! prefix trimmed is exactly `ok`), the size is exact, and nothing depends on
//! time or on the environment. Overflow sizes are small on purpose: `MAX + 1`,
//! `MAX + 4096` and `2 * MAX`. A large overflow can already fail without the
//! fix, because the runner drops the pipe at the cap and the child may see
//! EPIPE and exit non-zero. That race is why `MAX + 1` (smallest overflow, last
//! write can complete into the pipe buffer) is the discriminating case, and why
//! the larger sizes are asserted too: after the fix all of them must fault, in
//! the same way, on every run.

#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;
use guard_evaluation_support::evaluate_with_fixture_config;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc::ir::BoundRuleExpression;
use arc::runtime::evaluator::MAX_PROBE_OUTPUT_BYTES;
use arc::{
    ActionType, ActivationSnapshot, ArcEvent, ArcEventType, DefaultProbeRunner,
    EffectiveDisposition, EvaluationCompleteness, EvaluationFault, EventEvaluationReport,
    GuardEvaluationSpec, GuardResultState, ProbeRunner, SessionContext, WorkspaceProbeRunner,
};

const GUARD_ID: &str = "probe-limit-guard";
const EXPECTED: &str = "ok";

/// Private temp workspace, removed on drop (also when an assertion fails).
struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "arc-req014-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp workspace");
        Self { root }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.root.join(name), bytes).expect("write payload");
    }

    fn runner(&self) -> Arc<dyn ProbeRunner> {
        Arc::new(WorkspaceProbeRunner::new(&self.root))
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// `"ok\n"` followed by spaces up to exactly `len` bytes. Trimmed, it is `ok`.
fn ok_payload(len: usize) -> Vec<u8> {
    assert!(len >= 3, "payload must hold the `ok\\n` prefix");
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(b"ok\n");
    bytes.resize(len, b' ');
    assert_eq!(bytes.len(), len);
    bytes
}

fn print_file_command(file: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("cmd /c type {file}")
    } else {
        format!("cat {file}")
    }
}

fn failing_command() -> String {
    if cfg!(target_os = "windows") {
        "cmd /c exit 1".to_string()
    } else {
        "sh -c 'exit 1'".to_string()
    }
}

fn snapshot() -> ActivationSnapshot {
    ActivationSnapshot::from_event(
        "activation-req014",
        "invocation-req014",
        arc::ProviderTarget::Codex,
        &ArcEvent::lifecycle("session-1", "event-1", ArcEventType::End, 1),
        SessionContext {
            user_intent: "validate".into(),
            ..SessionContext::default()
        },
        Vec::new(),
        10_000,
    )
}

fn deny_guard(command: String, expected: &str) -> GuardEvaluationSpec {
    GuardEvaluationSpec {
        guard_id: GUARD_ID.into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("probe limit feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Probe {
            command: command.into(),
            expected_in: vec![expected.into()],
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    }
}

fn evaluate(
    runner: Arc<dyn ProbeRunner>,
    command: String,
    expected: &str,
) -> EventEvaluationReport {
    let guards = vec![deny_guard(command, expected)];
    evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), runner, None)
        .expect("a probe problem is a guard result, not a batch error")
}

/// Evaluates the payload of `len` bytes and returns the report.
fn evaluate_payload(len: usize) -> (Workspace, EventEvaluationReport) {
    let workspace = Workspace::new("payload");
    workspace.write("payload.txt", &ok_payload(len));
    let report = evaluate(
        workspace.runner(),
        print_file_command("payload.txt"),
        EXPECTED,
    );
    (workspace, report)
}

fn only_state(report: &EventEvaluationReport) -> &GuardResultState {
    assert_eq!(report.guard_results.len(), 1);
    assert_eq!(report.guard_results[0].guard_id, GUARD_ID);
    &report.guard_results[0].state
}

/// A single probe leaf faulted: the guard is `Faulted` with exactly one
/// `EvaluationFault::Probe` and no `Satisfied` anywhere.
fn assert_probe_leaf_faulted(report: &EventEvaluationReport, context: &str) {
    match only_state(report) {
        GuardResultState::Faulted { faults, .. } => {
            assert_eq!(faults.len(), 1, "{context}: one fault per probe leaf");
            assert!(
                matches!(faults[0], EvaluationFault::Probe { .. }),
                "{context}: fault must be EvaluationFault::Probe, got {:?}",
                faults[0]
            );
        }
        other => panic!(
            "{context}: probe output over the limit must be a Faulted probe leaf, got {other:?}"
        ),
    }
    assert!(
        report.guard_results[0].satisfied_attributions.is_empty(),
        "{context}: a faulted probe leaf carries no satisfied attribution"
    );
}

/// The guard-level outcome that AC-014.2 compares: state kind, completeness,
/// configured action, effective disposition and the fault variants (summary
/// text is excluded, it legitimately names a different cause).
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    guard_state_kind: &'static str,
    fault_kinds: Vec<&'static str>,
    cause_count: usize,
    completeness: EvaluationCompleteness,
    configured_action: ActionType,
    disposition: EffectiveDisposition,
}

fn outcome(report: &EventEvaluationReport) -> Outcome {
    let result = &report.guard_results[0];
    let (kind, fault_kinds, cause_count) = match &result.state {
        GuardResultState::Satisfied => ("satisfied", Vec::new(), 0),
        GuardResultState::Violated { causes } => ("violated", Vec::new(), causes.len()),
        GuardResultState::Faulted { faults, causes } => (
            "faulted",
            faults
                .iter()
                .map(|fault| match fault {
                    EvaluationFault::Probe { .. } => "probe",
                    _ => "other",
                })
                .collect(),
            causes.len(),
        ),
    };
    Outcome {
        guard_state_kind: kind,
        fault_kinds,
        cause_count,
        completeness: result.completeness,
        configured_action: result.configured_action,
        disposition: report.effective_disposition,
    }
}

// ---------------------------------------------------------------------------
// AC-014.1 / AC-014.2: overflow is a fault, never Satisfied
// ---------------------------------------------------------------------------

#[test]
fn probe_output_one_byte_over_the_limit_is_faulted_not_satisfied() {
    let (_ws, report) = evaluate_payload(MAX_PROBE_OUTPUT_BYTES + 1);
    assert!(
        !matches!(only_state(&report), GuardResultState::Satisfied),
        "silent approve: the retained prefix trims to `ok` but the output exceeded the limit"
    );
    assert_probe_leaf_faulted(&report, "MAX+1");
}

#[test]
fn probe_output_4096_bytes_over_the_limit_is_faulted_not_satisfied() {
    let (_ws, report) = evaluate_payload(MAX_PROBE_OUTPUT_BYTES + 4096);
    assert_probe_leaf_faulted(&report, "MAX+4096");
}

#[test]
fn probe_output_twice_the_limit_is_faulted_not_satisfied() {
    let (_ws, report) = evaluate_payload(2 * MAX_PROBE_OUTPUT_BYTES);
    assert_probe_leaf_faulted(&report, "2*MAX");
}

#[test]
fn probe_output_over_the_limit_with_non_whitespace_tail_is_faulted_not_satisfied() {
    // The first MAX bytes trim to `ok`; the single byte past the limit is the
    // only non-whitespace after `ok`. Dropping it changes the meaning.
    let workspace = Workspace::new("tail");
    let mut bytes = ok_payload(MAX_PROBE_OUTPUT_BYTES + 1);
    *bytes.last_mut().unwrap() = b'X';
    workspace.write("payload.txt", &bytes);
    let report = evaluate(
        workspace.runner(),
        print_file_command("payload.txt"),
        EXPECTED,
    );
    assert_probe_leaf_faulted(&report, "MAX+1 with non-whitespace last byte");
}

#[test]
fn over_the_limit_probe_yields_runtime_fault_disposition_and_incomplete_guard() {
    let (_ws, report) = evaluate_payload(MAX_PROBE_OUTPUT_BYTES + 1);
    assert_eq!(
        report.effective_disposition,
        EffectiveDisposition::RuntimeFault,
        "an over-limit probe is a RuntimeFault, not Continue and not Deny"
    );
    assert_eq!(
        report.guard_results[0].completeness,
        EvaluationCompleteness::IncompleteDueToFault
    );
}

#[test]
fn over_the_limit_outcome_equals_the_outcome_of_a_failing_probe_command() {
    let failing_ws = Workspace::new("failing");
    let failing = evaluate(failing_ws.runner(), failing_command(), EXPECTED);
    // The reference outcome is itself pinned, so the comparison cannot pass by
    // both sides being equally wrong.
    assert_probe_leaf_faulted(&failing, "failing probe command");
    assert_eq!(
        failing.effective_disposition,
        EffectiveDisposition::RuntimeFault,
        "a failing probe command yields RuntimeFault"
    );
    let reference = outcome(&failing);

    for len in [
        MAX_PROBE_OUTPUT_BYTES + 1,
        MAX_PROBE_OUTPUT_BYTES + 4096,
        2 * MAX_PROBE_OUTPUT_BYTES,
    ] {
        let (_ws, report) = evaluate_payload(len);
        assert_eq!(
            outcome(&report),
            reference,
            "payload of {len} bytes must yield the same guard outcome as a failing probe command (RuntimeFault)"
        );
        assert_eq!(
            report.effective_disposition,
            EffectiveDisposition::RuntimeFault
        );
    }
}

#[test]
fn over_the_limit_fault_is_reproducible_across_repeated_evaluations() {
    // Guards against a race-dependent outcome: the same payload must give the
    // same outcome on every run.
    for run in 0..5 {
        let (_ws, report) = evaluate_payload(MAX_PROBE_OUTPUT_BYTES + 1);
        assert_probe_leaf_faulted(&report, &format!("MAX+1 run {run}"));
        assert_eq!(
            report.effective_disposition,
            EffectiveDisposition::RuntimeFault,
            "run {run}"
        );
    }
}

#[test]
fn default_probe_runner_faults_when_output_is_over_the_limit() {
    // Same defect path through `DefaultProbeRunner`, which has no pinned cwd,
    // so the payload is addressed by absolute path.
    let workspace = Workspace::new("default-runner");
    workspace.write("payload.txt", &ok_payload(MAX_PROBE_OUTPUT_BYTES + 1));
    let absolute: &Path = &workspace.root.join("payload.txt");
    let command = print_file_command(&format!("\"{}\"", absolute.display()));
    let runner: Arc<dyn ProbeRunner> = Arc::new(DefaultProbeRunner);
    let report = evaluate(runner, command, EXPECTED);
    assert_probe_leaf_faulted(&report, "DefaultProbeRunner MAX+1");
    assert_eq!(
        report.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );
}

// ---------------------------------------------------------------------------
// AC-014.3: at the limit the output is accepted and matched
// ---------------------------------------------------------------------------

#[test]
fn probe_output_of_exactly_the_limit_is_accepted_and_matched() {
    let (_ws, report) = evaluate_payload(MAX_PROBE_OUTPUT_BYTES);
    assert!(
        matches!(only_state(&report), GuardResultState::Satisfied),
        "exactly MAX bytes must be accepted and match `ok`, got {:?}",
        only_state(&report)
    );
    assert_eq!(report.effective_disposition, EffectiveDisposition::Continue);
    assert_eq!(report.guard_results[0].satisfied_attributions.len(), 1);
}

#[test]
fn probe_output_of_exactly_the_limit_is_matched_against_expected_values_not_faulted() {
    // Same exact-limit payload, expected value that does not match: the result
    // must be a ProbeMismatch violation (output was matched), not a fault.
    let workspace = Workspace::new("limit-mismatch");
    workspace.write("payload.txt", &ok_payload(MAX_PROBE_OUTPUT_BYTES));
    let report = evaluate(
        workspace.runner(),
        print_file_command("payload.txt"),
        "not-ok",
    );
    match only_state(&report) {
        GuardResultState::Violated { causes } => {
            assert_eq!(causes.len(), 1);
            assert_eq!(causes[0].kind, arc::FailureCauseKind::ProbeMismatch);
        }
        other => panic!("exact-limit output must be matched and mismatch, got {other:?}"),
    }
    assert_eq!(
        report.effective_disposition,
        EffectiveDisposition::Deny,
        "a mismatching Deny guard denies; it must not become RuntimeFault"
    );
}

#[test]
fn probe_output_one_byte_under_the_limit_is_accepted_and_matched() {
    let (_ws, report) = evaluate_payload(MAX_PROBE_OUTPUT_BYTES - 1);
    assert!(
        matches!(only_state(&report), GuardResultState::Satisfied),
        "MAX-1 bytes must be accepted, got {:?}",
        only_state(&report)
    );
    assert_eq!(report.effective_disposition, EffectiveDisposition::Continue);
}
