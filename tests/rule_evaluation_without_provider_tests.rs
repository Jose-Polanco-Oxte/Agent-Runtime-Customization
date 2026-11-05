//! REQ-005: rule evaluation has a single decision path. Without a decision
//! provider, a rule that needs a decision fails with a typed configuration
//! error and never opens a UI. Symbol names of the removed second path are
//! assembled from pieces so this file itself never matches the zero-match scans.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use arc::ir::BoundRuleExpression;
use arc::{
    ActionType, ActivationEvaluationCache, ActivationSnapshot, ArcEvent, ArcEventType,
    DecisionError, DecisionExecutionProfile, DecisionProvider, DecisionVerdict,
    GuardDecisionEvidence, GuardEvaluationBatchError, GuardEvaluationSpec, MockProbeRunner,
    SessionContext, evaluate_all_guards_with_cache_concurrency,
};

const HOST_ENV: &str = "ARC_DECISION_UI_HOST";
const EMBEDDED_UI_TRANSPORT: &str = "arc_embedded_ui";
const ALIAS_TRANSPORT: &str = concat!("decision_ui", "_v2");

/// The sentinel host environment variable is process-global; tests that set it
/// are serialized through this lock.
static HOST_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Points `ARC_DECISION_UI_HOST` to a sentinel script that records any launch,
/// and restores the previous value on drop.
struct SentinelHost {
    dir: PathBuf,
    script: PathBuf,
    marker: PathBuf,
    previous: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

static SENTINEL_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl SentinelHost {
    fn install() -> Self {
        let lock = HOST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "arc-req005-sentinel-{}-{}",
            std::process::id(),
            SENTINEL_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).expect("create sentinel dir");
        let marker = dir.join("launched.marker");
        let script = write_sentinel_script(&dir, &marker);
        let previous = std::env::var_os(HOST_ENV);
        // SAFETY: access to the variable is serialized by HOST_ENV_LOCK.
        unsafe { std::env::set_var(HOST_ENV, &script) };
        Self {
            dir,
            script,
            marker,
            previous,
            _lock: lock,
        }
    }

    fn launched(&self) -> bool {
        self.marker.exists()
    }
}

impl Drop for SentinelHost {
    fn drop(&mut self) {
        // SAFETY: access to the variable is serialized by HOST_ENV_LOCK, still held here.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(HOST_ENV, value),
                None => std::env::remove_var(HOST_ENV),
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(windows)]
fn write_sentinel_script(dir: &Path, marker: &Path) -> PathBuf {
    let script = dir.join("sentinel-host.cmd");
    fs::write(
        &script,
        format!("@echo off\r\necho launched> \"{}\"\r\n", marker.display()),
    )
    .expect("write sentinel script");
    script
}

#[cfg(unix)]
fn write_sentinel_script(dir: &Path, marker: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("sentinel-host.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\necho launched > '{}'\n", marker.display()),
    )
    .expect("write sentinel script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod sentinel");
    script
}

struct CountingProvider {
    calls: AtomicUsize,
}

impl DecisionProvider for CountingProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&arc::CurrentOperation>,
        _evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(DecisionVerdict::deny("provider finding"))
    }
}

fn snapshot() -> ActivationSnapshot {
    ActivationSnapshot::from_event(
        "activation-req005",
        "invocation-req005",
        arc::ProviderTarget::Codex,
        &ArcEvent::lifecycle("session-req005", "event-req005", ArcEventType::End, 1),
        SessionContext {
            user_intent: "validate".into(),
            ..SessionContext::default()
        },
        Vec::new(),
        i64::MAX,
    )
}

fn profile(transport: &str) -> DecisionExecutionProfile {
    DecisionExecutionProfile {
        provider: arc::ProviderTarget::Codex,
        transport: transport.into(),
        model: None,
        adapter_contract_fingerprint: "adapter-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    }
}

fn guard(id: &str, expression: BoundRuleExpression) -> GuardEvaluationSpec {
    GuardEvaluationSpec {
        guard_id: id.into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: None,
        scope: "lifecycle:end".into(),
        expression,
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    }
}

fn decide(prompt: &str) -> BoundRuleExpression {
    BoundRuleExpression::Decide {
        prompt: prompt.into(),
    }
}

fn evaluate(
    guards: &[GuardEvaluationSpec],
    transport: &str,
    provider: Option<Arc<dyn DecisionProvider>>,
) -> Result<arc::EventEvaluationReport, GuardEvaluationBatchError> {
    evaluate_with_runner(guards, transport, provider, MockProbeRunner::new())
}

fn evaluate_with_runner(
    guards: &[GuardEvaluationSpec],
    transport: &str,
    provider: Option<Arc<dyn DecisionProvider>>,
    runner: MockProbeRunner,
) -> Result<arc::EventEvaluationReport, GuardEvaluationBatchError> {
    let cache = ActivationEvaluationCache::new("activation-req005");
    let result = evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        guards,
        &BTreeMap::new(),
        Path::new("."),
        "env-v1",
        "runner-v1",
        &profile(transport),
        &cache,
        Arc::new(runner),
        provider,
        4,
    );
    cache.close();
    result
}

fn expect_missing_provider(
    result: Result<arc::EventEvaluationReport, GuardEvaluationBatchError>,
    transport: &str,
) {
    let error = match result {
        Ok(_) => panic!(
            "a decide rule without a provider on transport '{transport}' must return an error, \
             not a report"
        ),
        Err(error) => error,
    };
    let debug = format!("{error:?}");
    assert!(
        debug.starts_with("MissingDecisionProvider"),
        "expected variant MissingDecisionProvider, got: {debug}"
    );
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("provider"),
        "message must name the missing provider: {message}"
    );
    if !transport.is_empty() {
        assert!(
            debug.contains(transport) && message.contains(&transport.to_lowercase()),
            "error must carry and name transport '{transport}': {debug} / {message}"
        );
    }
}

#[test]
fn sentinel_host_records_a_launch_so_the_no_ui_assertions_are_not_vacuous() {
    let sentinel = SentinelHost::install();
    assert!(!sentinel.launched());
    let status = std::process::Command::new(&sentinel.script)
        .status()
        .expect("sentinel script is executable");
    assert!(status.success());
    assert!(sentinel.launched());
}

#[test]
fn decide_rule_without_provider_on_embedded_ui_transport_returns_typed_error_and_opens_no_ui() {
    let sentinel = SentinelHost::install();
    let result = evaluate(
        &[guard("g1", decide("needs a decision"))],
        EMBEDDED_UI_TRANSPORT,
        None,
    );
    let launched = sentinel.launched();
    expect_missing_provider(result, EMBEDDED_UI_TRANSPORT);
    assert!(
        !launched,
        "no UI host process may be launched during rule evaluation"
    );
}

#[test]
fn decide_rule_without_provider_on_removed_alias_transport_returns_typed_error_and_opens_no_ui() {
    let sentinel = SentinelHost::install();
    let result = evaluate(
        &[guard("g1", decide("needs a decision"))],
        ALIAS_TRANSPORT,
        None,
    );
    let launched = sentinel.launched();
    expect_missing_provider(result, ALIAS_TRANSPORT);
    assert!(!launched, "the removed alias must not reach a UI host");
}

#[test]
fn decide_rule_without_provider_returns_same_typed_error_for_non_ui_transports() {
    let sentinel = SentinelHost::install();
    for transport in ["fixture", "codex_app_server", "cli_native", ""] {
        let result = evaluate(&[guard("g1", decide("needs a decision"))], transport, None);
        expect_missing_provider(result, transport);
    }
    assert!(!sentinel.launched());
}

#[test]
fn decide_nested_with_probe_and_without_provider_fails_the_whole_batch() {
    let sentinel = SentinelHost::install();
    let guards = [
        guard(
            "probe-only",
            BoundRuleExpression::Probe {
                command: "echo ok".into(),
                expected_in: vec!["ok".into()],
            },
        ),
        guard(
            "nested",
            BoundRuleExpression::All(vec![
                BoundRuleExpression::Probe {
                    command: "echo ok".into(),
                    expected_in: vec!["ok".into()],
                },
                decide("nested decision"),
            ]),
        ),
    ];
    // The probe must succeed so the lazy All reaches the Decide leaf.
    let runner = MockProbeRunner::new().with_output("echo ok", "ok");
    let result = evaluate_with_runner(&guards, EMBEDDED_UI_TRANSPORT, None, runner);
    let launched = sentinel.launched();
    expect_missing_provider(result, EMBEDDED_UI_TRANSPORT);
    assert!(!launched);
}

#[test]
fn rules_without_decide_leaves_still_evaluate_without_provider_on_embedded_ui_transport() {
    let guards = [guard(
        "probe-only",
        BoundRuleExpression::Probe {
            command: "echo ok".into(),
            expected_in: vec!["ok".into()],
        },
    )];
    let report = evaluate(&guards, EMBEDDED_UI_TRANSPORT, None)
        .expect("no decide leaf means no provider is needed");
    assert_eq!(report.guard_results.len(), 1);
    assert_eq!(
        report.activation_cache_summary.unique_decision_evaluations,
        0
    );
}

#[test]
fn decide_rule_with_provider_on_embedded_ui_transport_uses_provider_and_opens_no_ui() {
    let sentinel = SentinelHost::install();
    let provider = Arc::new(CountingProvider {
        calls: AtomicUsize::new(0),
    });
    let report = evaluate(
        &[guard("g1", decide("needs a decision"))],
        EMBEDDED_UI_TRANSPORT,
        Some(provider.clone()),
    )
    .expect("provider-backed evaluation completes");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.guard_results.len(), 1);
    assert!(matches!(
        report.guard_results[0].state,
        arc::GuardResultState::Violated { .. }
    ));
    assert!(!sentinel.launched());
}

// AC-005.1 / AC-005.3: zero matches of the removed symbols over the grep scope.

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "node_modules" | "target" | "dist" | ".git") {
                continue;
            }
            collect_files(&path, out);
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "ts" | "tsx" | "js" | "svelte" | "json" | "html")
        ) {
            out.push(path);
        }
    }
}

fn word_matches(symbol: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scope = [
        "src",
        "tests",
        "examples",
        "ui/decision/src",
        "ui/decision/src-tauri/src",
        "ui/decision/webdriver",
    ];
    let pattern = regex::Regex::new(&format!(r"\b{}\b", regex::escape(symbol))).expect("regex");
    let mut files = Vec::new();
    for directory in scope {
        collect_files(&root.join(directory), &mut files);
    }
    let mut hits = Vec::new();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if pattern.is_match(line) {
                hits.push(format!("{}:{}", file.display(), index + 1));
            }
        }
    }
    hits
}

#[test]
fn decision_ui_executor_and_transport_alias_have_zero_matches() {
    let executor = word_matches(concat!("DecisionUi", "Executor"));
    let alias = word_matches(ALIAS_TRANSPORT);
    assert!(executor.is_empty(), "executor still present: {executor:?}");
    assert!(alias.is_empty(), "alias still present: {alias:?}");
}

#[test]
fn unavailable_executor_and_decision_ui_host_have_zero_matches() {
    let unavailable = word_matches(concat!("UnavailableDecision", "Executor"));
    let host = word_matches(concat!("DecisionUi", "Host"));
    assert!(
        unavailable.is_empty(),
        "unavailable executor still present: {unavailable:?}"
    );
    assert!(host.is_empty(), "empty host type still present: {host:?}");
}

#[test]
fn spawn_v2_has_zero_matches_and_request_embedded_decision_remains_the_presenter_entry() {
    let spawn = word_matches(concat!("spawn_", "v2"));
    assert!(spawn.is_empty(), "spawn entry still present: {spawn:?}");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let exports = fs::read_to_string(root.join("src/decision_ui/mod.rs")).expect("mod.rs");
    let pattern = regex::Regex::new(r"\brequest_embedded_decision\b").unwrap();
    assert!(
        pattern.is_match(&exports),
        "decision_ui must keep exporting request_embedded_decision"
    );
    let orchestrator = fs::read_to_string(root.join("src/runtime/decision/orchestrator.rs"))
        .expect("orchestrator");
    assert!(
        pattern.is_match(&orchestrator),
        "the orchestrator presenter must keep calling request_embedded_decision"
    );
}
