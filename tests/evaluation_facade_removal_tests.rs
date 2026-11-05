//! REQ-004: the evaluation facades kept only for tests are removed.
//!
//! Structure checks (AC-004.1, AC-004.2, AC-004.4) scan the Rust sources under
//! `src/` with a small lexer that blanks comments and, where asked, drops
//! `#[cfg(test)]` items. Behavior checks (AC-004.3) exercise the shared fixture
//! helpers in `guard_evaluation_support.rs` against the remaining engine entry.

#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc::ir::{BehaviorIR, BoundLifecycleGuard, BoundRuleExpression, WorkspaceContext};
use arc::manifest::schema::{LifecycleTrigger, OnFailureConfig};
use arc::{
    ActionType, ActivationSnapshot, ArcEvent, ArcEventType, ArcRuntimeSession,
    EffectiveDisposition, GuardEvaluationBatchError, GuardEvaluationSpec, GuardResultState,
    MockProbeRunner, ProviderTarget, SessionContext,
};
use guard_evaluation_support::{
    evaluate_session_event, evaluate_with_fixture_config, fixture_decision_profile,
};

// ---------------------------------------------------------------------------
// Source scanner
// ---------------------------------------------------------------------------

struct Masked {
    /// Source with comments blanked; string contents preserved.
    code: Vec<u8>,
    /// Same length as `code`, string and char contents replaced by `x`,
    /// so braces inside literals never confuse item matching.
    skeleton: Vec<u8>,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn mask(src: &str) -> Masked {
    let b = src.as_bytes();
    let mut code = Vec::with_capacity(b.len());
    let mut skel = Vec::with_capacity(b.len());
    let mut i = 0;
    let push_both = |code: &mut Vec<u8>, skel: &mut Vec<u8>, c: u8| {
        code.push(c);
        skel.push(c);
    };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            while i < b.len() && b[i] != b'\n' {
                push_both(&mut code, &mut skel, b' ');
                i += 1;
            }
        } else if c == b'/' && next == Some(b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    push_both(&mut code, &mut skel, b' ');
                    push_both(&mut code, &mut skel, b' ');
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    push_both(&mut code, &mut skel, b' ');
                    push_both(&mut code, &mut skel, b' ');
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    let ch = if b[i] == b'\n' { b'\n' } else { b' ' };
                    push_both(&mut code, &mut skel, ch);
                    i += 1;
                }
            }
        } else if c == b'r'
            && (i == 0 || !is_ident(b[i - 1]) || b[i - 1] == b'b')
            && raw_string_hashes(b, i + 1).is_some()
        {
            let hashes = raw_string_hashes(b, i + 1).unwrap();
            // prefix: r, hashes, opening quote
            for _ in 0..(1 + hashes + 1) {
                push_both(&mut code, &mut skel, b[i]);
                i += 1;
            }
            while i < b.len() {
                if b[i] == b'"' && (0..hashes).all(|k| b.get(i + 1 + k) == Some(&b'#')) {
                    for _ in 0..(1 + hashes) {
                        push_both(&mut code, &mut skel, b[i]);
                        i += 1;
                    }
                    break;
                }
                code.push(b[i]);
                skel.push(if b[i] == b'\n' { b'\n' } else { b'x' });
                i += 1;
            }
        } else if c == b'"' {
            push_both(&mut code, &mut skel, c);
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' && i + 1 < b.len() {
                    code.push(b[i]);
                    code.push(b[i + 1]);
                    skel.push(b'x');
                    skel.push(if b[i + 1] == b'\n' { b'\n' } else { b'x' });
                    i += 2;
                } else if b[i] == b'"' {
                    push_both(&mut code, &mut skel, b'"');
                    i += 1;
                    break;
                } else {
                    code.push(b[i]);
                    skel.push(if b[i] == b'\n' { b'\n' } else { b'x' });
                    i += 1;
                }
            }
        } else if c == b'\'' {
            // Char literal ('x', '\n', '{') or lifetime ('a).
            let end = char_literal_end(b, i);
            match end {
                Some(end) => {
                    push_both(&mut code, &mut skel, b'\'');
                    for k in (i + 1)..(end - 1) {
                        code.push(b[k]);
                        skel.push(b'x');
                    }
                    push_both(&mut code, &mut skel, b'\'');
                    i = end;
                }
                None => {
                    push_both(&mut code, &mut skel, c);
                    i += 1;
                }
            }
        } else {
            push_both(&mut code, &mut skel, c);
            i += 1;
        }
    }
    Masked {
        code,
        skeleton: skel,
    }
}

fn raw_string_hashes(b: &[u8], mut j: usize) -> Option<usize> {
    let mut hashes = 0;
    while b.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    (b.get(j) == Some(&b'"')).then_some(hashes)
}

/// Returns the index just past the closing quote when `b[i]` opens a char literal.
fn char_literal_end(b: &[u8], i: usize) -> Option<usize> {
    let first = *b.get(i + 1)?;
    if first == b'\\' {
        let mut j = i + 2;
        while j < b.len() && b[j] != b'\'' && j < i + 12 {
            j += 1;
        }
        return (b.get(j) == Some(&b'\'')).then_some(j + 1);
    }
    // One UTF-8 scalar, then a closing quote.
    let width = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (b.get(i + 1 + width) == Some(&b'\'')).then_some(i + 2 + width)
}

/// Blanks every `#[cfg(test)]` item (attribute through the end of the item).
fn drop_cfg_test_items(m: &Masked) -> Vec<u8> {
    let attr = b"#[cfg(test)]";
    let mut out = m.code.clone();
    let mut i = 0;
    while i + attr.len() <= m.skeleton.len() {
        if &m.skeleton[i..i + attr.len()] != attr {
            i += 1;
            continue;
        }
        let mut j = i + attr.len();
        let mut braces = 0usize;
        let mut grouping = 0usize;
        let mut end = m.skeleton.len();
        while j < m.skeleton.len() {
            match m.skeleton[j] {
                b'(' | b'[' => grouping += 1,
                b')' | b']' => grouping = grouping.saturating_sub(1),
                b'{' => braces += 1,
                b'}' => {
                    braces = braces.saturating_sub(1);
                    if braces == 0 {
                        end = j + 1;
                        break;
                    }
                }
                b';' if braces == 0 && grouping == 0 => {
                    end = j + 1;
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        for byte in &mut out[i..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        i = end;
    }
    out
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn src_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    rust_sources(&root, &mut paths);
    assert!(
        paths.len() > 20,
        "expected the full src tree, found {} files",
        paths.len()
    );
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&p).unwrap();
            (rel, text)
        })
        .collect()
}

/// Whole-identifier occurrences of `name` in `code` (as byte offsets).
fn ident_hits(code: &[u8], name: &str) -> Vec<usize> {
    let n = name.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0;
    while i + n.len() <= code.len() {
        if &code[i..i + n.len()] == n
            && (i == 0 || !is_ident(code[i - 1]))
            && code.get(i + n.len()).is_none_or(|c| !is_ident(*c))
        {
            hits.push(i);
        }
        i += 1;
    }
    hits
}

/// Offsets where `fn <name>` is defined (comments excluded, test code included).
fn fn_definitions(code: &[u8], name: &str) -> Vec<usize> {
    ident_hits(code, name)
        .into_iter()
        .filter(|&at| {
            let before = &code[..at];
            let trimmed_len = before
                .iter()
                .rposition(|c| !c.is_ascii_whitespace())
                .map_or(0, |p| p + 1);
            let head = &before[..trimmed_len];
            head.ends_with(b"fn") && (head.len() == 2 || !is_ident(head[head.len() - 3]))
        })
        .collect()
}

fn line_of(code: &[u8], at: usize) -> usize {
    code[..at].iter().filter(|c| **c == b'\n').count() + 1
}

fn definitions_in_src(name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in src_files() {
        let m = mask(&text);
        for at in fn_definitions(&m.code, name) {
            found.push(format!("{path}:{}", line_of(&m.code, at)));
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Scanner self-checks (guard the structure tests below against false passes)
// ---------------------------------------------------------------------------

#[test]
fn scanner_drops_cfg_test_items_and_comments_but_keeps_production_literals() {
    let sample = r#"
fn prod() -> &'static str { "env-v1" }
// "runner-v1" in a comment
/* "runner-v1" /* nested */ still comment */
#[cfg(test)]
mod tests {
    const A: &str = "runner-v1";
    fn brace() -> char { '{' }
    fn text() -> &'static str { "}" }
}
fn after() -> &'static str { "kept-v1" }
"#;
    let m = mask(sample);
    let prod = String::from_utf8(drop_cfg_test_items(&m)).unwrap();
    assert!(prod.contains("\"env-v1\""), "production literal must stay");
    assert!(
        prod.contains("\"kept-v1\""),
        "item after the test module must stay"
    );
    assert!(
        !prod.contains("runner-v1"),
        "test module and comments must be blanked"
    );
}

#[test]
fn scanner_finds_fn_definitions_by_exact_name_only() {
    let sample = "pub fn evaluate_all_guards(a: u8) {}\n\
                  pub fn evaluate_all_guards_with_cache_concurrency() {}\n\
                  fn caller() { evaluate_all_guards(1); }\n\
                  // fn evaluate_all_guards in a comment\n";
    let m = mask(sample);
    assert_eq!(fn_definitions(&m.code, "evaluate_all_guards").len(), 1);
    assert_eq!(
        fn_definitions(&m.code, "evaluate_all_guards_with_cache").len(),
        0
    );
    assert_eq!(
        fn_definitions(&m.code, "evaluate_all_guards_with_cache_concurrency").len(),
        1
    );
}

// ---------------------------------------------------------------------------
// AC-004.1: no definitions of the removed entries remain in src/
// ---------------------------------------------------------------------------

#[test]
fn ac_004_1_no_fn_evaluate_all_guards_remains_in_src() {
    let found = definitions_in_src("evaluate_all_guards");
    assert!(found.is_empty(), "facade still defined at: {found:?}");
}

#[test]
fn ac_004_1_no_fn_evaluate_all_guards_with_cache_remains_in_src() {
    let found = definitions_in_src("evaluate_all_guards_with_cache");
    assert!(found.is_empty(), "facade still defined at: {found:?}");
}

#[test]
fn ac_004_1_no_fn_evaluate_event_remains_in_src() {
    let found = definitions_in_src("evaluate_event");
    assert!(
        found.is_empty(),
        "ArcRuntimeSession::evaluate_event (or a same-named helper) still defined at: {found:?}"
    );
}

#[test]
fn ac_004_1_engine_entries_stay_defined_in_src() {
    // Regression: only the facades go away; the explicit entries remain.
    assert_eq!(
        definitions_in_src("evaluate_all_guards_with_cache_concurrency").len(),
        1,
        "the engine entry must stay defined exactly once"
    );
    assert_eq!(
        definitions_in_src("evaluate_event_aggregate").len(),
        1,
        "the canonical aggregate entry must stay defined exactly once"
    );
}

// ---------------------------------------------------------------------------
// AC-004.2: fixture fingerprints appear only in test code
// ---------------------------------------------------------------------------

#[test]
fn ac_004_2_fixture_fingerprints_do_not_appear_in_non_test_src() {
    let mut hits = Vec::new();
    for (path, text) in src_files() {
        let prod = drop_cfg_test_items(&mask(&text));
        for literal in ["\"env-v1\"", "\"runner-v1\""] {
            let n = literal.as_bytes();
            for at in 0..prod.len().saturating_sub(n.len() - 1) {
                if &prod[at..at + n.len()] == n {
                    hits.push(format!("{path}:{} {literal}", line_of(&prod, at)));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "fixture fingerprints in production code: {hits:?}"
    );
}

#[test]
fn ac_004_2_real_path_fingerprints_stay_in_production_code() {
    // Regression for REQ-012: distinct production values must not be removed
    // by an over-eager cleanup (and must not be mistaken for the fixtures).
    let mut joined = String::new();
    for (_, text) in src_files() {
        joined.push_str(&String::from_utf8(drop_cfg_test_items(&mask(&text))).unwrap());
    }
    for literal in ["\"runtime-environment-v1\"", "\"probe-runner-v1\""] {
        assert!(
            joined.contains(literal),
            "production value {literal} was removed"
        );
    }
}

#[test]
fn ac_004_2_fixture_fingerprints_live_in_the_test_support_module() {
    let support = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("guard_evaluation_support.rs"),
    )
    .unwrap();
    assert!(support.contains("\"env-v1\""));
    assert!(support.contains("\"runner-v1\""));
}

// ---------------------------------------------------------------------------
// AC-004.4: the stale "legacy evaluator" phrase is gone
// ---------------------------------------------------------------------------

#[test]
fn ac_004_4_legacy_evaluator_phrase_has_zero_matches_in_src() {
    let mut hits = Vec::new();
    for (path, text) in src_files() {
        for (idx, line) in text.lines().enumerate() {
            if line.to_ascii_lowercase().contains("legacy evaluator") {
                hits.push(format!("{path}:{}", idx + 1));
            }
        }
    }
    assert!(hits.is_empty(), "stale phrase still present at: {hits:?}");
}

// ---------------------------------------------------------------------------
// AC-004.3: fixture helpers drive the remaining engine entry
// ---------------------------------------------------------------------------

fn snapshot() -> ActivationSnapshot {
    ActivationSnapshot::from_event(
        "activation-req004",
        "invocation-req004",
        ProviderTarget::Codex,
        &ArcEvent::lifecycle("session-req004", "event-req004", ArcEventType::End, 1),
        SessionContext::default(),
        Vec::new(),
        10_000,
    )
}

fn guard(id: &str, action: ActionType) -> GuardEvaluationSpec {
    GuardEvaluationSpec {
        guard_id: id.into(),
        order: 1,
        declaration_order: 1,
        action,
        configured_feedback: Some(format!("{id} feedback")),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Probe {
            command: format!("probe-{id}").into(),
            expected_in: vec!["ok".into()],
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    }
}

fn session_for(spec: &GuardEvaluationSpec, observed: &str) -> ArcRuntimeSession {
    let mut ir = BehaviorIR {
        schema: "1.0".into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: WorkspaceContext {
            workdir: ".".into(),
            instructions_path: None,
            instructions_content: None,
            roles: BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: vec![BoundLifecycleGuard {
            id: spec.guard_id.clone(),
            triggers: vec![LifecycleTrigger::End],
            require: spec.expression.clone(),
            on_failure: OnFailureConfig {
                action: spec.action,
                feedback: spec.configured_feedback.clone(),
            },
            order: spec.order,
            declaration_order: spec.declaration_order,
        }],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());
    ArcRuntimeSession::new("session-req004", ir).with_probe_runner(Arc::new(
        MockProbeRunner::new().with_output(&format!("probe-{}", spec.guard_id), observed),
    ))
}

#[test]
fn fixture_profile_is_the_generic_cli_native_read_only_profile() {
    let profile = fixture_decision_profile(ProviderTarget::Gemini);
    assert_eq!(profile.provider, ProviderTarget::Gemini);
    assert_eq!(profile.transport, "cli_native");
    assert_eq!(profile.model, None);
    assert_eq!(profile.adapter_contract_fingerprint, "contract-v1");
    assert_eq!(profile.output_schema_fingerprint, "schema-v1");
    assert_eq!(profile.sandbox_mode, "read_only");
    assert_eq!(profile.approval_policy, "never");
    profile
        .validate()
        .expect("fixture profile satisfies the contract");
}

#[test]
fn fixture_config_evaluates_a_violated_guard_through_the_engine_entry() {
    let spec = guard("g-deny", ActionType::Deny);
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-g-deny", "wrong"));
    let report = evaluate_with_fixture_config(&snapshot(), &[spec], &BTreeMap::new(), probes, None)
        .expect("batch evaluates");
    assert_eq!(report.guard_results.len(), 1);
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));
    assert_eq!(report.effective_disposition, EffectiveDisposition::Deny);
}

#[test]
fn fixture_config_rejects_duplicate_guard_ids_before_evaluation() {
    let guards = [
        guard("dup", ActionType::Deny),
        guard("dup", ActionType::Ask),
    ];
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-dup", "ok"));
    let result = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None);
    assert!(matches!(
        result,
        Err(GuardEvaluationBatchError::DuplicateGuardId { guard_id }) if guard_id == "dup"
    ));
}

#[test]
fn session_helper_denies_through_the_canonical_aggregate_entry() {
    let spec = guard("g-session-deny", ActionType::Deny);
    let mut session = session_for(&spec, "wrong");
    let event = ArcEvent::lifecycle("session-req004", "event-deny", ArcEventType::End, 1);
    let result = evaluate_session_event(&mut session, event).expect("session evaluates");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Deny);
}

#[test]
fn session_helper_continues_when_the_guard_is_satisfied() {
    let spec = guard("g-session-ok", ActionType::Deny);
    let mut session = session_for(&spec, "ok");
    let event = ArcEvent::lifecycle("session-req004", "event-ok", ArcEventType::End, 1);
    let result = evaluate_session_event(&mut session, event).expect("session evaluates");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
}
