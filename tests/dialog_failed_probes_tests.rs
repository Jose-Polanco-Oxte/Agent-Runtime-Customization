//! REQ-001: the decision dialog names every probe that caused a guard failure.
//!
//! Every test starts from a real evaluation (`evaluate_guard_with_observability`),
//! goes through `interactive_decision_request_from_evaluation_result` and
//! `InteractiveDecisionRequest::to_dialog_request`, and checks the
//! `failed_probes` list of each `DialogViolationItem`. The lifecycle End path
//! is in `lifecycle_stop_tests.rs`; the wire contract is in
//! `dialog_contract_fixture_tests.rs` and `decision_ui_v2_protocol_tests.rs`.
//!
//! Expected wire shape (plan Q3): `failed_probes: Vec<DialogFailedProbe>` with
//! `rule_name: Option<String>`, `command: String`, `reason: Option<String>`.
//!
//! Red phase: this crate does not compile until `DialogViolationItem` has the
//! `failed_probes` field (compile error). The fault-path tests (AC-001.5)
//! assert today's fail-closed behavior and pass once the crate compiles,
//! with or without the implementation.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

use arc::ir::{BehaviorIR, BoundMatcher, BoundRuleExpression, BoundToolGuard, WorkspaceContext};
use arc::manifest::schema::OnFailureConfig;
use arc::runtime::evaluator::MAX_PROBE_OUTPUT_BYTES;
use arc::runtime::guard_evaluation::{MAX_DIALOG_FAILED_PROBES, MAX_ID_CHARS};
use arc::{
    ActionType, ArcEvaluationResult, ArcEvent, ArcEventType, ArcRuntimeSession, DecisionVerdict,
    DialogRequest, DialogViolationItem, EffectiveDisposition, InteractiveDecisionRequest,
    MockDecisionProvider, MockProbeRunner, PresentationKind, ProviderTarget,
};

const PUSH: &str = "git push";
const NEGATED: &str = "negated expression evaluated to true";
const GENERIC_ERROR: &str = "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.";

/// (rule_name, command, reason), the three fields AC-001.1 and AC-001.4 name.
type Listed = (Option<String>, String, Option<String>);

fn listed(rule: Option<&str>, command: &str, reason: Option<&str>) -> Listed {
    (
        rule.map(str::to_owned),
        command.to_owned(),
        reason.map(str::to_owned),
    )
}

/// The probes of one dialog item, sorted: the order is not part of the contract.
fn probes_of(item: &DialogViolationItem) -> Vec<Listed> {
    let mut probes: Vec<Listed> = item
        .failed_probes
        .iter()
        .map(|probe| {
            (
                probe.rule_name.clone(),
                probe.command.clone(),
                probe.reason.clone(),
            )
        })
        .collect();
    probes.sort();
    probes
}

fn sorted(mut probes: Vec<Listed>) -> Vec<Listed> {
    probes.sort();
    probes
}

fn probe(command: &str, expected: &str) -> BoundRuleExpression {
    BoundRuleExpression::Probe {
        command: command.into(),
        expected_in: vec![expected.into()],
    }
}

fn rule(name: &str) -> BoundRuleExpression {
    BoundRuleExpression::RuleRef { name: name.into() }
}

fn decide(prompt: &str) -> BoundRuleExpression {
    BoundRuleExpression::Decide {
        prompt: prompt.into(),
    }
}

fn not(inner: BoundRuleExpression) -> BoundRuleExpression {
    BoundRuleExpression::Not(Box::new(inner))
}

fn guard(id: &str, order: u32, action: ActionType, require: BoundRuleExpression) -> BoundToolGuard {
    BoundToolGuard {
        id: id.into(),
        matcher: BoundMatcher {
            exact_patterns: vec![PUSH.into()],
            regex_patterns: Vec::new(),
        },
        require,
        on_failure: OnFailureConfig {
            action,
            feedback: Some(format!("{id} feedback")),
        },
        order,
        declaration_order: order as usize,
    }
}

fn ask(id: &str, order: u32, require: BoundRuleExpression) -> BoundToolGuard {
    guard(id, order, ActionType::Ask, require)
}

fn evaluate(
    guards: Vec<BoundToolGuard>,
    rules: Vec<(&str, BoundRuleExpression)>,
    probes: MockProbeRunner,
    decisions: MockDecisionProvider,
) -> (ArcEvaluationResult, ArcEvent) {
    let ir = BehaviorIR {
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
        lifecycle_guards: Vec::new(),
        tool_guards: guards,
        rules: rules
            .into_iter()
            .map(|(name, expression)| (name.to_owned(), expression))
            .collect(),
    };
    // An anchored session projects the configured feedback into the failure bundle.
    let anchor = arc::SqliteStateStore::open_in_memory()
        .unwrap()
        .trust_and_anchor_ir(std::path::Path::new("canonical/ir.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("probe-dialog", ir)
        .with_probe_runner(Arc::new(probes))
        .with_decision_provider(Arc::new(decisions))
        .with_state_store(Arc::new(arc::InMemoryStateStore::default()))
        .with_trusted_anchor(anchor)
        .unwrap();
    let observed = arc::HookObservationContext::new("codex", "probe-dialog", "inv-probe")
        .with_workspace("ws-probe")
        .with_turn("turn-probe");
    let event = ArcEvent::tool_call("probe-dialog", "ev-probe", 1, "bash", PUSH);
    let result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("the evaluation itself succeeds");
    (result, event)
}

fn evaluate_probes(
    guards: Vec<BoundToolGuard>,
    rules: Vec<(&str, BoundRuleExpression)>,
    probes: MockProbeRunner,
) -> (ArcEvaluationResult, ArcEvent) {
    evaluate(guards, rules, probes, MockDecisionProvider::new())
}

fn try_interactive(
    result: &ArcEvaluationResult,
    event: &ArcEvent,
) -> Option<InteractiveDecisionRequest> {
    arc::interactive_decision_request_from_evaluation_result(
        result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-probe",
        Some(arc::CurrentOperation::from(event)),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("building the request does not fail")
}

fn interactive(result: &ArcEvaluationResult, event: &ArcEvent) -> InteractiveDecisionRequest {
    try_interactive(result, event).expect("an Ask evaluation reaches the dialog")
}

/// The dialog the host receives. Also proves the item survives the stdin boundary.
fn dialog(result: &ArcEvaluationResult, event: &ArcEvent) -> DialogRequest {
    let dialog = interactive(result, event).to_dialog_request("Decision required");
    dialog.validate().expect("the dialog request is valid");
    let bytes = serde_json::to_vec(&dialog).expect("dialog serializes");
    let decoded = arc::decision_ui::read_dialog_request(Cursor::new(bytes))
        .expect("the host stdin reader accepts the dialog");
    assert_eq!(decoded, dialog);
    dialog
}

fn violation<'a>(dialog: &'a DialogRequest, guard_id: &str) -> &'a DialogViolationItem {
    dialog
        .violations
        .iter()
        .find(|item| item.guard_id == guard_id)
        .unwrap_or_else(|| panic!("guard '{guard_id}' is not in the dialog"))
}

fn runner(entries: &[(&str, &str)]) -> MockProbeRunner {
    entries
        .iter()
        .fold(MockProbeRunner::new(), |runner, (command, output)| {
            runner.with_output(*command, *output)
        })
}

// ---------------------------------------------------------------------------
// AC-001.1: a probe that did not match is shown under its guard
// ---------------------------------------------------------------------------

#[test]
fn a_probe_from_a_reusable_rule_is_listed_with_the_rule_name_and_the_command() {
    let (result, event) = evaluate_probes(
        vec![ask("g-rule", 1, rule("tests-green"))],
        vec![("tests-green", probe("cargo test", "ok"))],
        runner(&[("cargo test", "failed")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(dialog.presentation_kind, PresentationKind::GuardFailures);
    let item = violation(&dialog, "g-rule");
    assert_eq!(
        probes_of(item),
        vec![listed(Some("tests-green"), "cargo test", None)]
    );
    // The rest of the item is what it is today.
    assert_eq!(item.configured_feedback.as_deref(), Some("g-rule feedback"));
    assert_eq!(item.auditor_findings, None);
    assert_eq!(item.scope, "this exact tool call once");
}

#[test]
fn a_probe_reached_through_nested_rules_names_the_innermost_rule() {
    let (result, event) = evaluate_probes(
        vec![ask("g-nested", 1, rule("outer"))],
        vec![
            ("outer", rule("middle")),
            ("middle", rule("inner")),
            ("inner", probe("deep-check", "ok")),
        ],
        runner(&[("deep-check", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-nested")),
        vec![listed(Some("inner"), "deep-check", None)]
    );
}

#[test]
fn an_inline_probe_inside_a_rule_body_names_that_rule_and_a_nested_rule_probe_names_its_own() {
    let (result, event) = evaluate_probes(
        vec![ask("g-mixed", 1, rule("wrapper"))],
        vec![
            (
                "wrapper",
                BoundRuleExpression::Any(vec![probe("inline-in-wrapper", "ok"), rule("leaf-rule")]),
            ),
            ("leaf-rule", probe("leaf-check", "ok")),
        ],
        runner(&[("inline-in-wrapper", "bad"), ("leaf-check", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-mixed")),
        sorted(vec![
            listed(Some("wrapper"), "inline-in-wrapper", None),
            listed(Some("leaf-rule"), "leaf-check", None),
        ])
    );
}

// ---------------------------------------------------------------------------
// AC-001.2: an inline probe shows the command alone
// ---------------------------------------------------------------------------

#[test]
fn an_inline_probe_is_listed_with_its_command_and_no_rule_name() {
    let (result, event) = evaluate_probes(
        vec![ask("g-inline", 1, probe("git status --porcelain", "clean"))],
        Vec::new(),
        runner(&[("git status --porcelain", "M src/lib.rs")]),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-inline");
    assert_eq!(item.failed_probes.len(), 1);
    assert_eq!(item.failed_probes[0].rule_name, None);
    assert_eq!(item.failed_probes[0].command, "git status --porcelain");
    assert_eq!(item.failed_probes[0].reason, None);
}

#[test]
fn a_command_with_shell_syntax_and_angle_brackets_is_shown_exactly() {
    // Shell syntax that is not markup. A command with a tag-like `<name>` is
    // refused by the report validation before any dialog exists.
    let command = "sort < input.txt 2>/dev/null | head -n 1 && echo \"a > b\"";
    let (result, event) = evaluate_probes(
        vec![ask("g-shell", 1, probe(command, "0"))],
        Vec::new(),
        runner(&[(command, "3")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-shell")),
        vec![listed(None, command, None)]
    );
}

// ---------------------------------------------------------------------------
// AC-001.3: several probes, several guards
// ---------------------------------------------------------------------------

#[test]
fn every_failed_probe_of_a_guard_is_listed_and_a_satisfied_probe_is_not() {
    // `any` evaluates every branch when none matches, so all three are causes.
    // `all` first: its satisfied probe is evidence of success, never a failure.
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-several",
            1,
            BoundRuleExpression::All(vec![
                probe("check-ok", "ok"),
                BoundRuleExpression::Any(vec![
                    probe("check-a", "ok"),
                    probe("check-b", "ok"),
                    rule("check-c-rule"),
                ]),
            ]),
        )],
        vec![("check-c-rule", probe("check-c", "ok"))],
        runner(&[
            ("check-ok", "ok"),
            ("check-a", "bad"),
            ("check-b", "bad"),
            ("check-c", "bad"),
        ]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-several")),
        sorted(vec![
            listed(None, "check-a", None),
            listed(None, "check-b", None),
            listed(Some("check-c-rule"), "check-c", None),
        ])
    );
}

#[test]
fn under_all_the_probes_after_the_first_mismatch_are_skipped_and_are_not_listed() {
    // `all` stops at the first mismatch; a probe that never ran caused nothing.
    let probes = runner(&[("run-first", "bad"), ("never-run", "bad")]);
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-short-circuit",
            1,
            BoundRuleExpression::All(vec![probe("run-first", "ok"), probe("never-run", "ok")]),
        )],
        Vec::new(),
        probes,
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-short-circuit")),
        vec![listed(None, "run-first", None)]
    );
}

#[test]
fn an_any_expression_with_every_branch_failed_lists_every_branch() {
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-any",
            1,
            BoundRuleExpression::Any(vec![probe("branch-1", "ok"), probe("branch-2", "ok")]),
        )],
        Vec::new(),
        runner(&[("branch-1", "bad"), ("branch-2", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-any")),
        sorted(vec![
            listed(None, "branch-1", None),
            listed(None, "branch-2", None)
        ])
    );
}

#[test]
fn each_guard_lists_only_its_own_probes_and_guards_without_probes_have_none() {
    let (result, event) = evaluate(
        vec![
            ask("g-one", 1, probe("only-for-one", "ok")),
            ask(
                "g-two",
                2,
                BoundRuleExpression::Any(vec![probe("two-a", "ok"), rule("two-rule")]),
            ),
            ask("g-decide", 3, decide("Is the change safe?")),
            guard("g-satisfied", 4, ActionType::Ask, probe("fine", "ok")),
        ],
        vec![("two-rule", probe("two-b", "ok"))],
        runner(&[
            ("only-for-one", "bad"),
            ("two-a", "bad"),
            ("two-b", "bad"),
            ("fine", "ok"),
        ]),
        MockDecisionProvider::new().with_decision("Is the change safe?", false),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(dialog.violations.len(), 3, "the satisfied guard is absent");
    assert_eq!(
        probes_of(violation(&dialog, "g-one")),
        vec![listed(None, "only-for-one", None)]
    );
    assert_eq!(
        probes_of(violation(&dialog, "g-two")),
        sorted(vec![
            listed(None, "two-a", None),
            listed(Some("two-rule"), "two-b", None)
        ])
    );
    assert!(violation(&dialog, "g-decide").failed_probes.is_empty());
}

#[test]
fn a_probe_shared_by_two_guards_is_listed_under_each_of_them() {
    let (result, event) = evaluate_probes(
        vec![
            ask("g-first", 1, rule("shared")),
            ask(
                "g-second",
                2,
                BoundRuleExpression::Any(vec![rule("shared"), probe("second-only", "ok")]),
            ),
        ],
        vec![("shared", probe("shared-check", "ok"))],
        runner(&[("shared-check", "bad"), ("second-only", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-first")),
        vec![listed(Some("shared"), "shared-check", None)]
    );
    assert_eq!(
        probes_of(violation(&dialog, "g-second")),
        sorted(vec![
            listed(Some("shared"), "shared-check", None),
            listed(None, "second-only", None),
        ])
    );
}

#[test]
fn the_same_rule_referenced_twice_in_a_guard_gives_one_entry_per_cause() {
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-twice",
            1,
            BoundRuleExpression::Any(vec![rule("repeat"), rule("repeat")]),
        )],
        vec![("repeat", probe("repeat-check", "ok"))],
        runner(&[("repeat-check", "bad")]),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-twice");
    assert_eq!(item.failed_probes.len(), 2);
    assert_eq!(
        probes_of(item),
        vec![
            listed(Some("repeat"), "repeat-check", None),
            listed(Some("repeat"), "repeat-check", None)
        ]
    );
}

#[test]
fn a_guard_with_exactly_the_limit_of_failed_probes_lists_all_of_them() {
    assert_eq!(MAX_DIALOG_FAILED_PROBES, 64);
    let (result, event, commands) = many_failing_probes("at-limit", MAX_DIALOG_FAILED_PROBES);
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-many");
    assert_eq!(item.failed_probes.len(), MAX_DIALOG_FAILED_PROBES);
    assert_eq!(
        probes_of(item),
        sorted(commands.iter().map(|c| listed(None, c, None)).collect())
    );
}

#[test]
fn a_guard_with_more_failed_probes_than_the_limit_is_cut_at_the_limit_and_the_dialog_stays_valid() {
    let (result, event, commands) = many_failing_probes("over-limit", MAX_DIALOG_FAILED_PROBES + 6);
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-many");
    assert_eq!(item.failed_probes.len(), MAX_DIALOG_FAILED_PROBES);
    // What is kept is a subset of what failed, with no invented entry.
    for kept in probes_of(item) {
        assert!(commands.contains(&kept.1), "unexpected command {kept:?}");
        assert_eq!(kept.0, None);
    }
}

fn many_failing_probes(prefix: &str, count: usize) -> (ArcEvaluationResult, ArcEvent, Vec<String>) {
    let commands: Vec<String> = (0..count)
        .map(|index| format!("{prefix}-{index:03}"))
        .collect();
    let probes = commands
        .iter()
        .fold(MockProbeRunner::new(), |runner, command| {
            runner.with_output(command.as_str(), "bad")
        });
    let expression = BoundRuleExpression::Any(commands.iter().map(|c| probe(c, "ok")).collect());
    let (result, event) = evaluate_probes(vec![ask("g-many", 1, expression)], Vec::new(), probes);
    (result, event, commands)
}

#[test]
fn an_over_long_command_is_shown_cut_at_the_id_limit_and_the_dialog_stays_valid() {
    let command = format!("check-{}", "x".repeat(300));
    let (result, event) = evaluate_probes(
        vec![ask("g-long-command", 1, probe(&command, "ok"))],
        Vec::new(),
        runner(&[(command.as_str(), "bad")]),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-long-command");
    assert_eq!(item.failed_probes.len(), 1);
    let shown = &item.failed_probes[0].command;
    assert_eq!(shown.chars().count(), MAX_ID_CHARS);
    assert!(command.starts_with(shown.as_str()));
}

#[test]
fn a_long_rule_name_is_shown_whole_and_the_dialog_stays_valid() {
    // The evaluation itself refuses a rule path longer than 256 characters, so a
    // name past the dialog limit cannot reach the dialog; the longest that can
    // is shown without cutting.
    let rule_name = format!("rule-{}", "r".repeat(240));
    let (result, event) = evaluate_probes(
        vec![ask("g-long-rule", 1, rule(&rule_name))],
        vec![(rule_name.as_str(), probe("long-rule-check", "ok"))],
        runner(&[("long-rule-check", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-long-rule")),
        vec![listed(Some(&rule_name), "long-rule-check", None)]
    );
}

#[test]
fn the_aggregate_dialog_lists_failed_probes_of_its_violations_and_none_for_authorizations() {
    let (result, event) = evaluate(
        vec![
            ask("g-ask", 1, rule("branch-is-feature")),
            guard("g-auth", 2, ActionType::Deny, decide("Audit git push")),
        ],
        vec![("branch-is-feature", probe("git branch", "feature"))],
        runner(&[("git branch", "main")]),
        MockDecisionProvider::new().with_verdict(
            "Audit git push",
            DecisionVerdict {
                decision: true,
                findings: Some("No policy conflict.".into()),
            },
        ),
    );
    assert_eq!(result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(result.authorization_requirements.len(), 1);
    let dialog = dialog(&result, &event);

    assert_eq!(
        dialog.presentation_kind,
        PresentationKind::AggregateDecision
    );
    assert_eq!(dialog.violations.len(), 1);
    assert_eq!(
        probes_of(violation(&dialog, "g-ask")),
        vec![listed(Some("branch-is-feature"), "git branch", None)]
    );
    assert_eq!(dialog.authorizations.len(), 1);
    assert_eq!(dialog.authorizations[0].guard_id, "g-auth");
    let wire = serde_json::to_value(&dialog.authorizations[0]).unwrap();
    assert!(wire.get("failed_probes").is_none(), "{wire}");
}

// ---------------------------------------------------------------------------
// AC-001.4: a probe that fails through `not`
// ---------------------------------------------------------------------------

#[test]
fn a_probe_negated_by_not_is_listed_with_the_negated_expression_reason() {
    let (result, event) = evaluate_probes(
        vec![ask("g-not", 1, not(probe("git diff --quiet", "dirty")))],
        Vec::new(),
        runner(&[("git diff --quiet", "dirty")]),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-not");
    assert_eq!(
        probes_of(item),
        vec![listed(None, "git diff --quiet", Some(NEGATED))]
    );
    // The reason is the fixed sentence, not the internal cause summary.
    let reason = item.failed_probes[0].reason.as_deref().unwrap();
    assert!(!reason.contains("matched expected value"), "{reason}");
}

#[test]
fn a_negated_rule_reference_names_the_rule_and_gives_the_negated_expression_reason() {
    let (result, event) = evaluate_probes(
        vec![ask("g-not-rule", 1, not(rule("work-in-progress")))],
        vec![("work-in-progress", probe("cat .wip", "yes"))],
        runner(&[("cat .wip", "yes")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-not-rule")),
        vec![listed(Some("work-in-progress"), "cat .wip", Some(NEGATED))]
    );
}

#[test]
fn a_not_over_several_true_probes_lists_each_of_them_with_the_negated_expression_reason() {
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-not-several",
            1,
            not(BoundRuleExpression::All(vec![
                probe("flag-a", "on"),
                rule("flag-b-rule"),
            ])),
        )],
        vec![("flag-b-rule", probe("flag-b", "on"))],
        runner(&[("flag-a", "on"), ("flag-b", "on")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-not-several")),
        sorted(vec![
            listed(None, "flag-a", Some(NEGATED)),
            listed(Some("flag-b-rule"), "flag-b", Some(NEGATED)),
        ])
    );
}

#[test]
fn a_not_over_a_probe_and_a_decide_lists_only_the_probe() {
    let (result, event) = evaluate(
        vec![ask(
            "g-not-all",
            1,
            not(BoundRuleExpression::All(vec![
                probe("ready-check", "ready"),
                decide("Is it done?"),
            ])),
        )],
        Vec::new(),
        runner(&[("ready-check", "ready")]),
        MockDecisionProvider::new().with_decision("Is it done?", true),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-not-all")),
        vec![listed(None, "ready-check", Some(NEGATED))]
    );
}

#[test]
fn a_not_over_an_empty_all_has_no_probe_to_name_but_the_guard_still_reaches_the_dialog() {
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-not-empty",
            1,
            not(BoundRuleExpression::All(Vec::new())),
        )],
        Vec::new(),
        MockProbeRunner::new(),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-not-empty");
    assert!(item.failed_probes.is_empty());
    assert_eq!(
        item.configured_feedback.as_deref(),
        Some("g-not-empty feedback")
    );
}

#[test]
fn a_probe_that_mismatches_under_a_double_negation_is_listed_with_the_negated_expression_reason() {
    let (result, event) = evaluate_probes(
        vec![ask("g-not-not", 1, not(not(probe("double-check", "ok"))))],
        Vec::new(),
        runner(&[("double-check", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        probes_of(violation(&dialog, "g-not-not")),
        vec![listed(None, "double-check", Some(NEGATED))]
    );
}

// ---------------------------------------------------------------------------
// AC-001.5: probes that could not run stay fail-closed, no dialog (tool call
// and aggregate paths; lifecycle End is in lifecycle_stop_tests.rs)
// ---------------------------------------------------------------------------

fn assert_blocked_with_the_generic_error(result: &ArcEvaluationResult, command: &str) {
    assert_eq!(
        result.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );
    let codex = arc::CodexAdapter::evaluation_result_to_pre_tool_use_output(result).unwrap();
    let specific = codex.hook_specific_output.expect("codex hook output");
    assert_eq!(specific.permission_decision, "deny");
    let codex_reason = specific.permission_decision_reason.expect("codex reason");
    assert!(codex_reason.contains(GENERIC_ERROR), "{codex_reason}");
    assert!(!codex_reason.contains(command), "{codex_reason}");
    let agy = arc::AgyAdapter::evaluation_result_to_pre_tool_use_output(result).unwrap();
    assert_eq!(agy.decision, "deny");
    let agy_reason = agy.reason.expect("agy reason");
    assert!(agy_reason.contains(GENERIC_ERROR), "{agy_reason}");
    assert!(!agy_reason.contains(command), "{agy_reason}");
}

#[test]
fn an_ask_guard_whose_probe_cannot_run_never_reaches_the_dialog() {
    // No output is configured, so the runner returns an error for the command.
    let (result, event) = evaluate_probes(
        vec![ask("g-fault", 1, probe("cannot-run", "ok"))],
        Vec::new(),
        MockProbeRunner::new(),
    );

    assert!(try_interactive(&result, &event).is_none());
    assert_blocked_with_the_generic_error(&result, "cannot-run");
}

#[test]
fn a_probe_from_a_rule_that_cannot_run_never_reaches_the_dialog() {
    let (result, event) = evaluate_probes(
        vec![ask("g-fault-rule", 1, rule("flaky"))],
        vec![("flaky", probe("flaky-command", "ok"))],
        MockProbeRunner::new(),
    );

    assert!(try_interactive(&result, &event).is_none());
    assert_blocked_with_the_generic_error(&result, "flaky-command");
}

#[test]
fn a_probe_over_the_output_limit_never_reaches_the_dialog() {
    let oversized = "x".repeat(MAX_PROBE_OUTPUT_BYTES + 1);
    let (result, event) = evaluate_probes(
        vec![ask("g-too-big", 1, probe("too-big", "ok"))],
        Vec::new(),
        runner(&[("too-big", oversized.as_str())]),
    );

    assert!(try_interactive(&result, &event).is_none());
    assert_blocked_with_the_generic_error(&result, "too-big");
}

#[test]
fn a_probe_that_cannot_run_under_not_never_reaches_the_dialog() {
    let (result, event) = evaluate_probes(
        vec![ask(
            "g-fault-not",
            1,
            not(probe("cannot-run-negated", "ok")),
        )],
        Vec::new(),
        MockProbeRunner::new(),
    );

    assert!(try_interactive(&result, &event).is_none());
    assert_blocked_with_the_generic_error(&result, "cannot-run-negated");
}

#[test]
fn one_faulted_guard_keeps_every_other_ask_guard_out_of_the_dialog_too() {
    let (result, event) = evaluate_probes(
        vec![
            ask("g-faulted", 1, probe("cannot-run", "ok")),
            ask("g-plain-mismatch", 2, probe("plain", "ok")),
        ],
        Vec::new(),
        runner(&[("plain", "bad")]),
    );

    assert!(try_interactive(&result, &event).is_none());
    assert_blocked_with_the_generic_error(&result, "cannot-run");
}

#[test]
fn a_fault_beside_an_exact_authorization_blocks_the_aggregate_dialog() {
    let (result, event) = evaluate(
        vec![
            ask("g-faulted", 1, probe("cannot-run", "ok")),
            guard("g-auth", 2, ActionType::Deny, decide("Audit git push")),
        ],
        Vec::new(),
        MockProbeRunner::new(),
        MockDecisionProvider::new().with_decision("Audit git push", true),
    );

    assert!(try_interactive(&result, &event).is_none());
    assert_blocked_with_the_generic_error(&result, "cannot-run");
}

// ---------------------------------------------------------------------------
// AC-001.6: decide-only guards, and no expected values
// ---------------------------------------------------------------------------

#[test]
fn a_guard_failed_only_by_decide_has_no_failed_probes_and_its_findings_display_as_before() {
    let (result, event) = evaluate(
        vec![ask(
            "g-decide",
            1,
            decide("Does the change follow the policy?"),
        )],
        Vec::new(),
        MockProbeRunner::new(),
        MockDecisionProvider::new().with_verdict(
            "Does the change follow the policy?",
            DecisionVerdict {
                decision: false,
                findings: Some("The change skips the review step.".into()),
            },
        ),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-decide");
    assert!(item.failed_probes.is_empty());
    assert_eq!(
        item.auditor_findings.as_deref(),
        Some("The change skips the review step.")
    );
    assert_eq!(
        item.configured_feedback.as_deref(),
        Some("g-decide feedback")
    );
}

#[test]
fn a_decide_only_dialog_serializes_without_a_failed_probes_key() {
    let (result, event) = evaluate(
        vec![ask("g-decide", 1, decide("Is it fine?"))],
        Vec::new(),
        MockProbeRunner::new(),
        MockDecisionProvider::new().with_decision("Is it fine?", false),
    );
    let dialog = dialog(&result, &event);

    let wire = serde_json::to_value(&dialog).unwrap();
    let item = wire["violations"][0].as_object().expect("violation object");
    assert!(!item.contains_key("failed_probes"), "{wire}");
    let mut keys: Vec<&str> = item.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "auditor_findings",
            "configured_feedback",
            "guard_id",
            "scope",
            "summary"
        ]
    );
}

#[test]
fn a_guard_failed_by_a_probe_and_by_decide_shows_both_the_probe_and_the_findings() {
    let (result, event) = evaluate(
        vec![ask(
            "g-both",
            1,
            BoundRuleExpression::Any(vec![
                probe("both-probe", "ok"),
                decide("Is the work complete?"),
            ]),
        )],
        Vec::new(),
        runner(&[("both-probe", "bad")]),
        MockDecisionProvider::new().with_verdict(
            "Is the work complete?",
            DecisionVerdict {
                decision: false,
                findings: Some("Tests are missing.".into()),
            },
        ),
    );
    let dialog = dialog(&result, &event);

    let item = violation(&dialog, "g-both");
    assert_eq!(probes_of(item), vec![listed(None, "both-probe", None)]);
    assert_eq!(item.auditor_findings.as_deref(), Some("Tests are missing."));
}

#[test]
fn expected_values_and_observed_output_never_reach_the_dialog() {
    let (result, event) = evaluate_probes(
        vec![
            ask("g-secret", 1, probe("show-state", "EXPECTED-VALUE-7731")),
            ask(
                "g-secret-not",
                2,
                not(probe("show-flag", "ENABLED-VALUE-4402")),
            ),
        ],
        Vec::new(),
        runner(&[
            ("show-state", "OBSERVED-VALUE-9120"),
            ("show-flag", "ENABLED-VALUE-4402"),
        ]),
    );
    let dialog = dialog(&result, &event);

    let text = serde_json::to_string(&dialog).unwrap();
    for forbidden in [
        "EXPECTED-VALUE-7731",
        "OBSERVED-VALUE-9120",
        "ENABLED-VALUE-4402",
        "expected_values",
        "observed_sha256",
        "sha256:",
    ] {
        // The bundle fingerprint is the only legitimate "sha256:" text.
        let occurrences = text.matches(forbidden).count();
        let allowed = usize::from(forbidden == "sha256:");
        assert!(occurrences <= allowed, "'{forbidden}' leaked into {text}");
    }
    assert_eq!(violation(&dialog, "g-secret").failed_probes.len(), 1);
    assert_eq!(violation(&dialog, "g-secret-not").failed_probes.len(), 1);
}

#[test]
fn hook_feedback_composed_from_the_context_stays_free_of_probe_evidence() {
    let (result, event) = evaluate_probes(
        vec![ask("g-feedback", 1, rule("tests-green"))],
        vec![("tests-green", probe("cargo test --all", "ok"))],
        runner(&[("cargo test --all", "bad")]),
    );
    let request = interactive(&result, &event);

    assert_eq!(request.guards().len(), 1);
    let context = &request.guards()[0];
    assert_eq!(context.failed_probes().len(), 1);
    assert_eq!(
        arc::compose_failure_feedback(context).as_deref(),
        Some("g-feedback feedback")
    );
}

#[test]
fn a_context_built_without_failure_causes_has_no_failed_probes() {
    let context = arc::GuardFailureContext::new("g-new", Some("feedback".into()), None).unwrap();
    assert!(context.failed_probes().is_empty());
}

#[test]
fn the_bundle_fingerprint_of_the_dialog_is_the_bundle_fingerprint_of_the_evaluation() {
    let (result, event) = evaluate_probes(
        vec![ask("g-bundle", 1, probe("bundle-check", "ok"))],
        Vec::new(),
        runner(&[("bundle-check", "bad")]),
    );
    let dialog = dialog(&result, &event);

    assert_eq!(
        dialog.bundle_fingerprint,
        result.failure_bundle.bundle_fingerprint
    );
}
