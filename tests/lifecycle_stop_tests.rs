#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;
use guard_evaluation_support::evaluate_session_event;

use arc::decision_ui::{PortableDecision, UnresolvedReason};
use arc::ir::WorkspaceContext;
use arc::manifest::schema::{LifecycleTrigger, OnFailureConfig};
use arc::runtime::execution::{
    LifecycleStopActivation, LifecycleStopContext, LifecycleStopOutcome, coordinate_lifecycle_stop,
};
use arc::{
    ActionType, ArcEvent, ArcEventType, ArcRuntimeSession, BehaviorIR, BoundLifecycleGuard,
    BoundRuleExpression, GuardActivation, GuardExecutionCoordinator, GuardExecutionKey,
    GuardExecutionStateStore, InMemoryStateStore, MockProbeRunner, ProviderTarget,
};
use std::{collections::BTreeMap, sync::Arc};

/// Authenticated anchor for `ir`, issued by the in-memory trust store (public API).
fn trusted_anchor(ir: &BehaviorIR) -> arc::TrustedIrAnchor {
    arc::SqliteStateStore::open_in_memory()
        .unwrap()
        .trust_and_anchor_ir(std::path::Path::new("canonical/ir.json"), ir)
        .unwrap()
}

fn activation(provider: ProviderTarget, invocation: &str) -> LifecycleStopActivation {
    match provider {
        ProviderTarget::Codex => arc::CodexAdapter::stop_activation(
            &serde_json::from_value(
                serde_json::json!({"session_id":"stop-session", "turn_id":"turn-1"}),
            )
            .unwrap(),
            invocation,
        ),
        ProviderTarget::Gemini => arc::AgyAdapter::stop_activation(
            &serde_json::from_value(
                serde_json::json!({"conversationId":"stop-session", "executionNum":1}),
            )
            .unwrap(),
            invocation,
        ),
        _ => unreachable!("test only covers supported hook providers"),
    }
}

fn evaluation(
    provider: ProviderTarget,
    guards: &[(&str, ActionType, bool)],
    fault: bool,
) -> arc::ArcEvaluationResult {
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
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
        lifecycle_guards: guards
            .iter()
            .enumerate()
            .map(|(index, (id, action, satisfied))| BoundLifecycleGuard {
                id: (*id).into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "stop-check".into(),
                    expected_in: vec![if *satisfied {
                        "dirty".into()
                    } else {
                        "clean".into()
                    }],
                },
                on_failure: OnFailureConfig {
                    action: *action,
                    feedback: Some(format!("feedback-{id}")),
                },
                order: 0,
                declaration_order: index,
            })
            .collect(),
    };
    let runner = if fault {
        MockProbeRunner::new()
    } else {
        MockProbeRunner::new().with_output("stop-check", "dirty")
    };
    let mut event = ArcEvent::lifecycle("stop-session", "stop-event", ArcEventType::End, 1);
    event.provider = Some(provider);
    let mut session = ArcRuntimeSession::new("stop-session", ir.clone())
        .with_probe_runner(Arc::new(runner))
        .with_trusted_anchor(trusted_anchor(&ir))
        .unwrap();
    evaluate_session_event(&mut session, event).unwrap()
}

fn context(activation: &LifecycleStopActivation, available: bool) -> LifecycleStopContext<'_> {
    LifecycleStopContext {
        activation,
        workspace_id: "workspace",
        decision_transport_available: available,
    }
}

fn key(activation: &LifecycleStopActivation, id: &str) -> GuardExecutionKey {
    GuardExecutionKey {
        workspace_id: "workspace".into(),
        session_id: activation.session_id.clone(),
        turn_id: activation.turn_id.clone(),
        guard_id: id.into(),
        activation: GuardActivation::SessionStop,
        subject_id: None,
    }
}

fn response(
    provider: ProviderTarget,
    decision: PortableDecision,
) -> (arc::DialogResponse, arc::CapabilityResolution) {
    (
        arc::DialogResponse {
            schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "dialog".into(),
            bundle_fingerprint: "bundle".into(),
            decision,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: Some("user context".into()),
        },
        arc::resolve_capability(arc::CapabilityContext::cli(
            provider,
            arc::OsTarget::host().unwrap(),
            arc::CapabilityEvent::End,
            ActionType::Ask,
            arc::DecisionUiMode::Native,
        )),
    )
}

#[test]
fn both_providers_coordinate_all_asks_and_preserve_message_feedback() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for decision in [
            PortableDecision::Allow,
            PortableDecision::Deny,
            PortableDecision::Unresolved(UnresolvedReason::Closed),
        ] {
            let activation = activation(provider, "invocation-1");
            let store = Arc::new(InMemoryStateStore::default());
            let coordinator = GuardExecutionCoordinator::new(store.clone());
            let result = evaluation(
                provider,
                &[
                    ("ask-b", ActionType::Ask, false),
                    ("message", ActionType::Message, false),
                    ("ask-a", ActionType::Ask, false),
                ],
                false,
            );
            let mut presentations = 0;
            let mut transitions = Vec::new();
            let outcome = coordinate_lifecycle_stop(
                &coordinator,
                &context(&activation, true),
                &result,
                |request| {
                    presentations += 1;
                    assert_eq!(request.guard_id, "ask-a");
                    assert_eq!(
                        request
                            .failure_contexts
                            .iter()
                            .map(|guard| guard.guard_id())
                            .collect::<Vec<_>>(),
                        ["ask-b", "ask-a"]
                    );
                    assert_eq!(
                        request.correlation.owner_invocation_id(),
                        Some(activation.coordination_invocation_id.as_str())
                    );
                    Ok(response(provider, decision))
                },
                |guard, invocation, _, _| {
                    transitions.push((guard.to_owned(), invocation.to_owned()))
                },
            )
            .unwrap();
            assert_eq!(presentations, 1);
            for id in ["ask-a", "ask-b"] {
                let record = store.load(&key(&activation, id)).unwrap().unwrap();
                assert!(record.pending_decision.is_none());
                if !matches!(decision, PortableDecision::Unresolved(_)) {
                    assert!(record.processed_invocations.contains_key(&format!(
                        "{}:decision",
                        activation.coordination_invocation_id
                    )));
                }
            }
            assert!(transitions.iter().any(|(id, _)| id == "message"));
            let output = match provider {
                ProviderTarget::Codex => {
                    let output = arc::CodexAdapter::lifecycle_stop_to_output(
                        outcome,
                        &result,
                        "invocation-1",
                    )
                    .unwrap();
                    assert_eq!(
                        output.decision.as_deref(),
                        if decision == PortableDecision::Deny {
                            None
                        } else {
                            Some("block")
                        }
                    );
                    serde_json::to_value(output).unwrap()
                }
                ProviderTarget::Gemini => {
                    let output =
                        arc::AgyAdapter::lifecycle_stop_to_output(outcome, &result, "invocation-1")
                            .unwrap();
                    assert_eq!(
                        output.decision,
                        if decision == PortableDecision::Deny {
                            "stop"
                        } else {
                            "continue"
                        }
                    );
                    serde_json::to_value(output).unwrap()
                }
                _ => unreachable!(),
            };
            let text = output.to_string();
            for expected in ["feedback-ask-a", "feedback-ask-b", "feedback-message"] {
                assert!(text.contains(expected), "{text}");
            }
        }
    }
}

#[test]
fn terminal_evaluations_cancel_pending_decisions_without_presenting() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for fault in [false, true] {
            let activation = activation(provider, "invocation-1");
            let store = Arc::new(InMemoryStateStore::default());
            let coordinator = GuardExecutionCoordinator::new(store.clone());
            let ask = evaluation(provider, &[("ask", ActionType::Ask, false)], false);
            let _ = coordinate_lifecycle_stop(
                &coordinator,
                &context(&activation, true),
                &ask,
                |_| Err(anyhow::anyhow!("presenter unavailable")),
                |_, _, _, _| {},
            )
            .unwrap_err();
            // Recreate a real owned pending decision before applying the terminal result.
            coordinator
                .coordinate(arc::CoordinationInput {
                    key: key(&activation, "ask"),
                    invocation_id: "pending-owner".into(),
                    signals: Default::default(),
                    evaluation: arc::EvaluationSnapshot::Violated {
                        feedback: Some("pending".into()),
                    },
                    violation_handling: arc::ViolationHandling::RequireDecision,
                })
                .unwrap();
            let terminal = evaluation(
                provider,
                &[
                    ("ask", ActionType::Ask, false),
                    ("deny", ActionType::Deny, false),
                ],
                fault,
            );
            let outcome = coordinate_lifecycle_stop(
                &coordinator,
                &context(&activation, true),
                &terminal,
                |_| panic!("terminal latch must prevent presentation"),
                |_, _, _, _| {},
            )
            .unwrap();
            assert!(matches!(outcome, LifecycleStopOutcome::Blocked { .. }));
            for id in ["ask", "deny"] {
                assert!(
                    store
                        .load(&key(&activation, id))
                        .unwrap()
                        .unwrap()
                        .pending_decision
                        .is_none()
                );
            }
        }
    }
}

#[test]
fn presentation_error_and_missing_transport_release_the_entire_ask_set() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for available in [false, true] {
            let activation = activation(provider, "invocation-1");
            let store = Arc::new(InMemoryStateStore::default());
            let coordinator = GuardExecutionCoordinator::new(store.clone());
            let result = evaluation(
                provider,
                &[
                    ("ask-a", ActionType::Ask, false),
                    ("ask-b", ActionType::Ask, false),
                ],
                false,
            );
            let mut presentations = 0;
            let outcome = coordinate_lifecycle_stop(
                &coordinator,
                &context(&activation, available),
                &result,
                |_| {
                    presentations += 1;
                    Err(anyhow::anyhow!("transport failed"))
                },
                |_, _, _, _| {},
            );
            assert_eq!(presentations, usize::from(available));
            assert_eq!(outcome.is_err(), available);
            for id in ["ask-a", "ask-b"] {
                assert!(
                    store
                        .load(&key(&activation, id))
                        .unwrap()
                        .unwrap()
                        .pending_decision
                        .is_none()
                );
            }
        }
    }
}

#[test]
fn satisfied_and_message_only_results_never_present_a_decision() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for satisfied in [true, false] {
            let activation = activation(provider, "invocation-1");
            let coordinator =
                GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
            let result = evaluation(
                provider,
                &[("message", ActionType::Message, satisfied)],
                false,
            );
            let outcome = coordinate_lifecycle_stop(
                &coordinator,
                &context(&activation, true),
                &result,
                |_| panic!("advisory and satisfied guards never present"),
                |_, _, _, _| {},
            )
            .unwrap();
            assert!(matches!(outcome, LifecycleStopOutcome::ProjectEvaluation));
        }
    }
}

#[test]
fn a_pending_guard_owned_by_another_invocation_prevents_the_whole_dialog() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        let activation = activation(provider, "invocation-1");
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store.clone());
        coordinator
            .coordinate(arc::CoordinationInput {
                key: key(&activation, "ask-b"),
                invocation_id: "other-owner".into(),
                signals: Default::default(),
                evaluation: arc::EvaluationSnapshot::Violated {
                    feedback: Some("feedback-ask-b".into()),
                },
                violation_handling: arc::ViolationHandling::RequireDecision,
            })
            .unwrap();
        let result = evaluation(
            provider,
            &[
                ("ask-a", ActionType::Ask, false),
                ("ask-b", ActionType::Ask, false),
            ],
            false,
        );
        let outcome = coordinate_lifecycle_stop(
            &coordinator,
            &context(&activation, true),
            &result,
            |_| panic!("a partially owned Ask set must never present another dialog"),
            |_, _, _, _| {},
        )
        .unwrap();
        assert!(matches!(outcome, LifecycleStopOutcome::Blocked { .. }));
        let pending = store
            .load(&key(&activation, "ask-b"))
            .unwrap()
            .unwrap()
            .pending_decision
            .unwrap();
        assert_eq!(pending.owner_invocation_id.as_deref(), Some("other-owner"));
        assert!(
            store
                .load(&key(&activation, "ask-a"))
                .unwrap()
                .unwrap()
                .pending_decision
                .is_none()
        );
    }
}

fn bundle_feedback_for_denied_stop(anchored: bool) -> Vec<Option<String>> {
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
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
        lifecycle_guards: vec![BoundLifecycleGuard {
            id: "deny-stop".into(),
            triggers: vec![LifecycleTrigger::End],
            require: BoundRuleExpression::Probe {
                command: "stop-check".into(),
                expected_in: vec!["clean".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("feedback-deny-stop".into()),
            },
            order: 0,
            declaration_order: 0,
        }],
    };
    let runner = Arc::new(MockProbeRunner::new().with_output("stop-check", "dirty"));
    let mut session = ArcRuntimeSession::new("stop-session", ir.clone()).with_probe_runner(runner);
    if anchored {
        session = session.with_trusted_anchor(trusted_anchor(&ir)).unwrap();
    }
    assert_eq!(session.trust_anchor().is_some(), anchored);
    let (_report, bundle) = session
        .evaluate_event_with_bundle(
            ArcEvent::lifecycle("stop-session", "stop-event", ArcEventType::End, 1),
            arc::DecisionExecutionProfile::default(),
            std::path::Path::new("."),
            i64::MAX,
        )
        .unwrap();
    bundle
        .failed_guards
        .iter()
        .map(|guard| guard.configured_feedback.clone())
        .collect()
}

#[test]
fn unanchored_session_projects_no_configured_feedback_while_anchored_session_projects_it() {
    // PO decision Q1 (REQ-013): same IR and same input, only the trust anchor differs.
    assert_eq!(bundle_feedback_for_denied_stop(false), vec![None]);
    assert_eq!(
        bundle_feedback_for_denied_stop(true),
        vec![Some("feedback-deny-stop".to_string())]
    );
}

#[test]
fn native_reentry_metadata_is_normalized_without_changing_invocation_identity() {
    let input = serde_json::from_value(
        serde_json::json!({"session_id":"session", "turn_id":"turn", "stop_hook_active":true}),
    )
    .unwrap();
    let continued = arc::CodexAdapter::stop_activation(&input, "random-hook-id");
    assert_eq!(continued.coordination_invocation_id, "turn:continued");
    assert_eq!(continued.signals.reentry, arc::ReentryKind::ContinuedByHook);
    assert_eq!(continued.turn_id.as_deref(), Some("turn"));
    let initial = arc::CodexAdapter::stop_activation(
        &serde_json::from_value(serde_json::json!({})).unwrap(),
        "random-hook-id",
    );
    assert_eq!(initial.coordination_invocation_id, "turn-unknown:initial");
    assert_eq!(initial.session_id, "codex-session-default");
    let gemini = arc::AgyAdapter::stop_activation(
        &serde_json::from_value(serde_json::json!({"executionNum":7})).unwrap(),
        "hook-id",
    );
    assert_eq!(gemini.coordination_invocation_id, "step-7:hook-id");
    assert_eq!(gemini.signals.reentry, arc::ReentryKind::FirstInvocation);
    assert_eq!(gemini.turn_id.as_deref(), Some("step-7"));
    assert_eq!(gemini.session_id, "agy-session-default");
}

// ---------------------------------------------------------------------------
// REQ-001: the lifecycle End dialog names every probe that caused a failure.
//
// Red phase: `GuardFailureContext::failed_probes()` does not exist yet, so this
// crate fails to compile. The fault tests (AC-001.5) assert today's behavior.
// ---------------------------------------------------------------------------

const NEGATED: &str = "negated expression evaluated to true";
const GENERIC_ERROR: &str = "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.";

/// (rule_name, command, reason)
type Listed = (Option<String>, String, Option<String>);

fn listed(rule: Option<&str>, command: &str, reason: Option<&str>) -> Listed {
    (
        rule.map(str::to_owned),
        command.to_owned(),
        reason.map(str::to_owned),
    )
}

fn sorted(mut probes: Vec<Listed>) -> Vec<Listed> {
    probes.sort();
    probes
}

fn context_probes(context: &arc::GuardFailureContext) -> Vec<Listed> {
    sorted(
        context
            .failed_probes()
            .iter()
            .map(|probe| {
                (
                    probe.rule_name.clone(),
                    probe.command.clone(),
                    probe.reason.clone(),
                )
            })
            .collect(),
    )
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

fn not(inner: BoundRuleExpression) -> BoundRuleExpression {
    BoundRuleExpression::Not(Box::new(inner))
}

fn evaluation_with(
    provider: ProviderTarget,
    guards: Vec<(&str, ActionType, BoundRuleExpression)>,
    rules: Vec<(&str, BoundRuleExpression)>,
    runner: MockProbeRunner,
    decisions: arc::MockDecisionProvider,
) -> arc::ArcEvaluationResult {
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
        tool_guards: Vec::new(),
        rules: rules
            .into_iter()
            .map(|(name, expression)| (name.to_owned(), expression))
            .collect(),
        lifecycle_guards: guards
            .into_iter()
            .enumerate()
            .map(|(index, (id, action, require))| BoundLifecycleGuard {
                id: id.into(),
                triggers: vec![LifecycleTrigger::End],
                require,
                on_failure: OnFailureConfig {
                    action,
                    feedback: Some(format!("feedback-{id}")),
                },
                order: 0,
                declaration_order: index,
            })
            .collect(),
    };
    let mut event = ArcEvent::lifecycle("stop-session", "stop-event", ArcEventType::End, 1);
    event.provider = Some(provider);
    let mut session = ArcRuntimeSession::new("stop-session", ir.clone())
        .with_probe_runner(Arc::new(runner))
        .with_decision_provider(Arc::new(decisions))
        .with_trusted_anchor(trusted_anchor(&ir))
        .unwrap();
    evaluate_session_event(&mut session, event).unwrap()
}

fn runner_with(entries: &[(&str, &str)]) -> MockProbeRunner {
    entries
        .iter()
        .fold(MockProbeRunner::new(), |runner, (command, output)| {
            runner.with_output(*command, *output)
        })
}

#[test]
fn lifecycle_failure_contexts_and_the_dialog_built_from_them_list_each_guards_failed_probes() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        let activation = activation(provider, "invocation-1");
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        let result = evaluation_with(
            provider,
            vec![
                ("ask-rule", ActionType::Ask, rule("tests-green")),
                (
                    "ask-inline",
                    ActionType::Ask,
                    probe("git status --porcelain", ""),
                ),
                (
                    "ask-several",
                    ActionType::Ask,
                    // `any` runs every branch when none matches, so each one is a cause.
                    BoundRuleExpression::Any(vec![
                        probe("check-a", "ok"),
                        probe("check-b", "ok"),
                        probe("check-c", "ok"),
                    ]),
                ),
                ("ask-not", ActionType::Ask, not(rule("wip-flag"))),
                (
                    "ask-decide",
                    ActionType::Ask,
                    BoundRuleExpression::Decide {
                        prompt: "Is it complete?".into(),
                    },
                ),
                ("msg-probe", ActionType::Message, probe("advisory", "ok")),
            ],
            vec![
                ("tests-green", probe("cargo test", "ok")),
                ("wip-flag", probe("cat .wip", "yes")),
            ],
            runner_with(&[
                ("cargo test", "failed"),
                ("git status --porcelain", "M src/lib.rs"),
                ("check-a", "bad"),
                ("check-b", "bad"),
                ("check-c", "bad"),
                ("cat .wip", "yes"),
                ("advisory", "bad"),
            ]),
            arc::MockDecisionProvider::new().with_decision("Is it complete?", false),
        );
        let mut seen = false;
        coordinate_lifecycle_stop(
            &coordinator,
            &context(&activation, true),
            &result,
            |request| {
                seen = true;
                let by_guard = |id: &str| {
                    request
                        .failure_contexts
                        .iter()
                        .find(|context| context.guard_id() == id)
                        .unwrap_or_else(|| panic!("guard '{id}' has no failure context"))
                };
                let expected = [
                    (
                        "ask-rule",
                        vec![listed(Some("tests-green"), "cargo test", None)],
                    ),
                    (
                        "ask-inline",
                        vec![listed(None, "git status --porcelain", None)],
                    ),
                    (
                        "ask-several",
                        sorted(vec![
                            listed(None, "check-a", None),
                            listed(None, "check-b", None),
                            listed(None, "check-c", None),
                        ]),
                    ),
                    (
                        "ask-not",
                        vec![listed(Some("wip-flag"), "cat .wip", Some(NEGATED))],
                    ),
                    ("ask-decide", Vec::new()),
                ];
                for (id, probes) in &expected {
                    assert_eq!(&context_probes(by_guard(id)), probes, "guard {id}");
                }
                assert_eq!(
                    request.failure_contexts.len(),
                    5,
                    "message guards are not Ask"
                );

                // The same contexts become the dialog exactly as `main.rs` does it.
                let dialog = arc::InteractiveDecisionRequest::with_guards(
                    provider,
                    ArcEventType::End,
                    ActionType::Ask,
                    "presentation-1",
                    "invocation-1",
                    request.failure_contexts.to_vec(),
                    "Arc guards are not satisfied.",
                    None,
                    Some("lifecycle:end".into()),
                    "authorize remediation for this failed completion guard",
                    None,
                )
                .unwrap()
                .to_dialog_request("Decision required");
                dialog.validate().unwrap();
                assert_eq!(
                    dialog.presentation_kind,
                    arc::PresentationKind::GuardFailures
                );
                for (id, probes) in &expected {
                    let item = dialog
                        .violations
                        .iter()
                        .find(|item| item.guard_id == *id)
                        .unwrap_or_else(|| panic!("guard '{id}' is not in the dialog"));
                    let shown: Vec<Listed> = sorted(
                        item.failed_probes
                            .iter()
                            .map(|p| (p.rule_name.clone(), p.command.clone(), p.reason.clone()))
                            .collect(),
                    );
                    assert_eq!(&shown, probes, "dialog guard {id}");
                }
                let wire = serde_json::to_value(&dialog).unwrap();
                assert!(
                    wire["violations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|item| item["guard_id"] == "ask-decide")
                        .unwrap()
                        .get("failed_probes")
                        .is_none(),
                    "{wire}"
                );
                Ok(response(
                    provider,
                    PortableDecision::Unresolved(UnresolvedReason::Closed),
                ))
            },
            |_, _, _, _| {},
        )
        .unwrap();
        assert!(seen, "the Ask set must reach the presenter");
    }
}

fn assert_lifecycle_blocked_by_the_generic_error(
    provider: ProviderTarget,
    result: &arc::ArcEvaluationResult,
    command: &str,
) {
    assert_eq!(
        result.effective_disposition,
        arc::EffectiveDisposition::RuntimeFault
    );
    let activation = activation(provider, "invocation-1");
    let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
    let outcome = coordinate_lifecycle_stop(
        &coordinator,
        &context(&activation, true),
        result,
        |_| panic!("a faulted evaluation must never reach the presenter"),
        |_, _, _, _| {},
    )
    .unwrap();
    let LifecycleStopOutcome::Blocked { feedback } = &outcome else {
        panic!("expected a blocked stop, got {outcome:?}");
    };
    assert!(feedback.contains(GENERIC_ERROR), "{feedback}");
    assert!(!feedback.contains(command), "{feedback}");
    assert!(!feedback.contains("Failed probes"), "{feedback}");
    let text = match provider {
        ProviderTarget::Codex => serde_json::to_value(
            arc::CodexAdapter::lifecycle_stop_to_output(outcome, result, "invocation-1").unwrap(),
        )
        .unwrap()
        .to_string(),
        ProviderTarget::Gemini => serde_json::to_value(
            arc::AgyAdapter::lifecycle_stop_to_output(outcome, result, "invocation-1").unwrap(),
        )
        .unwrap()
        .to_string(),
        _ => unreachable!(),
    };
    assert!(text.contains(GENERIC_ERROR), "{text}");
    assert!(!text.contains(command), "{text}");
}

#[test]
fn an_ask_guard_whose_probe_cannot_run_blocks_the_stop_without_a_dialog() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        let result = evaluation_with(
            provider,
            vec![("ask-fault", ActionType::Ask, probe("cannot-run", "ok"))],
            Vec::new(),
            MockProbeRunner::new(),
            arc::MockDecisionProvider::new(),
        );
        assert_lifecycle_blocked_by_the_generic_error(provider, &result, "cannot-run");
    }
}

#[test]
fn an_ask_guard_whose_rule_probe_cannot_run_blocks_the_stop_without_a_dialog() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        let result = evaluation_with(
            provider,
            vec![("ask-fault-rule", ActionType::Ask, rule("flaky"))],
            vec![("flaky", probe("flaky-command", "ok"))],
            MockProbeRunner::new(),
            arc::MockDecisionProvider::new(),
        );
        assert_lifecycle_blocked_by_the_generic_error(provider, &result, "flaky-command");
    }
}

#[test]
fn an_ask_guard_whose_probe_exceeds_the_output_limit_blocks_the_stop_without_a_dialog() {
    let oversized = "x".repeat(arc::runtime::evaluator::MAX_PROBE_OUTPUT_BYTES + 1);
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        let result = evaluation_with(
            provider,
            vec![("ask-too-big", ActionType::Ask, probe("too-big", "ok"))],
            Vec::new(),
            runner_with(&[("too-big", oversized.as_str())]),
            arc::MockDecisionProvider::new(),
        );
        assert_lifecycle_blocked_by_the_generic_error(provider, &result, "too-big");
    }
}

#[test]
fn a_faulted_ask_guard_keeps_the_other_ask_guards_of_the_stop_out_of_the_dialog() {
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        let result = evaluation_with(
            provider,
            vec![
                ("ask-faulted", ActionType::Ask, probe("cannot-run", "ok")),
                ("ask-mismatch", ActionType::Ask, probe("plain", "ok")),
            ],
            Vec::new(),
            runner_with(&[("plain", "bad")]),
            arc::MockDecisionProvider::new(),
        );
        assert_lifecycle_blocked_by_the_generic_error(provider, &result, "cannot-run");
    }
}
