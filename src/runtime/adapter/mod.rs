pub mod agy;
pub mod codex;
pub(crate) mod common;

#[cfg(test)]
mod test_support {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use crate::ir::{
        BehaviorIR, BoundLifecycleGuard, BoundMatcher, BoundRuleExpression, BoundToolGuard,
        WorkspaceContext,
    };
    use crate::manifest::schema::{
        ActionType, DECISION_EVALUATION_TIMEOUT_SECONDS, LifecycleTrigger, OnFailureConfig,
    };
    use crate::runtime::evaluator::MockProbeRunner;
    use crate::runtime::events::{ArcEvent, ArcEventType};
    use crate::runtime::guard_evaluation::{
        ArcEvaluationResult, DecisionExecutionProfile, EffectiveDisposition, TrustedIrAnchor,
    };
    use crate::runtime::session::ArcRuntimeSession;

    /// Runs the production evaluator instead of manufacturing a parallel outcome model.
    pub(super) fn evaluate_result(
        disposition: EffectiveDisposition,
        event_type: ArcEventType,
        feedback: &str,
    ) -> ArcEvaluationResult {
        let action = match disposition {
            EffectiveDisposition::Ask => ActionType::Ask,
            EffectiveDisposition::Message => ActionType::Message,
            _ => ActionType::Deny,
        };
        let require = BoundRuleExpression::Probe {
            command: "fixture-check".into(),
            expected_in: vec!["pass".into()],
        };
        let on_failure = OnFailureConfig {
            action,
            feedback: Some(feedback.into()),
        };
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
            lifecycle_guards: Vec::new(),
            tool_guards: Vec::new(),
            rules: BTreeMap::new(),
        };
        let event = match event_type {
            ArcEventType::ToolCall => {
                ir.tool_guards.push(BoundToolGuard {
                    id: "fixture-guard".into(),
                    matcher: BoundMatcher {
                        exact_patterns: vec!["fixture-command".into()],
                        regex_patterns: Vec::new(),
                    },
                    require,
                    on_failure,
                    order: 0,
                    declaration_order: 0,
                });
                ArcEvent::tool_call(
                    "fixture-session",
                    "fixture-event",
                    1,
                    "Bash",
                    "fixture-command",
                )
            }
            ArcEventType::Start | ArcEventType::End => {
                ir.lifecycle_guards.push(BoundLifecycleGuard {
                    id: "fixture-guard".into(),
                    triggers: vec![if event_type == ArcEventType::Start {
                        LifecycleTrigger::Start
                    } else {
                        LifecycleTrigger::End
                    }],
                    require,
                    on_failure,
                    order: 0,
                    declaration_order: 0,
                });
                ArcEvent::lifecycle("fixture-session", "fixture-event", event_type, 1)
            }
        };
        let runner = match disposition {
            EffectiveDisposition::RuntimeFault => MockProbeRunner::new(),
            EffectiveDisposition::Continue => {
                MockProbeRunner::new().with_output("fixture-check", "pass")
            }
            _ => MockProbeRunner::new().with_output("fixture-check", "fail"),
        };
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let deadline_unix_ms = now_unix_ms.saturating_add(
            i64::try_from(DECISION_EVALUATION_TIMEOUT_SECONDS * 1_000).unwrap_or(i64::MAX),
        );
        let workspace_root = std::env::current_dir().unwrap_or_else(|_| ".".into());
        let anchor =
            TrustedIrAnchor::from_authenticated_store_digest(ir.compute_raw_bytes_digest());
        let result = ArcRuntimeSession::new("fixture-session", ir)
            .with_probe_runner(Arc::new(runner))
            .with_trusted_anchor(anchor)
            .expect("fixture IR must match its trusted anchor")
            .evaluate_event_aggregate(
                event,
                DecisionExecutionProfile::default(),
                &workspace_root,
                deadline_unix_ms,
            )
            .expect("fixture evaluation must satisfy the aggregate contract");
        assert_eq!(result.effective_disposition, disposition);
        result
    }
}

pub use common::format_bundle_feedback_for_provider;

pub(crate) fn stop_remediation_reason(
    guard_id: &str,
    invocation_id: &str,
    failure_context: Option<&str>,
    user_message: Option<&str>,
) -> String {
    let context = failure_context.unwrap_or("The completion guard is still failing.");
    let user_context = user_message
        .map(|message| format!(" User message: {message}"))
        .unwrap_or_default();
    format!(
        "The user authorized a remediation attempt for Arc guard '{guard_id}' on this stop attempt ({invocation_id}). Continue working now: resolve only the reported guard failure using actions already authorized in the conversation, verify the guard condition again, and report the actions and verification result to the user before finishing. If remediation requires commit, stash, discard, deletion, publication, or any other authority not already granted, ask the user in the chat instead of assuming permission. Guard context: {context}{user_context}"
    )
}

pub use agy::{
    AgyAdapter, AgyPreInvocationInput, AgyPreInvocationOutput, AgyPreToolUseInput,
    AgyPreToolUseOutput, AgyStopInput, AgyStopOutput, AgyToolCallDetail,
};
pub use codex::{
    CodexAdapter, CodexPreToolUseInput, CodexPreToolUseOutput, CodexSessionStartInput,
    CodexSessionStartOutput, CodexStopInput, CodexStopOutput,
};
