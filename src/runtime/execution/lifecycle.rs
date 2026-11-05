use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    CoordinationInput, DecisionActor, DecisionChoice, DecisionIntegrity, DecisionReceipt,
    EvaluationSnapshot, GuardActivation, GuardExecutionCoordinator, GuardExecutionKey,
    ProviderSignals, RuntimeDirective, RuntimeDisposition, ViolationHandling,
};
use crate::decision_ui::PortableDecision;
use crate::runtime::decision::GuardFailureContext;
use crate::runtime::events::ArcEventType;
use crate::runtime::guard_evaluation::{
    ArcEvaluationResult, DialogResponse, EffectiveDisposition, GuardResultState,
};
use crate::target::{CapabilityResolution, ProviderTarget};

/// Provider-specific reentry metadata normalized before entering the runtime.
#[derive(Debug, Clone)]
pub struct LifecycleStopActivation {
    pub provider: ProviderTarget,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub coordination_invocation_id: String,
    pub signals: ProviderSignals,
}

pub struct LifecycleStopContext<'a> {
    pub activation: &'a LifecycleStopActivation,
    pub workspace_id: &'a str,
    pub decision_transport_available: bool,
}

/// The presenter receives all pending Ask guards and their durable correlation.
pub struct LifecycleStopDecisionRequest<'a> {
    pub guard_id: &'a str,
    pub primary_context: &'a GuardFailureContext,
    pub failure_contexts: &'a [GuardFailureContext],
    pub correlation: crate::DecisionCorrelation,
}

#[derive(Debug)]
pub enum LifecycleStopOutcome {
    ProjectEvaluation,
    Completed { feedback: String },
    Blocked { feedback: String },
    Decision(Box<LifecycleStopDecision>),
}

#[derive(Debug)]
pub struct LifecycleStopDecision {
    pub response: DialogResponse,
    pub resolution: CapabilityResolution,
    pub guard_id: String,
    pub configured_feedback: Option<String>,
    pub aggregate_feedback: String,
}

const PUBLIC_HOOK_FAILURE_REASON: &str =
    "[ARC-HOOK-001] Guard evaluation failed; see local Arc diagnostics.";

#[derive(Debug, Clone)]
struct CoordinatedLifecycleGuard {
    guard_id: String,
    key: GuardExecutionKey,
    directive: RuntimeDirective,
    action: crate::ActionType,
}

fn lifecycle_has_terminal_latch(eval_result: &crate::ArcEvaluationResult) -> bool {
    matches!(
        eval_result.effective_disposition,
        crate::EffectiveDisposition::Deny | crate::EffectiveDisposition::RuntimeFault
    )
}

fn lifecycle_violation_handling(
    action: crate::ActionType,
    terminal_latch: bool,
) -> ViolationHandling {
    if terminal_latch {
        return ViolationHandling::Terminal;
    }
    match action {
        crate::ActionType::Ask => ViolationHandling::RequireDecision,
        crate::ActionType::Deny => ViolationHandling::Terminal,
        crate::ActionType::Message => ViolationHandling::FeedbackOnly,
    }
}

fn lifecycle_guard_feedback(guard: &crate::FailedGuardFeedback) -> Option<String> {
    guard.configured_feedback.clone().or_else(|| {
        guard.causes.first().map(|cause| {
            cause
                .auditor_findings
                .clone()
                .unwrap_or_else(|| cause.summary.clone())
        })
    })
}

fn lifecycle_guard_key(
    workspace_id: &str,
    session_id: &str,
    turn_id: Option<&str>,
    guard_id: &str,
) -> GuardExecutionKey {
    GuardExecutionKey {
        workspace_id: workspace_id.to_owned(),
        session_id: session_id.to_owned(),
        turn_id: turn_id.map(str::to_owned),
        guard_id: guard_id.to_owned(),
        activation: GuardActivation::SessionStop,
        subject_id: None,
    }
}

fn lifecycle_failure_contexts(
    eval_result: &crate::ArcEvaluationResult,
) -> Result<Vec<crate::GuardFailureContext>> {
    eval_result
        .failure_bundle
        .failed_guards
        .iter()
        .map(|guard| {
            crate::GuardFailureContext::from_failure_causes(
                guard.guard_id.clone(),
                guard.configured_feedback.clone(),
                &guard.causes,
            )
            .with_context(|| {
                format!(
                    "failed Guard '{}' could not be represented in the lifecycle decision context",
                    guard.guard_id
                )
            })
        })
        .collect()
}

fn lifecycle_ask_failure_contexts(
    eval_result: &crate::ArcEvaluationResult,
    ask_guard_ids: &BTreeSet<String>,
) -> Result<Vec<crate::GuardFailureContext>> {
    lifecycle_failure_contexts(eval_result).map(|contexts| {
        contexts
            .into_iter()
            .filter(|context| ask_guard_ids.contains(context.guard_id()))
            .collect()
    })
}

/// Coordinates a complete End evaluation once, independent of provider wire formats.
/// Terminal results cancel all pending decisions before coordination. Only owned Ask
/// requests can present; resolved receipts apply atomically to the complete Ask set.
/// Observation is best effort at the caller's boundary and never changes policy.
pub fn coordinate_lifecycle_stop(
    coordinator: &GuardExecutionCoordinator,
    context: &LifecycleStopContext<'_>,
    result: &ArcEvaluationResult,
    mut present: impl FnMut(
        LifecycleStopDecisionRequest<'_>,
    ) -> Result<(DialogResponse, CapabilityResolution)>,
    mut observe: impl FnMut(&str, &str, &RuntimeDirective, bool),
) -> Result<LifecycleStopOutcome> {
    result.validate()?;
    if result.report.event_type != ArcEventType::End {
        bail!("lifecycle stop coordination requires an End evaluation");
    }
    let activation = context.activation;
    let invocation_id = &activation.coordination_invocation_id;
    let make_key = |guard_id: &str| {
        lifecycle_guard_key(
            context.workspace_id,
            &activation.session_id,
            activation.turn_id.as_deref(),
            guard_id,
        )
    };
    let feedback_by_id = result
        .failure_bundle
        .failed_guards
        .iter()
        .map(|guard| (guard.guard_id.as_str(), guard))
        .collect::<BTreeMap<_, _>>();
    let terminal = lifecycle_has_terminal_latch(result);
    if terminal {
        for guard in &result.report.guard_results {
            coordinator.cancel_pending_decision(&make_key(&guard.guard_id))?;
        }
    }
    let mut directives = Vec::with_capacity(result.report.guard_results.len());
    for guard in &result.report.guard_results {
        let (snapshot, handling) = match &guard.state {
            GuardResultState::Satisfied => continue,
            GuardResultState::Faulted { .. } => (
                EvaluationSnapshot::Fault {
                    message: PUBLIC_HOOK_FAILURE_REASON.into(),
                },
                ViolationHandling::Terminal,
            ),
            GuardResultState::Violated { .. } => (
                EvaluationSnapshot::Violated {
                    feedback: feedback_by_id
                        .get(guard.guard_id.as_str())
                        .and_then(|guard| lifecycle_guard_feedback(guard)),
                },
                lifecycle_violation_handling(guard.configured_action, terminal),
            ),
        };
        let key = make_key(&guard.guard_id);
        let directive = coordinator.coordinate(CoordinationInput {
            key: key.clone(),
            invocation_id: invocation_id.clone(),
            signals: activation.signals.clone(),
            evaluation: snapshot,
            violation_handling: handling,
        })?;
        observe(
            &guard.guard_id,
            invocation_id,
            &directive,
            handling == ViolationHandling::RequireDecision && context.decision_transport_available,
        );
        directives.push(CoordinatedLifecycleGuard {
            guard_id: guard.guard_id.clone(),
            key,
            directive,
            action: guard.configured_action,
        });
    }
    let feedback = |fallback: &str| -> Result<String> {
        Ok(
            crate::runtime::adapter::format_bundle_feedback_for_provider(
                &result.failure_bundle,
                fallback,
            )?,
        )
    };
    if terminal {
        return Ok(LifecycleStopOutcome::Blocked {
            feedback: feedback(
                if result.effective_disposition == EffectiveDisposition::RuntimeFault {
                    "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics."
                } else {
                    "Session cannot end: Arc guard requirements unmet."
                },
            )?,
        });
    }
    let asks = directives
        .iter()
        .filter(|entry| {
            entry.action == crate::ActionType::Ask
                && entry.directive.disposition == RuntimeDisposition::RequestDecision
        })
        .collect::<Vec<_>>();
    let Some(selected) = asks.iter().min_by_key(|entry| entry.guard_id.as_str()) else {
        return if result.effective_disposition == EffectiveDisposition::Ask {
            Ok(LifecycleStopOutcome::Completed {
                feedback: feedback("Confirmation was already resolved for this guard evidence.")?,
            })
        } else {
            Ok(LifecycleStopOutcome::ProjectEvaluation)
        };
    };
    let cancel = || -> Result<()> {
        for entry in &asks {
            coordinator.cancel_pending_decision(&entry.key)?;
        }
        Ok(())
    };
    let request = selected
        .directive
        .decision_request
        .as_ref()
        .context("Arc lifecycle ask did not include its correlated decision request")?;
    if !context.decision_transport_available {
        cancel()?;
        return Ok(LifecycleStopOutcome::Blocked {
            feedback: feedback(
                "Arc lifecycle Ask cannot be presented: provider has no compatible decision transport.",
            )?,
        });
    }
    if let Some(other) = asks.iter().find(|entry| {
        entry
            .directive
            .decision_request
            .as_ref()
            .is_none_or(|pending| pending.owner_invocation_id.as_deref() != Some(invocation_id))
    }) {
        // Release this invocation's partial claims, preserving the other active owner's claim.
        for entry in &asks {
            if entry
                .directive
                .decision_request
                .as_ref()
                .is_some_and(|pending| {
                    pending.owner_invocation_id.as_deref() == Some(invocation_id)
                })
            {
                coordinator.cancel_pending_decision(&entry.key)?;
            }
        }
        return Ok(LifecycleStopOutcome::Blocked {
            feedback: format!(
                "[ARC {}] A decision dialog for guard '{}' is already pending; Arc refused to open a duplicate window.",
                other.directive.execution_id, other.guard_id,
            ),
        });
    }
    // Any failure after acquiring the Ask set releases it, including context,
    // transport and receipt validation errors. Cancellation errors propagate.
    let decision = (|| -> Result<LifecycleStopOutcome> {
        let ids = asks
            .iter()
            .map(|entry| entry.guard_id.clone())
            .collect::<BTreeSet<_>>();
        let contexts = lifecycle_ask_failure_contexts(result, &ids)?;
        let primary = contexts
            .iter()
            .find(|context| context.guard_id() == selected.guard_id)
            .context("Arc lifecycle Ask guard was missing from the aggregate failure bundle")?;
        let correlation = crate::DecisionCorrelation::new(
            request.decision_id.clone(),
            request.execution_id.clone(),
            Some(invocation_id.clone()),
        )?;
        let (response, resolution) = present(LifecycleStopDecisionRequest {
            guard_id: &selected.guard_id,
            primary_context: primary,
            failure_contexts: &contexts,
            correlation,
        })?;
        match response.decision {
            PortableDecision::Allow | PortableDecision::Deny => {
                let selected_choice = if response.decision == PortableDecision::Allow {
                    DecisionChoice::Allow
                } else {
                    DecisionChoice::Deny
                };
                let receipt = DecisionReceipt {
                    decision_id: request.decision_id.clone(),
                    execution_id: request.execution_id.clone(),
                    selected_choice,
                    actor: DecisionActor::User,
                    provider: activation.provider.as_str().into(),
                    received_at_unix_ms: now_unix_ms(),
                    integrity: DecisionIntegrity {
                        transport: response.transport.clone(),
                        native_interaction_id: None,
                    },
                };
                let keys = asks
                    .iter()
                    .map(|entry| entry.key.clone())
                    .collect::<Vec<_>>();
                let decision_invocation_id = format!("{invocation_id}:decision");
                let applied = coordinator.apply_aggregate_decision(
                    &keys,
                    &format!("arc:lifecycle:{}", request.decision_id),
                    &decision_invocation_id,
                    invocation_id,
                    &receipt,
                )?;
                for (entry, directive) in asks.iter().zip(&applied) {
                    observe(&entry.guard_id, &decision_invocation_id, directive, true);
                }
            }
            PortableDecision::Unresolved(_) => cancel()?,
        }
        Ok(LifecycleStopOutcome::Decision(Box::new(
            LifecycleStopDecision {
                response,
                resolution,
                guard_id: selected.guard_id.clone(),
                configured_feedback: primary.configured_feedback().map(str::to_owned),
                aggregate_feedback: feedback("Arc aggregate feedback.")?,
            },
        )))
    })();
    if decision.is_err() {
        cancel()?;
    }
    decision
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
