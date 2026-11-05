use serde_json::Value;

use crate::runtime::events::ToolArgumentExtraction;
use crate::runtime::guard_evaluation::{
    EvaluationFault, FailureBundle, FailureBundleError, MAX_PROVIDER_FEEDBACK_INLINE_BYTES,
};

/// Creates bounded, human-readable correction text from a canonical Arc bundle.
///
/// The hook receives only configured feedback, auditor findings, or generic
/// fault descriptions. Bundle IDs, fingerprints, causal paths, raw evidence,
/// and artifact references remain inside Arc and are never serialized here.
pub fn format_bundle_feedback_for_provider(
    bundle: &FailureBundle,
    default_fallback: &str,
) -> Result<String, FailureBundleError> {
    let fallback = if default_fallback.trim().is_empty() {
        "One or more Arc guards require attention."
    } else {
        default_fallback.trim()
    };
    let is_runtime_fault = bundle.effective_disposition
        == crate::runtime::guard_evaluation::EffectiveDisposition::RuntimeFault;
    let mut sections = Vec::new();

    if is_runtime_fault {
        sections.push(fallback.to_owned());
    }

    for guard in &bundle.failed_guards {
        if guard.faulted {
            continue;
        }

        let configured_feedback = guard
            .configured_feedback
            .as_deref()
            .map(str::trim)
            .filter(|feedback| !feedback.is_empty());
        let auditor_findings = guard
            .causes
            .iter()
            .filter_map(|cause| {
                cause
                    .auditor_findings
                    .as_deref()
                    .map(str::trim)
                    .filter(|finding| !finding.is_empty())
            })
            .collect::<Vec<_>>();
        let cause_summaries = if auditor_findings.is_empty() {
            guard
                .causes
                .iter()
                .map(|cause| cause.summary.trim())
                .filter(|summary| !summary.is_empty())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        if configured_feedback.is_none()
            && auditor_findings.is_empty()
            && cause_summaries.is_empty()
        {
            continue;
        }

        let mut lines = vec![format!("Guard '{}':", guard.guard_id)];
        if let Some(feedback) = configured_feedback {
            lines.push(format!("Configured feedback: {feedback}"));
        }
        if !auditor_findings.is_empty() {
            lines.push(format!(
                "Auditor findings:\n{}",
                auditor_findings
                    .iter()
                    .map(|finding| format!("- {finding}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        } else if !cause_summaries.is_empty() {
            lines.push(format!(
                "Evaluation findings:\n{}",
                cause_summaries
                    .iter()
                    .map(|summary| format!("- {summary}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
        sections.push(lines.join("\n"));
    }

    for f in &bundle.evaluation_faults {
        let message = match f {
            EvaluationFault::MissingLeaf { .. } => "Evaluation references a missing leaf",
            EvaluationFault::RuleCycle { .. } => "Evaluation rule cycle detected",
            EvaluationFault::MissingRule { .. } => "Evaluation references a missing rule",
            EvaluationFault::Probe { .. } => "Probe execution failed",
            EvaluationFault::Decision { .. } => "Decision evaluation failed",
            EvaluationFault::DeadlineExceeded => "Evaluation deadline exceeded",
            EvaluationFault::ProviderUnavailable => "Evaluation provider unavailable",
            EvaluationFault::InvalidPlan { .. } => "Evaluation plan is invalid",
            EvaluationFault::CacheKeyCollision => "Evaluation cache key collision",
            EvaluationFault::Canceled { .. } => "Evaluation was canceled",
        };
        sections.push(format!("Evaluation fault: {message}"));
    }

    if sections.is_empty() {
        sections.push(fallback.to_owned());
    }

    let rendered = format!("Arc guard feedback:\n\n{}", sections.join("\n\n"));
    if rendered.len() > MAX_PROVIDER_FEEDBACK_INLINE_BYTES {
        return Err(FailureBundleError::InlineTooLarge {
            bytes: rendered.len(),
            max: MAX_PROVIDER_FEEDBACK_INLINE_BYTES,
        });
    }
    Ok(rendered)
}

const COMMAND_TOOL_ALIASES: [&str; 14] = [
    "run_command",
    "execute_command",
    "terminal",
    "bash",
    "sh",
    "cmd",
    "exec",
    "powershell",
    "pwsh",
    "shell",
    "run_terminal_command",
    "execute_process",
    "run_script",
    "command",
];

const COMMAND_ARGUMENT_KEYS: [&str; 7] = [
    "CommandLine",
    "command",
    "cmd",
    "script",
    "exec",
    "args",
    "query",
];

pub fn is_command_tool(tool_name: &str) -> bool {
    let lower = tool_name.to_lowercase();
    COMMAND_TOOL_ALIASES.contains(&lower.as_str())
        || lower.contains("command")
        || lower.contains("bash")
        || lower.contains("terminal")
        || lower.contains("exec")
        || lower.contains("shell")
        || lower.contains("powershell")
        || lower.contains("pwsh")
}

pub fn normalize_tool_call_arguments(
    tool_name: &str,
    input: &Value,
) -> (Option<String>, ToolArgumentExtraction) {
    if is_command_tool(tool_name) {
        if let Some(cmd) = extract_command_text(input)
            && !cmd.trim().is_empty()
        {
            return (
                Some(cmd.clone()),
                ToolArgumentExtraction::Command { command: cmd },
            );
        }
        (
            None,
            ToolArgumentExtraction::MalformedOrUnrecognized {
                raw: input.clone(),
                reason: format!(
                    "Unrecognized, empty, or malformed arguments for command tool '{}'",
                    tool_name
                ),
            },
        )
    } else if let Some(cmd) = extract_command_text(input) {
        if !cmd.trim().is_empty() {
            (
                Some(cmd.clone()),
                ToolArgumentExtraction::Command { command: cmd },
            )
        } else {
            (None, ToolArgumentExtraction::NonCommand)
        }
    } else {
        (None, ToolArgumentExtraction::NonCommand)
    }
}

pub(super) fn validate_provider_tool_call_arguments(
    tool_name: &str,
    input: &Value,
) -> anyhow::Result<()> {
    if !input.is_object() {
        anyhow::bail!("Provider ToolCall arguments for tool '{tool_name}' must be a JSON object");
    }
    Ok(())
}

pub fn extract_command_text(input: &Value) -> Option<String> {
    match input {
        Value::String(s) => {
            if let Ok(nested) = serde_json::from_str::<Value>(s)
                && matches!(nested, Value::Object(_) | Value::Array(_))
            {
                return extract_command_text(&nested);
            }
            Some(normalize_command_str(s))
        }
        Value::Array(arr) => {
            if arr.is_empty() || arr.iter().any(|value| !value.is_string()) {
                return None;
            }
            let parts: Vec<String> = arr
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            (parts.len() == arr.len()).then(|| parts.join(" "))
        }
        Value::Object(map) => {
            let present: Vec<&Value> = COMMAND_ARGUMENT_KEYS
                .iter()
                .filter_map(|key| map.get(*key))
                .collect();
            if present.len() != 1 {
                return None;
            }
            extract_command_text(present[0])
        }
        _ => None,
    }
}

fn normalize_command_str(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
    {
        trimmed[1..trimmed.len() - 1].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SharedCase {
        name: &'static str,
        tool_name: &'static str,
        input: Value,
        expected: ToolArgumentExtraction,
    }

    #[test]
    fn codex_and_agy_share_tool_argument_extraction_contract() {
        let cases = vec![
            SharedCase {
                name: "CommandLine object",
                tool_name: "run_command",
                input: serde_json::json!({"CommandLine": "git push --force"}),
                expected: ToolArgumentExtraction::Command {
                    command: "git push --force".into(),
                },
            },
            SharedCase {
                name: "command object with quote normalization",
                tool_name: "Bash",
                input: serde_json::json!({"command": "\"git status\""}),
                expected: ToolArgumentExtraction::Command {
                    command: "git status".into(),
                },
            },
            SharedCase {
                name: "string array",
                tool_name: "terminal",
                input: serde_json::json!(["git", "push", "--force"]),
                expected: ToolArgumentExtraction::Command {
                    command: "git push --force".into(),
                },
            },
            SharedCase {
                name: "encoded object string",
                tool_name: "execute_command",
                input: serde_json::json!(r#"{"command":"git status"}"#),
                expected: ToolArgumentExtraction::Command {
                    command: "git status".into(),
                },
            },
            SharedCase {
                name: "non-command tool",
                tool_name: "view_file",
                input: serde_json::json!({"path": "README.md"}),
                expected: ToolArgumentExtraction::NonCommand,
            },
            SharedCase {
                name: "multiple command keys fail closed",
                tool_name: "run_command",
                input: serde_json::json!({"command": "safe", "script": "ambiguous"}),
                expected: ToolArgumentExtraction::MalformedOrUnrecognized {
                    raw: serde_json::json!({"command": "safe", "script": "ambiguous"}),
                    reason:
                        "Unrecognized, empty, or malformed arguments for command tool 'run_command'"
                            .into(),
                },
            },
            SharedCase {
                name: "non-string array member fails closed",
                tool_name: "run_command",
                input: serde_json::json!({"args": ["git", 42]}),
                expected: ToolArgumentExtraction::MalformedOrUnrecognized {
                    raw: serde_json::json!({"args": ["git", 42]}),
                    reason:
                        "Unrecognized, empty, or malformed arguments for command tool 'run_command'"
                            .into(),
                },
            },
        ];

        for case in cases {
            let expected_command = match &case.expected {
                ToolArgumentExtraction::Command { command } => Some(command.clone()),
                ToolArgumentExtraction::NonCommand
                | ToolArgumentExtraction::MalformedOrUnrecognized { .. } => None,
            };
            let expected = (expected_command, case.expected);
            let codex = crate::runtime::adapter::codex::normalize_tool_call_arguments(
                case.tool_name,
                &case.input,
            );
            let agy = crate::runtime::adapter::agy::normalize_tool_call_arguments(
                case.tool_name,
                &case.input,
            );

            assert_eq!(codex, agy, "provider mismatch for {}", case.name);
            assert_eq!(codex, expected, "contract mismatch for {}", case.name);
        }
    }

    #[test]
    fn provider_hook_tool_call_arguments_require_object_roots() {
        for input in [
            serde_json::json!("not-an-object"),
            serde_json::Value::Null,
            serde_json::json!(["echo", "hello"]),
            serde_json::json!(42),
            serde_json::json!(true),
        ] {
            let error = validate_provider_tool_call_arguments("Bash", &input)
                .expect_err("non-object provider hook arguments must be rejected");
            assert!(error.to_string().contains("must be a JSON object"));
        }

        assert!(
            validate_provider_tool_call_arguments(
                "Bash",
                &serde_json::json!({"command": "echo hello"})
            )
            .is_ok()
        );
    }
}

/// Appends aggregate feedback once while preserving the provider's decision context.
pub(super) fn append_aggregate_feedback(existing: Option<String>, aggregate: &str) -> String {
    match existing {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}\n\n{aggregate}"),
        _ => aggregate.to_owned(),
    }
}
