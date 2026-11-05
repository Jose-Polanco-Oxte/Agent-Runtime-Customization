use base64::Engine;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::emitters::traits::GeneratedArtifact;
use crate::ir::{BoundLifecycleGuard, BoundToolGuard};
use crate::manifest::schema::LifecycleTrigger;
use crate::manifest::schema::RuntimeConfig;
use crate::target::{DecisionUiMode, OsTarget, ProviderTarget};

pub struct HooksEmitter;

impl HooksEmitter {
    /// Emits the `.agents/hooks.json` artifact mapping active guards to AGY hook handlers.
    pub fn emit_hooks(
        lifecycle_guards: &[BoundLifecycleGuard],
        tool_guards: &[BoundToolGuard],
        target_os: &OsTarget,
        decision_ui: DecisionUiMode,
        custom_arc_bin: Option<&str>,
        runtime: &RuntimeConfig,
    ) -> Option<GeneratedArtifact> {
        let arc_cmd = custom_arc_bin
            .map(|s| s.to_string())
            .or_else(|| std::env::var("ARC_BIN").ok())
            .unwrap_or_else(|| "arc".to_string());
        let command = |event: &str| {
            let arguments = format!(
                "hook run --event-type {event} --provider gemini --decision-ui {decision_ui} --ir-path .agents/arc_ir.json"
            );
            if target_os.as_str() == OsTarget::WINDOWS {
                windows_hook_command(&arc_cmd, &arguments)
            } else {
                // Single quotes disable shell expansions; the splice handles a
                // literal apostrophe without changing the executable argument.
                format!("'{}' {arguments}", arc_cmd.replace('\'', "'\"'\"'"))
            }
        };

        let mut root = BTreeMap::new();

        // 1. PreToolUse Hook (if tool guards exist) - Grouped with matcher
        if !tool_guards.is_empty() {
            root.insert(
                "PreToolUse",
                json!([
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": command("pre-tool-use"),
                                "timeout": runtime.hook_timeout_seconds()
                            }
                        ]
                    }
                ]),
            );
        }

        // Check lifecycle triggers
        let has_start = lifecycle_guards
            .iter()
            .any(|g| g.triggers.contains(&LifecycleTrigger::Start));

        let has_end = lifecycle_guards
            .iter()
            .any(|g| g.triggers.contains(&LifecycleTrigger::End));

        // 2. PreInvocation Hook - Flat array (first turn start)
        if has_start {
            root.insert(
                "PreInvocation",
                json!([
                    {
                        "type": "command",
                        "command": command("pre-invocation"),
                        "timeout": runtime.hook_timeout_seconds()
                    }
                ]),
            );
        }

        // 3. Stop Hook - Flat array
        if has_end {
            root.insert(
                "Stop",
                json!([
                    {
                        "type": "command",
                        "command": command("stop"),
                        "timeout": runtime.hook_timeout_seconds()
                    }
                ]),
            );
        }

        if root.is_empty() {
            return None;
        }

        root.insert("enabled", json!(true));

        let group_object: serde_json::Map<String, Value> =
            root.into_iter().map(|(k, v)| (k.to_string(), v)).collect();

        let mut group_wrapper = serde_json::Map::new();
        group_wrapper.insert("arc-runtime".to_string(), Value::Object(group_object));

        let content =
            serde_json::to_string_pretty(&Value::Object(group_wrapper)).expect("Valid hooks JSON");

        Some(GeneratedArtifact {
            provider: ProviderTarget::Gemini,
            target_os: target_os.clone(),
            relative_path: PathBuf::from(".agents/hooks.json"),
            content,
            is_executable: false,
        })
    }
}

fn windows_hook_command(executable: &str, arguments: &str) -> String {
    if !executable.is_empty()
        && executable
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '\\' | '.' | ':'))
    {
        return format!("{executable} {arguments}");
    }

    // cmd expands %variables% even inside quotes, and can expand !variables!
    // when delayed expansion is enabled. An encoded PowerShell launcher keeps
    // the executable literal through either shell. Process.Start inherits the
    // standard handles; routing JSON through a PowerShell pipeline would alter
    // its encoding and line endings. Only Arc's fixed arguments are passed.
    let literal = executable.replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';\
         $p=[System.Diagnostics.Process]::new();\
         $p.StartInfo.FileName='{literal}';\
         $p.StartInfo.Arguments='{arguments}';\
         $p.StartInfo.UseShellExecute=$false;\
         try{{[void]$p.Start();$p.WaitForExit();exit $p.ExitCode}}\
         finally{{$p.Dispose()}}"
    );
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    format!("powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BoundMatcher, BoundRuleExpression};
    use crate::manifest::schema::{ActionType, OnFailureConfig};

    #[test]
    fn test_hooks_json_emission() {
        let tool_guards = vec![BoundToolGuard {
            id: "guard_push".into(),
            matcher: BoundMatcher::default(),
            require: BoundRuleExpression::Decide {
                prompt: "ok?".into(),
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: None,
            },
            order: 0,
            declaration_order: 0,
        }];

        let lifecycle_guards = vec![BoundLifecycleGuard {
            id: "guard_end".into(),
            triggers: vec![LifecycleTrigger::End],
            require: BoundRuleExpression::Decide {
                prompt: "clean?".into(),
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: None,
            },
            order: 0,
            declaration_order: 0,
        }];

        let runtime = RuntimeConfig {
            decision_timeout_seconds: 37,
        };
        let artifact = HooksEmitter::emit_hooks(
            &lifecycle_guards,
            &tool_guards,
            &OsTarget::new("windows").expect("windows is a valid test OS"),
            DecisionUiMode::Auto,
            None,
            &runtime,
        )
        .unwrap();

        assert_eq!(artifact.relative_path, PathBuf::from(".agents/hooks.json"));
        assert!(artifact.content.contains("PreToolUse"));
        assert!(artifact.content.contains("Stop"));
        assert!(!artifact.content.contains("PostInvocation"));
        assert!(artifact.content.contains("\"timeout\": 222"));
    }
}
