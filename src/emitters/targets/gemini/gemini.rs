use anyhow::{Context, Result, bail};
use std::path::PathBuf;

use crate::emitters::targets::gemini::agents_md::AgentsMdEmitter;
use crate::emitters::targets::gemini::hooks_emitter::HooksEmitter;
use crate::emitters::targets::gemini::skills_emitter::SkillsEmitter;
use crate::emitters::traits::{EmissionContext, GeneratedArtifact, TargetEmitter};
use crate::ir::BehaviorIR;
use crate::target::{
    CapabilityContext, CapabilityEvent, CapabilityLevel, ProviderTarget, resolve_capability,
};

pub struct GeminiEmitter;

impl TargetEmitter for GeminiEmitter {
    fn provider(&self) -> ProviderTarget {
        ProviderTarget::Gemini
    }

    fn emit(&self, ir: &BehaviorIR, ctx: &EmissionContext) -> Result<Vec<GeneratedArtifact>> {
        validate_capability_contract(ir, ctx)?;
        let mut artifacts = Vec::new();

        // 1. Emit compiled IR artifact: .agents/arc_ir.json
        let ir_json =
            serde_json::to_string_pretty(ir).context("Failed serializing BehaviorIR to JSON")?;
        artifacts.push(GeneratedArtifact {
            provider: ProviderTarget::Gemini,
            target_os: ctx.target_os.clone(),
            relative_path: PathBuf::from(".agents/arc_ir.json"),
            content: ir_json,
            is_executable: false,
        });

        // 2. Emit .agents/AGENTS.md
        let agents_md = AgentsMdEmitter::emit(&ir.context, &ctx.target_os);
        artifacts.push(agents_md);

        // 3. Emit .agents/skills/<id>/SKILL.md
        let skill_artifacts = SkillsEmitter::emit_skills(&ir.skills, &ctx.target_os)?;
        artifacts.extend(skill_artifacts);

        // 4. Emit .agents/hooks.json (if guards are active)
        if let Some(hooks_artifact) = HooksEmitter::emit_hooks(
            &ir.lifecycle_guards,
            &ir.tool_guards,
            &ctx.target_os,
            ctx.decision_ui,
            ctx.arc_bin.as_deref(),
            &ir.runtime,
        ) {
            artifacts.push(hooks_artifact);
        }

        Ok(artifacts)
    }
}

fn validate_capability_contract(ir: &BehaviorIR, ctx: &EmissionContext) -> Result<()> {
    if ctx.provider != ProviderTarget::Gemini {
        bail!(
            "Gemini emitter received capability context for {}",
            ctx.provider
        );
    }
    for guard in &ir.lifecycle_guards {
        for trigger in &guard.triggers {
            let event = match trigger {
                crate::manifest::schema::LifecycleTrigger::Start => CapabilityEvent::Start,
                crate::manifest::schema::LifecycleTrigger::End => CapabilityEvent::End,
            };
            ensure_guard_resolution(&guard.id, guard.on_failure.action, event, ctx)?;
        }
    }
    for guard in &ir.tool_guards {
        ensure_guard_resolution(
            &guard.id,
            guard.on_failure.action,
            CapabilityEvent::ToolCall,
            ctx,
        )?;
    }
    Ok(())
}

fn ensure_guard_resolution(
    guard_id: &str,
    action: crate::manifest::schema::ActionType,
    event: CapabilityEvent,
    ctx: &EmissionContext,
) -> Result<()> {
    let resolution = resolve_capability(CapabilityContext {
        provider: ctx.provider,
        environment: ctx.environment,
        target_os: ctx.target_os.clone(),
        event,
        requested_action: action,
        decision_ui: ctx.decision_ui,
        decision_environment: ctx.decision_environment.clone(),
    });
    if resolution.capability == CapabilityLevel::Unsupported {
        bail!(
            "guard '{}' cannot be emitted for this context: {}",
            guard_id,
            resolution.mechanism
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::WorkspaceContext;
    use crate::target::OsTarget;
    use std::collections::BTreeMap;

    #[test]
    fn test_gemini_emitter_full() {
        let ir = BehaviorIR {
            schema: "1.0".into(),
            compiler_version: env!("CARGO_PKG_VERSION").into(),
            build_id: None,
            content_hash: None,
            runtime: Default::default(),
            context: WorkspaceContext {
                workdir: PathBuf::from("."),
                instructions_path: None,
                instructions_content: Some("Global instructions".into()),
                roles: BTreeMap::new(),
            },
            skills: Vec::new(),
            lifecycle_guards: Vec::new(),
            tool_guards: Vec::new(),
            rules: BTreeMap::new(),
        };

        let ctx = EmissionContext {
            provider: ProviderTarget::Gemini,
            target_os: OsTarget::new("windows").expect("windows is a valid test OS"),
            environment: crate::target::ProviderEnvironment::Cli,
            decision_ui: crate::target::DecisionUiMode::Auto,
            decision_environment: crate::target::DecisionEnvironment {
                provider_native: true,
                arc_embedded_ui: true,
                arc_owns_app_server_session: false,
                direct_mcp_channel: false,
            },
            base_output_path: PathBuf::from("."),
            is_multi_target: false,
            arc_bin: None,
        };

        let emitter = GeminiEmitter;
        let artifacts = emitter.emit(&ir, &ctx).unwrap();

        assert!(
            artifacts
                .iter()
                .any(|a| a.relative_path == PathBuf::from(".agents/arc_ir.json"))
        );
        assert!(
            artifacts
                .iter()
                .any(|a| a.relative_path == PathBuf::from(".agents/AGENTS.md"))
        );
    }
}
