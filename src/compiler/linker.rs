use anyhow::{Context, Result};
use std::collections::BTreeMap;

use crate::ir::{
    BoundLifecycleGuard, BoundMatcher, BoundProbeCommand, BoundRuleExpression, BoundToolGuard,
};
use crate::manifest::loader::LoadedArcProject;
use crate::manifest::schema::{AliasesManifest, MatcherConfig, ProbeUse, RuleExpression};

pub struct GuardLinker;

impl GuardLinker {
    /// Links lifecycle guards, tool guards, and reusable rules for a specified list of target OSes.
    pub fn link_project(
        project: &LoadedArcProject,
        target_os_list: &[String],
    ) -> Result<(
        Vec<BoundLifecycleGuard>,
        Vec<BoundToolGuard>,
        BTreeMap<String, BoundRuleExpression>,
    )> {
        let aliases = project.aliases.as_ref();

        // 1. Link Lifecycle Guards
        let mut lifecycle_guards = Vec::new();
        for (name, guard) in &project.guards.lifecycle {
            let bound_require = Self::link_rule_expression(&guard.require, aliases, target_os_list)
                .with_context(|| {
                    format!(
                        "Failed linking rule expression for Lifecycle Guard '{}'",
                        name
                    )
                })?;

            lifecycle_guards.push(BoundLifecycleGuard {
                id: name.clone(),
                triggers: guard.trigger.to_vec(),
                require: bound_require,
                on_failure: guard.on_failure.clone(),
                order: guard.order.unwrap_or(0),
                declaration_order: guard.declaration_order,
            });
        }
        // Deterministic sort: order ascending, then declaration order from YAML (L5)
        lifecycle_guards.sort_by_key(|g| (g.order, g.declaration_order));

        // 2. Link Tool Guards
        let mut tool_guards = Vec::new();
        for (name, guard) in &project.guards.tools {
            let bound_matcher = Self::link_matcher(&guard.matches, aliases, target_os_list)
                .with_context(|| format!("Failed linking matcher for Tool Guard '{}'", name))?;

            let bound_require = Self::link_rule_expression(&guard.require, aliases, target_os_list)
                .with_context(|| {
                    format!("Failed linking rule expression for Tool Guard '{}'", name)
                })?;

            tool_guards.push(BoundToolGuard {
                id: name.clone(),
                matcher: bound_matcher,
                require: bound_require,
                on_failure: guard.on_failure.clone(),
                order: guard.order.unwrap_or(0),
                declaration_order: guard.declaration_order,
            });
        }
        // Deterministic sort: order ascending, then declaration order from YAML (L5)
        tool_guards.sort_by_key(|g| (g.order, g.declaration_order));

        // 3. Link Reusable Rules
        let mut rules = BTreeMap::new();
        if let Some(ref rules_manifest) = project.rules {
            for (rule_name, expr) in &rules_manifest.rules {
                let bound_expr = Self::link_rule_expression(expr, aliases, target_os_list)
                    .with_context(|| format!("Failed linking reusable rule '{}'", rule_name))?;
                rules.insert(rule_name.clone(), bound_expr);
            }
        }

        Ok((lifecycle_guards, tool_guards, rules))
    }

    fn link_matcher(
        matcher_config: &MatcherConfig,
        aliases: Option<&AliasesManifest>,
        target_os_list: &[String],
    ) -> Result<BoundMatcher> {
        match matcher_config {
            MatcherConfig::Alias { alias } => {
                let aliases_manifest = aliases.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Matcher alias '{}' referenced but aliases.yaml not present",
                        alias
                    )
                })?;
                let entry = aliases_manifest
                    .matchers
                    .as_ref()
                    .and_then(|m| m.get(alias))
                    .ok_or_else(|| {
                        anyhow::anyhow!("Matcher alias '{}' not found in aliases.yaml", alias)
                    })?;

                // Pure universal check: only `default` is defined (concrete) and no specific OS variants
                if entry.is_pure_universal() {
                    if let Some(crate::manifest::schema::AliasVariant::Concrete(im)) =
                        &entry.default
                    {
                        return Ok(BoundMatcher {
                            exact_patterns: im
                                .exact
                                .as_ref()
                                .map(|l| l.to_vec())
                                .unwrap_or_default(),
                            regex_patterns: im
                                .regex
                                .as_ref()
                                .map(|l| l.to_vec())
                                .unwrap_or_default(),
                        });
                    }
                }

                // Platform-differentiated: every requested target OS must have a valid definition
                let mut exact_patterns = Vec::new();
                let mut regex_patterns = Vec::new();

                for os in target_os_list {
                    let os_matcher = entry.get_os_matcher(os).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Compilation failed for matcher alias '{}': Missing definition for target OS '{}'. \
                            When platform-specific variants are declared, all requested target OSes must be explicitly covered \
                            (or only declare 'default' to make the alias universal).",
                            alias,
                            os
                        )
                    })?;

                    if let Some(e) = &os_matcher.exact {
                        for p in e.to_vec() {
                            if !exact_patterns.contains(&p) {
                                exact_patterns.push(p);
                            }
                        }
                    }
                    if let Some(r) = &os_matcher.regex {
                        for p in r.to_vec() {
                            if !regex_patterns.contains(&p) {
                                regex_patterns.push(p);
                            }
                        }
                    }
                }

                Ok(BoundMatcher {
                    exact_patterns,
                    regex_patterns,
                })
            }
            MatcherConfig::Inline(inline) => Ok(BoundMatcher {
                exact_patterns: inline
                    .exact
                    .as_ref()
                    .map(|l| l.to_vec())
                    .unwrap_or_default(),
                regex_patterns: inline
                    .regex
                    .as_ref()
                    .map(|l| l.to_vec())
                    .unwrap_or_default(),
            }),
        }
    }

    /// Links a rule expression iteratively using an explicit heap stack (M6).
    pub fn link_rule_expression(
        root_expr: &RuleExpression,
        aliases: Option<&AliasesManifest>,
        target_os_list: &[String],
    ) -> Result<BoundRuleExpression> {
        enum LinkAction<'a> {
            Process(&'a RuleExpression),
            CombineAll(usize),
            CombineAny(usize),
            CombineNot,
        }

        let mut action_stack = vec![LinkAction::Process(root_expr)];
        let mut result_stack: Vec<BoundRuleExpression> = Vec::new();

        while let Some(action) = action_stack.pop() {
            match action {
                LinkAction::Process(expr) => match expr {
                    RuleExpression::RuleRef { rule } => {
                        result_stack.push(BoundRuleExpression::RuleRef { name: rule.clone() });
                    }
                    RuleExpression::Probe { probe } => {
                        let command =
                            Self::resolve_probe_command(&probe.use_op, aliases, target_os_list)?;
                        result_stack.push(BoundRuleExpression::Probe {
                            command,
                            expected_in: probe.in_values.clone(),
                        });
                    }
                    RuleExpression::Decide { decide } => {
                        result_stack.push(BoundRuleExpression::Decide {
                            prompt: decide.prompt.clone(),
                        });
                    }
                    RuleExpression::All { all } => {
                        action_stack.push(LinkAction::CombineAll(all.len()));
                        for child in all.iter().rev() {
                            action_stack.push(LinkAction::Process(child));
                        }
                    }
                    RuleExpression::Any { any } => {
                        action_stack.push(LinkAction::CombineAny(any.len()));
                        for child in any.iter().rev() {
                            action_stack.push(LinkAction::Process(child));
                        }
                    }
                    RuleExpression::Not { not } => {
                        action_stack.push(LinkAction::CombineNot);
                        action_stack.push(LinkAction::Process(not));
                    }
                },
                LinkAction::CombineAll(count) => {
                    let mut children = Vec::with_capacity(count);
                    for _ in 0..count {
                        children.push(result_stack.pop().expect("Stack underflow in CombineAll"));
                    }
                    children.reverse();
                    result_stack.push(BoundRuleExpression::All(children));
                }
                LinkAction::CombineAny(count) => {
                    let mut children = Vec::with_capacity(count);
                    for _ in 0..count {
                        children.push(result_stack.pop().expect("Stack underflow in CombineAny"));
                    }
                    children.reverse();
                    result_stack.push(BoundRuleExpression::Any(children));
                }
                LinkAction::CombineNot => {
                    let child = result_stack.pop().expect("Stack underflow in CombineNot");
                    result_stack.push(BoundRuleExpression::Not(Box::new(child)));
                }
            }
        }

        result_stack
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Empty result stack in link_rule_expression"))
    }

    fn resolve_probe_command(
        use_op: &ProbeUse,
        aliases: Option<&AliasesManifest>,
        target_os_list: &[String],
    ) -> Result<BoundProbeCommand> {
        match use_op {
            ProbeUse::Command(cmd) => Ok(BoundProbeCommand::Single(cmd.clone())),
            ProbeUse::Alias { alias } => {
                let aliases_manifest = aliases.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Operation alias '{}' referenced but aliases.yaml not present",
                        alias
                    )
                })?;

                let entry = aliases_manifest
                    .operations
                    .as_ref()
                    .and_then(|o| o.get(alias))
                    .ok_or_else(|| {
                        anyhow::anyhow!("Operation alias '{}' not found in aliases.yaml", alias)
                    })?;

                // Pure universal check: only `default` is defined (concrete) and no specific OS variants
                if entry.is_pure_universal() {
                    if let Some(crate::manifest::schema::AliasVariant::Concrete(cmd)) =
                        &entry.default
                    {
                        Ok(BoundProbeCommand::Single(cmd.clone()))
                    } else {
                        unreachable!()
                    }
                } else if target_os_list.len() == 1 {
                    let os = &target_os_list[0];
                    let cmd = entry.get_os_operation(os).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Compilation failed for operation alias '{}': Missing definition for target OS '{}'. \
                            When platform-specific variants are declared, all requested target OSes must be explicitly covered \
                            (or only declare 'default' to make the alias universal).",
                            alias,
                            os
                        )
                    })?;
                    Ok(BoundProbeCommand::Single(cmd))
                } else {
                    let mut os_map = BTreeMap::new();
                    for os in target_os_list {
                        let cmd = entry.get_os_operation(os).ok_or_else(|| {
                            anyhow::anyhow!(
                                "Compilation failed for operation alias '{}': Missing definition for target OS '{}'. \
                                When platform-specific variants are declared, all requested target OSes must be explicitly covered \
                                (or only declare 'default' to make the alias universal).",
                                alias,
                                os
                            )
                        })?;
                        os_map.insert(os.clone(), cmd);
                    }
                    Ok(BoundProbeCommand::MultiOs(os_map))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{
        AliasVariant, InlineMatcher, MatcherAliasEntry, OperationAliasEntry, ProbeConfig,
        StringList,
    };

    #[test]
    fn test_universal_alias_compilation() {
        let mut operations = BTreeMap::new();
        operations.insert(
            "universal.branch".to_string(),
            OperationAliasEntry {
                default: Some(AliasVariant::Concrete("git branch".to_string())),
                windows: None,
                linux: None,
                macos: None,
            },
        );

        let aliases = AliasesManifest {
            schema: "1.0".to_string(),
            matchers: None,
            operations: Some(operations),
        };

        let expr = RuleExpression::Probe {
            probe: ProbeConfig {
                use_op: ProbeUse::Alias {
                    alias: "universal.branch".to_string(),
                },
                in_values: vec!["main".to_string()],
            },
        };

        // Compiles for all OS without requiring individual definitions
        let all_targets = vec![
            "windows".to_string(),
            "linux".to_string(),
            "macos".to_string(),
        ];
        let bound = GuardLinker::link_rule_expression(&expr, Some(&aliases), &all_targets).unwrap();

        match bound {
            BoundRuleExpression::Probe { command, .. } => {
                assert_eq!(command, BoundProbeCommand::Single("git branch".to_string()));
            }
            _ => panic!("Expected BoundRuleExpression::Probe"),
        }
    }

    #[test]
    fn test_differentiated_alias_strict_failure_on_missing_os() {
        let mut operations = BTreeMap::new();
        operations.insert(
            "diff.privilege".to_string(),
            OperationAliasEntry {
                default: None,
                windows: Some("whoami /groups".to_string()),
                linux: Some("id -u".to_string()),
                macos: None, // Missing macos!
            },
        );

        let aliases = AliasesManifest {
            schema: "1.0".to_string(),
            matchers: None,
            operations: Some(operations),
        };

        let expr = RuleExpression::Probe {
            probe: ProbeConfig {
                use_op: ProbeUse::Alias {
                    alias: "diff.privilege".to_string(),
                },
                in_values: vec!["0".to_string()],
            },
        };

        // 1. Succeeds for windows
        let win_target = vec!["windows".to_string()];
        let bound_win =
            GuardLinker::link_rule_expression(&expr, Some(&aliases), &win_target).unwrap();
        assert_eq!(
            bound_win,
            BoundRuleExpression::Probe {
                command: BoundProbeCommand::Single("whoami /groups".to_string()),
                expected_in: vec!["0".to_string()]
            }
        );

        // 2. Succeeds for windows + linux
        let win_lin_targets = vec!["windows".to_string(), "linux".to_string()];
        let bound_multi =
            GuardLinker::link_rule_expression(&expr, Some(&aliases), &win_lin_targets).unwrap();
        let mut expected_map = BTreeMap::new();
        expected_map.insert("windows".to_string(), "whoami /groups".to_string());
        expected_map.insert("linux".to_string(), "id -u".to_string());
        assert_eq!(
            bound_multi,
            BoundRuleExpression::Probe {
                command: BoundProbeCommand::MultiOs(expected_map),
                expected_in: vec!["0".to_string()]
            }
        );

        // 3. Fails for macos
        let mac_target = vec!["macos".to_string()];
        let err_mac =
            GuardLinker::link_rule_expression(&expr, Some(&aliases), &mac_target).unwrap_err();
        assert!(
            err_mac
                .to_string()
                .contains("Missing definition for target OS 'macos'")
        );

        // 4. Fails for all
        let all_targets = vec![
            "windows".to_string(),
            "linux".to_string(),
            "macos".to_string(),
        ];
        let err_all =
            GuardLinker::link_rule_expression(&expr, Some(&aliases), &all_targets).unwrap_err();
        assert!(
            err_all
                .to_string()
                .contains("Missing definition for target OS 'macos'")
        );
    }

    #[test]
    fn test_matcher_alias_os_subsets() {
        let mut matchers = BTreeMap::new();
        matchers.insert(
            "del.cmd".to_string(),
            MatcherAliasEntry {
                default: None,
                windows: Some(InlineMatcher {
                    exact: None,
                    regex: Some(StringList::Single("Remove-Item.*".to_string())),
                }),
                linux: Some(InlineMatcher {
                    exact: None,
                    regex: Some(StringList::Single("rm -rf.*".to_string())),
                }),
                macos: Some(InlineMatcher {
                    exact: None,
                    regex: Some(StringList::Single("rm -rf.*".to_string())),
                }),
            },
        );

        let aliases = AliasesManifest {
            schema: "1.0".to_string(),
            matchers: Some(matchers),
            operations: None,
        };

        let config = MatcherConfig::Alias {
            alias: "del.cmd".to_string(),
        };

        // For windows only: only Windows regex
        let bound_win =
            GuardLinker::link_matcher(&config, Some(&aliases), &["windows".to_string()]).unwrap();
        assert_eq!(bound_win.regex_patterns, vec!["Remove-Item.*"]);

        // For windows + linux: union
        let bound_both = GuardLinker::link_matcher(
            &config,
            Some(&aliases),
            &["windows".to_string(), "linux".to_string()],
        )
        .unwrap();
        assert_eq!(bound_both.regex_patterns, vec!["Remove-Item.*", "rm -rf.*"]);
    }
}
