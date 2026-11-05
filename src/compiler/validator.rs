use anyhow::{Result, bail};
use std::collections::{BTreeMap, HashSet};

use crate::ir::NormalizedSkill;
use crate::manifest::loader::LoadedArcProject;
use crate::manifest::schema::{
    AliasVariant, AliasesManifest, GuardsConfig, LifecycleGuardConfig, MatcherConfig, ProbeUse,
    RuleExpression, RulesManifest, ToolGuardConfig,
};

pub struct SemanticValidator;

impl SemanticValidator {
    /// Validates all semantic invariants of a loaded Arc project before lowering.
    pub fn validate_project(project: &LoadedArcProject) -> Result<()> {
        // 1. Validate rules graph (if rules.yaml exists)
        if let Some(ref rules_manifest) = project.rules {
            Self::validate_rules_manifest(rules_manifest)?;
        }

        // 2. Validate aliases (if aliases.yaml exists)
        if let Some(ref aliases_manifest) = project.aliases {
            Self::validate_aliases_manifest(aliases_manifest)?;
        }

        // 3. Validate guards
        Self::validate_guards(
            &project.guards,
            project.rules.as_ref(),
            project.aliases.as_ref(),
        )?;

        // 4. Validate all rule references in rules.yaml resolve and don't refer to nonexistent aliases
        if let Some(ref rules_manifest) = project.rules {
            for (rule_name, expr) in &rules_manifest.rules {
                Self::validate_rule_expression_refs(
                    expr,
                    &format!("Rule '{}'", rule_name),
                    Some(rules_manifest),
                    project.aliases.as_ref(),
                )?;
            }
        }

        Ok(())
    }

    /// Validates project semantic compatibility against a specific target provider.
    pub fn validate_project_for_provider(
        project: &LoadedArcProject,
        provider: crate::target::ProviderTarget,
    ) -> Result<()> {
        let diagnostics = crate::target::check_project_compatibility(project, provider);
        if !diagnostics.is_empty() {
            let error_msgs: Vec<String> = diagnostics
                .into_iter()
                .map(|d| format!("  - {}", d))
                .collect();
            bail!(
                "Provider capability validation failed for target '{}':\n{}",
                provider,
                error_msgs.join("\n")
            );
        }
        Ok(())
    }

    /// Validates guards configuration invariants.
    pub fn validate_guards(
        guards: &GuardsConfig,
        rules: Option<&RulesManifest>,
        aliases: Option<&AliasesManifest>,
    ) -> Result<()> {
        // Validate lifecycle guards
        for (name, guard) in &guards.lifecycle {
            Self::validate_lifecycle_guard(name, guard, rules, aliases)?;
        }

        // Validate tool guards
        for (name, guard) in &guards.tools {
            Self::validate_tool_guard(name, guard, rules, aliases)?;
        }

        Ok(())
    }

    fn validate_lifecycle_guard(
        name: &str,
        guard: &LifecycleGuardConfig,
        rules: Option<&RulesManifest>,
        aliases: Option<&AliasesManifest>,
    ) -> Result<()> {
        // Validate order range 0..100
        if let Some(order) = guard.order {
            if order > 100 {
                bail!(
                    "Lifecycle Guard '{}' has invalid order {}. Must be in range 0..100",
                    name,
                    order
                );
            }
        }

        let triggers = guard.trigger.to_vec();
        if triggers.is_empty() {
            bail!(
                "Lifecycle Guard '{}' must declare at least one lifecycle trigger",
                name
            );
        }
        if guard.on_failure.action == crate::manifest::schema::ActionType::Ask
            && triggers.contains(&crate::manifest::schema::LifecycleTrigger::Start)
        {
            bail!(
                "Lifecycle Guard '{}' is invalid: trigger 'start' cannot use on_failure.action 'ask'",
                name
            );
        }

        // Validate require rule expression
        Self::validate_rule_expression_refs(
            &guard.require,
            &format!("Lifecycle Guard '{}'", name),
            rules,
            aliases,
        )?;

        Ok(())
    }

    fn validate_tool_guard(
        name: &str,
        guard: &ToolGuardConfig,
        rules: Option<&RulesManifest>,
        aliases: Option<&AliasesManifest>,
    ) -> Result<()> {
        // Validate order range 0..100
        if let Some(order) = guard.order {
            if order > 100 {
                bail!(
                    "Tool Guard '{}' has invalid order {}. Must be in range 0..100",
                    name,
                    order
                );
            }
        }

        // Validate matcher
        match &guard.matches {
            MatcherConfig::Alias { alias } => {
                let aliases_manifest = aliases.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Tool Guard '{}' references matcher alias '{}' but 'aliases.yaml' does not exist",
                        name,
                        alias
                    )
                })?;

                let matchers = aliases_manifest.matchers.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Tool Guard '{}' references matcher alias '{}' but no 'matchers' section exists in 'aliases.yaml'",
                        name,
                        alias
                    )
                })?;

                if !matchers.contains_key(alias) {
                    bail!(
                        "Tool Guard '{}' references unknown matcher alias '{}' in 'aliases.yaml'",
                        name,
                        alias
                    );
                }
            }
            MatcherConfig::Inline(matcher) => {
                if matcher.is_empty() {
                    bail!(
                        "Tool Guard '{}' has an empty matcher. At least one of 'exact' or 'regex' must be provided with non-empty patterns",
                        name
                    );
                }
                if matcher.has_empty_list() {
                    bail!(
                        "Tool Guard '{}' contains an empty or whitespace-only pattern list in exact or regex matcher",
                        name
                    );
                }
                if let Some(ref regexes) = matcher.regex {
                    for pat in regexes.to_vec() {
                        Self::validate_re2_compatible_regex(
                            &pat,
                            &format!("Tool Guard '{}'", name),
                        )?;
                    }
                }
            }
        }

        // Validate require rule expression
        Self::validate_rule_expression_refs(
            &guard.require,
            &format!("Tool Guard '{}'", name),
            rules,
            aliases,
        )?;

        Ok(())
    }

    /// Iteratively validates that rule references and alias references in a rule expression exist (M6).
    pub fn validate_rule_expression_refs(
        root_expr: &RuleExpression,
        context: &str,
        rules: Option<&RulesManifest>,
        aliases: Option<&AliasesManifest>,
    ) -> Result<()> {
        let mut stack = vec![root_expr];
        while let Some(expr) = stack.pop() {
            match expr {
                RuleExpression::RuleRef { rule } => {
                    let rules_manifest = rules.ok_or_else(|| {
                        anyhow::anyhow!(
                            "{} references reusable rule '{}' but 'rules.yaml' does not exist",
                            context,
                            rule
                        )
                    })?;

                    if !rules_manifest.rules.contains_key(rule) {
                        bail!(
                            "{} references unknown rule '{}' in 'rules.yaml'",
                            context,
                            rule
                        );
                    }
                }
                RuleExpression::Probe { probe } => {
                    if let ProbeUse::Alias { alias } = &probe.use_op {
                        let aliases_manifest = aliases.ok_or_else(|| {
                            anyhow::anyhow!(
                                "{} probe references operation alias '{}' but 'aliases.yaml' does not exist",
                                context,
                                alias
                            )
                        })?;

                        let operations = aliases_manifest.operations.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "{} probe references operation alias '{}' but no 'operations' section exists in 'aliases.yaml'",
                                context,
                                alias
                            )
                        })?;

                        if !operations.contains_key(alias) {
                            bail!(
                                "{} probe references unknown operation alias '{}' in 'aliases.yaml'",
                                context,
                                alias
                            );
                        }
                    }
                }
                RuleExpression::Decide { .. } => {}
                RuleExpression::All { all } => {
                    for child in all.iter().rev() {
                        stack.push(child);
                    }
                }
                RuleExpression::Any { any } => {
                    for child in any.iter().rev() {
                        stack.push(child);
                    }
                }
                RuleExpression::Not { not } => {
                    stack.push(not);
                }
            }
        }

        Ok(())
    }

    /// Validates reusable rules in `rules.yaml` including dependency cycle detection (L2).
    pub fn validate_rules_manifest(manifest: &RulesManifest) -> Result<()> {
        // Build dependency adjacency map and check reference existence
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (rule_name, expr) in &manifest.rules {
            let mut refs = Vec::new();
            Self::collect_rule_refs(expr, &mut refs);
            for r in &refs {
                if !manifest.rules.contains_key(*r) {
                    bail!(
                        "Rule '{}' references unknown reusable rule '{}' in 'rules.yaml'",
                        rule_name,
                        r
                    );
                }
            }
            adj.insert(rule_name.as_str(), refs);
        }

        // Cycle detection using DFS
        let mut visited = HashSet::new();
        let mut rec_stack = Vec::new();

        for &node in adj.keys() {
            if !visited.contains(node) {
                Self::detect_cycle(node, &adj, &mut visited, &mut rec_stack)?;
            }
        }

        Ok(())
    }

    fn collect_rule_refs<'a>(root_expr: &'a RuleExpression, refs: &mut Vec<&'a str>) {
        let mut stack = vec![root_expr];
        while let Some(expr) = stack.pop() {
            match expr {
                RuleExpression::RuleRef { rule } => refs.push(rule.as_str()),
                RuleExpression::Probe { .. } | RuleExpression::Decide { .. } => {}
                RuleExpression::All { all } => {
                    for child in all.iter().rev() {
                        stack.push(child);
                    }
                }
                RuleExpression::Any { any } => {
                    for child in any.iter().rev() {
                        stack.push(child);
                    }
                }
                RuleExpression::Not { not } => {
                    stack.push(not);
                }
            }
        }
    }

    fn detect_cycle<'a>(
        node: &'a str,
        adj: &BTreeMap<&'a str, Vec<&'a str>>,
        visited: &mut HashSet<&'a str>,
        rec_stack: &mut Vec<&'a str>,
    ) -> Result<()> {
        let mut frames: Vec<(&'a str, usize)> = vec![(node, 0)];
        visited.insert(node);
        rec_stack.push(node);

        while let Some((current, next_neighbor)) = frames.last_mut() {
            let neighbors = adj.get(current).map(Vec::as_slice).unwrap_or(&[]);
            if *next_neighbor >= neighbors.len() {
                rec_stack.pop();
                frames.pop();
                continue;
            }

            let neighbor = neighbors[*next_neighbor];
            *next_neighbor += 1;
            if !visited.contains(neighbor) {
                visited.insert(neighbor);
                rec_stack.push(neighbor);
                frames.push((neighbor, 0));
            } else if let Some(cycle_start) = rec_stack.iter().position(|&name| name == neighbor) {
                let cycle_path: Vec<&str> = rec_stack[cycle_start..].to_vec();
                bail!(
                    "Cyclic rule dependency detected: {} -> {}",
                    cycle_path.join(" -> "),
                    neighbor
                );
            }
        }

        Ok(())
    }

    /// Validates `aliases.yaml` structure (default.set target validity, regex correctness, non-empty matchers).
    pub fn validate_aliases_manifest(manifest: &AliasesManifest) -> Result<()> {
        if let Some(ref matchers) = manifest.matchers {
            for (alias_name, entry) in matchers {
                if let Some(AliasVariant::Set { ref set }) = entry.default {
                    let valid_os = match set.as_str() {
                        "windows" => entry.windows.is_some(),
                        "linux" => entry.linux.is_some(),
                        "macos" => entry.macos.is_some(),
                        other => bail!(
                            "Matcher alias '{}': invalid 'default.set' value '{}'. Must be one of 'windows', 'linux', 'macos'",
                            alias_name,
                            other
                        ),
                    };
                    if !valid_os {
                        bail!(
                            "Matcher alias '{}': 'default.set' targets '{}' which is not defined in this alias",
                            alias_name,
                            set
                        );
                    }
                }

                // Validate each inline matcher in alias variants
                let check_matcher = |im: &crate::manifest::schema::InlineMatcher,
                                     variant_name: &str|
                 -> Result<()> {
                    if im.is_empty() {
                        bail!(
                            "Matcher alias '{}' ({}) is empty. At least one of 'exact' or 'regex' must be provided",
                            alias_name,
                            variant_name
                        );
                    }
                    if im.has_empty_list() {
                        bail!(
                            "Matcher alias '{}' ({}) contains an empty pattern list",
                            alias_name,
                            variant_name
                        );
                    }
                    if let Some(ref regexes) = im.regex {
                        for pat in regexes.to_vec() {
                            Self::validate_re2_compatible_regex(
                                &pat,
                                &format!("Matcher alias '{}' ({})", alias_name, variant_name),
                            )?;
                        }
                    }
                    Ok(())
                };

                if let Some(AliasVariant::Concrete(ref im)) = entry.default {
                    check_matcher(im, "default")?;
                }
                if let Some(ref im) = entry.windows {
                    check_matcher(im, "windows")?;
                }
                if let Some(ref im) = entry.linux {
                    check_matcher(im, "linux")?;
                }
                if let Some(ref im) = entry.macos {
                    check_matcher(im, "macos")?;
                }
            }
        }

        if let Some(ref operations) = manifest.operations {
            for (alias_name, entry) in operations {
                if let Some(AliasVariant::Set { ref set }) = entry.default {
                    let valid_os = match set.as_str() {
                        "windows" => entry.windows.is_some(),
                        "linux" => entry.linux.is_some(),
                        "macos" => entry.macos.is_some(),
                        other => bail!(
                            "Operation alias '{}': invalid 'default.set' value '{}'. Must be one of 'windows', 'linux', 'macos'",
                            alias_name,
                            other
                        ),
                    };
                    if !valid_os {
                        bail!(
                            "Operation alias '{}': 'default.set' targets '{}' which is not defined in this alias",
                            alias_name,
                            set
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates skill identifiers against path traversal, forbidden characters, and collisions (H4).
    pub fn validate_skills_normalization(skills: &[NormalizedSkill]) -> Result<()> {
        let mut seen_normalized: BTreeMap<String, String> = BTreeMap::new();

        for skill in skills {
            // Check for path traversal or forbidden separators in skill id
            if skill.id.contains('/')
                || skill.id.contains('\\')
                || skill.id.contains("..")
                || skill.id.starts_with('.')
            {
                bail!(
                    "Skill identifier '{}' is invalid: contains forbidden path traversal characters or separators",
                    skill.id
                );
            }

            if !skill
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                bail!(
                    "Skill identifier '{}' contains invalid characters. Only alphanumeric, '_' and '-' are allowed",
                    skill.id
                );
            }

            let normalized = skill.canonical_name();
            if let Some(previous) =
                seen_normalized.insert(normalized.clone(), skill.display_name.clone())
            {
                bail!(
                    "Skill identifier normalization collision: '{}' and '{}' both produce canonical name '{}'",
                    previous,
                    skill.display_name,
                    normalized,
                );
            }
        }

        Ok(())
    }

    /// Validates that a regex pattern complies with the RE2 linear-time contract (M10).
    pub fn validate_re2_compatible_regex(pat: &str, context: &str) -> Result<()> {
        // 1. Reject non-RE2 constructs (lookaheads, lookbehinds)
        if pat.contains("(?=")
            || pat.contains("(?!")
            || pat.contains("(?<=")
            || pat.contains("(?<!")
        {
            bail!(
                "{} has regex pattern '{}' containing lookaround assertions, which are not supported by the RE2 linear-time contract",
                context,
                pat
            );
        }

        // 2. Reject backreferences \1..\9
        let bytes = pat.as_bytes();
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == b'\\' && bytes[i + 1].is_ascii_digit() && bytes[i + 1] != b'0' {
                let is_escaped = i > 0 && bytes[i - 1] == b'\\';
                if !is_escaped {
                    bail!(
                        "{} has regex pattern '{}' containing backreference '\\{}', which is not supported by the RE2 linear-time contract",
                        context,
                        pat,
                        bytes[i + 1] as char
                    );
                }
            }
        }

        // 3. RE2 standard parsing via regex crate
        regex::Regex::new(pat).map_err(|e| {
            anyhow::anyhow!("{} has invalid regex pattern '{}': {}", context, pat, e)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{ActionType, LifecycleTrigger};
    use std::path::PathBuf;

    #[test]
    fn test_cycle_detection() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "rule_a".to_string(),
            RuleExpression::RuleRef {
                rule: "rule_b".to_string(),
            },
        );
        rules.insert(
            "rule_b".to_string(),
            RuleExpression::RuleRef {
                rule: "rule_c".to_string(),
            },
        );
        rules.insert(
            "rule_c".to_string(),
            RuleExpression::RuleRef {
                rule: "rule_a".to_string(),
            },
        );

        let manifest = RulesManifest {
            schema: "1.0".to_string(),
            rules,
        };

        let result = SemanticValidator::validate_rules_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cyclic rule dependency")
        );
    }

    #[test]
    fn test_valid_dag_rules() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "rule_a".to_string(),
            RuleExpression::Decide {
                decide: crate::manifest::schema::DecideConfig {
                    prompt: "test".into(),
                },
            },
        );
        rules.insert(
            "rule_b".to_string(),
            RuleExpression::RuleRef {
                rule: "rule_a".to_string(),
            },
        );
        rules.insert(
            "rule_c".to_string(),
            RuleExpression::All {
                all: vec![
                    RuleExpression::RuleRef {
                        rule: "rule_a".to_string(),
                    },
                    RuleExpression::RuleRef {
                        rule: "rule_b".to_string(),
                    },
                ],
            },
        );

        let manifest = RulesManifest {
            schema: "1.0".to_string(),
            rules,
        };

        assert!(SemanticValidator::validate_rules_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let guard = ToolGuardConfig {
            matches: MatcherConfig::Inline(crate::manifest::schema::InlineMatcher {
                exact: None,
                regex: Some(crate::manifest::schema::StringList::Single("[a-z".into())), // Unclosed bracket
            }),
            require: RuleExpression::Decide {
                decide: crate::manifest::schema::DecideConfig { prompt: "p".into() },
            },
            on_failure: crate::manifest::schema::OnFailureConfig {
                action: ActionType::Deny,
                feedback: None,
            },
            order: None,
            declaration_order: 0,
        };

        let mut tools = BTreeMap::new();
        tools.insert("bad_regex".to_string(), guard);

        let guards = GuardsConfig {
            lifecycle: BTreeMap::new(),
            tools,
        };

        let result = SemanticValidator::validate_guards(&guards, None, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid regex pattern")
        );
    }

    #[test]
    fn test_skill_id_traversal_rejected() {
        let bad_skill = NormalizedSkill {
            id: "../../../../escape".into(),
            display_name: "escape".into(),
            description: "bad".into(),
            source_path: PathBuf::from("escape"),
            content: String::new(),
        };

        let result = SemanticValidator::validate_skills_normalization(&[bad_skill]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("forbidden path traversal")
        );
    }

    #[test]
    fn rejects_leaf_and_group_skill_names_with_the_same_canonical_name() {
        let skills = [
            NormalizedSkill {
                id: "rust-dev".into(),
                display_name: "skills.rust-dev".into(),
                description: "leaf".into(),
                source_path: PathBuf::from("rust-dev.md"),
                content: String::new(),
            },
            NormalizedSkill {
                id: "rust-dev".into(),
                display_name: "skills.rust.members.dev".into(),
                description: "group member".into(),
                source_path: PathBuf::from("rust/dev.md"),
                content: String::new(),
            },
        ];

        let error = SemanticValidator::validate_skills_normalization(&skills)
            .expect_err("canonical skill collision must fail before emission");
        let message = error.to_string();
        assert!(message.contains("skills.rust-dev"));
        assert!(message.contains("skills.rust.members.dev"));
        assert!(message.contains("rust-dev"));
    }

    #[test]
    fn rejects_deep_grouping_ambiguity_after_flattening() {
        let skills = [
            NormalizedSkill {
                id: "rust-dev-test".into(),
                display_name: "skills.rust-dev.members.test".into(),
                description: "first grouping".into(),
                source_path: PathBuf::from("rust-dev/test.md"),
                content: String::new(),
            },
            NormalizedSkill {
                id: "rust-dev-test".into(),
                display_name: "skills.rust.members.dev-test".into(),
                description: "second grouping".into(),
                source_path: PathBuf::from("rust/dev-test.md"),
                content: String::new(),
            },
        ];

        let error = SemanticValidator::validate_skills_normalization(&skills)
            .expect_err("deep canonical skill collision must fail");
        assert!(error.to_string().contains("rust-dev-test"));
    }

    #[test]
    fn test_empty_matcher_list_rejected() {
        let guard = ToolGuardConfig {
            matches: MatcherConfig::Inline(crate::manifest::schema::InlineMatcher {
                exact: Some(crate::manifest::schema::StringList::Multiple(vec![])),
                regex: None,
            }),
            require: RuleExpression::Decide {
                decide: crate::manifest::schema::DecideConfig { prompt: "p".into() },
            },
            on_failure: crate::manifest::schema::OnFailureConfig {
                action: ActionType::Deny,
                feedback: None,
            },
            order: None,
            declaration_order: 0,
        };

        let mut tools = BTreeMap::new();
        tools.insert("empty_matcher".to_string(), guard);

        let guards = GuardsConfig {
            lifecycle: BTreeMap::new(),
            tools,
        };

        let result = SemanticValidator::validate_guards(&guards, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn lifecycle_start_ask_is_rejected_before_provider_validation() {
        let guard = LifecycleGuardConfig {
            trigger: crate::manifest::schema::TriggerSelector::Multiple(vec![
                LifecycleTrigger::End,
                LifecycleTrigger::Start,
            ]),
            require: RuleExpression::Decide {
                decide: crate::manifest::schema::DecideConfig { prompt: "p".into() },
            },
            on_failure: crate::manifest::schema::OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("ask user".into()),
            },
            order: None,
            declaration_order: 0,
        };

        let mut lifecycle = BTreeMap::new();
        lifecycle.insert("bad_lifecycle_ask".to_string(), guard);

        let guards = GuardsConfig {
            lifecycle,
            tools: BTreeMap::new(),
        };

        let result = SemanticValidator::validate_guards(&guards, None, None);
        let error = result.expect_err("start + ask must be invalid for every provider");
        assert!(error.to_string().contains("start"));
        assert!(error.to_string().contains("ask"));
    }

    #[test]
    fn test_m10_strict_re2_regex_validation() {
        // 1. Valid RE2 patterns pass
        assert!(SemanticValidator::validate_re2_compatible_regex(r"^git\s+push", "test").is_ok());
        assert!(SemanticValidator::validate_re2_compatible_regex(r".*\.rs$", "test").is_ok());
        assert!(
            SemanticValidator::validate_re2_compatible_regex(r"[a-zA-Z0-9_-]+", "test").is_ok()
        );

        // 2. Lookahead / lookbehind assertions fail
        let lookahead = SemanticValidator::validate_re2_compatible_regex(r"git(?=push)", "test");
        assert!(lookahead.is_err(), "Lookahead must be rejected");
        assert!(
            lookahead
                .unwrap_err()
                .to_string()
                .contains("lookaround assertions")
        );

        let lookbehind = SemanticValidator::validate_re2_compatible_regex(r"(?<=git)push", "test");
        assert!(lookbehind.is_err(), "Lookbehind must be rejected");

        // 3. Backreferences fail
        let backref = SemanticValidator::validate_re2_compatible_regex(r"(a)\1", "test");
        assert!(backref.is_err(), "Backreference must be rejected");
        assert!(backref.unwrap_err().to_string().contains("backreference"));

        // 4. Invalid regex syntax fails
        let invalid = SemanticValidator::validate_re2_compatible_regex(r"[a-z", "test");
        assert!(invalid.is_err(), "Invalid syntax must fail");
    }
}
