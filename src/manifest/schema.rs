use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

pub const DECISION_EVALUATION_TIMEOUT_SECONDS: u64 = 180;
pub const DEFAULT_DECISION_TIMEOUT_SECONDS: u64 = 300;
pub const PROVIDER_HOOK_TERMINATION_GRACE_SECONDS: u64 = 5;
pub const MAX_PROVIDER_HOOK_TIMEOUT_SECONDS: u64 = 86_400;
pub const HOOK_TIMEOUT_MARGIN_SECONDS: u64 =
    DECISION_EVALUATION_TIMEOUT_SECONDS + PROVIDER_HOOK_TERMINATION_GRACE_SECONDS;
pub const MAX_DECISION_TIMEOUT_SECONDS: u64 =
    MAX_PROVIDER_HOOK_TIMEOUT_SECONDS - HOOK_TIMEOUT_MARGIN_SECONDS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(
        default = "default_decision_timeout_seconds",
        deserialize_with = "deserialize_decision_timeout_seconds"
    )]
    pub decision_timeout_seconds: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            decision_timeout_seconds: DEFAULT_DECISION_TIMEOUT_SECONDS,
        }
    }
}

impl RuntimeConfig {
    pub fn hook_timeout_seconds(&self) -> u64 {
        self.decision_timeout_seconds
            .saturating_add(HOOK_TIMEOUT_MARGIN_SECONDS)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !(1..=MAX_DECISION_TIMEOUT_SECONDS).contains(&self.decision_timeout_seconds) {
            anyhow::bail!(
                "runtime.decision_timeout_seconds must be between 1 and {MAX_DECISION_TIMEOUT_SECONDS}"
            );
        }
        Ok(())
    }
}

fn default_decision_timeout_seconds() -> u64 {
    DEFAULT_DECISION_TIMEOUT_SECONDS
}

fn deserialize_decision_timeout_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let seconds = u64::deserialize(deserializer)?;
    if !(1..=MAX_DECISION_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(serde::de::Error::custom(format!(
            "decision timeout must be between 1 and {MAX_DECISION_TIMEOUT_SECONDS} seconds"
        )));
    }
    Ok(seconds)
}

/// Root Arc configuration file (`arc.yaml`) according to Schema `1.0`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArcManifest {
    pub schema: String,
    pub root: RootConfig,

    #[serde(default)]
    pub runtime: RuntimeConfig,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modules: Option<BTreeMap<String, PathBuf>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skills: Option<BTreeMap<String, SkillDeclaration>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<BTreeMap<String, RoleConfig>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guards: Option<GuardsConfig>,
}

/// Workspace configuration, defining workspace boundary and optional instruction file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    pub workdir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<PathBuf>,
}

/// A skill declaration, which can be a single leaf skill or a recursive skill group (H5, M6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillDeclaration {
    Group {
        description: Option<String>,
        members: BTreeMap<String, SkillDeclaration>,
    },
    Single(SkillItem),
}

impl Serialize for SkillDeclaration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(item) => item.serialize(serializer),
            Self::Group {
                description,
                members,
            } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(None)?;
                if let Some(desc) = description {
                    map.serialize_entry("description", desc)?;
                }
                map.serialize_entry("members", members)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for SkillDeclaration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let root = yaml_serde::Value::deserialize(deserializer)?;
        parse_skill_declaration_iterative(root).map_err(D::Error::custom)
    }
}

fn parse_skill_declaration_iterative(root: yaml_serde::Value) -> Result<SkillDeclaration, String> {
    struct GroupTask {
        node_id: usize,
        description: Option<String>,
        members: Vec<(String, usize)>,
    }

    let mut results: Vec<Option<SkillDeclaration>> = vec![None];
    let mut pending = vec![(0_usize, root)];
    let mut groups = Vec::new();

    while let Some((node_id, value)) = pending.pop() {
        let mut map = match value {
            yaml_serde::Value::Mapping(map) => map,
            _ => return Err("Skill declaration must be a YAML mapping".into()),
        };
        if map.is_empty() {
            return Err("Skill declaration cannot be empty".into());
        }

        let members_key = yaml_serde::Value::String("members".into());
        let src_key = yaml_serde::Value::String("src".into());
        let description_key = yaml_serde::Value::String("description".into());
        let has_members = map.contains_key(&members_key);
        let has_src = map.contains_key(&src_key);
        if has_members && has_src {
            return Err(
                "Ambiguous skill declaration: cannot contain both 'members' and 'src'".into(),
            );
        }

        if has_members {
            for key in map.keys() {
                let Some(key) = key.as_str() else {
                    return Err("Skill declaration keys must be strings".into());
                };
                if key != "members" && key != "description" {
                    return Err(format!(
                        "Unknown field '{}' in skill group declaration",
                        key
                    ));
                }
            }
            let description = map
                .get(&description_key)
                .map(|value| yaml_serde::from_value::<String>(value.clone()))
                .transpose()
                .map_err(|error| error.to_string())?;
            let members_value = map
                .remove(&members_key)
                .ok_or_else(|| "Skill group is missing members".to_string())?;
            let yaml_serde::Value::Mapping(members_map) = members_value else {
                return Err("Skill group members must be a YAML mapping".into());
            };
            let mut member_ids = Vec::with_capacity(members_map.len());
            for (name, child_value) in members_map {
                let name = name
                    .as_str()
                    .ok_or_else(|| "Skill member names must be strings".to_string())?
                    .to_string();
                let child_id = results.len();
                results.push(None);
                member_ids.push((name, child_id));
                pending.push((child_id, child_value));
            }
            groups.push(GroupTask {
                node_id,
                description,
                members: member_ids,
            });
        } else if has_src {
            for key in map.keys() {
                let Some(key) = key.as_str() else {
                    return Err("Skill declaration keys must be strings".into());
                };
                if key != "src" && key != "description" {
                    return Err(format!(
                        "Unknown field '{}' in single skill declaration",
                        key
                    ));
                }
            }
            let item: SkillItem = yaml_serde::from_value(yaml_serde::Value::Mapping(map))
                .map_err(|error| error.to_string())?;
            results[node_id] = Some(SkillDeclaration::Single(item));
        } else {
            return Err(
                "Invalid skill declaration: mapping must contain either 'src' or 'members'".into(),
            );
        }
    }

    for group in groups.into_iter().rev() {
        let mut members = BTreeMap::new();
        for (name, child_id) in group.members {
            let child = results
                .get_mut(child_id)
                .and_then(Option::take)
                .ok_or_else(|| format!("Skill member '{}' was not parsed", name))?;
            members.insert(name, child);
        }
        results[group.node_id] = Some(SkillDeclaration::Group {
            description: group.description,
            members,
        });
    }

    results
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| "Root skill declaration was not parsed".into())
}

/// A leaf skill item pointing to a source directory inside the workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillItem {
    pub description: String,
    pub src: PathBuf,
}

/// A role configuration defining a role descriptor and optional source document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<PathBuf>,
}

/// Module file representing `skills.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillsModule {
    pub schema: String,
    pub skills: BTreeMap<String, SkillDeclaration>,
}

/// Module file representing `roles.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RolesModule {
    pub schema: String,
    pub roles: BTreeMap<String, RoleConfig>,
}

/// Module file representing `guards.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardsModule {
    pub schema: String,
    pub guards: GuardsConfig,
}

/// Guards declaration section.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardsConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_ordered_lifecycle_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub lifecycle: BTreeMap<String, LifecycleGuardConfig>,

    #[serde(
        default,
        deserialize_with = "deserialize_ordered_tool_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub tools: BTreeMap<String, ToolGuardConfig>,
}

fn deserialize_ordered_lifecycle_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, LifecycleGuardConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedLifecycleMapVisitor;

    impl<'de> serde::de::Visitor<'de> for OrderedLifecycleMapVisitor {
        type Value = BTreeMap<String, LifecycleGuardConfig>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of lifecycle guards")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            let mut idx = 0;
            while let Some((key, mut guard)) =
                access.next_entry::<String, LifecycleGuardConfig>()?
            {
                guard.declaration_order = idx;
                idx += 1;
                map.insert(key, guard);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(OrderedLifecycleMapVisitor)
}

fn deserialize_ordered_tool_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, ToolGuardConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedToolMapVisitor;

    impl<'de> serde::de::Visitor<'de> for OrderedToolMapVisitor {
        type Value = BTreeMap<String, ToolGuardConfig>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of tool guards")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            let mut idx = 0;
            while let Some((key, mut guard)) = access.next_entry::<String, ToolGuardConfig>()? {
                guard.declaration_order = idx;
                idx += 1;
                map.insert(key, guard);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(OrderedToolMapVisitor)
}

/// Lifecycle Guard configuration activated by lifecycle triggers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleGuardConfig {
    pub trigger: TriggerSelector,
    pub require: RuleExpression,
    pub on_failure: OnFailureConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,
    #[serde(default, skip_serializing)]
    pub declaration_order: usize,
}

/// Tool Guard configuration activated by matching `tool_call` events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolGuardConfig {
    pub matches: MatcherConfig,
    pub require: RuleExpression,
    pub on_failure: OnFailureConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,
    #[serde(default, skip_serializing)]
    pub declaration_order: usize,
}

/// Lifecycle trigger selector, accepting either a single trigger string or a list of triggers (H5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerSelector {
    Single(LifecycleTrigger),
    Multiple(Vec<LifecycleTrigger>),
}

impl Serialize for TriggerSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(t) => t.serialize(serializer),
            Self::Multiple(vec) => vec.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for TriggerSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let val = yaml_serde::Value::deserialize(deserializer)?;
        match val {
            yaml_serde::Value::String(_) => {
                let t: LifecycleTrigger = yaml_serde::from_value(val).map_err(D::Error::custom)?;
                Ok(TriggerSelector::Single(t))
            }
            yaml_serde::Value::Sequence(_) => {
                let vec: Vec<LifecycleTrigger> =
                    yaml_serde::from_value(val).map_err(D::Error::custom)?;
                if vec.is_empty() {
                    return Err(D::Error::custom("Trigger list cannot be empty"));
                }
                Ok(TriggerSelector::Multiple(vec))
            }
            _ => Err(D::Error::custom(
                "Expected a trigger string ('start'/'end') or a non-empty list of triggers",
            )),
        }
    }
}

impl TriggerSelector {
    pub fn to_vec(&self) -> Vec<LifecycleTrigger> {
        match self {
            Self::Single(t) => vec![t.clone()],
            Self::Multiple(list) => list.clone(),
        }
    }
}

/// Recognized lifecycle triggers for Schema `1.0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleTrigger {
    Start,
    End,
}

impl fmt::Display for LifecycleTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "start"),
            Self::End => write!(f, "end"),
        }
    }
}

/// Failure outcome configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OnFailureConfig {
    pub action: ActionType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
}

/// Supported failure actions for Schema `1.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Deny,
    Ask,
    Message,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "deny"),
            Self::Ask => write!(f, "ask"),
            Self::Message => write!(f, "message"),
        }
    }
}

/// Matcher configuration for Tool Guards (H5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatcherConfig {
    Alias { alias: String },
    Inline(InlineMatcher),
}

impl Serialize for MatcherConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Alias { alias } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("alias", alias)?;
                map.end()
            }
            Self::Inline(inline) => inline.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for MatcherConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let val = yaml_serde::Value::deserialize(deserializer)?;
        let map = match val {
            yaml_serde::Value::Mapping(m) => m,
            _ => return Err(D::Error::custom("MatcherConfig must be a YAML mapping")),
        };

        if map.is_empty() {
            return Err(D::Error::custom("MatcherConfig cannot be empty"));
        }

        let has_alias = map.contains_key(&yaml_serde::Value::String("alias".into()));
        let has_exact = map.contains_key(&yaml_serde::Value::String("exact".into()));
        let has_regex = map.contains_key(&yaml_serde::Value::String("regex".into()));

        if has_alias && (has_exact || has_regex) {
            return Err(D::Error::custom(
                "Ambiguous matcher: cannot combine 'alias' with inline 'exact' or 'regex' patterns",
            ));
        }

        if has_alias {
            for k in map.keys() {
                if let Some(s) = k.as_str() {
                    if s != "alias" {
                        return Err(D::Error::custom(format!(
                            "Unknown field '{}' in alias matcher configuration; only 'alias' is allowed",
                            s
                        )));
                    }
                }
            }
            let alias_val = map.get(&yaml_serde::Value::String("alias".into())).unwrap();
            let alias: String =
                yaml_serde::from_value(alias_val.clone()).map_err(D::Error::custom)?;
            if alias.trim().is_empty() {
                return Err(D::Error::custom("Matcher alias cannot be empty"));
            }
            Ok(MatcherConfig::Alias { alias })
        } else if has_exact || has_regex {
            for k in map.keys() {
                if let Some(s) = k.as_str() {
                    if s != "exact" && s != "regex" {
                        return Err(D::Error::custom(format!(
                            "Unknown field '{}' in inline matcher; only 'exact' and 'regex' are allowed",
                            s
                        )));
                    }
                }
            }
            let inline: InlineMatcher = yaml_serde::from_value(yaml_serde::Value::Mapping(map))
                .map_err(D::Error::custom)?;
            if inline.is_empty() {
                return Err(D::Error::custom(
                    "Inline matcher cannot be empty; must specify at least one non-empty 'exact' or 'regex' pattern",
                ));
            }
            Ok(MatcherConfig::Inline(inline))
        } else {
            let keys: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .collect();
            Err(D::Error::custom(format!(
                "Invalid matcher configuration with fields {:?}: must contain either 'alias' or inline 'exact'/'regex'",
                keys
            )))
        }
    }
}

/// Inline command matcher supporting exact string matching and regex pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InlineMatcher {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<StringList>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<StringList>,
}

impl InlineMatcher {
    pub fn is_empty(&self) -> bool {
        let exact_empty = match &self.exact {
            None => true,
            Some(list) => {
                let vec = list.to_vec();
                vec.is_empty() || vec.iter().any(|s| s.trim().is_empty())
            }
        };
        let regex_empty = match &self.regex {
            None => true,
            Some(list) => {
                let vec = list.to_vec();
                vec.is_empty() || vec.iter().any(|s| s.trim().is_empty())
            }
        };
        exact_empty && regex_empty
    }

    pub fn has_empty_list(&self) -> bool {
        if let Some(list) = &self.exact {
            if list.to_vec().is_empty() || list.to_vec().iter().any(|s| s.trim().is_empty()) {
                return true;
            }
        }
        if let Some(list) = &self.regex {
            if list.to_vec().is_empty() || list.to_vec().iter().any(|s| s.trim().is_empty()) {
                return true;
            }
        }
        false
    }
}

/// Helper type to deserialize either a single String or a Vec<String> (H5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringList {
    Single(String),
    Multiple(Vec<String>),
}

impl Serialize for StringList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(s) => serializer.serialize_str(s),
            Self::Multiple(vec) => vec.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let val = yaml_serde::Value::deserialize(deserializer)?;
        match val {
            yaml_serde::Value::String(s) => {
                if s.trim().is_empty() {
                    return Err(D::Error::custom(
                        "String pattern cannot be empty or whitespace-only",
                    ));
                }
                Ok(StringList::Single(s))
            }
            yaml_serde::Value::Sequence(seq) => {
                let vec: Vec<String> = yaml_serde::from_value(yaml_serde::Value::Sequence(seq))
                    .map_err(D::Error::custom)?;
                if vec.is_empty() {
                    return Err(D::Error::custom("Pattern list cannot be empty"));
                }
                if vec.iter().any(|s| s.trim().is_empty()) {
                    return Err(D::Error::custom(
                        "Pattern list cannot contain empty or whitespace-only patterns",
                    ));
                }
                Ok(StringList::Multiple(vec))
            }
            _ => Err(D::Error::custom(
                "Expected a pattern string or a non-empty list of strings",
            )),
        }
    }
}

impl StringList {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(list) => list.clone(),
        }
    }
}

/// Rule expression grammar primitives for Schema `1.0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleExpression {
    RuleRef { rule: String },
    Probe { probe: ProbeConfig },
    Decide { decide: DecideConfig },
    All { all: Vec<RuleExpression> },
    Any { any: Vec<RuleExpression> },
    Not { not: Box<RuleExpression> },
}

impl Serialize for RuleExpression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::RuleRef { rule } => map.serialize_entry("rule", rule)?,
            Self::Probe { probe } => map.serialize_entry("probe", probe)?,
            Self::Decide { decide } => map.serialize_entry("decide", decide)?,
            Self::All { all } => map.serialize_entry("all", all)?,
            Self::Any { any } => map.serialize_entry("any", any)?,
            Self::Not { not } => map.serialize_entry("not", not)?,
        }
        map.end()
    }
}

#[derive(Debug, Clone, Copy)]
enum RuleExpressionComposite {
    All,
    Any,
    Not,
}

#[derive(Debug)]
enum RuleExpressionTask {
    Parse {
        node_id: usize,
        value: yaml_serde::Value,
    },
    Assemble {
        node_id: usize,
        kind: RuleExpressionComposite,
        child_ids: Vec<usize>,
    },
}

/// Parse a rule expression with an explicit work stack.
///
/// Rule expressions are supplied by the manifest and may be arbitrarily
/// nested.  Keeping the traversal on the heap prevents manifest-controlled
/// nesting from consuming the Rust call stack while retaining the schema's
/// strict one-operator-per-mapping rule.
fn parse_rule_expression_iterative(value: yaml_serde::Value) -> Result<RuleExpression, String> {
    let mut results: Vec<Option<RuleExpression>> = vec![None];
    let mut tasks = vec![RuleExpressionTask::Parse { node_id: 0, value }];

    while let Some(task) = tasks.pop() {
        match task {
            RuleExpressionTask::Parse { node_id, value } => {
                let map = match value {
                    yaml_serde::Value::Mapping(map) => map,
                    _ => return Err("Expected a mapping for rule expression".into()),
                };
                if map.is_empty() {
                    return Err("Rule expression mapping cannot be empty".into());
                }
                if map.len() > 1 {
                    let keys: Vec<String> = map
                        .keys()
                        .filter_map(|key| key.as_str().map(str::to_owned))
                        .collect();
                    return Err(format!(
                        "Rule expression must contain exactly one operator key, found multiple: {:?}",
                        keys
                    ));
                }

                let (key, value) = map
                    .into_iter()
                    .next()
                    .ok_or_else(|| "Rule expression mapping cannot be empty".to_string())?;
                let key = key
                    .as_str()
                    .ok_or_else(|| "Rule expression operator key must be a string".to_string())?;

                match key {
                    "rule" => {
                        let rule: String =
                            yaml_serde::from_value(value).map_err(|error| error.to_string())?;
                        results[node_id] = Some(RuleExpression::RuleRef { rule });
                    }
                    "probe" => {
                        let probe: ProbeConfig =
                            yaml_serde::from_value(value).map_err(|error| error.to_string())?;
                        results[node_id] = Some(RuleExpression::Probe { probe });
                    }
                    "decide" => {
                        let decide: DecideConfig =
                            yaml_serde::from_value(value).map_err(|error| error.to_string())?;
                        results[node_id] = Some(RuleExpression::Decide { decide });
                    }
                    "all" | "any" => {
                        let children = match value {
                            yaml_serde::Value::Sequence(children) => children,
                            _ => return Err(format!("Rule expression '{}' must be a list", key)),
                        };
                        let kind = if key == "all" {
                            RuleExpressionComposite::All
                        } else {
                            RuleExpressionComposite::Any
                        };
                        let mut child_ids = Vec::with_capacity(children.len());
                        let mut child_values = Vec::with_capacity(children.len());
                        for child in children {
                            let child_id = results.len();
                            results.push(None);
                            child_ids.push(child_id);
                            child_values.push((child_id, child));
                        }
                        tasks.push(RuleExpressionTask::Assemble {
                            node_id,
                            kind,
                            child_ids,
                        });
                        for (child_id, child) in child_values.into_iter().rev() {
                            tasks.push(RuleExpressionTask::Parse {
                                node_id: child_id,
                                value: child,
                            });
                        }
                    }
                    "not" => {
                        let child_id = results.len();
                        results.push(None);
                        tasks.push(RuleExpressionTask::Assemble {
                            node_id,
                            kind: RuleExpressionComposite::Not,
                            child_ids: vec![child_id],
                        });
                        tasks.push(RuleExpressionTask::Parse {
                            node_id: child_id,
                            value,
                        });
                    }
                    other => {
                        return Err(format!(
                            "Unknown rule expression operator '{}'. Expected one of: 'rule', 'probe', 'decide', 'all', 'any', 'not'",
                            other
                        ));
                    }
                }
            }
            RuleExpressionTask::Assemble {
                node_id,
                kind,
                child_ids,
            } => {
                let mut children = Vec::with_capacity(child_ids.len());
                for child_id in child_ids {
                    children.push(results[child_id].take().ok_or_else(|| {
                        "Rule expression child was not parsed before assembly".to_string()
                    })?);
                }
                results[node_id] = Some(match kind {
                    RuleExpressionComposite::All => RuleExpression::All { all: children },
                    RuleExpressionComposite::Any => RuleExpression::Any { any: children },
                    RuleExpressionComposite::Not => {
                        let child = children.into_iter().next().ok_or_else(|| {
                            "Rule expression 'not' requires one child".to_string()
                        })?;
                        RuleExpression::Not {
                            not: Box::new(child),
                        }
                    }
                });
            }
        }
    }

    results[0]
        .take()
        .ok_or_else(|| "Rule expression did not produce a result".to_string())
}

impl<'de> Deserialize<'de> for RuleExpression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let value = yaml_serde::Value::deserialize(deserializer)?;
        parse_rule_expression_iterative(value).map_err(D::Error::custom)
    }
}

/// Probe configuration obtaining active environment evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    #[serde(rename = "use")]
    pub use_op: ProbeUse,
    #[serde(rename = "in")]
    pub in_values: Vec<String>,
}

/// Probe operation, either a literal command string or an operation alias reference (H5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeUse {
    Command(String),
    Alias { alias: String },
}

impl Serialize for ProbeUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Command(cmd) => serializer.serialize_str(cmd),
            Self::Alias { alias } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("alias", alias)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ProbeUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let val = yaml_serde::Value::deserialize(deserializer)?;
        match val {
            yaml_serde::Value::String(s) => {
                if s.trim().is_empty() {
                    return Err(D::Error::custom("Probe command string cannot be empty"));
                }
                Ok(ProbeUse::Command(s))
            }
            yaml_serde::Value::Mapping(map) => {
                if map.is_empty() {
                    return Err(D::Error::custom("ProbeUse mapping cannot be empty"));
                }
                if let Some(alias_val) = map.get(&yaml_serde::Value::String("alias".into())) {
                    if map.len() > 1 {
                        let keys: Vec<String> = map
                            .keys()
                            .filter_map(|k| k.as_str().map(|s| s.to_string()))
                            .collect();
                        return Err(D::Error::custom(format!(
                            "ProbeUse alias mapping cannot contain extra keys: {:?}",
                            keys
                        )));
                    }
                    let alias: String =
                        yaml_serde::from_value(alias_val.clone()).map_err(D::Error::custom)?;
                    if alias.trim().is_empty() {
                        return Err(D::Error::custom("Probe alias cannot be empty"));
                    }
                    Ok(ProbeUse::Alias { alias })
                } else {
                    let keys: Vec<String> = map
                        .keys()
                        .filter_map(|k| k.as_str().map(|s| s.to_string()))
                        .collect();
                    Err(D::Error::custom(format!(
                        "Invalid probe use mapping with keys {:?}: expected 'alias: <name>'",
                        keys
                    )))
                }
            }
            _ => Err(D::Error::custom(
                "Invalid probe use: expected a command string or an 'alias: <name>' mapping",
            )),
        }
    }
}

/// Model-backed decision configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecideConfig {
    pub prompt: String,
}

/// Conventional `rules.yaml` file manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulesManifest {
    pub schema: String,
    #[serde(default)]
    pub rules: BTreeMap<String, RuleExpression>,
}

/// Conventional `aliases.yaml` file manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AliasesManifest {
    pub schema: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matchers: Option<BTreeMap<String, MatcherAliasEntry>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<BTreeMap<String, OperationAliasEntry>>,
}

/// A matcher alias entry in `aliases.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MatcherAliasEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<AliasVariant<InlineMatcher>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<InlineMatcher>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<InlineMatcher>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<InlineMatcher>,
}

impl MatcherAliasEntry {
    pub fn is_pure_universal(&self) -> bool {
        self.default.is_some()
            && self.windows.is_none()
            && self.linux.is_none()
            && self.macos.is_none()
    }

    pub fn get_os_matcher(&self, os: &str) -> Option<&InlineMatcher> {
        match os {
            "windows" => self.windows.as_ref().or_else(|| self.get_default_matcher()),
            "linux" => self.linux.as_ref().or_else(|| self.get_default_matcher()),
            "macos" => self.macos.as_ref().or_else(|| self.get_default_matcher()),
            _ => self.get_default_matcher(),
        }
    }

    fn get_default_matcher(&self) -> Option<&InlineMatcher> {
        match &self.default {
            Some(AliasVariant::Concrete(im)) => Some(im),
            Some(AliasVariant::Set { set }) => match set.as_str() {
                "windows" => self.windows.as_ref(),
                "linux" => self.linux.as_ref(),
                "macos" => self.macos.as_ref(),
                _ => None,
            },
            None => None,
        }
    }
}

/// An operation alias entry in `aliases.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationAliasEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<AliasVariant<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<String>,
}

impl OperationAliasEntry {
    pub fn is_pure_universal(&self) -> bool {
        self.default.is_some()
            && self.windows.is_none()
            && self.linux.is_none()
            && self.macos.is_none()
    }

    pub fn get_os_operation(&self, os: &str) -> Option<String> {
        match os {
            "windows" => self
                .windows
                .clone()
                .or_else(|| self.get_default_operation()),
            "linux" => self.linux.clone().or_else(|| self.get_default_operation()),
            "macos" => self.macos.clone().or_else(|| self.get_default_operation()),
            _ => self.get_default_operation(),
        }
    }

    fn get_default_operation(&self) -> Option<String> {
        match &self.default {
            Some(AliasVariant::Concrete(cmd)) => Some(cmd.clone()),
            Some(AliasVariant::Set { set }) => match set.as_str() {
                "windows" => self.windows.clone(),
                "linux" => self.linux.clone(),
                "macos" => self.macos.clone(),
                _ => None,
            },
            None => None,
        }
    }
}

/// An alias variant which is either a concrete definition or a `set: <os>` redirect (H5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasVariant<T> {
    Set { set: String },
    Concrete(T),
}

impl<T: Serialize> Serialize for AliasVariant<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Set { set } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("set", set)?;
                map.end()
            }
            Self::Concrete(c) => c.serialize(serializer),
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for AliasVariant<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let val = yaml_serde::Value::deserialize(deserializer)?;
        if let yaml_serde::Value::Mapping(ref map) = val {
            if let Some(set_val) = map.get(&yaml_serde::Value::String("set".into())) {
                if map.len() > 1 {
                    let keys: Vec<String> = map
                        .keys()
                        .filter_map(|k| k.as_str().map(|s| s.to_string()))
                        .collect();
                    return Err(D::Error::custom(format!(
                        "AliasVariant 'set' redirect mapping cannot contain extra fields: {:?}",
                        keys
                    )));
                }
                let set: String =
                    yaml_serde::from_value(set_val.clone()).map_err(D::Error::custom)?;
                let valid_os = ["windows", "linux", "macos"];
                if !valid_os.contains(&set.as_str()) {
                    return Err(D::Error::custom(format!(
                        "Invalid OS target '{}' in 'set' redirect; must be one of: {:?}",
                        set, valid_os
                    )));
                }
                return Ok(AliasVariant::Set { set });
            }
        }
        let concrete: T = yaml_serde::from_value(val).map_err(D::Error::custom)?;
        Ok(AliasVariant::Concrete(concrete))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_minimal_arc_yaml() {
        let yaml = r#"
schema: '1.0'
root:
  workdir: 'arc'
"#;
        let manifest: ArcManifest = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(manifest.schema, "1.0");
        assert_eq!(manifest.root.workdir, PathBuf::from("arc"));
        assert!(manifest.root.instructions.is_none());
        assert_eq!(manifest.runtime.decision_timeout_seconds, 300);
    }

    #[test]
    fn decision_timeout_is_configurable_and_strictly_bounded() {
        let configured: ArcManifest = yaml_serde::from_str(
            "schema: '1.0'\nroot:\n  workdir: arc\nruntime:\n  decision_timeout_seconds: 45\n",
        )
        .unwrap();
        assert_eq!(configured.runtime.decision_timeout_seconds, 45);

        for invalid in [0_u64, 86_216] {
            let yaml = format!(
                "schema: '1.0'\nroot:\n  workdir: arc\nruntime:\n  decision_timeout_seconds: {invalid}\n"
            );
            assert!(yaml_serde::from_str::<ArcManifest>(&yaml).is_err());
        }
    }

    #[test]
    fn test_deserialize_lifecycle_and_tool_guards() {
        let yaml = r#"
schema: '1.0'
root:
  workdir: 'arc'
  instructions: 'instructions.md'

guards:
  lifecycle:
    safe_start:
      trigger: start
      require:
        not:
          probe:
            use:
              alias: git.branch.current
            in:
              - main
      on_failure:
        action: deny
        feedback: "Cannot start on main"
      order: 10

  tools:
    protected_push:
      matches:
        alias: git.push.force
      require:
        rule: force_push.allowed
      on_failure:
        action: deny
      order: 5
"#;
        let manifest: ArcManifest = yaml_serde::from_str(yaml).unwrap();
        let guards = manifest.guards.unwrap();
        assert_eq!(guards.lifecycle.len(), 1);
        assert_eq!(guards.tools.len(), 1);

        let safe_start = guards.lifecycle.get("safe_start").unwrap();
        assert_eq!(safe_start.trigger.to_vec(), vec![LifecycleTrigger::Start]);
        assert_eq!(safe_start.order, Some(10));
        assert_eq!(safe_start.on_failure.action, ActionType::Deny);

        let protected_push = guards.tools.get("protected_push").unwrap();
        assert_eq!(protected_push.order, Some(5));
        match &protected_push.matches {
            MatcherConfig::Alias { alias } => assert_eq!(alias, "git.push.force"),
            _ => panic!("Expected alias matcher"),
        }
    }

    #[test]
    fn test_deserialize_rules_yaml() {
        let yaml = r#"
schema: '1.0'
rules:
  valid.state:
    not:
      probe:
        use: 'git rev-parse --abbrev-ref HEAD'
        in:
          - main

  explicitly.authorized:
    decide:
      prompt: "Is this authorized?"

  safe.op:
    all:
      - rule: valid.state
      - rule: explicitly.authorized
"#;
        let rules_manifest: RulesManifest = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(rules_manifest.schema, "1.0");
        assert_eq!(rules_manifest.rules.len(), 3);
    }

    #[test]
    fn test_deserialize_deny_unknown_fields() {
        let yaml = r#"
schema: '1.0'
root:
  workdir: 'arc'
  invalid_field: 123
"#;
        let res: Result<ArcManifest, _> = yaml_serde::from_str(yaml);
        assert!(res.is_err());
    }

    #[test]
    fn test_deserialize_rule_expression_ambiguous_or_unknown_rejected() {
        let yaml_ambiguous = r#"
rule: valid.state
decide:
  prompt: "ambiguous"
"#;
        let res: Result<RuleExpression, _> = yaml_serde::from_str(yaml_ambiguous);
        assert!(res.is_err());

        let yaml_unknown = r#"
unknown_op: "something"
"#;
        let res2: Result<RuleExpression, _> = yaml_serde::from_str(yaml_unknown);
        assert!(res2.is_err());
    }

    #[test]
    fn test_deserialize_message_action() {
        let yaml = r#"
action: message
feedback: "Advisory only"
"#;
        let failure_cfg: OnFailureConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(failure_cfg.action, ActionType::Message);
        assert_eq!(failure_cfg.feedback.as_deref(), Some("Advisory only"));
    }

    #[test]
    fn deeply_nested_skill_groups_parse_without_call_recursion() {
        let mut value = yaml_serde::Value::Mapping(yaml_serde::Mapping::from_iter([
            (
                yaml_serde::Value::String("description".into()),
                yaml_serde::Value::String("leaf".into()),
            ),
            (
                yaml_serde::Value::String("src".into()),
                yaml_serde::Value::String("leaf".into()),
            ),
        ]));
        for index in 0..4_000 {
            let mut members = yaml_serde::Mapping::new();
            members.insert(yaml_serde::Value::String(format!("level_{index}")), value);
            let mut group = yaml_serde::Mapping::new();
            group.insert(
                yaml_serde::Value::String("members".into()),
                yaml_serde::Value::Mapping(members),
            );
            value = yaml_serde::Value::Mapping(group);
        }

        let declaration = parse_skill_declaration_iterative(value).unwrap();
        {
            let mut current = &declaration;
            for _ in 0..4_000 {
                let SkillDeclaration::Group { members, .. } = current else {
                    panic!("expected nested group");
                };
                current = members.values().next().unwrap();
            }
            assert!(matches!(current, SkillDeclaration::Single(_)));
        }
        std::mem::forget(declaration);
    }

    #[test]
    fn deeply_nested_rule_expressions_deserialize_without_call_recursion() {
        let mut value = yaml_serde::Value::Mapping(yaml_serde::Mapping::from_iter([(
            yaml_serde::Value::String("rule".into()),
            yaml_serde::Value::String("leaf".into()),
        )]));
        for _ in 0..4_000 {
            value = yaml_serde::Value::Mapping(yaml_serde::Mapping::from_iter([(
                yaml_serde::Value::String("not".into()),
                value,
            )]));
        }

        let expression = parse_rule_expression_iterative(value).unwrap();
        let mut current = &expression;
        for _ in 0..4_000 {
            let RuleExpression::Not { not } = current else {
                panic!("expected nested not expression");
            };
            current = not;
        }
        assert!(matches!(current, RuleExpression::RuleRef { rule } if rule == "leaf"));
        std::mem::forget(expression);
    }
}
