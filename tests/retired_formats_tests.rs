//! REQ-007: retired Arc formats are not accepted, read, migrated or deleted.
//!
//! The retired transport label is built by joining its words, so the literal
//! has zero matches in the source tree (AC-007.1).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc::ir::{BehaviorIR, BoundMatcher, BoundRuleExpression, BoundToolGuard, WorkspaceContext};
use arc::manifest::schema::OnFailureConfig;
use arc::{
    ActionType, ArcEvent, ArcEventType, ArcRuntimeSession, DecisionChoice, DecisionContractError,
    DecisionEnvironment, DecisionTransport, GeneratedArtifact, MockProbeRunner, ProviderTarget,
    SqliteStateStore, recover_pending_build, write_artifacts,
};
use sha2::{Digest, Sha256};

fn retired_transport_label() -> String {
    ["arc", "native", "egui"].join("_")
}

fn retired_const_name() -> String {
    ["LEGACY", "ARC", "EMBEDDED", "UI", "TRANSPORT", "LABEL"].join("_")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "arc_retired_formats_{tag}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Relative path (forward slashes) -> sha256 of the bytes, or "<dir>" for directories.
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).expect("read dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("inside root")
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                out.insert(relative, "<dir>".into());
                walk(root, &path, out);
            } else {
                out.insert(relative, sha256_hex(&fs::read(&path).expect("read file")));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn write_file(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    fs::write(path, bytes).expect("write file");
}

// ---------------------------------------------------------------------------
// AC-007.1: retired transport label
// ---------------------------------------------------------------------------

#[test]
fn current_transport_label_is_accepted_in_json_and_yaml_config() {
    let json: DecisionTransport = serde_json::from_str("\"arc_embedded_ui\"").expect("json");
    let yaml: DecisionTransport = yaml_serde::from_str("arc_embedded_ui").expect("yaml");
    assert_eq!(json, DecisionTransport::ArcEmbeddedUi);
    assert_eq!(yaml, DecisionTransport::ArcEmbeddedUi);
    assert_eq!(
        serde_json::to_string(&DecisionTransport::ArcEmbeddedUi).unwrap(),
        "\"arc_embedded_ui\""
    );
}

#[test]
fn retired_transport_label_in_json_config_is_rejected_naming_the_current_label() {
    let input = format!("\"{}\"", retired_transport_label());
    let error = serde_json::from_str::<DecisionTransport>(&input)
        .expect_err("retired transport label must not deserialize")
        .to_string();
    assert!(error.contains("unknown variant"), "{error}");
    assert!(error.contains("arc_embedded_ui"), "{error}");
}

#[test]
fn retired_transport_label_in_yaml_config_is_rejected_naming_the_current_label() {
    let error = yaml_serde::from_str::<DecisionTransport>(&retired_transport_label())
        .expect_err("retired transport label must not deserialize from yaml")
        .to_string();
    assert!(error.contains("arc_embedded_ui"), "{error}");
}

#[test]
fn retired_environment_key_in_config_is_rejected_naming_the_current_key() {
    let current = r#"{"provider_native":false,"arc_embedded_ui":true,"arc_owns_app_server_session":false,"direct_mcp_channel":false}"#;
    let environment: DecisionEnvironment = serde_json::from_str(current).expect("current key");
    assert!(environment.arc_embedded_ui);

    let retired = format!(
        r#"{{"provider_native":false,"{}":true,"arc_owns_app_server_session":false,"direct_mcp_channel":false}}"#,
        retired_transport_label()
    );
    let error = serde_json::from_str::<DecisionEnvironment>(&retired)
        .expect_err("retired environment key must not deserialize")
        .to_string();
    assert!(error.contains("arc_embedded_ui"), "{error}");
}

fn ask_request_and_dialog() -> (arc::InteractiveDecisionRequest, arc::DialogRequest) {
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
        tool_guards: vec![BoundToolGuard {
            id: "guard-ask-fail".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "git branch".into(),
                expected_in: vec!["feature".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("Branch is not feature".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };
    let probes = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
    let state_store = Arc::new(arc::InMemoryStateStore::default());
    let mut session = ArcRuntimeSession::new("req007-session", ir)
        .with_probe_runner(probes)
        .with_state_store(state_store);
    let observed = arc::HookObservationContext::new("codex", "req007-session", "inv-req007")
        .with_workspace("ws-req007");
    let event = ArcEvent::tool_call("req007-session", "ev-req007", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);
    let evaluation =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("evaluates");
    let request = arc::interactive_decision_request_from_evaluation_result(
        &evaluation,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-req007",
        Some(operation),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("builds request")
    .expect("some request");
    let dialog = request.to_dialog_request("REQ-007");
    (request, dialog)
}

fn response_with_label(dialog: &arc::DialogRequest, label: &str) -> arc::DialogResponse {
    arc::DialogResponse {
        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
        request_id: dialog.request_id.clone(),
        bundle_fingerprint: dialog.bundle_fingerprint.clone(),
        decision: arc::PortableDecision::Allow,
        transport: label.into(),
        theme: "dark".into(),
        message: None,
    }
}

#[test]
fn dialog_response_with_current_label_is_accepted_for_embedded_ui() {
    let (request, dialog) = ask_request_and_dialog();
    let resolution = arc::InteractiveDecisionResolution::from_dialog_response(
        request,
        response_with_label(&dialog, "arc_embedded_ui"),
        DecisionTransport::ArcEmbeddedUi,
    )
    .expect("current label is accepted");
    assert_eq!(resolution.transport_label(), "arc_embedded_ui");
}

#[test]
fn dialog_response_with_retired_label_is_rejected_naming_the_current_label() {
    let (request, dialog) = ask_request_and_dialog();
    let retired = retired_transport_label();
    let error = arc::InteractiveDecisionResolution::from_dialog_response(
        request,
        response_with_label(&dialog, &retired),
        DecisionTransport::ArcEmbeddedUi,
    )
    .expect_err("retired label must not be accepted");
    match &error {
        DecisionContractError::TransportLabelMismatch { transport, label } => {
            assert_eq!(*transport, "arc_embedded_ui");
            assert_eq!(label, &retired);
        }
        other => panic!("expected TransportLabelMismatch, got {other:?}"),
    }
    assert!(error.to_string().contains("arc_embedded_ui"), "{error}");
}

#[test]
fn retired_labels_have_zero_matches_in_sources_tests_and_architecture_doc() {
    fn visit(dir: &Path, hits: &mut Vec<String>, needles: &[String]) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let cargo_target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                // Skip only the cargo build dir at the repo root; nested `target`
                // directories such as src/target are real source and must be scanned.
                if path == cargo_target_dir || name == "node_modules" || name == "__pycache__" {
                    continue;
                }
                visit(&path, hits, needles);
                continue;
            }
            let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(extension, "rs" | "py" | "ps1" | "md") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for needle in needles {
                if text.contains(needle.as_str()) {
                    hits.push(format!("{} contains {needle}", path.display()));
                }
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let needles = vec![retired_transport_label(), retired_const_name()];
    let mut hits = Vec::new();
    visit(&root.join("src"), &mut hits, &needles);
    visit(&root.join("tests"), &mut hits, &needles);
    visit(&root.join("ui/decision/src-tauri/src"), &mut hits, &needles);
    if let Ok(text) = fs::read_to_string(root.join("docs/DECISION_UI_ARCHITECTURE.md")) {
        for needle in &needles {
            if text.contains(needle.as_str()) {
                hits.push(format!(
                    "docs/DECISION_UI_ARCHITECTURE.md contains {needle}"
                ));
            }
        }
    }
    assert!(hits.is_empty(), "retired labels still present: {hits:#?}");
}

// ---------------------------------------------------------------------------
// AC-007.2: retired decision choices
// ---------------------------------------------------------------------------

#[test]
fn current_decision_choices_are_accepted() {
    assert_eq!(
        serde_json::from_str::<DecisionChoice>("\"allow\"").unwrap(),
        DecisionChoice::Allow
    );
    assert_eq!(
        yaml_serde::from_str::<DecisionChoice>("deny").unwrap(),
        DecisionChoice::Deny
    );
}

#[test]
fn retired_remediate_choice_is_rejected_naming_allow_and_deny() {
    let error = serde_json::from_str::<DecisionChoice>("\"remediate\"")
        .expect_err("remediate is retired")
        .to_string();
    assert!(error.contains("unknown variant"), "{error}");
    assert!(error.contains("allow"), "{error}");
    assert!(error.contains("deny"), "{error}");
}

#[test]
fn retired_finish_anyway_choice_is_rejected_naming_allow_and_deny() {
    let error = serde_json::from_str::<DecisionChoice>("\"finish_anyway\"")
        .expect_err("finish_anyway is retired")
        .to_string();
    assert!(error.contains("allow"), "{error}");
    assert!(error.contains("deny"), "{error}");
}

#[test]
fn retired_choices_inside_a_choice_list_in_yaml_config_are_rejected() {
    let error = yaml_serde::from_str::<Vec<DecisionChoice>>("- allow\n- finish_anyway\n")
        .expect_err("a retired choice invalidates the whole list")
        .to_string();
    assert!(error.contains("allow"), "{error}");
    assert!(error.contains("deny"), "{error}");
    let error = yaml_serde::from_str::<Vec<DecisionChoice>>("- remediate\n")
        .expect_err("remediate is retired in yaml")
        .to_string();
    assert!(error.contains("deny"), "{error}");
}

// ---------------------------------------------------------------------------
// AC-007.3 / AC-007.5: writer ignores old locations and never touches them
// ---------------------------------------------------------------------------

fn artifact(relative: &str, content: &str) -> GeneratedArtifact {
    GeneratedArtifact {
        provider: ProviderTarget::Codex,
        target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
        relative_path: PathBuf::from(relative),
        content: content.into(),
        is_executable: false,
    }
}

const LEGACY_SKILL: &str = ".codex/skills/Old_Skill/SKILL.md";
const LEGACY_SKILL_ORIGINAL: &str = "---\nname: Old_Skill\n---\nas generated by an older Arc";
const LEGACY_SKILL_USER_EDIT: &str = "---\nname: Old_Skill\n---\nedited by the user, keep me";
const LEGACY_CAPABILITIES: &str = "arc-capabilities.json";
const LEGACY_CAPABILITIES_BYTES: &str = "{\"capabilities\":\"old location\"}\n";

/// Lays out state in the retired locations and formats; returns the paths created.
fn lay_out_old_format_state(root: &Path) -> Vec<&'static str> {
    let legacy_manifest = serde_json::json!({
        "schema_version": "1.0",
        "arc_version": "0.0.1-legacy",
        "generated_at": "2020-01-01T00:00:00Z",
        "artifacts": [
            {
                "relative_path": LEGACY_SKILL,
                "sha256": sha256_hex(LEGACY_SKILL_ORIGINAL.as_bytes()),
                "size_bytes": LEGACY_SKILL_ORIGINAL.len(),
                "is_executable": false
            },
            {
                "relative_path": LEGACY_CAPABILITIES,
                "sha256": sha256_hex(LEGACY_CAPABILITIES_BYTES.as_bytes()),
                "size_bytes": LEGACY_CAPABILITIES_BYTES.len(),
                "is_executable": false
            }
        ]
    });
    write_file(
        root,
        "build_manifest.json",
        &serde_json::to_vec_pretty(&legacy_manifest).unwrap(),
    );
    write_file(root, LEGACY_SKILL, LEGACY_SKILL_USER_EDIT.as_bytes());
    write_file(
        root,
        LEGACY_CAPABILITIES,
        LEGACY_CAPABILITIES_BYTES.as_bytes(),
    );
    write_file(
        root,
        ".tmp_backup_legacy01",
        b"backup bytes of an older Arc\n",
    );
    write_file(
        root,
        ".tmp_retire_backup_legacy01",
        b"retire backup bytes\n",
    );
    vec![
        "build_manifest.json",
        LEGACY_SKILL,
        LEGACY_CAPABILITIES,
        ".tmp_backup_legacy01",
        ".tmp_retire_backup_legacy01",
    ]
}

// Product owner decision 2026-11-01 (dod.md, Proposed deviations): a pending build
// journal at a retired old location is REJECTED by presence only, with a typed
// error that names the file. The file is never read, migrated or modified.
const OLD_TRANSACTION_JOURNAL: &str = ".arc-build-transaction.json";
const OLD_CLEANUP_JOURNAL: &str = ".arc-build-cleanup.json";
const OLD_JOURNALS: [&str; 2] = [OLD_TRANSACTION_JOURNAL, OLD_CLEANUP_JOURNAL];

/// Writes one old-location pending journal with the given bytes.
fn lay_out_old_journal(root: &Path, journal: &str, bytes: &[u8]) {
    write_file(root, journal, bytes);
}

fn plausible_old_journal_bytes(journal: &str) -> &'static [u8] {
    if journal == OLD_TRANSACTION_JOURNAL {
        b"{\"state\":\"COMMITTING\",\"note\":\"pending journal of an older Arc\"}\n"
    } else {
        b"{\"files\":[\".tmp_backup_legacy01\"]}\n"
    }
}

/// The type is checked by Debug name (like the DB tests) so this file compiles
/// before the type exists. The error must name the offending journal file.
fn assert_retired_journal_rejected(error: &anyhow::Error, journal: &str) {
    let root = format!("{:?}", error.root_cause());
    assert!(
        root.starts_with("RetiredBuildJournalRejected"),
        "error must be RetiredBuildJournalRejected, got: {error:#}"
    );
    assert!(
        root.contains(journal),
        "error must name {journal}, got debug: {root}"
    );
    for other in OLD_JOURNALS.iter().filter(|other| **other != journal) {
        assert!(
            !root.contains(other),
            "error must name only the offending journal {journal}, got debug: {root}"
        );
    }
}

fn assert_old_files_byte_identical(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    paths: &[&str],
) {
    for path in paths {
        assert!(before.contains_key(*path), "{path} was not laid out");
        assert_eq!(
            before.get(*path),
            after.get(*path),
            "{path} must exist and be byte-identical"
        );
    }
}

#[test]
fn build_over_old_format_state_without_journals_leaves_backups_and_user_files_byte_identical() {
    let dir = TempDir::new("writer_old_state");
    let root = dir.path();
    let legacy_paths = lay_out_old_format_state(root);
    let before = snapshot(root);

    let manifest = write_artifacts(
        root,
        &[
            artifact(
                ".codex/skills/old-skill/SKILL.md",
                "---\nname: old-skill\n---\nnew",
            ),
            artifact(
                ".arc/arc-capabilities.json",
                "{\"capabilities\":\"new location\"}\n",
            ),
        ],
    )
    .expect("old-format files are ignored, so the build succeeds");

    let after = snapshot(root);
    for path in &legacy_paths {
        assert_eq!(
            before.get(*path),
            after.get(*path),
            "{path} must exist and be byte-identical after the build"
        );
    }
    assert_eq!(
        fs::read_to_string(root.join(LEGACY_SKILL)).unwrap(),
        LEGACY_SKILL_USER_EDIT
    );

    // The old manifest is not a read path: its records do not reach the new manifest.
    let recorded: Vec<String> = manifest
        .artifacts
        .iter()
        .map(|record| record.relative_path.clone())
        .collect();
    assert_eq!(
        recorded.iter().collect::<std::collections::BTreeSet<_>>(),
        [
            ".arc/arc-capabilities.json".to_string(),
            ".codex/skills/old-skill/SKILL.md".to_string()
        ]
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
    );
    assert!(root.join(".arc/build_manifest.json").is_file());
    assert_eq!(
        fs::read_to_string(root.join(".codex/skills/old-skill/SKILL.md")).unwrap(),
        "---\nname: old-skill\n---\nnew"
    );
}

#[test]
fn build_over_old_manifest_whose_skill_still_matches_does_not_retire_or_rename_it() {
    let dir = TempDir::new("writer_old_skill_unmodified");
    let root = dir.path();
    lay_out_old_format_state(root);
    // The user kept the file exactly as the old Arc generated it: still never deleted.
    write_file(root, LEGACY_SKILL, LEGACY_SKILL_ORIGINAL.as_bytes());
    let before = snapshot(root);

    write_artifacts(
        root,
        &[artifact(
            ".codex/skills/old-skill/SKILL.md",
            "---\nname: old-skill\n---\nnew",
        )],
    )
    .expect("build succeeds");

    let after = snapshot(root);
    assert_eq!(before.get(LEGACY_SKILL), after.get(LEGACY_SKILL));
    assert_eq!(
        before.get("build_manifest.json"),
        after.get("build_manifest.json")
    );
    assert_eq!(
        before.get(LEGACY_CAPABILITIES),
        after.get(LEGACY_CAPABILITIES)
    );
}

#[test]
fn recover_pending_build_without_old_location_journals_succeeds_over_old_state() {
    let dir = TempDir::new("writer_old_state_recover_ok");
    let root = dir.path();
    let legacy_paths = lay_out_old_format_state(root);
    let before = snapshot(root);
    let store = SqliteStateStore::open_in_memory().expect("in-memory store");

    recover_pending_build(root, &store)
        .expect("old manifest, backups and skills are not pending journals");

    assert_old_files_byte_identical(&before, &snapshot(root), &legacy_paths);
}

#[test]
fn recover_pending_build_rejects_old_location_journals_by_presence_only_naming_the_file() {
    for journal in OLD_JOURNALS {
        let dir = TempDir::new("writer_old_journal_recover");
        let root = dir.path();
        let mut legacy_paths = lay_out_old_format_state(root);
        lay_out_old_journal(root, journal, plausible_old_journal_bytes(journal));
        legacy_paths.push(journal);
        let before = snapshot(root);
        let store = SqliteStateStore::open_in_memory().expect("in-memory store");

        let error = recover_pending_build(root, &store)
            .expect_err("a journal at a retired location must be rejected");

        assert_retired_journal_rejected(&error, journal);
        assert_old_files_byte_identical(&before, &snapshot(root), &legacy_paths);
    }
}

#[test]
fn build_over_old_location_journal_is_rejected_naming_the_file_and_leaves_old_files_byte_identical()
{
    for journal in OLD_JOURNALS {
        let dir = TempDir::new("writer_old_journal_build");
        let root = dir.path();
        let mut legacy_paths = lay_out_old_format_state(root);
        lay_out_old_journal(root, journal, plausible_old_journal_bytes(journal));
        legacy_paths.push(journal);
        let before = snapshot(root);

        let error = write_artifacts(
            root,
            &[
                artifact(
                    ".codex/skills/old-skill/SKILL.md",
                    "---\nname: old-skill\n---\nnew",
                ),
                artifact(
                    ".arc/arc-capabilities.json",
                    "{\"capabilities\":\"new location\"}\n",
                ),
            ],
        )
        .expect_err("a journal at a retired location must reject the build");

        assert_retired_journal_rejected(&error, journal);
        let after = snapshot(root);
        assert_old_files_byte_identical(&before, &after, &legacy_paths);
        assert!(
            !root.join(".codex/skills/old-skill/SKILL.md").exists(),
            "a rejected build must not emit artifacts"
        );
    }
}

#[test]
fn old_location_journal_is_rejected_by_presence_whatever_its_content() {
    // Detection is by presence only: empty and non-UTF-8 content are rejected the
    // same way as plausible content, which shows the file is not parsed.
    let contents: [&[u8]; 2] = [b"", b"\xff\xfe\x00 not json at all \x80"];
    for journal in OLD_JOURNALS {
        for bytes in contents {
            let dir = TempDir::new("writer_old_journal_presence");
            let root = dir.path();
            lay_out_old_journal(root, journal, bytes);
            let before = snapshot(root);
            let store = SqliteStateStore::open_in_memory().expect("in-memory store");

            let recover_error = recover_pending_build(root, &store)
                .expect_err("recovery must reject the old journal by presence");
            assert_retired_journal_rejected(&recover_error, journal);

            let build_error = write_artifacts(
                root,
                &[artifact(
                    ".codex/skills/old-skill/SKILL.md",
                    "---\nname: old-skill\n---\nnew",
                )],
            )
            .expect_err("build must reject the old journal by presence");
            assert_retired_journal_rejected(&build_error, journal);

            assert_old_files_byte_identical(&before, &snapshot(root), &[journal]);
        }
    }
}

#[test]
fn both_old_location_journals_together_are_rejected_naming_a_journal_file() {
    let dir = TempDir::new("writer_both_old_journals");
    let root = dir.path();
    let mut legacy_paths = lay_out_old_format_state(root);
    for journal in OLD_JOURNALS {
        lay_out_old_journal(root, journal, plausible_old_journal_bytes(journal));
        legacy_paths.push(journal);
    }
    let before = snapshot(root);
    let store = SqliteStateStore::open_in_memory().expect("in-memory store");

    let error = recover_pending_build(root, &store).expect_err("both journals are rejected");

    let root_cause = format!("{:?}", error.root_cause());
    assert!(
        root_cause.starts_with("RetiredBuildJournalRejected"),
        "{error:#}"
    );
    assert!(
        OLD_JOURNALS
            .iter()
            .any(|journal| root_cause.contains(journal)),
        "error must name at least one old journal, got: {root_cause}"
    );
    assert_old_files_byte_identical(&before, &snapshot(root), &legacy_paths);
}

#[test]
fn writer_source_has_no_old_location_read_path_or_skill_name_migration() {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/emitters/writer.rs"))
            .expect("read writer.rs");
    for retired in [
        "LEGACY_BUILD_MANIFEST_FILE",
        "LEGACY_CLEANUP_JOURNAL_FILE",
        "LEGACY_TRANSACTION_JOURNAL_FILE",
        "reject_legacy_pending_journals",
        "legacy_artifact_successor",
        "RetiredArtifact",
    ] {
        assert!(
            !text.contains(retired),
            "writer.rs still references retired item {retired}"
        );
    }
}

// ---------------------------------------------------------------------------
// AC-007.6: fresh install, single creation path
// ---------------------------------------------------------------------------

fn read_user_version(path: &Path) -> u32 {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only");
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user_version")
}

fn schema_objects(connection: &rusqlite::Connection) -> Vec<(String, String, String)> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, COALESCE(sql, '') FROM sqlite_master \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .map(|row| row.expect("row"))
        .collect()
}

#[test]
fn fresh_install_creates_state_at_the_current_schema_version() {
    let dir = TempDir::new("fresh_install");
    let path = dir.path().join("state").join("arc-state.db");
    let current = SqliteStateStore::open_in_memory()
        .expect("in-memory store")
        .schema_version()
        .expect("version");
    assert!(current >= 5, "schema version must not go backwards");

    let store = SqliteStateStore::open(&path).expect("fresh install opens");
    assert_eq!(store.schema_version().unwrap(), current);
    drop(store);
    assert_eq!(read_user_version(&path), current);
}

#[test]
fn empty_file_is_a_fresh_install_not_an_old_schema() {
    let dir = TempDir::new("empty_file");
    let path = dir.path().join("arc-state.db");
    fs::write(&path, b"").unwrap();

    let store = SqliteStateStore::open(&path).expect("zero-byte file is treated as fresh");
    let current = store.schema_version().unwrap();
    drop(store);
    assert_eq!(read_user_version(&path), current);
}

#[test]
fn two_fresh_installs_create_identical_schemas() {
    let dir = TempDir::new("single_creation_path");
    let first = dir.path().join("first.db");
    let second = dir.path().join("second.db");
    drop(SqliteStateStore::open(&first).expect("first fresh install"));
    drop(SqliteStateStore::open(&second).expect("second fresh install"));

    let first_objects = schema_objects(&rusqlite::Connection::open(&first).unwrap());
    let second_objects = schema_objects(&rusqlite::Connection::open(&second).unwrap());
    assert!(
        !first_objects.is_empty(),
        "fresh install creates the schema"
    );
    assert_eq!(first_objects, second_objects);
}

#[test]
fn state_store_source_has_no_historical_migration_path() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime/state_store/sqlite.rs"),
    )
    .expect("read sqlite.rs");
    assert!(
        !text.contains("fn migrate_schema"),
        "migrate_schema must be removed"
    );
    assert!(
        !text.contains("ALTER TABLE"),
        "historical ALTER TABLE migrations must be removed"
    );
}

#[test]
fn reopening_a_current_version_database_succeeds_without_changing_the_version() {
    let dir = TempDir::new("reopen_current");
    let path = dir.path().join("arc-state.db");
    let first = SqliteStateStore::open(&path).expect("create");
    let version = first.schema_version().unwrap();
    drop(first);

    let second = SqliteStateStore::open(&path).expect("reopen current schema");
    assert_eq!(second.schema_version().unwrap(), version);
}

// ---------------------------------------------------------------------------
// AC-007.4 / AC-007.5: old schema is rejected with a typed error, untouched
// ---------------------------------------------------------------------------

fn current_schema_version() -> u32 {
    SqliteStateStore::open_in_memory()
        .expect("in-memory store")
        .schema_version()
        .expect("version")
}

/// Builds a rollback-journal SQLite file shaped like an older Arc state database.
fn build_old_schema_db(path: &Path, user_version: u32, with_tables: bool) {
    let connection = rusqlite::Connection::open(path).expect("create old db");
    if with_tables {
        connection
            .execute_batch(
                "CREATE TABLE guard_executions (
                     execution_id TEXT PRIMARY KEY,
                     guard_id TEXT NOT NULL,
                     record_json TEXT NOT NULL
                 );
                 INSERT INTO guard_executions VALUES ('exec-1', 'guard-1', '{\"choice\":\"remediate\"}');",
            )
            .expect("old tables");
    }
    connection
        .pragma_update(None, "user_version", user_version)
        .expect("stamp version");
    drop(connection);
}

/// Old-format neighbours of the database: journals and backups that must survive.
fn lay_out_old_state_neighbours(dir: &Path) {
    write_file(dir, "arc-state.db.bak", b"backup of an older database\n");
    write_file(dir, "arc-state.db.pre-migration", b"pre-migration copy\n");
    write_file(
        dir,
        ".arc-build-transaction.json",
        b"{\"state\":\"COMMITTING\"}\n",
    );
    write_file(dir, ".arc-build-cleanup.json", b"{\"files\":[]}\n");
    write_file(
        dir,
        "notes-by-user.txt",
        b"user file next to the database\n",
    );
}

/// The type is checked by name so this file compiles before the type exists.
fn assert_is_incompatible_schema(error: &anyhow::Error) {
    let root = format!("{:?}", error.root_cause());
    assert!(
        root.starts_with("IncompatibleStateSchema"),
        "error must be IncompatibleStateSchema, got: {error:#}"
    );
}

fn assert_rejected_and_untouched(found: u32, with_tables: bool) {
    let expected = current_schema_version();
    let dir = TempDir::new(&format!("old_db_v{found}"));
    let path = dir.path().join("arc-state.db");
    build_old_schema_db(&path, found, with_tables);
    lay_out_old_state_neighbours(dir.path());
    let before = snapshot(dir.path());
    assert!(before.contains_key("arc-state.db"));

    let error = SqliteStateStore::open(&path).err().unwrap_or_else(|| {
        panic!("schema version {found} must be rejected, not opened or migrated")
    });

    assert_is_incompatible_schema(&error);
    let message = format!("{error:#}").replace(&path.display().to_string(), "<path>");
    assert!(
        message.contains(&found.to_string()),
        "message must name the found version {found}: {message}"
    );
    assert!(
        message.contains(&expected.to_string()),
        "message must name the expected version {expected}: {message}"
    );

    let after = snapshot(dir.path());
    assert_eq!(
        before, after,
        "database, journals, backups and user files must be byte-identical and no file may be added"
    );
}

#[test]
fn schema_version_one_database_is_rejected_with_typed_error_and_left_untouched() {
    assert_rejected_and_untouched(1, true);
}

#[test]
fn schema_version_three_database_is_rejected_with_typed_error_and_left_untouched() {
    assert_rejected_and_untouched(3, true);
}

#[test]
fn schema_version_just_below_current_is_rejected_with_typed_error_and_left_untouched() {
    assert_rejected_and_untouched(current_schema_version() - 1, true);
}

#[test]
fn unversioned_database_with_tables_is_rejected_as_found_version_zero() {
    assert_rejected_and_untouched(0, true);
}

#[test]
fn schema_version_newer_than_current_is_rejected_with_the_same_typed_error() {
    assert_rejected_and_untouched(current_schema_version() + 1, true);
}

#[test]
fn rejected_old_database_creates_no_wal_shm_journal_or_replacement_file() {
    let dir = TempDir::new("old_db_no_sidecars");
    let path = dir.path().join("arc-state.db");
    build_old_schema_db(&path, 2, true);
    let names_before: Vec<String> = snapshot(dir.path()).into_keys().collect();
    assert_eq!(names_before, vec!["arc-state.db".to_string()]);

    for attempt in ["first", "second (rejection is repeatable)"] {
        let error = SqliteStateStore::open(&path)
            .err()
            .unwrap_or_else(|| panic!("{attempt} open of an old database must be rejected"));
        assert_is_incompatible_schema(&error);
    }

    let names_after: Vec<String> = snapshot(dir.path()).into_keys().collect();
    assert_eq!(
        names_after, names_before,
        "no -wal, -shm, -journal or new database file"
    );
}

#[test]
fn old_database_content_is_still_readable_after_rejection() {
    let dir = TempDir::new("old_db_still_readable");
    let path = dir.path().join("arc-state.db");
    build_old_schema_db(&path, 3, true);
    let error = SqliteStateStore::open(&path)
        .err()
        .expect("old database must be rejected");
    assert_is_incompatible_schema(&error);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let value: String = connection
        .query_row(
            "SELECT record_json FROM guard_executions WHERE execution_id = 'exec-1'",
            [],
            |row| row.get(0),
        )
        .expect("row survives");
    assert_eq!(value, "{\"choice\":\"remediate\"}");
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3, "version is not stamped forward");
}

// ---------------------------------------------------------------------------
// CP-38: old DB in WAL mode is rejected without creating -wal/-shm
// ---------------------------------------------------------------------------

/// Builds an old-schema database whose header says journal_mode=WAL, then closes
/// it cleanly. SQLite normally checkpoints and removes -wal/-shm on the last
/// close; whatever remains is part of the baseline snapshot taken by the caller.
fn build_old_schema_wal_db(path: &Path, user_version: u32) {
    let connection = rusqlite::Connection::open(path).expect("create old wal db");
    let mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .expect("set WAL");
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "fixture must really be in WAL mode"
    );
    connection
        .execute_batch(
            "CREATE TABLE guard_executions (
                 execution_id TEXT PRIMARY KEY,
                 guard_id TEXT NOT NULL,
                 record_json TEXT NOT NULL
             );
             INSERT INTO guard_executions VALUES ('exec-1', 'guard-1', '{\"choice\":\"remediate\"}');",
        )
        .expect("old tables");
    connection
        .pragma_update(None, "user_version", user_version)
        .expect("stamp version");
    connection
        .close()
        .map_err(|(_, error)| error)
        .expect("close cleanly");
}

#[test]
fn rejected_old_wal_database_creates_no_new_file_and_stays_byte_identical() {
    let expected = current_schema_version();
    for found in [3, expected - 1] {
        let dir = TempDir::new(&format!("old_wal_db_v{found}"));
        let path = dir.path().join("arc-state.db");
        build_old_schema_wal_db(&path, found);
        lay_out_old_state_neighbours(dir.path());
        // Baseline: listing and sha256 of every file, whatever the close left behind.
        let before = snapshot(dir.path());
        assert!(before.contains_key("arc-state.db"));

        for attempt in ["first", "second (rejection is repeatable)"] {
            let error = SqliteStateStore::open(&path).err().unwrap_or_else(|| {
                panic!("{attempt} open of a WAL database at version {found} must be rejected")
            });
            assert_is_incompatible_schema(&error);
            let message = format!("{error:#}").replace(&path.display().to_string(), "<path>");
            assert!(
                message.contains(&found.to_string()),
                "names found {found}: {message}"
            );
            assert!(
                message.contains(&expected.to_string()),
                "names expected {expected}: {message}"
            );

            let after = snapshot(dir.path());
            assert_eq!(
                before.keys().collect::<Vec<_>>(),
                after.keys().collect::<Vec<_>>(),
                "{attempt} open (WAL, version {found}) must not add -wal, -shm or any other file"
            );
            assert_eq!(
                before, after,
                "{attempt} open (WAL, version {found}) must leave every file byte-identical"
            );
        }
    }
}

#[test]
fn current_schema_wal_database_opens_fine() {
    let dir = TempDir::new("current_wal_db");
    let path = dir.path().join("arc-state.db");
    let current = SqliteStateStore::open_in_memory()
        .expect("in-memory store")
        .schema_version()
        .expect("version");
    drop(SqliteStateStore::open(&path).expect("create current db"));
    {
        let connection = rusqlite::Connection::open(&path).expect("reopen raw");
        let mode: String = connection
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .expect("set WAL");
        assert_eq!(mode.to_lowercase(), "wal");
        connection
            .close()
            .map_err(|(_, error)| error)
            .expect("close");
    }

    let store = SqliteStateStore::open(&path).expect("a current-schema WAL database opens");
    assert_eq!(store.schema_version().unwrap(), current);
}

// ---------------------------------------------------------------------------
// CP-40: old DB whose -wal still holds committed frames (not checkpointed)
// ---------------------------------------------------------------------------

/// Typed rejection of an old or unverifiable schema. `IncompatibleStateSchema` is the
/// contract; a typed "not verifiable" rejection (root cause named `...NotVerifiable...`
/// or `...Unverifiable...`) is accepted as the alternative when the header cannot be
/// read without touching the sidecars. Anything untyped (a raw SQLite or I/O error) fails.
fn assert_is_typed_schema_rejection(error: &anyhow::Error) {
    let root = format!("{:?}", error.root_cause());
    let name: String = root
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    let incompatible = name == "IncompatibleStateSchema";
    let not_verifiable = name.contains("NotVerifiable") || name.contains("Unverifiable");
    assert!(
        incompatible || not_verifiable,
        "error must be a typed IncompatibleStateSchema or not-verifiable rejection, got: {error:#}"
    );
}

/// Builds the old-schema DB in `dir` so that a non-empty `-wal` with committed frames
/// survives: the source connection stays open (autocheckpoint off) while the three
/// files are copied, then it is closed. The copies are what the test uses.
fn build_old_schema_db_with_surviving_wal(
    dir: &Path,
    user_version: u32,
    keep_shm: bool,
) -> PathBuf {
    let source = TempDir::new("old_wal_fixture_source");
    let source_db = source.path().join("arc-state.db");
    let connection = rusqlite::Connection::open(&source_db).expect("create source db");
    let mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .expect("set WAL");
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "fixture must really be in WAL mode"
    );
    connection
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable autocheckpoint");
    connection
        .execute_batch(
            "CREATE TABLE guard_executions (
                 execution_id TEXT PRIMARY KEY,
                 guard_id TEXT NOT NULL,
                 record_json TEXT NOT NULL
             );
             INSERT INTO guard_executions VALUES ('exec-1', 'guard-1', '{\"choice\":\"remediate\"}');",
        )
        .expect("old tables");
    connection
        .pragma_update(None, "user_version", user_version)
        .expect("stamp version");

    let target_db = dir.join("arc-state.db");
    for suffix in ["", "-wal", "-shm"] {
        let from = PathBuf::from(format!("{}{suffix}", source_db.display()));
        let to = PathBuf::from(format!("{}{suffix}", target_db.display()));
        fs::copy(&from, &to).unwrap_or_else(|e| panic!("copy {} while open: {e}", from.display()));
    }
    connection
        .close()
        .map_err(|(_, error)| error)
        .expect("close source connection");

    let wal = PathBuf::from(format!("{}-wal", target_db.display()));
    let shm = PathBuf::from(format!("{}-shm", target_db.display()));
    if !keep_shm {
        fs::remove_file(&shm).expect("remove copied -shm");
        assert!(!shm.exists());
    }
    let wal_len = fs::metadata(&wal).expect("copied -wal exists").len();
    assert!(
        wal_len > 0,
        "fixture must hold a non-empty -wal with committed frames"
    );
    target_db
}

fn assert_surviving_wal_db_rejected_and_untouched(found: u32, keep_shm: bool) {
    let expected = current_schema_version();
    let dir = TempDir::new(&format!("old_wal_surviving_v{found}_shm{keep_shm}"));
    let path = build_old_schema_db_with_surviving_wal(dir.path(), found, keep_shm);
    lay_out_old_state_neighbours(dir.path());
    let before = snapshot(dir.path());
    assert!(
        before.contains_key("arc-state.db-wal"),
        "baseline lists the -wal"
    );
    assert_eq!(
        before.contains_key("arc-state.db-shm"),
        keep_shm,
        "baseline -shm presence must match the variant"
    );

    for attempt in ["first", "second (rejection is repeatable)"] {
        let error = SqliteStateStore::open(&path).err().unwrap_or_else(|| {
            panic!(
                "{attempt} open of an old DB (version {found}) with a live -wal must be rejected"
            )
        });
        assert_is_typed_schema_rejection(&error);
        if format!("{:?}", error.root_cause()).starts_with("IncompatibleStateSchema") {
            let message = format!("{error:#}").replace(&path.display().to_string(), "<path>");
            assert!(
                message.contains(&found.to_string()),
                "names found {found}: {message}"
            );
            assert!(
                message.contains(&expected.to_string()),
                "names expected {expected}: {message}"
            );
        }

        let after = snapshot(dir.path());
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            after.keys().collect::<Vec<_>>(),
            "{attempt} open (version {found}, shm kept: {keep_shm}) must not add or remove any file"
        );
        assert_eq!(
            before, after,
            "{attempt} open (version {found}, shm kept: {keep_shm}) must leave db, -wal, -shm and neighbours byte-identical"
        );
    }
}

#[test]
fn old_version_three_db_with_surviving_wal_and_shm_is_rejected_and_every_file_untouched() {
    assert_surviving_wal_db_rejected_and_untouched(3, true);
}

#[test]
fn old_version_just_below_current_db_with_surviving_wal_and_shm_is_rejected_and_every_file_untouched()
 {
    assert_surviving_wal_db_rejected_and_untouched(current_schema_version() - 1, true);
}

#[test]
fn old_version_three_db_with_surviving_wal_and_no_shm_is_rejected_and_every_file_untouched() {
    assert_surviving_wal_db_rejected_and_untouched(3, false);
}

#[test]
fn old_version_just_below_current_db_with_surviving_wal_and_no_shm_is_rejected_and_every_file_untouched()
 {
    assert_surviving_wal_db_rejected_and_untouched(current_schema_version() - 1, false);
}

// ---------------------------------------------------------------------------
// CP-39: rejected build and rejected recovery leave the output dir untouched
// ---------------------------------------------------------------------------

#[test]
fn rejected_build_and_rejected_recovery_leave_the_output_listing_unchanged() {
    for journal in OLD_JOURNALS {
        let dir = TempDir::new("writer_rejection_listing");
        let root = dir.path();
        let mut old_files = lay_out_old_format_state(root);
        lay_out_old_journal(root, journal, plausible_old_journal_bytes(journal));
        old_files.push(journal);
        let before = snapshot(root);
        let listing_before: Vec<&String> = before.keys().collect();

        let build_error = write_artifacts(
            root,
            &[
                artifact(
                    ".codex/skills/old-skill/SKILL.md",
                    "---\nname: old-skill\n---\nnew",
                ),
                artifact(
                    ".arc/arc-capabilities.json",
                    "{\"capabilities\":\"new location\"}\n",
                ),
            ],
        )
        .expect_err("a journal at a retired location must reject the build");
        assert_retired_journal_rejected(&build_error, journal);

        let store = SqliteStateStore::open_in_memory().expect("in-memory store");
        let recover_error = recover_pending_build(root, &store)
            .expect_err("a journal at a retired location must reject recovery");
        assert_retired_journal_rejected(&recover_error, journal);

        let after = snapshot(root);
        let listing_after: Vec<&String> = after.keys().collect();
        let unexpected: Vec<&&String> = listing_after
            .iter()
            .filter(|name| !old_files.contains(&name.as_str()) && !listing_before.contains(name))
            .collect();
        assert!(
            unexpected.is_empty(),
            "rejections ({journal}) must not create any file; unexpected: {unexpected:?}"
        );
        assert!(
            !root.join(".arc").exists(),
            "no .arc/ manifest directory after rejection ({journal})"
        );
        assert!(
            !root.join(".codex/skills/old-skill").exists(),
            "no emitted skill after rejection ({journal})"
        );
        assert_eq!(
            listing_before, listing_after,
            "listing before == listing after ({journal})"
        );
        assert_eq!(
            before, after,
            "all pre-existing files byte-identical ({journal})"
        );
    }
}

// ---------------------------------------------------------------------------
// CP-41 / CP-42: review-04 gaps. Shared runtime-state file and live WAL.
// ---------------------------------------------------------------------------

/// CP-41 (AC-007.6): production order of `main.rs:962`: the observability journal
/// creates the shared file first, then the state store opens it. The journal's own
/// table must not make the store read the fresh file as an old schema (found 0).
#[test]
fn state_store_opens_a_fresh_file_the_observability_journal_created_first() {
    let dir = TempDir::new("journal_first_shared_file");
    let path = dir.path().join("runtime-state.sqlite3");
    let current = current_schema_version();

    let journal = arc::ObservabilityJournal::open(&path).expect("journal creates the fresh file");
    drop(journal);
    assert!(path.exists(), "journal must have created the shared file");

    let store = SqliteStateStore::open(&path)
        .expect("store opens a file that only holds the journal's tables (not an old schema)");
    assert_eq!(store.schema_version().unwrap(), current);
    drop(store);
    assert_eq!(read_user_version(&path), current);
}

/// CP-42 (AC-007.4): a live current-schema store has a non-empty `-wal`. A second
/// open of the same path must succeed: a rejection of every non-empty `-wal` would
/// break concurrent hook processes. Strengthened in iteration 7 (review-05 weak):
/// the on-disk header is current and the db is large, and the open must make no
/// probe copy of it (a copy is pure cost for a current store).
#[test]
fn second_open_of_a_current_database_succeeds_while_a_live_store_holds_a_nonempty_wal() {
    let dir = TempDir::new("live_v5_wal");
    let name = unique_db_name();
    let path = dir.path().join(&name);
    let current = current_schema_version();

    // Create, pad and close: the clean close checkpoints, so the header says current.
    drop(SqliteStateStore::open(&path).expect("first open creates the current database"));
    add_padding_row(&path, 16_000_000);
    assert_eq!(
        header_user_version(&path),
        current,
        "fixture: on-disk header is current"
    );

    let live = SqliteStateStore::open(&path).expect("live store on the current database");
    // A second connection commits a small write: frames stay in -wal while `live` is open.
    add_padding_row(&path, 16);
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let wal_len = fs::metadata(&wal)
        .expect("live store has a -wal file")
        .len();
    assert!(
        wal_len > 0,
        "fixture must hold a non-empty -wal while the first store is open"
    );

    let watcher = ProbeCopyWatcher::start(&name);
    let second = SqliteStateStore::open(&path);
    let copies = watcher.finish();

    let second = second.expect(
        "a second open of a current-schema database with a live non-empty -wal is accepted",
    );
    assert_eq!(second.schema_version().unwrap(), current);
    assert_eq!(live.schema_version().unwrap(), current);
    assert!(
        copies.is_empty(),
        "opening a current-header store must not copy the database into a probe dir: {copies:?}"
    );
}

// ---------------------------------------------------------------------------
// CP-43 to CP-45: probe fast path (review-05 MEDIUM). A current header needs no
// copy of the database; any other header keeps the copy path.
// ---------------------------------------------------------------------------

const PROBE_DIR_PREFIX: &str = "arc-probe-";

/// A db file name no other test uses. The probe copy keeps the file name of the
/// database, so `arc-probe-*/<this name>` identifies this test's probe copies even
/// while other tests run in parallel and create their own `arc-probe-*` dirs.
fn unique_db_name() -> String {
    format!("arc-state-{}.db", uuid::Uuid::new_v4())
}

/// Reads the SQLite header `user_version` (4 bytes big-endian at offset 60) with
/// plain file I/O, the same observable the fast path is allowed to use.
fn header_user_version(path: &Path) -> u32 {
    let bytes = fs::read(path).expect("read db header");
    assert!(bytes.len() >= 100, "db file shorter than the SQLite header");
    u32::from_be_bytes(bytes[60..64].try_into().unwrap())
}

/// Adds one `bytes_len`-byte row to a `padding` table through a raw connection.
fn add_padding_row(path: &Path, bytes_len: i64) {
    let connection = rusqlite::Connection::open(path).expect("raw connection");
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS padding (id INTEGER PRIMARY KEY, bytes BLOB NOT NULL);",
        )
        .expect("padding table");
    connection
        .execute(
            "INSERT INTO padding (bytes) VALUES (zeroblob(?1))",
            [bytes_len],
        )
        .expect("padding row");
    connection
        .close()
        .map_err(|(_, error)| error)
        .expect("close raw connection");
}

/// Polls the system temp dir while a store opens and records every probe copy of
/// the database called `db_file_name`. The copy dir is removed when `open` returns,
/// so a before/after listing cannot see it; only a watcher running during the open can.
struct ProbeCopyWatcher {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Vec<PathBuf>>,
}

impl ProbeCopyWatcher {
    fn start(db_file_name: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let name = db_file_name.to_string();
        let handle = std::thread::spawn(move || {
            let temp = std::env::temp_dir();
            let mut hits: Vec<PathBuf> = Vec::new();
            loop {
                let stopping = flag.load(Ordering::SeqCst);
                if let Ok(entries) = fs::read_dir(&temp) {
                    for entry in entries.flatten() {
                        if !entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(PROBE_DIR_PREFIX)
                        {
                            continue;
                        }
                        let candidate = entry.path().join(&name);
                        if candidate.exists() && !hits.contains(&candidate) {
                            hits.push(candidate);
                        }
                    }
                }
                if stopping {
                    break;
                }
                std::thread::yield_now();
            }
            hits
        });
        Self { stop, handle }
    }

    fn finish(self) -> Vec<PathBuf> {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().expect("watcher thread")
    }
}

/// Builds `<dir>/<file_name>` whose on-disk header says `header_version` and whose
/// non-empty `-wal` (committed frames, no `-shm`) holds a `wal_pad` byte row and,
/// when `wal_version` is set, a newer `user_version` that exists only in the WAL.
/// The source connection stays open (autocheckpoint off) while db and `-wal` are copied.
fn build_header_and_wal_db(
    dir: &Path,
    file_name: &str,
    header_version: u32,
    wal_version: Option<u32>,
    db_pad: i64,
    wal_pad: i64,
) -> PathBuf {
    let source = TempDir::new("header_wal_fixture_source");
    let source_db = source.path().join(file_name);
    {
        let connection = rusqlite::Connection::open(&source_db).expect("create source db");
        connection
            .execute_batch("CREATE TABLE padding (id INTEGER PRIMARY KEY, bytes BLOB NOT NULL);")
            .expect("padding table");
        connection
            .execute(
                "INSERT INTO padding (bytes) VALUES (zeroblob(?1))",
                [db_pad],
            )
            .expect("db padding");
        connection
            .pragma_update(None, "user_version", header_version)
            .expect("stamp header version");
        connection
            .close()
            .map_err(|(_, error)| error)
            .expect("close source");
    }

    let connection = rusqlite::Connection::open(&source_db).expect("reopen source");
    let mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .expect("set WAL");
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "fixture must really be in WAL mode"
    );
    connection
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable autocheckpoint");
    if let Some(version) = wal_version {
        connection
            .pragma_update(None, "user_version", version)
            .expect("stamp version into the WAL");
    }
    if wal_pad == 0 {
        // Touches one leaf page only: the database does not grow, so page 1 (which
        // holds the magic) is not rewritten into the WAL.
        connection
            .execute("UPDATE padding SET id = id + 1", [])
            .expect("in-place wal write");
    } else {
        connection
            .execute(
                "INSERT INTO padding (bytes) VALUES (zeroblob(?1))",
                [wal_pad],
            )
            .expect("wal padding");
    }

    let target_db = dir.join(file_name);
    let source_wal = PathBuf::from(format!("{}-wal", source_db.display()));
    let target_wal = PathBuf::from(format!("{}-wal", target_db.display()));
    fs::copy(&source_db, &target_db).expect("copy db while the source is open");
    fs::copy(&source_wal, &target_wal).expect("copy -wal while the source is open");
    connection
        .close()
        .map_err(|(_, error)| error)
        .expect("close source connection");

    assert!(
        fs::metadata(&target_wal).expect("-wal copied").len() > 0,
        "fixture: -wal is non-empty"
    );
    assert_eq!(
        header_user_version(&target_db),
        header_version,
        "fixture: on-disk header version"
    );
    assert!(
        !PathBuf::from(format!("{}-shm", target_db.display())).exists(),
        "fixture: no -shm"
    );
    target_db
}

/// CP-43 (AC-007.4): header already at the current version plus a non-empty `-wal`
/// (a concurrent hook, or a crash). The version is readable from the header, so the
/// open must not copy db and `-wal` into a temp probe dir.
#[test]
fn current_header_with_nonempty_wal_opens_without_creating_a_probe_copy() {
    let current = current_schema_version();
    let dir = TempDir::new("header_current_wal");
    let name = unique_db_name();
    let path = build_header_and_wal_db(dir.path(), &name, current, None, 16_000_000, 8_000_000);

    let watcher = ProbeCopyWatcher::start(&name);
    let result = SqliteStateStore::open(&path);
    let copies = watcher.finish();

    let store = result.expect("a current-header database with a non-empty -wal opens");
    assert_eq!(store.schema_version().unwrap(), current);
    assert!(
        copies.is_empty(),
        "header is current, so no arc-probe copy may be made: {copies:?}"
    );
}

/// CP-44 (AC-007.4): header one version behind, current version only in the WAL
/// (the header lags until a checkpoint). The header alone would reject it, so the
/// WAL must still be consulted; the database is current and must open.
#[test]
fn old_header_with_current_version_only_in_the_wal_opens_ok() {
    let current = current_schema_version();
    let dir = TempDir::new("header_old_wal_current");
    let name = unique_db_name();
    let path = build_header_and_wal_db(
        dir.path(),
        &name,
        current - 1,
        Some(current),
        64_000,
        64_000,
    );
    assert_eq!(header_user_version(&path), current - 1);

    let store = SqliteStateStore::open(&path)
        .expect("a database whose current version lives only in the WAL is not an old schema");
    assert_eq!(store.schema_version().unwrap(), current);
}

/// CP-45 (AC-007.4): the header carries the current version at offset 60 but the
/// SQLite magic is wrong, so it is not trusted and the copy path runs. Observable
/// result, same as before the fast path: the probe rejects it ("failed reading Arc
/// state database", not a later "failed opening") and the live files stay untouched.
#[test]
fn header_with_wrong_sqlite_magic_falls_back_to_the_copy_path_and_is_rejected() {
    let current = current_schema_version();
    let dir = TempDir::new("header_bad_magic");
    let name = unique_db_name();
    // wal_pad 0: the WAL write is in place, so page 1 (with the magic) stays only in the
    // db file; otherwise a page 1 frame in the WAL would mask the corrupted magic.
    let path = build_header_and_wal_db(dir.path(), &name, current, None, 100, 0);
    let mut bytes = fs::read(&path).unwrap();
    bytes[..16].copy_from_slice(b"Not SQLite fmt 3");
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        header_user_version(&path),
        current,
        "fixture: offset 60 still says current"
    );
    let before = snapshot(dir.path());

    let error = SqliteStateStore::open(&path)
        .err()
        .expect("a file without the SQLite magic must not open as a current database");

    let message = format!("{error:#}");
    assert!(
        message.contains("failed reading Arc state database"),
        "the probe (copy path) must be the one that rejects it: {message}"
    );
    assert!(
        !message.contains("failed opening Arc state database"),
        "must not reach the real open: {message}"
    );
    assert_eq!(
        before,
        snapshot(dir.path()),
        "rejected file and -wal stay byte-identical, nothing added"
    );
}
