//! REQ-002: one CLI decision backend per provider and one auditor output contract.
//!
//! Every test drives the real `arc hook run` binary with fake `codex` / `agy`
//! executables placed first on `PATH` and `ARC_LLM_CLI` removed, so the
//! provider-specific `AuditorCommandSpec` path is the one that runs.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const FAKE_CLI_SOURCE: &str = r#"
use std::io::Write;
fn main() {
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_stem().unwrap().to_string_lossy().into_owned();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Ok(log) = std::env::var("ARC_TEST_ARGV_LOG") {
        let escaped: Vec<String> = args
            .iter()
            .map(|a| a.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "\\r"))
            .collect();
        let record = format!("{}\u{1f}{}\n", name, escaped.join("\u{1f}"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .unwrap();
        file.write_all(record.as_bytes()).unwrap();
    }
    let stdout = std::env::var("ARC_TEST_STDOUT")
        .unwrap_or_else(|_| "{\"decision\":true,\"findings\":null,\"error\":null}".to_string());
    // ARC_TEST_TOLERATE_BROKEN_PIPE: a real CLI may ignore a closed stdout and
    // still exit 0, so the exit status must not hide a silently truncated read.
    if std::env::var("ARC_TEST_TOLERATE_BROKEN_PIPE").is_ok() {
        let pad_char = std::env::var("ARC_TEST_PAD_CHAR").unwrap_or_else(|_| "x".to_string());
        let mut out = std::io::stdout();
        let _ = out.write_all(stdout.as_bytes());
        if let Ok(pad) = std::env::var("ARC_TEST_PAD_BYTES") {
            let pad: usize = pad.parse().unwrap();
            let _ = out.write_all(pad_char.repeat(pad).as_bytes());
        }
        let _ = out.flush();
        let code: i32 = std::env::var("ARC_TEST_EXIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        std::process::exit(code);
    }
    print!("{}", stdout);
    if let Ok(pad) = std::env::var("ARC_TEST_PAD_BYTES") {
        let pad: usize = pad.parse().unwrap();
        print!("{}", "x".repeat(pad));
    }
    if let Ok(suffix) = std::env::var("ARC_TEST_SUFFIX") {
        print!("{}", suffix);
    }
    std::io::stdout().flush().unwrap();
    let code: i32 = std::env::var("ARC_TEST_EXIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    std::process::exit(code);
}
"#;

fn fake_cli_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let directory = std::env::temp_dir().join(format!(
            "arc-cli-backend-fake-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).expect("create fake cli directory");
        let source = directory.join("fake_cli.rs");
        fs::write(&source, FAKE_CLI_SOURCE).expect("write fake cli source");
        let binary = directory.join(format!("fake_cli{}", std::env::consts::EXE_SUFFIX));
        let output = Command::new("rustc")
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .expect("rustc must be available");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        binary
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Provider {
    Codex,
    Agy,
}

impl Provider {
    fn hook_name(self) -> &'static str {
        match self {
            Provider::Codex => "codex",
            Provider::Agy => "gemini",
        }
    }
}

struct Fixture {
    root: PathBuf,
    bin_dir: PathBuf,
    argv_log: PathBuf,
}

impl Fixture {
    /// Isolated workspace with both fake executables on disk and one trusted
    /// IR whose only guard is a `decide` expression on the tool `cargo test`.
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "arc_cli_backend_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        for name in ["codex", "agy"] {
            fs::copy(
                fake_cli_binary(),
                bin_dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        fs::create_dir_all(root.join(".codex/sessions")).unwrap();
        fs::create_dir_all(root.join(".gemini/antigravity/brain/session-cli-backend")).unwrap();
        fs::create_dir_all(root.join(".agents")).unwrap();

        let fail_command = if cfg!(windows) {
            "powershell -NoProfile -Command \"'dirty'\""
        } else {
            "printf dirty"
        };
        let ir = serde_json::json!({
            "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
            "skills": [],
            "lifecycle_guards": [],
            "tool_guards": [
                {
                    "id": "auth_decide_guard",
                    "matcher": {"exact_patterns": ["cargo test"]},
                    "require": {"decide": {"prompt": "Verify command safety"}},
                    "on_failure": {"action": "deny", "feedback": "Decide safety check rejected"},
                    "order": 1
                },
                {
                    // Always fails: makes the hook answer immediately instead of
                    // waiting for an exact-operation authorization UI.
                    "id": "failing_probe_guard",
                    "matcher": {"exact_patterns": ["cargo test"]},
                    "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                    "on_failure": {"action": "deny", "feedback": "Probe guard failed"},
                    "order": 2
                }
            ],
            "rules": {}
        });
        let mut ir: arc::ir::BehaviorIR = serde_json::from_value(ir).unwrap();
        ir.content_hash = Some(ir.compute_content_hash());
        let bytes = serde_json::to_vec_pretty(&ir).unwrap();
        for relative in [".codex/arc_ir.json", ".agents/arc_ir.json"] {
            let path = root.join(relative);
            fs::write(&path, &bytes).unwrap();
            arc::SqliteStateStore::open(&root.join(".arc-test-state/runtime-state.sqlite3"))
                .unwrap()
                .trust_ir_file(&path)
                .unwrap();
        }
        fs::write(
            root.join(".codex/sessions/session-cli-backend.jsonl"),
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"session-cli-backend\"}}\n\
             {\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"Run compliance validation suite\"}]}}\n",
        )
        .unwrap();
        fs::write(
            root.join(".gemini/antigravity/brain/session-cli-backend/transcript.jsonl"),
            "{\"type\":\"USER_INPUT\",\"content\":\"Run compliance validation suite\"}\n",
        )
        .unwrap();
        let argv_log = root.join("argv.log");
        Self {
            root,
            bin_dir,
            argv_log,
        }
    }

    /// Runs one `PreToolUse` hook whose `decide` guard reaches the fake CLI.
    /// Returns the hook stdout JSON.
    fn run_hook(&self, provider: Provider, stdout: &str, exit_code: i32) -> serde_json::Value {
        self.run_hook_with(provider, stdout, exit_code, &[])
    }

    fn run_hook_with(
        &self,
        provider: Provider,
        stdout: &str,
        exit_code: i32,
        extra_env: &[(&str, &str)],
    ) -> serde_json::Value {
        let _ = fs::remove_file(&self.argv_log);
        let input = match provider {
            Provider::Codex => serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cargo test"},
                "session_id": "session-cli-backend",
                "transcript_path": self
                    .root
                    .join(".codex/sessions/session-cli-backend.jsonl")
                    .to_string_lossy(),
            }),
            Provider::Agy => serde_json::json!({
                "toolCall": {"name": "Bash", "args": {"command": "cargo test"}},
                "conversationId": "session-cli-backend",
                "transcriptPath": self
                    .root
                    .join(".gemini/antigravity/brain/session-cli-backend/transcript.jsonl")
                    .to_string_lossy(),
            }),
        };
        let mut path = std::ffi::OsString::from(self.bin_dir.as_os_str());
        path.push(if cfg!(windows) { ";" } else { ":" });
        path.push(std::env::var_os("PATH").unwrap_or_default());
        let mut command = Command::new(env!("CARGO_BIN_EXE_arc"));
        command
            .current_dir(&self.root)
            .args([
                "hook",
                "run",
                "--event-type",
                "pre-tool-use",
                "--provider",
                provider.hook_name(),
            ])
            .env_remove("ARC_LLM_CLI")
            .env("PATH", path)
            .env("ARC_STATE_DIR", self.root.join(".arc-test-state"))
            .env("ARC_TEST_ARGV_LOG", &self.argv_log)
            .env("ARC_TEST_STDOUT", stdout)
            .env("ARC_TEST_EXIT", exit_code.to_string())
            .envs(extra_env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match provider {
            Provider::Codex => {
                command.env("CODEX_HOME", &self.root);
            }
            Provider::Agy => {
                command
                    .env("USERPROFILE", &self.root)
                    .env("HOME", &self.root);
            }
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// One entry per fake CLI invocation: (executable stem, argv without argv0).
    fn invocations(&self) -> Vec<(String, Vec<String>)> {
        let Ok(text) = fs::read_to_string(&self.argv_log) else {
            return Vec::new();
        };
        text.lines()
            .map(|line| {
                let mut parts = line.split('\u{1f}').map(str::to_string);
                let name = parts.next().unwrap();
                (name, parts.collect())
            })
            .collect()
    }

    /// Observability rows of the given type, oldest first, as parsed `details_json`.
    fn journal(&self, event_type: &str) -> Vec<serde_json::Value> {
        let connection =
            rusqlite::Connection::open(self.root.join(".arc-test-state/runtime-state.sqlite3"))
                .unwrap();
        let mut statement = connection
            .prepare(
                "SELECT details_json FROM observability_events
                 WHERE event_type = ?1 ORDER BY id ASC",
            )
            .unwrap();
        statement
            .query_map([event_type], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|raw| serde_json::from_str(&raw.unwrap()).unwrap())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const TRUE_PAYLOAD: &str = r#"{"decision":true,"findings":null,"error":null}"#;
const FALSE_PAYLOAD: &str = r#"{"decision":false,"findings":"needs review","error":null}"#;

impl Fixture {
    /// Outcome of the `decide` guard as recorded in the journal, without
    /// transport-dependent identifiers: state, auditor findings and fault summary.
    fn decision_outcome(&self) -> serde_json::Value {
        let rows = self.journal("GuardResultRecorded");
        let row = rows
            .iter()
            .rev()
            .find(|row| row["guard_id"] == "auth_decide_guard")
            .expect("GuardResultRecorded for auth_decide_guard must be journaled");
        let state = &row["state"];
        serde_json::json!({
            "state": state["state"],
            "findings": state["causes"][0]["auditor_findings"],
            "fault": state["faults"][0]["summary"],
        })
    }
}

fn hook_reason(output: &serde_json::Value) -> String {
    output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .or_else(|| output["reason"].as_str())
        .expect("hook must deny with a reason")
        .to_string()
}

fn is_deny(output: &serde_json::Value) -> bool {
    output["hookSpecificOutput"]["permissionDecision"] == "deny" || output["decision"] == "deny"
}

// ---------------------------------------------------------------------------
// AC-002.1: the executed command is `codex exec` / `agy --print`, nothing else.
// ---------------------------------------------------------------------------

#[test]
fn codex_hook_decision_runs_codex_exec_and_no_other_backend() {
    let fixture = Fixture::new();
    let output = fixture.run_hook(Provider::Codex, FALSE_PAYLOAD, 0);

    assert!(is_deny(&output), "{output}");
    assert!(hook_reason(&output).contains("Decide safety check rejected"));
    let invocations = fixture.invocations();
    assert_eq!(
        invocations.len(),
        1,
        "exactly one CLI call: {invocations:?}"
    );
    let (name, args) = &invocations[0];
    assert_eq!(name, "codex");
    assert!(args.iter().any(|a| a == "exec"), "argv: {args:?}");
    assert!(!args.iter().any(|a| a == "--print"), "argv: {args:?}");
    let prompt = args.last().unwrap();
    assert!(
        prompt.contains("read_only_compliance_auditor"),
        "the auditor payload must be the last argument: {prompt}"
    );
}

#[test]
fn agy_hook_decision_runs_agy_print_and_no_other_backend() {
    let fixture = Fixture::new();
    let output = fixture.run_hook(Provider::Agy, FALSE_PAYLOAD, 0);

    assert!(is_deny(&output), "{output}");
    assert!(hook_reason(&output).contains("Decide safety check rejected"));
    let invocations = fixture.invocations();
    assert_eq!(
        invocations.len(),
        1,
        "exactly one CLI call: {invocations:?}"
    );
    let (name, args) = &invocations[0];
    assert_eq!(name, "agy");
    assert!(args.iter().any(|a| a == "--print"), "argv: {args:?}");
    assert!(!args.iter().any(|a| a == "exec"), "argv: {args:?}");
    let prompt = args.last().unwrap();
    assert!(
        prompt.contains("read_only_compliance_auditor"),
        "the auditor payload must be the last argument: {prompt}"
    );
}

// ---------------------------------------------------------------------------
// AC-002.3: the journal names the CLI dispatcher that was executed.
// ---------------------------------------------------------------------------

fn started_transports(fixture: &Fixture) -> Vec<serde_json::Value> {
    fixture
        .journal("GuardEvaluationStarted")
        .iter()
        .map(|details| details["decision_transport"].clone())
        .collect()
}

#[test]
fn codex_journal_reports_codex_exec_dispatcher() {
    let fixture = Fixture::new();
    fixture.run_hook(Provider::Codex, FALSE_PAYLOAD, 0);

    assert_eq!(fixture.invocations()[0].0, "codex");
    assert_eq!(
        started_transports(&fixture),
        vec![serde_json::json!("codex_exec")],
        "Codex runs `codex exec`; it must not be reported as codex_app_server"
    );
}

#[test]
fn agy_journal_reports_agy_print_dispatcher() {
    let fixture = Fixture::new();
    fixture.run_hook(Provider::Agy, FALSE_PAYLOAD, 0);

    assert_eq!(fixture.invocations()[0].0, "agy");
    assert_eq!(
        started_transports(&fixture),
        vec![serde_json::json!("agy_print")],
        "Agy runs `agy --print`; it must not be reported as stream_json"
    );
}

#[test]
fn dispatcher_label_is_recorded_in_the_same_journal_row_as_the_event() {
    let fixture = Fixture::new();
    fixture.run_hook(Provider::Codex, FALSE_PAYLOAD, 0);

    let rows = fixture.journal("GuardEvaluationStarted");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event"], "tool_call");
    assert_eq!(rows[0]["decision_transport"], "codex_exec");
}

// ---------------------------------------------------------------------------
// AC-002.5: both providers parse identical auditor payloads identically.
// ---------------------------------------------------------------------------

fn assert_parity(stdout: &str, exit_code: i32, state: &str, findings: serde_json::Value) {
    let codex = Fixture::new();
    let codex_output = codex.run_hook(Provider::Codex, stdout, exit_code);
    let codex_outcome = codex.decision_outcome();
    let agy = Fixture::new();
    let agy_output = agy.run_hook(Provider::Agy, stdout, exit_code);
    let agy_outcome = agy.decision_outcome();

    assert_eq!(codex.invocations()[0].0, "codex");
    assert_eq!(agy.invocations()[0].0, "agy");
    assert_eq!(codex_outcome, agy_outcome, "payload: {stdout}");
    assert!(is_deny(&codex_output) && is_deny(&agy_output));
    assert_eq!(
        hook_reason(&codex_output),
        hook_reason(&agy_output),
        "payload: {stdout}"
    );
    assert_eq!(codex_outcome["state"], state, "payload: {stdout}");
    assert_eq!(codex_outcome["findings"], findings, "payload: {stdout}");
}

macro_rules! parity_case {
    ($name:ident, $stdout:expr, $exit:expr, $state:expr, $findings:expr) => {
        #[test]
        fn $name() {
            assert_parity($stdout, $exit, $state, $findings);
        }
    };
}

parity_case!(
    parity_valid_true_payload_satisfies_the_guard,
    TRUE_PAYLOAD,
    0,
    "satisfied",
    serde_json::Value::Null
);
parity_case!(
    parity_padded_findings_are_trimmed,
    r#"{"decision":false,"findings":"  needs review  ","error":null}"#,
    0,
    "violated",
    serde_json::json!("needs review")
);
parity_case!(
    parity_whitespace_only_findings_become_none,
    r#"{"decision":false,"findings":"   ","error":null}"#,
    0,
    "violated",
    serde_json::Value::Null
);
parity_case!(
    parity_non_empty_error_with_false_decision_is_a_fault,
    r#"{"decision":false,"findings":null,"error":"auditor crashed"}"#,
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_non_empty_error_with_true_decision_is_a_contradiction_fault,
    r#"{"decision":true,"findings":null,"error":"auditor crashed"}"#,
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_whitespace_only_error_is_ignored,
    r#"{"decision":true,"findings":null,"error":"   "}"#,
    0,
    "satisfied",
    serde_json::Value::Null
);
parity_case!(
    parity_confidence_inside_range_is_accepted,
    r#"{"decision":true,"confidence":0.5,"findings":null,"error":null}"#,
    0,
    "satisfied",
    serde_json::Value::Null
);
parity_case!(
    parity_confidence_above_one_is_a_fault,
    r#"{"decision":true,"confidence":1.5,"findings":null,"error":null}"#,
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_negative_confidence_is_a_fault,
    r#"{"decision":true,"confidence":-0.1,"findings":null,"error":null}"#,
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_unknown_field_is_a_fault,
    r#"{"decision":true,"findings":null,"error":null,"extra":1}"#,
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_non_json_text_is_a_fault,
    "yes",
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_markdown_fenced_json_is_a_fault,
    "```json\n{\"decision\":true,\"findings\":null,\"error\":null}\n```",
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_empty_stdout_is_a_fault,
    "",
    0,
    "faulted",
    serde_json::Value::Null
);
parity_case!(
    parity_non_zero_exit_with_valid_json_is_a_fault,
    TRUE_PAYLOAD,
    1,
    "faulted",
    serde_json::Value::Null
);

// ---------------------------------------------------------------------------
// Behavior of the removed backends that must still hold on the CLI path.
// ---------------------------------------------------------------------------

#[test]
fn oversized_cli_output_never_approves_a_truncated_valid_prefix() {
    for provider in [Provider::Codex, Provider::Agy] {
        let fixture = Fixture::new();
        // 1 MiB limit plus a small tail: the retained prefix is incomplete JSON.
        let output = fixture.run_hook_with(
            provider,
            r#"{"decision":true,"findings":""#,
            0,
            &[
                ("ARC_TEST_PAD_BYTES", "1049100"),
                ("ARC_TEST_SUFFIX", r#"","error":null}"#),
            ],
        );

        assert!(is_deny(&output), "{provider:?}: {output}");
        assert_eq!(
            fixture.decision_outcome()["state"],
            "faulted",
            "{provider:?} must not approve truncated output"
        );
    }
}

const PROBE_OUTPUT_LIMIT: usize = 1024 * 1024; // MAX_PROBE_OUTPUT_BYTES

/// A complete, valid approve payload followed by whitespace past the limit.
/// The CLI reader truncates at the limit; if truncation is silent, the retained
/// prefix is the valid approve JSON plus spaces and would be approved.
#[test]
fn complete_approve_json_followed_by_more_than_the_limit_of_whitespace_is_not_approved() {
    for provider in [Provider::Codex, Provider::Agy] {
        let fixture = Fixture::new();
        let pad = PROBE_OUTPUT_LIMIT + 1000 - TRUE_PAYLOAD.len();
        assert!(TRUE_PAYLOAD.len() + pad > PROBE_OUTPUT_LIMIT);
        let pad_text = pad.to_string();
        let output = fixture.run_hook_with(
            provider,
            TRUE_PAYLOAD,
            0,
            &[
                ("ARC_TEST_TOLERATE_BROKEN_PIPE", "1"),
                ("ARC_TEST_PAD_CHAR", " "),
                ("ARC_TEST_PAD_BYTES", &pad_text),
            ],
        );

        assert!(is_deny(&output), "{provider:?}: {output}");
        assert_eq!(
            fixture.decision_outcome()["state"],
            "faulted",
            "{provider:?} must fault when the output exceeds the limit, not approve a truncated read"
        );
    }
}

/// Exact-boundary accept: output at or just below the limit is complete, so a
/// valid approve JSON padded with trailing whitespace stays satisfied.
#[test]
fn approve_json_padded_with_whitespace_up_to_the_limit_is_still_accepted() {
    for provider in [Provider::Codex, Provider::Agy] {
        for total in [PROBE_OUTPUT_LIMIT - 1, PROBE_OUTPUT_LIMIT] {
            let fixture = Fixture::new();
            let pad_text = (total - TRUE_PAYLOAD.len()).to_string();
            fixture.run_hook_with(
                provider,
                TRUE_PAYLOAD,
                0,
                &[
                    ("ARC_TEST_TOLERATE_BROKEN_PIPE", "1"),
                    ("ARC_TEST_PAD_CHAR", " "),
                    ("ARC_TEST_PAD_BYTES", &pad_text),
                ],
            );

            assert_eq!(
                fixture.decision_outcome()["state"],
                "satisfied",
                "{provider:?} total output {total} bytes must be accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// AC-012.1 / AC-012.2: the real hook path is preserved.
// ---------------------------------------------------------------------------

#[test]
fn hook_run_persists_its_journal_in_the_sqlite_state_store() {
    let fixture = Fixture::new();
    fixture.run_hook(Provider::Codex, FALSE_PAYLOAD, 0);

    let database = fixture.root.join(".arc-test-state/runtime-state.sqlite3");
    assert!(database.is_file());
    assert_eq!(fixture.journal("GuardEvaluationStarted").len(), 1);
    assert_eq!(fixture.journal("GuardEvaluationCompleted").len(), 1);
}

#[test]
fn guard_failure_context_and_sqlite_store_remain_public_runtime_types() {
    assert!(std::any::type_name::<arc::GuardFailureContext>().ends_with("GuardFailureContext"));
    assert!(std::any::type_name::<arc::SqliteStateStore>().ends_with("SqliteStateStore"));
    let coordinator = std::fs::read_to_string("src/runtime/execution/coordinator.rs").unwrap();
    assert!(coordinator.contains("pub fn apply_aggregate_decision("));
}

// ---------------------------------------------------------------------------
// AC-002.2 / AC-002.4: structure. The removed backends and their output types
// have no references, and one output type and one validator remain.
// ---------------------------------------------------------------------------

fn removed_backend_symbols() -> Vec<String> {
    let agy = |tail: &str| format!("Agy{tail}");
    let codex = |tail: &str| format!("Codex{tail}");
    vec![
        format!("AGY_ONE_SHOT_{}", "TRANSPORT"),
        agy("DecisionProvider"),
        agy("DecisionTransport"),
        agy("OneShotWorker"),
        agy("TransportError"),
        format!("CommandAgy{}", "DecisionTransport"),
        format!("CODEX_APP_SERVER_{}", "TRANSPORT"),
        codex("AppServerDecisionProvider"),
        codex("AppServerSession"),
        codex("AppServerTransport"),
        codex("TransportError"),
        format!("CommandCodex{}", "AppServerTransport"),
        agy("DecisionOutputV1"),
        codex("DecisionOutputV1"),
    ]
}

fn collect_files(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "node_modules" && name != "target" && name != "dist" && name != ".git" {
                collect_files(&path, out);
            }
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "ts" | "tsx" | "js" | "json" | "toml" | "md" | "ps1")
        ) {
            out.push(path);
        }
    }
}

fn contains_word(text: &str, word: &str) -> bool {
    let is_word_char = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(word).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + word.len()..].chars().next();
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

fn grep_scope_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for directory in [
        "src",
        "tests",
        "examples",
        "ui/decision/src",
        "ui/decision/src-tauri/src",
        "ui/decision/webdriver",
    ] {
        collect_files(Path::new(directory), &mut files);
    }
    files
}

#[test]
fn removed_backend_symbols_have_zero_matches_in_the_grep_scope() {
    let symbols = removed_backend_symbols();
    let mut offenders = Vec::new();
    for file in grep_scope_files() {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for symbol in &symbols {
            if contains_word(&text, symbol) {
                offenders.push(format!("{}: {symbol}", file.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "removed symbols remain: {offenders:#?}"
    );
}

#[test]
fn removed_backend_source_files_do_not_exist() {
    for path in [
        "src/runtime/provider/codex/command_io.rs",
        "src/runtime/provider/codex.rs",
        "src/runtime/provider/agy.rs",
    ] {
        assert!(!Path::new(path).exists(), "{path} must be deleted");
    }
}

#[test]
fn windows_toolhelp_feature_is_dropped_with_the_codex_process_tree_walker() {
    let manifest = fs::read_to_string("Cargo.toml").unwrap();
    assert!(!manifest.contains("Win32_System_Diagnostics_ToolHelp"));
}

#[test]
fn a_single_auditor_output_type_and_validator_remain() {
    let mut definitions_of_output_type = 0;
    let mut definitions_of_validator = 0;
    let mut files = Vec::new();
    collect_files(Path::new("src"), &mut files);
    for file in files {
        let text = fs::read_to_string(&file).unwrap_or_default();
        definitions_of_output_type += text.matches("struct AuditorOutputPayload").count();
        definitions_of_validator += text.matches("fn handle_payload(").count();
        for line in text.lines() {
            let line = line.trim_start();
            assert!(
                !(line.starts_with("struct ") || line.starts_with("pub struct "))
                    || !line.contains("DecisionOutput"),
                "extra decision output type in {}: {line}",
                file.display()
            );
        }
    }
    assert_eq!(definitions_of_output_type, 1);
    assert_eq!(definitions_of_validator, 1);
}
