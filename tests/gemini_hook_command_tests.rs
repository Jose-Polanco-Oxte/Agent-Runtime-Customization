use arc::emitters::targets::gemini::hooks_emitter::HooksEmitter;
use arc::ir::{BoundLifecycleGuard, BoundMatcher, BoundRuleExpression, BoundToolGuard};
use arc::manifest::schema::{ActionType, LifecycleTrigger, OnFailureConfig, RuntimeConfig};
use arc::{DecisionUiMode, OsTarget};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

struct Fixture {
    directory: PathBuf,
    binary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("arc-hook-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let binary = directory.join(format!("fixture{}", std::env::consts::EXE_SUFFIX));
        let fixture = Self { directory, binary };
        let source = fixture.directory.join("fixture.rs");
        std::fs::write(
            &source,
            r#"
use std::io::{Read, Write};
fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    // Each argument and the input are returned as separate, unambiguous lines.
    for arg in args { writeln!(std::io::stdout(), "{arg}")?; }
    std::io::stdout().write_all(&input)?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(b"fixture-stderr")?;
    std::io::stderr().flush()?;
    std::process::exit(7);
}
"#,
        )
        .unwrap();
        let result = Command::new("rustc")
            .arg(source)
            .arg("-o")
            .arg(&fixture.binary)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }

    fn copy_to(&self, folder: &str) -> PathBuf {
        let directory = self.directory.join(folder);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("arc{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(&self.binary, &path).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn hooks(os: &str, executable: &str) -> Value {
    let failure = OnFailureConfig {
        action: ActionType::Deny,
        feedback: None,
    };
    let requirement = BoundRuleExpression::All(Vec::new());
    let lifecycle = BoundLifecycleGuard {
        id: "lifecycle".into(),
        triggers: vec![LifecycleTrigger::Start, LifecycleTrigger::End],
        require: requirement.clone(),
        on_failure: failure.clone(),
        order: 0,
        declaration_order: 0,
    };
    let tool = BoundToolGuard {
        id: "tool".into(),
        matcher: BoundMatcher::default(),
        require: requirement,
        on_failure: failure,
        order: 0,
        declaration_order: 0,
    };
    let artifact = HooksEmitter::emit_hooks(
        &[lifecycle],
        &[tool],
        &OsTarget::new(os).unwrap(),
        DecisionUiMode::Auto,
        Some(executable),
        &RuntimeConfig::default(),
    )
    .unwrap();
    serde_json::from_str(&artifact.content).unwrap()
}

fn assert_commands(fixture: &Fixture, os: &str, executable: &str, posix: bool) {
    let hooks = hooks(os, executable);
    let payload = "{\"message\":\"á 🦀\",\"lines\":[1,2]}\r\n";
    for (event, argument) in [
        ("PreToolUse", "pre-tool-use"),
        ("PreInvocation", "pre-invocation"),
        ("Stop", "stop"),
    ] {
        let handler = if event == "PreToolUse" {
            &hooks["arc-runtime"][event][0]["hooks"][0]
        } else {
            &hooks["arc-runtime"][event][0]
        };
        let command_text = handler["command"].as_str().unwrap();
        assert!(handler.get("commandWindows").is_none());
        let mut command = if posix {
            let shell = std::env::var_os("ARC_TEST_POSIX_SHELL").unwrap_or_else(|| {
                if cfg!(windows) {
                    "C:/Program Files/Git/bin/bash.exe".into()
                } else {
                    "sh".into()
                }
            });
            let mut command = Command::new(shell);
            command.args(["-c", command_text]);
            command
        } else {
            let mut command = Command::new("cmd.exe");
            command.args(["/D", "/V:ON", "/S", "/C", command_text]);
            // The bare `arc` form is resolved by PATH, as in production. Putting the
            // fixture first keeps the test independent of whether cmd.exe also looks
            // in the current directory (NoDefaultCurrentDirectoryInExePath) and of any
            // globally installed `arc.exe`.
            let mut search = vec![fixture.directory.clone()];
            if let Some(path) = std::env::var_os("PATH") {
                search.extend(std::env::split_paths(&path));
            }
            command.env("PATH", std::env::join_paths(search).unwrap());
            command
        };
        command
            .current_dir(&fixture.directory)
            .env("ARC_TEST_LITERAL", "WRONG_EXPANSION")
            .env("MSYS_NO_PATHCONV", "1");
        let output = arc::run_command_bounded_with_input(
            command,
            payload.as_bytes().to_vec(),
            Duration::from_secs(10),
            65536,
        )
        .expect("hook command must finish within the test deadline");
        assert_eq!(
            output.status.code(),
            Some(7),
            "command={command_text}\nstderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = format!(
            "hook\nrun\n--event-type\n{argument}\n--provider\ngemini\n--decision-ui\nauto\n--ir-path\n.agents/arc_ir.json\n{payload}"
        );
        assert_eq!(output.stdout, expected.as_bytes(), "event={event}");
        assert_eq!(output.stderr, b"fixture-stderr");
    }
}

#[test]
#[cfg(windows)]
fn windows_hooks_execute_literal_paths_and_preserve_the_protocol() {
    let fixture = Fixture::new();
    fixture.copy_to(".");
    assert_commands(&fixture, "windows", "arc", false);
    assert_commands(&fixture, "windows", ".\\arc.exe", false);
    for folder in [
        "Program Files",
        "literal&()^!ARC_TEST_LITERAL!%ARC_TEST_LITERAL%' é",
    ] {
        let path = fixture.copy_to(folder);
        assert_commands(&fixture, "windows", path.to_str().unwrap(), false);
    }
}

#[test]
fn posix_hooks_execute_literal_paths_and_preserve_the_protocol() {
    let fixture = Fixture::new();
    for os in ["linux", "macos"] {
        for folder in ["Program Files", "literal'&()$HOME`id`;! é"] {
            let path = fixture.copy_to(folder);
            let executable = path.to_str().unwrap().replace('\\', "/");
            assert_commands(&fixture, os, &executable, true);
        }
    }
}

#[test]
fn hooks_keep_the_documented_shape_and_timeout() {
    let hooks = hooks("windows", "arc");
    assert_eq!(hooks["arc-runtime"]["enabled"], json!(true));
    assert!(hooks["arc-runtime"]["Stop"][0]["timeout"].as_u64().unwrap() > 0);
}
