use std::process::Command;

fn arc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_arc"))
}

#[test]
fn invalid_hook_option_exits_with_clap_usage_error() {
    let output = arc()
        .args([
            "hook",
            "run",
            "--event-type",
            "pre-tool-use",
            "--decision-ui",
            "typo",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value 'typo'"));
}

#[test]
fn capabilities_rejects_an_invalid_explicit_path() {
    let output = arc()
        .args(["capabilities", "--path", "definitely-missing-arc-workspace"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("explicit manifest"));
}

#[test]
fn all_cannot_be_combined_with_specific_build_values() {
    for args in [
        ["build", "--target", "all,codex"],
        ["build", "--os", "all,windows"],
    ] {
        let output = arc().args(args).output().unwrap();

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be combined"));
    }
}

#[test]
fn capabilities_target_limits_the_rendered_table() {
    let output = arc()
        .args([
            "capabilities",
            "--target",
            "codex",
            "--path",
            "examples/01-fintech-payments/arc.yaml",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Codex"));
    assert!(!stdout.contains("Gemini (AGY)"));
    assert!(!stdout.contains("Claude"));
    assert!(!stdout.contains("OpenCode"));
}

#[test]
fn explicit_path_must_be_manifest_file_and_never_search_ancestors() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("arc_explicit_manifest_{}", uuid::Uuid::new_v4()));
    let nested = root.join("src");
    let manifest = root.join("arc.yaml");
    let explicit_nested_manifest = nested.join("custom.yaml");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(&manifest, "schema: '1.0'\nroot:\n  workdir: '.'\n").unwrap();
    std::fs::write(
        &explicit_nested_manifest,
        "schema: '2.0'\nroot:\n  workdir: '.'\n",
    )
    .unwrap();

    let capabilities_from_directory = arc()
        .args(["capabilities", "--target", "codex", "--path"])
        .arg(&nested)
        .output()
        .unwrap();
    assert!(!capabilities_from_directory.status.success());
    assert!(capabilities_from_directory.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&capabilities_from_directory.stderr).contains("not a regular file")
    );

    let capabilities_from_file = arc()
        .args(["capabilities", "--target", "codex", "--path"])
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(capabilities_from_file.status.success());
    assert!(String::from_utf8_lossy(&capabilities_from_file.stdout).contains("Inspecting project"));

    let capabilities_implicit = arc()
        .args(["capabilities", "--target", "codex"])
        .current_dir(&nested)
        .output()
        .unwrap();
    assert!(capabilities_implicit.status.success());
    assert!(String::from_utf8_lossy(&capabilities_implicit.stdout).contains("Inspecting project"));

    let build_from_directory = arc()
        .args(["build", "--target", "codex", "--os", "windows", "--path"])
        .arg(&nested)
        .output()
        .unwrap();
    assert!(!build_from_directory.status.success());
    assert!(String::from_utf8_lossy(&build_from_directory.stderr).contains("not a regular file"));

    let build_from_file = arc()
        .args(["build", "--target", "codex", "--os", "windows", "--path"])
        .arg(&explicit_nested_manifest)
        .output()
        .unwrap();
    assert!(!build_from_file.status.success());
    assert!(String::from_utf8_lossy(&build_from_file.stdout).contains("custom.yaml"));
    assert!(
        String::from_utf8_lossy(&build_from_file.stderr)
            .contains("Unsupported schema version '2.0'")
    );
    assert!(!String::from_utf8_lossy(&build_from_file.stderr).contains("not a regular file"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn monitor_on_empty_state_reports_unregistered_workspace_without_sql_error() {
    let root = std::env::temp_dir().join(format!("arc_monitor_empty_{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    let state_dir = root.join("state");
    std::fs::create_dir_all(&workspace).unwrap();

    let output = arc()
        .args(["monitor", "--workspace"])
        .arg(&workspace)
        .args(["--format", "json"])
        .env("ARC_STATE_DIR", &state_dir)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("workspace is not registered in Arc runtime state yet"));
    assert!(!stderr.contains("no such table"));

    std::fs::remove_dir_all(root).unwrap();
}
