use anyhow::{Result, bail};
use std::{ffi::OsString, path::PathBuf};

const TERMINAL_EVIDENCE_ENV: &str = "ARC_WEBDRIVER_TERMINAL_EVIDENCE";

fn evidence_path_from_value(value: Option<OsString>) -> Result<PathBuf> {
    let value = value.ok_or_else(|| anyhow::anyhow!("{TERMINAL_EVIDENCE_ENV} is required"))?;
    if value.is_empty() {
        bail!("{TERMINAL_EVIDENCE_ENV} cannot be empty");
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("{TERMINAL_EVIDENCE_ENV} must be absolute");
    }
    Ok(path)
}

fn resolve_evidence_path() -> Result<PathBuf> {
    // 1. Direct environment variable
    if let Ok(path) = evidence_path_from_value(std::env::var_os(TERMINAL_EVIDENCE_ENV)) {
        return Ok(path);
    }

    // 2. CLI argument passed by EdgeDriver/Chromium
    for arg in std::env::args() {
        if let Some(path_str) = arg.strip_prefix("--terminal-evidence=") {
            if let Ok(path) = evidence_path_from_value(Some(OsString::from(path_str))) {
                return Ok(path);
            }
        }
    }

    // 3. Parent output directory environment variable
    if let Some(out_dir) = std::env::var_os("ARC_WEBDRIVER_OUTPUT_DIR") {
        let candidate = PathBuf::from(out_dir).join("terminal-attempts.log");
        if candidate.is_absolute() {
            return Ok(candidate);
        }
    }

    // 4. Well-known temporary file written by test runner
    let temp_evidence_file = std::env::temp_dir().join("arc-webdriver-terminal-evidence-path.txt");
    if let Ok(content) = std::fs::read_to_string(&temp_evidence_file) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_absolute() {
                return Ok(candidate);
            }
        }
    }

    evidence_path_from_value(None)
}

fn main() {
    // EdgeDriver appends Chromium/WebView2 switches to the application command line.
    // Fixture configuration travels through environment or fallback channels.
    let result = resolve_evidence_path()
        .and_then(|path| arc_decision_ui_host::run_webdriver_fixture(&path));
    if let Err(error) = result {
        let crash_log = std::env::temp_dir().join("arc-webdriver-fixture-crash.log");
        let _ = std::fs::write(
            &crash_log,
            format!(
                "Arc decision UI WebDriver fixture failed: {error:#}\nArgs: {:?}\n",
                std::env::args().collect::<Vec<_>>()
            ),
        );
        eprintln!("Arc decision UI WebDriver fixture failed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_path_requires_a_value() {
        let error = evidence_path_from_value(None).expect_err("missing value must fail");
        assert!(error.to_string().contains(TERMINAL_EVIDENCE_ENV));
    }

    #[test]
    fn evidence_path_rejects_empty_and_relative_values() {
        assert!(evidence_path_from_value(Some(OsString::new())).is_err());
        assert!(evidence_path_from_value(Some(OsString::from("relative.log"))).is_err());
    }

    #[test]
    fn evidence_path_accepts_an_absolute_value() {
        let absolute = std::env::temp_dir().join("arc-webdriver-terminal-attempts.log");
        assert_eq!(
            evidence_path_from_value(Some(absolute.clone().into_os_string()))
                .expect("absolute evidence path must be accepted"),
            absolute
        );
    }
}
