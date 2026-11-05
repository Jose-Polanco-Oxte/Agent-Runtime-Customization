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

fn main() {
    // EdgeDriver appends Chromium/WebView2 switches to the application command line.
    // Fixture configuration therefore travels through an inherited environment value.
    let result = evidence_path_from_value(std::env::var_os(TERMINAL_EVIDENCE_ENV))
        .and_then(|path| arc_decision_ui_host::run_webdriver_fixture(&path));
    if let Err(error) = result {
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
