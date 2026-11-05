use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use crate::runtime::guard_evaluation::{DialogRequest, DialogResponse};

use super::lifecycle::{
    DECISION_UI_TIMEOUT_ENV, PARENT_PROCESS_ID_ENV, decision_ui_supervisor_timeout, trace,
    trace_enabled, unresolved_response,
};
use super::model::{
    MAX_DECISION_HOST_INPUT_BYTES, MAX_DECISION_HOST_OUTPUT_BYTES, PortableDecision,
    UnresolvedReason,
};
use super::protocol::bounded_diagnostic;

pub const DECISION_UI_HOST_ENV: &str = "ARC_DECISION_UI_HOST";
pub const DECISION_UI_HOST_BINARY: &str = "arc-decision-ui-host";

/// Presents one request through Arc's owned embedded UI sidecar.
///
/// The sidecar is an implementation boundary: this function knows only the
/// bounded JSON protocol and never imports a renderer or web runtime.
pub fn request_embedded_decision(
    request: &DialogRequest,
    timeout: Duration,
) -> Result<DialogResponse> {
    request
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid embedded decision request v2: {error}"))?;
    let payload =
        serde_json::to_vec(request).context("failed serializing embedded decision request v2")?;
    if payload.len() > MAX_DECISION_HOST_INPUT_BYTES {
        bail!(
            "embedded decision request exceeds the {} byte IPC limit",
            MAX_DECISION_HOST_INPUT_BYTES
        );
    }

    let executable = match resolve_decision_ui_host() {
        Ok(executable) => executable,
        Err(_) => {
            return Ok(transport_failure(
                request,
                "Arc embedded decision UI transport failed",
                "host executable is unavailable",
            ));
        }
    };
    request_embedded_decision_with_host(request, timeout, payload, &executable)
}

fn request_embedded_decision_with_host(
    request: &DialogRequest,
    timeout: Duration,
    payload: Vec<u8>,
    executable: &Path,
) -> Result<DialogResponse> {
    let mut command = Command::new(executable);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    command.env(PARENT_PROCESS_ID_ENV, std::process::id().to_string());
    command.env(
        DECISION_UI_TIMEOUT_ENV,
        timeout.as_millis().min(u128::from(u64::MAX)).to_string(),
    );
    let supervisor_timeout = decision_ui_supervisor_timeout(timeout);
    let lifecycle_trace_enabled = trace_enabled();
    if lifecycle_trace_enabled {
        eprintln!(
            "arc embedded decision ui trace: decision_timeout_ms={} supervisor_timeout_ms={}",
            timeout.as_millis(),
            supervisor_timeout.as_millis()
        );
    }
    trace(lifecycle_trace_enabled, "dialog_process_launch_requested");
    let output = crate::runtime::run_command_bounded_with_input(
        command,
        payload,
        supervisor_timeout,
        MAX_DECISION_HOST_OUTPUT_BYTES,
    );
    if let Ok(host_output) = &output {
        forward_child_lifecycle_trace(lifecycle_trace_enabled, &host_output.stderr);
    }
    trace(lifecycle_trace_enabled, "dialog_process_completed");
    Ok(response_from_host_result(request, timeout, output))
}

fn forward_child_lifecycle_trace(trace_enabled: bool, stderr: &[u8]) {
    if !trace_enabled {
        return;
    }
    let stderr = String::from_utf8_lossy(stderr);
    for line in stderr.lines() {
        let Some(event) = line.strip_prefix("arc embedded decision ui trace: ") else {
            continue;
        };
        if is_safe_child_lifecycle_event(event) {
            eprintln!("arc embedded decision ui trace: child_{event}");
        }
    }
}

fn is_safe_child_lifecycle_event(event: &str) -> bool {
    matches!(
        event,
        "dialog_process_started"
            | "request_validated"
            | "host_build_started"
            | "host_started"
            | "udf_resolved"
            | "udf_strategy=per_session"
            | "window_build_started"
            | "window_build_failed"
            | "window_built_hidden"
            | "page_load_started"
            | "page_load_finished"
            | "request_loaded"
            | "frontend_dom_settled"
            | "frontend_ready"
            | "frontend_ready_timeout"
            | "frontend_failed"
            | "frontend_failure_stage=load_request"
            | "frontend_failure_stage=render_or_ready"
            | "frontend_failure_code=invoke_rejected"
            | "frontend_failure_code=invalid_payload"
            | "frontend_failure_code=render_failed"
            | "frontend_failure_code=unknown"
            | "webview_runtime_busy"
            | "webview_runtime_access_denied"
            | "webview_runtime_error"
            | "ui_ready"
            | "window_visible"
            | "ui_visible"
            | "response_emitted"
            | "host_exit_requested"
    ) || event
        .strip_prefix("webview_runtime_hresult_")
        .is_some_and(|code| code.len() == 8 && code.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn response_from_host_result(
    request: &DialogRequest,
    timeout: Duration,
    output: std::io::Result<Output>,
) -> DialogResponse {
    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            return unresolved_response(
                request.request_id.clone(),
                request.bundle_fingerprint.clone(),
                UnresolvedReason::TimedOut,
                "unknown",
                Some(bounded_diagnostic(
                    "Arc decision deadline expired",
                    &format!("after {} seconds", timeout.as_secs()),
                )),
            );
        }
        Err(_) => {
            return transport_failure(
                request,
                "Arc embedded decision UI transport failed",
                "host process could not be started or joined",
            );
        }
    };

    if !output.status.success() {
        return transport_failure(
            request,
            "Arc embedded decision UI host failed",
            "host exited unsuccessfully",
        );
    }

    let response = match serde_json::from_slice::<DialogResponse>(&output.stdout) {
        Ok(response) => response,
        Err(_) => {
            return transport_failure(
                request,
                "Arc embedded decision UI host returned an invalid response",
                "stdout did not contain one valid DialogResponse",
            );
        }
    };
    if let Err(error) = response.validate_for(request) {
        return transport_failure(
            request,
            "Arc embedded decision UI response failed contract validation",
            &format!("{error}"),
        );
    }
    response
}

fn transport_failure(request: &DialogRequest, prefix: &str, details: &str) -> DialogResponse {
    unresolved_response(
        request.request_id.clone(),
        request.bundle_fingerprint.clone(),
        UnresolvedReason::TransportFailed,
        "unknown",
        Some(bounded_diagnostic(prefix, details)),
    )
}

fn resolve_decision_ui_host() -> Result<PathBuf> {
    let current_executable =
        std::env::current_exe().context("failed resolving the Arc executable")?;
    resolve_decision_ui_host_from(&current_executable, std::env::var_os(DECISION_UI_HOST_ENV))
}

fn resolve_decision_ui_host_from(
    current_executable: &Path,
    configured_host: Option<OsString>,
) -> Result<PathBuf> {
    if let Some(configured_host) = configured_host {
        if configured_host.is_empty() {
            bail!("{DECISION_UI_HOST_ENV} must not be empty");
        }
        let configured_host = PathBuf::from(configured_host);
        if !configured_host.is_file() {
            bail!("configured decision UI host is not a file");
        }
        return Ok(configured_host);
    }

    let executable_directory = current_executable
        .parent()
        .context("Arc executable has no parent directory")?;
    let sibling = executable_directory.join(format!(
        "{DECISION_UI_HOST_BINARY}{}",
        std::env::consts::EXE_SUFFIX
    ));
    if !sibling.is_file() {
        bail!("decision UI sidecar was not found beside Arc");
    }
    Ok(sibling)
}

pub fn request_terminal_decision(title: &str, message: &str) -> Result<PortableDecision> {
    if !io::stdin().is_terminal() {
        bail!("terminal fallback requires an interactive stdin");
    }
    eprintln!("\n{title}\n{message}\n[a] Allow  [d] Deny");
    loop {
        eprint!("> ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "a" | "allow" | "y" | "yes" => return Ok(PortableDecision::Allow),
            "d" | "deny" | "n" | "no" => return Ok(PortableDecision::Deny),
            _ => eprintln!("Enter a or d."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_ui::model::ARC_EMBEDDED_UI_TRANSPORT_LABEL;
    use crate::runtime::guard_evaluation::{DIALOG_RESPONSE_SCHEMA, DialogViolationItem};
    use std::process::ExitStatus;

    #[cfg(unix)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: u32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code)
    }

    fn host_output(code: u32, stdout: Vec<u8>, stderr: Vec<u8>) -> Output {
        Output {
            status: exit_status(code as _),
            stdout,
            stderr,
        }
    }

    fn request() -> DialogRequest {
        DialogRequest::guard_failures(
            "request-1",
            "Decision",
            "once",
            vec![DialogViolationItem {
                guard_id: "guard-1".into(),
                summary: "Allow the operation?".into(),
                configured_feedback: None,
                auditor_findings: None,
                scope: "once".into(),
                failed_probes: Vec::new(),
            }],
            "bundle-1",
            100,
        )
    }

    #[test]
    fn unresolved_host_results_are_non_authorizing_and_wire_compatible() {
        let response = transport_failure(
            &request(),
            "Arc embedded decision UI transport failed",
            "host unavailable",
        );
        assert!(matches!(
            response.decision,
            PortableDecision::Unresolved(UnresolvedReason::TransportFailed)
        ));
        assert_eq!(response.transport, ARC_EMBEDDED_UI_TRANSPORT_LABEL);
        assert_eq!(response.bundle_fingerprint, "bundle-1");
    }

    #[test]
    fn timeout_and_process_failure_are_sanitized_unresolved_results() {
        let timeout = response_from_host_result(
            &request(),
            Duration::from_secs(7),
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "raw timeout details",
            )),
        );
        assert!(matches!(
            timeout.decision,
            PortableDecision::Unresolved(UnresolvedReason::TimedOut)
        ));
        assert_eq!(
            timeout.message.as_deref(),
            Some("Arc decision deadline expired: after 7 seconds")
        );
        assert_eq!(timeout.bundle_fingerprint, "bundle-1");

        let failed = response_from_host_result(
            &request(),
            Duration::from_secs(7),
            Ok(host_output(
                1,
                Vec::new(),
                b"secret child diagnostic".to_vec(),
            )),
        );
        assert!(matches!(
            failed.decision,
            PortableDecision::Unresolved(UnresolvedReason::TransportFailed)
        ));
        assert!(
            !failed
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("secret")
        );
    }

    #[test]
    fn empty_invalid_multiple_and_mismatched_responses_fail_closed() {
        for stdout in [Vec::new(), b"not-json".to_vec(), b"{}\n{}\n".to_vec()] {
            let response = response_from_host_result(
                &request(),
                Duration::from_secs(1),
                Ok(host_output(0, stdout, Vec::new())),
            );
            assert!(matches!(
                response.decision,
                PortableDecision::Unresolved(UnresolvedReason::TransportFailed)
            ));
        }

        for mismatched in [
            DialogResponse {
                schema: DIALOG_RESPONSE_SCHEMA.into(),
                request_id: "different-request".into(),
                bundle_fingerprint: "bundle-1".into(),
                decision: PortableDecision::Allow,
                transport: ARC_EMBEDDED_UI_TRANSPORT_LABEL.into(),
                theme: "dark".into(),
                message: None,
            },
            DialogResponse {
                schema: DIALOG_RESPONSE_SCHEMA.into(),
                request_id: "request-1".into(),
                bundle_fingerprint: "different-bundle".into(),
                decision: PortableDecision::Allow,
                transport: ARC_EMBEDDED_UI_TRANSPORT_LABEL.into(),
                theme: "dark".into(),
                message: None,
            },
        ] {
            let response = response_from_host_result(
                &request(),
                Duration::from_secs(1),
                Ok(host_output(
                    0,
                    serde_json::to_vec(&mismatched).expect("response serializes"),
                    Vec::new(),
                )),
            );
            assert!(matches!(
                response.decision,
                PortableDecision::Unresolved(UnresolvedReason::TransportFailed)
            ));
        }
    }

    #[test]
    fn partial_json_response_is_transport_failure_without_a_retry_path() {
        let response = response_from_host_result(
            &request(),
            Duration::from_secs(1),
            Ok(host_output(
                0,
                br#"{"request_id":"request-1","decision":{"status":"allow"}"#.to_vec(),
                Vec::new(),
            )),
        );
        assert!(matches!(
            response.decision,
            PortableDecision::Unresolved(UnresolvedReason::TransportFailed)
        ));
    }

    #[test]
    fn one_valid_correlated_response_is_preserved_exactly() {
        let expected = DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "request-1".into(),
            bundle_fingerprint: "bundle-1".into(),
            decision: PortableDecision::Deny,
            transport: ARC_EMBEDDED_UI_TRANSPORT_LABEL.into(),
            theme: "light".into(),
            message: Some("not this operation".into()),
        };
        let actual = response_from_host_result(
            &request(),
            Duration::from_secs(1),
            Ok(host_output(
                0,
                serde_json::to_vec(&expected).expect("response serializes"),
                b"diagnostics are not part of the response".to_vec(),
            )),
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn child_trace_forwarding_allowlists_lifecycle_events_only() {
        assert!(is_safe_child_lifecycle_event("dialog_process_started"));
        assert!(is_safe_child_lifecycle_event("ui_visible"));
        assert!(is_safe_child_lifecycle_event("window_built_hidden"));
        assert!(is_safe_child_lifecycle_event("webview_runtime_busy"));
        assert!(is_safe_child_lifecycle_event(
            "webview_runtime_hresult_80004005"
        ));
        assert!(is_safe_child_lifecycle_event("frontend_ready_timeout"));
        assert!(is_safe_child_lifecycle_event(
            "frontend_failure_stage=render_or_ready"
        ));
        assert!(!is_safe_child_lifecycle_event(
            "log:INFO:secret request text"
        ));
        assert!(!is_safe_child_lifecycle_event(
            "window_event:CloseRequested"
        ));
        assert!(!is_safe_child_lifecycle_event(
            "webview_runtime_hresult_80004005 user input"
        ));
        assert!(!is_safe_child_lifecycle_event(
            "webview_runtime_hresult_not-a-code"
        ));
    }

    #[test]
    fn configured_host_is_authoritative_and_sibling_is_the_default() {
        let root = std::env::temp_dir().join(format!(
            "arc-decision-ui-host-resolver-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("temporary directory should be created");
        let current = root.join(format!("arc{}", std::env::consts::EXE_SUFFIX));
        let sibling = root.join(format!(
            "{DECISION_UI_HOST_BINARY}{}",
            std::env::consts::EXE_SUFFIX
        ));
        let configured = root.join(format!("custom-host{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&sibling, b"fixture").expect("sibling fixture should be written");
        std::fs::write(&configured, b"fixture").expect("override fixture should be written");

        assert_eq!(
            resolve_decision_ui_host_from(&current, None).expect("sibling should resolve"),
            sibling
        );
        assert_eq!(
            resolve_decision_ui_host_from(&current, Some(configured.clone().into_os_string()))
                .expect("configured host should resolve"),
            configured
        );

        std::fs::remove_dir_all(root).expect("temporary directory should be removed");
    }

    #[test]
    fn invalid_configured_host_does_not_fall_back_to_a_sibling() {
        let root = std::env::temp_dir().join(format!(
            "arc-decision-ui-host-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("temporary directory should be created");
        let current = root.join(format!("arc{}", std::env::consts::EXE_SUFFIX));
        let sibling = root.join(format!(
            "{DECISION_UI_HOST_BINARY}{}",
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::write(&sibling, b"fixture").expect("sibling fixture should be written");

        assert!(
            resolve_decision_ui_host_from(
                &current,
                Some(root.join("missing-host").into_os_string())
            )
            .is_err()
        );

        std::fs::remove_dir_all(root).expect("temporary directory should be removed");
    }
}
