use anyhow::Result;
use arc::decision_ui::{
    ARC_EMBEDDED_UI_TRANSPORT_LABEL, CompletionError, CompletionOutcome,
    MAX_DIALOG_USER_MESSAGE_CHARS, PARENT_LIVENESS_POLL_INTERVAL, PortableDecision,
    TerminalCoordinator, TerminalState, TerminalWriter, UiTheme, UnresolvedReason,
    bounded_user_message, decision_ui_timeout_from_environment, parent_process_id_from_environment,
    parent_process_is_alive, read_dialog_request, serialize_dialog_response, trace, trace_enabled,
    unresolved_response, write_serialized_dialog_response,
};
use arc::runtime::guard_evaluation::{DIALOG_RESPONSE_SCHEMA, DialogRequest, DialogResponse};
#[cfg(feature = "webdriver-fixture")]
use arc::runtime::guard_evaluation::{DialogAuthorizationItem, DialogViolationItem};
use serde::{Deserialize, Serialize};
use std::io;
#[cfg(feature = "webdriver-fixture")]
use std::io::Write;
#[cfg(feature = "webdriver-fixture")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
#[cfg(feature = "webdriver-fixture")]
use tauri::WebviewUrl;
use tauri::webview::{PageLoadEvent, WebviewWindowBuilder};
use tauri::{AppHandle, Manager, State, UserAttentionType, WebviewWindow, WindowEvent};

mod udf;

const DECISION_WINDOW_LABEL: &str = "decision";
#[cfg(feature = "webdriver-fixture")]
const UNAUTHORIZED_WINDOW_LABEL: &str = "unauthorized";
const FRONTEND_READY_TIMEOUT: Duration = Duration::from_secs(30);
const HOST_EXIT_FALLBACK_DELAY: Duration = Duration::from_millis(250);
#[cfg(any(feature = "frontend-failure-seam", test))]
const FRONTEND_FAILURE_SEAM_ENV: &str = "ARC_DECISION_UI_TEST_FRONTEND_FAILURE";
#[cfg(feature = "webdriver-fixture")]
const WEBDRIVER_FIXTURE_TIMEOUT: Duration = Duration::from_secs(120);

struct TraceLogger;

static TRACE_LOGGER: TraceLogger = TraceLogger;

impl log::Log for TraceLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            if record.target() == "tauri_runtime_wry" && record.level() == log::Level::Error {
                let message = record.args().to_string();
                let event = webview_runtime_error_event(&message);
                eprintln!("arc embedded decision ui trace: {event}");
            }
            eprintln!(
                "arc embedded decision ui trace: log:{}:{}:{}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

fn webview_runtime_error_event(message: &str) -> String {
    match extract_hresult(message) {
        Some(0x8007_00AA) => "webview_runtime_busy".into(),
        Some(0x8007_0005) => "webview_runtime_access_denied".into(),
        Some(code) => format!("webview_runtime_hresult_{code:08X}"),
        None if message.contains("Access is denied") => "webview_runtime_access_denied".into(),
        None => "webview_runtime_error".into(),
    }
}

fn extract_hresult(message: &str) -> Option<u32> {
    for (start, _) in message.match_indices("0x") {
        let before = message[..start].chars().next_back();
        if before.is_some_and(|character| character.is_ascii_alphanumeric()) {
            continue;
        }

        let digits_start = start + 2;
        let digits_end = digits_start + 8;
        let Some(digits) = message.get(digits_start..digits_end) else {
            continue;
        };
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if message
            .get(digits_end..)
            .and_then(|suffix| suffix.bytes().next())
            .is_some_and(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }

        return u32::from_str_radix(digits, 16).ok();
    }
    None
}

fn init_trace_logging() {
    if trace_enabled() {
        let _ = log::set_logger(&TRACE_LOGGER);
        log::set_max_level(log::LevelFilter::Trace);
    }
}

fn detect_system_theme() -> UiTheme {
    match dark_light::detect() {
        Ok(dark_light::Mode::Dark) => UiTheme::Dark,
        Ok(dark_light::Mode::Light) => UiTheme::Light,
        _ => UiTheme::Light,
    }
}

#[derive(Debug, Clone, Serialize)]
struct DecisionViewModel {
    request: DialogRequest,
    theme: UiTheme,
    max_user_message_chars: usize,
    preview: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DecisionIntent {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
struct DecisionSubmission {
    request_id: String,
    decision: DecisionIntent,
    message: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FrontendFailureStage {
    LoadRequest,
    RenderOrReady,
}

impl FrontendFailureStage {
    const fn diagnostic_event(self) -> &'static str {
        match self {
            Self::LoadRequest => "frontend_failure_stage=load_request",
            Self::RenderOrReady => "frontend_failure_stage=render_or_ready",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FrontendFailureCode {
    InvokeRejected,
    InvalidPayload,
    RenderFailed,
    Unknown,
}

impl FrontendFailureCode {
    const fn diagnostic_event(self) -> &'static str {
        match self {
            Self::InvokeRejected => "frontend_failure_code=invoke_rejected",
            Self::InvalidPayload => "frontend_failure_code=invalid_payload",
            Self::RenderFailed => "frontend_failure_code=render_failed",
            Self::Unknown => "frontend_failure_code=unknown",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct FrontendFailure {
    request_id: Option<String>,
    stage: FrontendFailureStage,
    code: FrontendFailureCode,
}

#[cfg(any(feature = "frontend-failure-seam", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrontendFailureInjection {
    LoadRequest,
    RenderOrReady,
}

#[cfg(feature = "frontend-failure-seam")]
fn trace_frontend_failure_injected(trace_enabled: bool, injection: FrontendFailureInjection) {
    match injection {
        FrontendFailureInjection::LoadRequest => {
            trace(trace_enabled, "frontend_failure_injected_load_request")
        }
        FrontendFailureInjection::RenderOrReady => {
            trace(trace_enabled, "frontend_failure_injected_render_or_ready")
        }
    }
}

#[cfg(any(feature = "frontend-failure-seam", test))]
fn parse_frontend_failure_injection(
    value: Option<&str>,
) -> Result<Option<FrontendFailureInjection>> {
    match value {
        None | Some("") => Ok(None),
        Some("load_request") => Ok(Some(FrontendFailureInjection::LoadRequest)),
        Some("render_or_ready") => Ok(Some(FrontendFailureInjection::RenderOrReady)),
        Some(value) => anyhow::bail!(
            "{FRONTEND_FAILURE_SEAM_ENV} must be load_request or render_or_ready, got unsupported value '{value}'"
        ),
    }
}

#[cfg(feature = "frontend-failure-seam")]
fn configured_frontend_failure_injection() -> Result<Option<FrontendFailureInjection>> {
    parse_frontend_failure_injection(std::env::var(FRONTEND_FAILURE_SEAM_ENV).ok().as_deref())
}

struct StdoutDialogResponseSink;

impl TerminalWriter for StdoutDialogResponseSink {
    fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
        write_serialized_dialog_response(io::stdout().lock(), frame).map_err(|error| {
            io::Error::other(format!(
                "failed writing embedded decision response: {error}"
            ))
        })
    }
}

#[cfg(feature = "webdriver-fixture")]
struct WebdriverEvidenceResponseSink {
    evidence_path: PathBuf,
}

#[cfg(feature = "webdriver-fixture")]
impl WebdriverEvidenceResponseSink {
    fn new(evidence_path: &Path) -> Result<Self> {
        if !evidence_path.is_absolute() {
            anyhow::bail!("WebDriver terminal evidence path must be absolute");
        }
        let parent = evidence_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("WebDriver terminal evidence parent is unavailable"))?;
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("failed creating WebDriver evidence root: {error}"))?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(evidence_path)
            .map_err(|error| {
                anyhow::anyhow!("failed initializing WebDriver terminal evidence: {error}")
            })?;
        file.sync_all().map_err(|error| {
            anyhow::anyhow!("failed syncing WebDriver terminal evidence: {error}")
        })?;
        Ok(Self {
            evidence_path: evidence_path.to_path_buf(),
        })
    }

    fn record_terminal_attempt(&self) -> io::Result<()> {
        let mut evidence = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.evidence_path)?;
        evidence.write_all(b"terminal_response_attempted\n")?;
        evidence.flush()?;
        evidence.sync_all()
    }
}

#[cfg(feature = "webdriver-fixture")]
impl TerminalWriter for WebdriverEvidenceResponseSink {
    fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
        self.record_terminal_attempt()?;
        if let Some(parent) = self.evidence_path.parent() {
            let response_path = parent.join("structured-response.json");
            let _ = std::fs::write(&response_path, frame);
        }
        StdoutDialogResponseSink.write_frame(frame)
    }
}

trait HostExit: Send + Sync {
    fn request_exit(&self, code: i32);
}

impl HostExit for AppHandle {
    fn request_exit(&self, code: i32) {
        self.exit(code);
        let fallback = std::thread::Builder::new()
            .name("arc-decision-host-exit-fallback".into())
            .spawn(move || {
                std::thread::sleep(HOST_EXIT_FALLBACK_DELAY);
                std::process::exit(code);
            });
        if fallback.is_err() {
            std::process::exit(code);
        }
    }
}

struct DecisionSession {
    request: DialogRequest,
    theme: UiTheme,
    terminal: TerminalCoordinator,
    parent_process_id: Option<u32>,
    deadline: Instant,
    frontend_deadline: Instant,
    frontend_ready: AtomicBool,
    response_sink: Arc<dyn TerminalWriter>,
    trace_enabled: bool,
}

impl DecisionSession {
    fn new(
        request: DialogRequest,
        theme: UiTheme,
        timeout: Duration,
        parent_process_id: Option<u32>,
        response_sink: Arc<dyn TerminalWriter>,
        trace_enabled: bool,
    ) -> Result<Self> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid embedded decision request v2: {error}"))?;
        let started_at = Instant::now();
        let deadline = started_at
            .checked_add(timeout)
            .ok_or_else(|| anyhow::anyhow!("decision timeout exceeds monotonic clock range"))?;
        let frontend_deadline = started_at
            .checked_add(timeout.min(FRONTEND_READY_TIMEOUT))
            .ok_or_else(|| anyhow::anyhow!("frontend timeout exceeds monotonic clock range"))?;
        Ok(Self {
            request,
            theme,
            terminal: TerminalCoordinator::new(),
            parent_process_id,
            deadline,
            frontend_deadline,
            frontend_ready: AtomicBool::new(false),
            response_sink,
            trace_enabled,
        })
    }

    fn view_model(&self) -> DecisionViewModel {
        DecisionViewModel {
            request: self.request.clone(),
            theme: self.theme,
            max_user_message_chars: MAX_DIALOG_USER_MESSAGE_CHARS,
            preview: false,
        }
    }

    fn mark_frontend_ready(&self, request_id: &str) -> Result<()> {
        self.validate_request_id(request_id)?;
        if self.is_terminal() {
            anyhow::bail!("decision session is already complete");
        }
        if Instant::now() >= self.deadline {
            anyhow::bail!("decision deadline expired");
        }
        self.frontend_ready.store(true, Ordering::Release);
        trace(self.trace_enabled, "frontend_ready");
        trace(self.trace_enabled, "ui_ready");
        Ok(())
    }

    fn submit(&self, submission: DecisionSubmission) -> Result<bool> {
        self.validate_request_id(&submission.request_id)?;
        if submission
            .message
            .as_deref()
            .is_some_and(|message| message.chars().count() > MAX_DIALOG_USER_MESSAGE_CHARS)
        {
            anyhow::bail!(
                "decision message exceeds the {MAX_DIALOG_USER_MESSAGE_CHARS} character limit"
            );
        }
        let decision = match submission.decision {
            DecisionIntent::Allow => PortableDecision::Allow,
            DecisionIntent::Deny => PortableDecision::Deny,
        };
        let message = submission.message.as_deref().and_then(bounded_user_message);
        self.finish_before_deadline(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: self.request.request_id.clone(),
            bundle_fingerprint: self.request.bundle_fingerprint.clone(),
            decision,
            transport: ARC_EMBEDDED_UI_TRANSPORT_LABEL.into(),
            theme: self.theme.to_string(),
            message,
        })
    }

    fn dismiss(&self, request_id: &str) -> Result<bool> {
        self.validate_request_id(request_id)?;
        self.finish_before_deadline(unresolved_response(
            self.request.request_id.clone(),
            self.request.bundle_fingerprint.clone(),
            UnresolvedReason::Closed,
            self.theme.as_str(),
            None,
        ))
    }

    fn frontend_failed(&self, failure: FrontendFailure) -> Result<bool> {
        if let Some(request_id) = failure.request_id.as_deref() {
            self.validate_request_id(request_id)?;
        }
        trace(self.trace_enabled, failure.stage.diagnostic_event());
        trace(self.trace_enabled, failure.code.diagnostic_event());
        self.finish_unresolved(
            UnresolvedReason::TransportFailed,
            Some("Arc decision frontend failed to initialize".into()),
        )
    }

    fn finish_unresolved(&self, reason: UnresolvedReason, message: Option<String>) -> Result<bool> {
        self.finish(unresolved_response(
            self.request.request_id.clone(),
            self.request.bundle_fingerprint.clone(),
            reason,
            self.theme.as_str(),
            message,
        ))
    }

    fn finish(&self, response: DialogResponse) -> Result<bool> {
        self.finish_with_deadline(response, None)
    }

    fn finish_before_deadline(&self, response: DialogResponse) -> Result<bool> {
        self.finish_with_deadline(response, Some(self.deadline))
    }

    fn finish_with_deadline(
        &self,
        response: DialogResponse,
        deadline: Option<Instant>,
    ) -> Result<bool> {
        let frame = serialize_dialog_response(&response)?;
        let emission = match deadline {
            Some(deadline) => {
                self.terminal
                    .emit_before(&frame, self.response_sink.as_ref(), deadline)
            }
            None => self.terminal.emit(&frame, self.response_sink.as_ref()),
        };
        match emission {
            Ok(CompletionOutcome::Emitted) => {
                trace(self.trace_enabled, "response_emitted");
                Ok(true)
            }
            Err(CompletionError::AlreadyCompleted | CompletionError::DeadlineExpired) => Ok(false),
            Err(CompletionError::Emission(error)) => Err(anyhow::anyhow!(
                "failed emitting embedded decision response: {error}"
            )),
        }
    }

    fn is_terminal(&self) -> bool {
        self.terminal.state() != TerminalState::Open
    }

    #[cfg(test)]
    fn terminal_state(&self) -> TerminalState {
        self.terminal.state()
    }

    fn validate_request_id(&self, request_id: &str) -> Result<()> {
        if request_id != self.request.request_id {
            anyhow::bail!("decision request correlation mismatch");
        }
        Ok(())
    }
}

#[tauri::command]
fn get_decision_request(
    session: State<'_, Arc<DecisionSession>>,
) -> std::result::Result<DecisionViewModel, String> {
    #[cfg(feature = "frontend-failure-seam")]
    match configured_frontend_failure_injection() {
        Ok(Some(injection @ FrontendFailureInjection::LoadRequest)) => {
            trace_frontend_failure_injected(session.trace_enabled, injection);
            return Err("frontend load failure seam injected".into());
        }
        Ok(Some(FrontendFailureInjection::RenderOrReady)) | Ok(None) => {}
        Err(error) => {
            trace(
                session.trace_enabled,
                "frontend_failure_seam_configuration_invalid",
            );
            return Err(error.to_string());
        }
    }
    trace(session.trace_enabled, "request_loaded");
    Ok(session.view_model())
}

#[tauri::command]
fn frontend_ready(
    app: AppHandle,
    window: WebviewWindow,
    session: State<'_, Arc<DecisionSession>>,
    request_id: String,
) -> std::result::Result<(), String> {
    trace(session.trace_enabled, "frontend_dom_settled");
    #[cfg(feature = "frontend-failure-seam")]
    match configured_frontend_failure_injection() {
        Ok(Some(injection @ FrontendFailureInjection::RenderOrReady)) => {
            trace_frontend_failure_injected(session.trace_enabled, injection);
            return Err("frontend readiness failure seam injected".into());
        }
        Ok(Some(FrontendFailureInjection::LoadRequest)) | Ok(None) => {}
        Err(error) => {
            trace(
                session.trace_enabled,
                "frontend_failure_seam_configuration_invalid",
            );
            return Err(error.to_string());
        }
    }
    session
        .mark_frontend_ready(&request_id)
        .map_err(|error| error.to_string())?;
    if let Err(error) = window.show().and_then(|_| window.set_focus()) {
        let _ = error;
        let _ = complete_and_exit(
            &app,
            &session,
            || best_effort_window_cleanup(&window, session.trace_enabled),
            |session| {
                session.finish_unresolved(
                    UnresolvedReason::TransportFailed,
                    Some("Arc decision window could not be presented".into()),
                )
            },
            "window_present_failed",
        );
        return Err("decision window could not be presented".into());
    }
    trace(session.trace_enabled, "window_visible");
    trace(session.trace_enabled, "ui_visible");
    if window
        .request_user_attention(Some(UserAttentionType::Informational))
        .is_err()
    {
        trace(session.trace_enabled, "user_attention_unavailable");
    }
    Ok(())
}

#[tauri::command]
fn submit_decision(
    app: AppHandle,
    window: WebviewWindow,
    session: State<'_, Arc<DecisionSession>>,
    submission: DecisionSubmission,
) -> std::result::Result<(), String> {
    complete_and_exit(
        &app,
        &session,
        || best_effort_window_cleanup(&window, session.trace_enabled),
        move |session| session.submit(submission),
        "selection",
    )
}

#[tauri::command]
fn dismiss_decision(
    app: AppHandle,
    window: WebviewWindow,
    session: State<'_, Arc<DecisionSession>>,
    request_id: String,
) -> std::result::Result<(), String> {
    complete_and_exit(
        &app,
        &session,
        || best_effort_window_cleanup(&window, session.trace_enabled),
        move |session| session.dismiss(&request_id),
        "dismissed",
    )
}

#[tauri::command]
fn frontend_failed(
    app: AppHandle,
    window: WebviewWindow,
    session: State<'_, Arc<DecisionSession>>,
    failure: FrontendFailure,
) -> std::result::Result<(), String> {
    complete_and_exit(
        &app,
        &session,
        || best_effort_window_cleanup(&window, session.trace_enabled),
        move |session| session.frontend_failed(failure),
        "frontend_failed",
    )
}

fn monitor_lifecycle(app: AppHandle, session: Arc<DecisionSession>) {
    std::thread::spawn(move || {
        loop {
            if session.is_terminal() {
                return;
            }
            if !parent_process_is_alive(session.parent_process_id) {
                finish_lifecycle_and_exit(
                    &app,
                    &session,
                    UnresolvedReason::TransportFailed,
                    Some("Arc decision parent process is no longer alive".into()),
                    "parent_process_lost",
                );
                return;
            }
            let now = Instant::now();
            if now >= session.deadline {
                finish_lifecycle_and_exit(
                    &app,
                    &session,
                    UnresolvedReason::TimedOut,
                    Some("Arc decision deadline expired".into()),
                    "decision_timeout",
                );
                return;
            }
            if !session.frontend_ready.load(Ordering::Acquire) && now >= session.frontend_deadline {
                finish_lifecycle_and_exit(
                    &app,
                    &session,
                    UnresolvedReason::TransportFailed,
                    Some("Arc decision frontend did not become ready".into()),
                    "frontend_ready_timeout",
                );
                return;
            }
            std::thread::sleep(PARENT_LIVENESS_POLL_INTERVAL);
        }
    });
}

fn finish_lifecycle_and_exit(
    app: &AppHandle,
    session: &DecisionSession,
    reason: UnresolvedReason,
    message: Option<String>,
    event: &'static str,
) {
    let _ = complete_and_exit(
        app,
        session,
        || Ok(()),
        move |session| session.finish_unresolved(reason, message),
        event,
    );
}

fn build_decision_window(
    app: &AppHandle,
    session: &Arc<DecisionSession>,
    data_directory: std::path::PathBuf,
) -> Result<()> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|config| config.label == DECISION_WINDOW_LABEL)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("decision window template is unavailable"))?;
    let trace_enabled = session.trace_enabled;
    WebviewWindowBuilder::from_config(app, &config)
        .map_err(|error| anyhow::anyhow!("decision window builder failed: {error}"))?
        .data_directory(data_directory)
        .prevent_overflow()
        .auto_resize()
        .on_page_load(move |_window, payload| {
            let event = match payload.event() {
                PageLoadEvent::Started => "page_load_started",
                PageLoadEvent::Finished => "page_load_finished",
            };
            trace(trace_enabled, event);
        })
        .build()
        .map_err(|error| anyhow::anyhow!("decision webview creation failed: {error}"))?;
    trace(session.trace_enabled, "window_built_hidden");
    Ok(())
}

#[cfg(feature = "webdriver-fixture")]
fn build_unauthorized_window(app: &AppHandle, data_directory: PathBuf) -> Result<()> {
    WebviewWindowBuilder::new(
        app,
        UNAUTHORIZED_WINDOW_LABEL,
        WebviewUrl::App("index.html".into()),
    )
    .title("Arc WebDriver unauthorized fixture")
    .visible(true)
    .data_directory(data_directory)
    .build()
    .map_err(|error| anyhow::anyhow!("unauthorized WebDriver fixture build failed: {error}"))?;
    trace(true, "unauthorized_window_built");
    Ok(())
}

fn best_effort_window_cleanup(
    window: &WebviewWindow,
    trace_enabled: bool,
) -> std::result::Result<(), ()> {
    let hide_failed = window.hide().is_err();
    if hide_failed {
        trace(trace_enabled, "window_cleanup_failed");
    }
    if hide_failed { Err(()) } else { Ok(()) }
}

fn complete_and_exit<C, F>(
    exit: &dyn HostExit,
    session: &DecisionSession,
    cleanup: C,
    complete: F,
    event: &'static str,
) -> std::result::Result<(), String>
where
    C: FnOnce() -> std::result::Result<(), ()>,
    F: FnOnce(&DecisionSession) -> Result<bool>,
{
    trace(session.trace_enabled, event);
    match complete(session) {
        Ok(true) => {
            let _ = cleanup();
            trace(session.trace_enabled, "host_exit_requested");
            exit.request_exit(0);
            Ok(())
        }
        Ok(false) => Err("decision session is already complete".into()),
        Err(error) => {
            trace(session.trace_enabled, "response_emission_failed");
            trace(session.trace_enabled, "host_exit_requested");
            exit.request_exit(1);
            Err(error.to_string())
        }
    }
}

fn resolve_local_app_data(app: &AppHandle, trace_enabled: bool) -> Result<PathBuf> {
    if let Some(override_path) = std::env::var_os("ARC_DECISION_UI_UDF_ROOT") {
        if override_path.is_empty() {
            return Err(anyhow::anyhow!(
                "ARC_DECISION_UI_UDF_ROOT must not be empty"
            ));
        }
        let path = PathBuf::from(override_path);
        if !path.is_absolute() {
            return Err(anyhow::anyhow!(
                "ARC_DECISION_UI_UDF_ROOT must be an absolute path"
            ));
        }
        trace(trace_enabled, "local_data_dir_override");
        return Ok(path);
    }

    match app.path().local_data_dir() {
        Ok(path) => Ok(path),
        Err(_) => {
            trace(trace_enabled, "local_data_dir_env_fallback");
            let path = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("local app data directory is unavailable"))?;
            if !path.is_absolute() {
                return Err(anyhow::anyhow!(
                    "LOCALAPPDATA is not an absolute local app data directory"
                ));
            }
            Ok(path)
        }
    }
}

fn run_tauri_host(session: Arc<DecisionSession>) -> tauri::Result<()> {
    let setup_session = Arc::clone(&session);
    let context = tauri::generate_context!();

    let app = tauri::Builder::default()
        .manage(session)
        .invoke_handler(tauri::generate_handler![
            self::get_decision_request,
            self::frontend_ready,
            self::frontend_failed,
            self::submit_decision,
            self::dismiss_decision
        ])
        .setup(move |app| {
            if setup_session.trace_enabled {
                eprintln!(
                    "arc embedded decision ui trace: setup_thread_id={:?}",
                    std::thread::current().id()
                );
            }
            let app_handle = app.handle().clone();
            monitor_lifecycle(app_handle.clone(), Arc::clone(&setup_session));
            trace(setup_session.trace_enabled, "host_started");
            let builder_session = Arc::clone(&setup_session);
            let builder_app = app_handle.clone();
            let builder = std::thread::Builder::new()
                .name("arc-decision-webview-builder".into())
                .spawn(move || {
                    let local_app_data =
                        match resolve_local_app_data(&builder_app, builder_session.trace_enabled) {
                            Ok(path) => path,
                            Err(_) => {
                                trace(
                                    builder_session.trace_enabled,
                                    "local_app_data_resolution_failed",
                                );
                                finish_lifecycle_and_exit(
                                    &builder_app,
                                    &builder_session,
                                    UnresolvedReason::TransportFailed,
                                    Some("Arc decision WebView data directory unavailable".into()),
                                    "udf_resolution_failed",
                                );
                                return;
                            }
                        };
                    let udf = match udf::resolve_session_udf(
                        &local_app_data,
                        std::process::id(),
                        &builder_session.request.request_id,
                    ) {
                        Ok(path) => path,
                        Err(error) => {
                            trace(
                                builder_session.trace_enabled,
                                udf::failure_trace_event(&error),
                            );
                            finish_lifecycle_and_exit(
                                &builder_app,
                                &builder_session,
                                UnresolvedReason::TransportFailed,
                                Some("Arc decision WebView data directory unavailable".into()),
                                "udf_resolution_failed",
                            );
                            return;
                        }
                    };
                    trace(builder_session.trace_enabled, "udf_resolved");
                    trace(builder_session.trace_enabled, "udf_strategy=per_session");
                    trace(builder_session.trace_enabled, "window_build_started");
                    if let Err(error) = build_decision_window(&builder_app, &builder_session, udf.clone()) {
                        eprintln!("arc embedded decision ui trace: window_build_failed: {error:#}");
                        let crash_log = std::env::temp_dir().join("arc-webdriver-fixture-crash.log");
                        let _ = std::fs::write(&crash_log, format!("window_build_failed: {error:#}\n"));
                        finish_lifecycle_and_exit(
                            &builder_app,
                            &builder_session,
                            UnresolvedReason::TransportFailed,
                            Some(format!("Arc decision WebView could not be created: {error:#}")),
                            "window_build_failed",
                        );
                        return;
                    }
                    #[cfg(feature = "webdriver-fixture")]
                    if let Err(error) = build_unauthorized_window(&builder_app, udf) {
                        eprintln!("arc embedded decision ui trace: unauthorized_window_build_failed: {error:#}");
                        let crash_log = std::env::temp_dir().join("arc-webdriver-fixture-crash.log");
                        let _ = std::fs::write(&crash_log, format!("unauthorized_window_build_failed: {error:#}\n"));
                        finish_lifecycle_and_exit(
                            &builder_app,
                            &builder_session,
                            UnresolvedReason::TransportFailed,
                            Some(format!("Arc unauthorized WebDriver fixture could not be created: {error:#}")),
                            "unauthorized_window_build_failed",
                        );
                    }
                });
            if builder.is_err() {
                finish_lifecycle_and_exit(
                    &app_handle,
                    &setup_session,
                    UnresolvedReason::TransportFailed,
                    Some("Arc decision WebView builder thread could not start".into()),
                    "window_build_thread_failed",
                );
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != DECISION_WINDOW_LABEL {
                return;
            }
            let is_terminal_window_event = matches!(
                event,
                WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed
            );
            if trace_enabled() && is_terminal_window_event {
                eprintln!("arc embedded decision ui trace: window_event:{event:?}");
            }
            if is_terminal_window_event {
                let session = window.state::<Arc<DecisionSession>>();
                let app = window.app_handle().clone();
                let _ = complete_and_exit(
                    &app,
                    &session,
                    || Ok(()),
                    |session| session.finish_unresolved(UnresolvedReason::Closed, None),
                    "window_closed",
                );
            }
        })
        .build(context)?;

    app.run(|app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let session = app_handle.state::<Arc<DecisionSession>>();
            if !session.is_terminal() {
                api.prevent_exit();
            }
        }
    });
    Ok(())
}

fn complete_after_host(session: &DecisionSession, host_result: &tauri::Result<()>) -> Result<()> {
    if session.is_terminal() {
        return Ok(());
    }

    let (reason, message) = if host_result.is_ok() {
        (UnresolvedReason::Closed, None)
    } else {
        (
            UnresolvedReason::TransportFailed,
            Some("Arc embedded decision UI host failed to initialize".into()),
        )
    };
    let _ = session.finish_unresolved(reason, message)?;
    Ok(())
}

pub fn run_from_stdio() -> Result<()> {
    init_trace_logging();
    let request = read_dialog_request(io::stdin().lock())?;
    let theme = detect_system_theme();
    let timeout = decision_ui_timeout_from_environment();
    let parent_process_id = parent_process_id_from_environment();
    let trace_enabled = trace_enabled();
    let response_sink: Arc<dyn TerminalWriter> = Arc::new(StdoutDialogResponseSink);
    let session = Arc::new(DecisionSession::new(
        request,
        theme,
        timeout,
        parent_process_id,
        Arc::clone(&response_sink),
        trace_enabled,
    )?);
    trace(trace_enabled, "dialog_process_started");
    trace(trace_enabled, "request_validated");
    trace(trace_enabled, "host_build_started");
    let host_result = run_tauri_host(Arc::clone(&session));
    complete_after_host(&session, &host_result)?;
    Ok(())
}

#[cfg(feature = "webdriver-fixture")]
pub fn run_webdriver_fixture(evidence_path: &Path) -> Result<()> {
    let request = DialogRequest::aggregate_decision(
        "webdriver-request",
        "Arc WebDriver integration fixture",
        "isolated WebDriver integration test",
        vec![DialogViolationItem {
            guard_id: "webdriver-ask".into(),
            summary: "Validate readiness and deny commands from an unauthorized window.".into(),
            configured_feedback: None,
            auditor_findings: None,
            scope: "isolated WebDriver integration test".into(),
            failed_probes: Vec::new(),
        }],
        vec![DialogAuthorizationItem {
            guard_id: "webdriver-auth".into(),
            summary: "Operation requires interactive confirmation.".into(),
            operation_fingerprint: "sha256:auth-fingerprint".into(),
            auditor_findings: None,
        }],
        Some("Bash git push".into()),
        "sha256:semantic-bundle-fingerprint-12345678",
        0,
    );
    let response_sink: Arc<dyn TerminalWriter> =
        Arc::new(WebdriverEvidenceResponseSink::new(evidence_path)?);
    let session = Arc::new(DecisionSession::new(
        request,
        UiTheme::Light,
        WEBDRIVER_FIXTURE_TIMEOUT,
        None,
        response_sink,
        true,
    )?);
    trace(true, "request_validated");
    trace(true, "host_build_started");
    let host_result = run_tauri_host(Arc::clone(&session));
    complete_after_host(&session, &host_result)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingDialogResponseSink {
        responses: Mutex<Vec<DialogResponse>>,
    }

    impl RecordingDialogResponseSink {
        fn responses(&self) -> Vec<DialogResponse> {
            self.responses
                .lock()
                .expect("recording response sink lock")
                .clone()
        }
    }

    impl TerminalWriter for RecordingDialogResponseSink {
        fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
            let response: DialogResponse = serde_json::from_slice(frame)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            self.responses
                .lock()
                .map_err(|_| io::Error::other("recording response sink lock poisoned"))?
                .push(response.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingHostExit {
        codes: Mutex<Vec<i32>>,
    }

    impl HostExit for RecordingHostExit {
        fn request_exit(&self, code: i32) {
            self.codes.lock().expect("exit codes lock").push(code);
        }
    }

    struct FailingDialogResponseSink;

    impl TerminalWriter for FailingDialogResponseSink {
        fn write_frame(&self, _frame: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fault-injected response writer",
            ))
        }
    }

    fn request() -> DialogRequest {
        DialogRequest::guard_failures(
            "request-host",
            "Decision",
            "once",
            vec![arc::runtime::guard_evaluation::DialogViolationItem {
                guard_id: "guard".into(),
                summary: "Allow the operation?".into(),
                scope: "once".into(),
                configured_feedback: None,
                auditor_findings: None,
                failed_probes: Vec::new(),
            }],
            "bundle-host",
            100,
        )
    }

    fn session() -> (DecisionSession, Arc<RecordingDialogResponseSink>) {
        let response_sink = Arc::new(RecordingDialogResponseSink::default());
        let session = DecisionSession::new(
            request(),
            UiTheme::Dark,
            Duration::from_secs(30),
            None,
            response_sink.clone(),
            false,
        )
        .expect("fixture session should be valid");
        (session, response_sink)
    }

    fn failing_session() -> DecisionSession {
        DecisionSession::new(
            request(),
            UiTheme::Dark,
            Duration::from_secs(30),
            None,
            Arc::new(FailingDialogResponseSink),
            false,
        )
        .expect("fixture session should be valid")
    }

    #[test]
    fn view_model_preserves_request_contract_without_authorization_state() {
        let (session, _) = session();
        let model = session.view_model();
        assert_eq!(model.request, request());
        assert_eq!(model.max_user_message_chars, 4_000);
        assert!(!model.preview);
    }

    #[test]
    fn explicit_submission_builds_one_correlated_response_in_rust() {
        let (session, response_sink) = session();
        assert!(
            session
                .submit(DecisionSubmission {
                    request_id: "request-host".into(),
                    decision: DecisionIntent::Allow,
                    message: Some("  approved once  ".into()),
                })
                .expect("submission should be valid")
        );
        assert!(
            !session
                .submit(DecisionSubmission {
                    request_id: "request-host".into(),
                    decision: DecisionIntent::Deny,
                    message: None,
                })
                .expect("second submission is structurally valid")
        );
        let responses = response_sink.responses();
        assert_eq!(responses.len(), 1);
        let response = &responses[0];
        assert_eq!(response.request_id, "request-host");
        assert_eq!(response.bundle_fingerprint, "bundle-host");
        assert_eq!(response.decision, PortableDecision::Allow);
        assert_eq!(response.transport, ARC_EMBEDDED_UI_TRANSPORT_LABEL);
        assert_eq!(response.message.as_deref(), Some("approved once"));
        assert_eq!(session.terminal_state(), TerminalState::Emitted);
    }

    #[test]
    fn correlation_and_message_limits_are_enforced_before_selection() {
        let (session, response_sink) = session();
        assert!(
            session
                .submit(DecisionSubmission {
                    request_id: "other-request".into(),
                    decision: DecisionIntent::Allow,
                    message: None,
                })
                .is_err()
        );
        assert!(
            session
                .submit(DecisionSubmission {
                    request_id: "request-host".into(),
                    decision: DecisionIntent::Allow,
                    message: Some("x".repeat(MAX_DIALOG_USER_MESSAGE_CHARS + 1)),
                })
                .is_err()
        );
        assert!(response_sink.responses().is_empty());
        assert_eq!(session.terminal_state(), TerminalState::Open);
    }

    #[test]
    fn dismiss_is_unresolved_closed_and_never_deny() {
        let (session, response_sink) = session();
        assert!(
            session
                .dismiss("request-host")
                .expect("dismiss should work")
        );
        assert!(matches!(
            response_sink.responses().as_slice(),
            [DialogResponse {
                decision: PortableDecision::Unresolved(UnresolvedReason::Closed),
                ..
            }]
        ));
        assert_eq!(session.terminal_state(), TerminalState::Emitted);
    }

    #[test]
    fn emitted_response_requests_zero_even_when_visual_cleanup_fails() {
        let (session, response_sink) = session();
        let exit = RecordingHostExit::default();
        let cleanup_failed = complete_and_exit(
            &exit,
            &session,
            || Err(()),
            |session| {
                session.submit(DecisionSubmission {
                    request_id: "request-host".into(),
                    decision: DecisionIntent::Allow,
                    message: None,
                })
            },
            "selection",
        );

        assert!(cleanup_failed.is_ok());
        assert_eq!(*exit.codes.lock().expect("exit codes lock"), vec![0]);
        assert_eq!(session.terminal_state(), TerminalState::Emitted);
        assert_eq!(response_sink.responses().len(), 1);
    }

    #[test]
    fn emission_failure_requests_one_and_never_reopens_the_terminal() {
        let session = failing_session();
        let exit = RecordingHostExit::default();
        let result = complete_and_exit(
            &exit,
            &session,
            || Ok(()),
            |session| session.dismiss("request-host"),
            "dismissed",
        );

        assert!(result.is_err());
        assert_eq!(*exit.codes.lock().expect("exit codes lock"), vec![1]);
        assert_eq!(session.terminal_state(), TerminalState::Failed);
    }

    #[test]
    fn submission_after_deadline_is_rejected_without_claiming_terminal_emission() {
        let sink = Arc::new(RecordingDialogResponseSink::default());
        let session = DecisionSession::new(
            request(),
            UiTheme::Dark,
            Duration::ZERO,
            None,
            sink.clone(),
            false,
        )
        .expect("fixture session should be valid");

        assert!(
            !session
                .submit(DecisionSubmission {
                    request_id: "request-host".into(),
                    decision: DecisionIntent::Allow,
                    message: None,
                })
                .expect("expired submit is a validly shaped request")
        );
        assert_eq!(session.terminal_state(), TerminalState::Open);
        assert!(sink.responses().is_empty());
    }

    #[test]
    fn session_rejects_a_timeout_that_would_overflow_instant() {
        let sink = Arc::new(RecordingDialogResponseSink::default());
        let result =
            DecisionSession::new(request(), UiTheme::Dark, Duration::MAX, None, sink, false);

        assert!(result.is_err());
    }

    #[test]
    fn frontend_failure_with_wrong_request_id_is_rejected_without_terminal_output() {
        let (session, sink) = session();
        let result = session.frontend_failed(FrontendFailure {
            request_id: Some("other-request".into()),
            stage: FrontendFailureStage::RenderOrReady,
            code: FrontendFailureCode::InvokeRejected,
        });

        assert!(result.is_err());
        assert_eq!(session.terminal_state(), TerminalState::Open);
        assert!(sink.responses().is_empty());
    }

    #[test]
    fn frontend_failure_without_request_id_is_transport_failed_and_non_authorizing() {
        let (session, sink) = session();
        assert!(
            session
                .frontend_failed(FrontendFailure {
                    request_id: None,
                    stage: FrontendFailureStage::LoadRequest,
                    code: FrontendFailureCode::InvokeRejected,
                })
                .expect("frontend failure should complete the session")
        );
        assert!(matches!(
            sink.responses().as_slice(),
            [DialogResponse {
                decision: PortableDecision::Unresolved(UnresolvedReason::TransportFailed),
                ..
            }]
        ));
        assert_eq!(session.terminal_state(), TerminalState::Emitted);
    }

    #[test]
    fn frontend_failure_diagnostics_are_allowlisted_and_stable() {
        assert_eq!(
            FrontendFailureStage::LoadRequest.diagnostic_event(),
            "frontend_failure_stage=load_request"
        );
        assert_eq!(
            FrontendFailureStage::RenderOrReady.diagnostic_event(),
            "frontend_failure_stage=render_or_ready"
        );
        assert_eq!(
            FrontendFailureCode::InvokeRejected.diagnostic_event(),
            "frontend_failure_code=invoke_rejected"
        );
        assert_eq!(
            FrontendFailureCode::InvalidPayload.diagnostic_event(),
            "frontend_failure_code=invalid_payload"
        );
        assert_eq!(
            FrontendFailureCode::RenderFailed.diagnostic_event(),
            "frontend_failure_code=render_failed"
        );
        assert_eq!(
            FrontendFailureCode::Unknown.diagnostic_event(),
            "frontend_failure_code=unknown"
        );
    }

    #[test]
    fn webview_runtime_diagnostics_expose_only_a_validated_hresult() {
        assert_eq!(
            webview_runtime_error_event("WebView2 error: HRESULT(0x800700AA)"),
            "webview_runtime_busy"
        );
        assert_eq!(
            webview_runtime_error_event("WebView2 error: HRESULT(0x80070005)"),
            "webview_runtime_access_denied"
        );
        assert_eq!(
            webview_runtime_error_event("WebView2 error: HRESULT(0x80004005)"),
            "webview_runtime_hresult_80004005"
        );
        assert_eq!(
            webview_runtime_error_event("request secret 0x80004005A"),
            "webview_runtime_error"
        );
        assert_eq!(
            webview_runtime_error_event("request secret: Access is denied"),
            "webview_runtime_access_denied"
        );
        assert_eq!(
            webview_runtime_error_event("request secret without an HRESULT"),
            "webview_runtime_error"
        );
    }

    #[test]
    fn frontend_failure_seam_parser_accepts_supported_stages_only() {
        assert_eq!(
            parse_frontend_failure_injection(Some("load_request")).expect("load seam should parse"),
            Some(FrontendFailureInjection::LoadRequest)
        );
        assert_eq!(
            parse_frontend_failure_injection(Some("render_or_ready"))
                .expect("ready seam should parse"),
            Some(FrontendFailureInjection::RenderOrReady)
        );
        assert_eq!(
            parse_frontend_failure_injection(None).expect("missing seam should be disabled"),
            None
        );
    }

    #[test]
    fn frontend_failure_seam_parser_rejects_arbitrary_values() {
        let error =
            parse_frontend_failure_injection(Some("allow")).expect_err("allow is not a seam stage");
        assert!(error.to_string().contains("load_request"));
        assert!(error.to_string().contains("render_or_ready"));
    }
}
