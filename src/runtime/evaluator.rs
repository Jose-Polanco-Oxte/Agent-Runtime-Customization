use anyhow::Result;
#[cfg(any(test, feature = "test-support"))]
use anyhow::bail;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "test-support"))]
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::manifest::schema::DECISION_EVALUATION_TIMEOUT_SECONDS;
use crate::runtime::events::{ArcEvent, ArcEventPayload, ArcEventType};
use crate::target::ProviderTarget;

pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const DECISION_COMMAND_TIMEOUT: Duration = Duration::from_secs(DECISION_EVALUATION_TIMEOUT_SECONDS);
pub const MAX_PROBE_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MB
const PROBE_CAPTURE_LIMIT: usize = MAX_PROBE_OUTPUT_BYTES + 1;
pub const ARC_RECURSION_MARKER_ENV: &str = "ARC_HOOK_ACTIVE";
pub const ARC_RECURSION_INTERNAL_TOKEN: &str = "ARC_INTERNAL_RECURSION_V1";
const ARC_AUDITOR_PROMPT_ENV: &str = "ARC_AUDITOR_PROMPT";

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error(
        "Probe command '{command}' failed with exit code {exit_code:?}.\nStderr: {stderr}\nStdout: {stdout}"
    )]
    ExecutionFailed {
        command: String,
        exit_code: Option<i32>,
        stderr: String,
        stdout: String,
    },
    #[error("Failed to spawn probe command '{command}': {source}")]
    SpawnFailed {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Probe command '{command}' timed out: {source}")]
    TimedOut {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Probe command '{command}' output exceeded the {limit} byte limit")]
    OutputLimitExceeded { command: String, limit: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum DecisionError {
    #[error("Decision evaluation requires a non-empty session intent")]
    SessionIntentUnavailable,
    #[error(
        "Decision CLI command '{command}' failed with exit code {exit_code:?}.\nStderr metadata: {stderr_summary}\nStdout metadata: {stdout_summary}"
    )]
    ExecutionFailed {
        command: String,
        exit_code: Option<i32>,
        stderr_summary: String,
        stdout_summary: String,
    },
    #[error("Failed to spawn decision CLI command '{command}': {source}")]
    SpawnFailed {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Decision provider '{command}' exceeded its deadline")]
    TimedOut { command: String },
    #[error("Decision CLI command '{command}' violates physical evaluation isolation: {reason}")]
    IsolationViolation { command: String, reason: String },
    #[error("Decision provider '{command}' attempted an unsupported tool call")]
    ToolUseAttempted { command: String },
    #[error("Decision provider '{command}' has no usable authentication: {details_summary}")]
    AuthenticationUnavailable {
        command: String,
        details_summary: String,
    },
    #[error(
        "Decision model output from '{command}' could not be parsed as a boolean decision: '{response}'"
    )]
    UnparseableResponse { command: String, response: String },
}

/// Pluggable probe runner for executing environment checks.
pub trait ProbeRunner: Send + Sync {
    fn run_probe(&self, command: &str) -> Result<String>;
}

/// Default probe runner executing commands directly or via shell if pipeline operators are needed.
pub struct DefaultProbeRunner;

impl ProbeRunner for DefaultProbeRunner {
    fn run_probe(&self, command: &str) -> Result<String> {
        run_probe_in_directory(command, None)
    }
}

/// Probe runner pinned to the workspace that owns the compiled BehaviorIR.
/// Hook processes do not necessarily inherit the provider workspace as cwd.
pub struct WorkspaceProbeRunner {
    workspace_root: PathBuf,
}

impl WorkspaceProbeRunner {
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
        }
    }
}

impl ProbeRunner for WorkspaceProbeRunner {
    fn run_probe(&self, command: &str) -> Result<String> {
        run_probe_in_directory(command, Some(&self.workspace_root))
    }
}

fn command_in_directory(program: &str, cwd: Option<&Path>) -> Command {
    let mut command = Command::new(program);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
        // Codex Desktop can launch hooks under its sandbox principal while the
        // checked-out repository belongs to the interactive Windows user. Git
        // then rejects even read-only probes as "dubious ownership". Scope the
        // trust exception to this child process and this exact canonical
        // workspace; never mutate the user's global Git configuration.
        let config_index = std::env::var("GIT_CONFIG_COUNT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        command
            .env("GIT_CONFIG_COUNT", (config_index + 1).to_string())
            .env(format!("GIT_CONFIG_KEY_{config_index}"), "safe.directory")
            .env(
                format!("GIT_CONFIG_VALUE_{config_index}"),
                git_safe_directory_value(cwd),
            );
    }
    command
}

fn git_safe_directory_value(cwd: &Path) -> String {
    let value = cwd.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{unc}");
        }
        if let Some(drive_path) = value.strip_prefix(r"\\?\") {
            return drive_path.to_string();
        }
    }
    value.into_owned()
}

fn truncate_output(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}... [truncated]", &s[..end])
    }
}

fn decision_output_metadata(bytes: &[u8]) -> String {
    format!(
        "<redacted bytes={} sha256={}>",
        bytes.len(),
        hex::encode(Sha256::digest(bytes))
    )
}

fn decision_response_summary(response: &str) -> String {
    if response.trim().is_empty() {
        String::new()
    } else {
        decision_output_metadata(response.as_bytes())
    }
}

#[cfg(unix)]
trait BoundedPipeReader: Read + std::os::unix::io::AsRawFd {
    fn prepare_for_polling(&self) -> bool {
        use std::os::unix::io::AsRawFd;
        let fd = self.as_raw_fd();
        // Make the pipe polling-friendly so timeout cleanup can stop the
        // reader without waiting for a descendant to close its inherited fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return false;
        }
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0 }
    }

    fn readiness(&self) -> Option<bool> {
        use std::os::unix::io::AsRawFd;
        let mut poll_fd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll_fd, 1, 50) };
        if result > 0 {
            Some(true)
        } else if result == 0
            || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            None
        } else {
            Some(false)
        }
    }
}

#[cfg(windows)]
trait BoundedPipeReader: Read + std::os::windows::io::AsRawHandle {
    fn prepare_for_polling(&self) -> bool {
        true
    }

    fn readiness(&self) -> Option<bool> {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let mut available = 0u32;
        let peeked = unsafe {
            PeekNamedPipe(
                self.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if peeked == 0 {
            Some(false)
        } else if available > 0 {
            Some(true)
        } else {
            None
        }
    }
}

#[cfg(unix)]
impl BoundedPipeReader for std::process::ChildStdout {}
#[cfg(unix)]
impl BoundedPipeReader for std::process::ChildStderr {}
#[cfg(windows)]
impl BoundedPipeReader for std::process::ChildStdout {}
#[cfg(windows)]
impl BoundedPipeReader for std::process::ChildStderr {}

fn read_pipe_bounded<R: BoundedPipeReader>(
    mut reader: R,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Vec<u8> {
    if !reader.prepare_for_polling() {
        return Vec::new();
    }

    let mut retained = Vec::with_capacity(max_bytes.min(8192));
    let mut chunk = [0u8; 4096];
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }

        match reader.readiness() {
            Some(false) => break,
            None => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Some(true) => {}
        }

        match reader.read(&mut chunk) {
            Ok(0) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
            Ok(n) => {
                let remaining = max_bytes.saturating_sub(retained.len());
                retained.extend_from_slice(&chunk[..n.min(remaining)]);
                if retained.len() >= max_bytes {
                    break;
                }
            }
        }
    }
    retained
}

#[cfg(windows)]
struct WindowsProcessJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl WindowsProcessJob {
    fn attach(child: &std::process::Child) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: null security attributes and name request a private job with
        // default security. The returned owned handle is closed in Drop.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Self { handle };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` has the exact layout and size required by the
        // JobObjectExtendedLimitInformation information class.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the Child owns a live process handle for the process just
        // spawned by this supervisor; the job remains alive in `job`.
        let assigned =
            unsafe { AssignProcessToJobObject(job.handle, child.as_raw_handle().cast()) };
        if assigned == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    fn terminate(&self) -> bool {
        // SAFETY: `self.handle` remains owned and valid until Drop.
        unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, 1) != 0 }
    }
}

#[cfg(windows)]
impl Drop for WindowsProcessJob {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed exactly once.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
type ProcessSupervisor = Option<WindowsProcessJob>;
#[cfg(unix)]
type ProcessSupervisor = ();

#[cfg(windows)]
fn attach_process_supervisor(child: &std::process::Child) -> ProcessSupervisor {
    WindowsProcessJob::attach(child).ok()
}

#[cfg(unix)]
fn attach_process_supervisor(_child: &std::process::Child) -> ProcessSupervisor {}

fn terminate_process_tree(child: &mut std::process::Child, supervisor: &ProcessSupervisor) {
    #[cfg(unix)]
    {
        let process_group = -(child.id() as i32);
        // SAFETY: the child was placed in its own process group immediately
        // before spawn, and this sends SIGKILL only to that exact group.
        unsafe {
            libc::kill(process_group, libc::SIGKILL);
        }
    }

    #[cfg(windows)]
    {
        if supervisor
            .as_ref()
            .is_some_and(WindowsProcessJob::terminate)
        {
            let _ = child.kill();
        } else {
            if let Ok(mut killer) = Command::new("taskkill.exe")
                .args(["/PID", &child.id().to_string(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                let started = Instant::now();
                while started.elapsed() < Duration::from_millis(250) {
                    match killer.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                        Err(_) => break,
                    }
                }
                if killer.try_wait().ok().flatten().is_none() {
                    let _ = killer.kill();
                }
            }
        }
    }

    let _ = child.kill();
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(250) {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break,
        }
    }
}

fn fallback_on_spawn_error<T>(
    result: std::io::Result<T>,
    fallback: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    match result {
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || (cfg!(windows) && error.kind() == std::io::ErrorKind::InvalidInput) =>
        {
            fallback()
        }
        other => other,
    }
}

fn probe_command_error(command: String, source: std::io::Error) -> ProbeError {
    if source.kind() == std::io::ErrorKind::TimedOut {
        ProbeError::TimedOut { command, source }
    } else {
        ProbeError::SpawnFailed { command, source }
    }
}

pub fn run_command_bounded(
    command: Command,
    timeout: Duration,
    max_bytes: usize,
) -> std::io::Result<std::process::Output> {
    run_command_bounded_inner(command, None, timeout, max_bytes)
}

pub fn run_command_bounded_with_input(
    command: Command,
    input: Vec<u8>,
    timeout: Duration,
    max_bytes: usize,
) -> std::io::Result<std::process::Output> {
    run_command_bounded_inner(command, Some(input), timeout, max_bytes)
}

fn run_command_bounded_inner(
    mut command: Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
    max_bytes: usize,
) -> std::io::Result<std::process::Output> {
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn()?;
    let process_supervisor = attach_process_supervisor(&child);
    let stdin_thread = input.map(|payload| {
        let mut stdin = child.stdin.take();
        std::thread::spawn(move || -> std::io::Result<()> {
            let mut stdin = stdin.take().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "child stdin unavailable")
            })?;
            stdin.write_all(&payload)?;
            stdin.flush()
        })
    });
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let stdout_cancelled = Arc::new(AtomicBool::new(false));
    let stderr_cancelled = Arc::new(AtomicBool::new(false));
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    let stdout_cancelled_for_thread = Arc::clone(&stdout_cancelled);
    let stdout_thread = std::thread::spawn(move || {
        let data = stdout_handle
            .map(|reader| read_pipe_bounded(reader, max_bytes, &stdout_cancelled_for_thread))
            .unwrap_or_default();
        let _ = stdout_tx.send(data.clone());
        data
    });

    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
    let stderr_cancelled_for_thread = Arc::clone(&stderr_cancelled);
    let stderr_thread = std::thread::spawn(move || {
        let data = stderr_handle
            .map(|reader| read_pipe_bounded(reader, max_bytes, &stderr_cancelled_for_thread))
            .unwrap_or_default();
        let _ = stderr_tx.send(data.clone());
        data
    });

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None => {
                if start.elapsed() > timeout {
                    terminate_process_tree(&mut child, &process_supervisor);
                    timed_out = true;
                    stdout_cancelled.store(true, Ordering::Release);
                    stderr_cancelled.store(true, Ordering::Release);
                    break child.try_wait()?;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };

    // Drain readers within a bounded cleanup window. The process tree is killed
    // before this path on timeout, so inherited pipe handles are released before
    // joining the reader threads (M1).
    let remaining_timeout = timeout
        .saturating_sub(start.elapsed())
        .max(Duration::from_millis(100));
    let stdout = match stdout_rx.recv_timeout(remaining_timeout) {
        Ok(bytes) => bytes,
        Err(_) => {
            terminate_process_tree(&mut child, &process_supervisor);
            stdout_rx
                .recv_timeout(Duration::from_millis(50))
                .unwrap_or_default()
        }
    };

    let stderr = match stderr_rx.recv_timeout(Duration::from_millis(100)) {
        Ok(bytes) => bytes,
        Err(_) => {
            terminate_process_tree(&mut child, &process_supervisor);
            stderr_rx
                .recv_timeout(Duration::from_millis(50))
                .unwrap_or_default()
        }
    };

    if timed_out {
        // The readers use cancellation-aware polling, so timeout cleanup does
        // not leave detached threads even when descendants inherited pipes.
        stdout_cancelled.store(true, Ordering::Release);
        stderr_cancelled.store(true, Ordering::Release);
        stdout_thread.join().map_err(|_| {
            std::io::Error::other("stdout reader thread panicked during timeout cleanup")
        })?;
        stderr_thread.join().map_err(|_| {
            std::io::Error::other("stderr reader thread panicked during timeout cleanup")
        })?;
        if let Some(stdin_thread) = stdin_thread {
            let _writer_result = stdin_thread.join().map_err(|_| {
                std::io::Error::other("stdin writer thread panicked during timeout cleanup")
            })?;
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Command execution timed out after {}ms",
                timeout.as_millis()
            ),
        ));
    }

    let _stdout_joined = stdout_thread.join().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "stdout reader thread panicked during bounded command cleanup",
        )
    })?;
    let _stderr_joined = stderr_thread.join().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "stderr reader thread panicked during bounded command cleanup",
        )
    })?;
    if let Some(stdin_thread) = stdin_thread {
        stdin_thread.join().map_err(|_| {
            std::io::Error::other("stdin writer thread panicked during bounded command cleanup")
        })??;
    }

    let status = status.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Command process did not exit during bounded timeout cleanup",
        )
    })?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn run_probe_in_directory(command: &str, cwd: Option<&Path>) -> Result<String> {
    run_probe_in_directory_with_timeout(command, cwd, DEFAULT_COMMAND_TIMEOUT)
}

fn run_probe_in_directory_with_timeout(
    command: &str,
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<String> {
    let tokens = parse_command_tokens(command);

    // If simple command without shell operators (pipes, redirection, chaining), execute directly
    let output = if !tokens.is_empty() && !command.contains(['|', '&', ';', '>', '<']) {
        let mut cmd = command_in_directory(&tokens[0], cwd);
        cmd.args(&tokens[1..]);
        fallback_on_spawn_error(
            run_command_bounded(cmd, timeout, PROBE_CAPTURE_LIMIT),
            || {
                // Fallback to shell if direct spawn fails (e.g. built-in shell commands or PATH lookup)
                let shell_res = if cfg!(target_os = "windows") {
                    let mut cmd = command_in_directory("cmd", cwd);
                    cmd.args(["/C", command]);
                    run_command_bounded(cmd, timeout, PROBE_CAPTURE_LIMIT)
                } else {
                    let mut cmd = command_in_directory("sh", cwd);
                    cmd.args(["-c", command]);
                    run_command_bounded(cmd, timeout, PROBE_CAPTURE_LIMIT)
                };
                shell_res
            },
        )
        .map_err(|error| probe_command_error(command.to_string(), error))?
    } else if cfg!(target_os = "windows") {
        let mut cmd = command_in_directory("cmd", cwd);
        cmd.args(["/C", command]);
        run_command_bounded(cmd, timeout, PROBE_CAPTURE_LIMIT)
            .map_err(|error| probe_command_error(command.to_string(), error))?
    } else {
        let mut cmd = command_in_directory("sh", cwd);
        cmd.args(["-c", command]);
        run_command_bounded(cmd, timeout, PROBE_CAPTURE_LIMIT)
            .map_err(|error| probe_command_error(command.to_string(), error))?
    };

    if output.stdout.len() > MAX_PROBE_OUTPUT_BYTES {
        return Err(ProbeError::OutputLimitExceeded {
            command: command.to_string(),
            limit: MAX_PROBE_OUTPUT_BYTES,
        }
        .into());
    }

    if !output.status.success() {
        let exit_code = output.status.code();
        let stderr = truncate_output(&String::from_utf8_lossy(&output.stderr).trim(), 2048);
        let stdout = truncate_output(&String::from_utf8_lossy(&output.stdout).trim(), 2048);
        return Err(ProbeError::ExecutionFailed {
            command: command.to_string(),
            exit_code,
            stderr,
            stdout,
        }
        .into());
    }

    let stdout = truncate_output(&String::from_utf8_lossy(&output.stdout).trim(), 65536);
    Ok(stdout)
}

pub(crate) fn parse_command_tokens(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    for c in command.chars() {
        match c {
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// In-memory mock probe runner for testing without shell execution.
#[cfg(any(test, feature = "test-support"))]
pub struct MockProbeRunner {
    outputs: BTreeMap<String, String>,
    calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockProbeRunner {
    pub fn new() -> Self {
        Self {
            outputs: BTreeMap::new(),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn with_output(mut self, command: impl Into<String>, output: impl Into<String>) -> Self {
        self.outputs.insert(command.into(), output.into());
        self
    }

    pub fn set_output(&mut self, command: impl Into<String>, output: impl Into<String>) {
        self.outputs.insert(command.into(), output.into());
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ProbeRunner for MockProbeRunner {
    fn run_probe(&self, command: &str) -> Result<String> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(command.to_string());
        }
        if let Some(out) = self.outputs.get(command) {
            Ok(out.clone())
        } else {
            bail!(
                "MockProbeRunner: No mock output configured for command '{}'",
                command
            )
        }
    }
}

use crate::runtime::context::SessionContext;

/// Requires the session intent that gives a semantic `decide` evaluation its
/// user-authorized goal. Missing intent is an evaluation fault, not a negative
/// semantic verdict that may be reduced through a Guard's configured action.
pub(crate) fn require_session_intent(
    context: Option<&SessionContext>,
) -> Result<&SessionContext, DecisionError> {
    context
        .filter(|session_context| !session_context.user_intent.trim().is_empty())
        .ok_or(DecisionError::SessionIntentUnavailable)
}

/// Output verdict from an audit decision evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionVerdict {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<String>,
}

impl DecisionVerdict {
    pub fn allow() -> Self {
        Self {
            decision: true,
            findings: None,
        }
    }

    pub fn deny(findings: impl Into<String>) -> Self {
        Self {
            decision: false,
            findings: Some(findings.into()),
        }
    }
}

/// Request details passed to the auditor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRequestDetails {
    pub goal: String,
    pub role: String,
}

/// The normalized operation that caused the current guard evaluation.
/// This is kept separate from transcript context so the auditor cannot
/// accidentally authorize a different command mentioned earlier in the chat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentOperation {
    pub event_type: ArcEventType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatcherEvidence {
    pub kind: String,
    pub matcher: String,
    pub matched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicEvidence {
    pub rule_path: Vec<String>,
    pub operation: String,
    /// Configured probe outputs that count as a match. An empty value is valid
    /// and represents a probe whose normalized output is empty.
    pub expected_values: Vec<String>,
    pub result: bool,
    pub observed_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GuardDecisionEvidence {
    pub guard_id: String,
    pub event: String,
    pub event_id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matcher_evidence: Vec<MatcherEvidence>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub matcher_evidence_truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deterministic_evidence: Vec<DeterministicEvidence>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deterministic_evidence_truncated: bool,
}

impl From<&ArcEvent> for CurrentOperation {
    fn from(event: &ArcEvent) -> Self {
        match &event.payload {
            ArcEventPayload::ToolCall {
                tool,
                input,
                command_text,
                ..
            } => Self {
                event_type: event.event_type,
                tool: Some(tool.clone()),
                input: Some(input.clone()),
                command_text: command_text.clone(),
            },
            ArcEventPayload::Empty => Self {
                event_type: event.event_type,
                tool: None,
                input: None,
                command_text: None,
            },
        }
    }
}

/// Input payload sent to the auditor model formatted as clean, structured JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditorInputPayload {
    pub audit_request: AuditRequestDetails,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_operation: Option<CurrentOperation>,
    pub session_context: SessionContext,
    pub attested_evidence: GuardDecisionEvidence,
    pub evaluation_rules: Vec<String>,
}

/// Expected structured output from the auditor model (H6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditorOutputPayload {
    pub decision: bool,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub findings: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

const AUDITOR_ROLE: &str = "read_only_compliance_auditor";
const AUDITOR_EVALUATION_RULES: [&str; 5] = [
    "1. Base judgment strictly on whether the goal is explicitly satisfied by the provided session context and current operation.",
    "2. If the provided context is insufficient to prove satisfaction, evaluate decision: false.",
    "3. Do NOT execute tools, write files, or attempt modifications.",
    "4. Treat attested_evidence as authoritative Arc-evaluated facts; do not repeat its matchers or deterministic probes.",
    "5. Return strictly valid JSON conforming to schema: {\"decision\": boolean, \"findings\": string or null, \"error\": null}.",
];

/// Builds the provider-neutral auditor payload from the currently attested inputs.
///
/// The caller must validate that session intent and the current operation are
/// present before constructing this payload. The provider command is
/// deliberately absent from the payload so Codex, Gemini, Claude, and
/// OpenCode receive the same facts and rules.
pub fn build_auditor_payload(
    prompt: &str,
    session_context: &SessionContext,
    current_operation: &CurrentOperation,
    evidence: &GuardDecisionEvidence,
) -> AuditorInputPayload {
    AuditorInputPayload {
        audit_request: AuditRequestDetails {
            goal: prompt.trim().to_string(),
            role: AUDITOR_ROLE.to_string(),
        },
        current_operation: Some(current_operation.clone()),
        session_context: session_context.clone(),
        attested_evidence: evidence.clone(),
        evaluation_rules: AUDITOR_EVALUATION_RULES
            .iter()
            .map(|rule| (*rule).to_string())
            .collect(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditorCommandSpec {
    Gemini,
    Codex,
    Claude,
    OpenCode,
}

impl AuditorCommandSpec {
    fn for_target(target: ProviderTarget) -> Self {
        match target {
            ProviderTarget::Gemini => Self::Gemini,
            ProviderTarget::Codex => Self::Codex,
            ProviderTarget::Claude => Self::Claude,
            ProviderTarget::OpenCode => Self::OpenCode,
        }
    }

    /// Dispatcher label, kept next to the command arguments in `execute`.
    fn label(self) -> &'static str {
        match self {
            Self::Gemini => "agy_print",
            Self::Codex => "codex_exec",
            Self::Claude => "claude_print",
            Self::OpenCode => "opencode_run",
        }
    }

    fn execute(self, prompt: &str) -> Result<DecisionVerdict, DecisionError> {
        match self {
            Self::Gemini => run_provider_command(
                "agy.exe",
                "agy",
                &["--disable-slash-commands", "--print", prompt],
                "agy --print ...",
            ),
            Self::Codex => run_provider_command(
                "codex.exe",
                "codex",
                &["-c", "features.hooks=false", "exec", prompt],
                "codex exec ...",
            ),
            Self::Claude => {
                run_provider_command("claude.exe", "claude", &["-p", prompt], "claude -p ...")
            }
            Self::OpenCode => run_provider_command(
                "opencode.exe",
                "opencode",
                &["run", prompt],
                "opencode run ...",
            ),
        }
    }
}

/// Pluggable decision provider for resolving model-backed `decide` expressions.
pub trait DecisionProvider: Send + Sync {
    fn decide(
        &self,
        prompt: &str,
        context: Option<&SessionContext>,
        current_operation: Option<&CurrentOperation>,
        evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError>;

    /// Label of the dispatcher that executes decisions (for example `codex_exec`).
    fn dispatcher_label(&self) -> String {
        "unspecified".to_string()
    }
}

/// In-memory mock decision provider for testing.
#[cfg(any(test, feature = "test-support"))]
pub struct MockDecisionProvider {
    decisions: BTreeMap<String, DecisionVerdict>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockDecisionProvider {
    pub fn new() -> Self {
        Self {
            decisions: BTreeMap::new(),
        }
    }

    pub fn with_decision(mut self, prompt: impl Into<String>, result: bool) -> Self {
        self.decisions.insert(
            prompt.into().trim().to_string(),
            DecisionVerdict {
                decision: result,
                findings: if !result {
                    Some("Mock failure findings".to_string())
                } else {
                    None
                },
            },
        );
        self
    }

    pub fn with_verdict(mut self, prompt: impl Into<String>, verdict: DecisionVerdict) -> Self {
        self.decisions
            .insert(prompt.into().trim().to_string(), verdict);
        self
    }
}

#[cfg(any(test, feature = "test-support"))]
impl DecisionProvider for MockDecisionProvider {
    fn decide(
        &self,
        prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&CurrentOperation>,
        _evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        if let Some(res) = self.decisions.get(prompt.trim()) {
            Ok(res.clone())
        } else {
            Err(DecisionError::UnparseableResponse {
                command: "mock".into(),
                response: format!(
                    "No mock decision found for prompt ({})",
                    decision_response_summary(prompt)
                ),
            })
        }
    }
}

/// Provider-backed decision provider querying models via local authenticated CLI or local endpoints.
pub struct CliDecisionProvider {
    target: ProviderTarget,
    custom_command: Option<String>,
}

impl Default for CliDecisionProvider {
    fn default() -> Self {
        Self::new(ProviderTarget::Gemini)
    }
}

impl CliDecisionProvider {
    pub fn new(target: ProviderTarget) -> Self {
        Self {
            target,
            custom_command: std::env::var("ARC_LLM_CLI").ok(),
        }
    }

    pub fn for_gemini() -> Self {
        Self::new(ProviderTarget::Gemini)
    }

    pub fn for_codex() -> Self {
        Self::new(ProviderTarget::Codex)
    }

    pub fn with_custom_command(mut self, command: impl Into<String>) -> Self {
        self.custom_command = Some(command.into());
        self
    }

    /// Queries the model with a structured compliance auditor prompt and parses DecisionVerdict.
    fn query_auditor(
        &self,
        prompt: &str,
        context: Option<&SessionContext>,
        current_operation: Option<&CurrentOperation>,
        evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        let session_ctx = require_session_intent(context)?;
        let Some(current_operation) = current_operation else {
            return Ok(DecisionVerdict::deny(
                "Decision denied because the current operation is unavailable.",
            ));
        };

        let input_payload = build_auditor_payload(prompt, session_ctx, current_operation, evidence);

        let minified_json = serde_json::to_string(&input_payload).map_err(|e| {
            DecisionError::UnparseableResponse {
                command: "serialize_payload".into(),
                response: format!("Failed serializing auditor input payload: {}", e),
            }
        })?;

        let system_instruction = "System: You are an automated, strictly read-only compliance auditor and security evaluator. Analyze the provided audit JSON payload and evaluate whether the goal is satisfied. Do not make file changes or call tools. Output ONLY valid JSON according to schema: {\"decision\": true, \"findings\": null, \"error\": null} (or decision: false with findings text).\n\nAudit Payload: ";
        let full_prompt = format!("{}{}", system_instruction, minified_json);

        // 1. If custom command configured via ARC_LLM_CLI or builder
        if let Some(ref custom_cmd) = self.custom_command {
            if let Some(flag) = forbidden_conversation_flag(custom_cmd) {
                return Err(DecisionError::IsolationViolation {
                    command: custom_cmd.clone(),
                    reason: format!(
                        "conversation reuse flag '{}' is forbidden; each physical evaluation requires a fresh conversation",
                        flag
                    ),
                });
            }
            return run_cli_decision(custom_cmd, &full_prompt);
        }

        // 2. Provider-specific command line is the only provider-dependent
        // part of the auditor transport. The payload and rules remain shared.
        AuditorCommandSpec::for_target(self.target).execute(&full_prompt)
    }
}

pub(crate) fn forbidden_conversation_flag(command: &str) -> Option<&'static str> {
    parse_command_tokens(command).into_iter().find_map(|token| {
        ["--continue", "--conversation"]
            .into_iter()
            .find(|flag| token == *flag || token.starts_with(&format!("{flag}=")))
    })
}

impl DecisionProvider for CliDecisionProvider {
    fn decide(
        &self,
        prompt: &str,
        context: Option<&SessionContext>,
        current_operation: Option<&CurrentOperation>,
        evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        self.query_auditor(prompt, context, current_operation, evidence)
    }

    fn dispatcher_label(&self) -> String {
        if self.custom_command.is_some() {
            "custom_cli".to_string()
        } else {
            AuditorCommandSpec::for_target(self.target)
                .label()
                .to_string()
        }
    }
}

const ISOLATED_AUDITOR_REMOVED_ENV_VARS: [&str; 7] = [
    "ANTIGRAVITY_LS_ADDRESS",
    "ANTIGRAVITY_CSRF_TOKEN",
    "ANTIGRAVITY_CONVERSATION_ID",
    "ANTIGRAVITY_TRAJECTORY_ID",
    "ANTIGRAVITY_SOURCE_METADATA",
    "ANTIGRAVITY_PROJECT_ID",
    "ANTIGRAVITY_AGENT",
];

/// Configures an auditor CLI command to execute in an isolated sandbox directory
/// without inheriting parent Antigravity language-server attachment or workspace hooks.
pub(crate) fn configure_isolated_auditor_command(command: &mut Command) {
    command.env(ARC_RECURSION_MARKER_ENV, ARC_RECURSION_INTERNAL_TOKEN);
    for env_key in ISOLATED_AUDITOR_REMOVED_ENV_VARS {
        command.env_remove(env_key);
    }
    let sandbox_dir = std::env::temp_dir().join("arc-auditor-sandbox");
    if std::fs::create_dir_all(&sandbox_dir).is_ok() {
        command.current_dir(sandbox_dir);
    }
}

/// Returns true if the extracted `user_intent` belongs to an internal Arc read-only
/// compliance auditor session rather than an interactive user session.
pub fn is_auditor_session_intent(user_intent: &str) -> bool {
    let trimmed = user_intent.trim();
    trimmed.starts_with("System: You are a")
        && trimmed.contains("compliance auditor")
        && trimmed.contains("\"role\":\"read_only_compliance_auditor\"")
}

/// Decision output is captured one byte past the limit so oversized output is detectable.
const DECISION_CAPTURE_LIMIT: usize = MAX_PROBE_OUTPUT_BYTES + 1;

fn run_provider_command(
    primary_program: &str,
    fallback_program: &str,
    args: &[&str],
    display_command: &str,
) -> Result<DecisionVerdict, DecisionError> {
    let mut primary = Command::new(primary_program);
    configure_isolated_auditor_command(&mut primary);
    primary.args(args);
    let output = fallback_on_spawn_error(
        run_command_bounded(primary, DECISION_COMMAND_TIMEOUT, DECISION_CAPTURE_LIMIT),
        || {
            let mut fallback = Command::new(fallback_program);
            configure_isolated_auditor_command(&mut fallback);
            fallback.args(args);
            run_command_bounded(fallback, DECISION_COMMAND_TIMEOUT, DECISION_CAPTURE_LIMIT)
        },
    );

    handle_cli_output(display_command, output)
}

fn handle_cli_output(
    command: &str,
    output_res: std::io::Result<std::process::Output>,
) -> Result<DecisionVerdict, DecisionError> {
    match output_res {
        Ok(out) => {
            if out.stdout.len() > MAX_PROBE_OUTPUT_BYTES {
                return Err(DecisionError::UnparseableResponse {
                    command: command.to_string(),
                    response: format!(
                        "auditor output exceeded the {MAX_PROBE_OUTPUT_BYTES} byte limit"
                    ),
                });
            }
            if !out.status.success() {
                return Err(DecisionError::ExecutionFailed {
                    command: command.to_string(),
                    exit_code: out.status.code(),
                    stderr_summary: decision_output_metadata(&out.stderr),
                    stdout_summary: decision_output_metadata(&out.stdout),
                });
            }

            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_auditor_response(command, &stdout)
        }
        Err(e) => Err(DecisionError::SpawnFailed {
            command: command.to_string(),
            source: e,
        }),
    }
}

fn run_cli_decision(cmd: &str, prompt: &str) -> Result<DecisionVerdict, DecisionError> {
    let tokens = parse_command_tokens(cmd);
    let output = if !tokens.is_empty() {
        let mut command = Command::new(&tokens[0]);
        command.env(ARC_RECURSION_MARKER_ENV, ARC_RECURSION_INTERNAL_TOKEN);
        if tokens.len() > 1 {
            command.args(&tokens[1..]);
        }
        command.arg(prompt);
        fallback_on_spawn_error(
            run_command_bounded(command, DECISION_COMMAND_TIMEOUT, DECISION_CAPTURE_LIMIT),
            || {
                if cfg!(target_os = "windows") {
                    let mut shell_cmd = Command::new("cmd");
                    shell_cmd
                        .env(ARC_RECURSION_MARKER_ENV, ARC_RECURSION_INTERNAL_TOKEN)
                        .env(ARC_AUDITOR_PROMPT_ENV, prompt)
                        .args(["/D", "/V:ON", "/S", "/C"])
                        .arg(format!("{} \"!{}!\"", cmd, ARC_AUDITOR_PROMPT_ENV));
                    run_command_bounded(shell_cmd, DECISION_COMMAND_TIMEOUT, DECISION_CAPTURE_LIMIT)
                } else {
                    let mut shell_cmd = Command::new("sh");
                    shell_cmd
                        .env(ARC_RECURSION_MARKER_ENV, ARC_RECURSION_INTERNAL_TOKEN)
                        .args(["-c", &format!("{} \"$@\"", cmd), "--", prompt]);
                    run_command_bounded(shell_cmd, DECISION_COMMAND_TIMEOUT, DECISION_CAPTURE_LIMIT)
                }
            },
        )
    } else {
        let mut command = Command::new(cmd);
        command
            .env(ARC_RECURSION_MARKER_ENV, ARC_RECURSION_INTERNAL_TOKEN)
            .arg(prompt);
        run_command_bounded(command, DECISION_COMMAND_TIMEOUT, DECISION_CAPTURE_LIMIT)
    };

    handle_cli_output(cmd, output)
}

fn parse_auditor_response(command: &str, response: &str) -> Result<DecisionVerdict, DecisionError> {
    let clean = response.trim();
    if clean.is_empty() {
        return Err(DecisionError::UnparseableResponse {
            command: command.to_string(),
            response: decision_response_summary(response),
        });
    }

    // Strict JSON parsing only (H6). Rejects markdown blocks, embedded substring JSON, and raw booleans.
    if let Ok(payload) = serde_json::from_str::<AuditorOutputPayload>(clean) {
        return handle_payload(command, clean, payload);
    }

    Err(DecisionError::UnparseableResponse {
        command: command.to_string(),
        response: decision_response_summary(response),
    })
}

fn handle_payload(
    command: &str,
    raw: &str,
    payload: AuditorOutputPayload,
) -> Result<DecisionVerdict, DecisionError> {
    // 1. Validate confidence range if provided (H6)
    if let Some(conf) = payload.confidence {
        if conf.is_nan() || !(0.0..=1.0).contains(&conf) {
            return Err(DecisionError::UnparseableResponse {
                command: command.to_string(),
                response: format!(
                    "Invalid confidence value {} (must be between 0.0 and 1.0)",
                    conf
                ),
            });
        }
    }

    // 2. Validate error and contradiction rules (H6)
    if let Some(ref err_msg) = payload.error {
        let trimmed_err = err_msg.trim();
        if !trimmed_err.is_empty() {
            // Contradiction: decision=true with active error message
            if payload.decision {
                return Err(DecisionError::UnparseableResponse {
                    command: command.to_string(),
                    response: format!(
                        "Contradictory auditor payload: decision is true but error field is non-empty ({}).",
                        decision_response_summary(trimmed_err)
                    ),
                });
            }
            return Err(DecisionError::ExecutionFailed {
                command: command.to_string(),
                exit_code: Some(1),
                stderr_summary: decision_output_metadata(trimmed_err.as_bytes()),
                stdout_summary: decision_output_metadata(raw.as_bytes()),
            });
        }
    }

    // 3. Clean findings (reject empty/whitespace-only findings)
    let cleaned_findings = match payload.findings {
        Some(ref f) if f.trim().is_empty() => None,
        Some(f) => Some(f.trim().to_string()),
        None => None,
    };

    Ok(DecisionVerdict {
        decision: payload.decision,
        findings: cleaned_findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_timeout_is_reported_as_execution_timeout_not_spawn_failure() {
        let command = if cfg!(target_os = "windows") {
            "powershell -NoProfile -Command \"Start-Sleep -Seconds 2\""
        } else {
            "sleep 2"
        };
        let timeout_error =
            run_probe_in_directory_with_timeout(command, None, Duration::from_millis(100))
                .unwrap_err();
        assert!(
            timeout_error.to_string().contains("timed out"),
            "unexpected probe failure: {timeout_error:#}"
        );
        assert!(!timeout_error.to_string().contains("Failed to spawn"));

        let spawn_error = probe_command_error(
            "missing_probe".into(),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        );
        assert!(matches!(spawn_error, ProbeError::SpawnFailed { .. }));
    }

    fn verified_decision_inputs() -> (SessionContext, CurrentOperation) {
        (
            SessionContext {
                user_intent: "Run the requested validation".into(),
                ..SessionContext::default()
            },
            CurrentOperation {
                event_type: ArcEventType::End,
                tool: None,
                input: None,
                command_text: None,
            },
        )
    }

    #[test]
    fn workspace_probe_runner_uses_the_session_workspace() {
        let workspace =
            std::env::temp_dir().join(format!("arc-workspace-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("probe-marker.txt"), "workspace-bound").unwrap();

        let runner = WorkspaceProbeRunner::new(&workspace);
        let command = if cfg!(target_os = "windows") {
            "cmd /c type probe-marker.txt"
        } else {
            "cat probe-marker.txt"
        };

        let output = runner.run_probe(command).unwrap();
        std::fs::remove_dir_all(&workspace).unwrap();

        assert_eq!(output, "workspace-bound");
    }

    #[test]
    fn workspace_probe_runner_scopes_git_safe_directory_to_the_workspace() {
        let workspace =
            std::env::temp_dir().join(format!("arc-workspace-git-safe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&workspace).unwrap();
        let canonical = workspace.canonicalize().unwrap();

        let runner = WorkspaceProbeRunner::new(&canonical);
        let output = runner
            .run_probe("git config --get-all safe.directory")
            .unwrap();
        std::fs::remove_dir_all(&workspace).unwrap();

        let injected = output.lines().last().unwrap();
        assert_eq!(
            std::path::PathBuf::from(injected),
            std::path::PathBuf::from(git_safe_directory_value(&canonical)),
            "the child-process trust exception must name its exact workspace"
        );
    }

    #[test]
    fn test_probe_execution_failure() {
        let runner = DefaultProbeRunner;
        let command = if cfg!(target_os = "windows") {
            "cmd /c exit 1"
        } else {
            "sh -c 'exit 1'"
        };
        let result = runner.run_probe(command);
        assert!(result.is_err(), "Expected error for non-zero exit code");
    }

    #[test]
    fn test_strict_cli_decision_parsing() {
        // Valid JSON objects
        assert!(
            parse_auditor_response("test", "{\"decision\": true}")
                .unwrap()
                .decision
        );
        assert!(
            !parse_auditor_response("test", "{\"decision\": false, \"findings\": \"denied\"}")
                .unwrap()
                .decision
        );

        // Strict rejections per H6:
        // 1. Bare booleans
        assert!(parse_auditor_response("test", "true").is_err());
        assert!(parse_auditor_response("test", "false").is_err());

        // 2. Free-text
        assert!(parse_auditor_response("test", "Yes, the action is allowed").is_err());
        assert!(parse_auditor_response("test", "No, unauthorized").is_err());

        // 3. Markdown code blocks
        assert!(parse_auditor_response("test", "```json\n{\"decision\": true}\n```").is_err());

        // 4. Embedded JSON in explanatory text
        assert!(
            parse_auditor_response("test", "Here is my evaluation: {\"decision\": true}").is_err()
        );

        // 5. Unknown fields (deny_unknown_fields)
        assert!(parse_auditor_response("test", "{\"decision\": true, \"extra\": 123}").is_err());

        // 6. Missing required field 'decision'
        assert!(parse_auditor_response("test", "{\"findings\": \"ok\"}").is_err());

        // 7. Empty or whitespace
        assert!(parse_auditor_response("test", "").is_err());
        assert!(parse_auditor_response("test", "   ").is_err());
    }

    #[test]
    fn decision_errors_redact_process_output_and_model_response() {
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args([
                    "/C",
                    "echo STDOUT_SECRET & echo STDERR_SECRET 1>&2 & exit /B 1",
                ])
                .output()
                .unwrap()
        } else {
            Command::new("sh")
                .args([
                    "-c",
                    "printf STDOUT_SECRET; printf STDERR_SECRET >&2; exit 1",
                ])
                .output()
                .unwrap()
        };

        let error = handle_cli_output("decision-fixture", Ok(output)).unwrap_err();
        let rendered = error.to_string();
        assert!(!rendered.contains("STDOUT_SECRET"));
        assert!(!rendered.contains("STDERR_SECRET"));
        assert!(rendered.contains("Stdout metadata"));
        assert!(rendered.contains("Stderr metadata"));
        assert!(rendered.contains("sha256="));

        let parse_error = parse_auditor_response("decision-fixture", "MODEL_SECRET").unwrap_err();
        assert!(!parse_error.to_string().contains("MODEL_SECRET"));

        let empty_error = parse_auditor_response("decision-fixture", "   ").unwrap_err();
        assert_eq!(
            empty_error.to_string(),
            "Decision model output from 'decision-fixture' could not be parsed as a boolean decision: ''"
        );

        let mock_error = MockDecisionProvider::new()
            .decide(
                "MOCK_SECRET",
                None,
                None,
                &GuardDecisionEvidence {
                    guard_id: "fixture".into(),
                    event: "tool_call".into(),
                    event_id: "fixture-event".into(),
                    scope: "test".into(),
                    matcher_evidence: Vec::new(),
                    matcher_evidence_truncated: false,
                    deterministic_evidence: Vec::new(),
                    deterministic_evidence_truncated: false,
                },
            )
            .unwrap_err();
        assert!(!mock_error.to_string().contains("MOCK_SECRET"));
    }

    #[test]
    fn test_auditor_output_json_parsing() {
        let json_pass = r#"{"decision": true, "confidence": 1.0, "findings": null, "error": null}"#;
        let verdict = parse_auditor_response("test", json_pass).unwrap();
        assert!(verdict.decision);
        assert!(verdict.findings.is_none());

        let json_whitespace = r#"{"decision": true, "findings": "   \t\n  ", "error": null}"#;
        let verdict_ws = parse_auditor_response("test", json_whitespace).unwrap();
        assert!(verdict_ws.decision);
        assert!(verdict_ws.findings.is_none());

        let json_empty = r#"{"decision": false, "findings": "", "error": null}"#;
        let verdict_empty = parse_auditor_response("test", json_empty).unwrap();
        assert!(!verdict_empty.decision);
        assert!(verdict_empty.findings.is_none());

        let json_fail = r#"{"decision": false, "confidence": 0.95, "findings": "Missing unit tests", "error": null}"#;
        let verdict_fail = parse_auditor_response("test", json_fail).unwrap();
        assert!(!verdict_fail.decision);
        assert_eq!(verdict_fail.findings.unwrap(), "Missing unit tests");

        let json_err = r#"{"decision": false, "error": "Internal evaluator timeout"}"#;
        let err_res = parse_auditor_response("test", json_err);
        assert!(err_res.is_err());
    }

    #[test]
    fn test_cli_decision_provider_resolution() {
        let temp_dir = std::env::temp_dir();
        let script_path = if cfg!(target_os = "windows") {
            let p = temp_dir.join(format!("mock_decision_{}.bat", uuid::Uuid::new_v4()));
            std::fs::write(&p, "@echo {\"decision\": true}\r\n").unwrap();
            p
        } else {
            let p = temp_dir.join(format!("mock_decision_{}.sh", uuid::Uuid::new_v4()));
            std::fs::write(&p, "#!/bin/sh\necho '{\"decision\": true}'\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&p).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&p, perms).unwrap();
            }
            p
        };
        let custom_cmd = script_path.to_string_lossy().to_string();
        let provider = CliDecisionProvider::for_gemini().with_custom_command(custom_cmd);
        let (context, operation) = verified_decision_inputs();
        let result = provider.decide(
            "Is this valid?",
            Some(&context),
            Some(&operation),
            &GuardDecisionEvidence::default(),
        );
        let _ = std::fs::remove_file(&script_path);
        assert_eq!(
            result.unwrap(),
            DecisionVerdict {
                decision: true,
                findings: None
            }
        );
    }

    #[test]
    fn test_cli_decision_provider_execution_failure() {
        let custom_cmd = if cfg!(target_os = "windows") {
            "cmd /c exit 1"
        } else {
            "sh -c 'exit 1'"
        };
        let provider = CliDecisionProvider::for_gemini().with_custom_command(custom_cmd);
        let (context, operation) = verified_decision_inputs();
        let result = provider.decide(
            "Is this valid?",
            Some(&context),
            Some(&operation),
            &GuardDecisionEvidence::default(),
        );
        assert!(
            result.is_err(),
            "Expected error when CLI command exits with non-zero code"
        );
    }

    #[test]
    fn test_cli_decision_provider_unparseable_failure() {
        let custom_cmd = if cfg!(target_os = "windows") {
            "cmd /c (echo completely inconclusive) & rem"
        } else {
            "sh -c 'echo completely inconclusive; exit 0' --"
        };
        let provider = CliDecisionProvider::for_gemini().with_custom_command(custom_cmd);
        let (context, operation) = verified_decision_inputs();
        let result = provider.decide(
            "Is this valid?",
            Some(&context),
            Some(&operation),
            &GuardDecisionEvidence::default(),
        );
        assert!(
            result.is_err(),
            "Expected error when model response is unparseable"
        );
    }

    #[test]
    fn cli_decision_fails_closed_without_context_or_current_operation() {
        let provider =
            CliDecisionProvider::for_gemini().with_custom_command(if cfg!(target_os = "windows") {
                "cmd /c echo {\"decision\":true}"
            } else {
                "printf '{\"decision\":true}'"
            });

        let result = provider.decide("Allow?", None, None, &GuardDecisionEvidence::default());
        assert!(
            result.is_err(),
            "missing session context must be a runtime evaluation error"
        );
        assert!(result.unwrap_err().to_string().contains("session intent"));
    }

    #[test]
    fn semantic_auditor_receives_only_current_attested_matcher_and_probe_evidence() {
        use std::sync::Mutex;

        struct CapturingProvider {
            captured: Mutex<Option<GuardDecisionEvidence>>,
        }

        impl DecisionProvider for CapturingProvider {
            fn decide(
                &self,
                _prompt: &str,
                _context: Option<&SessionContext>,
                _current_operation: Option<&CurrentOperation>,
                evidence: &GuardDecisionEvidence,
            ) -> Result<DecisionVerdict, DecisionError> {
                *self.captured.lock().expect("capture lock") = Some(evidence.clone());
                Ok(DecisionVerdict {
                    decision: false,
                    findings: None,
                })
            }
        }

        let provider = CapturingProvider {
            captured: Mutex::new(None),
        };
        let (context, operation) = verified_decision_inputs();
        let initial = GuardDecisionEvidence {
            guard_id: "guard-1".into(),
            event: "tool_call".into(),
            event_id: "event-1".into(),
            scope: "current_operation".into(),
            matcher_evidence: vec![MatcherEvidence {
                kind: "exact".into(),
                matcher: "publish package".into(),
                matched: true,
            }],
            matcher_evidence_truncated: false,
            deterministic_evidence: vec![DeterministicEvidence {
                rule_path: vec!["rule-1".into()],
                operation: "check clean".into(),
                expected_values: vec!["clean".into()],
                result: true,
                observed_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .into(),
            }],
            deterministic_evidence_truncated: false,
        };

        provider
            .decide(
                "Is the semantic requirement satisfied?",
                Some(&context),
                Some(&operation),
                &initial,
            )
            .unwrap();

        let captured = provider
            .captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("auditor evidence");
        assert_eq!(captured.guard_id, "guard-1");
        assert_eq!(captured.matcher_evidence.len(), 1);
        assert_eq!(captured.deterministic_evidence.len(), 1);
        assert!(captured.deterministic_evidence[0].result);
        assert_eq!(captured.deterministic_evidence[0].operation, "check clean");
        assert_eq!(
            captured.deterministic_evidence[0].observed_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_m1_bounded_command_execution_timeout_with_pipe_holding_descendants() {
        let cmd = if cfg!(target_os = "windows") {
            let mut c = Command::new("cmd");
            c.args(["/C", "ping -n 5 127.0.0.1 >nul"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", "sleep 5 & wait"]);
            c
        };

        let start = Instant::now();
        let timeout = Duration::from_millis(300);
        let res = run_command_bounded(cmd, timeout, MAX_PROBE_OUTPUT_BYTES);
        let elapsed = start.elapsed();

        assert!(res.is_err(), "Long running command must time out");
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(3),
            "Command execution must respect deadline without hanging in pipe drain: elapsed {:?}",
            elapsed
        );
    }

    #[test]
    fn bounded_command_with_input_delivers_stdin_and_collects_output() {
        let command = if cfg!(target_os = "windows") {
            let mut command = Command::new("cmd");
            command.args(["/C", "findstr .* "]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "cat"]);
            command
        };

        let output = run_command_bounded_with_input(
            command,
            b"decision pending\n".to_vec(),
            Duration::from_secs(2),
            1024,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("decision pending"));
    }
}
