use std::io;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

use super::model::UnresolvedReason;
use crate::runtime::guard_evaluation::{DIALOG_RESPONSE_SCHEMA, DialogResponse};

pub const PARENT_PROCESS_ID_ENV: &str = "ARC_DECISION_UI_PARENT_PID";
pub const DECISION_UI_TIMEOUT_ENV: &str = "ARC_DECISION_UI_TIMEOUT_MS";
pub const DECISION_UI_TRACE_ENV: &str = "ARC_DECISION_UI_TRACE";
pub const PARENT_LIVENESS_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(100);
pub const DEFAULT_DECISION_UI_HOST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(300);
pub const MAX_DECISION_UI_HOST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
pub const DECISION_UI_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
pub const MAX_DECISION_UI_SUPERVISOR_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60 + 5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalState {
    Open,
    EmissionAttempted,
    Emitted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionOutcome {
    Emitted,
}

#[derive(Debug, Error)]
pub enum CompletionError {
    #[error("terminal response has already been claimed")]
    AlreadyCompleted,
    #[error("decision deadline has expired")]
    DeadlineExpired,
    #[error("terminal response emission failed: {0}")]
    Emission(#[source] io::Error),
}

pub trait TerminalWriter: Send + Sync {
    fn write_frame(&self, frame: &[u8]) -> io::Result<()>;
}

pub struct TerminalCoordinator {
    state: Mutex<TerminalState>,
}

impl TerminalCoordinator {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(TerminalState::Open),
        }
    }

    pub fn state(&self) -> TerminalState {
        *self.lock_state()
    }

    pub fn emit(
        &self,
        serialized_frame: &[u8],
        writer: &dyn TerminalWriter,
    ) -> Result<CompletionOutcome, CompletionError> {
        self.claim(None)?;

        self.write_claimed(serialized_frame, writer)
    }

    pub fn emit_before(
        &self,
        serialized_frame: &[u8],
        writer: &dyn TerminalWriter,
        deadline: Instant,
    ) -> Result<CompletionOutcome, CompletionError> {
        self.claim(Some(deadline))?;

        self.write_claimed(serialized_frame, writer)
    }

    fn claim(&self, deadline: Option<Instant>) -> Result<(), CompletionError> {
        let mut state = self.lock_state();
        if *state != TerminalState::Open {
            return Err(CompletionError::AlreadyCompleted);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(CompletionError::DeadlineExpired);
        }
        *state = TerminalState::EmissionAttempted;
        Ok(())
    }

    fn write_claimed(
        &self,
        serialized_frame: &[u8],
        writer: &dyn TerminalWriter,
    ) -> Result<CompletionOutcome, CompletionError> {
        match writer.write_frame(serialized_frame) {
            Ok(()) => {
                *self.lock_state() = TerminalState::Emitted;
                Ok(CompletionOutcome::Emitted)
            }
            Err(error) => {
                *self.lock_state() = TerminalState::Failed;
                Err(CompletionError::Emission(error))
            }
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, TerminalState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Default for TerminalCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn unresolved_response(
    request_id: impl Into<String>,
    bundle_fingerprint: impl Into<String>,
    reason: UnresolvedReason,
    theme: impl Into<String>,
    message: Option<String>,
) -> DialogResponse {
    DialogResponse {
        schema: DIALOG_RESPONSE_SCHEMA.into(),
        request_id: request_id.into(),
        bundle_fingerprint: bundle_fingerprint.into(),
        decision: super::model::PortableDecision::Unresolved(reason),
        transport: super::model::ARC_EMBEDDED_UI_TRANSPORT_LABEL.into(),
        theme: theme.into(),
        message,
    }
}

pub fn parent_process_id_from_environment() -> Option<u32> {
    std::env::var(PARENT_PROCESS_ID_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
}

pub fn parent_process_is_alive(parent_process_id: Option<u32>) -> bool {
    let Some(parent_process_id) = parent_process_id else {
        return true;
    };

    #[cfg(unix)]
    {
        return current_parent_process_id() == parent_process_id as libc::pid_t;
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };

        // SAFETY: the PID is parsed as a bounded u32 and only the synchronization
        // right is requested for this zero-time liveness probe.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, parent_process_id) };
        if handle.is_null() {
            // Access denied is inconclusive; only an invalid PID proves that the
            // process no longer exists.
            return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
        }
        // SAFETY: the handle was returned by OpenProcess and is closed once.
        let state = unsafe { WaitForSingleObject(handle, 0) };
        // SAFETY: the handle is valid until this close.
        unsafe { CloseHandle(handle) };
        state != WAIT_OBJECT_0
    }

    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

#[cfg(unix)]
fn current_parent_process_id() -> libc::pid_t {
    // SAFETY: getppid has no preconditions and only reads process state.
    unsafe { libc::getppid() }
}

pub fn decision_ui_timeout_from_environment() -> std::time::Duration {
    let Some(value) = std::env::var(DECISION_UI_TIMEOUT_ENV).ok() else {
        return DEFAULT_DECISION_UI_HOST_TIMEOUT;
    };
    let Ok(milliseconds) = value.parse::<u64>() else {
        return DEFAULT_DECISION_UI_HOST_TIMEOUT;
    };
    std::time::Duration::from_millis(milliseconds).clamp(
        std::time::Duration::from_millis(1),
        MAX_DECISION_UI_HOST_TIMEOUT,
    )
}

pub fn decision_ui_supervisor_timeout(decision_timeout: Duration) -> Duration {
    decision_timeout
        .saturating_add(DECISION_UI_SHUTDOWN_GRACE)
        .min(MAX_DECISION_UI_SUPERVISOR_TIMEOUT)
}

pub fn trace_enabled() -> bool {
    std::env::var_os(DECISION_UI_TRACE_ENV).is_some()
}

pub fn trace(enabled: bool, event: &'static str) {
    if enabled {
        eprintln!("arc embedded decision ui trace: {event}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{Duration, Instant};

    struct FaultInjectingWriter {
        fail_after_bytes: Option<usize>,
        fail_flush: bool,
        frames: Mutex<Vec<Vec<u8>>>,
    }

    impl FaultInjectingWriter {
        fn failing_before_first_byte() -> Self {
            Self {
                fail_after_bytes: Some(0),
                fail_flush: false,
                frames: Mutex::new(Vec::new()),
            }
        }

        fn failing_after(bytes: usize) -> Self {
            Self {
                fail_after_bytes: Some(bytes),
                fail_flush: false,
                frames: Mutex::new(Vec::new()),
            }
        }

        fn failing_on_flush() -> Self {
            Self {
                fail_after_bytes: None,
                fail_flush: true,
                frames: Mutex::new(Vec::new()),
            }
        }

        fn successful() -> Self {
            Self {
                fail_after_bytes: None,
                fail_flush: false,
                frames: Mutex::new(Vec::new()),
            }
        }

        fn frame_count(&self) -> usize {
            self.frames.lock().expect("writer lock").len()
        }
    }

    impl TerminalWriter for FaultInjectingWriter {
        fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
            let mut frames = self.frames.lock().expect("writer lock");
            if let Some(limit) = self.fail_after_bytes {
                let written = limit.min(frame.len());
                frames.push(frame[..written].to_vec());
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fault-injected write failure",
                ));
            }
            frames.push(frame.to_vec());
            if self.fail_flush {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "fault-injected flush failure",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn absent_parent_metadata_keeps_a_standalone_host_alive() {
        assert!(parent_process_is_alive(None));
    }

    #[test]
    fn current_parent_is_alive_and_invalid_pid_is_not() {
        assert!(parent_process_is_alive(Some(std::process::id())));
        assert!(!parent_process_is_alive(Some(u32::MAX)));
    }

    #[test]
    fn host_timeout_has_a_finite_upper_bound() {
        assert_eq!(
            MAX_DECISION_UI_HOST_TIMEOUT,
            std::time::Duration::from_secs(86_400)
        );
    }

    #[test]
    fn supervisor_timeout_adds_grace_without_exceeding_the_documented_maximum() {
        assert_eq!(
            decision_ui_supervisor_timeout(Duration::from_secs(7)),
            Duration::from_secs(12)
        );
        assert_eq!(
            decision_ui_supervisor_timeout(MAX_DECISION_UI_HOST_TIMEOUT),
            MAX_DECISION_UI_SUPERVISOR_TIMEOUT
        );
    }

    #[test]
    fn deadline_checked_before_terminal_claim_keeps_submit_from_emitting() {
        let coordinator = TerminalCoordinator::new();
        let writer = FaultInjectingWriter::successful();

        assert!(matches!(
            coordinator.emit_before(
                b"frame\n",
                &writer,
                Instant::now() - Duration::from_millis(1)
            ),
            Err(CompletionError::DeadlineExpired)
        ));
        assert_eq!(coordinator.state(), TerminalState::Open);
        assert_eq!(writer.frame_count(), 0);
    }

    #[test]
    fn terminal_writer_failure_before_first_byte_cannot_retry() {
        let coordinator = TerminalCoordinator::new();
        let failing = FaultInjectingWriter::failing_before_first_byte();
        let successful = FaultInjectingWriter::successful();

        assert!(matches!(
            coordinator.emit(b"frame\n", &failing),
            Err(CompletionError::Emission(_))
        ));
        assert_eq!(coordinator.state(), TerminalState::Failed);
        assert!(matches!(
            coordinator.emit(b"frame\n", &successful),
            Err(CompletionError::AlreadyCompleted)
        ));
        assert_eq!(failing.frame_count(), 1);
        assert_eq!(successful.frame_count(), 0);
    }

    #[test]
    fn terminal_writer_partial_failure_never_emits_a_second_frame() {
        let coordinator = TerminalCoordinator::new();
        let failing = FaultInjectingWriter::failing_after(2);
        let successful = FaultInjectingWriter::successful();

        assert!(matches!(
            coordinator.emit(b"frame\n", &failing),
            Err(CompletionError::Emission(_))
        ));
        assert!(matches!(
            coordinator.emit(b"frame\n", &successful),
            Err(CompletionError::AlreadyCompleted)
        ));
        assert_eq!(coordinator.state(), TerminalState::Failed);
        assert_eq!(failing.frame_count(), 1);
        assert_eq!(successful.frame_count(), 0);
    }

    #[test]
    fn terminal_writer_flush_failure_is_terminal_without_retry() {
        let coordinator = TerminalCoordinator::new();
        let failing = FaultInjectingWriter::failing_on_flush();
        let successful = FaultInjectingWriter::successful();

        assert!(matches!(
            coordinator.emit(b"frame\n", &failing),
            Err(CompletionError::Emission(_))
        ));
        assert_eq!(coordinator.state(), TerminalState::Failed);
        assert!(matches!(
            coordinator.emit(b"frame\n", &successful),
            Err(CompletionError::AlreadyCompleted)
        ));
        assert_eq!(failing.frame_count(), 1);
        assert_eq!(successful.frame_count(), 0);
    }

    #[test]
    fn terminal_coordinator_allows_one_emitter_under_a_32_thread_race() {
        let coordinator = Arc::new(TerminalCoordinator::new());
        let writer = Arc::new(FaultInjectingWriter::successful());
        let barrier = Arc::new(Barrier::new(32));
        let handles = (0..32)
            .map(|_| {
                let coordinator = Arc::clone(&coordinator);
                let writer = Arc::clone(&writer);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    coordinator.emit(b"frame\n", writer.as_ref())
                })
            })
            .collect::<Vec<_>>();

        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("terminal worker should finish"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(CompletionOutcome::Emitted)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(CompletionError::AlreadyCompleted)))
                .count(),
            31
        );
        assert_eq!(coordinator.state(), TerminalState::Emitted);
        assert_eq!(writer.frame_count(), 1);
    }
}
