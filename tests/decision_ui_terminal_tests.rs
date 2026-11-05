use arc::decision_ui::{CompletionError, TerminalCoordinator, TerminalState, TerminalWriter};
use std::io;
use std::sync::Mutex;

struct PartialWriter {
    attempts: Mutex<usize>,
}

impl TerminalWriter for PartialWriter {
    fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "partial writer lock poisoned"))?;
        *attempts += 1;
        if frame.len() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "partial writer stopped after a prefix",
            ));
        }
        Ok(())
    }
}

#[test]
fn public_terminal_coordinator_rejects_retry_after_partial_writer_failure() {
    let coordinator = TerminalCoordinator::new();
    let writer = PartialWriter {
        attempts: Mutex::new(0),
    };

    assert!(matches!(
        coordinator.emit(b"serialized-frame\n", &writer),
        Err(CompletionError::Emission(_))
    ));
    assert_eq!(coordinator.state(), TerminalState::Failed);
    assert!(matches!(
        coordinator.emit(b"serialized-frame\n", &writer),
        Err(CompletionError::AlreadyCompleted)
    ));
    assert_eq!(*writer.attempts.lock().expect("attempt counter lock"), 1);
}
