mod host;
mod lifecycle;
mod model;
mod protocol;

pub use host::{
    DECISION_UI_HOST_BINARY, DECISION_UI_HOST_ENV, request_embedded_decision,
    request_terminal_decision,
};
pub use lifecycle::{
    CompletionError, CompletionOutcome, DECISION_UI_SHUTDOWN_GRACE, DECISION_UI_TIMEOUT_ENV,
    DECISION_UI_TRACE_ENV, DEFAULT_DECISION_UI_HOST_TIMEOUT, MAX_DECISION_UI_HOST_TIMEOUT,
    MAX_DECISION_UI_SUPERVISOR_TIMEOUT, PARENT_LIVENESS_POLL_INTERVAL, PARENT_PROCESS_ID_ENV,
    TerminalCoordinator, TerminalState, TerminalWriter, decision_ui_supervisor_timeout,
    decision_ui_timeout_from_environment, parent_process_id_from_environment,
    parent_process_is_alive, trace, trace_enabled, unresolved_response,
};
pub use model::{
    ARC_EMBEDDED_UI_TRANSPORT_LABEL, MAX_DECISION_HOST_INPUT_BYTES, MAX_DECISION_HOST_OUTPUT_BYTES,
    MAX_DIALOG_USER_MESSAGE_CHARS, PortableDecision, UiTheme, UnresolvedReason,
};
pub use protocol::{
    MAX_DIALOG_MESSAGE_CHARS, bounded_diagnostic, bounded_user_message, read_dialog_request,
    serialize_dialog_response, write_dialog_response, write_serialized_dialog_response,
};

// Re-export canonical protocol types for convenience
pub use crate::runtime::guard_evaluation::{
    DIALOG_REQUEST_SCHEMA, DIALOG_RESPONSE_SCHEMA, DialogAuthorizationItem, DialogRequest,
    DialogResponse, DialogViolationItem, PresentationKind,
};
