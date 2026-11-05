use thiserror::Error;

pub(crate) const MAX_GUARD_ID_CHARS: usize = 256;
pub(crate) const MAX_DECISION_ID_CHARS: usize = 256;
pub(crate) const MAX_EXECUTION_ID_CHARS: usize = 256;
pub(crate) const MAX_INVOCATION_ID_CHARS: usize = 256;
pub(crate) const MAX_PRESENTATION_ID_CHARS: usize = 256;
pub(crate) const MAX_MESSAGE_CHARS: usize = 16 * 1024;
pub(crate) const MAX_FINDINGS_CHARS: usize = 16 * 1024;
pub(crate) const MAX_OPERATION_DISPLAY_CHARS: usize = 4 * 1024;
pub(crate) const MAX_OPERATION_TOOL_CHARS: usize = 256;
pub(crate) const MAX_COMMAND_TEXT_CHARS: usize = 16 * 1024;
pub(crate) const MAX_OPERATION_INPUT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SCOPE_CHARS: usize = 2 * 1024;
pub(crate) const MAX_TRANSPORT_LABEL_CHARS: usize = 256;
pub(crate) const MAX_THEME_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecisionContractError {
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("{field} exceeds the {max} character limit (got {actual})")]
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("{field} exceeds the {max} byte limit (got {actual})")]
    StructuredFieldTooLarge {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("{field} contains an unsupported value")]
    InvalidStructuredField { field: &'static str },
    #[error("interactive decisions for the Start event are rejected before presentation")]
    StartAskNotSupported,
    #[error(
        "interactive request {field} does not match capability context (expected {expected}, got {actual})"
    )]
    CapabilityMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("interactive requests must use action ask (got {actual})")]
    InvalidRequestedAction { actual: String },
    #[error(
        "interactive presentation already claimed for invocation {invocation_id} and decision {decision_id:?}"
    )]
    DuplicatePresentation {
        invocation_id: String,
        decision_id: Option<String>,
    },
    #[error(
        "current operation event {operation_event} does not match interactive request event {request_event}"
    )]
    OperationEventMismatch {
        operation_event: String,
        request_event: String,
    },
    #[error("decision response request id does not match the presented request")]
    ResponseRequestMismatch { expected: String, received: String },
    #[error("schema mismatch: expected '{expected}', got '{actual}'")]
    Schema {
        expected: &'static str,
        actual: String,
    },
    #[error("correlation field '{field}' does not match the request")]
    CorrelationMismatch { field: &'static str },
    #[error("transport label {label} does not match transport {transport}")]
    TransportLabelMismatch {
        transport: &'static str,
        label: String,
    },
}

pub(crate) fn validate_required(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), DecisionContractError> {
    if value.trim().is_empty() {
        return Err(DecisionContractError::EmptyField { field });
    }
    validate_bounded(field, value, max)
}

pub(crate) fn validate_optional(
    field: &'static str,
    value: Option<&str>,
    max: usize,
) -> Result<(), DecisionContractError> {
    if let Some(value) = value {
        validate_required(field, value, max)?;
    }
    Ok(())
}

pub(crate) fn validate_bounded(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), DecisionContractError> {
    let actual = value.chars().count();
    if actual > max {
        return Err(DecisionContractError::FieldTooLong { field, max, actual });
    }
    Ok(())
}

pub(crate) fn validate_structured_bounded(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), DecisionContractError> {
    if actual > max {
        return Err(DecisionContractError::StructuredFieldTooLarge { field, max, actual });
    }
    Ok(())
}
