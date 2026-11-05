use anyhow::{Context, Result, bail};
use std::io::{Read, Write};

use super::model::{MAX_DECISION_HOST_INPUT_BYTES, MAX_DECISION_HOST_OUTPUT_BYTES};
use crate::runtime::guard_evaluation::{DialogRequest, DialogResponse};

pub const MAX_DIALOG_MESSAGE_CHARS: usize = 16 * 1024;

pub fn read_dialog_request<R: Read>(reader: R) -> Result<DialogRequest> {
    let raw = read_bounded_request(reader)?;
    let request: DialogRequest =
        serde_json::from_slice(&raw).context("invalid embedded decision request v2 JSON")?;
    request
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid embedded decision request v2: {error}"))?;
    Ok(request)
}

fn read_bounded_request<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(MAX_DECISION_HOST_INPUT_BYTES + 1);
    reader
        .take((MAX_DECISION_HOST_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .context("failed reading embedded decision request")?;
    if raw.len() > MAX_DECISION_HOST_INPUT_BYTES {
        bail!(
            "embedded decision request exceeds the {} byte IPC limit",
            MAX_DECISION_HOST_INPUT_BYTES
        );
    }
    if raw.iter().all(u8::is_ascii_whitespace) {
        bail!("embedded decision request is empty");
    }
    Ok(raw)
}

pub fn write_serialized_dialog_response<W: Write>(mut writer: W, frame: &[u8]) -> Result<()> {
    writer
        .write_all(frame)
        .context("failed writing embedded decision response")?;
    writer
        .flush()
        .context("failed flushing embedded decision response")?;
    Ok(())
}

pub fn serialize_dialog_response(response: &DialogResponse) -> Result<Vec<u8>> {
    let encoded =
        serde_json::to_vec(response).context("failed serializing embedded decision response v2")?;
    let frame_len = encoded
        .len()
        .checked_add(1)
        .context("embedded decision response v2 frame length overflowed")?;
    if frame_len > MAX_DECISION_HOST_OUTPUT_BYTES {
        bail!(
            "embedded decision response v2 exceeds the {} byte IPC limit",
            MAX_DECISION_HOST_OUTPUT_BYTES
        );
    }
    let mut frame = encoded;
    frame.push(b'\n');
    Ok(frame)
}

pub fn write_dialog_response<W: Write>(mut writer: W, response: &DialogResponse) -> Result<()> {
    let frame = serialize_dialog_response(response)?;
    write_serialized_dialog_response(&mut writer, &frame)
}

pub fn bounded_user_message(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| {
        value
            .chars()
            .take(super::model::MAX_DIALOG_USER_MESSAGE_CHARS)
            .collect()
    })
}

pub fn bounded_diagnostic(prefix: &str, details: &str) -> String {
    let prefix = prefix.trim();
    let details = details.trim();
    let mut message = prefix
        .chars()
        .take(MAX_DIALOG_MESSAGE_CHARS)
        .collect::<String>();
    let remaining = MAX_DIALOG_MESSAGE_CHARS.saturating_sub(message.chars().count());
    if details.is_empty() || remaining == 0 {
        return message;
    }
    if remaining >= 2 {
        message.push_str(": ");
    }
    let remaining = MAX_DIALOG_MESSAGE_CHARS.saturating_sub(message.chars().count());
    message.extend(details.chars().take(remaining));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_ui::model::{self, PortableDecision, UnresolvedReason};
    use crate::runtime::guard_evaluation::{DIALOG_RESPONSE_SCHEMA, DialogViolationItem};
    use std::io::Cursor;

    fn request() -> DialogRequest {
        DialogRequest::guard_failures(
            "request-1",
            "Decision",
            "once",
            vec![DialogViolationItem {
                guard_id: "guard-1".into(),
                summary: "Literal text: مرحبا".into(),
                configured_feedback: Some("Review the current operation.".into()),
                auditor_findings: Some("The audit found a policy mismatch.".into()),
                scope: "once".into(),
                failed_probes: Vec::new(),
            }],
            "bundle-hash-1",
            100,
        )
    }

    #[test]
    fn valid_v2_request_is_read_with_literal_unicode_content() {
        let encoded = serde_json::to_vec(&request()).expect("request serializes");
        let decoded = read_dialog_request(Cursor::new(encoded)).expect("request is valid");
        assert_eq!(decoded.violations[0].summary, "Literal text: مرحبا");
        assert_eq!(
            decoded.violations[0].auditor_findings.as_deref(),
            Some("The audit found a policy mismatch.")
        );
    }

    #[test]
    fn empty_invalid_and_oversized_requests_are_rejected_before_host_creation() {
        assert!(read_dialog_request(Cursor::new(b"  \n".to_vec())).is_err());
        assert!(read_dialog_request(Cursor::new(b"not-json".to_vec())).is_err());

        let oversized = vec![b'x'; MAX_DECISION_HOST_INPUT_BYTES + 1];
        assert!(read_dialog_request(Cursor::new(oversized)).is_err());

        let mut invalid = request();
        invalid.request_id.clear();
        let encoded = serde_json::to_vec(&invalid).expect("request serializes");
        assert!(read_dialog_request(Cursor::new(encoded)).is_err());
    }

    #[test]
    fn v2_response_writer_emits_one_bounded_json_line() {
        let response = DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "request-1".into(),
            bundle_fingerprint: "bundle-hash-1".into(),
            decision: PortableDecision::Unresolved(UnresolvedReason::Closed),
            transport: "arc_embedded_ui".into(),
            theme: "light".into(),
            message: None,
        };
        let mut output = Vec::new();
        write_dialog_response(&mut output, &response).expect("response writes");
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        let decoded: DialogResponse = serde_json::from_slice(&output).expect("response is JSON");
        assert_eq!(decoded, response);
    }

    #[test]
    fn user_notes_are_trimmed_and_bounded_by_character_count() {
        assert_eq!(
            bounded_user_message("  approved once  "),
            Some("approved once".into())
        );
        assert_eq!(bounded_user_message("  "), None);
        assert_eq!(
            bounded_user_message(&"x".repeat(model::MAX_DIALOG_USER_MESSAGE_CHARS + 1))
                .expect("non-empty note")
                .chars()
                .count(),
            model::MAX_DIALOG_USER_MESSAGE_CHARS
        );
    }

    #[test]
    fn diagnostics_are_bounded_without_exposing_unbounded_data() {
        let message = bounded_diagnostic("native host failed", &"x".repeat(100_000));
        assert_eq!(message.chars().count(), MAX_DIALOG_MESSAGE_CHARS);
        assert!(message.starts_with("native host failed: "));
    }
}
