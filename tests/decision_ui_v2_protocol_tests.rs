use arc::decision_ui::{read_dialog_request, serialize_dialog_response, write_dialog_response};
use arc::runtime::guard_evaluation::{DialogFailedProbe, MAX_DIALOG_FAILED_PROBES};
use arc::{
    DialogAuthorizationItem, DialogRequest, DialogResponse, DialogViolationItem, PortableDecision,
};
use serde_json::{Value, json};
use std::io::Cursor;

fn request() -> DialogRequest {
    DialogRequest::guard_failures(
        "request-v2",
        "Arc policy decision",
        "this activation",
        vec![
            DialogViolationItem {
                guard_id: "guard-a".into(),
                summary: "Tests are incomplete".into(),
                configured_feedback: Some("Run the required tests before finishing.".into()),
                auditor_findings: Some("The required test suite did not run.".into()),
                scope: "lifecycle:end".into(),
                failed_probes: Vec::new(),
            },
            DialogViolationItem {
                guard_id: "guard-b".into(),
                summary: "Workspace is dirty".into(),
                configured_feedback: None,
                auditor_findings: None,
                scope: "lifecycle:end".into(),
                failed_probes: Vec::new(),
            },
        ],
        "sha256:bundle",
        100,
    )
}

#[test]
fn v2_request_is_bounded_validated_and_round_trips() {
    let encoded = serde_json::to_vec(&request()).expect("request JSON");
    let decoded = read_dialog_request(Cursor::new(encoded)).expect("valid v2 request");
    assert_eq!(decoded, request());
    assert_eq!(decoded.violations.len(), 2);
}

#[test]
fn v2_request_rejects_invalid_auditor_findings() {
    let mut request = request();
    request.violations[0].auditor_findings = Some("<script>do not render</script>".into());
    assert!(request.validate().is_err());

    request.violations[0].auditor_findings = Some("  ".into());
    assert!(request.validate().is_err());
}

#[test]
fn v2_request_rejects_invalid_configured_feedback() {
    let mut request = request();
    request.violations[0].configured_feedback = Some("<script>do not render</script>".into());
    assert!(request.validate().is_err());

    request.violations[0].configured_feedback = Some("  ".into());
    assert!(request.validate().is_err());
}

#[test]
fn v2_request_rejects_mixed_presentations_before_sidecar_creation() {
    let mut value = serde_json::to_value(request()).expect("request JSON");
    value["presentation_kind"] = "exact_operation_authorization".into();
    value["authorization"] = serde_json::json!({
        "guard_id": "guard-a",
        "summary": "Authorize exact operation",
        "operation_fingerprint": "sha256:operation"
    });
    let encoded = serde_json::to_vec(&value).expect("mixed request JSON");
    assert!(read_dialog_request(Cursor::new(encoded)).is_err());
}

#[test]
fn v2_response_is_one_bounded_json_line_and_correlates_to_request() {
    let request = DialogRequest::exact_authorizations(
        "request-auth",
        "Authorize operation",
        "once",
        vec![DialogAuthorizationItem {
            guard_id: "guard-tool".into(),
            summary: "Authorize exact operation".into(),
            auditor_findings: Some("The auditor found no policy conflict.".into()),
            operation_fingerprint: "sha256:operation".into(),
        }],
        "git status",
        "sha256:bundle",
        100,
    );
    let response = DialogResponse {
        schema: "arc.decision.dialog.response.v2".into(),
        request_id: request.request_id.clone(),
        bundle_fingerprint: request.bundle_fingerprint.clone(),
        decision: PortableDecision::Allow,
        transport: "arc_embedded_ui".into(),
        theme: "dark".into(),
        message: None,
    };
    response
        .validate_for(&request)
        .expect("response correlation");
    let frame = serialize_dialog_response(&response).expect("response frame");
    assert_eq!(frame.iter().filter(|byte| **byte == b'\n').count(), 1);
    let mut output = Vec::new();
    write_dialog_response(&mut output, &response).expect("write response");
    assert_eq!(output, frame);
}

#[test]
fn v2_request_accepts_aggregate_decision_with_both_violations_and_authorizations() {
    let request = DialogRequest::aggregate_decision(
        "request-agg",
        "Aggregate policy decision",
        "activation",
        vec![DialogViolationItem {
            guard_id: "guard-ask".into(),
            summary: "Requires operator confirmation".into(),
            configured_feedback: None,
            auditor_findings: None,
            scope: "activation".into(),
            failed_probes: Vec::new(),
        }],
        vec![DialogAuthorizationItem {
            guard_id: "guard-auth".into(),
            summary: "Requires exact authorization".into(),
            auditor_findings: None,
            operation_fingerprint: "sha256:operation".into(),
        }],
        Some("git commit -m test".into()),
        "sha256:semantic-bundle-fingerprint",
        150,
    );
    let encoded = serde_json::to_vec(&request).expect("request JSON");
    let decoded = read_dialog_request(Cursor::new(encoded)).expect("valid aggregate request");
    assert_eq!(decoded, request);
    assert_eq!(decoded.violations.len(), 1);
    assert_eq!(decoded.authorizations.len(), 1);
    assert_eq!(
        decoded.presentation_kind,
        arc::PresentationKind::AggregateDecision
    );
}

#[test]
fn v2_request_rejects_empty_aggregate_decision() {
    let request = DialogRequest::aggregate_decision(
        "request-empty-agg",
        "Empty aggregate",
        "activation",
        Vec::new(),
        Vec::new(),
        None,
        "sha256:bundle",
        150,
    );
    let encoded = serde_json::to_vec(&request).expect("request JSON");
    assert!(read_dialog_request(Cursor::new(encoded)).is_err());
}

#[test]
fn v2_request_rejects_aggregate_decision_with_authorizations_but_missing_operation() {
    let request = DialogRequest::aggregate_decision(
        "request-agg-no-op",
        "Aggregate missing operation",
        "activation",
        Vec::new(),
        vec![DialogAuthorizationItem {
            guard_id: "guard-auth".into(),
            summary: "Requires exact authorization".into(),
            auditor_findings: None,
            operation_fingerprint: "sha256:operation".into(),
        }],
        None,
        "sha256:bundle",
        150,
    );
    let encoded = serde_json::to_vec(&request).expect("request JSON");
    assert!(read_dialog_request(Cursor::new(encoded)).is_err());
}

// ---------------------------------------------------------------------------
// REQ-001 AC-001.7: the `failed_probes` wire field and its validation.
// ---------------------------------------------------------------------------

fn failed_probe(rule: Option<&str>, command: &str, reason: Option<&str>) -> DialogFailedProbe {
    DialogFailedProbe {
        rule_name: rule.map(str::to_owned),
        command: command.to_owned(),
        reason: reason.map(str::to_owned),
    }
}

fn request_with_probes(probes: Vec<DialogFailedProbe>) -> DialogRequest {
    let mut request = request();
    request.violations[0].failed_probes = probes;
    request
}

fn accepted_by_the_host_reader(request: &DialogRequest) -> bool {
    let encoded = serde_json::to_vec(request).expect("request JSON");
    read_dialog_request(Cursor::new(encoded)).is_ok()
}

fn wire_with_probes(probes: Value) -> Vec<u8> {
    let mut value = serde_json::to_value(request()).expect("request JSON");
    value["violations"][0]["failed_probes"] = probes;
    serde_json::to_vec(&value).expect("wire JSON")
}

#[test]
fn v2_request_with_failed_probes_round_trips_through_the_host_reader() {
    let request = request_with_probes(vec![
        failed_probe(Some("tests-green"), "cargo test", None),
        failed_probe(None, "git status --porcelain", None),
        failed_probe(
            Some("wip-flag"),
            "cat .wip",
            Some("negated expression evaluated to true"),
        ),
    ]);
    request.validate().expect("valid request");
    let encoded = serde_json::to_vec(&request).expect("request JSON");
    let decoded = read_dialog_request(Cursor::new(encoded)).expect("valid v2 request");
    assert_eq!(decoded, request);
    assert_eq!(decoded.violations[0].failed_probes.len(), 3);
    assert!(decoded.violations[1].failed_probes.is_empty());
}

#[test]
fn v2_request_without_failed_probes_has_no_failed_probes_key_on_the_wire() {
    let value = serde_json::to_value(request()).expect("request JSON");
    for violation in value["violations"].as_array().expect("violations") {
        assert!(violation.get("failed_probes").is_none(), "{violation}");
    }
}

#[test]
fn v2_request_accepts_the_failed_probe_limit_and_rejects_one_more() {
    assert_eq!(MAX_DIALOG_FAILED_PROBES, 64);
    let probes = |count: usize| -> Vec<DialogFailedProbe> {
        (0..count)
            .map(|index| failed_probe(None, &format!("probe-{index}"), None))
            .collect()
    };
    let at_limit = request_with_probes(probes(MAX_DIALOG_FAILED_PROBES));
    assert!(at_limit.validate().is_ok());
    assert!(accepted_by_the_host_reader(&at_limit));

    let over_limit = request_with_probes(probes(MAX_DIALOG_FAILED_PROBES + 1));
    assert!(over_limit.validate().is_err());
    assert!(!accepted_by_the_host_reader(&over_limit));
}

#[test]
fn v2_request_rejects_a_failed_probe_with_a_blank_or_over_long_command() {
    for command in ["", "   ", "\u{85}"] {
        let request = request_with_probes(vec![failed_probe(None, command, None)]);
        assert!(request.validate().is_err(), "command {command:?}");
        assert!(
            !accepted_by_the_host_reader(&request),
            "command {command:?}"
        );
    }
    let at_limit = request_with_probes(vec![failed_probe(None, &"c".repeat(256), None)]);
    assert!(at_limit.validate().is_ok());
    let over_limit = request_with_probes(vec![failed_probe(None, &"c".repeat(257), None)]);
    assert!(over_limit.validate().is_err());
}

#[test]
fn v2_request_keeps_shell_text_in_a_failed_probe_command_unchecked_for_markup() {
    let request = request_with_probes(vec![failed_probe(
        Some("a<b>rule"),
        "echo <script>x</script> 2>/dev/null",
        None,
    )]);
    request
        .validate()
        .expect("commands and rule names are not markup checked");
    assert!(accepted_by_the_host_reader(&request));
}

#[test]
fn v2_request_checks_the_failed_probe_rule_name_and_reason() {
    let blank_rule = request_with_probes(vec![failed_probe(Some("  "), "cargo test", None)]);
    assert!(blank_rule.validate().is_err());
    let long_rule = request_with_probes(vec![failed_probe(Some(&"r".repeat(257)), "c", None)]);
    assert!(long_rule.validate().is_err());
    let rule_at_limit = request_with_probes(vec![failed_probe(Some(&"r".repeat(256)), "c", None)]);
    assert!(rule_at_limit.validate().is_ok());

    let blank_reason = request_with_probes(vec![failed_probe(None, "c", Some(""))]);
    assert!(blank_reason.validate().is_err());
    let markup_reason = request_with_probes(vec![failed_probe(None, "c", Some("<b>bold</b>"))]);
    assert!(markup_reason.validate().is_err());
    let long_reason = request_with_probes(vec![failed_probe(None, "c", Some(&"x".repeat(513)))]);
    assert!(long_reason.validate().is_err());
    let reason_at_limit =
        request_with_probes(vec![failed_probe(None, "c", Some(&"x".repeat(512)))]);
    assert!(reason_at_limit.validate().is_ok());
}

#[test]
fn v2_wire_rejects_malformed_failed_probes() {
    let good = json!([{"rule_name": "r", "command": "c", "reason": null}]);
    assert!(read_dialog_request(Cursor::new(wire_with_probes(good))).is_ok());
    let absent_optionals = json!([{"command": "c"}]);
    assert!(read_dialog_request(Cursor::new(wire_with_probes(absent_optionals))).is_ok());

    for (label, probes) in [
        ("null list", Value::Null),
        ("string list", json!("x")),
        ("string item", json!(["x"])),
        ("null item", json!([null])),
        ("missing command", json!([{"rule_name": "r"}])),
        ("null command", json!([{"command": null}])),
        ("numeric command", json!([{"command": 7}])),
        (
            "unknown key",
            json!([{"command": "c", "expected_values": ["x"]}]),
        ),
        (
            "numeric rule_name",
            json!([{"command": "c", "rule_name": 3}]),
        ),
        ("numeric reason", json!([{"command": "c", "reason": 3}])),
    ] {
        assert!(
            read_dialog_request(Cursor::new(wire_with_probes(probes))).is_err(),
            "{label} must be rejected"
        );
    }
}
