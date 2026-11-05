//! REQ-010: Rust side of the shared dialog contract fixture.
//!
//! `tests/fixtures/dialog_contract.json` is read by this file and by
//! `ui/decision/src/lib/dialog-contract-fixture.test.ts`. Rust is the reference:
//! every request goes through `read_dialog_request`, the function the decision
//! UI host calls on stdin (`run_from_stdio`), so a fixture case that disagrees
//! with Rust is a fixture bug.

use arc::decision_ui::{MAX_DIALOG_USER_MESSAGE_CHARS, UiTheme, read_dialog_request};
use arc::runtime::guard_evaluation::{
    DIALOG_REQUEST_SCHEMA, MAX_DIALOG_AUDITOR_FINDINGS_CHARS, MAX_DIALOG_CONFIGURED_FEEDBACK_CHARS,
    MAX_DIALOG_FAILED_PROBES, MAX_ID_CHARS, MAX_OPERATION_CHARS, MAX_SCOPE_CHARS,
    MAX_SUMMARY_CHARS, MAX_TITLE_CHARS,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Cursor;

const FIXTURE: &str = include_str!("fixtures/dialog_contract.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("dialog_contract.json is valid JSON")
}

fn limit(fx: &Value, key: &str) -> usize {
    fx["limits"][key]
        .as_u64()
        .unwrap_or_else(|| panic!("fixture limit '{key}' is missing")) as usize
}

/// `astral_count` astral code points followed by `fill`, `len` code points in total.
fn build_string(fx: &Value, len: usize) -> String {
    let spec = &fx["boundary_string"];
    let astral = spec["astral"].as_str().expect("astral char");
    let fill = spec["fill"].as_str().expect("fill char");
    let count = spec["astral_count"].as_u64().expect("astral_count") as usize;
    assert!(
        len >= count,
        "boundary length {len} is below astral_count {count}"
    );
    let mut out = astral.repeat(count);
    out.push_str(&fill.repeat(len - count));
    out
}

fn step<'a>(node: &'a mut Value, segment: &str) -> &'a mut Value {
    match segment.parse::<usize>() {
        Ok(index) => node
            .get_mut(index)
            .unwrap_or_else(|| panic!("fixture path index {index} is out of range")),
        Err(_) => node
            .get_mut(segment)
            .unwrap_or_else(|| panic!("fixture path segment '{segment}' does not exist")),
    }
}

fn set_path(root: &mut Value, path: &str, value: Value) {
    let segments: Vec<&str> = path.split('.').collect();
    let (last, parents) = segments.split_last().expect("non-empty path");
    let mut node = root;
    for segment in parents {
        node = step(node, segment);
    }
    match last.parse::<usize>() {
        Ok(index) => node[index] = value,
        Err(_) => {
            node.as_object_mut()
                .unwrap_or_else(|| panic!("fixture path '{path}' parent is not an object"))
                .insert((*last).to_string(), value);
        }
    }
}

fn remove_path(root: &mut Value, path: &str) {
    let segments: Vec<&str> = path.split('.').collect();
    let (last, parents) = segments.split_last().expect("non-empty path");
    let mut node = root;
    for segment in parents {
        node = step(node, segment);
    }
    node.as_object_mut()
        .unwrap_or_else(|| panic!("fixture path '{path}' parent is not an object"))
        .remove(*last);
}

fn base(fx: &Value, name: &str) -> Value {
    fx["bases"][name].clone()
}

fn base_request(fx: &Value, case: &Value) -> Value {
    if let Some(literal) = case.get("request") {
        return literal.clone();
    }
    let name = case["base"].as_str().expect("case base");
    let mut request = base(fx, name);
    if let Some(set) = case.get("set").and_then(Value::as_object) {
        for (path, value) in set {
            set_path(&mut request, path, value.clone());
        }
    }
    if let Some(remove) = case.get("remove").and_then(Value::as_array) {
        for path in remove {
            remove_path(&mut request, path.as_str().expect("remove path"));
        }
    }
    request
}

fn boundary_request(fx: &Value, case: &Value) -> Value {
    let mut request = base(fx, case["base"].as_str().expect("case base"));
    let len = limit(fx, case["limit"].as_str().expect("limit key"))
        + case["offset"].as_u64().expect("offset") as usize;
    set_path(
        &mut request,
        case["field"].as_str().expect("field"),
        Value::String(build_string(fx, len)),
    );
    request
}

/// REQ-001: `limits[limit] + offset` copies of `item` at `field`.
fn count_request(fx: &Value, case: &Value) -> Value {
    let mut request = base(fx, case["base"].as_str().expect("case base"));
    let len = limit(fx, case["limit"].as_str().expect("limit key"))
        + case["offset"].as_u64().expect("offset") as usize;
    let items = vec![case["item"].clone(); len];
    set_path(
        &mut request,
        case["field"].as_str().expect("field"),
        Value::Array(items),
    );
    request
}

/// Runs the value through the host stdin boundary. `Err` carries the rejection reason.
fn through_host_reader(request: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(request).expect("fixture value serializes");
    read_dialog_request(Cursor::new(bytes))
        .map(|_| ())
        .map_err(|error| format!("{error:#}"))
}

fn expected_accept(case: &Value) -> bool {
    match case["expect"].as_str() {
        Some("accept") => true,
        Some("reject") => false,
        other => panic!("case {} has invalid expect {other:?}", case["name"]),
    }
}

fn cases<'a>(fx: &'a Value, key: &str) -> &'a Vec<Value> {
    fx[key]
        .as_array()
        .unwrap_or_else(|| panic!("fixture key '{key}' is not an array"))
}

fn view_model_value(fx: &Value, case: &Value) -> Value {
    if let Some(literal) = case.get("view_model") {
        return literal.clone();
    }
    let mut request = base(fx, case["base"].as_str().expect("case base"));
    if let Some(set) = case.get("request_set").and_then(Value::as_object) {
        for (path, value) in set {
            set_path(&mut request, path, value.clone());
        }
    }
    let mut model = serde_json::Map::new();
    model.insert("request".into(), request);
    for (key, value) in case["view"].as_object().expect("view object") {
        model.insert(key.clone(), value.clone());
    }
    if let Some(remove) = case.get("view_remove").and_then(Value::as_array) {
        for key in remove {
            model.remove(key.as_str().expect("view_remove key"));
        }
    }
    Value::Object(model)
}

/// The host builds the view model with `serde::Serialize` only, so there is no
/// Rust deserializer to call. The reference is made of the real pieces: the
/// stdin reader for `request`, `UiTheme` for `theme`, and the crate bound for
/// `max_user_message_chars`.
fn view_model_accepted_by_rust(model: &Value) -> bool {
    let Some(object) = model.as_object() else {
        return false;
    };
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = ["max_user_message_chars", "preview", "request", "theme"]
        .into_iter()
        .collect();
    if keys != expected {
        return false;
    }
    if through_host_reader(&object["request"]).is_err() {
        return false;
    }
    if serde_json::from_value::<UiTheme>(object["theme"].clone()).is_err() {
        return false;
    }
    match object["max_user_message_chars"].as_u64() {
        Some(n) if n >= 1 && (n as usize) <= MAX_DIALOG_USER_MESSAGE_CHARS => {}
        _ => return false,
    }
    object["preview"].is_boolean()
}

#[test]
fn fixture_limits_equal_the_crate_constants() {
    let fx = fixture();
    let expected = [
        ("id", MAX_ID_CHARS),
        ("title", MAX_TITLE_CHARS),
        ("scope", MAX_SCOPE_CHARS),
        ("summary", MAX_SUMMARY_CHARS),
        ("operation", MAX_OPERATION_CHARS),
        ("feedback", MAX_DIALOG_CONFIGURED_FEEDBACK_CHARS),
        ("findings", MAX_DIALOG_AUDITOR_FINDINGS_CHARS),
        ("user_message", MAX_DIALOG_USER_MESSAGE_CHARS),
        // REQ-001: the per-guard cap of the `failed_probes` list.
        ("failed_probes", MAX_DIALOG_FAILED_PROBES),
    ];
    for (key, constant) in expected {
        assert_eq!(
            limit(&fx, key),
            constant,
            "fixture limit '{key}' differs from the crate"
        );
    }
    let fixture_keys: BTreeSet<&str> = fx["limits"]
        .as_object()
        .expect("limits object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected_keys: BTreeSet<&str> = expected.iter().map(|(key, _)| *key).collect();
    assert_eq!(
        fixture_keys, expected_keys,
        "fixture limits has unexpected or missing keys"
    );
}

#[test]
fn fixture_bases_use_the_crate_schema_token_and_are_accepted() {
    let fx = fixture();
    for name in [
        "guard_failures",
        "exact_operation_authorization",
        "aggregate_decision",
    ] {
        let request = base(&fx, name);
        assert_eq!(request["schema"], DIALOG_REQUEST_SCHEMA);
        assert_eq!(request["presentation_kind"], name);
        through_host_reader(&request)
            .unwrap_or_else(|error| panic!("base '{name}' rejected: {error}"));
    }
}

#[test]
fn boundary_strings_hold_an_astral_code_point_so_utf16_counting_fails() {
    let fx = fixture();
    let text = build_string(&fx, 10);
    assert_eq!(text.chars().count(), 10);
    assert_eq!(
        text.encode_utf16().count(),
        10 + fx["boundary_string"]["astral_count"].as_u64().unwrap() as usize
    );
    assert!(
        fx["boundary_string"]["astral_count"].as_u64().unwrap() >= 1,
        "at least one astral code point is required"
    );
    assert!(
        fx["boundary_string"]["astral"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| (c as u32) > 0xFFFF),
        "astral must be outside the BMP"
    );
}

#[test]
fn fixture_covers_every_limit_kind_and_pairs_each_boundary() {
    let fx = fixture();
    let boundary = cases(&fx, "boundary_cases");
    for key in [
        "id",
        "title",
        "scope",
        "summary",
        "operation",
        "feedback",
        "findings",
    ] {
        for (offset, expect) in [(0, "accept"), (1, "reject")] {
            assert!(
                boundary.iter().any(|case| case["limit"] == key
                    && case["offset"] == offset
                    && case["expect"] == expect),
                "no boundary case for limit '{key}' offset {offset}"
            );
        }
    }
    // Every (field, base) boundary is present on both sides of the limit.
    for case in boundary {
        let partner_offset = if case["offset"] == 0 { 1 } else { 0 };
        assert!(
            boundary.iter().any(|other| other["field"] == case["field"]
                && other["base"] == case["base"]
                && other["limit"] == case["limit"]
                && other["offset"] == partner_offset),
            "boundary case {} has no partner on the other side of the limit",
            case["name"]
        );
    }
    let requests = cases(&fx, "request_cases");
    for kind in [
        "guard_failures",
        "exact_operation_authorization",
        "aggregate_decision",
    ] {
        assert!(
            requests
                .iter()
                .any(|case| case["base"] == kind && case["expect"] == "accept"),
            "no accepted request case for kind {kind}"
        );
    }
    for key in ["boundary_cases", "request_cases", "view_model_cases"] {
        let names: Vec<&str> = cases(&fx, key)
            .iter()
            .map(|case| case["name"].as_str().expect("case name"))
            .collect();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "duplicate case names in {key}");
        for case in cases(&fx, key) {
            expected_accept(case);
        }
    }
}

#[test]
fn boundary_cases_match_the_rust_stdin_reader() {
    let fx = fixture();
    let mut mismatches = Vec::new();
    for case in cases(&fx, "boundary_cases") {
        let request = boundary_request(&fx, case);
        let outcome = through_host_reader(&request);
        let name = case["name"].as_str().expect("case name");
        match (&outcome, expected_accept(case)) {
            (Ok(()), true) => {}
            (Err(error), false) => eprintln!("{name}: rejected as expected: {error}"),
            (Ok(()), false) => {
                mismatches.push(format!("{name}: Rust accepted, fixture expects reject"))
            }
            (Err(error), true) => mismatches.push(format!(
                "{name}: Rust rejected ({error}), fixture expects accept"
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "fixture disagrees with Rust:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn request_cases_match_the_rust_stdin_reader() {
    let fx = fixture();
    let mut mismatches = Vec::new();
    for case in cases(&fx, "request_cases") {
        let request = base_request(&fx, case);
        let outcome = through_host_reader(&request);
        let name = case["name"].as_str().expect("case name");
        match (&outcome, expected_accept(case)) {
            (Ok(()), true) => {}
            (Err(error), false) => eprintln!("{name}: rejected as expected: {error}"),
            (Ok(()), false) => {
                mismatches.push(format!("{name}: Rust accepted, fixture expects reject"))
            }
            (Err(error), true) => mismatches.push(format!(
                "{name}: Rust rejected ({error}), fixture expects accept"
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "fixture disagrees with Rust:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn view_model_cases_match_the_rust_reference() {
    let fx = fixture();
    let mut mismatches = Vec::new();
    for case in cases(&fx, "view_model_cases") {
        let model = view_model_value(&fx, case);
        let accepted = view_model_accepted_by_rust(&model);
        let name = case["name"].as_str().expect("case name");
        if accepted != expected_accept(case) {
            mismatches.push(format!(
                "{name}: Rust reference {}, fixture expects {}",
                if accepted { "accepts" } else { "rejects" },
                case["expect"]
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "fixture disagrees with Rust:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn host_stdin_boundary_rejects_unknown_kind_and_over_limit_title() {
    // AC-010.5, Rust side: the host reader itself rejects invalid requests.
    let fx = fixture();
    let mut unknown_kind = base(&fx, "guard_failures");
    set_path(
        &mut unknown_kind,
        "presentation_kind",
        Value::String("bulk_decision".into()),
    );
    assert!(through_host_reader(&unknown_kind).is_err());

    let mut long_title = base(&fx, "guard_failures");
    set_path(
        &mut long_title,
        "title",
        Value::String(build_string(&fx, limit(&fx, "title") + 1)),
    );
    assert!(through_host_reader(&long_title).is_err());

    let mut at_limit = base(&fx, "guard_failures");
    set_path(
        &mut at_limit,
        "title",
        Value::String(build_string(&fx, limit(&fx, "title"))),
    );
    assert!(through_host_reader(&at_limit).is_ok());
}

// ---------------------------------------------------------------------------
// REQ-001 AC-001.7: the `failed_probes` wire field.
// ---------------------------------------------------------------------------

#[test]
fn count_cases_match_the_rust_stdin_reader() {
    let fx = fixture();
    let mut mismatches = Vec::new();
    for case in cases(&fx, "count_cases") {
        let request = count_request(&fx, case);
        let outcome = through_host_reader(&request);
        let name = case["name"].as_str().expect("case name");
        match (&outcome, expected_accept(case)) {
            (Ok(()), true) => {}
            (Err(error), false) => eprintln!("{name}: rejected as expected: {error}"),
            (Ok(()), false) => {
                mismatches.push(format!("{name}: Rust accepted, fixture expects reject"))
            }
            (Err(error), true) => mismatches.push(format!(
                "{name}: Rust rejected ({error}), fixture expects accept"
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "fixture disagrees with Rust:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn fixture_pins_the_failed_probes_limit_with_both_sides_of_each_count_boundary() {
    let fx = fixture();
    assert_eq!(limit(&fx, "failed_probes"), MAX_DIALOG_FAILED_PROBES);
    let counts = cases(&fx, "count_cases");
    for kind in ["guard_failures", "aggregate_decision"] {
        for (offset, expect) in [(0, "accept"), (1, "reject")] {
            assert!(
                counts.iter().any(|case| case["base"] == kind
                    && case["limit"] == "failed_probes"
                    && case["offset"] == offset
                    && case["expect"] == expect),
                "no count case for kind {kind} offset {offset}"
            );
        }
    }
    let names: Vec<&str> = counts
        .iter()
        .map(|case| case["name"].as_str().expect("case name"))
        .collect();
    let unique: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(
        names.len(),
        unique.len(),
        "duplicate case names in count_cases"
    );
    // The three string fields of an entry sit on both sides of their limit.
    let boundary = cases(&fx, "boundary_cases");
    for (field, limit_key) in [
        ("violations.0.failed_probes.0.command", "id"),
        ("violations.0.failed_probes.0.rule_name", "id"),
        ("violations.0.failed_probes.0.reason", "summary"),
    ] {
        for (offset, expect) in [(0, "accept"), (1, "reject")] {
            assert!(
                boundary.iter().any(|case| case["field"] == field
                    && case["limit"] == limit_key
                    && case["offset"] == offset
                    && case["expect"] == expect),
                "no boundary case for {field} offset {offset}"
            );
        }
    }
}

#[test]
fn the_probe_base_is_accepted_and_carries_every_failed_probe_field() {
    let fx = fixture();
    let request = base(&fx, "guard_failures_with_probes");
    assert_eq!(request["schema"], DIALOG_REQUEST_SCHEMA);
    assert_eq!(request["presentation_kind"], "guard_failures");
    through_host_reader(&request).expect("probe base accepted");
    let probe = &request["violations"][0]["failed_probes"][0];
    for key in ["rule_name", "command", "reason"] {
        assert!(probe[key].is_string(), "base probe lacks '{key}'");
    }
}

#[test]
fn an_over_limit_count_case_is_valid_except_for_its_count() {
    // The entries repeat one valid item, so only the count can make it fail.
    let fx = fixture();
    for case in cases(&fx, "count_cases") {
        let mut at_limit = case.clone();
        at_limit["offset"] = Value::from(0);
        through_host_reader(&count_request(&fx, &at_limit))
            .unwrap_or_else(|error| panic!("{}: at-limit request rejected: {error}", case["name"]));
    }
}
