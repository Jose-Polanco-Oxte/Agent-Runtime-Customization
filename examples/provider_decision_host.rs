use anyhow::{Context, Result, bail};
use arc::decision_ui::{
    ARC_EMBEDDED_UI_TRANSPORT_LABEL, DIALOG_RESPONSE_SCHEMA, DialogResponse, PortableDecision,
    read_dialog_request, write_dialog_response,
};
use std::io;

const FIXTURE_DECISION_ENV: &str = "ARC_PROVIDER_E2E_DECISION";

fn main() -> Result<()> {
    let request = read_dialog_request(io::stdin().lock())
        .context("provider E2E fixture rejected the dialog request")?;
    let configured = std::env::var(FIXTURE_DECISION_ENV)
        .with_context(|| format!("{FIXTURE_DECISION_ENV} is required"))?;
    let decision = match configured.trim().to_ascii_lowercase().as_str() {
        "allow" => PortableDecision::Allow,
        "deny" => PortableDecision::Deny,
        unsupported => bail!("{FIXTURE_DECISION_ENV} must be allow or deny, got {unsupported:?}"),
    };
    let response = DialogResponse {
        schema: DIALOG_RESPONSE_SCHEMA.to_owned(),
        request_id: request.request_id,
        bundle_fingerprint: request.bundle_fingerprint,
        decision,
        transport: ARC_EMBEDDED_UI_TRANSPORT_LABEL.to_owned(),
        theme: "fixture".to_owned(),
        message: Some("Arc provider E2E scripted sidecar response".to_owned()),
    };
    write_dialog_response(io::stdout().lock(), &response)
        .context("provider E2E fixture failed writing its terminal response")
}
