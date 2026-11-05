use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

const TOOL_NAME: &str = "arc_request_decision";

use std::collections::VecDeque;

pub fn serve<R: BufRead, W: Write>(mut reader: R, mut writer: W) -> Result<()> {
    let mut elicitation_supported = false;
    let mut next_server_request_id = 1_u64;
    let mut line = String::new();
    let mut incoming_queue: VecDeque<Value> = VecDeque::new();

    loop {
        let message: Value = if let Some(msg) = incoming_queue.pop_front() {
            msg
        } else {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok(());
            }
            serde_json::from_str(line.trim_end())
                .context("invalid JSON-RPC message received by Arc MCP server")?
        };

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            write_message(
                &mut writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "unexpected JSON-RPC response; no request is pending"
                    }
                }),
            )?;
            continue;
        };

        match method {
            "initialize" => {
                elicitation_supported = message
                    .pointer("/params/capabilities/elicitation")
                    .is_some();
                let protocol_version = message
                    .pointer("/params/protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2025-11-25");
                respond(
                    &mut writer,
                    &message,
                    json!({
                        "protocolVersion": protocol_version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "arc-decision-dialog-poc",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }),
                )?;
            }
            "notifications/initialized" => {}
            "ping" => respond(&mut writer, &message, json!({}))?,
            "tools/list" => respond(
                &mut writer,
                &message,
                json!({
                    "tools": [{
                        "name": TOOL_NAME,
                        "title": "Request an Arc policy decision",
                        "description": "Pause the active agent turn and ask the user to allow or deny an Arc policy event.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "event_type": {
                                    "type": "string",
                                    "description": "Arc/provider event that triggered the decision."
                                },
                                "message": {
                                    "type": "string",
                                    "description": "Human-readable explanation shown in the dialog."
                                },
                                "guard_id": {
                                    "type": "string",
                                    "description": "Optional Arc guard identifier."
                                }
                            },
                            "required": ["event_type", "message"],
                            "additionalProperties": false
                        }
                    }]
                }),
            )?,
            "tools/call" => {
                let request_id = message.get("id").cloned().unwrap_or(Value::Null);
                let name = message.pointer("/params/name").and_then(Value::as_str);
                if name != Some(TOOL_NAME) {
                    write_message(
                        &mut writer,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {"code": -32601, "message": "unknown Arc MCP tool"}
                        }),
                    )?;
                    continue;
                }
                if !elicitation_supported {
                    write_tool_error(
                        &mut writer,
                        request_id,
                        "The MCP client did not advertise form elicitation support.",
                    )?;
                    continue;
                }
                let event_type = message
                    .pointer("/params/arguments/event_type")
                    .and_then(Value::as_str)
                    .unwrap_or("agent_event");
                let prompt = message
                    .pointer("/params/arguments/message")
                    .and_then(Value::as_str)
                    .unwrap_or("Arc requires a decision before continuing.");
                let guard_id = message
                    .pointer("/params/arguments/guard_id")
                    .and_then(Value::as_str);

                let elicitation_id = json!(format!("arc-elicitation-{next_server_request_id}"));
                next_server_request_id += 1;
                write_message(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": elicitation_id,
                        "method": "elicitation/create",
                        "params": {
                            "mode": "form",
                            "message": prompt,
                            "requestedSchema": {
                                "type": "object",
                                "properties": {
                                    "decision": {
                                        "type": "string",
                                        "title": "Decision",
                                        "description": format!("Arc event: {event_type}"),
                                        "oneOf": [
                                            {"const": "allow", "title": "Allow"},
                                            {"const": "deny", "title": "Deny"}
                                        ]
                                    },
                                    "note": {
                                        "type": "string",
                                        "title": "Reason (optional)",
                                        "maxLength": 500
                                    }
                                },
                                "required": ["decision"]
                            }
                        }
                    }),
                )?;

                let elicitation_result = wait_for_response(
                    &mut reader,
                    &mut writer,
                    &elicitation_id,
                    &mut incoming_queue,
                )?;
                let action = elicitation_result
                    .pointer("/result/action")
                    .and_then(Value::as_str)
                    .unwrap_or("transport_failed");
                let submitted_decision = elicitation_result
                    .pointer("/result/content/decision")
                    .and_then(Value::as_str);
                let (status, decision, unresolved_reason) = match (action, submitted_decision) {
                    ("accept", Some(decision @ ("allow" | "deny"))) => {
                        ("resolved", Some(decision), None)
                    }
                    ("accept", _) => ("unresolved", None, Some("transport_failed")),
                    // `cancel` is the MCP transport's standardized form action,
                    // not an Arc decision. Normalize it without creating Deny.
                    ("cancel", _) | ("decline", _) => ("unresolved", None, Some("closed")),
                    _ => ("unresolved", None, Some("transport_failed")),
                };
                let note = elicitation_result
                    .pointer("/result/content/note")
                    .and_then(Value::as_str);
                let result = json!({
                    "status": status,
                    "decision": decision,
                    "unresolved_reason": unresolved_reason,
                    "event_type": event_type,
                    "guard_id": guard_id,
                    "note": note
                });
                write_message(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string(&result)?
                            }],
                            "structuredContent": result,
                            "isError": false
                        }
                    }),
                )?;
            }
            _ if message.get("id").is_some() => {
                write_message(
                    &mut writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32601, "message": "method not found"}
                    }),
                )?;
            }
            _ => {}
        }
    }
}

fn wait_for_response<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    expected_id: &Value,
    incoming_queue: &mut VecDeque<Value>,
) -> Result<Value> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            bail!("MCP client disconnected while Arc was waiting for user input");
        }
        let message: Value = serde_json::from_str(line.trim_end())
            .context("invalid JSON-RPC message while waiting for elicitation response")?;

        // 1. Expected Response matching the exact elicitation request ID (M9)
        if message.get("id") == Some(expected_id) && message.get("method").is_none() {
            return Ok(message);
        }

        // 2. Interleaved Ping request can be handled immediately
        if message.get("method").and_then(Value::as_str) == Some("ping") {
            respond(writer, &message, json!({}))?;
        } else if message.get("method").is_some() {
            // 3. Interleaved Request or Notification: buffer in queue for subsequent dispatch (M9)
            incoming_queue.push_back(message);
        } else {
            // 4. Orphaned response is explicitly rejected instead of being silently dropped.
            write_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": message.get("id").cloned().unwrap_or(Value::Null),
                    "error": {
                        "code": -32001,
                        "message": "orphaned JSON-RPC response"
                    }
                }),
            )?;
        }
    }
}

fn respond<W: Write>(writer: &mut W, request: &Value, result: Value) -> Result<()> {
    write_message(
        writer,
        &json!({"jsonrpc": "2.0", "id": request["id"], "result": result}),
    )
}

fn write_tool_error<W: Write>(writer: &mut W, id: Value, message: &str) -> Result<()> {
    write_message(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": message}],
                "isError": true
            }
        }),
    )
}

fn write_message<W: Write>(writer: &mut W, message: &Value) -> Result<()> {
    serde_json::to_writer(&mut *writer, message)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn tool_call_blocks_on_elicitation_and_returns_the_decision() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"elicitation": {"form": {}}},
                    "clientInfo": {"name": "test", "version": "1"}
                }
            }),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": TOOL_NAME, "arguments": {
                    "event_type": "PreToolUse", "message": "Run deployment?", "guard_id": "deploy"
                }}
            }),
            json!({
                "jsonrpc": "2.0", "id": "arc-elicitation-1",
                "result": {"action": "accept", "content": {"decision": "allow", "note": "approved"}}
            }),
        ];
        let wire = input
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();
        serve(BufReader::new(Cursor::new(wire)), &mut output).unwrap();
        let messages: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(messages[1]["method"], "elicitation/create");
        assert_eq!(messages[1]["params"]["mode"], "form");
        assert_eq!(messages[2]["id"], 2);
        assert_eq!(
            messages[2]["result"]["structuredContent"]["decision"],
            "allow"
        );
    }

    #[test]
    fn declines_when_client_does_not_support_elicitation() {
        let wire = [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}
            }}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": TOOL_NAME, "arguments": {"event_type": "Stop", "message": "Continue?"}
            }}),
        ]
        .iter()
        .map(|value| serde_json::to_string(value).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
            + "\n";
        let mut output = Vec::new();
        serve(BufReader::new(Cursor::new(wire)), &mut output).unwrap();
        let last: Value =
            serde_json::from_str(String::from_utf8(output).unwrap().lines().last().unwrap())
                .unwrap();
        assert_eq!(last["result"]["isError"], true);
    }

    #[test]
    fn transport_cancellation_is_unresolved_and_never_a_user_denial() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"elicitation": {"form": {}}}
                }
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": TOOL_NAME, "arguments": {
                    "event_type": "Stop", "message": "Attempt remediation?"
                }}
            }),
            json!({
                "jsonrpc": "2.0", "id": "arc-elicitation-1",
                "result": {"action": "cancel"}
            }),
        ];
        let wire = input
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();
        serve(BufReader::new(Cursor::new(wire)), &mut output).unwrap();
        let response: Value = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .find(|message: &Value| message["id"] == 2)
            .unwrap();

        let result = &response["result"]["structuredContent"];
        assert_eq!(result["status"], "unresolved");
        assert!(result["decision"].is_null());
        assert_eq!(result["unresolved_reason"], "closed");
    }

    #[test]
    fn rejects_orphaned_responses_explicitly() {
        let wire = r#"{"jsonrpc":"2.0","id":77,"result":{"ok":true}}
"#;
        let mut output = Vec::new();
        serve(BufReader::new(Cursor::new(wire)), &mut output).unwrap();
        let response: Value =
            serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(response["id"], 77);
        assert_eq!(response["error"]["code"], -32001);
    }
}
