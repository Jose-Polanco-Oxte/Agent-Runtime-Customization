use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionChoice {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionActor {
    User,
    Administrator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub decision_id: String,
    pub execution_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_invocation_id: Option<String>,
    pub choices: Vec<DecisionChoice>,
    pub required_actor: DecisionActor,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionIntegrity {
    pub transport: String,
    pub native_interaction_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub decision_id: String,
    pub execution_id: String,
    pub selected_choice: DecisionChoice,
    pub actor: DecisionActor,
    pub provider: String,
    pub received_at_unix_ms: i64,
    pub integrity: DecisionIntegrity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardWaiver {
    pub decision_id: String,
    pub execution_id: String,
    pub evidence_fingerprint: String,
    pub expires_at_unix_ms: i64,
    pub uses_remaining: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_json(choice: &str) -> String {
        format!(
            r#"{{
                "decision_id": "decision-1",
                "execution_id": "execution-1",
                "owner_invocation_id": "invocation-1",
                "choices": ["{choice}"],
                "required_actor": "user",
                "expires_at_unix_ms": 4102444800000
            }}"#
        )
    }

    #[test]
    fn legacy_decision_choice_aliases_are_rejected_and_wire_is_canonical() {
        assert!(serde_json::from_str::<DecisionRequest>(&request_json("remediate")).is_err());
        assert!(serde_json::from_str::<DecisionRequest>(&request_json("finish_anyway")).is_err());
        let allow: DecisionRequest =
            serde_json::from_str(&request_json("allow")).expect("canonical allow");
        assert_eq!(allow.choices, vec![DecisionChoice::Allow]);
        assert_eq!(
            serde_json::to_value(allow.choices[0]).expect("serialize allow"),
            serde_json::json!("allow")
        );
        let deny: DecisionRequest =
            serde_json::from_str(&request_json("deny")).expect("canonical deny");
        assert_eq!(deny.choices, vec![DecisionChoice::Deny]);
    }
}
