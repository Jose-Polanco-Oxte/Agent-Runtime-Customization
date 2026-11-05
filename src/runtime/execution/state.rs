use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{DecisionRequest, GuardExecutionKey, GuardWaiver, RuntimeDirective};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardExecutionState {
    Dormant,
    Evaluating,
    Satisfied,
    Violated,
    RemediationRequested,
    AwaitingDecision,
    AwaitingAuthorization,
    RemediationInProgress,
    Retrying,
    Stalled,
    BlockedByEnvironment,
    Suspended,
    EvaluationFault,
    Waived,
    TerminalDenied,
    Exhausted,
    Aborted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSnapshot {
    pub total_attempts: u32,
    pub stalled_attempts: u32,
    pub fault_attempts: u32,
    pub committed_transitions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardExecutionRecord {
    pub execution_id: String,
    pub key: GuardExecutionKey,
    pub state: GuardExecutionState,
    pub attempts: AttemptSnapshot,
    pub last_evidence_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_decision: Option<DecisionRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver: Option<GuardWaiver>,
    pub processed_invocations: BTreeMap<String, RuntimeDirective>,
    pub revision: u64,
    pub updated_at_unix_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

impl GuardExecutionRecord {
    pub fn new(execution_id: String, key: GuardExecutionKey, now_unix_ms: i64) -> Self {
        Self {
            execution_id,
            key,
            state: GuardExecutionState::Dormant,
            attempts: AttemptSnapshot::default(),
            last_evidence_fingerprint: None,
            pending_decision: None,
            waiver: None,
            processed_invocations: BTreeMap::new(),
            revision: 0,
            updated_at_unix_ms: now_unix_ms,
            requested_at: None,
            completed_at: None,
        }
    }

    pub fn mark_requested(&mut self, timestamp: impl Into<String>) {
        self.requested_at = Some(timestamp.into());
        self.completed_at = None;
    }

    pub fn mark_completed(&mut self, timestamp: impl Into<String>) {
        let ts = timestamp.into();
        if self.requested_at.is_none() {
            self.requested_at = Some(ts.clone());
        }
        self.completed_at = Some(ts);
    }
}

pub fn unix_ms_to_iso8601(ms: i64) -> String {
    let secs = if ms >= 0 { (ms / 1000) as u64 } else { 0 };
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    format!("{}T{:02}:{:02}:{:02}Z", format_days_to_date(days), h, m, s)
}

fn format_days_to_date(mut days: u64) -> String {
    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days < days_in_year {
            let month_days = if is_leap {
                [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            } else {
                [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            };
            for (idx, &md) in month_days.iter().enumerate() {
                if days < md {
                    let month = idx + 1;
                    let day = days + 1;
                    return format!("{:04}-{:02}-{:02}", year, month, day);
                }
                days -= md;
            }
            return format!("{:04}-12-31", year);
        }
        days -= days_in_year;
        year += 1;
    }
}
