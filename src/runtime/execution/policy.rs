#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionPolicy {
    pub automatic_remediations: u32,
    pub max_stalled_attempts: u32,
    pub max_fault_retries: u32,
    pub max_committed_transitions: u32,
    pub execution_ttl_ms: i64,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            automatic_remediations: 1,
            max_stalled_attempts: 1,
            max_fault_retries: 0,
            max_committed_transitions: 8,
            execution_ttl_ms: 24 * 60 * 60 * 1000,
        }
    }
}
