use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationSnapshot {
    Satisfied,
    Violated { feedback: Option<String> },
    Fault { message: String },
}

impl EvaluationSnapshot {
    pub fn fingerprint(&self, guard_id: &str) -> String {
        let canonical = match self {
            Self::Satisfied => format!("{guard_id}\0satisfied"),
            Self::Violated { feedback } => {
                format!(
                    "{guard_id}\0violated\0{}",
                    feedback.as_deref().unwrap_or("")
                )
            }
            Self::Fault { message } => format!("{guard_id}\0fault\0{message}"),
        };
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    pub fn message(&self) -> Option<String> {
        match self {
            Self::Satisfied => None,
            Self::Violated { feedback } => feedback.clone(),
            Self::Fault { message } => Some(message.clone()),
        }
    }
}
