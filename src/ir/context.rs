use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceContext {
    pub workdir: PathBuf,
    pub instructions_path: Option<PathBuf>,
    pub instructions_content: Option<String>,
    pub roles: BTreeMap<String, BoundRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundRole {
    pub description: String,
    pub src_path: Option<PathBuf>,
    pub content: Option<String>,
}
