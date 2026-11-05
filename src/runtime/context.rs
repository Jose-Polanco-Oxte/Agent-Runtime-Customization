// src/runtime/context.rs

use crate::target::ProviderTarget;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Telemetry record of a command executed by the agent during the session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandTelemetry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub status: String,
}

/// Compact, high-signal summary of a session's history for compliance auditing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionContext {
    /// Full, sanitized user request stating the goal of the session.
    pub user_intent: String,
    /// List of file paths created or edited during the session.
    pub files_created_or_modified: Vec<String>,
    /// Summary of commands and test suites run with status.
    pub test_commands_run: Vec<CommandTelemetry>,
    /// Total number of tool invocations performed.
    pub tools_executed_count: usize,
    /// The latest/final message delivered by the agent to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_final_response: Option<String>,
}

#[derive(Debug, Error)]
pub enum TranscriptResolutionError {
    #[error("invalid Codex session id '{session_id}'")]
    InvalidSessionId { session_id: String },
    #[error("provider transcript path must be an absolute file path: {path:?}")]
    InvalidProviderPath { path: PathBuf },
    #[error(
        "transcript path contains a symbolic link, junction, reparse point, or parent traversal: {path:?}"
    )]
    IndirectedPath { path: PathBuf },
    #[error("transcript path is outside every allowed Codex sessions root: {path:?}")]
    OutsideAllowedRoots { path: PathBuf },
    #[error("failed to {operation} transcript at {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("transcript is not a regular file: {path:?}")]
    NotRegularFile { path: PathBuf },
    #[error("opened transcript identity changed: requested {expected:?}, opened {opened:?}")]
    HandleIdentityMismatch { expected: PathBuf, opened: PathBuf },
    #[error("opened transcript file identity changed at {path:?}")]
    FileIdentityMismatch { path: PathBuf },
    #[error("malformed JSON on line {line} of transcript {path:?}: {source}")]
    MalformedJsonLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("malformed structured session metadata on line {line} of transcript {path:?}")]
    MalformedSessionMetadata { path: PathBuf, line: usize },
    #[error("transcript has no structured session metadata: {path:?}")]
    MissingSessionMetadata { path: PathBuf },
    #[error("transcript has {count} structured session metadata records: {path:?}")]
    MultipleSessionMetadata { path: PathBuf, count: usize },
    #[error("transcript session mismatch: expected '{expected}', found '{actual}' in {path:?}")]
    SessionMismatch {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("found {count} Codex rollouts for session '{session_id}'")]
    AmbiguousMatches { session_id: String, count: usize },
    #[error("post-open transcript test hook failed for {path:?}: {source}")]
    PostOpenHook {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A Codex transcript whose path, open-file identity, structured session
/// metadata, and extracted context all refer to the same file handle.
#[derive(Debug)]
pub struct OpenedTranscript {
    canonical_path: PathBuf,
    validated_handle: File,
    session_identity: String,
    context: SessionContext,
}

impl OpenedTranscript {
    pub fn open_codex(
        path: &Path,
        expected_session_id: &str,
    ) -> Result<Self, TranscriptResolutionError> {
        Self::open_with_allowed_roots(path, expected_session_id, &codex_allowed_session_roots())
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn validated_handle(&self) -> &File {
        &self.validated_handle
    }

    pub fn session_identity(&self) -> &str {
        &self.session_identity
    }

    pub fn into_context(self) -> SessionContext {
        self.context
    }

    pub(crate) fn open_with_allowed_roots(
        path: &Path,
        expected_session_id: &str,
        allowed_roots: &[PathBuf],
    ) -> Result<Self, TranscriptResolutionError> {
        Self::open_with_allowed_roots_and_hook(path, expected_session_id, allowed_roots, || Ok(()))
    }

    fn open_with_allowed_roots_and_hook<F>(
        path: &Path,
        expected_session_id: &str,
        allowed_roots: &[PathBuf],
        after_open: F,
    ) -> Result<Self, TranscriptResolutionError>
    where
        F: FnOnce() -> std::io::Result<()>,
    {
        validate_codex_session_id(expected_session_id)?;
        if !path.is_absolute()
            || path.as_os_str().is_empty()
            || path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(TranscriptResolutionError::InvalidProviderPath {
                path: path.to_path_buf(),
            });
        }
        if !path_has_no_indirected_ancestor(path) {
            return Err(TranscriptResolutionError::IndirectedPath {
                path: path.to_path_buf(),
            });
        }

        let expected_file_metadata =
            std::fs::symlink_metadata(path).map_err(|source| TranscriptResolutionError::Io {
                operation: "inspect transcript entry",
                path: path.to_path_buf(),
                source,
            })?;
        if !expected_file_metadata.is_file() || expected_file_metadata.file_type().is_symlink() {
            return Err(TranscriptResolutionError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }

        let canonical_roots = canonical_allowed_roots(allowed_roots);
        let canonical_path = crate::manifest::loader::normalize_handle_path(
            path.canonicalize()
                .map_err(|source| TranscriptResolutionError::Io {
                    operation: "canonicalize",
                    path: path.to_path_buf(),
                    source,
                })?,
        );
        if !canonical_roots
            .iter()
            .any(|root| canonical_path.starts_with(root))
        {
            return Err(TranscriptResolutionError::OutsideAllowedRoots {
                path: canonical_path,
            });
        }

        let mut file = open_transcript_without_following_leaf(path).map_err(|source| {
            TranscriptResolutionError::Io {
                operation: "open",
                path: path.to_path_buf(),
                source,
            }
        })?;
        let metadata = file
            .metadata()
            .map_err(|source| TranscriptResolutionError::Io {
                operation: "inspect opened handle",
                path: path.to_path_buf(),
                source,
            })?;
        if !metadata.is_file() {
            return Err(TranscriptResolutionError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if opened_metadata_is_indirected(&metadata) {
            return Err(TranscriptResolutionError::IndirectedPath {
                path: path.to_path_buf(),
            });
        }
        #[cfg(unix)]
        if !same_unix_file_identity(&expected_file_metadata, &metadata) {
            return Err(TranscriptResolutionError::FileIdentityMismatch {
                path: path.to_path_buf(),
            });
        }

        let opened_path = crate::manifest::loader::normalize_handle_path(
            crate::manifest::loader::get_handle_final_path(&file).map_err(|error| {
                TranscriptResolutionError::Io {
                    operation: "resolve opened handle identity",
                    path: path.to_path_buf(),
                    source: std::io::Error::other(error.to_string()),
                }
            })?,
        );
        if opened_path != canonical_path
            || !canonical_roots
                .iter()
                .any(|root| opened_path.starts_with(root))
        {
            return Err(TranscriptResolutionError::HandleIdentityMismatch {
                expected: canonical_path,
                opened: opened_path,
            });
        }

        after_open().map_err(|source| TranscriptResolutionError::PostOpenHook {
            path: path.to_path_buf(),
            source,
        })?;

        let session_identity =
            read_structured_session_identity(&mut file, expected_session_id, &opened_path)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| TranscriptResolutionError::Io {
                operation: "rewind opened handle",
                path: opened_path.clone(),
                source,
            })?;
        let context = SessionContextExtractor::extract_from_reader(BufReader::new(&mut file));

        Ok(Self {
            canonical_path: opened_path,
            validated_handle: file,
            session_identity,
            context,
        })
    }
}

fn validate_codex_session_id(session_id: &str) -> Result<(), TranscriptResolutionError> {
    if session_id.is_empty()
        || session_id.trim() != session_id
        || !session_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(TranscriptResolutionError::InvalidSessionId {
            session_id: session_id.to_string(),
        });
    }
    Ok(())
}

fn canonical_allowed_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut canonical = BTreeSet::new();
    for root in roots {
        if !root.is_absolute() || !path_has_no_indirected_ancestor(root) {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(root) else {
            continue;
        };
        if !metadata.is_dir() || opened_metadata_is_indirected(&metadata) {
            continue;
        }
        if let Ok(path) = root.canonicalize() {
            canonical.insert(crate::manifest::loader::normalize_handle_path(path));
        }
    }
    canonical.into_iter().collect()
}

fn codex_allowed_session_roots() -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    if let Some(codex_home) = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        roots.insert(codex_home.join("sessions"));
    }
    for variable in ["USERPROFILE", "HOME"] {
        if let Some(home) = std::env::var_os(variable)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
        {
            roots.insert(home.join(".codex").join("sessions"));
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.insert(current_dir.join(".codex").join("sessions"));
    }
    roots.into_iter().collect()
}

fn open_transcript_without_following_leaf(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn opened_metadata_is_indirected(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(unix)]
fn same_unix_file_identity(expected: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    expected.dev() == opened.dev() && expected.ino() == opened.ino()
}

fn structured_session_id(value: &serde_json::Value) -> Result<Option<&str>, ()> {
    match value.get("type").and_then(serde_json::Value::as_str) {
        Some("session_meta") => value
            .pointer("/payload/id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(Some)
            .ok_or(()),
        Some("session_metadata") => value
            .get("session_id")
            .or_else(|| value.pointer("/payload/session_id"))
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(Some)
            .ok_or(()),
        _ => Ok(None),
    }
}

fn read_structured_session_identity(
    file: &mut File,
    expected_session_id: &str,
    canonical_path: &Path,
) -> Result<String, TranscriptResolutionError> {
    let mut identities = Vec::new();
    for (line_index, line_result) in BufReader::new(file).lines().enumerate() {
        let line_number = line_index + 1;
        let line = line_result.map_err(|source| TranscriptResolutionError::Io {
            operation: "read opened handle",
            path: canonical_path.to_path_buf(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<serde_json::Value>(&line).map_err(|source| {
            TranscriptResolutionError::MalformedJsonLine {
                path: canonical_path.to_path_buf(),
                line: line_number,
                source,
            }
        })?;
        match structured_session_id(&value) {
            Ok(Some(identity)) => identities.push(identity.to_string()),
            Ok(None) => {}
            Err(()) => {
                return Err(TranscriptResolutionError::MalformedSessionMetadata {
                    path: canonical_path.to_path_buf(),
                    line: line_number,
                });
            }
        }
    }

    if identities.is_empty() {
        return Err(TranscriptResolutionError::MissingSessionMetadata {
            path: canonical_path.to_path_buf(),
        });
    }
    if identities.len() != 1 {
        return Err(TranscriptResolutionError::MultipleSessionMetadata {
            path: canonical_path.to_path_buf(),
            count: identities.len(),
        });
    }
    let Some(actual) = identities.pop() else {
        return Err(TranscriptResolutionError::MissingSessionMetadata {
            path: canonical_path.to_path_buf(),
        });
    };
    if actual != expected_session_id {
        return Err(TranscriptResolutionError::SessionMismatch {
            expected: expected_session_id.to_string(),
            actual,
            path: canonical_path.to_path_buf(),
        });
    }
    Ok(actual)
}

pub struct SessionContextExtractor;

impl SessionContextExtractor {
    pub fn extract_from_session_id_with_provider_path(
        session_id: &str,
        provider: Option<ProviderTarget>,
        provider_transcript_path: Option<&Path>,
    ) -> SessionContext {
        match provider {
            Some(ProviderTarget::Gemini) => provider_transcript_path.map_or_else(
                || Self::extract_from_agy_roots(agy_session_roots(session_id)),
                |path| Self::extract_from_supplied_agy_path(session_id, path),
            ),
            Some(ProviderTarget::Codex) | None => {
                let allowed_roots = codex_allowed_session_roots();
                Self::extract_from_codex_session_with_path_and_roots(
                    session_id,
                    provider_transcript_path,
                    &allowed_roots,
                )
            }
            Some(ProviderTarget::Claude | ProviderTarget::OpenCode) => SessionContext::default(),
        }
    }

    fn extract_from_supplied_agy_path(session_id: &str, path: &Path) -> SessionContext {
        Self::extract_from_supplied_agy_path_with_roots(path, agy_session_roots(session_id))
    }

    fn extract_from_supplied_agy_path_with_roots(
        path: &Path,
        roots: impl IntoIterator<Item = PathBuf>,
    ) -> SessionContext {
        let Ok(supplied) = path.canonicalize() else {
            return SessionContext::default();
        };
        let supplied = crate::manifest::loader::normalize_handle_path(supplied);
        let authorized = roots
            .into_iter()
            .filter_map(|root| root.canonicalize().ok())
            .map(crate::manifest::loader::normalize_handle_path)
            .any(|root| supplied.starts_with(root));
        if !authorized {
            return SessionContext::default();
        }
        Self::extract_from_file(path).unwrap_or_default()
    }

    fn extract_from_agy_roots(roots: impl IntoIterator<Item = PathBuf>) -> SessionContext {
        let canonical_roots = roots
            .into_iter()
            .filter_map(|root| root.canonicalize().ok())
            .map(crate::manifest::loader::normalize_handle_path)
            .collect::<BTreeSet<_>>();
        let mut matches = canonical_roots
            .into_iter()
            .filter_map(|root| Self::extract_from_agy_root(&root))
            .collect::<Vec<_>>();

        if matches.len() == 1 {
            matches.remove(0)
        } else {
            SessionContext::default()
        }
    }

    fn extract_from_agy_root(root: &Path) -> Option<SessionContext> {
        // Antigravity intentionally maintains compact and complete views of
        // the same event stream. They are alternatives, not independent
        // session matches; prefer the complete historical record and fall
        // back only when it is unavailable or has no usable context yet.
        let candidates = [
            root.join(".system_generated")
                .join("logs")
                .join("transcript_full.jsonl"),
            root.join(".system_generated")
                .join("logs")
                .join("transcript.jsonl"),
            root.join("transcript.jsonl"),
        ];
        candidates.into_iter().find_map(|path| {
            Self::extract_from_file(&path).ok().filter(|context| {
                !context.user_intent.is_empty() || context.tools_executed_count > 0
            })
        })
    }

    fn extract_from_codex_session_with_path_and_roots(
        session_id: &str,
        provider_transcript_path: Option<&Path>,
        codex_session_roots: &[PathBuf],
    ) -> SessionContext {
        if let Some(path) = provider_transcript_path {
            return OpenedTranscript::open_with_allowed_roots(
                path,
                session_id,
                codex_session_roots,
            )
            .map(OpenedTranscript::into_context)
            .unwrap_or_default();
        }

        let canonical_roots = canonical_allowed_roots(codex_session_roots);
        let mut codex_match = None;
        for root in canonical_roots {
            match find_opened_codex_rollout_in_sessions_dir(&root, session_id) {
                Ok(Some(opened)) => {
                    if codex_match.is_some() {
                        return SessionContext::default();
                    }
                    codex_match = Some(opened);
                }
                Ok(None) => {}
                Err(TranscriptResolutionError::AmbiguousMatches { .. }) => {
                    return SessionContext::default();
                }
                Err(_) => {}
            }
        }
        if let Some(opened) = codex_match {
            return opened.into_context();
        }
        SessionContext::default()
    }

    /// Extracts session context from a transcript log file.
    pub fn extract_from_file(path: &Path) -> std::io::Result<SessionContext> {
        if !path_has_no_indirected_ancestor(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing transcript path with a symlink or reparse ancestor: {path:?}"),
            ));
        }
        let file = File::open(path)?;
        let opened_path = crate::manifest::loader::normalize_handle_path(
            crate::manifest::loader::get_handle_final_path(&file)
                .map_err(|error| std::io::Error::other(error.to_string()))?,
        );
        let expected_path = crate::manifest::loader::normalize_handle_path(path.canonicalize()?);
        if opened_path != expected_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "transcript handle resolved to {opened_path:?}, expected {expected_path:?}"
                ),
            ));
        }
        let reader = BufReader::new(file);
        Ok(Self::extract_from_reader(reader))
    }

    /// Extracts session context from an arbitrary JSON Lines reader.
    pub fn extract_from_reader<R: BufRead>(reader: R) -> SessionContext {
        let mut user_intent = String::new();
        let mut files_modified = BTreeSet::new();
        let mut commands_run: Vec<CommandTelemetry> = Vec::new();
        let mut tools_count = 0;
        let mut last_agent_message = None;

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let entry: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let response_item = (entry.get("type").and_then(|value| value.as_str())
                == Some("response_item"))
            .then(|| entry.get("payload"))
            .flatten();

            // 1. Extract and sanitize initial user intent
            if user_intent.is_empty() {
                if let Some(payload) = response_item.filter(|payload| {
                    payload.get("type").and_then(|value| value.as_str()) == Some("message")
                        && payload.get("role").and_then(|value| value.as_str()) == Some("user")
                }) {
                    let content = extract_message_text(payload, "input_text");
                    let sanitized = sanitize_user_prompt(&content);
                    if !sanitized.is_empty() {
                        user_intent = sanitized;
                    }
                }
                if let Some(step_type) = entry.get("type").and_then(|t| t.as_str()) {
                    if step_type == "USER_INPUT" {
                        if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
                            let sanitized = sanitize_user_prompt(content);
                            if !sanitized.is_empty() {
                                user_intent = sanitized;
                            }
                        }
                    }
                }
            }

            // 2. Extract tool activity telemetry (requests)
            if let Some(tool_calls) = entry.get("tool_calls").and_then(|tc| tc.as_array()) {
                for tc in tool_calls {
                    tools_count += 1;
                    if let Some(tool_name) = tc.get("name").and_then(|n| n.as_str()) {
                        let args = tc.get("args");
                        let call_id = tc
                            .get("id")
                            .or_else(|| tc.get("call_id"))
                            .or_else(|| tc.get("tool_call_id"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        match tool_name {
                            "write_to_file" | "replace_file_content" | "create_file" => {
                                if let Some(path) = extract_file_target(args) {
                                    files_modified.insert(path);
                                }
                            }
                            "run_command" | "execute_command" | "terminal" => {
                                if let Some(cmd) = extract_command_str(args) {
                                    commands_run.push(CommandTelemetry {
                                        call_id,
                                        command: cmd,
                                        exit_code: None,
                                        status: "requested".to_string(),
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // 3. Correlate tool responses / execution outcomes (M3)
            let step_type = entry.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let is_tool_response = step_type == "TOOL_RESPONSE"
                || step_type == "tool_response"
                || step_type == "TOOL_RESULT"
                || step_type == "tool_result"
                || (entry.get("tool_call_id").is_some() && step_type != "PLANNER_RESPONSE");

            if is_tool_response {
                let res_call_id = entry
                    .get("tool_call_id")
                    .or_else(|| entry.get("call_id"))
                    .or_else(|| entry.get("id"))
                    .and_then(|v| v.as_str());

                // Find matching requested command
                let target_cmd = res_call_id.and_then(|cid| {
                    commands_run
                        .iter_mut()
                        .find(|c| c.call_id.as_deref() == Some(cid))
                });

                if let Some(cmd) = target_cmd {
                    let direct_code = entry
                        .get("exit_code")
                        .or_else(|| entry.pointer("/result/exit_code"))
                        .or_else(|| entry.pointer("/result/code"))
                        .and_then(|v| v.as_i64())
                        .map(|n| n as i32);

                    let content_code = entry
                        .get("content")
                        .and_then(|c| c.as_str())
                        .and_then(parse_exit_code_from_content);

                    let parsed_exit_code = direct_code.or(content_code);
                    if let Some(code) = parsed_exit_code {
                        cmd.status = "completed".to_string();
                        cmd.exit_code = Some(code);
                    } else {
                        // A textual status is not a real process exit code. Keep
                        // the correlation visible without inventing success/failure.
                        cmd.status = "unknown".to_string();
                        cmd.exit_code = None;
                    }
                }
            }

            // 4. Extract final agent response
            if let Some(payload) = response_item.filter(|payload| {
                payload.get("type").and_then(|value| value.as_str()) == Some("message")
                    && payload.get("role").and_then(|value| value.as_str()) == Some("assistant")
            }) {
                let content = extract_message_text(payload, "output_text");
                let cleaned = content.trim();
                if !cleaned.is_empty() {
                    last_agent_message = Some(truncate_str(cleaned, 800));
                }
            }
            if let Some(source) = entry.get("source").and_then(|s| s.as_str()) {
                if source == "MODEL" {
                    if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
                        let cleaned = content.trim();
                        // Ignore checkpoint markers and raw tool wrappers
                        if !cleaned.is_empty()
                            && !cleaned.starts_with("Created At:")
                            && !cleaned.starts_with("{\"File\":")
                            && !cleaned.starts_with("{{ CHECKPOINT")
                        {
                            last_agent_message = Some(truncate_str(cleaned, 800));
                        }
                    }
                }
            }
        }

        SessionContext {
            user_intent: truncate_str(&user_intent, 400),
            files_created_or_modified: files_modified.into_iter().take(10).collect(),
            test_commands_run: commands_run,
            tools_executed_count: tools_count,
            agent_final_response: last_agent_message.map(|msg| truncate_str(&msg, 400)),
        }
    }
}

fn extract_message_text(payload: &serde_json::Value, expected_type: &str) -> String {
    payload
        .get("content")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("type").and_then(serde_json::Value::as_str) == Some(expected_type))
        .filter_map(|item| item.get("text").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_exit_code_from_content(content: &str) -> Option<i32> {
    for line in content.lines() {
        let lower = line.to_lowercase();
        if let Some(pos) = lower.find("exited with code") {
            let rem = line[pos + "exited with code".len()..].trim();
            if let Some(num_str) = rem.split_whitespace().next() {
                let clean_num: String = num_str
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect();
                if let Ok(code) = clean_num.parse::<i32>() {
                    return Some(code);
                }
            }
        }
        if let Some(pos) = lower.find("exit code") {
            let rem = line[pos + "exit code".len()..]
                .trim()
                .trim_start_matches(':')
                .trim();
            if let Some(num_str) = rem.split_whitespace().next() {
                let clean_num: String = num_str
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect();
                if let Ok(code) = clean_num.parse::<i32>() {
                    return Some(code);
                }
            }
        }
    }
    None
}

/// Sanitizes user prompt by extracting the core request and removing IDE boilerplate.
pub fn sanitize_user_prompt(raw: &str) -> String {
    let mut text = raw.trim().to_string();

    // 1. Extract content inside <USER_REQUEST> if present
    if let Some(start) = text.find("<USER_REQUEST>") {
        let after_start = &text[start + "<USER_REQUEST>".len()..];
        if let Some(end) = after_start.find("</USER_REQUEST>") {
            text = after_start[..end].trim().to_string();
        } else {
            text = after_start.trim().to_string();
        }
    }

    // 2. Strip metadata tags if still present
    text = strip_tag_block(&text, "<ADDITIONAL_METADATA>", "</ADDITIONAL_METADATA>");
    text = strip_tag_block(&text, "<USER_SETTINGS_CHANGE>", "</USER_SETTINGS_CHANGE>");
    text = strip_tag_block(&text, "<CONTEXT_SUMMARY>", "</CONTEXT_SUMMARY>");
    text = strip_tag_block(&text, "{{ CHECKPOINT", "}}");

    text.trim().to_string()
}

fn strip_tag_block(input: &str, open_tag: &str, close_tag: &str) -> String {
    let mut result = input.to_string();
    while let Some(start) = result.find(open_tag) {
        if let Some(end_offset) = result[start..].find(close_tag) {
            let end = start + end_offset + close_tag.len();
            result.replace_range(start..end, "");
        } else {
            result.truncate(start);
            break;
        }
    }
    result
}

fn extract_file_target(args: Option<&serde_json::Value>) -> Option<String> {
    let args = args?;
    args.get("TargetFile")
        .or_else(|| args.get("AbsolutePath"))
        .or_else(|| args.get("path"))
        .or_else(|| args.get("file_path"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
}

fn extract_command_str(args: Option<&serde_json::Value>) -> Option<String> {
    let args = args?;
    args.get("CommandLine")
        .or_else(|| args.get("command"))
        .or_else(|| args.get("cmd"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{}... [truncated]", truncated)
    }
}

const AGY_PRODUCT_DIRS: [&str; 3] = ["antigravity", "antigravity-cli", "antigravity-ide"];

fn agy_session_roots_under(gemini_root: &Path, clean_session_id: &str) -> Vec<PathBuf> {
    AGY_PRODUCT_DIRS
        .into_iter()
        .map(|product_dir| {
            gemini_root
                .join(product_dir)
                .join("brain")
                .join(clean_session_id)
        })
        .collect()
}

fn agy_session_roots(session_id: &str) -> Vec<PathBuf> {
    let clean_session_id = session_id.trim();
    if clean_session_id.is_empty()
        || clean_session_id == "."
        || clean_session_id == ".."
        || clean_session_id.contains('/')
        || clean_session_id.contains('\\')
        || clean_session_id.contains('\0')
        || !clean_session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Vec::new();
    }

    let home_path = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .map(PathBuf::from);

    let mut roots = Vec::new();
    if let Some(ref home) = home_path {
        roots.extend(agy_session_roots_under(
            &home.join(".gemini"),
            clean_session_id,
        ));
    }

    if let Ok(app_data) = std::env::var("APPDATA") {
        let gemini_root = PathBuf::from(app_data).join("..").join(".gemini");
        roots.extend(agy_session_roots_under(&gemini_root, clean_session_id));
    }

    roots
        .into_iter()
        .map(|root| {
            root.canonicalize()
                .map(crate::manifest::loader::normalize_handle_path)
                .unwrap_or(root)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Iteratively resolves a dated or direct Codex rollout file (M2, M6).
/// Runtime evaluation uses the opened resolver so it never reopens the selected file.
fn find_opened_codex_rollout_in_sessions_dir(
    sessions_root: &Path,
    clean_session_id: &str,
) -> Result<Option<OpenedTranscript>, TranscriptResolutionError> {
    validate_codex_session_id(clean_session_id)?;
    let canonical_roots = canonical_allowed_roots(&[sessions_root.to_path_buf()]);
    let Some(canonical_root) = canonical_roots.into_iter().next() else {
        return Ok(None);
    };

    // Stack-based iterative directory traversal prevents call recursion.
    let mut dir_stack = vec![canonical_root.clone()];
    let mut matched = None;
    while let Some(current_dir) = dir_stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&current_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.file_type().is_symlink() || !path_has_no_indirected_ancestor(&path) {
                    continue;
                }
                if meta.is_dir() {
                    dir_stack.push(path);
                    continue;
                }
                if !meta.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !((name.starts_with("rollout-") && name.ends_with(".jsonl"))
                    || name == "transcript.jsonl")
                {
                    continue;
                }
                let Ok(opened) = OpenedTranscript::open_with_allowed_roots(
                    &path,
                    clean_session_id,
                    std::slice::from_ref(&canonical_root),
                ) else {
                    continue;
                };
                if matched.is_some() {
                    return Err(TranscriptResolutionError::AmbiguousMatches {
                        session_id: clean_session_id.to_string(),
                        count: 2,
                    });
                }
                matched = Some(opened);
            }
        }
    }

    Ok(matched)
}

fn path_has_no_indirected_ancestor(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        if component == std::path::Component::CurDir {
            continue;
        }
        if component == std::path::Component::ParentDir {
            return false;
        }
        current.push(component.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_user_prompt_clean_extraction() {
        let raw = r#"<USER_REQUEST>
Hola, ¿qué día es hoy?
</USER_REQUEST>
<ADDITIONAL_METADATA>
The current local time is: 2026-08-20T18:33:09-06:00.
</ADDITIONAL_METADATA>
<USER_SETTINGS_CHANGE>
Model selection changed
</USER_SETTINGS_CHANGE>"#;

        let sanitized = sanitize_user_prompt(raw);
        assert_eq!(sanitized, "Hola, ¿qué día es hoy?");
    }

    #[test]
    fn test_extract_from_reader_compact_telemetry() {
        let jsonl = r#"
{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"<USER_REQUEST>\nCrea un endpoint de autenticación con tests unitarios.\n</USER_REQUEST>"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"name":"write_to_file","args":{"TargetFile":"src/auth.rs"}}]}
{"step_index":2,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"name":"run_command","args":{"CommandLine":"cargo test --test auth_tests"}}]}
{"step_index":3,"source":"MODEL","type":"PLANNER_RESPONSE","content":"He creado el módulo de autenticación y ejecuté las pruebas exitosamente."}
"#;

        let ctx = SessionContextExtractor::extract_from_reader(jsonl.as_bytes());
        assert_eq!(
            ctx.user_intent,
            "Crea un endpoint de autenticación con tests unitarios."
        );
        assert_eq!(ctx.tools_executed_count, 2);
        assert_eq!(ctx.files_created_or_modified, vec!["src/auth.rs"]);
        assert_eq!(ctx.test_commands_run.len(), 1);
        assert_eq!(
            ctx.test_commands_run[0].command,
            "cargo test --test auth_tests"
        );
        assert_eq!(ctx.test_commands_run[0].status, "requested");
        assert_eq!(ctx.test_commands_run[0].exit_code, None);
        assert!(
            ctx.agent_final_response
                .unwrap()
                .contains("He creado el módulo")
        );
    }

    #[test]
    fn extracts_user_intent_from_current_codex_rollout_envelope() {
        let jsonl = r#"
{"type":"session_meta","payload":{"id":"session-current"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<USER_REQUEST>\nCorrige el guard sin descartar mis cambios.\n</USER_REQUEST>"}]}}
{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Voy a revisar el guard."}]}}
"#;

        let context = SessionContextExtractor::extract_from_reader(jsonl.as_bytes());
        assert_eq!(
            context.user_intent,
            "Corrige el guard sin descartar mis cambios."
        );
        assert_eq!(
            context.agent_final_response.as_deref(),
            Some("Voy a revisar el guard.")
        );
    }

    #[test]
    fn supplied_agy_transcript_is_bound_to_provider_session_roots() {
        let root = std::env::temp_dir().join(format!(
            "arc-agy-transcript-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let authorized = root.join("transcript.jsonl");
        let unrelated = root.join("unrelated.jsonl");
        std::fs::write(
            &authorized,
            "{\"type\":\"USER_INPUT\",\"content\":\"Authorized AGY intent\"}\n",
        )
        .unwrap();
        std::fs::write(
            &unrelated,
            "{\"type\":\"USER_INPUT\",\"content\":\"Untrusted intent\"}\n",
        )
        .unwrap();

        let accepted = SessionContextExtractor::extract_from_supplied_agy_path_with_roots(
            &authorized,
            [root.clone()],
        );
        assert_eq!(accepted.user_intent, "Authorized AGY intent");
        let outside_root = std::env::temp_dir().join(format!(
            "arc-agy-outside-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&outside_root).unwrap();
        let rejected = SessionContextExtractor::extract_from_supplied_agy_path_with_roots(
            &unrelated,
            [outside_root.clone()],
        );
        assert!(rejected.user_intent.is_empty());

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside_root);
    }

    #[test]
    fn agy_session_uses_one_authoritative_transcript_when_compact_and_full_exist() {
        let root = std::env::temp_dir().join(format!(
            "arc-agy-authoritative-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let logs = root.join(".system_generated").join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("transcript.jsonl"),
            "{\"type\":\"USER_INPUT\",\"content\":\"Compact intent\"}\n",
        )
        .unwrap();
        std::fs::write(
            logs.join("transcript_full.jsonl"),
            "{\"type\":\"USER_INPUT\",\"content\":\"Full intent\"}\n",
        )
        .unwrap();

        let context = SessionContextExtractor::extract_from_agy_roots([root.clone()]);
        assert_eq!(context.user_intent, "Full intent");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn agy_session_with_multiple_distinct_roots_fails_closed() {
        let base = std::env::temp_dir().join(format!(
            "arc-agy-ambiguous-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let roots = [base.join("first"), base.join("second")];
        for (index, root) in roots.iter().enumerate() {
            let logs = root.join(".system_generated").join("logs");
            std::fs::create_dir_all(&logs).unwrap();
            std::fs::write(
                logs.join("transcript_full.jsonl"),
                format!("{{\"type\":\"USER_INPUT\",\"content\":\"Intent {index}\"}}\n"),
            )
            .unwrap();
        }

        let context = SessionContextExtractor::extract_from_agy_roots(roots);
        assert_eq!(context, SessionContext::default());

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn agy_session_roots_cover_desktop_cli_and_ide_surfaces() {
        for product_dir in ["antigravity", "antigravity-cli", "antigravity-ide"] {
            let base = std::env::temp_dir().join(format!(
                "arc-agy-surface-{product_dir}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            let gemini_root = base.join(".gemini");
            let session_id = "c9444a2e-bcc0-44c3-976a-a64cac576d04";
            let logs = gemini_root
                .join(product_dir)
                .join("brain")
                .join(session_id)
                .join(".system_generated")
                .join("logs");
            std::fs::create_dir_all(&logs).unwrap();
            let transcript_full = logs.join("transcript_full.jsonl");
            std::fs::write(
                &transcript_full,
                format!("{{\"type\":\"USER_INPUT\",\"content\":\"Intent from {product_dir}\"}}\n"),
            )
            .unwrap();

            let candidate_roots = agy_session_roots_under(&gemini_root, session_id);
            let supplied_ctx = SessionContextExtractor::extract_from_supplied_agy_path_with_roots(
                &transcript_full,
                candidate_roots.clone(),
            );
            assert_eq!(
                supplied_ctx.user_intent,
                format!("Intent from {product_dir}")
            );

            let discovered_ctx = SessionContextExtractor::extract_from_agy_roots(candidate_roots);
            assert_eq!(
                discovered_ctx.user_intent,
                format!("Intent from {product_dir}")
            );

            let _ = std::fs::remove_dir_all(base);
        }
    }

    #[test]
    fn test_m3_temporal_command_telemetry_and_correlation() {
        // 1. Solicitud sola sin respuesta -> requested, exit_code: None
        let jsonl_req_only = r#"
{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"Run suite"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"id":"call_1","name":"run_command","args":{"CommandLine":"cargo test"}}]}
"#;
        let ctx1 = SessionContextExtractor::extract_from_reader(jsonl_req_only.as_bytes());
        assert_eq!(ctx1.test_commands_run.len(), 1);
        assert_eq!(ctx1.test_commands_run[0].status, "requested");
        assert_eq!(ctx1.test_commands_run[0].exit_code, None);

        // 2. Solicitud + éxito con exit_code 0 -> completed, exit_code: Some(0)
        let jsonl_success = r#"
{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"Run suite"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"id":"call_1","name":"run_command","args":{"CommandLine":"cargo test"}}]}
{"step_index":2,"source":"SYSTEM","type":"TOOL_RESPONSE","tool_call_id":"call_1","content":"The command exited with code 0.\nOutput:\ntest result: ok."}
"#;
        let ctx2 = SessionContextExtractor::extract_from_reader(jsonl_success.as_bytes());
        assert_eq!(ctx2.test_commands_run[0].status, "completed");
        assert_eq!(ctx2.test_commands_run[0].exit_code, Some(0));

        // 3. Solicitud + fallo con exit_code 1 -> completed, exit_code: Some(1)
        let jsonl_failure = r#"
{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"Run suite"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"id":"call_1","name":"run_command","args":{"CommandLine":"cargo test"}}]}
{"step_index":2,"source":"SYSTEM","type":"TOOL_RESPONSE","tool_call_id":"call_1","content":"The command exited with code 1.\nOutput:\nFAILED: test_auth"}
"#;
        let ctx3 = SessionContextExtractor::extract_from_reader(jsonl_failure.as_bytes());
        assert_eq!(ctx3.test_commands_run[0].status, "completed");
        assert_eq!(ctx3.test_commands_run[0].exit_code, Some(1));

        // 4. Solicitud + respuesta sin código -> unknown, exit_code: None
        let jsonl_no_code = r#"
{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"Run suite"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"id":"call_1","name":"run_command","args":{"CommandLine":"cargo test"}}]}
{"step_index":2,"source":"SYSTEM","type":"TOOL_RESPONSE","tool_call_id":"call_1","content":"Process terminated by user"}
"#;
        let ctx4 = SessionContextExtractor::extract_from_reader(jsonl_no_code.as_bytes());
        assert_eq!(ctx4.test_commands_run[0].status, "unknown");
        assert_eq!(ctx4.test_commands_run[0].exit_code, None);

        // 5. Dos comandos concurrentes con respuestas invertidas / fuera de orden
        let jsonl_concurrent = r#"
{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"Run multi-suite"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"id":"c1","name":"run_command","args":{"CommandLine":"cargo test"}},{"id":"c2","name":"run_command","args":{"CommandLine":"npm test"}}]}
{"step_index":2,"source":"SYSTEM","type":"TOOL_RESPONSE","tool_call_id":"c2","content":"The command exited with code 1.\nOutput: 1 failed"}
{"step_index":3,"source":"SYSTEM","type":"TOOL_RESPONSE","tool_call_id":"c1","content":"The command exited with code 0.\nOutput: all passed"}
"#;
        let ctx5 = SessionContextExtractor::extract_from_reader(jsonl_concurrent.as_bytes());
        assert_eq!(ctx5.test_commands_run.len(), 2);
        let cmd1 = ctx5
            .test_commands_run
            .iter()
            .find(|c| c.call_id.as_deref() == Some("c1"))
            .unwrap();
        assert_eq!(cmd1.command, "cargo test");
        assert_eq!(cmd1.status, "completed");
        assert_eq!(cmd1.exit_code, Some(0));

        let cmd2 = ctx5
            .test_commands_run
            .iter()
            .find(|c| c.call_id.as_deref() == Some("c2"))
            .unwrap();
        assert_eq!(cmd2.command, "npm test");
        assert_eq!(cmd2.status, "completed");
        assert_eq!(cmd2.exit_code, Some(1));

        let without_id = r#"
{"type":"PLANNER_RESPONSE","tool_calls":[{"id":"only","name":"run_command","args":{"CommandLine":"cargo check"}}]}
{"type":"TOOL_RESPONSE","status":"success","content":"successful without a process exit code"}
"#;
        let ctx_without_id = SessionContextExtractor::extract_from_reader(without_id.as_bytes());
        assert_eq!(ctx_without_id.test_commands_run[0].status, "requested");
        assert_eq!(ctx_without_id.test_commands_run[0].exit_code, None);

        let textual_status = r#"
{"type":"PLANNER_RESPONSE","tool_calls":[{"id":"textual","name":"run_command","args":{"CommandLine":"cargo test"}}]}
{"type":"TOOL_RESPONSE","tool_call_id":"textual","status":"success","content":"all tests passed"}
"#;
        let ctx_textual_status =
            SessionContextExtractor::extract_from_reader(textual_status.as_bytes());
        assert_eq!(ctx_textual_status.test_commands_run[0].status, "unknown");
        assert_eq!(ctx_textual_status.test_commands_run[0].exit_code, None);
    }

    #[test]
    fn rollout_matching_requires_structured_exact_session_id() {
        let (root, sessions) = m2_test_sessions_root("structured_match");
        let path = sessions.join("rollout-structured.jsonl");
        std::fs::write(
            &path,
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"session-1234\"}}\n\
             {\"type\":\"event\",\"content\":\"session-123\"}\n",
        )
        .expect("write rollout fixture");

        assert!(
            OpenedTranscript::open_with_allowed_roots(&path, "session-1234", &[sessions.clone()])
                .is_ok()
        );
        assert!(matches!(
            OpenedTranscript::open_with_allowed_roots(&path, "session-123", &[sessions]),
            Err(TranscriptResolutionError::SessionMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn provider_transcript_path_is_authoritative_and_validated() {
        let root = std::env::temp_dir().join(format!(
            "arc_provider_transcript_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).expect("create Codex sessions root");
        let path = sessions.join("rollout-valid.jsonl");
        std::fs::write(
            &path,
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"provider-session\"}}\n\
             {\"type\":\"USER_INPUT\",\"content\":\"Provider transcript\"}\n",
        )
        .expect("write provider transcript fixture");

        let context = SessionContextExtractor::extract_from_codex_session_with_path_and_roots(
            "provider-session",
            Some(&path),
            &[sessions.clone()],
        );
        assert_eq!(context.user_intent, "Provider transcript");

        let mismatched = SessionContextExtractor::extract_from_codex_session_with_path_and_roots(
            "different-session",
            Some(&path),
            &[sessions],
        );
        assert_eq!(mismatched, SessionContext::default());

        let _ = std::fs::remove_dir_all(root);
    }

    fn m2_test_sessions_root(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "arc_m2_{label}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).expect("create test sessions root");
        (root, sessions)
    }

    fn write_m2_rollout(path: &Path, session_id: &str, intent: &str) {
        std::fs::write(
            path,
            format!(
                "{{\"type\":\"session_meta\",\"payload\":{{\"id\":{}}}}}\n\
                 {{\"type\":\"USER_INPUT\",\"content\":{}}}\n",
                serde_json::to_string(session_id).unwrap(),
                serde_json::to_string(intent).unwrap()
            ),
        )
        .expect("write Codex rollout fixture");
    }

    #[test]
    fn m2_provider_path_outside_allowed_root_fails_closed() {
        let (root, sessions) = m2_test_sessions_root("outside_root");
        let outside = root.join("outside.jsonl");
        write_m2_rollout(&outside, "outside-session", "must not be consumed");
        write_m2_rollout(
            &sessions.join("rollout-fallback.jsonl"),
            "outside-session",
            "fallback must not be used",
        );

        let error = OpenedTranscript::open_with_allowed_roots(
            &outside,
            "outside-session",
            &[sessions.clone()],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            TranscriptResolutionError::OutsideAllowedRoots { .. }
        ));
        assert_eq!(
            SessionContextExtractor::extract_from_codex_session_with_path_and_roots(
                "outside-session",
                Some(&outside),
                &[sessions],
            ),
            SessionContext::default(),
            "an invalid authoritative provider path must not trigger local discovery"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn m2_incidental_nested_id_does_not_select_rollout() {
        let (root, sessions) = m2_test_sessions_root("incidental_id");
        let path = sessions.join("rollout-incidental.jsonl");
        std::fs::write(
            &path,
            "{\"type\":\"event_msg\",\"payload\":{\"session_id\":\"target-session\",\"nested\":{\"type\":\"session_meta\",\"payload\":{\"id\":\"target-session\"}}}}\n\
             {\"type\":\"USER_INPUT\",\"content\":\"untrusted\"}\n",
        )
        .unwrap();

        let error = OpenedTranscript::open_with_allowed_roots(&path, "target-session", &[sessions])
            .unwrap_err();
        assert!(matches!(
            error,
            TranscriptResolutionError::MissingSessionMetadata { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dated_codex_rollout_is_resolved_from_year_month_day_directory() {
        let (root, sessions) = m2_test_sessions_root("dated");
        let session_id = "01a0205a-a192-7012-a9dc-ac713b22f85a";
        let dated = sessions.join("2026").join("08").join("22");
        std::fs::create_dir_all(&dated).unwrap();
        write_m2_rollout(
            &dated.join(format!("rollout-{session_id}.jsonl")),
            session_id,
            "dated intent",
        );

        let context = SessionContextExtractor::extract_from_codex_session_with_path_and_roots(
            session_id,
            None,
            &[sessions],
        );
        assert_eq!(
            context.user_intent, "dated intent",
            "must find the dated rollout file in YYYY/MM/DD structure"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn m2_duplicate_rollouts_with_same_session_fail_closed() {
        let (root, sessions) = m2_test_sessions_root("duplicate");
        write_m2_rollout(
            &sessions.join("rollout-first.jsonl"),
            "duplicate-session",
            "first",
        );
        write_m2_rollout(
            &sessions.join("rollout-second.jsonl"),
            "duplicate-session",
            "second",
        );

        assert!(matches!(
            find_opened_codex_rollout_in_sessions_dir(&sessions, "duplicate-session"),
            Err(TranscriptResolutionError::AmbiguousMatches { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn m2_malformed_provider_transcript_fails_closed() {
        let (root, sessions) = m2_test_sessions_root("malformed");
        let path = sessions.join("rollout-malformed.jsonl");
        std::fs::write(
            &path,
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"malformed-session\"}}\n{not-json}\n",
        )
        .unwrap();

        let error =
            OpenedTranscript::open_with_allowed_roots(&path, "malformed-session", &[sessions])
                .unwrap_err();
        assert!(matches!(
            error,
            TranscriptResolutionError::MalformedJsonLine { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn m2_replacement_after_open_is_not_read_through_path_again() {
        let (root, sessions) = m2_test_sessions_root("replacement");
        let path = sessions.join("rollout-replaced.jsonl");
        let moved = sessions.join("rollout-opened.jsonl");
        write_m2_rollout(&path, "replacement-session", "trusted original");

        let opened = OpenedTranscript::open_with_allowed_roots_and_hook(
            &path,
            "replacement-session",
            &[sessions],
            || {
                std::fs::rename(&path, &moved)?;
                write_m2_rollout(&path, "replacement-session", "replacement attacker content");
                Ok(())
            },
        )
        .expect("the already-opened transcript remains authoritative");

        assert_eq!(opened.into_context().user_intent, "trusted original");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn m2_unix_file_identity_rejects_replacement_before_open() {
        let (root, sessions) = m2_test_sessions_root("identity_before_open");
        let path = sessions.join("rollout-identity.jsonl");
        write_m2_rollout(&path, "identity-session", "original");
        let expected = std::fs::symlink_metadata(&path).expect("inspect original transcript");

        let replacement = sessions.join("replacement.jsonl");
        write_m2_rollout(&replacement, "identity-session", "replacement");
        std::fs::rename(&replacement, &path).expect("replace transcript before opening");
        let opened = std::fs::File::open(&path).expect("open replacement transcript");
        let actual = opened.metadata().expect("inspect opened replacement");

        assert!(!same_unix_file_identity(&expected, &actual));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn m2_symlinked_provider_transcript_is_rejected() {
        let (root, sessions) = m2_test_sessions_root("symlink");
        let outside = root.join("outside.jsonl");
        let linked = sessions.join("rollout-linked.jsonl");
        write_m2_rollout(&outside, "symlink-session", "outside");
        std::os::unix::fs::symlink(&outside, &linked).unwrap();

        let error =
            OpenedTranscript::open_with_allowed_roots(&linked, "symlink-session", &[sessions])
                .unwrap_err();
        assert!(matches!(
            error,
            TranscriptResolutionError::IndirectedPath { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn m2_symlinked_provider_transcript_is_rejected() {
        let (root, sessions) = m2_test_sessions_root("symlink");
        let outside = root.join("outside.jsonl");
        let linked = sessions.join("rollout-linked.jsonl");
        write_m2_rollout(&outside, "symlink-session", "outside");
        if std::os::windows::fs::symlink_file(&outside, &linked).is_err() {
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        let error =
            OpenedTranscript::open_with_allowed_roots(&linked, "symlink-session", &[sessions])
                .unwrap_err();
        assert!(matches!(
            error,
            TranscriptResolutionError::IndirectedPath { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
