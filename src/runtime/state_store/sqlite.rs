use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ir::BehaviorIR;
use crate::runtime::decision::{DecisionPresentationClaimStore, InteractiveDecisionOutcome};
use crate::runtime::execution::{DecisionReceipt, GuardExecutionKey, GuardExecutionRecord};
use crate::runtime::guard_evaluation::{ExactOperationAuthorization, TrustedIrAnchor};

use super::{
    AggregateGuardResolutionApplyRequest, AggregateResolutionApplyOutcome,
    AggregateResolutionApplyRequest, ExactAuthorizationContext, GuardExecutionStateStore,
    WriteOutcome,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum SqliteRevisionConversionError {
    #[error("guard execution revision {revision} exceeds SQLite's signed INTEGER range")]
    OutOfRange { revision: u64 },
    #[error("SQLite stored a negative guard execution revision: {revision}")]
    NegativeStored { revision: i64 },
}

fn revision_to_sqlite_integer(revision: u64) -> Result<i64> {
    i64::try_from(revision)
        .map_err(|_| SqliteRevisionConversionError::OutOfRange { revision }.into())
}

fn revision_from_sqlite_integer(revision: i64) -> Result<u64> {
    u64::try_from(revision)
        .map_err(|_| SqliteRevisionConversionError::NegativeStored { revision }.into())
}

fn revision_transition_is_valid(expected_revision: u64, next_revision: u64) -> bool {
    expected_revision.checked_add(1) == Some(next_revision)
}

/// An immutable, verified snapshot of a `BehaviorIR` loaded from disk and validated
/// against the external trust store (e.g. SQLite `trusted_irs`).
///
/// Fields are encapsulated to prevent external callers from mutating the IR or
/// substituting an unverified anchor after validation.
#[derive(Debug, Clone)]
pub struct TrustedIrSnapshot {
    ir: BehaviorIR,
    canonical_ir_path: PathBuf,
    anchor: TrustedIrAnchor,
}

impl TrustedIrSnapshot {
    pub(crate) fn new(ir: BehaviorIR, canonical_ir_path: PathBuf, anchor: TrustedIrAnchor) -> Self {
        Self {
            ir,
            canonical_ir_path,
            anchor,
        }
    }

    /// Returns a reference to the verified BehaviorIR.
    pub fn ir(&self) -> &BehaviorIR {
        &self.ir
    }

    /// Returns the canonical path of the BehaviorIR file on disk.
    pub fn canonical_ir_path(&self) -> &Path {
        &self.canonical_ir_path
    }

    /// Returns a reference to the verified trust anchor.
    pub fn anchor(&self) -> &TrustedIrAnchor {
        &self.anchor
    }

    /// Consumes the snapshot and returns the inner BehaviorIR.
    pub fn into_ir(self) -> BehaviorIR {
        self.ir
    }
}

/// The on-disk state database was written by a different schema version.
/// Arc never migrates, repairs, or resets such a database.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "Arc runtime state database at {path:?} has schema version {found}, but this Arc build requires schema version {expected}; the database was left untouched"
)]
pub struct IncompatibleStateSchema {
    pub path: PathBuf,
    pub found: u32,
    pub expected: u32,
}

fn sqlite_master_has_tables(connection: &Connection) -> Result<bool> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name <> 'observability_events'",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub struct SqliteStateStore {
    connection: Mutex<Connection>,
}

impl SqliteStateStore {
    /// Creates the complete current schema in one transaction and stamps
    /// `user_version`. Shared by file-backed and in-memory fresh databases.
    fn create_schema(connection: &mut Connection) -> Result<()> {
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let found: u32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if found == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }
        if found != 0 || sqlite_master_has_tables(&transaction)? {
            return Err(IncompatibleStateSchema {
                path: transaction.path().map(PathBuf::from).unwrap_or_default(),
                found,
                expected: CURRENT_SCHEMA_VERSION,
            }
            .into());
        }
        transaction.execute_batch(
            "CREATE TABLE guard_executions (
                 execution_key TEXT PRIMARY KEY,
                 revision INTEGER NOT NULL,
                 updated_at_unix_ms INTEGER NOT NULL,
                 requested_at TEXT,
                 completed_at TEXT,
                 record_json TEXT NOT NULL
             );
             CREATE INDEX guard_executions_updated
                 ON guard_executions(updated_at_unix_ms);
             CREATE TABLE workspaces (
                 canonical_root TEXT PRIMARY KEY,
                 workspace_id TEXT NOT NULL UNIQUE
             );
             CREATE TABLE trusted_irs (
                 canonical_ir_path TEXT PRIMARY KEY,
                 workspace_id TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 trusted_at_unix_ms INTEGER NOT NULL,
                 FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id)
             );
             CREATE TABLE quarantined_guard_executions (
                 execution_key TEXT PRIMARY KEY,
                 quarantined_at_unix_ms INTEGER NOT NULL,
                 record_sha256 TEXT NOT NULL,
                 error TEXT NOT NULL
             );
             CREATE TABLE decision_presentation_claims (
                 claim_key TEXT PRIMARY KEY,
                 invocation_id TEXT NOT NULL,
                 decision_id TEXT,
                 claimed_at_unix_ms INTEGER NOT NULL
             );
             CREATE INDEX decision_presentation_claims_claimed_at
                 ON decision_presentation_claims(claimed_at_unix_ms);
             CREATE INDEX decision_presentation_claims_invocation
                 ON decision_presentation_claims(invocation_id);
             CREATE INDEX decision_presentation_claims_decision
                 ON decision_presentation_claims(decision_id)
                 WHERE decision_id IS NOT NULL;
             CREATE TABLE exact_operation_authorizations (
                 authorization_id TEXT PRIMARY KEY,
                 guard_id TEXT NOT NULL,
                 operation_fingerprint TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 tool TEXT NOT NULL,
                 normalized_arguments_fingerprint TEXT NOT NULL,
                 decision_id TEXT,
                 uses_remaining INTEGER NOT NULL,
                  expires_at_unix_ms INTEGER NOT NULL,
                  created_at_unix_ms INTEGER NOT NULL,
                  session_id TEXT,
                  invocation_id TEXT,
                  consumed_by_invocation_id TEXT,
                  origin TEXT,
                  destination TEXT,
                  workspace_id TEXT,
                  provider TEXT,
                  guard_set_fingerprint TEXT,
                  policy_fingerprint TEXT,
                  evidence_fingerprint TEXT
             );
             CREATE INDEX exact_op_auth_lookup
                 ON exact_operation_authorizations(guard_id, operation_fingerprint, expires_at_unix_ms);
             CREATE UNIQUE INDEX exact_op_auth_idempotency
                 ON exact_operation_authorizations(decision_id, guard_id, operation_fingerprint)
                 WHERE decision_id IS NOT NULL;
             CREATE TABLE decision_receipts (
                 decision_id TEXT PRIMARY KEY,
                 execution_id TEXT NOT NULL,
                 selected_choice TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 provider TEXT NOT NULL,
                 received_at_unix_ms INTEGER NOT NULL,
                 transport TEXT NOT NULL,
                 receipt_json TEXT NOT NULL
             );
             CREATE INDEX decision_receipts_received
                 ON decision_receipts(received_at_unix_ms);
             CREATE TABLE aggregate_resolutions (
                 resolution_id TEXT PRIMARY KEY,
                 decision_id TEXT,
                 invocation_id TEXT NOT NULL,
                 session_id TEXT NOT NULL,
                 outcome TEXT NOT NULL,
                 applied_at_unix_ms INTEGER NOT NULL,
                 expires_at_unix_ms INTEGER NOT NULL,
                 details_json TEXT NOT NULL
             );
             CREATE UNIQUE INDEX aggregate_resolutions_decision
                 ON aggregate_resolutions(decision_id)
                 WHERE decision_id IS NOT NULL;
             CREATE INDEX aggregate_resolutions_invocation
                 ON aggregate_resolutions(invocation_id);",
        )?;
        transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    }

    fn finish_open(mut connection: Connection) -> Result<Self> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        Self::create_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating Arc state directory at {parent:?}"))?;
        }
        // An existing non-empty file is probed read-only before any write or
        // journal-mode change, so a rejected database stays byte-identical.
        let existing = std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if existing {
            let (found, has_tables) = probe_schema(path)
                .with_context(|| format!("failed reading Arc state database at {path:?}"))?;
            let fresh = found == 0 && !has_tables;
            if !fresh && found != CURRENT_SCHEMA_VERSION {
                return Err(IncompatibleStateSchema {
                    path: path.to_path_buf(),
                    found,
                    expected: CURRENT_SCHEMA_VERSION,
                }
                .into());
            }
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed opening Arc state database at {path:?}"))?;
        Self::finish_open(connection)
    }

    /// Opens an in-memory SQLite state store initialized with the full Arc schema.
    pub fn open_in_memory() -> Result<Self> {
        let connection =
            Connection::open_in_memory().context("failed opening in-memory Arc state database")?;
        Self::finish_open(connection)
    }

    pub fn schema_version(&self) -> Result<u32> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Arc state database lock is poisoned"))?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        Ok(version)
    }

    /// Records the exact generated IR bytes outside the workspace trust boundary.
    /// A later hook must match both this canonical path and digest.
    pub fn trust_ir_file(&self, ir_path: &Path) -> Result<PathBuf> {
        let (canonical_ir_path, bytes) = read_ir_snapshot(ir_path)?;
        let canonical_root = super::canonical_workspace_root(&canonical_ir_path)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let root = canonical_root.to_string_lossy().into_owned();
        let ir = canonical_ir_path.to_string_lossy().into_owned();
        let workspace_id = Uuid::new_v4().to_string();
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Arc state database lock is poisoned"))?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO workspaces(canonical_root, workspace_id) VALUES (?1, ?2)",
            params![&root, workspace_id],
        )?;
        let workspace_id: String = transaction.query_row(
            "SELECT workspace_id FROM workspaces WHERE canonical_root = ?1",
            [&root],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO trusted_irs(canonical_ir_path, workspace_id, sha256, trusted_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(canonical_ir_path) DO UPDATE SET
                 workspace_id = excluded.workspace_id,
                 sha256 = excluded.sha256,
                 trusted_at_unix_ms = excluded.trusted_at_unix_ms",
            params![ir, workspace_id, digest, unix_time_ms()],
        )?;
        transaction.commit()?;
        Ok(canonical_ir_path)
    }

    /// Registers several generated IR snapshots in one state transaction.
    /// Either every snapshot is trusted or none of them is recorded (H8/M8).
    pub fn trust_ir_files(&self, ir_paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let snapshots: Vec<(PathBuf, String)> = ir_paths
            .iter()
            .map(|path| {
                let (canonical, bytes) = read_ir_snapshot(path)?;
                let digest = hex::encode(Sha256::digest(&bytes));
                Ok((canonical, digest))
            })
            .collect::<Result<_>>()?;
        self.trust_ir_entries(&snapshots)
    }

    /// Registers generated IR using the immutable bytes produced by the
    /// compiler. The committed path is checked against those bytes, but the
    /// database records the expected digest rather than trusting a second
    /// pathname read (H8).
    pub fn trust_ir_contents(&self, ir_entries: &[(PathBuf, Vec<u8>)]) -> Result<Vec<PathBuf>> {
        let snapshots: Vec<(PathBuf, String)> = ir_entries
            .iter()
            .map(|(path, expected_bytes)| {
                let (canonical, actual_bytes) = read_ir_snapshot(path)?;
                let expected_digest = hex::encode(Sha256::digest(expected_bytes));
                let actual_digest = hex::encode(Sha256::digest(&actual_bytes));
                if actual_digest != expected_digest {
                    anyhow::bail!(
                        "generated IR changed before trust registration at {:?}: expected {}, got {}",
                        canonical,
                        expected_digest,
                        actual_digest
                    );
                }
                Ok((canonical, expected_digest))
            })
            .collect::<Result<_>>()?;
        self.trust_ir_entries(&snapshots)
    }

    /// Returns the digest registered for one already-canonical IR path without
    /// reading the workspace file. Build recovery uses this to determine
    /// whether the external trust transaction contains the previous or the new
    /// generation after a process interruption.
    pub(crate) fn trusted_ir_digest_for_exact_path(
        &self,
        ir_path: &Path,
    ) -> Result<Option<String>> {
        let normalized = crate::manifest::loader::normalize_handle_path(ir_path.to_path_buf());
        let path = normalized.to_string_lossy().into_owned();
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Arc state database lock is poisoned"))?;
        connection
            .query_row(
                "SELECT sha256 FROM trusted_irs WHERE canonical_ir_path = ?1",
                [&path],
                |row| row.get(0),
            )
            .optional()
            .context("failed reading trusted IR digest for build recovery")
    }

    fn trust_ir_entries(&self, snapshots: &[(PathBuf, String)]) -> Result<Vec<PathBuf>> {
        let connection = self.connection.lock().unwrap();
        let transaction = connection.unchecked_transaction()?;
        for (canonical_ir_path, digest) in snapshots {
            let canonical_root = match super::canonical_workspace_root(canonical_ir_path) {
                Ok(root) => root,
                Err(_) => {
                    let parent = canonical_ir_path.parent().unwrap_or(Path::new("."));
                    let parent = if parent.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        parent
                    };
                    parent.canonicalize().unwrap_or_else(|_| {
                        crate::manifest::loader::normalize_handle_path(parent.to_path_buf())
                    })
                }
            };
            let root = canonical_root.to_string_lossy().into_owned();
            let workspace_id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT OR IGNORE INTO workspaces(canonical_root, workspace_id) VALUES (?1, ?2)",
                params![&root, workspace_id],
            )?;
            let workspace_id: String = transaction.query_row(
                "SELECT workspace_id FROM workspaces WHERE canonical_root = ?1",
                [&root],
                |row| row.get(0),
            )?;
            let normalized_ir_path =
                crate::manifest::loader::normalize_handle_path(canonical_ir_path.to_path_buf());
            let ir = normalized_ir_path.to_string_lossy().into_owned();
            transaction.execute(
                "INSERT INTO trusted_irs(canonical_ir_path, workspace_id, sha256, trusted_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(canonical_ir_path) DO UPDATE SET
                     workspace_id = excluded.workspace_id,
                     sha256 = excluded.sha256,
                     trusted_at_unix_ms = excluded.trusted_at_unix_ms",
                params![ir, workspace_id, digest, unix_time_ms()],
            )?;
        }
        transaction.commit()?;
        Ok(snapshots.iter().map(|(path, _)| path.clone()).collect())
    }

    /// Verifies that an IR still matches the exact bytes registered by `arc build`.
    pub fn verify_trusted_ir_file(&self, ir_path: &Path) -> Result<PathBuf> {
        self.load_trusted_ir_file(ir_path)
            .map(|(canonical_path, _)| canonical_path)
    }

    /// Loads and verifies one immutable byte snapshot so callers never parse a
    /// second, potentially swapped file after validation.
    pub fn load_trusted_ir_file(&self, ir_path: &Path) -> Result<(PathBuf, Vec<u8>)> {
        let (canonical_ir_path, bytes) = read_ir_snapshot(ir_path)?;
        let actual_digest = hex::encode(Sha256::digest(&bytes));
        let ir = canonical_ir_path.to_string_lossy().into_owned();
        let connection = self.connection.lock().unwrap();
        let expected_digest: Option<String> = connection
            .query_row(
                "SELECT sha256 FROM trusted_irs WHERE canonical_ir_path = ?1",
                [&ir],
                |row| row.get(0),
            )
            .optional()?;
        let expected_digest = expected_digest.with_context(|| {
            format!(
                "IR at {:?} has no external Arc trust record; run `arc build` before enabling hooks",
                canonical_ir_path
            )
        })?;
        if actual_digest != expected_digest {
            anyhow::bail!(
                "trusted digest mismatch for IR at {:?}: expected {}, got {}",
                canonical_ir_path,
                expected_digest,
                actual_digest
            );
        }
        Ok((canonical_ir_path, bytes))
    }

    /// Loads and verifies one immutable BehaviorIR snapshot against SQLite `trusted_irs`,
    /// returning the parsed BehaviorIR alongside its opaque `TrustedIrAnchor`.
    pub fn load_trusted_ir_snapshot(&self, ir_path: &Path) -> Result<TrustedIrSnapshot> {
        let (canonical_ir_path, bytes) = self.load_trusted_ir_file(ir_path)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let ir: BehaviorIR = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed parsing IR JSON at {:?}", canonical_ir_path))?;
        ir.validate_integrity()
            .with_context(|| format!("Integrity check failed for IR at {:?}", canonical_ir_path))?;
        let anchor = TrustedIrAnchor::from_authenticated_store_digest(digest);
        Ok(TrustedIrSnapshot::new(ir, canonical_ir_path, anchor))
    }

    /// Registers an in-memory BehaviorIR in SQLite `trusted_irs` under `canonical_ir_path`
    /// and issues an authenticated `TrustedIrAnchor`.
    ///
    /// Validates the IR's runtime integrity before committing the record to the database.
    pub fn trust_and_anchor_ir(
        &self,
        canonical_ir_path: &Path,
        ir: &BehaviorIR,
    ) -> Result<TrustedIrAnchor> {
        ir.validate_integrity()
            .with_context(|| format!("Integrity check failed for IR at {:?}", canonical_ir_path))?;
        let digest = ir.compute_raw_bytes_digest();
        self.trust_ir_entries(&[(canonical_ir_path.to_path_buf(), digest.clone())])?;
        Ok(TrustedIrAnchor::from_authenticated_store_digest(digest))
    }

    /// Queries SQLite `trusted_irs` for `canonical_ir_path`, verifies that the
    /// registered sha256 matches `ir.compute_raw_bytes_digest()`, and returns an authenticated
    /// `TrustedIrAnchor`.
    ///
    /// Fails if the path has no record in SQLite or if the IR digest does not match SQLite.
    pub fn verify_trusted_ir_anchor(
        &self,
        canonical_ir_path: &Path,
        ir: &BehaviorIR,
    ) -> Result<TrustedIrAnchor> {
        ir.validate_integrity()
            .with_context(|| format!("Integrity check failed for IR at {:?}", canonical_ir_path))?;
        let path = crate::manifest::loader::normalize_handle_path(canonical_ir_path.to_path_buf());
        let path_str = path.to_string_lossy().into_owned();
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Arc state database lock is poisoned"))?;
        let expected_digest: Option<String> = connection
            .query_row(
                "SELECT sha256 FROM trusted_irs WHERE canonical_ir_path = ?1",
                [&path_str],
                |row| row.get(0),
            )
            .optional()
            .context("failed querying trusted_irs database")?;
        let expected_digest = expected_digest.with_context(|| {
            format!(
                "IR at {:?} has no external Arc trust record in SQLite; run `arc build` before running hooks",
                canonical_ir_path
            )
        })?;
        let actual_digest = ir.compute_raw_bytes_digest();
        if actual_digest != expected_digest {
            anyhow::bail!(
                "trusted digest mismatch for IR at {:?}: expected {}, got {}",
                canonical_ir_path,
                expected_digest,
                actual_digest
            );
        }
        Ok(TrustedIrAnchor::from_authenticated_store_digest(
            expected_digest,
        ))
    }

    pub fn record_uncorrelated_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        let auth_id = format!("auth-{}", Uuid::new_v4());
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO exact_operation_authorizations (
                authorization_id, guard_id, operation_fingerprint, event_id, tool,
                normalized_arguments_fingerprint, decision_id, uses_remaining,
                expires_at_unix_ms, created_at_unix_ms, session_id, invocation_id,
                consumed_by_invocation_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL)",
            params![
                auth_id,
                auth.guard_id,
                auth.operation_fingerprint,
                auth.event_id,
                auth.tool,
                auth.normalized_arguments_fingerprint,
                decision_id,
                uses,
                expires_at_unix_ms,
                unix_time_ms(),
            ],
        )?;
        Ok(())
    }
}

fn read_ir_snapshot(ir_path: &Path) -> Result<(PathBuf, Vec<u8>)> {
    crate::manifest::loader::inspect_all_components_without_indirection(ir_path, "Arc IR")?;
    let metadata = std::fs::symlink_metadata(ir_path)
        .with_context(|| format!("failed inspecting Arc IR path {ir_path:?}"))?;
    if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
        anyhow::bail!("Arc IR path must not be a symbolic link or reparse point: {ir_path:?}");
    }
    let mut file = std::fs::File::open(ir_path)
        .with_context(|| format!("failed opening Arc IR at {ir_path:?}"))?;
    let canonical = crate::manifest::loader::normalize_handle_path(
        crate::manifest::loader::get_handle_final_path(&file)
            .with_context(|| format!("failed resolving opened Arc IR handle {ir_path:?}"))?,
    );
    let expected = crate::manifest::loader::normalize_handle_path(
        ir_path
            .canonicalize()
            .with_context(|| format!("failed canonicalizing Arc IR path {ir_path:?}"))?,
    );
    if canonical != expected {
        anyhow::bail!(
            "Arc IR path changed while opening: expected {:?}, opened {:?}",
            expected,
            canonical
        );
    }
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        anyhow::bail!("Arc IR path is not a regular file: {canonical:?}");
    }
    #[cfg(unix)]
    if !same_unix_file_identity(&metadata, &opened_metadata) {
        anyhow::bail!("Arc IR file identity changed while opening: {ir_path:?}");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed reading trusted Arc IR at {canonical:?}"))?;
    Ok((canonical, bytes))
}

#[cfg(unix)]
fn same_unix_file_identity(expected: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    expected.dev() == opened.dev() && expected.ino() == opened.ino()
}

fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

impl GuardExecutionStateStore for SqliteStateStore {
    fn load(&self, key: &GuardExecutionKey) -> Result<Option<GuardExecutionRecord>> {
        let mut connection = self.connection.lock().unwrap();
        let json: Option<String> = connection
            .query_row(
                "SELECT record_json FROM guard_executions WHERE execution_key = ?1",
                [key.storage_key()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(value) = json else {
            return Ok(None);
        };
        match serde_json::from_str(&value) {
            Ok(record) => Ok(Some(record)),
            Err(error) => {
                let record_hash = hex::encode(Sha256::digest(value.as_bytes()));
                let diagnostic = error.to_string();
                let transaction = connection.transaction()?;
                transaction.execute(
                    "INSERT INTO quarantined_guard_executions(
                        execution_key, quarantined_at_unix_ms, record_sha256, error
                     ) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(execution_key) DO UPDATE SET
                        quarantined_at_unix_ms = excluded.quarantined_at_unix_ms,
                        record_sha256 = excluded.record_sha256,
                        error = excluded.error",
                    params![key.storage_key(), unix_time_ms(), record_hash, diagnostic],
                )?;
                transaction.execute(
                    "DELETE FROM guard_executions WHERE execution_key = ?1",
                    [key.storage_key()],
                )?;
                transaction.commit()?;
                Err(error).context("corrupt Arc guard execution state")
            }
        }
    }

    fn compare_and_swap(
        &self,
        expected_revision: Option<u64>,
        record: &GuardExecutionRecord,
    ) -> Result<WriteOutcome> {
        let record_revision = revision_to_sqlite_integer(record.revision)?;
        let expected_revision = expected_revision
            .map(revision_to_sqlite_integer)
            .transpose()?;
        let connection = self.connection.lock().unwrap();
        let storage_key = record.key.storage_key();
        let json = serde_json::to_string(record)?;
        let changed = match expected_revision {
            None => connection.execute(
                "INSERT OR IGNORE INTO guard_executions(
                    execution_key, revision, updated_at_unix_ms, requested_at, completed_at, record_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    storage_key,
                    record_revision,
                    record.updated_at_unix_ms,
                    record.requested_at,
                    record.completed_at,
                    json
                ],
            )?,
            Some(expected) => connection.execute(
                "UPDATE guard_executions
                 SET revision = ?2, updated_at_unix_ms = ?3, requested_at = ?4, completed_at = ?5, record_json = ?6
                 WHERE execution_key = ?1 AND revision = ?7",
                params![
                    storage_key,
                    record_revision,
                    record.updated_at_unix_ms,
                    record.requested_at,
                    record.completed_at,
                    json,
                    expected
                ],
            )?,
        };
        Ok(if changed == 1 {
            WriteOutcome::Written
        } else {
            WriteOutcome::Conflict
        })
    }

    fn resolve_workspace_id(&self, canonical_root: &Path) -> Result<String> {
        let root = canonical_root.to_string_lossy().into_owned();
        let connection = self.connection.lock().unwrap();
        let workspace_id = Uuid::new_v4().to_string();
        connection.execute(
            "INSERT OR IGNORE INTO workspaces(canonical_root, workspace_id) VALUES (?1, ?2)",
            params![&root, workspace_id],
        )?;
        Ok(connection.query_row(
            "SELECT workspace_id FROM workspaces WHERE canonical_root = ?1",
            [&root],
            |row| row.get(0),
        )?)
    }

    fn purge_expired(&self, older_than_unix_ms: i64) -> Result<usize> {
        let connection = self.connection.lock().unwrap();
        let _ = connection.execute(
            "DELETE FROM exact_operation_authorizations WHERE expires_at_unix_ms < ?1 OR (uses_remaining = 0 AND created_at_unix_ms < ?1)",
            [older_than_unix_ms],
        );
        Ok(connection.execute(
            "DELETE FROM guard_executions WHERE updated_at_unix_ms < ?1",
            [older_than_unix_ms],
        )?)
    }

    fn record_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        context.validate_for(std::slice::from_ref(auth))?;
        let auth_id = format!("auth-{}", Uuid::new_v4());
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO exact_operation_authorizations (
                authorization_id, guard_id, operation_fingerprint, event_id, tool,
                normalized_arguments_fingerprint, decision_id, uses_remaining,
                expires_at_unix_ms, created_at_unix_ms, session_id, invocation_id,
                consumed_by_invocation_id, origin, destination, workspace_id, provider,
                guard_set_fingerprint, policy_fingerprint, evidence_fingerprint
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                auth_id,
                auth.guard_id,
                auth.operation_fingerprint,
                auth.event_id,
                auth.tool,
                auth.normalized_arguments_fingerprint,
                decision_id,
                uses,
                expires_at_unix_ms,
                unix_time_ms(),
                context.session_id,
                context.invocation_id,
                Option::<String>::None,
                context.origin,
                context.destination,
                context.workspace_id,
                context.provider,
                context.guard_set_fingerprint,
                context.policy_fingerprint,
                context.evidence_fingerprint,
            ],
        )?;
        Ok(())
    }

    fn record_exact_authorizations_bundle(
        &self,
        auths: &[ExactOperationAuthorization],
        context: &ExactAuthorizationContext,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        if auths.is_empty() {
            return Ok(());
        }
        context.validate_for(auths)?;
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction()?;
        let created_at = unix_time_ms();
        for auth in auths {
            let auth_id = format!("auth-{}", Uuid::new_v4());
            transaction.execute(
                "INSERT INTO exact_operation_authorizations (
                    authorization_id, guard_id, operation_fingerprint, event_id, tool,
                    normalized_arguments_fingerprint, decision_id, uses_remaining,
                    expires_at_unix_ms, created_at_unix_ms, session_id, invocation_id,
                    consumed_by_invocation_id, origin, destination, workspace_id, provider,
                    guard_set_fingerprint, policy_fingerprint, evidence_fingerprint
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                params![
                    auth_id,
                    auth.guard_id,
                    auth.operation_fingerprint,
                    auth.event_id,
                    auth.tool,
                    auth.normalized_arguments_fingerprint,
                    decision_id,
                    uses,
                    expires_at_unix_ms,
                    created_at,
                    context.session_id,
                    context.invocation_id,
                    Option::<String>::None,
                    context.origin,
                    context.destination,
                    context.workspace_id,
                    context.provider,
                    context.guard_set_fingerprint,
                    context.policy_fingerprint,
                    context.evidence_fingerprint,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn consume_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> Result<bool> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction()?;
        let matching_id: Option<String> = transaction
            .query_row(
                "SELECT authorization_id FROM exact_operation_authorizations
                  WHERE guard_id = ?1 AND operation_fingerprint = ?2
                   AND event_id = ?3 AND tool = ?4
                   AND normalized_arguments_fingerprint = ?5
                   AND session_id = ?6 AND invocation_id = ?7
                   AND origin = ?8 AND destination = ?9 AND workspace_id = ?10
                   AND provider = ?11 AND guard_set_fingerprint = ?12
                   AND policy_fingerprint = ?13 AND evidence_fingerprint = ?14
                   AND expires_at_unix_ms > ?15 AND uses_remaining > 0
                  ORDER BY created_at_unix_ms ASC LIMIT 1",
                params![
                    auth.guard_id,
                    auth.operation_fingerprint,
                    auth.event_id,
                    auth.tool,
                    auth.normalized_arguments_fingerprint,
                    context.session_id,
                    context.invocation_id,
                    context.origin,
                    context.destination,
                    context.workspace_id,
                    context.provider,
                    context.guard_set_fingerprint,
                    context.policy_fingerprint,
                    context.evidence_fingerprint,
                    now_unix_ms,
                ],
                |row| row.get(0),
            )
            .optional()?;

        let Some(auth_id) = matching_id else {
            return Ok(false);
        };

        let updated = transaction.execute(
            "UPDATE exact_operation_authorizations
             SET uses_remaining = uses_remaining - 1
             WHERE authorization_id = ?1 AND uses_remaining > 0",
            params![auth_id],
        )?;
        transaction.commit()?;
        Ok(updated == 1)
    }

    fn has_valid_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> Result<bool> {
        let connection = self.connection.lock().unwrap();
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM exact_operation_authorizations
             WHERE guard_id = ?1 AND operation_fingerprint = ?2
               AND event_id = ?3 AND tool = ?4
               AND normalized_arguments_fingerprint = ?5
               AND session_id = ?6 AND invocation_id = ?7
               AND origin = ?8 AND destination = ?9 AND workspace_id = ?10
               AND provider = ?11 AND guard_set_fingerprint = ?12
               AND policy_fingerprint = ?13 AND evidence_fingerprint = ?14
               AND expires_at_unix_ms > ?15 AND uses_remaining > 0",
            params![
                auth.guard_id,
                auth.operation_fingerprint,
                auth.event_id,
                auth.tool,
                auth.normalized_arguments_fingerprint,
                context.session_id,
                context.invocation_id,
                context.origin,
                context.destination,
                context.workspace_id,
                context.provider,
                context.guard_set_fingerprint,
                context.policy_fingerprint,
                context.evidence_fingerprint,
                now_unix_ms,
            ],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn record_decision_receipt(&self, receipt: &DecisionReceipt) -> Result<()> {
        let connection = self.connection.lock().unwrap();
        let json = serde_json::to_string(receipt)?;
        connection.execute(
            "INSERT INTO decision_receipts (
                decision_id, execution_id, selected_choice, actor, provider,
                received_at_unix_ms, transport, receipt_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(decision_id) DO NOTHING",
            params![
                receipt.decision_id,
                receipt.execution_id,
                serde_json::to_string(&receipt.selected_choice)?,
                serde_json::to_string(&receipt.actor)?,
                receipt.provider,
                receipt.received_at_unix_ms,
                receipt.integrity.transport,
                json,
            ],
        )?;
        let persisted_json: String = connection.query_row(
            "SELECT receipt_json FROM decision_receipts WHERE decision_id = ?1",
            params![receipt.decision_id],
            |row| row.get(0),
        )?;
        let persisted: DecisionReceipt = serde_json::from_str(&persisted_json)?;
        if persisted != *receipt {
            anyhow::bail!(
                "conflicting decision receipt for decision '{}'",
                receipt.decision_id
            );
        }
        Ok(())
    }

    fn load_decision_receipt(&self, decision_id: &str) -> Result<Option<DecisionReceipt>> {
        let connection = self.connection.lock().unwrap();
        let json: Option<String> = connection
            .query_row(
                "SELECT receipt_json FROM decision_receipts WHERE decision_id = ?1",
                params![decision_id],
                |row| row.get(0),
            )
            .optional()?;
        match json {
            Some(value) => Ok(Some(serde_json::from_str(&value)?)),
            None => Ok(None),
        }
    }

    fn apply_aggregate_resolution(
        &self,
        request: &AggregateResolutionApplyRequest,
    ) -> Result<AggregateResolutionApplyOutcome> {
        self.apply_aggregate_resolution_with_targets(request, &[])
    }

    fn apply_aggregate_guard_resolution(
        &self,
        request: &AggregateGuardResolutionApplyRequest,
    ) -> Result<AggregateResolutionApplyOutcome> {
        self.apply_aggregate_resolution_with_targets(&request.resolution, &request.targets)
    }

    fn load_aggregate_resolution_by_decision(
        &self,
        decision_id: &str,
    ) -> Result<Option<AggregateGuardResolutionApplyRequest>> {
        let connection = self.connection.lock().unwrap();
        let details_json: Option<String> = connection
            .query_row(
                "SELECT details_json FROM aggregate_resolutions
                 WHERE decision_id = ?1 OR resolution_id = ?1
                 LIMIT 1",
                params![decision_id],
                |row| row.get(0),
            )
            .optional()?;
        details_json
            .map(|json| Ok(serde_json::from_str(&json)?))
            .transpose()
    }
}

impl SqliteStateStore {
    fn apply_aggregate_resolution_with_targets(
        &self,
        request: &AggregateResolutionApplyRequest,
        targets: &[super::AggregateGuardResolutionTarget],
    ) -> Result<AggregateResolutionApplyOutcome> {
        request.validate(targets.len())?;
        let candidate = AggregateGuardResolutionApplyRequest {
            resolution: request.clone(),
            targets: targets.to_vec(),
        };
        let idempotency_fingerprint = candidate.idempotency_fingerprint()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Arc state database lock is poisoned"))?;
        let transaction = connection.transaction()?;

        let decision_id = request
            .decision_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("aggregate decision_id is required"))?;
        let resolution_key = decision_id;

        let existing_resolution: Option<(String, String)> = transaction
            .query_row(
                "SELECT outcome, details_json FROM aggregate_resolutions
                 WHERE resolution_id = ?1 OR decision_id = ?2
                 LIMIT 1",
                params![request.resolution_id, decision_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((_existing_str, details_json)) = existing_resolution {
            let existing_fingerprint =
                serde_json::from_str::<AggregateGuardResolutionApplyRequest>(&details_json)
                    .ok()
                    .and_then(|request| request.idempotency_fingerprint().ok());
            if existing_fingerprint.as_deref() == Some(idempotency_fingerprint.as_str()) {
                return Ok(AggregateResolutionApplyOutcome::IdempotentReplay);
            } else {
                return Ok(AggregateResolutionApplyOutcome::Conflict);
            }
        }
        candidate.validate_target_scope()?;

        let outcome_str = serde_json::to_string(&request.outcome)?;
        let details_json = serde_json::to_string(&candidate)?;

        if !targets.is_empty() {
            let mut seen = std::collections::BTreeSet::new();
            for target in targets {
                if !seen.insert(target.key.storage_key()) {
                    anyhow::bail!(
                        "aggregate resolution contains duplicate guard execution targets"
                    );
                }
                if target.record.key != target.key
                    || !revision_transition_is_valid(
                        target.expected_revision,
                        target.record.revision,
                    )
                {
                    anyhow::bail!("aggregate resolution target record is inconsistent");
                }
                let current: Option<(i64, String)> = transaction
                    .query_row(
                        "SELECT revision, record_json FROM guard_executions WHERE execution_key = ?1",
                        [target.key.storage_key()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let Some((revision, record_json)) = current else {
                    anyhow::bail!("aggregate resolution refers to an unknown guard execution");
                };
                let revision = revision_from_sqlite_integer(revision)?;
                let current_record: GuardExecutionRecord = serde_json::from_str(&record_json)?;
                if revision != target.expected_revision
                    || current_record.key != target.key
                    || current_record.execution_id != target.expected_execution_id
                    || current_record
                        .pending_decision
                        .as_ref()
                        .map(|pending| pending.decision_id.as_str())
                        != Some(target.expected_decision_id.as_str())
                    || current_record
                        .pending_decision
                        .as_ref()
                        .map(|pending| pending.execution_id.as_str())
                        != Some(target.expected_execution_id.as_str())
                    || current_record
                        .pending_decision
                        .as_ref()
                        .and_then(|pending| pending.owner_invocation_id.as_deref())
                        != Some(target.expected_owner_invocation_id.as_str())
                {
                    anyhow::bail!("aggregate resolution target changed concurrently");
                }
            }
        }

        transaction.execute(
            "INSERT INTO aggregate_resolutions (
                resolution_id, decision_id, invocation_id, session_id, outcome,
                applied_at_unix_ms, expires_at_unix_ms, details_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.resolution_id,
                request.decision_id,
                request.invocation_id,
                request.session_id,
                outcome_str,
                request.now_unix_ms,
                request.expires_at_unix_ms,
                details_json,
            ],
        )?;

        if request.outcome == InteractiveDecisionOutcome::Allow {
            for auth in &request.authorizations {
                let context = request
                    .authorization_context
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("allow authorizations require context"))?;
                let auth_id = format!(
                    "auth:{}:{}:{}",
                    resolution_key, auth.guard_id, auth.operation_fingerprint
                );
                transaction.execute(
                    "INSERT INTO exact_operation_authorizations (
                        authorization_id, guard_id, operation_fingerprint, event_id, tool,
                        normalized_arguments_fingerprint, decision_id, uses_remaining,
                        expires_at_unix_ms, created_at_unix_ms, session_id, invocation_id,
                        consumed_by_invocation_id, origin, destination, workspace_id, provider,
                        guard_set_fingerprint, policy_fingerprint, evidence_fingerprint
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                    ON CONFLICT(authorization_id) DO NOTHING",
                    params![
                        auth_id,
                        auth.guard_id,
                        auth.operation_fingerprint,
                        auth.event_id,
                        auth.tool,
                        auth.normalized_arguments_fingerprint,
                        request.decision_id,
                        0, // Consumed immediately for this pending invocation!
                        request.expires_at_unix_ms,
                        request.now_unix_ms,
                        context.session_id,
                        context.invocation_id,
                        request.invocation_id,
                        context.origin,
                        context.destination,
                        context.workspace_id,
                        context.provider,
                        context.guard_set_fingerprint,
                        context.policy_fingerprint,
                        context.evidence_fingerprint,
                    ],
                )?;
            }
        }

        if let Some(receipt) = &request.decision_receipt {
            let json = serde_json::to_string(receipt)?;
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT receipt_json FROM decision_receipts WHERE decision_id = ?1",
                    params![receipt.decision_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                let existing_receipt: DecisionReceipt = serde_json::from_str(&existing)?;
                if existing_receipt != *receipt {
                    anyhow::bail!(
                        "conflicting decision receipt for decision '{}'",
                        receipt.decision_id
                    );
                }
            } else {
                transaction.execute(
                    "INSERT INTO decision_receipts (
                        decision_id, execution_id, selected_choice, actor, provider,
                        received_at_unix_ms, transport, receipt_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        receipt.decision_id,
                        receipt.execution_id,
                        serde_json::to_string(&receipt.selected_choice)?,
                        serde_json::to_string(&receipt.actor)?,
                        receipt.provider,
                        receipt.received_at_unix_ms,
                        receipt.integrity.transport,
                        json,
                    ],
                )?;
            }
        }

        for target in targets {
            let record_revision = revision_to_sqlite_integer(target.record.revision)?;
            let expected_revision = revision_to_sqlite_integer(target.expected_revision)?;
            let json = serde_json::to_string(&target.record)?;
            let changed = transaction.execute(
                "UPDATE guard_executions
                 SET revision = ?2, updated_at_unix_ms = ?3, requested_at = ?4, completed_at = ?5, record_json = ?6
                 WHERE execution_key = ?1 AND revision = ?7",
                params![
                    target.key.storage_key(),
                    record_revision,
                    target.record.updated_at_unix_ms,
                    target.record.requested_at,
                    target.record.completed_at,
                    json,
                    expected_revision,
                ],
            )?;
            if changed != 1 {
                anyhow::bail!("aggregate resolution target changed concurrently");
            }
        }

        transaction.commit()?;
        Ok(AggregateResolutionApplyOutcome::Applied)
    }
}

impl DecisionPresentationClaimStore for SqliteStateStore {
    fn claim_presentation(&self, invocation_id: &str, decision_id: Option<&str>) -> Result<bool> {
        validate_presentation_claim_id("invocation_id", invocation_id)?;
        if let Some(decision_id) = decision_id {
            validate_presentation_claim_id("decision_id", decision_id)?;
        }

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Arc state database lock is poisoned"))?;
        let transaction = connection.transaction()?;
        let cutoff = unix_time_ms().saturating_sub(PRESENTATION_CLAIM_TTL_MS);
        transaction.execute(
            "DELETE FROM decision_presentation_claims WHERE claimed_at_unix_ms < ?1",
            [cutoff],
        )?;

        let now = unix_time_ms();
        let invocation_key = format!("invocation:{invocation_id}");
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO decision_presentation_claims(
                 claim_key, invocation_id, decision_id, claimed_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![invocation_key, invocation_id, decision_id, now],
        )?;
        if inserted != 1 {
            return Ok(false);
        }

        if let Some(decision_id) = decision_id {
            let decision_key = format!("decision:{decision_id}");
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO decision_presentation_claims(
                     claim_key, invocation_id, decision_id, claimed_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![decision_key, invocation_id, decision_id, now],
            )?;
            if inserted != 1 {
                return Ok(false);
            }
        }

        transaction.commit()?;
        Ok(true)
    }
}

fn validate_presentation_claim_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("Arc presentation {field} must not be empty");
    }
    let length = value.chars().count();
    if length > MAX_PRESENTATION_CLAIM_ID_CHARS {
        anyhow::bail!(
            "Arc presentation {field} exceeds the {} character limit",
            MAX_PRESENTATION_CLAIM_ID_CHARS
        );
    }
    Ok(())
}

const CURRENT_SCHEMA_VERSION: u32 = 5;
const PRESENTATION_CLAIM_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_PRESENTATION_CLAIM_ID_CHARS: usize = 256;

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::decision::DecisionPresentationClaimStore;
    use crate::runtime::execution::{
        DecisionActor, DecisionChoice, DecisionRequest, GuardActivation, GuardExecutionRecord,
        GuardExecutionState,
    };
    use crate::runtime::state_store::AggregateGuardResolutionTarget;

    #[test]
    fn sqlite_revision_conversion_preserves_valid_values_and_rejects_invalid_ranges() {
        assert_eq!(revision_to_sqlite_integer(0).unwrap(), 0);
        assert_eq!(
            revision_to_sqlite_integer(i64::MAX as u64).unwrap(),
            i64::MAX
        );
        assert_eq!(
            revision_from_sqlite_integer(i64::MAX).unwrap(),
            i64::MAX as u64
        );

        let too_large = revision_to_sqlite_integer(u64::MAX).unwrap_err();
        assert_eq!(
            too_large.downcast_ref::<SqliteRevisionConversionError>(),
            Some(&SqliteRevisionConversionError::OutOfRange { revision: u64::MAX })
        );

        let negative = revision_from_sqlite_integer(-1).unwrap_err();
        assert_eq!(
            negative.downcast_ref::<SqliteRevisionConversionError>(),
            Some(&SqliteRevisionConversionError::NegativeStored { revision: -1 })
        );
    }

    #[test]
    fn sqlite_revision_transition_rejects_increment_overflow() {
        assert!(revision_transition_is_valid(0, 1));
        assert!(!revision_transition_is_valid(u64::MAX, 0));
        assert!(!revision_transition_is_valid(u64::MAX, u64::MAX));
    }

    #[test]
    fn compare_and_swap_rejects_unrepresentable_revision_without_writing() {
        let store = SqliteStateStore::open_in_memory().unwrap();
        let key = GuardExecutionKey {
            workspace_id: "workspace-revision-range".into(),
            session_id: "session-revision-range".into(),
            turn_id: Some("turn-revision-range".into()),
            guard_id: "guard-revision-range".into(),
            activation: GuardActivation::ToolCall,
            subject_id: Some("event-revision-range".into()),
        };
        let mut record =
            GuardExecutionRecord::new("execution-revision-range".into(), key.clone(), 0);
        record.revision = u64::MAX;

        let error = store
            .compare_and_swap(None, &record)
            .expect_err("SQLite cannot store a revision above signed INTEGER range");
        assert!(matches!(
            error.downcast_ref::<SqliteRevisionConversionError>(),
            Some(SqliteRevisionConversionError::OutOfRange { revision }) if *revision == u64::MAX
        ));
        assert!(store.load(&key).unwrap().is_none());
    }

    fn authorization_context(
        auths: &[ExactOperationAuthorization],
        session_id: &str,
        invocation_id: &str,
    ) -> ExactAuthorizationContext {
        ExactAuthorizationContext::for_authorizations(
            &auths[0].event_id,
            &auths[0].tool,
            "workspace-1",
            "codex",
            session_id,
            invocation_id,
            "policy-1",
            "evidence-1",
            auths,
        )
        .unwrap()
    }

    fn target_for(
        key: GuardExecutionKey,
        decision_id: &str,
    ) -> (GuardExecutionRecord, AggregateGuardResolutionTarget) {
        let mut record = GuardExecutionRecord::new("execution-1".into(), key.clone(), 0);
        record.revision = 1;
        record.state = GuardExecutionState::AwaitingAuthorization;
        record.pending_decision = Some(DecisionRequest {
            decision_id: decision_id.into(),
            execution_id: record.execution_id.clone(),
            owner_invocation_id: Some("inv-1".into()),
            choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
            required_actor: DecisionActor::User,
            expires_at_unix_ms: 5000,
        });
        let mut resolved = record.clone();
        resolved.revision = 2;
        resolved.pending_decision = None;
        (
            record,
            AggregateGuardResolutionTarget {
                key,
                expected_revision: 1,
                expected_decision_id: decision_id.into(),
                expected_execution_id: "execution-1".into(),
                expected_owner_invocation_id: "inv-1".into(),
                record: resolved,
            },
        )
    }

    #[test]
    fn sqlite_store_persists_uuid_and_compare_and_swap() {
        let root = std::env::temp_dir().join(format!(
            "arc_state_store_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("state.sqlite3");
        let store = SqliteStateStore::open(&database).unwrap();

        let workspace_a = store.resolve_workspace_id(&root).unwrap();
        let workspace_b = store.resolve_workspace_id(&root).unwrap();
        assert_eq!(workspace_a, workspace_b);
        assert_ne!(workspace_a, root.to_string_lossy());

        let key = GuardExecutionKey {
            workspace_id: workspace_a,
            session_id: "session".into(),
            turn_id: Some("turn".into()),
            guard_id: "guard".into(),
            activation: GuardActivation::SessionStop,
            subject_id: None,
        };
        let mut record = GuardExecutionRecord::new("execution".into(), key.clone(), 1);
        record.state = GuardExecutionState::RemediationRequested;
        record.revision = 1;
        assert_eq!(
            store.compare_and_swap(None, &record).unwrap(),
            WriteOutcome::Written
        );
        assert_eq!(store.load(&key).unwrap().unwrap(), record);
        assert_eq!(
            store.compare_and_swap(None, &record).unwrap(),
            WriteOutcome::Conflict
        );

        drop(store);
        let reopened = SqliteStateStore::open(&database).unwrap();
        assert_eq!(
            reopened.load(&key).unwrap().unwrap().execution_id,
            "execution"
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn trusted_ir_rejects_replacement_after_registration() {
        let root = std::env::temp_dir().join(format!(
            "arc_trusted_ir_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let integration = root.join(".codex");
        let database = root.join("state.sqlite3");
        let ir_path = integration.join("arc_ir.json");
        std::fs::create_dir_all(&integration).unwrap();
        std::fs::write(&ir_path, br#"{"policy":"original"}"#).unwrap();

        let store = SqliteStateStore::open(&database).unwrap();
        store.trust_ir_file(&ir_path).unwrap();
        assert!(store.verify_trusted_ir_file(&ir_path).is_ok());

        std::fs::write(
            &ir_path,
            br#"{"policy":"replacement","content_hash":"recomputed"}"#,
        )
        .unwrap();
        let error = store.verify_trusted_ir_file(&ir_path).unwrap_err();
        assert!(error.to_string().contains("trusted digest mismatch"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_ir_unix_snapshot_rejects_replacement_before_open() {
        let root = std::env::temp_dir().join(format!(
            "arc_trusted_ir_identity_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let integration = root.join(".codex");
        let ir_path = integration.join("arc_ir.json");
        std::fs::create_dir_all(&integration).unwrap();
        std::fs::write(&ir_path, br#"{"policy":"original"}"#).unwrap();
        let expected = std::fs::symlink_metadata(&ir_path).unwrap();
        let replacement = integration.join("replacement.json");
        std::fs::write(&replacement, br#"{"policy":"replacement"}"#).unwrap();
        std::fs::rename(&replacement, &ir_path).unwrap();
        let opened = std::fs::File::open(&ir_path).unwrap();

        assert!(!same_unix_file_identity(
            &expected,
            &opened.metadata().unwrap()
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn batch_trust_registration_is_all_or_nothing_before_database_commit() {
        let root = std::env::temp_dir().join(format!(
            "arc_trusted_ir_batch_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let integration = root.join(".codex");
        let database = root.join("state.sqlite3");
        let first = integration.join("first_ir.json");
        let missing = integration.join("missing_ir.json");
        std::fs::create_dir_all(&integration).unwrap();
        std::fs::write(&first, br#"{"policy":"first"}"#).unwrap();

        let store = SqliteStateStore::open(&database).unwrap();
        let error = store.trust_ir_files(&[first.clone(), missing]).unwrap_err();
        assert!(error.to_string().contains("missing_ir"));
        assert!(store.verify_trusted_ir_file(&first).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn separate_connections_detect_revision_conflicts() {
        let root = std::env::temp_dir().join(format!(
            "arc_state_conflict_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("state.sqlite3");
        let first_store = SqliteStateStore::open(&database).unwrap();
        let second_store = SqliteStateStore::open(&database).unwrap();
        let key = GuardExecutionKey {
            workspace_id: "workspace".into(),
            session_id: "session".into(),
            turn_id: None,
            guard_id: "guard".into(),
            activation: GuardActivation::SessionStop,
            subject_id: None,
        };
        let mut initial = GuardExecutionRecord::new("execution".into(), key, 1);
        initial.revision = 1;
        assert_eq!(
            first_store.compare_and_swap(None, &initial).unwrap(),
            WriteOutcome::Written
        );

        let mut winner = initial.clone();
        winner.revision = 2;
        winner.updated_at_unix_ms = 2;
        let mut stale = initial.clone();
        stale.revision = 2;
        stale.updated_at_unix_ms = 3;
        assert_eq!(
            first_store.compare_and_swap(Some(1), &winner).unwrap(),
            WriteOutcome::Written
        );
        assert_eq!(
            second_store.compare_and_swap(Some(1), &stale).unwrap(),
            WriteOutcome::Conflict
        );
        assert_eq!(
            second_store
                .load(&initial.key)
                .unwrap()
                .unwrap()
                .updated_at_unix_ms,
            2
        );
        drop(first_store);
        drop(second_store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn presentation_claims_are_atomic_across_separate_connections() {
        let root = std::env::temp_dir().join(format!(
            "arc_presentation_claim_store_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("state.sqlite3");
        let first = SqliteStateStore::open(&database).unwrap();
        let second = SqliteStateStore::open(&database).unwrap();

        assert!(
            first
                .claim_presentation("invocation-1", Some("decision-1"))
                .unwrap()
        );
        assert!(
            !second
                .claim_presentation("invocation-1", Some("decision-2"))
                .unwrap()
        );
        assert!(
            !second
                .claim_presentation("invocation-2", Some("decision-1"))
                .unwrap()
        );

        let count: u32 = second
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM decision_presentation_claims",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
        drop(first);
        drop(second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn presentation_claims_survive_a_real_process_boundary() {
        let root = std::env::temp_dir().join(format!(
            "arc_presentation_claim_process_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("state.sqlite3");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::state_store::sqlite::tests::presentation_claim_worker",
                "--nocapture",
            ])
            .env("ARC_PRESENTATION_CLAIM_WORKER_DB", &database)
            .status()
            .unwrap();
        assert!(child.success(), "claim worker process must claim once");

        let store = SqliteStateStore::open(&database).unwrap();
        assert!(
            !store
                .claim_presentation("process-invocation", Some("process-decision"))
                .unwrap()
        );
        assert!(
            !store
                .claim_presentation("other-invocation", Some("process-decision"))
                .unwrap()
        );

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn presentation_claim_worker() {
        let Ok(database) = std::env::var("ARC_PRESENTATION_CLAIM_WORKER_DB") else {
            return;
        };
        let store = SqliteStateStore::open(std::path::Path::new(&database)).unwrap();
        assert!(
            store
                .claim_presentation("process-invocation", Some("process-decision"))
                .unwrap()
        );
    }

    #[test]
    fn corrupt_record_is_reported_and_never_treated_as_missing() {
        let root = std::env::temp_dir().join(format!(
            "arc_state_corrupt_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("state.sqlite3");
        let store = SqliteStateStore::open(&database).unwrap();
        let key = GuardExecutionKey {
            workspace_id: "workspace".into(),
            session_id: "session".into(),
            turn_id: None,
            guard_id: "guard".into(),
            activation: GuardActivation::SessionStop,
            subject_id: None,
        };
        let mut record = GuardExecutionRecord::new("execution".into(), key.clone(), 1);
        record.revision = 1;
        store.compare_and_swap(None, &record).unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute("UPDATE guard_executions SET record_json = 'not-json'", [])
            .unwrap();
        let error = store.load(&key).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("corrupt Arc guard execution state")
        );
        assert!(store.load(&key).unwrap().is_none());
        let quarantined: u32 = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM quarantined_guard_executions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quarantined, 1);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn purge_expired_removes_only_old_execution_records() {
        let root = std::env::temp_dir().join(format!(
            "arc_state_ttl_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();
        for (guard_id, updated_at) in [("old", 10), ("fresh", 30)] {
            let key = GuardExecutionKey {
                workspace_id: "workspace".into(),
                session_id: "session".into(),
                turn_id: None,
                guard_id: guard_id.into(),
                activation: GuardActivation::SessionStop,
                subject_id: None,
            };
            let mut record = GuardExecutionRecord::new(guard_id.into(), key, updated_at);
            record.revision = 1;
            store.compare_and_swap(None, &record).unwrap();
        }
        assert_eq!(store.purge_expired(20).unwrap(), 1);
        let remaining: u32 = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM guard_executions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 1);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_operation_authorization_and_receipt_roundtrip() {
        let root = std::env::temp_dir().join(format!(
            "arc_auth_receipt_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();

        let auth = ExactOperationAuthorization {
            guard_id: "guard-tool-bash".into(),
            operation_fingerprint: "op-fp-123".into(),
            event_id: "ev-tool-1".into(),
            tool: "Bash".into(),
            normalized_arguments_fingerprint: "args-fp-456".into(),
        };

        let auth_context = authorization_context(std::slice::from_ref(&auth), "session-1", "inv-1");

        // Record authorization with 1 use, valid until timestamp 1000
        store
            .record_exact_authorization(&auth, &auth_context, Some("decision-rec-1"), 1000, 1)
            .unwrap();

        // Check validity before timestamp 1000
        assert!(
            store
                .has_valid_exact_authorization(&auth, &auth_context, 500)
                .unwrap()
        );
        // Expired check
        assert!(
            !store
                .has_valid_exact_authorization(&auth, &auth_context, 1000)
                .unwrap()
        );
        // Mismatched op
        let mut different_auth = auth.clone();
        different_auth.operation_fingerprint = "op-fp-different".into();
        assert!(
            !store
                .has_valid_exact_authorization(&different_auth, &auth_context, 500)
                .unwrap()
        );

        // First consume succeeds
        assert!(
            store
                .consume_exact_authorization(&auth, &auth_context, 500)
                .unwrap()
        );
        // Second consume fails (uses exhausted)
        assert!(
            !store
                .consume_exact_authorization(&auth, &auth_context, 500)
                .unwrap()
        );
        // Valid check is now false
        assert!(
            !store
                .has_valid_exact_authorization(&auth, &auth_context, 500)
                .unwrap()
        );

        // Test DecisionReceipt
        let receipt = DecisionReceipt {
            decision_id: "decision-rec-1".into(),
            execution_id: "exec-1".into(),
            selected_choice: crate::runtime::execution::DecisionChoice::Allow,
            actor: crate::runtime::execution::DecisionActor::User,
            provider: "codex".into(),
            received_at_unix_ms: 600,
            integrity: crate::runtime::execution::DecisionIntegrity {
                transport: "arc_embedded_ui".into(),
                native_interaction_id: Some("interaction-1".into()),
            },
        };

        store.record_decision_receipt(&receipt).unwrap();
        let loaded = store
            .load_decision_receipt("decision-rec-1")
            .unwrap()
            .expect("receipt exists");
        assert_eq!(loaded, receipt);
        assert!(
            store
                .load_decision_receipt("non-existent")
                .unwrap()
                .is_none()
        );

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn uncorrelated_legacy_records_denied_authority() {
        let root = std::env::temp_dir().join(format!(
            "arc_uncorr_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();

        let auth = ExactOperationAuthorization {
            guard_id: "guard-tool-bash".into(),
            operation_fingerprint: "op-fp-uncorr".into(),
            event_id: "ev-tool-1".into(),
            tool: "Bash".into(),
            normalized_arguments_fingerprint: "args-fp-1".into(),
        };

        // Record uncorrelated record (simulating legacy data)
        store
            .record_uncorrelated_exact_authorization(&auth, None, 2000, 1)
            .unwrap();
        let auth_context = authorization_context(std::slice::from_ref(&auth), "session-1", "inv-1");

        // Authority must be denied
        assert!(
            !store
                .has_valid_exact_authorization(&auth, &auth_context, 1000)
                .unwrap()
        );
        assert!(
            !store
                .consume_exact_authorization(&auth, &auth_context, 1000)
                .unwrap()
        );

        // Verify history row still exists in database
        let count: i64 = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM exact_operation_authorizations WHERE session_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn apply_aggregate_resolution_atomic_idempotent_conflict_and_no_future_grants() {
        let root = std::env::temp_dir().join(format!(
            "arc_agg_res_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();

        let auth = ExactOperationAuthorization {
            guard_id: "guard-tool-write".into(),
            operation_fingerprint: "op-fp-write".into(),
            event_id: "ev-1".into(),
            tool: "Write".into(),
            normalized_arguments_fingerprint: "args-1".into(),
        };

        let req = AggregateResolutionApplyRequest {
            resolution_id: "res-1".into(),
            decision_id: Some("dec-1".into()),
            invocation_id: "inv-1".into(),
            session_id: "sess-1".into(),
            workspace_id: Some("workspace-1".into()),
            provider: "codex".into(),
            outcome: crate::runtime::decision::InteractiveDecisionOutcome::Allow,
            authorizations: vec![auth.clone()],
            now_unix_ms: 1000,
            expires_at_unix_ms: 5000,
            decision_receipt: None,
            authorization_context: Some(authorization_context(
                std::slice::from_ref(&auth),
                "sess-1",
                "inv-1",
            )),
        };
        let key = GuardExecutionKey {
            workspace_id: "workspace-1".into(),
            session_id: "sess-1".into(),
            turn_id: Some("turn-1".into()),
            guard_id: auth.guard_id.clone(),
            activation: GuardActivation::ToolCall,
            subject_id: Some(auth.event_id.clone()),
        };
        let (pending, target) = target_for(key, "dec-1");
        store.compare_and_swap(None, &pending).unwrap();

        // 1. First apply returns Applied
        let outcome = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: req.clone(),
                targets: vec![target.clone()],
            })
            .unwrap();
        assert_eq!(outcome, AggregateResolutionApplyOutcome::Applied);

        // 2. F-04 / §5.1: No future grants. Authorization is persisted with uses_remaining = 0
        // because it was already approved for the pending invocation_id.
        assert!(
            !store
                .has_valid_exact_authorization(
                    &auth,
                    req.authorization_context.as_ref().unwrap(),
                    1500
                )
                .unwrap(),
            "Interactive Allow must NOT authorize future operations (uses_remaining = 0)"
        );

        // Verify row in DB has uses_remaining = 0 and consumed_by_invocation_id = 'inv-1'
        let (uses, consumed_by): (i64, Option<String>) = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT uses_remaining, consumed_by_invocation_id FROM exact_operation_authorizations WHERE guard_id = 'guard-tool-write'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(uses, 0);
        assert_eq!(consumed_by, Some("inv-1".into()));

        // 3. Idempotent replay: sending same request returns IdempotentReplay without errors
        let replay = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: req.clone(),
                targets: vec![target.clone()],
            })
            .unwrap();
        assert_eq!(replay, AggregateResolutionApplyOutcome::IdempotentReplay);

        // 4. Contradictory decision on same decision_id returns Conflict
        let mut contradictory_req = req.clone();
        contradictory_req.outcome = crate::runtime::decision::InteractiveDecisionOutcome::Deny;
        let conflict = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: contradictory_req,
                targets: vec![target],
            })
            .unwrap();
        assert_eq!(conflict, AggregateResolutionApplyOutcome::Conflict);

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn apply_aggregate_resolution_expiration_rejection() {
        let root = std::env::temp_dir().join(format!(
            "arc_agg_exp_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();

        let req = AggregateResolutionApplyRequest {
            resolution_id: "res-expired".into(),
            decision_id: Some("dec-expired".into()),
            invocation_id: "inv-1".into(),
            session_id: "sess-1".into(),
            workspace_id: Some("workspace-1".into()),
            provider: "codex".into(),
            outcome: crate::runtime::decision::InteractiveDecisionOutcome::Allow,
            authorizations: vec![],
            now_unix_ms: 5000,
            expires_at_unix_ms: 4000, // Expired!
            decision_receipt: None,
            authorization_context: None,
        };
        let key = GuardExecutionKey {
            workspace_id: "workspace-1".into(),
            session_id: "sess-1".into(),
            turn_id: Some("turn-1".into()),
            guard_id: "guard-expired".into(),
            activation: GuardActivation::ToolCall,
            subject_id: Some("event-expired".into()),
        };
        let (pending, target) = target_for(key, "dec-expired");
        store.compare_and_swap(None, &pending).unwrap();

        let err = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: req,
                targets: vec![target],
            })
            .unwrap_err();
        assert!(err.to_string().contains("expired"));

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    const RACE_TEST_VERSION: u32 = 3;

    /// Builds a WAL-mode database whose committed content lives only in a
    /// non-empty `-wal`. The files are copied while the writer is still open
    /// (so no lock or checkpoint is involved), then the writer is closed.
    fn wal_only_db(version: u32) -> (ProbeDir, PathBuf) {
        let root = ProbeDir(std::env::temp_dir().join(format!("arc-race-test-{}", Uuid::new_v4())));
        let src_dir = root.0.join("src");
        let live_dir = root.0.join("live");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&live_dir).unwrap();
        let src = src_dir.join("state.db");
        let writer = Connection::open(&src).unwrap();
        writer
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE marker (id INTEGER);
                 INSERT INTO marker VALUES (1);
                 PRAGMA user_version={version};"
            ))
            .unwrap();
        let live = live_dir.join("state.db");
        let live_wal = live_dir.join("state.db-wal");
        std::fs::copy(&src, &live).unwrap();
        std::fs::copy(src_dir.join("state.db-wal"), &live_wal).unwrap();
        drop(writer);
        assert!(std::fs::metadata(&live_wal).unwrap().len() > 0);
        (root, live)
    }

    fn wal_of(path: &Path) -> PathBuf {
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        PathBuf::from(wal)
    }

    /// Simulates the last writer closing: checkpoints into the main file and
    /// lets SQLite remove the `-wal`.
    fn checkpoint_and_remove_wal(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        drop(connection);
        let wal = wal_of(path);
        if wal.exists() {
            std::fs::remove_file(&wal).unwrap();
        }
        assert!(!wal.exists());
    }

    fn probe_with_wal_vanishing_at(stage: ProbeStage) -> (Result<(u32, bool)>, u32) {
        let (_root, db) = wal_only_db(RACE_TEST_VERSION);
        let mut fired = false;
        let mut calls = 0u32;
        let result = probe_schema_with_hook(&db, &mut |s| {
            calls += 1;
            if s == stage && !fired {
                fired = true;
                checkpoint_and_remove_wal(&db);
            }
        });
        assert!(fired, "hook never reached {stage:?}");
        (result, calls)
    }

    #[test]
    fn probe_race_wal_vanishes_before_copy_retries_to_correct_result() {
        let (result, _) = probe_with_wal_vanishing_at(ProbeStage::BeforeCopy);
        assert_eq!(result.unwrap(), (RACE_TEST_VERSION, true));
    }

    #[test]
    fn probe_race_wal_vanishes_between_copies_retries_to_correct_result() {
        let (result, _) = probe_with_wal_vanishing_at(ProbeStage::BetweenCopies);
        assert_eq!(result.unwrap(), (RACE_TEST_VERSION, true));
    }

    #[test]
    fn probe_race_main_db_vanishes_before_db_copy_retries_to_correct_result() {
        let (_root, db) = wal_only_db(RACE_TEST_VERSION);
        let parked = db.with_extension("parked");
        let mut removed = false;
        let mut restored = false;
        let result = probe_schema_with_hook(&db, &mut |s| match s {
            ProbeStage::BeforeDbCopy if !removed => {
                removed = true;
                std::fs::rename(&db, &parked).unwrap();
            }
            ProbeStage::BeforeCopy if removed && !restored => {
                restored = true;
                std::fs::rename(&parked, &db).unwrap();
            }
            _ => {}
        });
        assert!(removed && restored, "race was not injected and restored");
        assert_eq!(result.unwrap(), (RACE_TEST_VERSION, true));
    }

    #[test]
    fn probe_race_same_length_wal_rewrite_in_place_restarts_and_reads_new_content() {
        let (_root, db) = wal_only_db(RACE_TEST_VERSION);
        let wal = wal_of(&db);
        let mut fired = false;
        let mut restarts = 0u32;
        let result = probe_schema_with_hook(&db, &mut |s| match s {
            ProbeStage::BeforeCopy => restarts += 1,
            ProbeStage::AfterCopies if !fired => {
                fired = true;
                let meta = std::fs::metadata(&wal).unwrap();
                let bytes = std::fs::read(&wal).unwrap();
                std::fs::write(&wal, &bytes).unwrap();
                assert_eq!(std::fs::metadata(&wal).unwrap().len(), meta.len());
                let file = std::fs::OpenOptions::new().write(true).open(&wal).unwrap();
                file.set_modified(meta.modified().unwrap() + std::time::Duration::from_secs(10))
                    .unwrap();
            }
            _ => {}
        });
        assert!(fired);
        assert_eq!(result.unwrap(), (RACE_TEST_VERSION, true));
        assert_eq!(
            restarts, 2,
            "same-length rewrite must restart the probe once"
        );
    }

    #[test]
    fn probe_race_wal_vanishes_after_copies_retries_to_correct_result() {
        let (result, _) = probe_with_wal_vanishing_at(ProbeStage::AfterCopies);
        assert_eq!(result.unwrap(), (RACE_TEST_VERSION, true));
    }

    #[test]
    fn probe_race_wal_changing_on_every_call_exhausts_with_typed_error() {
        let (_root, db) = wal_only_db(RACE_TEST_VERSION);
        let wal = wal_of(&db);
        let mut calls = 0u32;
        let err = probe_schema_with_hook(&db, &mut |_| {
            calls += 1;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
            file.write_all(&[0u8]).unwrap();
        })
        .unwrap_err();
        assert!(err.downcast_ref::<ProbeRaceExhausted>().is_some());
        assert!(calls >= PROBE_MAX_ATTEMPTS);
    }

    #[test]
    fn probe_race_does_not_bypass_old_schema_rejection() {
        let (_root, db) = wal_only_db(RACE_TEST_VERSION);
        let mut fired = false;
        let probed = probe_schema_with_hook(&db, &mut |s| {
            if s == ProbeStage::BeforeCopy && !fired {
                fired = true;
                checkpoint_and_remove_wal(&db);
            }
        });
        assert!(fired);
        // The race resolves to the real old version, never to Ok(current).
        assert_eq!(probed.unwrap(), (RACE_TEST_VERSION, true));

        let err = SqliteStateStore::open(&db)
            .err()
            .expect("old schema must be rejected");
        assert!(err.downcast_ref::<ProbeRaceExhausted>().is_none());
        let incompatible = err
            .downcast_ref::<IncompatibleStateSchema>()
            .expect("expected IncompatibleStateSchema");
        assert_eq!(incompatible.found, RACE_TEST_VERSION);
        assert_eq!(incompatible.expected, CURRENT_SCHEMA_VERSION);
    }
}

/// Removes a private probe directory on drop, including on error paths.
struct ProbeDir(PathBuf);

impl Drop for ProbeDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_probe(connection: &Connection) -> rusqlite::Result<(u32, bool)> {
    let found: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let has_tables = sqlite_master_has_tables(connection)
        .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
    Ok((found, has_tables))
}

/// Reads `user_version` and whether foreign tables exist without touching the
/// live files. Without a non-empty `-wal` the database is opened `immutable=1`
/// (no locks, no sidecars). With one, the database and its `-wal` are copied
/// into a private temp directory and the copy is probed, so committed WAL
/// content is visible while the live db, `-wal` and `-shm` stay untouched.
fn probe_schema(path: &Path) -> Result<(u32, bool)> {
    probe_schema_with_hook(path, &mut |_| {})
}

/// Points of `probe_schema` where a concurrent writer can change the files.
/// Exposed so a test can inject the race deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeStage {
    /// After the `-wal` existence check, before anything is copied.
    BeforeCopy,
    /// After the main db was copied, before the `-wal` is copied.
    BetweenCopies,
    /// After the stamp of the db and `-wal`, before the main db is copied.
    BeforeDbCopy,
    /// After both copies, before the closing stamp comparison.
    AfterCopies,
}

/// The files kept changing during the probe; nothing was accepted. Retry-safe.
#[derive(Debug)]
pub(crate) struct ProbeRaceExhausted;

impl std::fmt::Display for ProbeRaceExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "state database kept changing during schema probe; retry")
    }
}

impl std::error::Error for ProbeRaceExhausted {}

const PROBE_MAX_ATTEMPTS: u32 = 8;

fn file_stamp(path: &Path) -> std::io::Result<(u64, Option<std::time::SystemTime>)> {
    let meta = std::fs::metadata(path)?;
    Ok((meta.len(), meta.modified().ok()))
}

/// Same as `probe_schema`, calling `hook` at each `ProbeStage`. A vanished
/// `-wal` (the last writer closed and checkpointed it), a vanished db, or files
/// that change while being copied restart the probe from the existence check,
/// never accepting a possibly stale copy. After `PROBE_MAX_ATTEMPTS` restarts
/// the typed `ProbeRaceExhausted` error is returned.
pub(crate) fn probe_schema_with_hook(
    path: &Path,
    hook: &mut dyn FnMut(ProbeStage),
) -> Result<(u32, bool)> {
    use std::io::ErrorKind::NotFound;
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let wal = PathBuf::from(wal);
    for _ in 0..PROBE_MAX_ATTEMPTS {
        let has_wal = std::fs::metadata(&wal)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if has_wal && header_user_version(path) == Some(CURRENT_SCHEMA_VERSION) {
            // Current-version store: skip the copy; create_schema re-checks.
            return Ok((CURRENT_SCHEMA_VERSION, true));
        }
        if !has_wal {
            let probe = open_immutable(path)?;
            return Ok(read_probe(&probe)?);
        }
        hook(ProbeStage::BeforeCopy);
        let dir = ProbeDir(std::env::temp_dir().join(format!("arc-probe-{}", Uuid::new_v4())));
        std::fs::create_dir_all(&dir.0)?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("state database path has no file name"))?;
        let copy = dir.0.join(name);
        let mut copy_wal = copy.as_os_str().to_os_string();
        copy_wal.push("-wal");
        let before = match (file_stamp(path), file_stamp(&wal)) {
            (Ok(db), Ok(w)) => (db, w),
            (Err(e), _) | (_, Err(e)) if e.kind() == NotFound => continue,
            (Err(e), _) | (_, Err(e)) => return Err(e.into()),
        };
        hook(ProbeStage::BeforeDbCopy);
        match std::fs::copy(path, &copy) {
            Ok(_) => {}
            Err(e) if e.kind() == NotFound => continue,
            Err(e) => return Err(e.into()),
        }
        hook(ProbeStage::BetweenCopies);
        match std::fs::copy(&wal, PathBuf::from(copy_wal)) {
            Ok(_) => {}
            Err(e) if e.kind() == NotFound => continue,
            Err(e) => return Err(e.into()),
        }
        hook(ProbeStage::AfterCopies);
        match (file_stamp(path), file_stamp(&wal)) {
            (Ok(db), Ok(w)) if (db, w) == before => {}
            (Ok(_), Ok(_)) => continue,
            (Err(e), _) | (_, Err(e)) if e.kind() == NotFound => continue,
            (Err(e), _) | (_, Err(e)) => return Err(e.into()),
        }
        let probe = Connection::open(&copy)?;
        let result = read_probe(&probe);
        drop(probe);
        return Ok(result?);
    }
    Err(ProbeRaceExhausted.into())
}

/// Reads `user_version` (big-endian u32 at offset 60) from the db header with
/// plain file I/O. Returns `None` on read errors, short reads or bad magic.
fn header_user_version(path: &Path) -> Option<u32> {
    use std::io::Read;
    let mut header = [0u8; 64];
    std::fs::File::open(path)
        .ok()?
        .read_exact(&mut header)
        .ok()?;
    if &header[..16] != b"SQLite format 3\0" {
        return None;
    }
    Some(u32::from_be_bytes(header[60..64].try_into().ok()?))
}

fn open_immutable(path: &Path) -> rusqlite::Result<Connection> {
    use rusqlite::OpenFlags;
    let raw = path.to_string_lossy().replace('\\', "/");
    let mut uri = String::from("file:");
    if !raw.starts_with('/') {
        uri.push('/');
    }
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                uri.push(byte as char)
            }
            _ => uri.push_str(&format!("%{byte:02X}")),
        }
    }
    uri.push_str("?immutable=1");
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
}
