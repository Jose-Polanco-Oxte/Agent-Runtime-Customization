use super::traits::GeneratedArtifact;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use std::cell::Cell;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Build manifest recording generated artifacts, hashes, and metadata (M3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema_version: String,
    pub arc_version: String,
    pub generated_at: String,
    pub artifacts: Vec<BuildArtifactRecord>,
}

/// Metadata record for an individual generated artifact (M3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildArtifactRecord {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub is_executable: bool,
}

const ARC_STATE_DIR: &str = ".arc";
const BUILD_MANIFEST_FILE: &str = ".arc/build_manifest.json";
const CLEANUP_JOURNAL_FILE: &str = ".arc/build-cleanup.json";
const TRANSACTION_JOURNAL_FILE: &str = ".arc/build-transaction.json";
const TRANSACTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct CleanupJournal {
    files: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum BuildTransactionState {
    Prepared,
    Committing,
    Committed,
    TrustRegistered,
    Cleanup,
    Complete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TransactionFileKind {
    Artifact,
    Manifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransactionFileRecord {
    kind: TransactionFileKind,
    target: String,
    temp: String,
    backup: Option<String>,
    previous_sha256: Option<String>,
    new_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransactionTrustRecord {
    ir_path: String,
    previous_sha256: Option<String>,
    new_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BuildTransactionJournal {
    schema_version: u32,
    transaction_id: String,
    state: BuildTransactionState,
    files: Vec<TransactionFileRecord>,
    trusted_irs: Vec<TransactionTrustRecord>,
}

const BUILD_LOCK_FILE: &str = "build.lock";
const BUILD_LOCK_PATH: &str = ".arc/build.lock";

/// Capability-like reference to one directory below the already-opened output
/// root. All security-sensitive file operations are resolved from this handle,
/// never by reopening the original path after validation (H4).
#[derive(Clone, Debug)]
struct OpenDirectory {
    handle: Arc<File>,
    display_path: PathBuf,
    relative_path: PathBuf,
}

#[derive(Debug)]
struct OpenRelativeFile {
    parent: OpenDirectory,
    name: OsString,
    handle: File,
}

#[derive(Clone, Debug)]
struct OpenedDestination {
    parent: OpenDirectory,
    name: OsString,
}

#[derive(Debug)]
struct BuildDirectoryLock {
    _file: OpenRelativeFile,
}

trait DurableBuildFinalizer {
    fn plan(
        &self,
        output: &OpenDirectory,
        files: &[TransactionFileRecord],
    ) -> Result<Vec<TransactionTrustRecord>>;

    fn commit(&mut self, output: &OpenDirectory, manifest: &BuildManifest) -> Result<()>;

    fn classify(
        &self,
        output: &OpenDirectory,
        journal: &BuildTransactionJournal,
    ) -> Result<ExternalTrustState>;
}

struct NoopBuildFinalizer;

impl DurableBuildFinalizer for NoopBuildFinalizer {
    fn plan(
        &self,
        _output: &OpenDirectory,
        _files: &[TransactionFileRecord],
    ) -> Result<Vec<TransactionTrustRecord>> {
        Ok(Vec::new())
    }

    fn commit(&mut self, _output: &OpenDirectory, _manifest: &BuildManifest) -> Result<()> {
        Ok(())
    }

    fn classify(
        &self,
        _output: &OpenDirectory,
        journal: &BuildTransactionJournal,
    ) -> Result<ExternalTrustState> {
        if journal.trusted_irs.is_empty() {
            Ok(ExternalTrustState::NotApplicable)
        } else {
            Ok(ExternalTrustState::Ambiguous)
        }
    }
}

#[cfg(test)]
struct ClosureBuildFinalizer<F> {
    callback: Option<F>,
    succeeded: Cell<bool>,
}

#[cfg(test)]
impl<F> ClosureBuildFinalizer<F> {
    fn new(callback: F) -> Self {
        Self {
            callback: Some(callback),
            succeeded: Cell::new(false),
        }
    }
}

#[cfg(test)]
impl<F> DurableBuildFinalizer for ClosureBuildFinalizer<F>
where
    F: FnOnce(&BuildManifest) -> Result<()>,
{
    fn plan(
        &self,
        _output: &OpenDirectory,
        _files: &[TransactionFileRecord],
    ) -> Result<Vec<TransactionTrustRecord>> {
        Ok(Vec::new())
    }

    fn commit(&mut self, _output: &OpenDirectory, manifest: &BuildManifest) -> Result<()> {
        let callback = self
            .callback
            .take()
            .ok_or_else(|| anyhow::anyhow!("build finalizer invoked more than once"))?;
        callback(manifest)?;
        self.succeeded.set(true);
        Ok(())
    }

    fn classify(
        &self,
        _output: &OpenDirectory,
        journal: &BuildTransactionJournal,
    ) -> Result<ExternalTrustState> {
        if !journal.trusted_irs.is_empty() {
            return Ok(ExternalTrustState::Ambiguous);
        }
        Ok(if self.succeeded.get() {
            ExternalTrustState::New
        } else {
            ExternalTrustState::NotApplicable
        })
    }
}

struct SqliteIrTrustFinalizer<'a> {
    store: &'a crate::runtime::state_store::SqliteStateStore,
    entries: &'a [(PathBuf, Vec<u8>)],
}

impl DurableBuildFinalizer for SqliteIrTrustFinalizer<'_> {
    fn plan(
        &self,
        output: &OpenDirectory,
        files: &[TransactionFileRecord],
    ) -> Result<Vec<TransactionTrustRecord>> {
        let file_hashes: BTreeMap<&str, &str> = files
            .iter()
            .map(|record| (record.target.as_str(), record.new_sha256.as_str()))
            .collect();
        let mut planned = Vec::with_capacity(self.entries.len());
        for (relative, bytes) in self.entries {
            validate_transaction_relative_path(relative, "trusted IR")?;
            let normalized = normalize_relative_path(relative);
            let new_sha256 = sha256_bytes(bytes);
            let Some(recorded_hash) = file_hashes.get(normalized.as_str()) else {
                bail!("trusted IR {relative:?} is not part of the generated transaction");
            };
            if *recorded_hash != new_sha256 {
                bail!("trusted IR {relative:?} does not match the generated transaction bytes");
            }
            let canonical_path = output.display_path.join(relative);
            let previous_sha256 = self
                .store
                .trusted_ir_digest_for_exact_path(&canonical_path)?;
            planned.push(TransactionTrustRecord {
                ir_path: normalized,
                previous_sha256,
                new_sha256,
            });
        }
        planned.sort_by(|left, right| left.ir_path.cmp(&right.ir_path));
        if planned
            .windows(2)
            .any(|pair| pair[0].ir_path == pair[1].ir_path)
        {
            bail!("duplicate trusted IR path in build transaction");
        }
        Ok(planned)
    }

    fn commit(&mut self, output: &OpenDirectory, _manifest: &BuildManifest) -> Result<()> {
        let absolute_entries: Vec<(PathBuf, Vec<u8>)> = self
            .entries
            .iter()
            .map(|(relative, bytes)| (output.display_path.join(relative), bytes.clone()))
            .collect();
        self.store
            .trust_ir_contents(&absolute_entries)
            .map(|_| ())
            .context("failed registering generated IR trust atomically")
    }

    fn classify(
        &self,
        output: &OpenDirectory,
        journal: &BuildTransactionJournal,
    ) -> Result<ExternalTrustState> {
        classify_sqlite_trust(self.store, output, journal)
    }
}

struct SqliteRecoveryFinalizer<'a> {
    store: &'a crate::runtime::state_store::SqliteStateStore,
}

impl DurableBuildFinalizer for SqliteRecoveryFinalizer<'_> {
    fn plan(
        &self,
        _output: &OpenDirectory,
        _files: &[TransactionFileRecord],
    ) -> Result<Vec<TransactionTrustRecord>> {
        bail!("recovery finalizer cannot create a new transaction")
    }

    fn commit(&mut self, _output: &OpenDirectory, _manifest: &BuildManifest) -> Result<()> {
        bail!("recovery finalizer cannot register new trust")
    }

    fn classify(
        &self,
        output: &OpenDirectory,
        journal: &BuildTransactionJournal,
    ) -> Result<ExternalTrustState> {
        classify_sqlite_trust(self.store, output, journal)
    }
}

#[derive(Debug)]
struct PreparedTransactionFile {
    destination: OpenedDestination,
    temp: OpenRelativeFile,
    backup: Option<OpenRelativeFile>,
    record: TransactionFileRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionCheckpoint {
    BeforeJournalPublish,
    AfterJournalPublish,
    BeforeFirstReplace,
    AfterReplace { index: usize, target: String },
    AfterManifestReplace,
    BeforeFinalizer,
    AfterFinalizer,
    BeforeBackupCleanup { index: usize, backup: String },
    AfterBackupCleanup { index: usize, backup: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalTrustState {
    NotApplicable,
    Previous,
    New,
    Ambiguous,
}

impl OpenDirectory {
    fn open_root(canonical_path: &Path) -> std::io::Result<Self> {
        let handle = open_directory_handle_without_links(canonical_path)?;
        validate_opened_directory(&handle, canonical_path)?;
        Ok(Self {
            handle: Arc::new(handle),
            display_path: canonical_path.to_path_buf(),
            relative_path: PathBuf::new(),
        })
    }

    fn acquire_build_lock(&self) -> std::io::Result<BuildDirectoryLock> {
        let state_directory = self.open_child(OsStr::new(ARC_STATE_DIR), true)?;
        let file = open_build_lock(&state_directory, OsStr::new(BUILD_LOCK_FILE))?;
        Ok(BuildDirectoryLock { _file: file })
    }

    fn resolve_destination(
        &self,
        relative: &Path,
        create_parents: bool,
    ) -> std::io::Result<OpenedDestination> {
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                std::path::Component::Normal(name) => names.push(name.to_os_string()),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "artifact path must contain only normal relative components: {relative:?}"
                        ),
                    ));
                }
            }
        }
        let name = names.pop().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "artifact path has no file name",
            )
        })?;
        validate_relative_name(&name)?;

        let mut parent = self.clone();
        for child_name in names {
            parent = parent.open_child(&child_name, create_parents)?;
        }
        Ok(OpenedDestination { parent, name })
    }

    fn open_child(&self, name: &OsStr, create: bool) -> std::io::Result<Self> {
        validate_relative_name(name)?;
        let handle = open_child_directory_handle(self, name, create)?;
        let expected = self.display_path.join(name);
        validate_opened_directory(&handle, &expected)?;
        Ok(Self {
            handle: Arc::new(handle),
            display_path: expected,
            relative_path: self.relative_path.join(name),
        })
    }

    fn create_new_file(&self, name: &OsStr) -> std::io::Result<OpenRelativeFile> {
        validate_relative_name(name)?;
        let handle = create_new_file_at(self, name)?;
        validate_opened_regular_file(&handle, self, name)?;
        Ok(OpenRelativeFile {
            parent: self.clone(),
            name: name.to_os_string(),
            handle,
        })
    }

    fn open_existing_file(&self, name: &OsStr) -> std::io::Result<Option<OpenRelativeFile>> {
        validate_relative_name(name)?;
        let handle = match open_existing_file_at(self, name) {
            Ok(handle) => handle,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        validate_opened_regular_file(&handle, self, name)?;
        Ok(Some(OpenRelativeFile {
            parent: self.clone(),
            name: name.to_os_string(),
            handle,
        }))
    }

    fn sync(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            self.handle.sync_all()
        }
        #[cfg(windows)]
        {
            // Windows does not support FlushFileBuffers for directory handles.
            // The file itself is flushed before the atomic rename.
            Ok(())
        }
    }
}

impl OpenedDestination {
    fn display_path(&self) -> PathBuf {
        self.parent.display_path.join(&self.name)
    }

    fn open_existing(&self) -> std::io::Result<Option<OpenRelativeFile>> {
        self.parent.open_existing_file(&self.name)
    }

    fn create_transaction_file(&self, prefix: &str) -> std::io::Result<OpenRelativeFile> {
        let name = OsString::from(format!("{prefix}{}.tmp", uuid::Uuid::new_v4()));
        self.parent.create_new_file(&name)
    }
}

impl OpenRelativeFile {
    fn display_path(&self) -> PathBuf {
        self.parent.display_path.join(&self.name)
    }

    fn relative_path(&self) -> PathBuf {
        self.parent.relative_path.join(&self.name)
    }

    fn write_and_sync(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.handle.seek(SeekFrom::Start(0))?;
        self.handle.set_len(0)?;
        self.handle.write_all(bytes)?;
        self.handle.sync_all()
    }

    fn read_all(&mut self) -> std::io::Result<Vec<u8>> {
        self.handle.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.handle.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn copy_to(&mut self, destination: &mut OpenRelativeFile) -> std::io::Result<()> {
        self.handle.seek(SeekFrom::Start(0))?;
        destination.handle.seek(SeekFrom::Start(0))?;
        destination.handle.set_len(0)?;
        std::io::copy(&mut self.handle, &mut destination.handle)?;
        destination.handle.sync_all()
    }

    fn rename_replace(
        &mut self,
        destination_parent: &OpenDirectory,
        destination_name: &OsStr,
    ) -> std::io::Result<()> {
        validate_relative_name(destination_name)?;
        rename_relative_file(
            &self.parent,
            &self.name,
            &self.handle,
            destination_parent,
            destination_name,
        )?;
        self.parent = destination_parent.clone();
        self.name = destination_name.to_os_string();
        Ok(())
    }

    fn remove(&self) -> std::io::Result<()> {
        remove_relative_file(&self.parent, &self.name, &self.handle)
    }
}

fn validate_relative_name(name: &OsStr) -> std::io::Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("entry name must be one normal relative component: {name:?}"),
        ));
    }
    Ok(())
}

fn validate_opened_directory(handle: &File, expected: &Path) -> std::io::Result<()> {
    let metadata = handle.metadata()?;
    if !metadata.is_dir() || metadata_is_indirected(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing indirect or non-directory output component: {expected:?}"),
        ));
    }
    let opened = crate::manifest::loader::normalize_handle_path(
        crate::manifest::loader::get_handle_final_path(handle)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );
    let expected = crate::manifest::loader::normalize_handle_path(expected.to_path_buf());
    if opened != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("opened directory {opened:?} does not match expected {expected:?}"),
        ));
    }
    Ok(())
}

fn validate_opened_regular_file(
    handle: &File,
    parent: &OpenDirectory,
    name: &OsStr,
) -> std::io::Result<()> {
    let metadata = handle.metadata()?;
    if !metadata.is_file() || metadata_is_indirected(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing symlink, reparse point, or non-file entry: {:?}",
                parent.display_path.join(name)
            ),
        ));
    }
    let opened = crate::manifest::loader::normalize_handle_path(
        crate::manifest::loader::get_handle_final_path(handle)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );
    let parent_opened = crate::manifest::loader::normalize_handle_path(
        crate::manifest::loader::get_handle_final_path(&parent.handle)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );
    let expected = crate::manifest::loader::normalize_handle_path(parent_opened.join(name));
    if opened != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("opened file {opened:?} is not inside opened parent {parent_opened:?}"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn c_entry_name(name: &OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(unix)]
fn open_directory_handle_without_links(path: &Path) -> std::io::Result<File> {
    use std::os::fd::FromRawFd;
    let raw = open_directory_without_links(path)?;
    Ok(unsafe { File::from_raw_fd(raw) })
}

#[cfg(windows)]
fn open_directory_handle_without_links(path: &Path) -> std::io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(unix)]
fn open_child_directory_handle(
    parent: &OpenDirectory,
    name: &OsStr,
    create: bool,
) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_entry_name(name)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut raw = unsafe { libc::openat(parent.handle.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 && create && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        let created = unsafe { libc::mkdirat(parent.handle.as_raw_fd(), name.as_ptr(), 0o755) };
        if created != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        raw = unsafe { libc::openat(parent.handle.as_raw_fd(), name.as_ptr(), flags) };
    }
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

#[cfg(windows)]
fn open_child_directory_handle(
    parent: &OpenDirectory,
    name: &OsStr,
    create: bool,
) -> std::io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    windows_nt_open_relative(
        parent,
        name,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        if create { FILE_OPEN_IF } else { FILE_OPEN },
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_ATTRIBUTE_DIRECTORY,
    )
}

#[cfg(unix)]
fn create_new_file_at(parent: &OpenDirectory, name: &OsStr) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_entry_name(name)?;
    let raw = unsafe {
        libc::openat(
            parent.handle.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

#[cfg(unix)]
fn open_existing_file_at(parent: &OpenDirectory, name: &OsStr) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_entry_name(name)?;
    let raw = unsafe {
        libc::openat(
            parent.handle.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing symlink entry in opened output directory",
            ));
        }
        return Err(error);
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

#[cfg(windows)]
fn windows_open_file_at(
    parent: &OpenDirectory,
    name: &OsStr,
    disposition: u32,
    share_mode: u32,
) -> std::io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    windows_nt_open_relative(
        parent,
        name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        share_mode,
        disposition,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_ATTRIBUTE_NORMAL,
    )
}

#[cfg(windows)]
fn windows_nt_open_relative(
    parent: &OpenDirectory,
    name: &OsStr,
    desired_access: u32,
    share_mode: u32,
    disposition: u32,
    create_options: u32,
    file_attributes: u32,
) -> std::io::Result<File> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
    use windows_sys::Win32::Foundation::{
        INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    validate_relative_name(name)?;
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let byte_len = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "relative Windows entry name is too long",
            )
        })?;
    if byte_len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "relative Windows entry name is empty",
        ));
    }
    let object_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: wide.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.handle.as_raw_handle(),
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = INVALID_HANDLE_VALUE;
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            file_attributes,
            share_mode,
            disposition,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let win32_error = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(win32_error as i32));
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(
            "NtCreateFile succeeded without returning a valid handle",
        ));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn create_new_file_at(parent: &OpenDirectory, name: &OsStr) -> std::io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    windows_open_file_at(
        parent,
        name,
        FILE_CREATE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

#[cfg(windows)]
fn open_existing_file_at(parent: &OpenDirectory, name: &OsStr) -> std::io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    windows_open_file_at(
        parent,
        name,
        FILE_OPEN,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

#[cfg(unix)]
fn open_build_lock(parent: &OpenDirectory, name: &OsStr) -> std::io::Result<OpenRelativeFile> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c_name = c_entry_name(name)?;
    let raw = unsafe {
        libc::openat(
            parent.handle.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(raw) };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!("another Arc build holds {BUILD_LOCK_FILE}"),
        ));
    }
    validate_opened_regular_file(&file, parent, name)?;
    Ok(OpenRelativeFile {
        parent: parent.clone(),
        name: name.to_os_string(),
        handle: file,
    })
}

#[cfg(windows)]
fn open_build_lock(parent: &OpenDirectory, name: &OsStr) -> std::io::Result<OpenRelativeFile> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN_IF;
    let file = windows_open_file_at(parent, name, FILE_OPEN_IF, 0).map_err(|error| {
        if error.raw_os_error() == Some(32) {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("another Arc build holds {BUILD_LOCK_FILE}"),
            )
        } else {
            error
        }
    })?;
    validate_opened_regular_file(&file, parent, name)?;
    Ok(OpenRelativeFile {
        parent: parent.clone(),
        name: name.to_os_string(),
        handle: file,
    })
}

#[cfg(unix)]
fn rename_relative_file(
    source_parent: &OpenDirectory,
    source_name: &OsStr,
    source_handle: &File,
    destination_parent: &OpenDirectory,
    destination_name: &OsStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    verify_unix_name_identity(source_parent, source_name, source_handle, "rename source")?;
    let source_name = c_entry_name(source_name)?;
    let destination_name = c_entry_name(destination_name)?;
    let result = unsafe {
        libc::renameat(
            source_parent.handle.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.handle.as_raw_fd(),
            destination_name.as_ptr(),
        )
    };
    if result == 0 {
        destination_parent.sync()
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_relative_file(
    source_parent: &OpenDirectory,
    _source_name: &OsStr,
    source_handle: &File,
    destination_parent: &OpenDirectory,
    destination_name: &OsStr,
) -> std::io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::copy_nonoverlapping;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    if !Arc::ptr_eq(&source_parent.handle, &destination_parent.handle) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows atomic replacement requires one retained parent directory handle",
        ));
    }
    let destination_wide: Vec<u16> = destination_name.encode_wide().collect();
    if destination_wide.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination name is empty",
        ));
    }
    let name_bytes = destination_wide
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "name too long"))?;
    let info_size = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes.saturating_sub(size_of::<u16>()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rename metadata too large",
            )
        })?;
    let mut info = vec![0u8; info_size];
    let info_ptr = info.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
    unsafe {
        (*info_ptr).Anonymous.ReplaceIfExists = true;
        // NtSetInformationFile accepts a directory handle plus a simple
        // relative name. No absolute or process-relative destination path is
        // resolved at the commit boundary.
        (*info_ptr).RootDirectory = destination_parent.handle.as_raw_handle();
        (*info_ptr).FileNameLength = name_bytes as u32;
        copy_nonoverlapping(
            destination_wide.as_ptr(),
            (*info_ptr).FileName.as_mut_ptr(),
            destination_wide.len(),
        );
    }
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            source_handle.as_raw_handle(),
            &mut io_status,
            info_ptr.cast(),
            info.len() as u32,
            FileRenameInformation,
        )
    };
    if status < 0 {
        let win32_error = unsafe { RtlNtStatusToDosError(status) };
        let source = std::io::Error::from_raw_os_error(win32_error as i32);
        Err(std::io::Error::new(
            source.kind(),
            format!(
                "relative handle rename failed; unsafe full-path fallback is disabled: {source}"
            ),
        ))
    } else {
        destination_parent.sync()
    }
}

#[cfg(unix)]
fn remove_relative_file(
    parent: &OpenDirectory,
    name: &OsStr,
    handle: &File,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    verify_unix_name_identity(parent, name, handle, "remove target")?;
    let name = c_entry_name(name)?;
    if unsafe { libc::unlinkat(parent.handle.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        parent.sync()
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn verify_unix_name_identity(
    parent: &OpenDirectory,
    name: &OsStr,
    expected_handle: &File,
    operation: &str,
) -> std::io::Result<()> {
    let current = open_existing_file_at(parent, name)?;
    use std::os::unix::fs::MetadataExt;
    let expected = expected_handle.metadata()?;
    let actual = current.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing {operation}: opened handle no longer matches directory entry {name:?}"
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn remove_relative_file(
    parent: &OpenDirectory,
    _name: &OsStr,
    handle: &File,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let mut disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let removed = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle(),
            FileDispositionInfo,
            (&mut disposition as *mut FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if removed == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        parent.sync()
    }
}

const OLD_TRANSACTION_JOURNAL_NAME: &str = ".arc-build-transaction.json";
const OLD_CLEANUP_JOURNAL_NAME: &str = ".arc-build-cleanup.json";

/// A pending build journal exists at a retired location. It is detected by
/// presence only and is never read, migrated, moved or modified.
#[derive(Debug)]
pub struct RetiredBuildJournalRejected {
    pub path: PathBuf,
}

impl std::fmt::Display for RetiredBuildJournalRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pending build journal at retired location is not supported: {}",
            self.path.display()
        )
    }
}

impl std::error::Error for RetiredBuildJournalRejected {}

fn reject_retired_build_journals(root: &Path) -> Result<()> {
    for name in [OLD_TRANSACTION_JOURNAL_NAME, OLD_CLEANUP_JOURNAL_NAME] {
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(anyhow::Error::new(RetiredBuildJournalRejected { path }));
        }
    }
    Ok(())
}

/// Writes one complete generation and a durable manifest. A transaction
/// journal is synced before the first replacement, so a later process can
/// deterministically finish or roll back an interrupted multi-file commit.
pub fn write_artifacts<P: AsRef<Path>>(
    output_dir: P,
    artifacts: &[GeneratedArtifact],
) -> Result<BuildManifest> {
    let mut finalizer = NoopBuildFinalizer;
    write_artifacts_transactional_inner(
        output_dir,
        artifacts,
        &mut finalizer,
        |_| Ok(()),
        |_| Ok(()),
        |_| Ok(()),
    )
}

/// Durable build entry point for the production IR trust transaction. Trust
/// entries use contained relative paths and the immutable bytes emitted by the
/// compiler. Recovery compares the external SQLite digests with the journal
/// before choosing the previous or new filesystem generation.
pub fn write_artifacts_with_trust<P: AsRef<Path>>(
    output_dir: P,
    artifacts: &[GeneratedArtifact],
    store: &crate::runtime::state_store::SqliteStateStore,
    trusted_irs: &[(PathBuf, Vec<u8>)],
) -> Result<BuildManifest> {
    let mut finalizer = SqliteIrTrustFinalizer {
        store,
        entries: trusted_irs,
    };
    write_artifacts_transactional_inner(
        output_dir,
        artifacts,
        &mut finalizer,
        |_| Ok(()),
        |_| Ok(()),
        |_| Ok(()),
    )
}

#[cfg(test)]
fn write_artifacts_with_finalizer<P, F>(
    output_dir: P,
    artifacts: &[GeneratedArtifact],
    finalizer: F,
) -> Result<BuildManifest>
where
    P: AsRef<Path>,
    F: FnOnce(&BuildManifest) -> Result<()>,
{
    let mut finalizer = ClosureBuildFinalizer::new(finalizer);
    write_artifacts_transactional_inner(
        output_dir,
        artifacts,
        &mut finalizer,
        |_| Ok(()),
        |_| Ok(()),
        |_| Ok(()),
    )
}

/// Recovers an interrupted production build before a new build or hook reads
/// generated state. A malformed journal, unexpected hash, or mixed trust state
/// is rejected without modifying further files.
pub fn recover_pending_build<P: AsRef<Path>>(
    output_dir: P,
    store: &crate::runtime::state_store::SqliteStateStore,
) -> Result<()> {
    reject_retired_build_journals(output_dir.as_ref())?;
    let (output, _build_lock) = open_output_for_transaction(output_dir.as_ref(), false)?;
    recover_cleanup_journal(&output)?;
    let finalizer = SqliteRecoveryFinalizer { store };
    recover_pending_transaction(&output, &finalizer)
}

fn write_artifacts_transactional_inner<P, D, O, H, S>(
    output_dir: P,
    artifacts: &[GeneratedArtifact],
    finalizer: &mut D,
    mut observer: O,
    mut after_parent_validated: H,
    mut after_temp_staged: S,
) -> Result<BuildManifest>
where
    P: AsRef<Path>,
    D: DurableBuildFinalizer,
    O: FnMut(&TransactionCheckpoint) -> Result<()>,
    H: FnMut(&Path) -> Result<()>,
    S: FnMut(&Path) -> Result<()>,
{
    reject_retired_build_journals(output_dir.as_ref())?;
    let (output, _build_lock) = open_output_for_transaction(output_dir.as_ref(), true)?;
    recover_cleanup_journal(&output)?;
    recover_pending_transaction(&output, finalizer)?;

    let mut destinations = Vec::with_capacity(artifacts.len());
    let mut seen_targets = std::collections::BTreeSet::new();
    for artifact in artifacts {
        validate_artifact_target(&artifact.relative_path)?;
        let normalized = normalize_relative_path(&artifact.relative_path);
        if !seen_targets.insert(normalized.clone()) {
            bail!("duplicate artifact target in build transaction: {normalized}");
        }
        let destination = output
            .resolve_destination(&artifact.relative_path, true)
            .with_context(|| format!("failed opening artifact target {normalized:?}"))?;
        validate_arc_owned_destination(artifact, &destination)?;
        after_parent_validated(&destination.parent.display_path)?;
        destinations.push(destination);
    }

    let (manifest, manifest_bytes) = build_manifest_snapshot(&output, artifacts)?;
    let mut prepared = Vec::with_capacity(artifacts.len() + 1);
    for (artifact, destination) in artifacts.iter().zip(destinations) {
        let item = match prepare_transaction_file(
            destination,
            artifact.content.as_bytes(),
            artifact.is_executable,
            TransactionFileKind::Artifact,
            ".tmp_arc_",
            ".tmp_backup_",
        ) {
            Ok(item) => item,
            Err(error) => {
                return Err(cleanup_unpublished_transaction(error, prepared));
            }
        };
        if let Err(error) = after_temp_staged(&item.temp.display_path()) {
            prepared.push(item);
            return Err(cleanup_unpublished_transaction(error, prepared));
        }
        prepared.push(item);
    }

    let manifest_destination = output
        .resolve_destination(Path::new(BUILD_MANIFEST_FILE), false)
        .context("failed resolving build manifest destination")?;
    match prepare_transaction_file(
        manifest_destination,
        &manifest_bytes,
        false,
        TransactionFileKind::Manifest,
        ".tmp_build_manifest_",
        ".tmp_manifest_backup_",
    ) {
        Ok(item) => prepared.push(item),
        Err(error) => return Err(cleanup_unpublished_transaction(error, prepared)),
    }

    let files: Vec<TransactionFileRecord> =
        prepared.iter().map(|item| item.record.clone()).collect();
    let trusted_irs = match finalizer.plan(&output, &files) {
        Ok(entries) => entries,
        Err(error) => return Err(cleanup_unpublished_transaction(error, prepared)),
    };
    let mut journal = BuildTransactionJournal {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id: uuid::Uuid::new_v4().to_string(),
        state: BuildTransactionState::Prepared,
        files,
        trusted_irs,
    };
    validate_transaction_journal(&journal)?;

    if let Err(error) = observer(&TransactionCheckpoint::BeforeJournalPublish) {
        return Err(cleanup_unpublished_transaction(error, prepared));
    }
    if let Err(error) = persist_transaction_journal(&output, &journal) {
        return Err(cleanup_unpublished_transaction(error, prepared));
    }
    if let Err(error) = observer(&TransactionCheckpoint::AfterJournalPublish) {
        drop(prepared);
        return recover_after_transaction_error(error, &output, finalizer);
    }

    let execution = execute_transaction(
        &output,
        &manifest,
        &mut journal,
        prepared,
        finalizer,
        &mut observer,
    );
    match execution {
        Ok(()) => Ok(manifest),
        Err(error) => recover_after_transaction_error(error, &output, finalizer),
    }
}

fn open_output_for_transaction(
    requested_base: &Path,
    create: bool,
) -> Result<(OpenDirectory, BuildDirectoryLock)> {
    if create {
        fs::create_dir_all(requested_base)
            .with_context(|| format!("failed creating output directory {requested_base:?}"))?;
    }
    reject_indirected_components(requested_base, "output root")?;
    reject_indirected_path(requested_base, "output root")?;
    let canonical_base = requested_base
        .canonicalize()
        .with_context(|| format!("failed canonicalizing output directory {requested_base:?}"))?;
    let output = OpenDirectory::open_root(&canonical_base)
        .with_context(|| format!("failed opening output directory {canonical_base:?}"))?;
    let lock = output
        .acquire_build_lock()
        .with_context(|| format!("failed acquiring build lock in {canonical_base:?}"))?;
    Ok((output, lock))
}

fn execute_transaction<D, O>(
    output: &OpenDirectory,
    manifest: &BuildManifest,
    journal: &mut BuildTransactionJournal,
    prepared: Vec<PreparedTransactionFile>,
    finalizer: &mut D,
    observer: &mut O,
) -> Result<()>
where
    D: DurableBuildFinalizer,
    O: FnMut(&TransactionCheckpoint) -> Result<()>,
{
    journal.state = BuildTransactionState::Committing;
    persist_transaction_journal(output, journal)?;
    observer(&TransactionCheckpoint::BeforeFirstReplace)?;

    for (index, mut item) in prepared.into_iter().enumerate() {
        item.temp
            .rename_replace(&item.destination.parent, &item.destination.name)
            .with_context(|| format!("failed publishing {:?}", item.destination.display_path()))?;
        observer(&TransactionCheckpoint::AfterReplace {
            index,
            target: item.record.target.clone(),
        })?;
        if item.record.kind == TransactionFileKind::Manifest {
            observer(&TransactionCheckpoint::AfterManifestReplace)?;
        }
    }

    journal.state = BuildTransactionState::Committed;
    persist_transaction_journal(output, journal)?;
    observer(&TransactionCheckpoint::BeforeFinalizer)?;
    finalizer
        .commit(output, manifest)
        .context("external finalizer failed")?;
    observer(&TransactionCheckpoint::AfterFinalizer)?;

    journal.state = BuildTransactionState::TrustRegistered;
    persist_transaction_journal(output, journal)?;
    journal.state = BuildTransactionState::Cleanup;
    persist_transaction_journal(output, journal)?;
    cleanup_transaction_files(output, journal, observer)?;

    journal.state = BuildTransactionState::Complete;
    persist_transaction_journal(output, journal)?;
    remove_transaction_journal(output)
}

fn prepare_transaction_file(
    destination: OpenedDestination,
    bytes: &[u8],
    is_executable: bool,
    kind: TransactionFileKind,
    temp_prefix: &str,
    backup_prefix: &str,
) -> Result<PreparedTransactionFile> {
    let mut temp = destination
        .create_transaction_file(temp_prefix)
        .with_context(|| {
            format!(
                "failed creating staged file for {:?}",
                destination.display_path()
            )
        })?;
    if let Err(error) = temp.write_and_sync(bytes) {
        let cleanup = temp.remove().err().map(anyhow::Error::new);
        return Err(combine_failures(
            anyhow::Error::new(error)
                .context(format!("failed staging {:?}", destination.display_path())),
            None,
            cleanup,
        ));
    }
    #[cfg(not(unix))]
    let _ = is_executable;
    #[cfg(unix)]
    if is_executable {
        let permission_result = (|| -> std::io::Result<()> {
            let mut permissions = temp.handle.metadata()?.permissions();
            permissions.set_mode(0o755);
            temp.handle.set_permissions(permissions)?;
            temp.handle.sync_all()
        })();
        if let Err(error) = permission_result {
            let cleanup = temp.remove().err().map(anyhow::Error::new);
            return Err(combine_failures(
                anyhow::Error::new(error).context(format!(
                    "failed setting permissions on {:?}",
                    temp.display_path()
                )),
                None,
                cleanup,
            ));
        }
    }

    let (backup, previous_sha256) = match destination.open_existing()? {
        Some(mut existing) => {
            let previous = existing.read_all().with_context(|| {
                format!(
                    "failed reading previous file {:?}",
                    destination.display_path()
                )
            })?;
            let mut backup = match destination.create_transaction_file(backup_prefix) {
                Ok(backup) => backup,
                Err(error) => {
                    let cleanup = temp.remove().err().map(anyhow::Error::new);
                    return Err(combine_failures(
                        anyhow::Error::new(error).context(format!(
                            "failed creating backup for {:?}",
                            destination.display_path()
                        )),
                        None,
                        cleanup,
                    ));
                }
            };
            if let Err(error) = existing.copy_to(&mut backup) {
                let temp_cleanup = temp.remove().err().map(anyhow::Error::new);
                let backup_cleanup = backup.remove().err().map(anyhow::Error::new);
                return Err(combine_failures(
                    anyhow::Error::new(error).context(format!(
                        "failed backing up {:?}",
                        destination.display_path()
                    )),
                    backup_cleanup,
                    temp_cleanup,
                ));
            }
            (Some(backup), Some(sha256_bytes(&previous)))
        }
        None => (None, None),
    };
    let target = normalize_relative_path(&destination.parent.relative_path.join(&destination.name));
    let record = TransactionFileRecord {
        kind,
        target,
        temp: normalize_relative_path(&temp.relative_path()),
        backup: backup
            .as_ref()
            .map(|file| normalize_relative_path(&file.relative_path())),
        previous_sha256,
        new_sha256: sha256_bytes(bytes),
    };
    Ok(PreparedTransactionFile {
        destination,
        temp,
        backup,
        record,
    })
}

fn cleanup_unpublished_transaction(
    base: anyhow::Error,
    prepared: Vec<PreparedTransactionFile>,
) -> anyhow::Error {
    let mut cleanup = None;
    for item in prepared {
        if let Err(error) = item.temp.remove() {
            cleanup = Some(anyhow::Error::new(error).context("failed removing staged file"));
        }
        if let Some(backup) = item.backup
            && let Err(error) = backup.remove()
        {
            cleanup = Some(anyhow::Error::new(error).context("failed removing unpublished backup"));
        }
    }
    combine_failures(base, None, cleanup)
}

fn recover_after_transaction_error<D: DurableBuildFinalizer>(
    error: anyhow::Error,
    output: &OpenDirectory,
    finalizer: &D,
) -> Result<BuildManifest> {
    match recover_pending_transaction(output, finalizer) {
        Ok(()) => Err(anyhow::anyhow!(
            "build transaction failed: {error:#}; durable recovery restored a complete generation"
        )),
        Err(recovery) => Err(anyhow::anyhow!(
            "{error:#}; durable recovery failed closed: {recovery:#}"
        )),
    }
}

fn combine_failures(
    base: anyhow::Error,
    rollback: Option<anyhow::Error>,
    cleanup: Option<anyhow::Error>,
) -> anyhow::Error {
    match (rollback, cleanup) {
        (Some(rollback), Some(cleanup)) => {
            anyhow::anyhow!("{base:#}; rollback failed: {rollback:#}; cleanup failed: {cleanup:#}")
        }
        (Some(rollback), None) => anyhow::anyhow!("{base:#}; rollback failed: {rollback:#}"),
        (None, Some(cleanup)) => anyhow::anyhow!("{base:#}; cleanup failed: {cleanup:#}"),
        (None, None) => base,
    }
}

fn validate_artifact_target(relative: &Path) -> Result<()> {
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!(
            "artifact path {relative:?} violates containment: only normal relative components are allowed"
        );
    }
    if relative.to_str().is_none() {
        bail!("artifact path must be valid Unicode for durable journaling: {relative:?}");
    }
    let normalized = normalize_relative_path(relative);
    if matches!(
        normalized.as_str(),
        BUILD_MANIFEST_FILE | TRANSACTION_JOURNAL_FILE | CLEANUP_JOURNAL_FILE | BUILD_LOCK_PATH
    ) {
        bail!("artifact target {relative:?} collides with Arc transaction metadata");
    }
    Ok(())
}

fn validate_transaction_relative_path(relative: &Path, kind: &str) -> Result<()> {
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("{kind} path must contain only normal relative components: {relative:?}");
    }
    Ok(())
}

fn normalize_relative_path(relative: &Path) -> String {
    relative.to_string_lossy().replace('\\', "/")
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_sha256(digest: &str, label: &str) -> Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} is not a lowercase SHA-256 digest");
    }
    if digest.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("{label} must use lowercase hexadecimal");
    }
    Ok(())
}

fn validate_arc_owned_destination(
    artifact: &GeneratedArtifact,
    destination: &OpenedDestination,
) -> Result<()> {
    if !is_arc_owned_codex_artifact(&artifact.relative_path) {
        return Ok(());
    }
    let Some(mut existing) = destination.open_existing().with_context(|| {
        format!(
            "failed inspecting existing artifact {:?}",
            destination.display_path()
        )
    })?
    else {
        return Ok(());
    };
    let bytes = existing.read_all().with_context(|| {
        format!(
            "failed reading existing artifact {:?}",
            destination.display_path()
        )
    })?;
    let content = String::from_utf8(bytes).with_context(|| {
        format!(
            "existing Arc-owned artifact is not UTF-8: {:?}",
            destination.display_path()
        )
    })?;
    if !content.contains("Auto-generated by Arc")
        && !content.contains("Auto-generated Arc runtime guard hooks")
    {
        bail!(
            "Refusing to overwrite non-Arc Codex configuration at {:?}. Move or merge it explicitly before rebuilding.",
            destination.display_path()
        );
    }
    Ok(())
}

fn persist_transaction_journal(
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
) -> Result<()> {
    validate_transaction_journal(journal)?;
    let bytes = serde_json::to_vec_pretty(journal).context("failed serializing build journal")?;
    let destination = output.resolve_destination(Path::new(TRANSACTION_JOURNAL_FILE), true)?;
    let mut temp = destination
        .parent
        .create_new_file(&OsString::from(format!(
            ".tmp_transaction_journal_{}.tmp",
            uuid::Uuid::new_v4()
        )))
        .context("failed creating transaction journal temp")?;
    if let Err(error) = temp.write_and_sync(&bytes) {
        let cleanup = temp.remove().err().map(anyhow::Error::new);
        return Err(combine_failures(
            anyhow::Error::new(error).context("failed syncing transaction journal temp"),
            None,
            cleanup,
        ));
    }
    if let Err(error) = temp.rename_replace(&destination.parent, &destination.name) {
        let cleanup = temp.remove().err().map(anyhow::Error::new);
        return Err(combine_failures(
            anyhow::Error::new(error).context("failed publishing durable transaction journal"),
            None,
            cleanup,
        ));
    }
    Ok(())
}

fn load_transaction_journal(output: &OpenDirectory) -> Result<Option<BuildTransactionJournal>> {
    let destination = output.resolve_destination(Path::new(TRANSACTION_JOURNAL_FILE), false)?;
    let Some(mut file) = destination.open_existing()? else {
        return Ok(None);
    };
    let bytes = file
        .read_all()
        .context("failed reading pending build transaction journal")?;
    let journal: BuildTransactionJournal =
        serde_json::from_slice(&bytes).context("pending build transaction journal is malformed")?;
    validate_transaction_journal(&journal)?;
    Ok(Some(journal))
}

fn remove_transaction_journal(output: &OpenDirectory) -> Result<()> {
    let destination = output.resolve_destination(Path::new(TRANSACTION_JOURNAL_FILE), false)?;
    if let Some(file) = destination.open_existing()? {
        file.remove()
            .context("failed removing completed build transaction journal")?;
    }
    Ok(())
}

fn validate_transaction_journal(journal: &BuildTransactionJournal) -> Result<()> {
    if journal.schema_version != TRANSACTION_SCHEMA_VERSION {
        bail!(
            "unsupported build transaction journal schema {}",
            journal.schema_version
        );
    }
    uuid::Uuid::parse_str(&journal.transaction_id)
        .context("build transaction journal has an invalid transaction ID")?;
    if journal.files.is_empty() {
        bail!("build transaction journal contains no files");
    }

    let mut all_paths = BTreeSet::new();
    let mut target_hashes = BTreeMap::new();
    let mut manifest_count = 0usize;
    for record in &journal.files {
        let target = Path::new(&record.target);
        let temp = Path::new(&record.temp);
        validate_transaction_relative_path(target, "transaction target")?;
        validate_transaction_relative_path(temp, "transaction temp")?;
        validate_sha256(&record.new_sha256, "new file hash")?;
        if let Some(previous) = &record.previous_sha256 {
            validate_sha256(previous, "previous file hash")?;
        }
        if record.previous_sha256.is_some() != record.backup.is_some() {
            bail!("transaction backup presence does not match previous file hash");
        }
        if target.parent() != temp.parent() {
            bail!(
                "transaction temp is not beside its target: {:?}",
                record.temp
            );
        }
        let temp_name = temp.file_name().and_then(OsStr::to_str).unwrap_or_default();
        let expected_temp_prefix = match record.kind {
            TransactionFileKind::Artifact => ".tmp_arc_",
            TransactionFileKind::Manifest => ".tmp_build_manifest_",
        };
        if !temp_name.starts_with(expected_temp_prefix) || !temp_name.ends_with(".tmp") {
            bail!(
                "transaction contains an invalid staged filename: {:?}",
                record.temp
            );
        }
        if let Some(backup) = &record.backup {
            let backup_path = Path::new(backup);
            validate_transaction_relative_path(backup_path, "transaction backup")?;
            if target.parent() != backup_path.parent() {
                bail!("transaction backup is not beside its target: {backup:?}");
            }
            let backup_name = backup_path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let expected_backup_prefix = match record.kind {
                TransactionFileKind::Artifact => ".tmp_backup_",
                TransactionFileKind::Manifest => ".tmp_manifest_backup_",
            };
            if !backup_name.starts_with(expected_backup_prefix) || !backup_name.ends_with(".tmp") {
                bail!("transaction contains an invalid backup filename: {backup:?}");
            }
            if !all_paths.insert(backup.clone()) {
                bail!("duplicate path in build transaction journal: {backup:?}");
            }
        }
        if !all_paths.insert(record.target.clone()) || !all_paths.insert(record.temp.clone()) {
            bail!("duplicate path in build transaction journal");
        }
        match record.kind {
            TransactionFileKind::Artifact => validate_artifact_target(target)?,
            TransactionFileKind::Manifest => {
                manifest_count += 1;
                if record.target != BUILD_MANIFEST_FILE {
                    bail!("manifest transaction record has the wrong target");
                }
            }
        }
        target_hashes.insert(record.target.as_str(), record.new_sha256.as_str());
    }
    if manifest_count != 1 {
        bail!("build transaction journal must contain exactly one manifest record");
    }

    let mut trust_paths = BTreeSet::new();
    for trust in &journal.trusted_irs {
        let path = Path::new(&trust.ir_path);
        validate_transaction_relative_path(path, "trusted IR")?;
        validate_sha256(&trust.new_sha256, "new trusted IR hash")?;
        if let Some(previous) = &trust.previous_sha256 {
            validate_sha256(previous, "previous trusted IR hash")?;
        }
        if !trust_paths.insert(trust.ir_path.clone()) {
            bail!("duplicate trusted IR path in build transaction journal");
        }
        if target_hashes.get(trust.ir_path.as_str()) != Some(&trust.new_sha256.as_str()) {
            bail!("trusted IR does not match a generated transaction file");
        }
    }
    Ok(())
}

fn classify_sqlite_trust(
    store: &crate::runtime::state_store::SqliteStateStore,
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
) -> Result<ExternalTrustState> {
    if journal.trusted_irs.is_empty() {
        return Ok(ExternalTrustState::NotApplicable);
    }
    let mut previous = 0usize;
    let mut new = 0usize;
    for trust in &journal.trusted_irs {
        let current =
            store.trusted_ir_digest_for_exact_path(&output.display_path.join(&trust.ir_path))?;
        if trust.previous_sha256.as_deref() == Some(trust.new_sha256.as_str())
            && current.as_deref() == Some(trust.new_sha256.as_str())
        {
            continue;
        }
        if current.as_deref() == Some(trust.new_sha256.as_str()) {
            new += 1;
        } else if current == trust.previous_sha256 {
            previous += 1;
        } else {
            return Ok(ExternalTrustState::Ambiguous);
        }
    }
    Ok(match (previous, new) {
        (0, 0) | (0, _) => ExternalTrustState::New,
        (_, 0) => ExternalTrustState::Previous,
        _ => ExternalTrustState::Ambiguous,
    })
}

fn recover_pending_transaction<D: DurableBuildFinalizer>(
    output: &OpenDirectory,
    finalizer: &D,
) -> Result<()> {
    let Some(mut journal) = load_transaction_journal(output)? else {
        return Ok(());
    };
    let trust = finalizer.classify(output, &journal)?;
    let keep_new = match journal.state {
        BuildTransactionState::Prepared => match trust {
            ExternalTrustState::NotApplicable | ExternalTrustState::Previous => false,
            ExternalTrustState::New | ExternalTrustState::Ambiguous => {
                bail!("prepared transaction has ambiguous or prematurely updated trust state")
            }
        },
        BuildTransactionState::Committing | BuildTransactionState::Committed => match trust {
            ExternalTrustState::NotApplicable | ExternalTrustState::Previous => false,
            ExternalTrustState::New => true,
            ExternalTrustState::Ambiguous => {
                bail!("interrupted transaction has a mixed external trust state")
            }
        },
        BuildTransactionState::TrustRegistered
        | BuildTransactionState::Cleanup
        | BuildTransactionState::Complete => match trust {
            ExternalTrustState::NotApplicable | ExternalTrustState::New => true,
            ExternalTrustState::Previous | ExternalTrustState::Ambiguous => {
                bail!("committed transaction contradicts external trust state")
            }
        },
    };

    preflight_recovery(output, &journal, keep_new)?;
    if keep_new {
        complete_new_generation(output, &journal)?;
        journal.state = BuildTransactionState::Cleanup;
        persist_transaction_journal(output, &journal)?;
        cleanup_transaction_files(output, &journal, &mut |_| Ok(()))?;
        journal.state = BuildTransactionState::Complete;
        persist_transaction_journal(output, &journal)?;
        remove_transaction_journal(output)
    } else {
        restore_previous_generation(output, &journal)?;
        remove_transaction_journal(output)
    }
}

fn preflight_recovery(
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
    keep_new: bool,
) -> Result<()> {
    for record in &journal.files {
        let destination = output.resolve_destination(Path::new(&record.target), false)?;
        let target = destination_hash(&destination)?;
        let mut temp = open_sibling(&destination, Path::new(&record.temp))?;
        if let Some(file) = temp.as_mut() {
            verify_open_file_hash(file, &record.new_sha256, "staged file")?;
        }
        let mut backup = match &record.backup {
            Some(path) => open_sibling(&destination, Path::new(path))?,
            None => None,
        };
        if let (Some(file), Some(previous)) = (backup.as_mut(), &record.previous_sha256) {
            verify_open_file_hash(file, previous, "transaction backup")?;
        }

        if keep_new {
            if target.as_deref() == Some(record.new_sha256.as_str()) {
                continue;
            }
            if target != record.previous_sha256 && target.is_some() {
                bail!("transaction target {:?} has an unknown hash", record.target);
            }
            if temp.is_none() {
                bail!(
                    "missing staged file required to complete {:?}",
                    record.target
                );
            }
            continue;
        }

        match &record.previous_sha256 {
            Some(previous) => {
                if target.as_deref() == Some(previous.as_str()) {
                    continue;
                }
                if target.as_deref() != Some(record.new_sha256.as_str()) && target.is_some() {
                    bail!("transaction target {:?} has an unknown hash", record.target);
                }
                if backup.is_none() {
                    bail!("missing backup required to restore {:?}", record.target);
                }
            }
            None => {
                if target.as_deref() != Some(record.new_sha256.as_str()) && target.is_some() {
                    bail!(
                        "new transaction target {:?} has an unknown hash",
                        record.target
                    );
                }
            }
        }
    }
    Ok(())
}

fn complete_new_generation(
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
) -> Result<()> {
    for record in &journal.files {
        let destination = output.resolve_destination(Path::new(&record.target), false)?;
        let current = destination_hash(&destination)?;
        if current.as_deref() == Some(record.new_sha256.as_str()) {
            remove_sibling_if_hash(&destination, Path::new(&record.temp), &record.new_sha256)?;
            continue;
        }
        if current != record.previous_sha256 && current.is_some() {
            bail!("transaction target {:?} has an unknown hash", record.target);
        }
        let mut temp = open_sibling(&destination, Path::new(&record.temp))?
            .ok_or_else(|| anyhow::anyhow!("missing staged file for {:?}", record.target))?;
        verify_open_file_hash(&mut temp, &record.new_sha256, "staged file")?;
        temp.rename_replace(&destination.parent, &destination.name)
            .with_context(|| format!("failed completing transaction target {:?}", record.target))?;
    }
    verify_generation(output, journal, true)
}

fn restore_previous_generation(
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
) -> Result<()> {
    for record in journal.files.iter().rev() {
        let destination = output.resolve_destination(Path::new(&record.target), false)?;
        let current = destination_hash(&destination)?;
        match &record.previous_sha256 {
            Some(previous) => {
                if current.as_deref() != Some(previous.as_str()) {
                    if current.as_deref() != Some(record.new_sha256.as_str()) && current.is_some() {
                        bail!("transaction target {:?} has an unknown hash", record.target);
                    }
                    let backup_path = record
                        .backup
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("missing backup metadata"))?;
                    let mut backup = open_sibling(&destination, Path::new(backup_path))?
                        .ok_or_else(|| anyhow::anyhow!("missing backup for {:?}", record.target))?;
                    verify_open_file_hash(&mut backup, previous, "transaction backup")?;
                    backup
                        .rename_replace(&destination.parent, &destination.name)
                        .with_context(|| format!("failed restoring {:?}", record.target))?;
                }
            }
            None => {
                if current.as_deref() == Some(record.new_sha256.as_str()) {
                    destination
                        .open_existing()?
                        .ok_or_else(|| anyhow::anyhow!("transaction target disappeared"))?
                        .remove()
                        .with_context(|| {
                            format!("failed removing new target {:?}", record.target)
                        })?;
                } else if current.is_some() {
                    bail!(
                        "new transaction target {:?} has an unknown hash",
                        record.target
                    );
                }
            }
        }
        remove_sibling_if_hash(&destination, Path::new(&record.temp), &record.new_sha256)?;
        if let (Some(backup), Some(previous)) = (&record.backup, &record.previous_sha256) {
            remove_sibling_if_hash(&destination, Path::new(backup), previous)?;
        }
    }
    verify_generation(output, journal, false)
}

fn verify_generation(
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
    expect_new: bool,
) -> Result<()> {
    for record in &journal.files {
        let destination = output.resolve_destination(Path::new(&record.target), false)?;
        let actual = destination_hash(&destination)?;
        let expected = if expect_new {
            Some(record.new_sha256.as_str())
        } else {
            record.previous_sha256.as_deref()
        };
        if actual.as_deref() != expected {
            bail!(
                "transaction recovery could not verify {:?}: expected {:?}, got {:?}",
                record.target,
                expected,
                actual
            );
        }
    }
    Ok(())
}

fn destination_hash(destination: &OpenedDestination) -> Result<Option<String>> {
    let Some(mut file) = destination.open_existing()? else {
        return Ok(None);
    };
    Ok(Some(sha256_bytes(&file.read_all()?)))
}

fn open_sibling(
    destination: &OpenedDestination,
    sibling_path: &Path,
) -> Result<Option<OpenRelativeFile>> {
    let sibling_parent = sibling_path.parent().unwrap_or_else(|| Path::new(""));
    let target_parent =
        Path::new(&normalize_relative_path(&destination.parent.relative_path)).to_path_buf();
    if normalize_relative_path(sibling_parent) != normalize_relative_path(&target_parent) {
        bail!("transaction sibling is not in the retained target directory");
    }
    let name = sibling_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("transaction sibling has no filename"))?;
    destination
        .parent
        .open_existing_file(name)
        .map_err(anyhow::Error::new)
}

fn verify_open_file_hash(file: &mut OpenRelativeFile, expected: &str, label: &str) -> Result<()> {
    let actual = sha256_bytes(&file.read_all()?);
    if actual != expected {
        bail!("{label} {:?} has an unexpected hash", file.display_path());
    }
    Ok(())
}

fn remove_sibling_if_hash(
    destination: &OpenedDestination,
    sibling: &Path,
    expected: &str,
) -> Result<()> {
    let Some(mut file) = open_sibling(destination, sibling)? else {
        return Ok(());
    };
    verify_open_file_hash(&mut file, expected, "transaction cleanup file")?;
    file.remove()
        .with_context(|| format!("failed removing transaction file {sibling:?}"))
}

fn cleanup_transaction_files<O>(
    output: &OpenDirectory,
    journal: &BuildTransactionJournal,
    observer: &mut O,
) -> Result<()>
where
    O: FnMut(&TransactionCheckpoint) -> Result<()>,
{
    for (index, record) in journal.files.iter().enumerate() {
        remove_sibling_if_hash(
            &output.resolve_destination(Path::new(&record.target), false)?,
            Path::new(&record.temp),
            &record.new_sha256,
        )?;
        let (Some(backup), Some(previous)) = (&record.backup, &record.previous_sha256) else {
            continue;
        };
        observer(&TransactionCheckpoint::BeforeBackupCleanup {
            index,
            backup: backup.clone(),
        })?;
        remove_sibling_if_hash(
            &output.resolve_destination(Path::new(&record.target), false)?,
            Path::new(backup),
            previous,
        )?;
        observer(&TransactionCheckpoint::AfterBackupCleanup {
            index,
            backup: backup.clone(),
        })?;
    }
    Ok(())
}

fn metadata_is_indirected(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
fn write_cleanup_journal(output: &OpenDirectory, files: &[PathBuf]) -> Result<()> {
    let mut relative_files = Vec::with_capacity(files.len());
    for relative in files {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("Cleanup journal path {relative:?} is not a contained relative path");
        }
        let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
            bail!("Cleanup journal path {relative:?} has no valid file name");
        };
        if !name.starts_with(".tmp_backup_") && !name.starts_with(".tmp_manifest_backup_") {
            bail!("Refusing to journal non-transaction file {relative:?}");
        }
        relative_files.push(relative.to_string_lossy().to_string());
    }

    let journal = serde_json::to_vec(&CleanupJournal {
        files: relative_files,
    })
    .context("Failed serializing cleanup journal")?;
    let destination = output.resolve_destination(Path::new(CLEANUP_JOURNAL_FILE), true)?;
    let temp_name = OsString::from(format!(".tmp_cleanup_{}.tmp", uuid::Uuid::new_v4()));
    let mut temp = destination
        .parent
        .create_new_file(&temp_name)
        .context("Failed creating cleanup journal temp")?;
    if let Err(error) = temp.write_and_sync(&journal) {
        let cleanup = temp.remove().err();
        return Err(anyhow::Error::new(error).context(match cleanup {
            Some(cleanup) => format!("Cleanup journal temp removal also failed: {cleanup}"),
            None => "Cleanup journal temp removed".to_string(),
        }));
    }
    if let Err(error) = temp.rename_replace(&destination.parent, &destination.name) {
        let cleanup = temp.remove().err();
        return Err(anyhow::Error::new(error).context(match cleanup {
            Some(cleanup) => format!(
                "Failed publishing cleanup journal {:?}; temporary journal cleanup also failed: {cleanup}",
                destination.display_path()
            ),
            None => format!(
                "Failed publishing cleanup journal {:?}; temporary journal removed",
                destination.display_path()
            ),
        }));
    }
    Ok(())
}

fn recover_cleanup_journal(output: &OpenDirectory) -> Result<()> {
    let journal_destination = output.resolve_destination(Path::new(CLEANUP_JOURNAL_FILE), false)?;
    let Some(mut journal_file) = journal_destination.open_existing().with_context(|| {
        format!(
            "Failed inspecting cleanup journal {:?}",
            journal_destination.display_path()
        )
    })?
    else {
        return Ok(());
    };
    let bytes = journal_file.read_all().with_context(|| {
        format!(
            "Failed reading cleanup journal {:?}",
            journal_destination.display_path()
        )
    })?;
    let journal: CleanupJournal = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "Cleanup journal {:?} is malformed",
            journal_destination.display_path()
        )
    })?;
    for relative in &journal.files {
        let relative_path = PathBuf::from(&relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("Cleanup journal contains an escaping path: {:?}", relative);
        }
        let Some(name) = relative_path.file_name().and_then(|name| name.to_str()) else {
            bail!("Cleanup journal contains a nameless path: {:?}", relative);
        };
        if !name.starts_with(".tmp_backup_") && !name.starts_with(".tmp_manifest_backup_") {
            bail!(
                "Cleanup journal contains a non-transaction path: {:?}",
                relative
            );
        }
    }
    bail!(
        "legacy cleanup journal {:?} lacks transaction state and target hashes; backups were preserved and ARC cannot recover it automatically",
        journal_destination.display_path()
    )
}

fn reject_indirected_path(path: &Path, resource_name: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Failed inspecting {resource_name} at {path:?}"))?;
    if metadata_is_indirected(&metadata) {
        bail!("Refusing {resource_name} through a symlink or reparse point: {path:?}");
    }
    if !metadata.is_dir() {
        bail!("{resource_name} is not a directory: {path:?}");
    }
    Ok(())
}

fn reject_indirected_components(path: &Path, resource_name: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        if component == std::path::Component::CurDir {
            continue;
        }
        if component == std::path::Component::ParentDir {
            bail!("Refusing parent traversal in {resource_name}: {path:?}");
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata_is_indirected(&metadata) => {
                bail!(
                    "Refusing symlink or reparse point in {resource_name}: {:?}",
                    current
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed inspecting {resource_name} path component {:?}",
                        current
                    )
                });
            }
        }
    }
    Ok(())
}

fn build_manifest_snapshot(
    output: &OpenDirectory,
    artifacts: &[GeneratedArtifact],
) -> Result<(BuildManifest, Vec<u8>)> {
    let destination = output.resolve_destination(Path::new(BUILD_MANIFEST_FILE), false)?;
    let mut artifact_map: BTreeMap<String, BuildArtifactRecord> = BTreeMap::new();
    let mut previous_records = Vec::new();

    if let Some(mut existing) = destination.open_existing()? {
        let bytes = existing.read_all().with_context(|| {
            format!(
                "Failed reading existing build manifest {:?}",
                destination.display_path()
            )
        })?;
        let existing_manifest =
            serde_json::from_slice::<BuildManifest>(&bytes).with_context(|| {
                format!(
                    "Failed parsing existing build manifest {:?}",
                    destination.display_path()
                )
            })?;
        previous_records = existing_manifest.artifacts;
    }

    for record in previous_records {
        artifact_map.insert(record.relative_path.clone(), record);
    }

    for artifact in artifacts {
        let norm_rel = artifact.relative_path.to_string_lossy().replace('\\', "/");
        let bytes = artifact.content.as_bytes();
        artifact_map.insert(
            norm_rel.clone(),
            BuildArtifactRecord {
                relative_path: norm_rel,
                sha256: sha256_bytes(bytes),
                size_bytes: bytes.len() as u64,
                is_executable: artifact.is_executable,
            },
        );
    }

    let manifest = BuildManifest {
        schema_version: "1.0".into(),
        arc_version: env!("CARGO_PKG_VERSION").into(),
        generated_at: current_iso8601_timestamp(),
        artifacts: artifact_map.into_values().collect(),
    };
    let bytes =
        serde_json::to_vec_pretty(&manifest).context("Failed serializing build manifest")?;
    Ok((manifest, bytes))
}

fn current_iso8601_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
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

#[cfg(unix)]
fn open_directory_without_links(path: &Path) -> std::io::Result<libc::c_int> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = CString::new(b"/".as_slice()).expect("literal root path cannot contain NUL");
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::open(root.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for component in absolute.components() {
        let std::path::Component::Normal(name) = component else {
            if matches!(
                component,
                std::path::Component::RootDir | std::path::Component::CurDir
            ) {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory path contains parent traversal",
            ));
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            unsafe { libc::close(fd) };
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL")
        })?;
        let next = unsafe { libc::openat(fd, name.as_ptr(), flags) };
        if next < 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        unsafe { libc::close(fd) };
        fd = next;
    }
    Ok(fd)
}

fn is_arc_owned_codex_artifact(path: &Path) -> bool {
    path == Path::new(".codex/hooks.json") || path == Path::new(".codex/rules/arc-generated.rules")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{OsTarget, ProviderTarget};

    fn m8_artifacts(generation: &str) -> Vec<GeneratedArtifact> {
        vec![
            GeneratedArtifact {
                provider: ProviderTarget::Codex,
                target_os: OsTarget::host().unwrap(),
                relative_path: "first.txt".into(),
                content: format!("{generation}-first"),
                is_executable: false,
            },
            GeneratedArtifact {
                provider: ProviderTarget::Gemini,
                target_os: OsTarget::host().unwrap(),
                relative_path: "second.txt".into(),
                content: format!("{generation}-second"),
                is_executable: false,
            },
        ]
    }

    fn assert_m8_generation(root: &Path, generation: &str) {
        assert_eq!(
            fs::read_to_string(root.join("first.txt")).unwrap(),
            format!("{generation}-first")
        );
        assert_eq!(
            fs::read_to_string(root.join("second.txt")).unwrap(),
            format!("{generation}-second")
        );
        let manifest: BuildManifest = serde_json::from_slice(
            &fs::read(root.join(BUILD_MANIFEST_FILE)).expect("read recovered manifest"),
        )
        .expect("parse recovered manifest");
        let records: BTreeMap<_, _> = manifest
            .artifacts
            .iter()
            .map(|record| (record.relative_path.as_str(), record.sha256.as_str()))
            .collect();
        assert_eq!(
            records.get("first.txt").copied(),
            Some(sha256_bytes(format!("{generation}-first").as_bytes()).as_str())
        );
        assert_eq!(
            records.get("second.txt").copied(),
            Some(sha256_bytes(format!("{generation}-second").as_bytes()).as_str())
        );
    }

    #[test]
    fn refuses_to_replace_foreign_codex_hooks() {
        let root = std::env::temp_dir().join(format!("arc_writer_foreign_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::write(root.join(".codex/hooks.json"), "{\"hooks\":{}}").unwrap();
        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::new("windows").expect("windows is a valid test OS"),
            relative_path: ".codex/hooks.json".into(),
            content: "{\"description\":\"Auto-generated by Arc\"}".into(),
            is_executable: false,
        };
        let err = write_artifacts(&root, &[artifact]).unwrap_err();
        assert!(err.to_string().contains("Refusing to overwrite"));
        assert_eq!(
            fs::read_to_string(root.join(".codex/hooks.json")).unwrap(),
            "{\"hooks\":{}}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn atomically_replaces_arc_owned_artifact() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_replace_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::write(
            root.join(".codex/hooks.json"),
            "{\"description\":\"Auto-generated by Arc: old\"}",
        )
        .unwrap();
        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::host().expect("test host OS is supported"),
            relative_path: ".codex/hooks.json".into(),
            content: "{\"description\":\"Auto-generated by Arc: new\"}".into(),
            is_executable: false,
        };

        write_artifacts(&root, &[artifact]).unwrap();

        assert_eq!(
            fs::read_to_string(root.join(".codex/hooks.json")).unwrap(),
            "{\"description\":\"Auto-generated by Arc: new\"}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rolls_back_artifacts_when_manifest_update_fails() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_manifest_failure_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("artifact.txt");
        fs::write(&target, "old").unwrap();
        fs::create_dir_all(root.join(ARC_STATE_DIR)).unwrap();
        fs::write(root.join(BUILD_MANIFEST_FILE), "{not valid json").unwrap();

        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::host().expect("test host OS is supported"),
            relative_path: "artifact.txt".into(),
            content: "new".into(),
            is_executable: false,
        };
        let error = write_artifacts(&root, &[artifact]).unwrap_err();
        assert!(
            error.to_string().contains("manifest"),
            "unexpected rollback error: {error:#}"
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "old",
            "rollback error: {error:#}"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rolls_back_artifacts_when_external_finalizer_fails() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_finalizer_failure_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("artifact.txt");
        fs::write(&target, "old").unwrap();

        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::host().expect("test host OS is supported"),
            relative_path: "artifact.txt".into(),
            content: "new".into(),
            is_executable: false,
        };
        write_artifacts(&root, &[artifact.clone()]).unwrap();
        let previous_manifest = fs::read_to_string(root.join(BUILD_MANIFEST_FILE)).unwrap();
        fs::write(&target, "old-again").unwrap();

        let error = write_artifacts_with_finalizer(&root, &[artifact], |_| {
            anyhow::bail!("trust registration failed")
        })
        .unwrap_err();
        assert!(error.to_string().contains("finalizer"));
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "old-again",
            "rollback error: {error:#}"
        );
        assert_eq!(
            fs::read_to_string(root.join(BUILD_MANIFEST_FILE)).unwrap(),
            previous_manifest
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rolls_back_before_finalizer_when_cleanup_journal_fails() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_journal_failure_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("artifact.txt");
        fs::write(&target, "old").unwrap();

        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::host().expect("test host OS is supported"),
            relative_path: "artifact.txt".into(),
            content: "new".into(),
            is_executable: false,
        };
        write_artifacts(&root, std::slice::from_ref(&artifact)).unwrap();
        let previous_manifest = fs::read_to_string(root.join(BUILD_MANIFEST_FILE)).unwrap();
        fs::write(&target, "old-again").unwrap();

        let finalizer_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finalizer_called_in_closure = std::sync::Arc::clone(&finalizer_called);
        let mut finalizer = ClosureBuildFinalizer::new(move |_: &BuildManifest| {
            finalizer_called_in_closure.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let error = write_artifacts_transactional_inner(
            &root,
            std::slice::from_ref(&artifact),
            &mut finalizer,
            |point| {
                if *point == TransactionCheckpoint::BeforeJournalPublish {
                    anyhow::bail!("injected transaction journal failure");
                }
                Ok(())
            },
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected transaction journal failure"),
            "unexpected error: {error:#}"
        );
        assert!(!finalizer_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(fs::read_to_string(&target).unwrap(), "old-again");
        assert_eq!(
            fs::read_to_string(root.join(BUILD_MANIFEST_FILE)).unwrap(),
            previous_manifest
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_cleanup_journal_fails_closed_without_deleting_backups() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_cleanup_recovery_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let backup = root.join(".tmp_backup_recovery.tmp");
        fs::write(&backup, "old").unwrap();
        let output = OpenDirectory::open_root(&root.canonicalize().unwrap()).unwrap();
        write_cleanup_journal(&output, &[PathBuf::from(".tmp_backup_recovery.tmp")]).unwrap();

        let error = recover_cleanup_journal(&output).unwrap_err();

        assert!(format!("{error:#}").contains("lacks transaction state"));
        assert!(backup.exists());
        assert!(root.join(CLEANUP_JOURNAL_FILE).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn m8_recovery_never_leaves_a_mixed_artifact_set() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_m8_mixed_recovery_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let old = m8_artifacts("old");
        let new = m8_artifacts("new");
        write_artifacts(&root, &old).unwrap();
        let mut finalizer = NoopBuildFinalizer;
        let error = write_artifacts_transactional_inner(
            &root,
            &new,
            &mut finalizer,
            |point| {
                if matches!(point, TransactionCheckpoint::AfterReplace { index: 0, .. }) {
                    anyhow::bail!("injected interruption after first replacement");
                }
                Ok(())
            },
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected interruption"));
        assert_m8_generation(&root, "old");
        assert!(!root.join(TRANSACTION_JOURNAL_FILE).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn m8_fault_injection_recovers_every_durable_transition() {
        #[derive(Clone, Copy, Debug)]
        enum Fault {
            BeforeJournal,
            AfterJournal,
            BeforeFirstReplace,
            AfterReplace(usize),
            AfterManifest,
            BeforeFinalizer,
            AfterFinalizer,
            BeforeBackupCleanup(usize),
            AfterBackupCleanup(usize),
        }

        fn selected(fault: Fault, point: &TransactionCheckpoint) -> bool {
            match (fault, point) {
                (Fault::BeforeJournal, TransactionCheckpoint::BeforeJournalPublish)
                | (Fault::AfterJournal, TransactionCheckpoint::AfterJournalPublish)
                | (Fault::BeforeFirstReplace, TransactionCheckpoint::BeforeFirstReplace)
                | (Fault::AfterManifest, TransactionCheckpoint::AfterManifestReplace)
                | (Fault::BeforeFinalizer, TransactionCheckpoint::BeforeFinalizer)
                | (Fault::AfterFinalizer, TransactionCheckpoint::AfterFinalizer) => true,
                (
                    Fault::AfterReplace(expected),
                    TransactionCheckpoint::AfterReplace { index, .. },
                )
                | (
                    Fault::BeforeBackupCleanup(expected),
                    TransactionCheckpoint::BeforeBackupCleanup { index, .. },
                )
                | (
                    Fault::AfterBackupCleanup(expected),
                    TransactionCheckpoint::AfterBackupCleanup { index, .. },
                ) => expected == *index,
                _ => false,
            }
        }

        let cases = [
            Fault::BeforeJournal,
            Fault::AfterJournal,
            Fault::BeforeFirstReplace,
            Fault::AfterReplace(0),
            Fault::AfterReplace(1),
            Fault::AfterManifest,
            Fault::BeforeFinalizer,
            Fault::AfterFinalizer,
            Fault::BeforeBackupCleanup(0),
            Fault::BeforeBackupCleanup(1),
            Fault::BeforeBackupCleanup(2),
            Fault::AfterBackupCleanup(0),
            Fault::AfterBackupCleanup(1),
            Fault::AfterBackupCleanup(2),
        ];
        for fault in cases {
            let root = std::env::temp_dir().join(format!(
                "arc_writer_m8_fault_{fault:?}_{}_{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&root).unwrap();
            write_artifacts(&root, &m8_artifacts("old")).unwrap();
            let mut finalizer = ClosureBuildFinalizer::new(|_: &BuildManifest| Ok(()));
            let error = write_artifacts_transactional_inner(
                &root,
                &m8_artifacts("new"),
                &mut finalizer,
                |point| {
                    if selected(fault, point) {
                        anyhow::bail!("injected failure at {point:?}");
                    }
                    Ok(())
                },
                |_| Ok(()),
                |_| Ok(()),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("injected failure"));
            let expected = match fault {
                Fault::AfterFinalizer
                | Fault::BeforeBackupCleanup(_)
                | Fault::AfterBackupCleanup(_) => "new",
                _ => "old",
            };
            assert_m8_generation(&root, expected);
            assert!(!root.join(TRANSACTION_JOURNAL_FILE).exists());
            let _ = fs::remove_dir_all(root);
        }
    }

    fn m8_ir_artifacts(generation: &str) -> Vec<GeneratedArtifact> {
        [
            (ProviderTarget::Codex, ".codex/arc_ir.json"),
            (ProviderTarget::Gemini, ".agents/arc_ir.json"),
        ]
        .into_iter()
        .map(|(provider, path)| GeneratedArtifact {
            provider,
            target_os: OsTarget::host().unwrap(),
            relative_path: path.into(),
            content: format!(r#"{{"generation":"{generation}","path":"{path}"}}"#),
            is_executable: false,
        })
        .collect()
    }

    fn m8_trust_entries(artifacts: &[GeneratedArtifact]) -> Vec<(PathBuf, Vec<u8>)> {
        artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.relative_path.clone(),
                    artifact.content.as_bytes().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn m8_external_trust_and_files_choose_the_same_generation() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_m8_trust_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("runtime-state.sqlite3");
        let store = crate::runtime::state_store::SqliteStateStore::open(&state_path).unwrap();
        let old = m8_ir_artifacts("old");
        let new = m8_ir_artifacts("new");
        write_artifacts_with_trust(&root, &old, &store, &m8_trust_entries(&old)).unwrap();

        let new_entries = m8_trust_entries(&new);
        let mut before_trust = SqliteIrTrustFinalizer {
            store: &store,
            entries: &new_entries,
        };
        write_artifacts_transactional_inner(
            &root,
            &new,
            &mut before_trust,
            |point| {
                if matches!(point, TransactionCheckpoint::AfterReplace { index: 0, .. }) {
                    anyhow::bail!("interrupt before trust registration");
                }
                Ok(())
            },
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();
        for artifact in &old {
            let (_, bytes) = store
                .load_trusted_ir_file(&root.join(&artifact.relative_path))
                .unwrap();
            assert_eq!(bytes, artifact.content.as_bytes());
        }

        let mut after_trust = SqliteIrTrustFinalizer {
            store: &store,
            entries: &new_entries,
        };
        write_artifacts_transactional_inner(
            &root,
            &new,
            &mut after_trust,
            |point| {
                if *point == TransactionCheckpoint::AfterFinalizer {
                    anyhow::bail!("interrupt after trust registration");
                }
                Ok(())
            },
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();
        for artifact in &new {
            let (_, bytes) = store
                .load_trusted_ir_file(&root.join(&artifact.relative_path))
                .unwrap();
            assert_eq!(bytes, artifact.content.as_bytes());
        }
        assert_eq!(
            fs::read_to_string(root.join(".codex/arc_ir.json")).unwrap(),
            new[0].content
        );
        assert_eq!(
            fs::read_to_string(root.join(".agents/arc_ir.json")).unwrap(),
            new[1].content
        );
        assert!(!root.join(TRANSACTION_JOURNAL_FILE).exists());
        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn m8_prepared_journal_contains_complete_recovery_and_trust_plan() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_m8_journal_plan_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let store = crate::runtime::state_store::SqliteStateStore::open(
            &root.join("runtime-state.sqlite3"),
        )
        .unwrap();
        let old = m8_ir_artifacts("old");
        let new = m8_ir_artifacts("new");
        write_artifacts_with_trust(&root, &old, &store, &m8_trust_entries(&old)).unwrap();
        let new_entries = m8_trust_entries(&new);
        let mut finalizer = SqliteIrTrustFinalizer {
            store: &store,
            entries: &new_entries,
        };
        write_artifacts_transactional_inner(
            &root,
            &new,
            &mut finalizer,
            |point| {
                if *point != TransactionCheckpoint::AfterJournalPublish {
                    return Ok(());
                }
                let journal: BuildTransactionJournal =
                    serde_json::from_slice(&fs::read(root.join(TRANSACTION_JOURNAL_FILE)).unwrap())
                        .unwrap();
                assert_eq!(journal.state, BuildTransactionState::Prepared);
                assert_eq!(journal.files.len(), 3);
                assert_eq!(journal.trusted_irs.len(), 2);
                assert!(journal.files.iter().all(|record| {
                    record.backup.is_some()
                        && record.previous_sha256.is_some()
                        && !record.new_sha256.is_empty()
                        && root.join(&record.temp).exists()
                        && root.join(record.backup.as_ref().unwrap()).exists()
                }));
                assert!(journal.trusted_irs.iter().all(|entry| {
                    entry.previous_sha256.is_some() && !entry.new_sha256.is_empty()
                }));
                anyhow::bail!("stop after inspecting prepared journal");
            },
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();
        for artifact in &old {
            assert_eq!(
                fs::read_to_string(root.join(&artifact.relative_path)).unwrap(),
                artifact.content
            );
        }
        assert!(!root.join(TRANSACTION_JOURNAL_FILE).exists());
        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn m8_real_process_crash_is_recovered_on_restart() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_m8_process_crash_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        write_artifacts(&root, &m8_artifacts("old")).unwrap();

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("emitters::writer::tests::m8_crash_worker")
            .arg("--nocapture")
            .env("ARC_M8_CRASH_ROOT", &root)
            .status()
            .expect("run crash worker");
        assert_eq!(status.code(), Some(86));

        let store = crate::runtime::state_store::SqliteStateStore::open(
            &root.join("runtime-state.sqlite3"),
        )
        .unwrap();
        recover_pending_build(&root, &store).unwrap();
        assert_m8_generation(&root, "old");
        assert!(!root.join(TRANSACTION_JOURNAL_FILE).exists());
        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn m8_ambiguous_hash_fails_closed_before_recovery_mutates_more_files() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_m8_ambiguous_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        write_artifacts(&root, &m8_artifacts("old")).unwrap();
        let previous_manifest = fs::read(root.join(BUILD_MANIFEST_FILE)).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("emitters::writer::tests::m8_crash_worker")
            .env("ARC_M8_CRASH_ROOT", &root)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        fs::write(root.join("first.txt"), "unknown-generation").unwrap();

        let store = crate::runtime::state_store::SqliteStateStore::open(
            &root.join("runtime-state.sqlite3"),
        )
        .unwrap();
        let error = recover_pending_build(&root, &store).unwrap_err();
        assert!(format!("{error:#}").contains("unknown hash"));
        assert_eq!(
            fs::read_to_string(root.join("first.txt")).unwrap(),
            "unknown-generation"
        );
        assert_eq!(
            fs::read_to_string(root.join("second.txt")).unwrap(),
            "old-second"
        );
        assert_eq!(
            fs::read(root.join(BUILD_MANIFEST_FILE)).unwrap(),
            previous_manifest
        );
        assert!(root.join(TRANSACTION_JOURNAL_FILE).exists());
        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn m8_crash_worker() {
        let Some(root) = std::env::var_os("ARC_M8_CRASH_ROOT").map(PathBuf::from) else {
            return;
        };
        let mut finalizer = NoopBuildFinalizer;
        let _ = write_artifacts_transactional_inner(
            &root,
            &m8_artifacts("new"),
            &mut finalizer,
            |point| {
                if matches!(point, TransactionCheckpoint::AfterReplace { index: 0, .. }) {
                    std::process::exit(86);
                }
                Ok(())
            },
            |_| Ok(()),
            |_| Ok(()),
        );
        panic!("crash worker reached the end without terminating");
    }

    #[test]
    fn h4_output_lock_rejects_concurrent_builds() {
        use std::sync::mpsc::sync_channel;

        let root = std::env::temp_dir().join(format!(
            "arc_writer_h4_lock_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create output directory");
        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::host().expect("test host OS is supported"),
            relative_path: "artifact.txt".into(),
            content: "first build".into(),
            is_executable: false,
        };
        let (locked_tx, locked_rx) = sync_channel::<()>(0);
        let (release_tx, release_rx) = sync_channel::<()>(0);
        let writer_root = root.clone();
        let writer_artifact = artifact.clone();
        let first = std::thread::spawn(move || {
            let mut finalizer = NoopBuildFinalizer;
            write_artifacts_transactional_inner(
                &writer_root,
                &[writer_artifact],
                &mut finalizer,
                |_| Ok(()),
                |_| {
                    locked_tx
                        .send(())
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    release_rx
                        .recv()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    Ok(())
                },
                |_| Ok(()),
            )
        });

        locked_rx.recv().expect("first build must hold the lock");
        let second_error = write_artifacts(&root, &[artifact]).unwrap_err();
        assert!(
            format!("{second_error:#}").contains("build lock"),
            "unexpected concurrent-build error: {second_error:#}"
        );
        release_tx.send(()).expect("release first build");
        first
            .join()
            .expect("first build thread must not panic")
            .expect("first build must complete");
        assert_eq!(
            fs::read_to_string(root.join("artifact.txt")).unwrap(),
            "first build"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn h4_ancestor_replacement_after_validation_never_writes_outside_opened_output() {
        use std::sync::mpsc::sync_channel;

        let root = std::env::temp_dir().join(format!(
            "arc_writer_h4_race_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let ancestor = root.join("ancestor");
        let parent = ancestor.join("nested");
        let original_ancestor = root.join("ancestor-original");
        let outside = std::env::temp_dir().join(format!(
            "arc_writer_h4_outside_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let outside_parent = outside.join("nested");
        fs::create_dir_all(&parent).expect("create output parent");
        fs::create_dir_all(&outside_parent).expect("create external directory");

        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::host().expect("test host OS is supported"),
            relative_path: "ancestor/nested/artifact.txt".into(),
            content: "generated inside opened output".into(),
            is_executable: false,
        };
        let (validated_tx, validated_rx) = sync_channel::<()>(0);
        let (continue_tx, continue_rx) = sync_channel::<()>(0);
        let (staged_tx, staged_rx) = sync_channel::<()>(0);
        let (finish_tx, finish_rx) = sync_channel::<()>(0);
        let writer_root = root.clone();
        let writer = std::thread::spawn(move || {
            let mut finalizer = NoopBuildFinalizer;
            write_artifacts_transactional_inner(
                &writer_root,
                &[artifact],
                &mut finalizer,
                |_| Ok(()),
                |_| {
                    validated_tx
                        .send(())
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    continue_rx
                        .recv()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    Ok(())
                },
                |_| {
                    staged_tx
                        .send(())
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    finish_rx
                        .recv()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    Ok(())
                },
            )
        });

        validated_rx
            .recv()
            .expect("writer must pause after validating the parent");
        let ancestor_was_renamed = match fs::rename(&ancestor, &original_ancestor) {
            Ok(()) => true,
            #[cfg(windows)]
            Err(error) => {
                eprintln!(
                    "H4 ancestor replacement was blocked by the retained directory handle: {error}"
                );
                false
            }
            #[cfg(unix)]
            Err(error) => panic!("rename validated ancestor: {error}"),
        };
        #[cfg(unix)]
        if ancestor_was_renamed {
            std::os::unix::fs::symlink(&outside, &ancestor).expect("replace ancestor with symlink");
        }
        #[cfg(windows)]
        if ancestor_was_renamed
            && let Err(error) = std::os::windows::fs::symlink_dir(&outside, &ancestor)
        {
            continue_tx
                .send(())
                .expect("release writer when symlinks are unavailable");
            let _ = staged_rx.recv();
            let _ = finish_tx.send(());
            let _ = writer.join();
            let _ = fs::rename(&original_ancestor, &ancestor);
            let _ = fs::remove_dir_all(&root);
            let _ = fs::remove_dir_all(&outside);
            eprintln!("H4 race test skipped: cannot create Windows directory symlink: {error}");
            return;
        }
        continue_tx.send(()).expect("release paused writer");
        staged_rx
            .recv()
            .expect("writer must pause after staging the temporary file");
        let external_entries_during_staging = fs::read_dir(&outside_parent)
            .expect("inspect external directory")
            .count();
        finish_tx.send(()).expect("release staged writer");
        let result = writer.join().expect("writer thread must not panic");

        let outside_was_modified = outside_parent.join("artifact.txt").exists();
        let original_content = fs::read_to_string(
            if ancestor_was_renamed {
                &original_ancestor
            } else {
                &ancestor
            }
            .join("nested/artifact.txt"),
        )
        .ok();
        #[cfg(unix)]
        if ancestor_was_renamed {
            let _ = fs::remove_file(&ancestor);
        }
        #[cfg(windows)]
        if ancestor_was_renamed {
            let _ = fs::remove_dir(&ancestor);
        }
        if ancestor_was_renamed {
            let _ = fs::rename(&original_ancestor, &ancestor);
        }
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);

        assert!(
            external_entries_during_staging == 0 && !outside_was_modified,
            "writer modified the external directory during staging; result was {result:?}"
        );
        assert!(
            result.is_err()
                || original_content.as_deref() == Some("generated inside opened output"),
            "writer must either fail closed or commit through the original opened parent"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_relative_creation_is_bound_to_parent_handle() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_h4_relative_root_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let outside = std::env::temp_dir().join(format!(
            "arc_writer_h4_relative_outside_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create output directory");
        fs::create_dir_all(&outside).expect("create external directory");

        let mut opened = OpenDirectory::open_root(&root.canonicalize().unwrap()).unwrap();
        // Simulate a stale textual path after an ancestor move. Security-sensitive
        // creation must use the retained handle, while display_path is diagnostic.
        opened.display_path = outside.clone();
        let created = opened
            .create_new_file(OsStr::new("relative-only.tmp"))
            .expect("create relative to retained parent handle");

        assert!(root.join("relative-only.tmp").exists());
        assert!(!outside.join("relative-only.tmp").exists());
        created.remove().expect("remove relative test file");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_write_to_leaf_symlink() {
        let root = std::env::temp_dir().join(format!("arc_writer_symlink_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".codex")).unwrap();
        let outside_target =
            std::env::temp_dir().join(format!("outside_target_{}", std::process::id()));
        fs::write(&outside_target, "SAFE_CONTENT").unwrap();

        let _ = std::os::unix::fs::symlink(&outside_target, root.join(".codex/hooks.json"));

        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: ".codex/hooks.json".into(),
            content: "{\"description\":\"Auto-generated by Arc\"}".into(),
            is_executable: false,
        };
        let err = write_artifacts(&root, &[artifact]).unwrap_err();
        assert!(
            format!("{err:#}").to_lowercase().contains("symlink"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read_to_string(&outside_target).unwrap(), "SAFE_CONTENT");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside_target);
    }

    #[cfg(unix)]
    #[test]
    fn unix_relative_operations_reject_replaced_leaf_handles() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_unix_leaf_identity_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create output directory");
        let opened = OpenDirectory::open_root(&root.canonicalize().unwrap()).unwrap();

        let mut source = opened
            .create_new_file(OsStr::new("source.tmp"))
            .expect("create source file");
        source
            .write_and_sync(b"trusted source")
            .expect("write source");
        fs::rename(root.join("source.tmp"), root.join("source.moved"))
            .expect("move original source entry");
        fs::write(root.join("source.tmp"), b"replacement source").expect("replace source entry");

        let rename_error = source
            .rename_replace(&opened, OsStr::new("target.txt"))
            .expect_err("renaming a replaced source entry must fail closed");
        assert!(rename_error.to_string().contains("no longer matches"));
        assert_eq!(
            fs::read(root.join("source.tmp")).unwrap(),
            b"replacement source"
        );
        assert!(!root.join("target.txt").exists());

        let removable = opened
            .create_new_file(OsStr::new("remove.tmp"))
            .expect("create removable file");
        removable.handle.sync_all().expect("sync removable file");
        fs::rename(root.join("remove.tmp"), root.join("remove.moved"))
            .expect("move original removable entry");
        fs::write(root.join("remove.tmp"), b"replacement removable")
            .expect("replace removable entry");

        let remove_error = removable
            .remove()
            .expect_err("removing a replaced entry must fail closed");
        assert!(remove_error.to_string().contains("no longer matches"));
        assert!(root.join("remove.tmp").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn refuses_to_write_to_leaf_symlink_on_windows() {
        let root = std::env::temp_dir().join(format!(
            "arc_writer_symlink_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(root.join(".codex")).unwrap();
        let outside_target = root.with_extension("outside.txt");
        fs::write(&outside_target, "SAFE_CONTENT").unwrap();
        if std::os::windows::fs::symlink_file(&outside_target, root.join(".codex/hooks.json"))
            .is_err()
        {
            let _ = fs::remove_dir_all(&root);
            let _ = fs::remove_file(&outside_target);
            return;
        }

        let artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::new("windows").expect("windows is a valid test OS"),
            relative_path: ".codex/hooks.json".into(),
            content: "{\"description\":\"Auto-generated by Arc\"}".into(),
            is_executable: false,
        };
        let error = write_artifacts(&root, &[artifact]).unwrap_err();
        assert!(
            format!("{error:#}").to_lowercase().contains("symlink"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fs::read_to_string(&outside_target).unwrap(), "SAFE_CONTENT");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside_target);
    }
}
