use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const UDF_ROOT_COMPONENTS: [&str; 3] = ["Arc", "decision-webview", "sessions"];
const SESSION_HASH_CHARS: usize = 32;
const ACTIVE_MARKER: &str = ".arc-decision-ui.active";
const STALE_SESSION_MIN_AGE: Duration = Duration::from_secs(2 * 24 * 60 * 60);
const MAX_STALE_SESSION_CANDIDATES: usize = 16;

pub(crate) fn resolve_session_udf(
    local_app_data_dir: &Path,
    process_id: u32,
    request_id: &str,
) -> Result<PathBuf> {
    if !local_app_data_dir.is_absolute() {
        bail!("WebView2 local app data directory must be absolute");
    }
    let root = UDF_ROOT_COMPONENTS
        .iter()
        .fold(local_app_data_dir.to_path_buf(), |path, component| {
            path.join(component)
        });
    fs::create_dir_all(&root).with_context(|| "failed creating the WebView2 UDF root")?;
    let root =
        fs::canonicalize(&root).with_context(|| "failed canonicalizing the WebView2 UDF root")?;
    let session_name = format!("{process_id}-{}", request_id_hash(request_id));
    let session = root.join(session_name);
    if !session.starts_with(&root) {
        bail!("WebView2 session UDF escaped its root");
    }

    // Cleanup is deliberately best-effort: it must never prevent a new
    // session from reaching the WebView builder or change its decision.
    let _ = cleanup_stale_session_udfs(
        &root,
        &session,
        SystemTime::now(),
        STALE_SESSION_MIN_AGE,
        MAX_STALE_SESSION_CANDIDATES,
    );
    fs::create_dir_all(&session).with_context(|| "failed creating the WebView2 session UDF")?;
    let session = fs::canonicalize(&session)
        .with_context(|| "failed canonicalizing the WebView2 session UDF")?;
    if !session.starts_with(&root) {
        bail!("canonical WebView2 session UDF escaped its root");
    }
    create_active_marker(&session, process_id)?;
    Ok(session)
}

fn create_active_marker(session: &Path, process_id: u32) -> Result<()> {
    let marker = session.join(ACTIVE_MARKER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .with_context(|| "failed registering the active WebView2 session")?;
    writeln!(file, "{process_id}")
        .with_context(|| "failed writing the active WebView2 session marker")?;
    file.sync_all()
        .with_context(|| "failed syncing the active WebView2 session marker")?;
    Ok(())
}

pub(crate) fn request_id_hash(request_id: &str) -> String {
    let digest = Sha256::digest(request_id.as_bytes());
    digest
        .iter()
        .take(SESSION_HASH_CHARS / 2)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn failure_trace_event(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("failed creating the WebView2 UDF root") {
        "udf_root_create_failed"
    } else if message.contains("failed canonicalizing the WebView2 UDF root") {
        "udf_root_canonicalize_failed"
    } else if message.contains("failed creating the WebView2 session UDF") {
        "udf_session_create_failed"
    } else if message.contains("failed canonicalizing the WebView2 session UDF") {
        "udf_session_canonicalize_failed"
    } else if message.contains("WebView2 session UDF escaped its root") {
        "udf_session_containment_failed"
    } else if message.contains("canonical WebView2 session UDF escaped its root") {
        "udf_canonical_containment_failed"
    } else {
        "udf_validation_failed"
    }
}

fn bounded_stale_session_candidates(
    entries: &[(PathBuf, SystemTime)],
    active: &Path,
    now: SystemTime,
    max_age: Duration,
    max_entries: usize,
) -> Vec<PathBuf> {
    let mut candidates = entries
        .iter()
        .filter(|(path, modified)| {
            path != active
                && now
                    .duration_since(*modified)
                    .is_ok_and(|age| age >= max_age)
        })
        .map(|(path, modified)| (path.clone(), *modified))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(_, modified)| *modified);
    candidates
        .into_iter()
        .take(max_entries)
        .map(|(path, _)| path)
        .collect()
}

pub(crate) fn cleanup_stale_session_udfs(
    root: &Path,
    active: &Path,
    now: SystemTime,
    max_age: Duration,
    max_entries: usize,
) -> Result<Vec<PathBuf>> {
    if max_entries == 0 {
        return Ok(Vec::new());
    }

    let root =
        fs::canonicalize(root).with_context(|| "failed canonicalizing the WebView2 UDF root")?;
    let active = fs::canonicalize(active).unwrap_or_else(|_| active.to_path_buf());
    let mut stale_entries = Vec::new();
    for entry in fs::read_dir(&root).with_context(|| "failed reading the WebView2 UDF root")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }

        let candidate = match fs::canonicalize(entry.path()) {
            Ok(candidate) if candidate.starts_with(&root) => candidate,
            _ => continue,
        };
        if candidate == active {
            continue;
        }

        let marker = candidate.join(ACTIVE_MARKER);
        let marker_pid = match fs::read_to_string(&marker)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
        {
            Some(pid) => pid,
            None => continue,
        };
        if process_is_alive(marker_pid) {
            continue;
        }
        let modified = match fs::metadata(&marker).and_then(|metadata| metadata.modified()) {
            Ok(modified) => modified,
            Err(_) => continue,
        };
        stale_entries.push((candidate, modified));
    }

    let candidates =
        bounded_stale_session_candidates(&stale_entries, &active, now, max_age, max_entries);
    let mut removed = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if fs::remove_dir_all(&candidate).is_ok() {
            removed.push(candidate);
        }
    }
    Ok(removed)
}

#[cfg(windows)]
fn process_is_alive(process_id: u32) -> bool {
    arc::decision_ui::parent_process_is_alive(Some(process_id))
}

#[cfg(unix)]
fn process_is_alive(process_id: u32) -> bool {
    if process_id == 0 {
        return false;
    }
    // SAFETY: kill(pid, 0) performs a liveness/permission probe and sends no
    // signal. The PID is parsed from a bounded decimal marker.
    let result = unsafe { libc::kill(process_id as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(any(unix, windows)))]
fn process_is_alive(_process_id: u32) -> bool {
    // Unknown platforms conservatively retain marked profiles.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "arc-decision-ui-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn session_udf_is_absolute_contained_and_does_not_include_request_text() {
        let local_app_data = temp_root("udf-path");
        let request_id = "request/with sensitive text";
        let udf = resolve_session_udf(&local_app_data, 42, request_id)
            .expect("session UDF should resolve");
        let root = fs::canonicalize(
            local_app_data
                .join(UDF_ROOT_COMPONENTS[0])
                .join(UDF_ROOT_COMPONENTS[1])
                .join(UDF_ROOT_COMPONENTS[2]),
        )
        .expect("UDF root should exist");

        assert!(udf.is_absolute());
        assert!(udf.starts_with(root));
        assert!(udf.to_string_lossy().contains("42-"));
        assert!(!udf.to_string_lossy().contains(request_id));
        assert_eq!(
            udf.file_name().and_then(|name| name.to_str()).map(str::len),
            Some(35)
        );

        fs::remove_dir_all(local_app_data).expect("test UDF tree should be removable");
    }

    #[test]
    fn concurrent_sessions_get_distinct_contained_paths() {
        let local_app_data = temp_root("udf-concurrent");
        let root = local_app_data.clone();
        let handles = [(100, "request-a"), (101, "request-b")]
            .into_iter()
            .map(|(process_id, request_id)| {
                let root = root.clone();
                std::thread::spawn(move || resolve_session_udf(&root, process_id, request_id))
            })
            .collect::<Vec<_>>();
        let paths = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("UDF worker should finish")
                    .expect("UDF should resolve")
            })
            .collect::<Vec<_>>();

        assert_ne!(paths[0], paths[1]);
        assert!(paths.iter().all(|path| {
            path.starts_with(
                fs::canonicalize(
                    local_app_data
                        .join(UDF_ROOT_COMPONENTS[0])
                        .join(UDF_ROOT_COMPONENTS[1])
                        .join(UDF_ROOT_COMPONENTS[2]),
                )
                .expect("UDF root should exist"),
            )
        }));
        fs::remove_dir_all(local_app_data).expect("test UDF tree should be removable");
    }

    #[test]
    fn relative_local_data_root_is_rejected_before_filesystem_creation() {
        assert!(resolve_session_udf(Path::new("relative"), 42, "request").is_err());
    }

    #[test]
    fn stale_janitor_candidates_exclude_active_and_are_bounded() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let entries = vec![
            (PathBuf::from("old-a"), now - Duration::from_secs(50)),
            (PathBuf::from("active"), now - Duration::from_secs(60)),
            (PathBuf::from("old-b"), now - Duration::from_secs(40)),
            (PathBuf::from("young"), now - Duration::from_secs(5)),
        ];
        let candidates = bounded_stale_session_candidates(
            &entries,
            Path::new("active"),
            now,
            Duration::from_secs(30),
            1,
        );

        assert_eq!(candidates, vec![PathBuf::from("old-a")]);
    }

    #[test]
    fn production_janitor_removes_bounded_dead_sessions_and_preserves_active() {
        let local_app_data = temp_root("udf-janitor");
        let root = local_app_data
            .join(UDF_ROOT_COMPONENTS[0])
            .join(UDF_ROOT_COMPONENTS[1])
            .join(UDF_ROOT_COMPONENTS[2]);
        fs::create_dir_all(&root).expect("UDF root should be created");

        let active = root.join("active-session");
        let stale_a = root.join("stale-a");
        let stale_b = root.join("stale-b");
        let young = root.join("young-session");
        for path in [&active, &stale_a, &stale_b, &young] {
            fs::create_dir_all(path).expect("session directory should be created");
        }
        fs::write(active.join(ACTIVE_MARKER), std::process::id().to_string())
            .expect("active marker should be written");
        fs::write(stale_a.join(ACTIVE_MARKER), u32::MAX.to_string())
            .expect("stale marker should be written");
        fs::write(stale_b.join(ACTIVE_MARKER), u32::MAX.to_string())
            .expect("stale marker should be written");
        fs::write(young.join(ACTIVE_MARKER), u32::MAX.to_string())
            .expect("young marker should be written");

        let now = SystemTime::now();
        let stale_time = now - Duration::from_secs(120);
        set_modified(&stale_a.join(ACTIVE_MARKER), stale_time);
        set_modified(
            &stale_b.join(ACTIVE_MARKER),
            stale_time + Duration::from_secs(1),
        );
        set_modified(&active.join(ACTIVE_MARKER), stale_time);
        let stale_a_canonical = fs::canonicalize(&stale_a).expect("stale session should resolve");

        let removed = cleanup_stale_session_udfs(&root, &active, now, Duration::from_secs(30), 1)
            .expect("janitor should inspect the UDF root");

        assert_eq!(removed, vec![stale_a_canonical]);
        assert!(active.is_dir());
        assert!(!stale_a.exists());
        assert!(stale_b.is_dir());
        assert!(young.is_dir());

        fs::remove_dir_all(local_app_data).expect("test UDF tree should be removable");
    }

    fn set_modified(path: &Path, modified: SystemTime) {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("session directory should be openable");
        file.set_times(fs::FileTimes::new().set_modified(modified))
            .expect("session directory time should be settable");
    }
}
