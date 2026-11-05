use arc::{EventQuery, ObservabilityJournal};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct StateDirectory(PathBuf);
impl StateDirectory {
    fn new() -> Self {
        let root =
            Self(std::env::temp_dir().join(format!("arc-monitor-filter-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir_all(&root.0).unwrap();
        let journal = ObservabilityJournal::open(&root.database()).unwrap();
        drop(journal);
        root
    }
    fn database(&self) -> PathBuf {
        self.0.join("runtime-state.sqlite3")
    }
    fn monitor(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_arc"));
        command.env("ARC_STATE_DIR", &self.0);
        command
    }
    fn insert(&self, count: usize, event_type: &str, level: &str, scope: &str) {
        let connection = Connection::open(self.database()).unwrap();
        connection.busy_timeout(Duration::from_secs(5)).unwrap();
        connection.execute(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1)
             INSERT INTO observability_events(timestamp_unix_ms,event_type,level,workspace_id,session_id,execution_id,process_id,details_json)
             SELECT CAST(strftime('%s','now') AS INTEGER)*1000,?2,?3,?4,?4,?4,1,'{}' FROM n",
            params![count as i64, event_type, level, scope],
        ).unwrap();
    }
}
impl Drop for StateDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct MonitorProcess(Child);
impl Drop for MonitorProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().unwrap();
    }
}

#[test]
fn query_filters_before_limiting_and_preserves_normalized_names_and_scopes() {
    let state = StateDirectory::new();
    state.insert(10_001, "Noise", "error", "wanted");
    state.insert(1, "HookFailed", "error", "wrong");
    state.insert(1, "HookFailed", "debug", "wanted");
    state.insert(1, "HookFailed", "warn", "wanted");
    state.insert(1, "hook.failed", "error", "wanted");
    state.insert(1, "OtherEvent", "error", "wanted");
    let journal = ObservabilityJournal::open(&state.database()).unwrap();
    let query = EventQuery {
        workspace_id: Some("wanted".into()),
        session_id: Some("wanted".into()),
        execution_id: Some("wanted".into()),
        minimum_level: Some("warn".into()),
        event_types: vec!["HOOK-failed".into()],
        limit: 1,
        ..Default::default()
    };
    let first = journal.query(&query).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id, 10_004);
    let next = journal
        .query(&EventQuery {
            after_id: first[0].id,
            ..query.clone()
        })
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].id, 10_005);
    let multiple = journal
        .query(&EventQuery {
            event_types: vec!["hook_failed".into(), "OTHER-event".into()],
            limit: 10,
            ..query.clone()
        })
        .unwrap();
    assert_eq!(
        multiple.iter().map(|event| event.id).collect::<Vec<_>>(),
        [10_004, 10_005, 10_006]
    );
    assert!(
        journal
            .query(&EventQuery {
                event_types: vec!["missing".into()],
                ..query
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(journal.query(&EventQuery::default()).unwrap().len(), 500);
    assert_eq!(
        journal
            .query(&EventQuery {
                limit: usize::MAX,
                ..Default::default()
            })
            .unwrap()
            .len(),
        10_000
    );
}

#[test]
fn historical_monitor_finds_a_filtered_event_after_more_than_ten_thousand_rows() {
    let state = StateDirectory::new();
    state.insert(10_001, "Noise", "warn", "session");
    state.insert(1, "HookFailed", "warn", "session");
    let output = state
        .monitor()
        .args([
            "monitor",
            "--events",
            "hook-failed",
            "--session",
            "session",
            "--execution",
            "session",
            "--level",
            "warn",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["id"], 10_002);
    assert_eq!(events[0]["event_type"], "HookFailed");
}

#[test]
fn follow_monitor_advances_after_new_noise_and_does_not_replay_history() {
    let state = StateDirectory::new();
    state.insert(1, "HookFailed", "warn", "session");
    let child = state
        .monitor()
        .args([
            "monitor",
            "--follow",
            "--poll-ms",
            "50",
            "--events",
            "hook-failed",
            "--session",
            "session",
            "--execution",
            "session",
            "--level",
            "info",
            "--format",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut process = MonitorProcess(child);
    let stdout = process.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    // A matching readiness event proves the monitor has chosen its initial
    // cursor. Avoid assuming that process creation means initialization ended.
    let started = Instant::now();
    let ready_id = loop {
        state.insert(1, "HookFailed", "warn", "session");
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                let event: Value = serde_json::from_str(&line.unwrap()).unwrap();
                let id = event["id"].as_i64().unwrap();
                assert!(id > 1, "follow must not replay preexisting history");
                break id;
            }
            Err(mpsc::RecvTimeoutError::Timeout) if started.elapsed() < Duration::from_secs(10) => {
            }
            other => {
                // Disconnected means the monitor closed stdout, i.e. exited. Report
                // why instead of only the channel state.
                let status = process.0.try_wait();
                let _ = process.0.kill();
                let mut stderr = String::new();
                if let Some(mut pipe) = process.0.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
                }
                panic!("monitor never became ready: {other:?}; status={status:?}; stderr={stderr}")
            }
        }
    };
    state.insert(10_001, "Noise", "info", "session");
    state.insert(1, "HookFailed", "warn", "session");
    let expected_id = Connection::open(state.database())
        .unwrap()
        .query_row("SELECT MAX(id) FROM observability_events", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert!(expected_id > ready_id + 10_000);
    let started = Instant::now();
    loop {
        let line = receiver
            .recv_timeout(Duration::from_secs(10).saturating_sub(started.elapsed()))
            .expect("follow must find the event beyond the noise")
            .unwrap();
        let event: Value = serde_json::from_str(&line).unwrap();
        if event["id"] == expected_id {
            break;
        }
        assert!(event["id"].as_i64().unwrap() > ready_id);
    }
    drop(process);
    reader.join().unwrap();
}
