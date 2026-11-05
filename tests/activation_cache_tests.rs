use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;

use arc::{ActivationEvaluationCache, CacheResolutionProvenance, DecisionTaskResult};

fn fixture_decision_result(finding: &str) -> DecisionTaskResult {
    DecisionTaskResult::Satisfied {
        physical_evaluation_id: "phys-id".into(),
        evaluation_key: "same-key".into(),
        findings: Some(finding.to_string()),
        provider_receipt: arc::ProviderEvaluationReceipt {
            provider: arc::ProviderTarget::Codex,
            transport: "test".into(),
            isolated_conversation_fingerprint: "fp".into(),
            started_unix_ms: 1000,
            completed_unix_ms: 1050,
            queue_duration_ms: 10,
            inference_duration_ms: 40,
        },
    }
}

#[test]
fn duplicate_in_flight_work_has_one_leader_and_one_physical_result() {
    let cache = Arc::new(ActivationEvaluationCache::new("activation-a"));
    let executions = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Barrier::new(2));
    let (release_tx, release_rx) = mpsc::channel();

    let leader_cache = Arc::clone(&cache);
    let leader_executions = Arc::clone(&executions);
    let leader_entered = Arc::clone(&entered);
    let leader = thread::spawn(move || {
        leader_cache
            .resolve_decision(
                "same-key",
                b"canonical-input".to_vec(),
                "occ-leader",
                || {
                    leader_executions.fetch_add(1, Ordering::SeqCst);
                    leader_entered.wait();
                    release_rx.recv().expect("leader release signal");
                    fixture_decision_result("leader")
                },
            )
            .expect("leader resolves")
    });

    entered.wait();

    let follower_cache = Arc::clone(&cache);
    let follower_executions = Arc::clone(&executions);
    let follower = thread::spawn(move || {
        follower_cache
            .resolve_decision(
                "same-key",
                b"canonical-input".to_vec(),
                "occ-follower",
                || {
                    follower_executions.fetch_add(1, Ordering::SeqCst);
                    fixture_decision_result("follower")
                },
            )
            .expect("follower resolves")
    });
    for _ in 0..100_000 {
        if cache.coalesced_in_flight() >= 1 {
            break;
        }
        thread::yield_now();
    }
    assert_eq!(cache.coalesced_in_flight(), 1);
    release_tx.send(()).expect("release leader");
    let leader_result = leader.join().expect("leader thread");
    let follower_result = follower.join().expect("follower thread");

    assert_eq!(executions.load(Ordering::SeqCst), 1);
    assert_eq!(leader_result.result, follower_result.result);
    assert_eq!(leader_result.result, fixture_decision_result("leader"));
    assert_eq!(
        leader_result.physical_evaluation_id,
        follower_result.physical_evaluation_id
    );
    assert_eq!(
        leader_result.provenance,
        CacheResolutionProvenance::Executed
    );
    assert_eq!(
        follower_result.provenance,
        CacheResolutionProvenance::CoalescedInFlight
    );
    assert_ne!(leader_result.occurrence_id, follower_result.occurrence_id);
}

#[test]
fn completed_results_reuse_only_inside_one_activation_and_collisions_fault_closed() {
    let first = ActivationEvaluationCache::new("activation-a");
    let calls = AtomicUsize::new(0);
    let ready = first
        .resolve_probe("same-key", b"bytes-a".to_vec(), "occ-1", || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("observed".to_string())
        })
        .expect("first probe");
    let reused = first
        .resolve_probe("same-key", b"bytes-a".to_vec(), "occ-2", || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("wrong".to_string())
        })
        .expect("ready probe");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reused.result, Ok("observed".to_string()));
    assert_eq!(
        reused.provenance,
        CacheResolutionProvenance::ReusedCompleted
    );

    let collision = first.resolve_probe("same-key", b"bytes-b".to_vec(), "occ-3", || {
        Ok("must-not-run".to_string())
    });
    assert!(matches!(
        collision,
        Err(arc::ActivationCacheError::KeyCollision { .. })
    ));

    let second = ActivationEvaluationCache::new("activation-b");
    let second_result = second
        .resolve_probe("same-key", b"bytes-a".to_vec(), "occ-4", || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("new-activation".to_string())
        })
        .expect("second activation");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_ne!(
        ready.physical_evaluation_id,
        second_result.physical_evaluation_id
    );
}

#[test]
fn cache_rejects_work_after_terminal_drop() {
    let cache = ActivationEvaluationCache::new("activation-a");
    cache.close();
    let result = cache.resolve_probe("key", b"input".to_vec(), "occ", || Ok("val".to_string()));
    assert!(matches!(result, Err(arc::ActivationCacheError::Closed)));
}

#[test]
fn physical_panic_becomes_one_shared_fault_instead_of_hanging_followers() {
    let cache = Arc::new(ActivationEvaluationCache::new("activation-panic"));
    let leader_cache = Arc::clone(&cache);
    let follower_cache = Arc::clone(&cache);
    let (leader_started_tx, leader_started_rx) = std::sync::mpsc::sync_channel(0);
    let leader = thread::spawn(move || {
        leader_cache.resolve_decision("panic-key", b"panic-key".to_vec(), "leader", || {
            leader_started_tx
                .send(())
                .expect("follower synchronization receiver remains alive");
            panic!("fixture physical panic")
        })
    });
    leader_started_rx
        .recv()
        .expect("leader must own the physical evaluation before the follower starts");
    let follower =
        follower_cache.resolve_decision("panic-key", b"panic-key".to_vec(), "follower", || {
            fixture_decision_result("follower")
        });
    let leader_result = leader.join().expect("cache catches physical panic");
    assert!(matches!(
        leader_result,
        Err(arc::ActivationCacheError::ExecutionPanicked)
    ));
    assert!(matches!(
        follower,
        Err(arc::ActivationCacheError::ExecutionPanicked)
    ));
    assert_eq!(cache.summary().physical_faults, 1);
}
