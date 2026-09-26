//! Regression tests for load-plan duration validation. These call the public
//! `validate_plan` entry point only; no traffic is sent and no worker runs.
//!
//! The overflow cases build a plan whose stage durations sum past `u64`. With
//! overflow checks on, an unchecked sum panics; with them off, it wraps to a
//! small value and the plan is wrongly accepted. Both must instead be refused
//! through `LoadError::Invalid`.

use anvil_domain::Id;
use anvil_domain::load::{ConnectionMode, LoadPlan, Stage, Workload};
use anvil_load::executor::MAX_DURATION_SECS;
use anvil_load::{LoadError, validate_plan};
use chrono::Utc;

fn plan(workload: Workload) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "validation".into(),
        workload,
        chain: vec![Id::new()],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: ConnectionMode::Persistent,
        warmup_secs: 0,
        abort: None,
        seed: 0,
        trusted: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn stages(durations: &[(u64, u64)]) -> Vec<Stage> {
    durations.iter().map(|&(duration_secs, target)| Stage { duration_secs, target }).collect()
}

/// `u64::MAX + 2` wraps to one second: the reproduction from the report.
fn overflow_stages() -> Vec<Stage> {
    stages(&[(u64::MAX, 1), (2, 1)])
}

fn assert_invalid(workload: Workload) {
    assert!(matches!(validate_plan(&plan(workload)), Err(LoadError::Invalid(_))));
}

fn assert_valid(workload: Workload) {
    assert!(validate_plan(&plan(workload)).is_ok());
}

fn is_typed_refusal(result: Result<Result<(), LoadError>, Box<dyn std::any::Any + Send>>) -> bool {
    matches!(result, Ok(Err(LoadError::Invalid(_))))
}

#[test]
fn overflowing_closed_plan_is_refused_without_panicking() {
    let result =
        std::panic::catch_unwind(|| validate_plan(&plan(Workload::ClosedVirtualUsers { stages: overflow_stages(), think_time_ms: 0 })));
    assert!(is_typed_refusal(result), "a closed plan whose stages overflow must be a typed refusal");
}

#[test]
fn overflowing_open_plan_is_refused_without_panicking() {
    let result =
        std::panic::catch_unwind(|| validate_plan(&plan(Workload::OpenArrivalRate { stages: overflow_stages(), max_in_flight: 1 })));
    assert!(is_typed_refusal(result), "an open plan whose stages overflow must be a typed refusal");
}

#[test]
fn json_loaded_closed_plan_overflow_is_refused() {
    let original = plan(Workload::ClosedVirtualUsers { stages: overflow_stages(), think_time_ms: 0 });
    let json = serde_json::to_string(&original).expect("plan serializes");
    let loaded: LoadPlan = serde_json::from_str(&json).expect("plan deserializes");
    assert!(matches!(validate_plan(&loaded), Err(LoadError::Invalid(_))), "overflow survives a JSON round trip");
}

#[test]
fn ordinary_over_limit_duration_is_refused() {
    let over = stages(&[(MAX_DURATION_SECS + 1, 1)]);
    assert_invalid(Workload::ClosedVirtualUsers { stages: over.clone(), think_time_ms: 0 });
    assert_invalid(Workload::OpenArrivalRate { stages: over, max_in_flight: 1 });
}

#[test]
fn zero_total_duration_is_refused() {
    let zero = stages(&[(0, 1), (0, 1)]);
    assert_invalid(Workload::ClosedVirtualUsers { stages: zero.clone(), think_time_ms: 0 });
    assert_invalid(Workload::OpenArrivalRate { stages: zero, max_in_flight: 1 });
}

#[test]
fn valid_step_and_ramp_schedules_are_accepted() {
    // A zero-duration step up to a hold (constant load 10 for 120 s).
    assert_valid(Workload::ClosedVirtualUsers { stages: stages(&[(0, 10), (120, 10)]), think_time_ms: 0 });
    // A linear ramp 10 → 50 arrivals/s over 300 s.
    assert_valid(Workload::OpenArrivalRate { stages: stages(&[(60, 10), (240, 50)]), max_in_flight: 100 });
    // The exact limit is still allowed.
    assert_valid(Workload::OpenArrivalRate { stages: stages(&[(MAX_DURATION_SECS, 1)]), max_in_flight: 1 });
}
