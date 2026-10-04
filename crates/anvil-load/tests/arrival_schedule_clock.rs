//! Production arrival offsets driven by real Tokio timers under a paused
//! clock. The loopback scenario separately checks the wall-clock executor's
//! report, ledgers, drops, latency and lag bounds.
//!
//! Workspace CI enables Tokio's test-util through anvil-transport's tests;
//! a focused hosted run of this target also needs `--features tokio/test-util`.

use anvil_domain::load::Stage;
use anvil_load::schedule::{Arrivals, planned_arrivals, total_secs};
use std::time::Duration;
use tokio::time::{Instant, advance, sleep_until};

fn stages() -> [Stage; 2] {
    [Stage { duration_secs: 0, target: 20 }, Stage { duration_secs: 3, target: 20 }]
}

#[tokio::test(start_paused = true)]
async fn constant_arrivals_follow_twenty_per_second_without_clock_drift() {
    let stages = stages();
    let start = Instant::now();
    let end = start + Duration::from_secs(total_secs(&stages).unwrap());
    let mut count = 0u64;
    for offset in Arrivals::new(&stages) {
        let due = start + Duration::from_secs_f64(offset);
        assert_eq!(due - start, Duration::from_millis(count * 50), "arrival {count} has an absolute 50 ms deadline");
        assert!(due < end, "the schedule excludes its end boundary");
        sleep_until(due).await;
        assert_eq!(Instant::now(), due, "arrival {count} starts on its paused-clock deadline");
        count += 1;
    }
    sleep_until(end).await;
    assert_eq!(count, 60);
    assert_eq!(planned_arrivals(&stages), count as f64);
    assert_eq!(start.elapsed(), Duration::from_secs(3));
    assert_eq!(count as f64 / start.elapsed().as_secs_f64(), 20.0);
}

#[tokio::test(start_paused = true)]
async fn delayed_polling_keeps_arrivals_and_accounts_for_the_longer_window() {
    let stages = stages();
    let start = Instant::now();
    let end = start + Duration::from_secs(total_secs(&stages).unwrap());
    let mut count = 0u64;
    let mut late = Vec::new();
    for offset in Arrivals::new(&stages) {
        let due = start + Duration::from_secs_f64(offset);
        assert_eq!(due - start, Duration::from_millis(count * 50), "delay never moves the planned deadlines");
        assert!(due < end);
        if count == 20 {
            // Poll the remaining schedule after its end, without sleeping
            // the host or replacing the production arrival calculation.
            advance(Duration::from_secs(4) - start.elapsed()).await;
        }
        sleep_until(due).await;
        let now = Instant::now();
        if count < 20 {
            assert_eq!(now, due);
        } else {
            assert_eq!(now - start, Duration::from_secs(4), "overdue arrivals catch up without a fresh interval");
            late.push(now - due);
        }
        count += 1;
    }
    sleep_until(end).await;
    assert_eq!(count, 60, "late polling neither skips nor adds arrivals");
    assert_eq!(late.len(), 40);
    assert_eq!(late.first(), Some(&Duration::from_secs(3)));
    assert_eq!(late.last(), Some(&Duration::from_millis(1_050)));
    assert_eq!(start.elapsed(), Duration::from_secs(4), "stopping late extends the actual scheduling window");
    assert_eq!(planned_arrivals(&stages) / 3.0, 20.0, "the planned rate remains twenty per second");
    assert_eq!(count as f64 / start.elapsed().as_secs_f64(), 15.0, "measured arrivals per second include the imposed delay");
}
