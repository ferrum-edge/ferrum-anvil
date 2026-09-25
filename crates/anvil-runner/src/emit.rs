//! Bounded, throttled run events.
//!
//! * `run_started` / `run_finished` are always delivered.
//! * Events about failed / errored steps are preferred: delivered up to
//!   [`MAX_FAILURE_EVENTS`] per run regardless of the rate limit.
//! * Everything else passes a token bucket: a burst of [`BURST`] events, then
//!   [`RATE_PER_SEC`] per second. Dropped events are counted and reported in
//!   `run_finished`; every delivered step/iteration event carries a fresh
//!   progress snapshot, so nothing is lost but intermediate detail.

use crate::RunEventSink;
use anvil_domain::runner::RunEvent;
use std::time::Instant;

pub const BURST: f64 = 200.0;
pub const RATE_PER_SEC: f64 = 20.0;
pub const MAX_FAILURE_EVENTS: u64 = 1_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Always,
    Failure,
    Normal,
}

pub struct Emitter {
    sink: Option<RunEventSink>,
    tokens: f64,
    last: Instant,
    failures: u64,
    pub dropped: u64,
}

impl Emitter {
    pub fn new(sink: Option<RunEventSink>) -> Self {
        Emitter { sink, tokens: BURST, last: Instant::now(), failures: 0, dropped: 0 }
    }

    pub fn emit(&mut self, ev: RunEvent, class: Class) {
        let Some(sink) = &self.sink else { return };
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * RATE_PER_SEC).min(BURST);
        self.last = now;
        let deliver = match class {
            Class::Always => true,
            Class::Failure if self.failures < MAX_FAILURE_EVENTS => {
                self.failures += 1;
                true
            }
            _ if self.tokens >= 1.0 => {
                self.tokens -= 1.0;
                true
            }
            _ => false,
        };
        if deliver {
            sink(ev);
        } else {
            self.dropped += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_domain::Id;
    use anvil_domain::runner::RunProgress;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn bursts_then_throttles_but_keeps_always_and_failure_events() {
        let n = Arc::new(AtomicU64::new(0));
        let n2 = n.clone();
        let mut e = Emitter::new(Some(Arc::new(move |_| {
            n2.fetch_add(1, Ordering::Relaxed);
        })));
        let ev = || RunEvent::IterationFinished {
            run_id: Id::nil(),
            iteration: 0,
            status: anvil_domain::runner::RunIterationStatus::Passed,
            progress: RunProgress::default(),
        };
        for _ in 0..10_000 {
            e.emit(ev(), Class::Normal);
        }
        let delivered = n.load(Ordering::Relaxed);
        assert!((200..=260).contains(&delivered), "burst then rate limit: {delivered}");
        e.emit(ev(), Class::Always);
        e.emit(ev(), Class::Failure);
        assert_eq!(n.load(Ordering::Relaxed), delivered + 2);
        assert_eq!(e.dropped, 10_000 - delivered);
    }
}
