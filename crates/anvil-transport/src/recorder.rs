//! Monotonic phase recording and bounded event emission.

use anvil_domain::Id;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::{Phase, PhaseStatus, PhaseTiming};
use std::sync::Arc;
use std::time::Instant;

/// Callback receiving live execution events. Implementations must not block
/// (use a bounded channel with `try_send` and drop on overflow).
pub type EventFn = Arc<dyn Fn(ExecutionEvent) + Send + Sync>;

#[derive(Clone)]
pub struct EventCtx {
    pub execution_id: Id,
    pub sink: Option<EventFn>,
}

impl EventCtx {
    pub fn none() -> Self {
        EventCtx { execution_id: Id::nil(), sink: None }
    }

    pub fn emit(&self, ev: ExecutionEvent) {
        if let Some(s) = &self.sink {
            s(ev);
        }
    }
}

pub struct Recorder {
    pub t0: Instant,
    pub phases: Vec<PhaseTiming>,
    pub attempt: u32,
    pub events: EventCtx,
}

impl Recorder {
    pub fn new(attempt: u32, events: EventCtx) -> Self {
        Recorder { t0: Instant::now(), phases: Vec::new(), attempt, events }
    }

    pub fn us(&self) -> u64 {
        self.t0.elapsed().as_micros() as u64
    }

    pub fn us_at(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.t0).as_micros() as u64
    }

    fn emit(&self, phase: Phase, status: PhaseStatus, offset: u64) {
        self.events.emit(ExecutionEvent::Phase {
            execution_id: self.events.execution_id,
            attempt: self.attempt,
            phase,
            status,
            offset_us: offset,
        });
    }

    /// Begin a measured phase; returns its index.
    pub fn start(&mut self, phase: Phase) -> usize {
        let now = self.us();
        self.phases.push(PhaseTiming { phase, status: PhaseStatus::Unknown, start_us: Some(now), end_us: None, detail: None });
        self.emit(phase, PhaseStatus::Unknown, now);
        self.phases.len() - 1
    }

    pub fn finish(&mut self, idx: usize, status: PhaseStatus) {
        let now = self.us();
        if let Some(p) = self.phases.get_mut(idx) {
            p.status = status;
            p.end_us = Some(now);
            let phase = p.phase;
            self.emit(phase, status, now);
        }
    }

    pub fn finish_with(&mut self, idx: usize, status: PhaseStatus, detail: impl Into<String>) {
        self.finish(idx, status);
        if let Some(p) = self.phases.get_mut(idx) {
            p.detail = Some(detail.into());
        }
    }

    /// Record a phase that has no measurement on this attempt.
    pub fn mark(&mut self, phase: Phase, status: PhaseStatus, detail: Option<&str>) {
        self.phases.push(PhaseTiming { phase, status, start_us: None, end_us: None, detail: detail.map(|s| s.to_string()) });
    }

    /// Close any still-open phase with the given status (on failure/cancel).
    pub fn close_open(&mut self, status: PhaseStatus) {
        let now = self.us();
        for p in self.phases.iter_mut() {
            if p.end_us.is_none() && p.start_us.is_some() {
                p.end_us = Some(now);
                p.status = status;
            }
        }
    }

    pub fn open_phase(&self) -> Option<Phase> {
        self.phases.iter().rev().find(|p| p.end_us.is_none() && p.start_us.is_some()).map(|p| p.phase)
    }
}
