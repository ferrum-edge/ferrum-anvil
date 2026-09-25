//! Stage math for timed workloads.
//!
//! A stage ramps linearly from the previous stage's target (0 before the
//! first stage) to its own target over `duration_secs`. A zero-duration stage
//! is an instantaneous step, so a constant rate `R` for `D` seconds is
//! `[{0 s → R}, {D s → R}]`, and a spike is a zero-duration step up followed
//! by a hold and a step down.

use anvil_domain::load::Stage;

/// Total schedule length in seconds.
pub fn total_secs(stages: &[Stage]) -> u64 {
    stages.iter().map(|s| s.duration_secs).sum()
}

/// Target (arrivals/s or virtual users) at `t` seconds after start.
pub fn target_at(stages: &[Stage], t: f64) -> f64 {
    let mut start = 0.0;
    let mut prev = 0.0;
    for s in stages {
        let d = s.duration_secs as f64;
        if d > 0.0 && t < start + d {
            return prev + (s.target as f64 - prev) * ((t - start).max(0.0) / d);
        }
        start += d;
        prev = s.target as f64;
    }
    prev
}

/// Active virtual users at `t` (floor of the ramped target).
pub fn vus_at(stages: &[Stage], t: f64) -> u64 {
    (target_at(stages, t) + 1e-9).floor().max(0.0) as u64
}

/// Earliest time `t ≥ from` at which the ramped target reaches `level`
/// (consistent with [`vus_at`]), or `None` if it never does before the
/// schedule ends. Lets an inactive virtual user sleep until its activation
/// instead of polling.
pub fn next_time_at_or_above(stages: &[Stage], from: f64, level: f64) -> Option<f64> {
    let lvl = level - 1e-9;
    let (mut start, mut prev) = (0.0, 0.0);
    for s in stages {
        let d = s.duration_secs as f64;
        let tgt = s.target as f64;
        if d == 0.0 {
            // A step: the next segment starts from this target.
            prev = tgt;
            continue;
        }
        let end = start + d;
        if end > from {
            let a = from.max(start);
            let va = prev + (tgt - prev) * ((a - start) / d);
            if va >= lvl {
                return Some(a);
            }
            if tgt >= lvl && tgt > prev {
                let t = start + (lvl - prev) / (tgt - prev) * d;
                return Some(t.clamp(a, end));
            }
        }
        start = end;
        prev = tgt;
    }
    None
}

/// Expected number of arrivals over the whole schedule (integral of the rate).
pub fn planned_arrivals(stages: &[Stage]) -> f64 {
    let mut prev = 0.0;
    let mut total = 0.0;
    for s in stages {
        let d = s.duration_secs as f64;
        total += (prev + s.target as f64) * 0.5 * d;
        prev = s.target as f64;
    }
    total
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    t0: f64,
    dur: f64,
    /// Rate at segment start.
    a: f64,
    /// Rate slope (per second).
    b: f64,
    /// Cumulative arrivals at segment start.
    n0: f64,
}

impl Segment {
    fn n_end(&self) -> f64 {
        self.n0 + self.a * self.dur + 0.5 * self.b * self.dur * self.dur
    }
}

/// Deterministic arrival offsets (seconds from start) for an open workload:
/// arrival `k` (0-based) happens when the cumulative planned arrivals reach
/// `k`. Independent of response times by construction.
pub struct Arrivals {
    segments: Vec<Segment>,
    idx: usize,
    k: u64,
}

impl Arrivals {
    pub fn new(stages: &[Stage]) -> Self {
        let mut segments = Vec::new();
        let (mut t0, mut prev, mut n0) = (0.0, 0.0, 0.0);
        for s in stages {
            let dur = s.duration_secs as f64;
            let target = s.target as f64;
            if dur > 0.0 {
                let seg = Segment { t0, dur, a: prev, b: (target - prev) / dur, n0 };
                n0 = seg.n_end();
                segments.push(seg);
                t0 += dur;
            }
            prev = target;
        }
        Arrivals { segments, idx: 0, k: 0 }
    }
}

impl Iterator for Arrivals {
    type Item = f64;

    fn next(&mut self) -> Option<f64> {
        let target = self.k as f64;
        while let Some(s) = self.segments.get(self.idx) {
            if target < s.n_end() - 1e-9 {
                let delta = (target - s.n0).max(0.0);
                let u = if delta == 0.0 {
                    0.0
                } else {
                    // Numerically stable root of n0 + a·u + b·u²/2 = target.
                    let disc = s.a * s.a + 2.0 * s.b * delta;
                    let denom = s.a + disc.max(0.0).sqrt();
                    if denom <= 0.0 {
                        self.idx += 1;
                        continue;
                    }
                    2.0 * delta / denom
                };
                self.k += 1;
                return Some(s.t0 + u.min(s.dur));
            }
            self.idx += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(d: u64, t: u64) -> Stage {
        Stage { duration_secs: d, target: t }
    }

    #[test]
    fn constant_rate_arrivals_are_evenly_spaced() {
        let a: Vec<f64> = Arrivals::new(&[st(0, 20), st(3, 20)]).collect();
        assert_eq!(a.len(), 60);
        assert_eq!(a[0], 0.0);
        assert!((a[1] - 0.05).abs() < 1e-9);
        assert!(a.iter().all(|t| *t < 3.0));
        assert_eq!(planned_arrivals(&[st(0, 20), st(3, 20)]), 60.0);
    }

    #[test]
    fn ramp_from_zero_integrates_the_rate() {
        let a: Vec<f64> = Arrivals::new(&[st(10, 10)]).collect();
        assert_eq!(a.len(), 50);
        assert!((a[1] - 2f64.sqrt()).abs() < 1e-9, "rate(t)=t so arrival 1 is at √2: {}", a[1]);
        assert!(a.windows(2).all(|w| w[1] >= w[0]));
    }

    #[test]
    fn ramp_down_and_step_stages() {
        // Step up to 10/s for 2 s, ramp down to 0 over 2 s: 20 + 10 arrivals.
        let stages = [st(0, 10), st(2, 10), st(2, 0)];
        let a: Vec<f64> = Arrivals::new(&stages).collect();
        assert_eq!(a.len(), 30);
        assert!(a.iter().all(|t| *t < 4.0));
        assert_eq!(total_secs(&stages), 4);
    }

    #[test]
    fn vus_follow_linear_ramp() {
        let stages = [st(10, 10), st(5, 10), st(0, 2), st(5, 2)];
        assert_eq!(vus_at(&stages, 0.0), 0);
        assert_eq!(vus_at(&stages, 3.5), 3);
        assert_eq!(vus_at(&stages, 12.0), 10);
        assert_eq!(vus_at(&stages, 16.0), 2);
    }

    #[test]
    fn activation_times_match_the_ramp() {
        // Ramp 0→10 over 10 s, hold, drop to 2, ramp back up to 6 over 4 s.
        let stages = [st(10, 10), st(5, 10), st(0, 2), st(4, 6)];
        assert!((next_time_at_or_above(&stages, 0.0, 3.0).unwrap() - 3.0).abs() < 1e-6);
        assert_eq!(next_time_at_or_above(&stages, 12.0, 10.0), Some(12.0), "already active");
        let t = next_time_at_or_above(&stages, 15.5, 5.0).unwrap();
        assert!((t - 18.0).abs() < 1e-6, "second ramp 2→6 over 15–19 s reaches 5 at 18 s: {t}");
        assert_eq!(next_time_at_or_above(&stages, 15.5, 7.0), None, "never reached again");
        let steps = [st(0, 4), st(2, 4)];
        assert_eq!(next_time_at_or_above(&steps, 0.0, 4.0), Some(0.0), "a zero-duration step activates immediately");
        // Consistency with vus_at on a grid.
        for vu in 0..10u64 {
            if let Some(t) = next_time_at_or_above(&stages, 0.0, (vu + 1) as f64) {
                assert!(vus_at(&stages, t + 1e-6) > vu, "vu {vu} active at {t}");
                assert!(t < 1e-9 || vus_at(&stages, t - 1e-3) <= vu, "vu {vu} not active before {t}");
            }
        }
    }
}
