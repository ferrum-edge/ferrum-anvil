//! Load-generator self-measurement: process CPU time, peak RSS and open file
//! descriptors, sampled periodically. Uses `getrusage(RUSAGE_SELF)` and the
//! `/dev/fd` listing on Unix; on other platforms every value is `None` and the
//! report says the measurement is unavailable rather than inventing zeros.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub cpu: Duration,
    pub max_rss_bytes: u64,
}

#[cfg(unix)]
#[allow(unsafe_code)] // getrusage has no safe std equivalent; see SAFETY notes.
pub fn sample() -> Option<Sample> {
    // SAFETY: `rusage` is a plain C struct; zeroed is a valid initial value,
    // and getrusage only writes into the struct we pass.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointer to a live, properly aligned rusage.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    if rc != 0 {
        return None;
    }
    let tv = |t: libc::timeval| Duration::from_secs(t.tv_sec.max(0) as u64) + Duration::from_micros(t.tv_usec.max(0) as u64);
    let cpu = tv(ru.ru_utime) + tv(ru.ru_stime);
    let raw = ru.ru_maxrss.max(0) as u64;
    // macOS reports bytes; Linux and the BSDs report KiB.
    let max_rss_bytes = if cfg!(target_os = "macos") { raw } else { raw * 1024 };
    Some(Sample { cpu, max_rss_bytes })
}

#[cfg(not(unix))]
pub fn sample() -> Option<Sample> {
    None
}

/// Open descriptors of this process (sockets included).
pub fn open_fds() -> Option<u64> {
    if !cfg!(unix) {
        return None;
    }
    let dir = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    // The listing itself holds one descriptor while it is read.
    std::fs::read_dir(dir).ok().map(|d| d.count().saturating_sub(1) as u64)
}

pub const METHOD_NOTE: &str = "Generator CPU is process user+system time over wall time (100 % = one core) and RSS is the peak resident set, both from getrusage(RUSAGE_SELF); descriptors are counted from the process fd table. They describe the whole process that ran the load engine.";

pub struct HealthSampler {
    start: Option<(Instant, Sample)>,
    last: Option<(Instant, Sample)>,
    pub peak_cpu_percent: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
    pub peak_open_fds: Option<u64>,
}

impl Default for HealthSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthSampler {
    pub fn new() -> Self {
        let first = sample().map(|s| (Instant::now(), s));
        let mut h = HealthSampler {
            start: first,
            last: first,
            peak_cpu_percent: None,
            peak_rss_bytes: first.map(|(_, s)| s.max_rss_bytes),
            peak_open_fds: None,
        };
        h.peak_open_fds = open_fds();
        h
    }

    pub fn available(&self) -> bool {
        self.start.is_some()
    }

    pub fn sample(&mut self) {
        if let Some(fds) = open_fds() {
            self.peak_open_fds = Some(self.peak_open_fds.map_or(fds, |p| p.max(fds)));
        }
        let Some(now) = sample() else { return };
        let t = Instant::now();
        if let Some((t0, s0)) = self.last {
            let wall = t.duration_since(t0).as_secs_f64();
            // Very short intervals give meaningless ratios.
            if wall >= 0.05 {
                let pct = now.cpu.saturating_sub(s0.cpu).as_secs_f64() / wall * 100.0;
                self.peak_cpu_percent = Some(self.peak_cpu_percent.map_or(pct, |p| p.max(pct)));
                self.last = Some((t, now));
            }
        } else {
            self.last = Some((t, now));
        }
        self.peak_rss_bytes = Some(self.peak_rss_bytes.map_or(now.max_rss_bytes, |p| p.max(now.max_rss_bytes)));
    }

    /// Mean CPU percent since the sampler was created.
    pub fn mean_cpu_percent(&self) -> Option<f64> {
        let (t0, s0) = self.start?;
        let now = sample()?;
        let wall = t0.elapsed().as_secs_f64();
        (wall > 0.0).then(|| now.cpu.saturating_sub(s0.cpu).as_secs_f64() / wall * 100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn unix_sampling_reports_values() {
        let mut h = HealthSampler::new();
        assert!(h.available());
        let t = Instant::now();
        let mut x = 0u64;
        while t.elapsed() < Duration::from_millis(80) {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
        std::hint::black_box(x);
        h.sample();
        assert!(h.peak_cpu_percent.unwrap() > 1.0);
        assert!(h.peak_rss_bytes.unwrap() > 1024 * 1024);
        assert!(h.peak_open_fds.unwrap() >= 3);
    }
}
