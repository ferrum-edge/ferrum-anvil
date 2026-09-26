//! Standalone, offline HTML load report.
//!
//! * Inline CSS and inline SVG only: no scripts, no external stylesheets,
//!   fonts or images; a restrictive Content-Security-Policy is embedded so a
//!   viewer blocks any network or script even if content slipped through.
//! * Every dynamic string (plan name, destinations, failure samples, notes —
//!   several are response-derived) goes through [`esc`].
//! * Hover detail uses SVG `<title>` (native tooltips, no JavaScript); the
//!   timeline table is the accessible data view.

use anvil_domain::load::*;
use std::fmt::Write as _;

/// Escape text for HTML element content and quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => o.push('\u{FFFD}'),
            c => o.push(c),
        }
    }
    o
}

pub fn fmt_us(us: u64) -> String {
    match us {
        0..1_000 => format!("{us} µs"),
        1_000..1_000_000 => format!("{:.2} ms", us as f64 / 1e3),
        _ => format!("{:.2} s", us as f64 / 1e6),
    }
}

pub fn fmt_n(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    o
}

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", U[i]) }
}

const CSS: &str = r#"
.viz-root{color-scheme:light;--page:#f9f9f7;--surface-1:#fcfcfb;--text-primary:#0b0b0b;--text-secondary:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--series-1:#2a78d6;--series-2:#eb6834;--series-3:#1baf7a;--band:#f0efec;--critical:#d03b3b;--warning:#fab219;--good:#0ca30c}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--page:#0d0d0d;--surface-1:#1a1a19;--text-primary:#fff;--text-secondary:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--band:#262624}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--page:#0d0d0d;--surface-1:#1a1a19;--text-primary:#fff;--text-secondary:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--band:#262624}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body.viz-root{background:var(--page);color:var(--text-primary);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px;font-weight:600}
h2{font-size:16px;margin:32px 0 8px;font-weight:600}
.sub{color:var(--text-secondary);margin:0}
.card{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:16px;margin:12px 0;overflow-x:auto}
.banner{border-left:4px solid var(--critical);background:var(--surface-1);border-radius:6px;padding:12px 16px;margin:16px 0}
.banner.warn{border-left-color:var(--warning)}
.banner strong{font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.tile .label{color:var(--text-secondary);font-size:12px}
.tile .value{font-size:22px;font-weight:600}
.tile .hint{color:var(--muted);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--text-secondary);font-weight:600}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
ul.examples{margin:4px 0 0;padding-left:18px;color:var(--text-secondary)}
.legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--text-secondary);font-size:12px;margin:0 0 6px}
.key{display:inline-block;width:14px;height:2px;vertical-align:middle;margin-right:6px;border-radius:1px}
svg{display:block;width:100%;height:auto}
svg text{fill:var(--muted);font:11px system-ui,-apple-system,"Segoe UI",sans-serif}
svg .lbl{fill:var(--text-secondary)}
.ok{color:var(--text-secondary)}
details summary{cursor:pointer;color:var(--text-secondary)}
footer{color:var(--muted);font-size:12px;margin-top:32px}
"#;

fn nice_step(max: f64, ticks: f64) -> f64 {
    if max <= 0.0 {
        return 1.0;
    }
    let raw = max / ticks;
    let mag = 10f64.powf(raw.log10().floor());
    let n = raw / mag;
    let m = if n <= 1.0 {
        1.0
    } else if n <= 2.0 {
        2.0
    } else if n <= 5.0 {
        5.0
    } else {
        10.0
    };
    m * mag
}

struct Series<'a> {
    label: &'a str,
    var: &'a str,
    points: Vec<(f64, f64)>,
}

const W: f64 = 720.0;
const H: f64 = 220.0;
const L: f64 = 56.0;
const R: f64 = 110.0;
const T: f64 = 12.0;
const B: f64 = 28.0;

/// Single-axis line chart with a warmup band, hairline grid, direct end
/// labels (when they don't collide) and native `<title>` hover bands.
fn line_chart(aria: &str, series: &[Series], x_max: f64, warmup: f64, y_fmt: &dyn Fn(f64) -> String, hover: &[(f64, String)]) -> String {
    let y_max_raw = series.iter().flat_map(|s| s.points.iter().map(|p| p.1)).fold(0.0, f64::max);
    let step = nice_step(y_max_raw, 4.0);
    let y_max = (y_max_raw / step).ceil().max(1.0) * step;
    let x_max = x_max.max(1.0);
    let pw = W - L - R;
    let ph = H - T - B;
    let sx = |x: f64| L + x / x_max * pw;
    let sy = |y: f64| T + ph - y / y_max * ph;
    let mut s = String::new();
    let _ = write!(s, r#"<svg viewBox="0 0 {W} {H}" role="img" aria-label="{}">"#, esc(aria));
    if warmup > 0.0 {
        let _ = write!(
            s,
            r#"<rect x="{:.1}" y="{T}" width="{:.1}" height="{ph}" fill="var(--band)"/><text x="{:.1}" y="{:.1}">warmup</text>"#,
            sx(0.0),
            sx(warmup.min(x_max)) - sx(0.0),
            sx(0.0) + 4.0,
            T + 12.0
        );
    }
    let mut y = 0.0;
    while y <= y_max + step / 2.0 {
        let py = sy(y);
        let stroke = if y == 0.0 { "var(--axis)" } else { "var(--grid)" };
        let _ = write!(
            s,
            r#"<line x1="{L}" x2="{:.1}" y1="{py:.1}" y2="{py:.1}" stroke="{stroke}" stroke-width="1"/><text x="{:.1}" y="{:.1}" text-anchor="end">{}</text>"#,
            L + pw,
            L - 6.0,
            py + 4.0,
            esc(&y_fmt(y))
        );
        y += step;
    }
    let xstep = nice_step(x_max, 6.0).max(1.0);
    let mut x = 0.0;
    while x <= x_max + 1e-9 {
        let _ = write!(s, r#"<text x="{:.1}" y="{:.1}" text-anchor="middle">{}s</text>"#, sx(x), H - 8.0, x as u64);
        x += xstep;
    }
    let mut ends: Vec<(f64, &str)> = Vec::new();
    for se in series {
        if se.points.is_empty() {
            continue;
        }
        let pts: Vec<String> = se.points.iter().map(|(x, y)| format!("{:.1},{:.1}", sx(*x), sy(*y))).collect();
        let _ = write!(
            s,
            r#"<polyline points="{}" fill="none" stroke="var({})" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>"#,
            pts.join(" "),
            se.var
        );
        let (lx, ly) = *se.points.last().expect("non-empty");
        let _ = write!(
            s,
            r#"<circle cx="{:.1}" cy="{:.1}" r="4" fill="var({})" stroke="var(--surface-1)" stroke-width="2"/>"#,
            sx(lx),
            sy(ly),
            se.var
        );
        ends.push((sy(ly), se.label));
    }
    ends.sort_by(|a, b| a.0.total_cmp(&b.0));
    let collide = ends.windows(2).any(|w| w[1].0 - w[0].0 < 13.0);
    if !collide {
        for (py, label) in &ends {
            let _ = write!(s, r#"<text class="lbl" x="{:.1}" y="{:.1}">{}</text>"#, L + pw + 10.0, py + 4.0, esc(label));
        }
    }
    // Native hover bands (no script). Bounded for long timelines.
    if !hover.is_empty() && hover.len() <= 900 {
        let bw = (pw / hover.len() as f64).max(1.0);
        for (hx, title) in hover {
            let _ = write!(
                s,
                r#"<rect x="{:.1}" y="{T}" width="{bw:.1}" height="{ph}" fill="transparent"><title>{}</title></rect>"#,
                sx(*hx).min(L + pw - bw),
                esc(title)
            );
        }
    }
    s.push_str("</svg>");
    s
}

fn legend(items: &[(&str, &str)]) -> String {
    let mut s = String::from(r#"<div class="legend">"#);
    for (label, var) in items {
        let _ = write!(s, r#"<span><span class="key" style="background:var({var})"></span>{}</span>"#, esc(label));
    }
    s.push_str("</div>");
    s
}

fn status_bars(dist: &[(u16, u64)]) -> String {
    if dist.is_empty() {
        return r#"<p class="ok">No responses were received.</p>"#.into();
    }
    let max = dist.iter().map(|d| d.1).max().unwrap_or(1).max(1) as f64;
    let row = 30.0;
    let bar_h = 18.0;
    let (lw, rw) = (60.0, 90.0);
    let h = dist.len() as f64 * row + 8.0;
    let pw = W - lw - rw;
    let mut s = format!(r#"<svg viewBox="0 0 {W} {h}" role="img" aria-label="Response status distribution">"#);
    let _ = write!(s, r#"<line x1="{lw}" x2="{lw}" y1="0" y2="{h}" stroke="var(--axis)" stroke-width="1"/>"#);
    for (i, (status, n)) in dist.iter().enumerate() {
        let y = 4.0 + i as f64 * row + (row - bar_h) / 2.0;
        let w = (*n as f64 / max * pw).max(2.0);
        let r = 4f64.min(w / 2.0).min(bar_h / 2.0);
        let x0 = lw;
        let x1 = lw + w;
        let _ = write!(
            s,
            r#"<text class="lbl" x="{:.1}" y="{:.1}" text-anchor="end">{status}</text><path d="M{x0:.1} {y:.1} H{:.1} Q{x1:.1} {y:.1} {x1:.1} {:.1} V{:.1} Q{x1:.1} {:.1} {:.1} {:.1} H{x0:.1} Z" fill="var(--series-1)"><title>HTTP {status}: {} responses</title></path><text class="lbl" x="{:.1}" y="{:.1}">{}</text>"#,
            lw - 8.0,
            y + bar_h / 2.0 + 4.0,
            x1 - r,
            y + r,
            y + bar_h - r,
            y + bar_h,
            x1 - r,
            y + bar_h,
            fmt_n(*n),
            x1 + 6.0,
            y + bar_h / 2.0 + 4.0,
            fmt_n(*n)
        );
    }
    s.push_str("</svg>");
    s
}

fn tile(label: &str, value: &str, hint: &str) -> String {
    format!(
        r#"<div class="tile"><div class="label">{}</div><div class="value">{}</div><div class="hint">{}</div></div>"#,
        esc(label),
        esc(value),
        esc(hint)
    )
}

fn latency_row(name: &str, l: &LatencySummary) -> String {
    if l.count == 0 {
        // No sample means no value — never "0 µs".
        let dash = r#"<td class="num">—</td>"#.repeat(7);
        return format!(r#"<tr><td>{}</td><td class="num">0</td>{dash}</tr>"#, esc(name));
    }
    format!(
        r#"<tr><td>{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td></tr>"#,
        esc(name),
        fmt_n(l.count),
        fmt_us(l.min_us),
        fmt_us(l.p50_us),
        fmt_us(l.p90_us),
        fmt_us(l.p95_us),
        fmt_us(l.p99_us),
        fmt_us(l.max_us),
        fmt_us(l.mean_us)
    )
}

/// Canonical gRPC status code names.
pub fn grpc_code_name(code: i32) -> &'static str {
    match code {
        0 => "OK",
        1 => "CANCELLED",
        2 => "UNKNOWN",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        6 => "ALREADY_EXISTS",
        7 => "PERMISSION_DENIED",
        8 => "RESOURCE_EXHAUSTED",
        9 => "FAILED_PRECONDITION",
        10 => "ABORTED",
        11 => "OUT_OF_RANGE",
        12 => "UNIMPLEMENTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        15 => "DATA_LOSS",
        16 => "UNAUTHENTICATED",
        _ => "non-standard code",
    }
}

fn closed_text(c: anvil_domain::outcome::ClosedBy) -> &'static str {
    use anvil_domain::outcome::ClosedBy::*;
    match c {
        Peer => "peer",
        Client => "client (stop condition or close)",
        Abnormal => "abnormal (no close handshake)",
        Timeout => "timeout (idle or deadline)",
        NotClosed => "not closed",
    }
}

fn kv_table(rows: &[(&str, String)]) -> String {
    let mut s = String::from("<table>");
    for (k, v) in rows {
        let _ = write!(s, r#"<tr><th>{}</th><td class="num">{}</td></tr>"#, esc(k), esc(v));
    }
    s.push_str("</table>");
    s
}

fn ratio(n: u64, d: u64) -> String {
    if d == 0 { "—".into() } else { format!("{:.3}", n as f64 / d as f64) }
}

/// The unit's definitions and its protocol denominators.
fn protocol_section(p: &ProtocolLoadMetrics) -> String {
    let mut h = String::new();
    let sem = &p.semantics;
    let _ = write!(
        h,
        r#"<h2>Protocol: {}</h2><div class="card"><table><tr><th>Unit</th><td>{}</td></tr><tr><th>Completed</th><td>{}</td></tr><tr><th>Success</th><td>{}</td></tr><tr><th>Latency</th><td>{}</td></tr><tr><th>Connections</th><td>{}</td></tr></table>"#,
        esc(crate::protocol::label(p.unit)),
        esc(&sem.unit_singular),
        esc(&sem.completed_means),
        esc(&sem.success_means),
        esc(&sem.latency_means),
        esc(&sem.connection_mode_means)
    );
    let lat_head = r#"<table><tr><th>Distribution</th><th class="num">Count</th><th class="num">Min</th><th class="num">p50</th><th class="num">p90</th><th class="num">p95</th><th class="num">p99</th><th class="num">Max</th><th class="num">Mean</th></tr>"#;
    if let Some(x) = &p.http {
        h.push_str(&kv_table(&[
            ("HTTP/3 → TCP fallback attempts (extra attempts, not requests)", fmt_n(x.protocol_fallback_attempts)),
            ("Requests that needed a fallback", fmt_n(x.units_with_fallback)),
            ("Requests completed over HTTP/3", fmt_n(x.units_over_h3)),
        ]));
    }
    if let Some(g) = &p.grpc {
        h.push_str(&kv_table(&[
            ("Status OK", fmt_n(g.ok)),
            ("Status non-OK", fmt_n(g.non_ok)),
            ("Response without a terminal status (incomplete, never success)", fmt_n(g.missing_status)),
            ("HTTP/3 → TCP fallback attempts", fmt_n(g.protocol_fallback_attempts)),
        ]));
        if !g.status_codes.is_empty() {
            h.push_str(r#"<table><tr><th>grpc-status</th><th>Name</th><th class="num">Completed</th></tr>"#);
            for (code, n) in &g.status_codes {
                let _ = write!(
                    h,
                    r#"<tr><td class="num">{code}</td><td>{}</td><td class="num">{}</td></tr>"#,
                    grpc_code_name(*code),
                    fmt_n(*n)
                );
            }
            h.push_str("</table>");
        }
    }
    if let Some(s) = &p.stream {
        let per = if s.opened == 0 { "—".to_string() } else { format!("{:.1}", s.messages_received as f64 / s.opened as f64) };
        h.push_str(&kv_table(&[
            ("Streams opened", fmt_n(s.opened)),
            (if p.unit == LoadUnitKind::SseStream { "Events received" } else { "Messages received" }, fmt_n(s.messages_received)),
            ("Opened streams with at least one", fmt_n(s.with_messages)),
            ("Mean per opened stream", per),
        ]));
        h.push_str(lat_head);
        h.push_str(&latency_row("Time to first message/event", &s.time_to_first_message));
        h.push_str("</table>");
        if !s.ended_by.is_empty() {
            let rows: Vec<(&str, String)> = s.ended_by.iter().map(|c| (closed_text(c.closed_by), fmt_n(c.count))).collect();
            h.push_str("<p class=\"sub\">How opened streams ended:</p>");
            h.push_str(&kv_table(&rows));
        }
    }
    if let Some(w) = &p.websocket {
        h.push_str(&kv_table(&[
            ("Sessions opened (handshake accepted)", fmt_n(w.opened)),
            ("Handshake rejected (server answered another status)", fmt_n(w.handshake_rejected)),
            ("Not opened (DNS, connect, TLS, invalid handshake, timeout, cancel)", fmt_n(w.not_opened)),
            ("Opened and closed cleanly", fmt_n(w.closed_cleanly)),
            ("Messages sent", fmt_n(w.messages_sent)),
            ("Messages received", fmt_n(w.messages_received)),
        ]));
        if w.rtt_defined {
            h.push_str(lat_head);
            h.push_str(&latency_row("Round trip (i-th sent → i-th received)", &w.rtt));
            h.push_str("</table>");
            let _ = write!(
                h,
                r#"<p class="sub">{} pair(s); {} session(s) could not be paired.</p>"#,
                fmt_n(w.rtt_pairs),
                fmt_n(w.rtt_unpaired_sessions)
            );
        } else {
            h.push_str(r#"<p class="sub">Round-trip time: not defined — the request does not set expect_messages, so messages are not paired.</p>"#);
        }
        if !w.close_codes.is_empty() {
            h.push_str(r#"<table><tr><th>Closed by</th><th class="num">Code</th><th class="num">Sessions</th></tr>"#);
            for c in &w.close_codes {
                let _ = write!(
                    h,
                    r#"<tr><td>{}</td><td class="num">{}</td><td class="num">{}</td></tr>"#,
                    closed_text(c.closed_by),
                    c.code.map(|c| c.to_string()).unwrap_or_else(|| "—".into()),
                    fmt_n(c.count)
                );
            }
            h.push_str("</table>");
        }
    }
    if let Some(t) = &p.tcp {
        h.push_str(&kv_table(&[
            ("Connections set up", fmt_n(t.connected)),
            ("Frames sent / received", format!("{} / {}", fmt_n(t.frames_sent), fmt_n(t.frames_received))),
            ("Payload bytes sent / received", format!("{} / {}", fmt_bytes(t.payload_bytes_sent), fmt_bytes(t.payload_bytes_received))),
            ("Exchanges ending with a partial frame", fmt_n(t.partial_frames)),
            ("Exchanges the peer closed", fmt_n(t.peer_closes)),
            ("Expected frames per exchange", t.expected_frames.map(|f| f.to_string()).unwrap_or_else(|| "not defined".into())),
            ("Expected frames received / short", format!("{} / {}", fmt_n(t.expectation_met), fmt_n(t.expectation_short))),
        ]));
    }
    if let Some(d) = &p.datagram {
        h.push_str(&kv_table(&[
            ("Datagrams sent", fmt_n(d.datagrams_sent)),
            ("Datagrams received", fmt_n(d.datagrams_received)),
            ("Received per sent (observed ratio, not a delivery rate)", ratio(d.datagrams_received, d.datagrams_sent)),
            ("Exchanges with a response", fmt_n(d.exchanges_with_response)),
            ("Exchanges with no response observed", fmt_n(d.exchanges_silent)),
            ("Repeated payloads (identical to an earlier received one)", fmt_n(d.repeated_payloads)),
            (
                "Echoed payloads / other payloads",
                format!("{} / {}", fmt_n(d.echoed_payloads), fmt_n(d.datagrams_received.saturating_sub(d.echoed_payloads))),
            ),
            ("Exchanges with ICMP port unreachable", fmt_n(d.icmp_unreachable_exchanges)),
        ]));
        h.push_str(lat_head);
        h.push_str(&latency_row("Time to first response", &d.time_to_first_datagram));
        if let Some(hs) = &d.dtls_handshakes {
            h.push_str(&latency_row("DTLS handshake (completed)", &hs.duration));
        }
        h.push_str("</table>");
        if let Some(hs) = &d.dtls_handshakes {
            h.push_str(&kv_table(&[
                ("DTLS handshakes attempted", fmt_n(hs.attempted)),
                ("Completed / failed / timed out", format!("{} / {} / {}", fmt_n(hs.completed), fmt_n(hs.failed), fmt_n(hs.timed_out))),
            ]));
        }
        h.push_str(r#"<p class="sub">Sent and received are separate counts. UDP has no acknowledgement: nothing here claims delivery or loss, and received datagrams are not attributed to sent ones. Silence means only that no response was observed.</p>"#);
    }
    h.push_str("</div>");
    h
}

fn completion_text(c: RunCompletion) -> &'static str {
    match c {
        RunCompletion::Completed => "Completed",
        RunCompletion::CanceledByUser => "Canceled by the user",
        RunCompletion::AbortedByRule => "Aborted by an abort rule",
        RunCompletion::WorkerCrashed => "Load worker crashed",
        RunCompletion::StoppedByLock => "Stopped because the vault locked",
    }
}

/// Singular and plural unit nouns of a report (`request`/`requests` for
/// reports written before protocol load existed).
pub fn unit_words(r: &LoadReport) -> (String, String) {
    match &r.protocol_metrics {
        Some(p) => (p.semantics.unit_singular.clone(), p.semantics.unit_plural.clone()),
        None => ("request".into(), "requests".into()),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Render the report as a single self-contained HTML document.
pub fn to_html(r: &LoadReport) -> String {
    let mut h = String::with_capacity(32 * 1024);
    let title = format!("Load report — {}", r.plan.name);
    let _ = write!(
        h,
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"><meta name="referrer" content="no-referrer"><title>{}</title><style>{CSS}</style></head><body class="viz-root"><main>"#,
        esc(&title)
    );
    let _ = write!(
        h,
        r#"<h1>{}</h1><p class="sub">{} · run <span class="mono">{}</span> · {} → {} · {} {}</p>"#,
        esc(&r.plan.name),
        esc(completion_text(r.completion)),
        esc(&r.run_id.to_string()),
        esc(&r.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        esc(&r.finished_at.format("%H:%M:%S UTC").to_string()),
        esc(&r.engine),
        esc(&r.engine_version)
    );
    if r.partial {
        let _ = write!(
            h,
            r#"<div class="banner"><strong>Partial report — {}.</strong> These results do not cover the planned run; do not read them as a full-duration result.</div>"#,
            esc(completion_text(r.completion))
        );
    }
    if r.generator.target_not_achieved {
        h.push_str(r#"<div class="banner warn"><strong>Target not achieved.</strong> The generator did not sustain the planned arrival rate; this run does not establish the target's capacity. See generator health below.</div>"#);
    }
    let _ = write!(h, r#"<div class="card"><p class="sub">{}</p>"#, esc(&r.workload_label));
    let _ = write!(
        h,
        r#"<p class="sub">Destinations: {} · connection mode {} · warmup {} s (excluded from metrics) · seed {}{}</p></div>"#,
        if r.destination_summary.is_empty() { "none observed".into() } else { esc(&r.destination_summary.join(", ")) },
        esc(&format!("{:?}", r.plan.connection_mode).to_lowercase()),
        r.plan.warmup_secs,
        r.plan.seed,
        r.dataset_sha256.as_ref().map(|d| format!(" · dataset sha256 <span class=\"mono\">{}</span>", esc(d))).unwrap_or_default()
    );

    // Tiles.
    let c = &r.counts;
    let q = &r.requests;
    let (one, many) = unit_words(r);
    let title_many = capitalize(&many);
    let failed = q.transport_failures + q.timeouts + q.application_failures.max(q.assertion_failures);
    let finished = q.completed + q.transport_failures + q.timeouts;
    let err_pct = if finished > 0 { failed as f64 * 100.0 / finished as f64 } else { 0.0 };
    h.push_str(r#"<div class="tiles">"#);
    h.push_str(&tile("Achieved rate", &format!("{:.1}/s", r.achieved_rate_per_sec), "iterations started per second"));
    if let Some(o) = r.offered_rate_per_sec {
        h.push_str(&tile("Offered rate", &format!("{o:.1}/s"), "arrivals scheduled per second"));
    }
    // No successful unit means no success latency, never "0 µs".
    let success_us = |v: u64| if r.latency_success.count == 0 { "—".to_string() } else { fmt_us(v) };
    let sub = if r.latency_success.count == 0 { format!("no successful {many}") } else { "merged histogram".to_string() };
    h.push_str(&tile("p50 success", &success_us(r.latency_success.p50_us), &sub));
    h.push_str(&tile("p99 success", &success_us(r.latency_success.p99_us), &sub));
    h.push_str(&tile(&format!("Failed {many}"), &format!("{err_pct:.1} %"), &format!("{} of {} finished", fmt_n(failed), fmt_n(finished))));
    h.push_str(&tile("Dropped arrivals", &fmt_n(c.dropped), "never started, no latency"));
    h.push_str(&tile("Timeouts", &fmt_n(r.timeouts_censored.count), "censored, excluded from latency"));
    h.push_str("</div>");

    // Counts.
    let balanced = crate::report::check_balance(c).is_ok() && crate::report::check_request_balance(q).is_ok();
    h.push_str(r#"<h2>Accounting</h2><div class="card"><table><tr><th></th><th class="num">Scheduled</th><th class="num">Started</th><th class="num">Dropped</th><th class="num">Completed</th><th class="num">Transport failures</th><th class="num">Timeouts</th><th class="num">Canceled</th><th class="num">In flight at end</th><th class="num">App failures</th><th class="num">Assertion failures</th></tr>"#);
    let _ = write!(
        h,
        r#"<tr><td>Iterations</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td></tr>"#,
        fmt_n(c.scheduled),
        fmt_n(c.started),
        fmt_n(c.dropped),
        fmt_n(c.completed),
        fmt_n(c.transport_failures),
        fmt_n(c.timeouts),
        fmt_n(c.canceled),
        fmt_n(c.in_flight_at_end),
        fmt_n(c.application_failures),
        fmt_n(c.assertion_failures)
    );
    let _ = write!(
        h,
        r#"<tr><td>{title_many}</td><td class="num">—</td><td class="num">{}</td><td class="num">—</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td></tr></table>"#,
        fmt_n(q.started),
        fmt_n(q.completed),
        fmt_n(q.transport_failures),
        fmt_n(q.timeouts),
        fmt_n(q.canceled),
        fmt_n(q.in_flight_at_end),
        fmt_n(q.application_failures),
        fmt_n(q.assertion_failures)
    );
    let balanced = balanced && crate::report::check_protocol_balance(r).is_ok();
    let _ = write!(
        h,
        r#"<p class="sub">{} One iteration runs the plan's chain (or one weighted pick); each step is one {one}. Scheduled = started + dropped; started = completed + transport failures + timeouts + canceled + in flight at end. Application and assertion failures are subsets of completed. Connections: {} opened, {} reused. Bytes (logical): {} sent, {} received over {:.1} s measured.</p></div>"#,
        if balanced { "Counts balance." } else { "WARNING: counts do not balance — treat this report as suspect." },
        fmt_n(q.connections_opened),
        fmt_n(q.connections_reused),
        fmt_bytes(r.bytes_sent),
        fmt_bytes(r.bytes_received),
        r.measured_duration_secs
    );

    if let Some(p) = &r.protocol_metrics {
        h.push_str(&protocol_section(p));
    }

    // Latency.
    h.push_str(r#"<h2>Latency</h2><div class="card"><table><tr><th>Distribution</th><th class="num">Count</th><th class="num">Min</th><th class="num">p50</th><th class="num">p90</th><th class="num">p95</th><th class="num">p99</th><th class="num">Max</th><th class="num">Mean</th></tr>"#);
    h.push_str(&latency_row(&format!("Successful {many}"), &r.latency_success));
    h.push_str(&latency_row(&format!("Failed {many} (to failure)"), &r.latency_failure));
    h.push_str(&latency_row("Setup (prepare, token, backoff)", &r.latency_setup));
    h.push_str(&latency_row("Timeouts — censored, not latency", &r.timeouts_censored.elapsed_at_timeout));
    let _ = write!(
        h,
        r#"</table><p class="sub">{} Percentiles cover successful {} only (— when there are none) and come from HDR histograms merged across all workers before any percentile is computed; they are never averages of per-worker percentiles. {}</p></div>"#,
        esc(&r.protocol_metrics.as_ref().map(|p| p.semantics.latency_means.clone()).unwrap_or_default()),
        esc(&many),
        if r.timeouts_censored.count > 0 { esc(&r.timeouts_censored.label) } else { String::new() }
    );

    // Charts.
    let tl: Vec<&TimeBucket> = r.timeline.iter().collect();
    if !tl.is_empty() {
        let width = if tl.len() > 1 { (tl[1].second - tl[0].second).max(1) } else { 1 } as f64;
        let x_max = tl.last().map(|b| b.second as f64 + width).unwrap_or(1.0);
        let per_s =
            |f: &dyn Fn(&TimeBucket) -> u64| tl.iter().map(|b| (b.second as f64 + width / 2.0, f(b) as f64 / width)).collect::<Vec<_>>();
        let mut series = vec![
            Series { label: "Completed", var: "--series-1", points: per_s(&|b| b.completed) },
            Series { label: "Failures", var: "--series-2", points: per_s(&|b| b.failures) },
        ];
        let has_drops = tl.iter().any(|b| b.dropped > 0);
        if has_drops {
            series.push(Series { label: "Dropped", var: "--series-3", points: per_s(&|b| b.dropped) });
        }
        let hover: Vec<(f64, String)> = tl
            .iter()
            .map(|b| {
                (
                    b.second as f64,
                    format!(
                        "{} s{}: started {}, completed {}, failures {}, dropped {}, peak in flight {}",
                        b.second,
                        if b.warmup { " (warmup)" } else { "" },
                        b.started,
                        b.completed,
                        b.failures,
                        b.dropped,
                        b.in_flight
                    ),
                )
            })
            .collect();
        h.push_str(r#"<h2>Throughput per second</h2><div class="card">"#);
        let (completed_label, failed_label) = (format!("Completed {many}"), format!("Failed {many}"));
        let mut items = vec![(completed_label.as_str(), "--series-1"), (failed_label.as_str(), "--series-2")];
        if has_drops {
            items.push(("Dropped arrivals", "--series-3"));
        }
        h.push_str(&legend(&items));
        h.push_str(&line_chart(
            &format!("{title_many} completed, failed and arrivals dropped per second"),
            &series,
            x_max,
            r.plan.warmup_secs as f64,
            &|v| format!("{v:.0}"),
            &hover,
        ));
        h.push_str("</div>");

        let lat: Vec<&TimeBucket> = tl.iter().copied().filter(|b| b.p50_us > 0).collect();
        if !lat.is_empty() {
            let ms = |f: &dyn Fn(&TimeBucket) -> u64| {
                lat.iter().map(|b| (b.second as f64 + width / 2.0, f(b) as f64 / 1000.0)).collect::<Vec<_>>()
            };
            let series = [
                Series { label: "p50", var: "--series-1", points: ms(&|b| b.p50_us) },
                Series { label: "p99", var: "--series-2", points: ms(&|b| b.p99_us) },
            ];
            let hover: Vec<(f64, String)> = lat
                .iter()
                .map(|b| {
                    (b.second as f64, format!("{} s: p50 {}, p99 {} (successful {many})", b.second, fmt_us(b.p50_us), fmt_us(b.p99_us)))
                })
                .collect();
            let _ = write!(h, r#"<h2>Successful-{one} latency per second</h2><div class="card">"#);
            h.push_str(&legend(&[("p50", "--series-1"), ("p99", "--series-2")]));
            h.push_str(&line_chart(
                &format!("Successful-{one} latency p50 and p99 per second, milliseconds"),
                &series,
                x_max,
                r.plan.warmup_secs as f64,
                &|v| format!("{v:.0} ms"),
                &hover,
            ));
            h.push_str("</div>");
        }
    }
    h.push_str(r#"<h2>Response status</h2><div class="card">"#);
    h.push_str(&status_bars(&r.status_distribution));
    h.push_str("</div>");

    // Failures.
    h.push_str(r#"<h2>Failure categories</h2><div class="card">"#);
    if r.failure_categories.is_empty() {
        h.push_str(r#"<p class="ok">No failures in the measured window.</p>"#);
    } else {
        h.push_str(r#"<table><tr><th>Category</th><th class="num">Count</th></tr>"#);
        for f in &r.failure_categories {
            let _ = write!(h, r#"<tr><td><code>{}</code><ul class="examples">"#, esc(&f.category));
            for e in &f.examples {
                let _ = write!(h, "<li><code>{}</code></li>", esc(e));
            }
            let _ = write!(h, r#"</ul></td><td class="num">{}</td></tr>"#, fmt_n(f.count));
        }
        h.push_str(r#"</table><p class="sub">Examples are bounded per category and taken from redacted execution records.</p>"#);
    }
    h.push_str("</div>");

    // Generator.
    let g = &r.generator;
    h.push_str(r#"<h2>Generator health</h2><div class="card"><table>"#);
    let na = "unavailable".to_string();
    for (k, v) in [
        ("Peak CPU", g.peak_cpu_percent.map(|v| format!("{v:.0} % of one core")).unwrap_or(na.clone())),
        ("Peak RSS", g.peak_rss_bytes.map(fmt_bytes).unwrap_or(na.clone())),
        ("Peak open descriptors", g.peak_open_fds.map(fmt_n).unwrap_or(na.clone())),
        ("Start lag p99 / max", format!("{} / {}", fmt_us(g.p99_schedule_lag_us), fmt_us(g.max_schedule_lag_us))),
        ("Target achieved", if g.target_not_achieved { "no".into() } else { "yes or not applicable".into() }),
    ] {
        let _ = write!(h, r#"<tr><th>{}</th><td>{}</td></tr>"#, esc(k), esc(&v));
    }
    h.push_str("</table><ul class=\"examples\">");
    for n in &g.notes {
        let _ = write!(h, "<li>{}</li>", esc(n));
    }
    h.push_str("</ul></div>");

    h.push_str(r#"<h2>Notes</h2><div class="card"><ul class="examples">"#);
    for n in &r.notes {
        let _ = write!(h, "<li>{}</li>", esc(n));
    }
    h.push_str("</ul></div>");

    if !r.timeline.is_empty() {
        h.push_str(r#"<details class="card"><summary>Timeline table</summary><table><tr><th class="num">Second</th><th>Phase</th><th class="num">Started</th><th class="num">Completed</th><th class="num">Failures</th><th class="num">Dropped</th><th class="num">Peak in flight</th><th class="num">p50</th><th class="num">p99</th><th class="num">Start lag p99</th></tr>"#);
        for b in &r.timeline {
            let _ = write!(
                h,
                r#"<tr><td class="num">{}</td><td>{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td></tr>"#,
                b.second,
                if b.warmup { "warmup" } else { "measured" },
                b.started,
                b.completed,
                b.failures,
                b.dropped,
                b.in_flight,
                fmt_us(b.p50_us),
                fmt_us(b.p99_us),
                fmt_us(b.p99_schedule_lag_us)
            );
        }
        h.push_str("</table></details>");
    }
    let _ = write!(
        h,
        r#"<footer>Static report: no scripts, no network requests. Plan <span class="mono">{}</span> · integrity sha256 <span class="mono">{}</span></footer></main></body></html>"#,
        esc(&r.plan.id.to_string()),
        esc(r.integrity_sha256.as_deref().unwrap_or("not sealed"))
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::sample_report;

    #[test]
    fn load_011_html_escapes_planted_script_and_makes_no_requests() {
        let mut r = sample_report();
        let evil = r#"<script>alert(document.cookie)</script>"><img src=x onerror=alert(1)>"#;
        r.plan.name = format!("plan {evil}");
        r.destination_summary.push(format!("http://{evil}"));
        r.failure_categories[0].category = format!("application_failure: {evil}");
        r.failure_categories[0].examples.push(format!("GET http://127.0.0.1/ → HTTP 500 {evil}"));
        r.notes.push(evil.into());
        r.generator.notes.push(evil.into());
        let html = to_html(&r);
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "no script element may appear");
        assert!(!lower.contains("<img"), "no injected element may appear");
        assert!(html.contains("&lt;script&gt;alert(document.cookie)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"));
        for needle in ["<link", "@import", "url(", "src=\"http", "href=\"http", "<iframe", "<object", "<embed", "javascript:"] {
            assert!(!lower.contains(needle), "no external resource or script reference: {needle}");
        }
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
    }

    #[test]
    fn partial_reports_are_labelled() {
        let mut r = sample_report();
        r.partial = true;
        r.completion = RunCompletion::WorkerCrashed;
        let html = to_html(&r);
        assert!(html.contains("Partial report — Load worker crashed"));
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(fmt_n(1234567), "1,234,567");
        assert_eq!(fmt_us(999), "999 µs");
        assert_eq!(fmt_us(1_500), "1.50 ms");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert_eq!(esc("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#39;");
    }
}
