//! JUnit XML export.
//!
//! * One `<testsuite>` per iteration, one `<testcase>` per retained step.
//! * A step that failed on a *transport* dimension counted by the run's
//!   `fail_on` — or that could not be prepared by the runner (`error`) — is a
//!   JUnit `<error>`: the test could not be carried out. A step that failed
//!   only on application status and/or assertions is a `<failure>`: the
//!   system answered, but not as expected.
//! * Skipped and canceled steps are `<skipped>`.
//! * Every value is XML-escaped; characters XML 1.0 cannot carry are
//!   replaced with U+FFFD. Values are already redacted in the report.

use anvil_domain::runner::*;
use std::fmt::Write as _;

/// Escape for double-quoted attribute values (line breaks and tabs are
/// kept as character references so parsers do not normalize them away).
pub fn xml_escape(s: &str) -> String {
    escape(s, true)
}

/// Escape for element text (line breaks stay literal).
pub fn xml_text(s: &str) -> String {
    escape(s, false)
}

fn escape(s: &str, attr: bool) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            '\n' if attr => o.push_str("&#10;"),
            '\r' if attr => o.push_str("&#13;"),
            '\t' if attr => o.push_str("&#9;"),
            '\n' | '\r' | '\t' => o.push(c),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => o.push('\u{FFFD}'),
            c => o.push(c),
        }
    }
    o
}

fn secs(ms: u64) -> String {
    format!("{}.{:03}", ms / 1000, ms % 1000)
}

fn dim_name(d: OutcomeDimension) -> &'static str {
    match d {
        OutcomeDimension::Transport => "transport",
        OutcomeDimension::Application => "application",
        OutcomeDimension::Assertions => "assertion",
    }
}

fn counted(d: OutcomeDimension, f: &FailOn) -> bool {
    match d {
        OutcomeDimension::Transport => f.transport,
        OutcomeDimension::Application => f.application,
        OutcomeDimension::Assertions => f.assertions,
    }
}

enum Verdict {
    Pass,
    Failure { kind: String, message: String },
    Error { kind: String, message: String },
    Skipped(String),
}

fn verdict(s: &RunStep, f: &FailOn) -> Verdict {
    match s.status {
        RunStepStatus::Passed => Verdict::Pass,
        RunStepStatus::Skipped | RunStepStatus::Canceled => Verdict::Skipped(s.message.clone().unwrap_or_else(|| "not run".into())),
        RunStepStatus::Error => Verdict::Error {
            kind: "not_sent".into(),
            message: s.message.clone().unwrap_or_else(|| "the step could not be prepared".into()),
        },
        RunStepStatus::Failed => {
            let dims: Vec<OutcomeDimension> = s.failed_dimensions.iter().copied().filter(|d| counted(*d, f)).collect();
            let kind = dims.iter().map(|d| dim_name(*d)).collect::<Vec<_>>().join(",");
            if dims.contains(&OutcomeDimension::Transport) {
                let transport = s.transport.map(|t| format!("{t:?}").to_lowercase()).unwrap_or_default();
                let msg = match &s.message {
                    Some(m) => format!("transport {transport}: {m}"),
                    None => format!("transport {transport}: {}", s.summary),
                };
                Verdict::Error { kind, message: msg }
            } else {
                let mut parts = Vec::new();
                if dims.contains(&OutcomeDimension::Application) {
                    parts.push(format!("application failure: {}", s.summary));
                }
                if dims.contains(&OutcomeDimension::Assertions) {
                    let failed: Vec<String> =
                        s.assertion_results.iter().filter(|a| !a.passed).map(|a| format!("{} — {}", a.label, a.message)).take(5).collect();
                    parts.push(format!("assertion failed: {}", failed.join("; ")));
                }
                Verdict::Failure { kind, message: parts.join(" · ") }
            }
        }
    }
}

fn detail(s: &RunStep) -> String {
    let mut d = String::new();
    if !s.method.is_empty() || !s.url.is_empty() {
        let _ = writeln!(d, "{} {}", s.method, s.url);
    }
    if !s.summary.is_empty() {
        let _ = writeln!(d, "{}", s.summary);
    }
    if let (Some(t), Some(a), Some(x)) = (s.transport, s.application, s.assertions) {
        let _ = writeln!(
            d,
            "transport={t:?} application={a:?} assertions={x:?} dispatch={:?}",
            s.dispatch.unwrap_or(anvil_domain::execution::DispatchState::Unknown)
        );
    }
    if let Some(m) = &s.message {
        let _ = writeln!(d, "{m}");
    }
    for a in &s.assertion_results {
        let _ = writeln!(d, "{} {} — {}", if a.passed { "PASS" } else { "FAIL" }, a.label, a.message);
    }
    for f in &s.findings {
        let _ = writeln!(d, "finding {} [{:?}/{:?}]: {}", f.code, f.severity, f.confidence, f.title);
    }
    if let Some(id) = s.execution_id {
        let _ = writeln!(d, "execution record: {id}");
    }
    d
}

/// Render the report as JUnit XML.
pub fn to_junit(r: &RunReport) -> String {
    let classname = format!("anvil.{}", r.name);
    let mut suites = String::new();
    let (mut t_tests, mut t_fail, mut t_err, mut t_skip) = (0u64, 0u64, 0u64, 0u64);
    for it in &r.iterations {
        let (mut tests, mut failures, mut errors, mut skipped) = (0u64, 0u64, 0u64, 0u64);
        let mut cases = String::new();
        for s in &it.steps {
            tests += 1;
            let name = format!("{:02} {}", s.index + 1, if s.name.is_empty() { s.request_id.to_string() } else { s.name.clone() });
            let _ = write!(
                cases,
                "    <testcase name=\"{}\" classname=\"{}\" time=\"{}\">",
                xml_escape(&name),
                xml_escape(&classname),
                secs(s.duration_ms.unwrap_or(0))
            );
            // Failure/error bodies carry the step detail; passing and skipped
            // cases carry it as system-out (never both, to avoid duplication).
            let body = xml_text(&detail(s));
            match verdict(s, &r.fail_on) {
                Verdict::Pass => {
                    let _ = write!(cases, "\n      <system-out>{body}</system-out>");
                }
                Verdict::Failure { kind, message } => {
                    failures += 1;
                    let _ = write!(
                        cases,
                        "\n      <failure type=\"{}\" message=\"{}\">{body}</failure>",
                        xml_escape(&kind),
                        xml_escape(&message)
                    );
                }
                Verdict::Error { kind, message } => {
                    errors += 1;
                    let _ =
                        write!(cases, "\n      <error type=\"{}\" message=\"{}\">{body}</error>", xml_escape(&kind), xml_escape(&message));
                }
                Verdict::Skipped(m) => {
                    skipped += 1;
                    let _ = write!(cases, "\n      <skipped message=\"{}\"/>\n      <system-out>{body}</system-out>", xml_escape(&m));
                }
            }
            cases.push_str("\n    </testcase>\n");
        }
        let suite_name = match it.dataset_row {
            Some(row) => format!("{} · iteration {} (dataset row {row})", r.name, it.index + 1),
            None => format!("{} · iteration {}", r.name, it.index + 1),
        };
        let _ = writeln!(
            suites,
            "  <testsuite name=\"{}\" id=\"{}\" tests=\"{tests}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\" time=\"{}\" timestamp=\"{}\">",
            xml_escape(&suite_name),
            it.index,
            secs(it.duration_ms),
            it.started_at.format("%Y-%m-%dT%H:%M:%S")
        );
        properties(
            &mut suites,
            r,
            &[
                ("anvil.iteration", it.index.to_string()),
                ("anvil.iteration_status", format!("{:?}", it.status).to_lowercase()),
                ("anvil.steps_omitted", it.steps_omitted.to_string()),
            ],
        );
        suites.push_str(&cases);
        let _ = writeln!(suites, "  </testsuite>");
        t_tests += tests;
        t_fail += failures;
        t_err += errors;
        t_skip += skipped;
    }
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<testsuites name=\"{}\" tests=\"{t_tests}\" failures=\"{t_fail}\" errors=\"{t_err}\" skipped=\"{t_skip}\" time=\"{}\" timestamp=\"{}\">",
        xml_escape(&r.name),
        secs(r.duration_ms),
        r.started_at.format("%Y-%m-%dT%H:%M:%S")
    );
    out.push_str(&suites);
    if r.iterations.is_empty() {
        // Keep the document meaningful when nothing ran (canceled at once).
        let _ = writeln!(
            out,
            "  <testsuite name=\"{}\" tests=\"0\" failures=\"0\" errors=\"0\" skipped=\"0\" time=\"0.000\">",
            xml_escape(&r.name)
        );
        properties(&mut out, r, &[]);
        let _ = writeln!(out, "  </testsuite>");
    }
    out.push_str("</testsuites>\n");
    out
}

/// Run-level facts repeated in every suite (JUnit has no run-level properties).
fn properties(out: &mut String, r: &RunReport, extra: &[(&str, String)]) {
    let _ = writeln!(out, "    <properties>");
    let run = [
        ("anvil.run_id", r.run_id.to_string()),
        ("anvil.completion", format!("{:?}", r.completion).to_lowercase()),
        ("anvil.partial", r.partial.to_string()),
        ("anvil.runner_version", r.runner_version.clone()),
    ];
    for (k, v) in run.iter().map(|(k, v)| (*k, v)).chain(extra.iter().map(|(k, v)| (*k, v))) {
        let _ = writeln!(out, "      <property name=\"{}\" value=\"{}\"/>", xml_escape(k), xml_escape(v));
    }
    let _ = writeln!(out, "    </properties>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_invalid_xml_chars() {
        assert_eq!(xml_escape("<a href=\"x\">&'\u{1}"), "&lt;a href=&quot;x&quot;&gt;&amp;&apos;\u{FFFD}");
        assert_eq!(xml_escape("a\nb"), "a&#10;b");
        assert_eq!(xml_text("a\nb<\u{2}"), "a\nb&lt;\u{FFFD}");
        assert_eq!(secs(1234), "1.234");
    }
}
