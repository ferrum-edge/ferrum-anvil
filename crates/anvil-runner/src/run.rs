//! The run loop.

use crate::emit::{Class, Emitter};
use crate::plan::{PlannedStep, RunOptions, RunPlan};
use crate::provider::{StepError, StepProvider};
use crate::redact::RunSecrets;
use crate::{MAX_ASSERTIONS_PER_STEP, MAX_EXTRA_FAILED_STEPS, MAX_FINDINGS_PER_STEP, MAX_NOTES, MAX_REPORT_STEPS, RunError, clip};
use anvil_domain::Id;
use anvil_domain::execution::{DispatchState, ExecutionRecord};
use anvil_domain::outcome::{ApplicationState, AssertionState, ProtocolStatus, TransportState};
use anvil_domain::runner::*;
use anvil_engine::Engine;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_transport::recorder::EventCtx;
use chrono::Utc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const MAX_URL: usize = 2_048;
const MAX_TEXT: usize = 1_024;
const MAX_SUMMARY: usize = 512;

/// Execute a plan. Returns an error only when the run cannot start (trust,
/// validation); once started, cancellation or an abort still yields a
/// (partial) report.
pub async fn run(
    engine: &Engine,
    provider: &dyn StepProvider,
    plan: RunPlan,
    opts: RunOptions,
    cancel: CancellationToken,
) -> Result<RunReport, RunError> {
    let iterations = plan.check(&opts)?;
    let mut r = Run::new(&plan, &opts, iterations);
    r.emitter.emit(
        RunEvent::RunStarted { run_id: r.run_id, name: plan.name.clone(), iterations, steps: plan.steps.len() as u32 },
        Class::Always,
    );

    for it in 0..iterations {
        if cancel.is_cancelled() {
            r.completion = RunnerCompletion::Canceled;
            break;
        }
        let incomplete = r.iteration(engine, provider, &plan, it, &cancel).await;
        if incomplete {
            break;
        }
    }
    Ok(r.finish(plan))
}

#[derive(Default)]
struct Notes(Vec<String>);

impl Notes {
    fn push(&mut self, secrets: &RunSecrets, note: impl AsRef<str>) {
        let n = clip(&secrets.text(note.as_ref()), MAX_TEXT);
        if self.0.contains(&n) {
            return;
        }
        if self.0.len() < MAX_NOTES {
            self.0.push(n);
        } else if self.0.len() == MAX_NOTES {
            self.0.push("further notes were omitted".into());
        }
    }
}

struct Run {
    run_id: Id,
    started_at: chrono::DateTime<Utc>,
    t0: Instant,
    fail_on: FailOn,
    stop_on_failure: bool,
    max_report_steps: usize,
    secrets: RunSecrets,
    notes: Notes,
    emitter: Emitter,
    progress: RunProgress,
    totals: RunTotals,
    iterations: Vec<RunIteration>,
    retained: usize,
    completion: RunnerCompletion,
    abort_reason: Option<String>,
    source: RunSource,
}

impl Run {
    fn new(plan: &RunPlan, opts: &RunOptions, iterations: u32) -> Run {
        let mut secrets = RunSecrets::new(vec![]);
        let mut notes = Notes::default();
        let mut source = plan.source.clone();
        if let RunSource::Scenario { untrusted_override, .. } = &mut source {
            *untrusted_override = !plan.trusted;
        }
        if !plan.trusted {
            notes.push(
                &secrets,
                "This scenario is not trusted (imported or not yet reviewed); it ran only because this run explicitly allowed it.",
            );
        }
        if let Some(d) = &plan.dataset {
            for c in &d.sensitive_columns {
                secrets.add_name(c);
            }
            if !d.missing_sensitive_columns.is_empty() {
                notes.push(
                    &secrets,
                    format!(
                        "Sensitive column(s) {} are not in dataset '{}'; nothing was marked for them.",
                        d.missing_sensitive_columns.join(", "),
                        d.name
                    ),
                );
            }
            if iterations as usize > d.row_count() {
                notes.push(
                    &secrets,
                    format!(
                        "{iterations} iterations over {} dataset row(s): rows are reused in order (iteration i uses row i mod rows).",
                        d.row_count()
                    ),
                );
            } else if (iterations as usize) < d.row_count() {
                notes.push(&secrets, format!("Only the first {iterations} of {} dataset rows were used.", d.row_count()));
            }
        }
        let run_id = opts.run_id.unwrap_or_default();
        Run {
            run_id,
            started_at: Utc::now(),
            t0: Instant::now(),
            fail_on: opts.fail_on,
            stop_on_failure: opts.stop_on_failure.unwrap_or(plan.stop_on_failure),
            max_report_steps: opts.max_report_steps.unwrap_or(MAX_REPORT_STEPS),
            secrets,
            notes,
            emitter: Emitter::new(opts.events.clone()),
            progress: RunProgress {
                steps_total: iterations as u64 * plan.steps.len() as u64,
                iterations_total: iterations,
                ..Default::default()
            },
            totals: RunTotals { iterations_planned: iterations, ..Default::default() },
            iterations: Vec::new(),
            retained: 0,
            completion: RunnerCompletion::Completed,
            abort_reason: None,
            source,
        }
    }

    /// Run one iteration; returns true when the run must stop.
    async fn iteration(
        &mut self,
        engine: &Engine,
        provider: &dyn StepProvider,
        plan: &RunPlan,
        it: u32,
        cancel: &CancellationToken,
    ) -> bool {
        let started_at = Utc::now();
        let t0 = Instant::now();
        let dataset_row = plan.dataset.as_ref().map(|d| d.row_index(it) as u32 + 1);
        let dataset_layer = plan.dataset.as_ref().map(|d| d.row_layer(it));
        if let Some(d) = &plan.dataset {
            self.secrets.add_values(d.sensitive_values(it));
        }
        self.totals.iterations_started += 1;
        self.emitter.emit(RunEvent::IterationStarted { run_id: self.run_id, iteration: it, dataset_row }, Class::Normal);

        // Run-local values, each with the scope of the step that extracted
        // it (`ExecutionContext::scope`).
        let mut extracted: Vec<(Option<Id>, VarEntry)> = Vec::new();
        let mut stopped_at: Option<u32> = None;
        let mut failed = false;
        let mut stop = false;
        let mut steps = Vec::with_capacity(plan.steps.len());
        let mut omitted = 0u32;

        for (pos, step) in plan.steps.iter().enumerate() {
            let pos = pos as u32;
            if !stop && cancel.is_cancelled() {
                self.completion = RunnerCompletion::Canceled;
                stop = true;
            }
            let not_run = if stop {
                Some((RunStepStatus::Canceled, self.stop_reason()))
            } else if !step.enabled {
                Some((RunStepStatus::Skipped, "disabled in the scenario".to_string()))
            } else {
                stopped_at.map(|f| {
                    (RunStepStatus::Skipped, format!("not run: step {} failed and the run stops an iteration at its first failure", f + 1))
                })
            };
            if let Some((status, msg)) = not_run {
                let s = not_executed(pos, step, status, msg, 0);
                self.finish_step(it, s, &mut steps, &mut omitted);
                continue;
            }

            // Think time (cancellable).
            if step.delay_ms > 0 {
                let canceled = tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(step.delay_ms)) => false,
                    _ = cancel.cancelled() => true,
                };
                if canceled {
                    self.completion = RunnerCompletion::Canceled;
                    stop = true;
                    let s = not_executed(pos, step, RunStepStatus::Canceled, "canceled during think time; not sent".into(), step.delay_ms);
                    self.finish_step(it, s, &mut steps, &mut omitted);
                    continue;
                }
            }

            let name = if step.name.is_empty() { step.request_id.to_string() } else { step.name.clone() };
            self.emitter.emit(
                RunEvent::StepStarted { run_id: self.run_id, iteration: it, step: pos, request_id: step.request_id, name: name.clone() },
                Class::Normal,
            );
            let provided = match provider.step(&step.request_id) {
                Ok(p) => p,
                Err(e) => {
                    let fatal = matches!(e, StepError::Fatal(_));
                    let msg = clip(&self.secrets.text(&e.to_string()), MAX_TEXT);
                    let s = not_executed(pos, step, RunStepStatus::Error, format!("not sent: {msg}"), step.delay_ms);
                    self.finish_step(it, s, &mut steps, &mut omitted);
                    failed = true;
                    if fatal {
                        self.abort(msg);
                        stop = true;
                    } else if self.stop_on_failure {
                        stopped_at = Some(pos);
                    }
                    continue;
                }
            };
            let name = if provided.name.is_empty() { name } else { provided.name };
            let mut ctx = provided.context;
            ctx.var_layers.push(VarLayer {
                label: "run".into(),
                vars: vec![
                    VarEntry { name: "anvil.iteration".into(), value: it.to_string(), secret: false },
                    VarEntry { name: "anvil.step".into(), value: pos.to_string(), secret: false },
                ],
            });
            // A step under a sealed import root sees only values extracted
            // under that root, and no dataset row (the dataset is the
            // workspace's); a step outside it never sees what it extracted.
            let scope = ctx.scope;
            if scope.is_none()
                && let Some(l) = &dataset_layer
            {
                ctx.var_layers.push(l.clone());
            }
            let visible: Vec<VarEntry> = extracted.iter().filter(|(s, _)| *s == scope).map(|(_, e)| e.clone()).collect();
            if !visible.is_empty() {
                ctx.var_layers.push(VarLayer { label: "extracted (this iteration)".into(), vars: visible });
            }
            for n in self.secrets.names() {
                if !ctx.redaction_names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                    ctx.redaction_names.push(n.clone());
                }
            }
            ctx.seed = ctx.seed.map(|s| splitmix64(s ^ splitmix64(((it as u64) << 32) | pos as u64)));

            let mut out = engine.execute(&ctx, EventCtx::none(), cancel.clone()).await;

            // Run-local extraction: values stay in memory for this iteration
            // only; sensitive ones become run secrets before anything is
            // recorded or reported.
            let mut new_secrets = Vec::new();
            for (var, value, sensitive) in std::mem::take(&mut out.extracted) {
                if sensitive {
                    new_secrets.push(value.clone());
                    self.secrets.add_name(&var);
                }
                extracted.retain(|(s, e)| *s != scope || e.name != var);
                extracted.push((scope, VarEntry { name: var, value, secret: sensitive }));
            }
            self.secrets.add_values(new_secrets);
            self.secrets.scrub_record(&mut out.record);
            if let Some(n) = self.secrets.scrub_body(&mut out) {
                self.notes.push(&self.secrets, n);
            }
            if let Err(e) = provider.record(&out) {
                let msg = clip(&self.secrets.text(&e.to_string()), MAX_TEXT);
                match e {
                    StepError::Step(_) => self.notes.push(&self.secrets, format!("A step could not be recorded in history: {msg}")),
                    StepError::Fatal(_) => {
                        self.abort(msg);
                        stop = true;
                    }
                }
            }

            let s = self.executed(pos, step, &name, &out.record);
            match s.status {
                RunStepStatus::Canceled => {
                    if self.completion == RunnerCompletion::Completed {
                        self.completion = RunnerCompletion::Canceled;
                    }
                    stop = true;
                    if matches!(s.dispatch, Some(DispatchState::Sent | DispatchState::MayHaveBeenSent | DispatchState::Unknown)) {
                        self.notes.push(
                            &self.secrets,
                            format!(
                                "Iteration {} step {} ('{}') was canceled after its request may have reached the peer ({:?}). It was not retried; check the server state before running it again.",
                                it + 1,
                                pos + 1,
                                name,
                                s.dispatch.unwrap_or(DispatchState::Unknown)
                            ),
                        );
                    }
                }
                RunStepStatus::Failed => {
                    failed = true;
                    if self.stop_on_failure && stopped_at.is_none() {
                        stopped_at = Some(pos);
                    }
                }
                _ => {}
            }
            self.finish_step(it, s, &mut steps, &mut omitted);
        }

        let status = if stop {
            RunIterationStatus::Incomplete
        } else if failed {
            RunIterationStatus::Failed
        } else {
            RunIterationStatus::Passed
        };
        match status {
            RunIterationStatus::Passed => self.totals.iterations_passed += 1,
            RunIterationStatus::Failed => self.totals.iterations_failed += 1,
            RunIterationStatus::Incomplete => self.totals.iterations_incomplete += 1,
        }
        self.progress.iterations_done += 1;
        self.emitter.emit(
            RunEvent::IterationFinished { run_id: self.run_id, iteration: it, status, progress: self.progress },
            if status == RunIterationStatus::Passed { Class::Normal } else { Class::Failure },
        );
        self.iterations.push(RunIteration {
            index: it,
            dataset_row,
            started_at,
            duration_ms: t0.elapsed().as_millis() as u64,
            status,
            stopped_at_step: stopped_at,
            steps,
            steps_omitted: omitted,
        });
        stop
    }

    fn stop_reason(&self) -> String {
        match self.completion {
            RunnerCompletion::Aborted => "not started: the run was aborted".into(),
            _ => "not started: the run was canceled".into(),
        }
    }

    fn abort(&mut self, reason: String) {
        self.completion = RunnerCompletion::Aborted;
        if self.abort_reason.is_none() {
            self.abort_reason = Some(reason);
        }
    }

    /// Count, emit and (within the report bound) retain a step summary.
    fn finish_step(&mut self, it: u32, s: RunStep, steps: &mut Vec<RunStep>, omitted: &mut u32) {
        let t = &mut self.totals;
        match s.status {
            RunStepStatus::Passed => t.steps_passed += 1,
            RunStepStatus::Failed => t.steps_failed += 1,
            RunStepStatus::Error => t.steps_errored += 1,
            RunStepStatus::Skipped => t.steps_skipped += 1,
            RunStepStatus::Canceled if s.execution_id.is_some() => t.steps_canceled_in_flight += 1,
            RunStepStatus::Canceled => t.steps_canceled += 1,
        }
        if s.execution_id.is_some() {
            t.steps_executed += 1;
            t.step_time_ms += s.duration_ms.unwrap_or(0);
            for d in &s.failed_dimensions {
                match d {
                    OutcomeDimension::Transport => t.transport_failures += 1,
                    OutcomeDimension::Application => t.application_failures += 1,
                    OutcomeDimension::Assertions => t.assertion_failures += 1,
                }
            }
        }
        self.progress.steps_done += 1;
        let failed = matches!(s.status, RunStepStatus::Failed | RunStepStatus::Error);
        if failed {
            self.progress.steps_failed += 1;
        }
        self.emitter.emit(
            RunEvent::StepFinished {
                run_id: self.run_id,
                iteration: it,
                step: s.index,
                status: s.status,
                execution_id: s.execution_id,
                http_status: s.http_status,
                duration_ms: s.duration_ms,
                progress: self.progress,
            },
            if failed { Class::Failure } else { Class::Normal },
        );
        let keep = self.retained < self.max_report_steps
            || (!matches!(s.status, RunStepStatus::Passed | RunStepStatus::Skipped)
                && self.retained < self.max_report_steps + MAX_EXTRA_FAILED_STEPS);
        if keep {
            self.retained += 1;
            steps.push(s);
        } else {
            *omitted += 1;
            self.notes.push(
                &self.secrets,
                format!(
                    "The report keeps at most {} step summaries (plus {MAX_EXTRA_FAILED_STEPS} failed ones); further summaries were omitted, totals still count them.",
                    self.max_report_steps
                ),
            );
        }
    }

    fn executed(&mut self, pos: u32, step: &PlannedStep, name: &str, rec: &ExecutionRecord) -> RunStep {
        let o = &rec.outcome;
        let mut dims = Vec::new();
        let status = if o.transport == TransportState::Canceled {
            RunStepStatus::Canceled
        } else {
            if o.transport != TransportState::Completed {
                dims.push(OutcomeDimension::Transport);
            }
            if o.application == ApplicationState::Failure {
                dims.push(OutcomeDimension::Application);
            }
            if o.assertions == AssertionState::Fail {
                dims.push(OutcomeDimension::Assertions);
            }
            let counted = dims.iter().any(|d| match d {
                OutcomeDimension::Transport => self.fail_on.transport,
                OutcomeDimension::Application => self.fail_on.application,
                OutcomeDimension::Assertions => self.fail_on.assertions,
            });
            if counted { RunStepStatus::Failed } else { RunStepStatus::Passed }
        };
        let (http_status, grpc_status) = match &o.protocol_status {
            ProtocolStatus::Http { status, .. } => (Some(*status), None),
            ProtocolStatus::Grpc { http_status, grpc_status, .. } => (*http_status, *grpc_status),
            ProtocolStatus::WebSocket { handshake_status, .. } => (*handshake_status, None),
            ProtocolStatus::Sse { http_status, .. } => (Some(*http_status), None),
            _ => (rec.response.as_ref().map(|r| r.status), None),
        };
        let sec = &self.secrets;
        for a in &rec.assertion_results {
            if a.passed {
                self.totals.assertions_passed += 1;
            } else {
                self.totals.assertions_failed += 1;
            }
        }
        let assertion_results = rec
            .assertion_results
            .iter()
            .take(MAX_ASSERTIONS_PER_STEP)
            .map(|a| anvil_domain::assertions::AssertionResult {
                label: clip(&sec.text(&a.label), MAX_SUMMARY),
                passed: a.passed,
                actual: a.actual.as_ref().map(|x| clip(&sec.text(x), MAX_SUMMARY)),
                message: clip(&sec.text(&a.message), MAX_TEXT),
            })
            .collect();
        // Keep the diagnostics engine's order (severity, then hop-specific
        // before generic status explanations) so every surface agrees.
        let findings: Vec<&anvil_domain::diagnostics::DiagnosticFinding> = rec.findings.iter().collect();
        let message = rec.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| clip(&sec.text(&f.message), MAX_TEXT)).or_else(|| {
            // Extraction misses are warnings on an otherwise complete step;
            // surface them because the next step will depend on them.
            let misses: Vec<&str> =
                o.warnings.iter().filter(|w| w.message.starts_with("extraction for")).map(|w| w.message.as_str()).take(3).collect();
            if misses.is_empty() { None } else { Some(clip(&sec.text(&misses.join("; ")), MAX_TEXT)) }
        });
        RunStep {
            index: pos,
            request_id: step.request_id,
            revision_id: rec.revision_id,
            name: clip(name, MAX_SUMMARY),
            protocol: Some(rec.prepared.protocol),
            method: clip(&rec.prepared.method, 32),
            url: clip(&sec.url(&rec.prepared.url), MAX_URL),
            status,
            failed_dimensions: dims,
            execution_id: Some(rec.id),
            transport: Some(o.transport),
            application: Some(o.application),
            assertions: Some(o.assertions),
            dispatch: Some(o.dispatch),
            http_status,
            grpc_status,
            summary: clip(&sec.text(&o.summary), MAX_SUMMARY),
            message,
            duration_ms: Some((rec.finished_at - rec.started_at).num_milliseconds().max(0) as u64),
            exchange_ms: if rec.attempts.is_empty() { None } else { Some(rec.attempts.iter().map(|a| a.duration_us).sum::<u64>() / 1000) },
            delay_ms: step.delay_ms,
            assertion_results,
            assertion_results_omitted: rec.assertion_results.len().saturating_sub(MAX_ASSERTIONS_PER_STEP) as u32,
            findings: findings
                .into_iter()
                .take(MAX_FINDINGS_PER_STEP)
                .map(|f| RunFindingSummary {
                    code: f.code.clone(),
                    title: clip(&sec.text(&f.title), MAX_SUMMARY),
                    confidence: f.confidence,
                    severity: f.severity,
                })
                .collect(),
            extracted: rec.extracted.clone(),
        }
    }

    fn finish(mut self, plan: RunPlan) -> RunReport {
        let partial = self.completion != RunnerCompletion::Completed;
        self.emitter.emit(
            RunEvent::RunFinished {
                run_id: self.run_id,
                completion: self.completion,
                progress: self.progress,
                dropped_events: self.emitter.dropped,
            },
            Class::Always,
        );
        let finished_at = Utc::now();
        RunReport {
            run_id: self.run_id,
            report_version: RUN_REPORT_VERSION,
            schema_version: anvil_domain::SCHEMA_VERSION,
            runner_version: crate::runner_version(),
            workspace_id: plan.workspace_id,
            name: clip(&plan.name, MAX_SUMMARY),
            source: self.source,
            environment_id: plan.environment_id,
            environment_name: plan.environment_name,
            dataset: plan.dataset.as_ref().map(|d| d.summary()),
            fail_on: self.fail_on,
            stop_on_failure: self.stop_on_failure,
            started_at: self.started_at,
            finished_at,
            duration_ms: self.t0.elapsed().as_millis() as u64,
            completion: self.completion,
            partial,
            abort_reason: self.abort_reason,
            totals: self.totals,
            iterations: self.iterations,
            notes: self.notes.0,
        }
    }
}

fn not_executed(pos: u32, step: &PlannedStep, status: RunStepStatus, message: String, delay_ms: u64) -> RunStep {
    RunStep {
        index: pos,
        request_id: step.request_id,
        revision_id: None,
        name: clip(if step.name.is_empty() { "" } else { &step.name }, MAX_SUMMARY),
        protocol: None,
        method: String::new(),
        url: String::new(),
        status,
        failed_dimensions: vec![],
        execution_id: None,
        transport: None,
        application: None,
        assertions: None,
        dispatch: None,
        http_status: None,
        grpc_status: None,
        summary: String::new(),
        message: Some(message),
        duration_ms: None,
        exchange_ms: None,
        delay_ms,
        assertion_results: vec![],
        assertion_results_omitted: 0,
        findings: vec![],
        extracted: vec![],
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
