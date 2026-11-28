//! The Apache JMeter adapter's entry points (LOAD-012), shared by the CLI
//! and the desktop: export a saved load plan as a JMeter test plan, and
//! import a JMeter result file as a load report of a workspace.

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::load::{LoadPlan, LoadReport};
use anvil_jmeter::ExportInput;
use std::collections::HashMap;
use std::io::{Read, Seek};

/// The adapter's types, for the shells (the desktop needs no direct dependency).
pub use anvil_jmeter::export::{DatasetReport, Mapping, Reason, SecretProperty};
pub use anvil_jmeter::{Export, ExportOptions, ExportRefused, ExportReport, JMETER_VERSION, JtlLimits, JtlOptions};

impl App {
    /// Translate `plan` into a JMeter test plan. The plan's requests are
    /// frozen exactly as a load run freezes them ([`App::load_job`]), so the
    /// export prepares what a run would send. `Ok(Err(_))` is a refusal with
    /// every reason (nothing was written); secret values are resolved only
    /// with [`ExportOptions::include_secrets`].
    pub fn load_export_jmx(&self, plan: &LoadPlan, opts: &ExportOptions) -> Result<std::result::Result<Export, ExportRefused>> {
        anvil_load::validate_plan(plan).map_err(|e| AppError::Invalid(e.to_string()))?;
        let job = self.load_job_for_export(plan)?;
        let mut names = HashMap::new();
        for id in Self::plan_requests(plan) {
            names.insert(id, self.request(&id)?.name);
        }
        Ok(anvil_jmeter::export(&ExportInput { plan, job: &job, request_names: &names }, opts))
    }

    /// Import a JMeter result file (CSV or XML JTL) into workspace `ws` and
    /// save it as a load report. With a plan (which must belong to `ws`), the
    /// report carries it, so it is compared with that plan's Anvil runs.
    pub fn import_jtl<R: Read + Seek>(&self, ws: &Id, reader: R, mut opts: JtlOptions) -> Result<LoadReport> {
        self.workspace(ws)?;
        if let Some(p) = &opts.plan
            && p.workspace_id != *ws
        {
            return Err(AppError::Invalid("the load plan belongs to another workspace".into()));
        }
        opts.workspace_id = *ws;
        let report = anvil_jmeter::import_jtl(reader, &opts).map_err(|e| AppError::Invalid(e.to_string()))?;
        self.save_load_report(&report)?;
        Ok(report)
    }
}
