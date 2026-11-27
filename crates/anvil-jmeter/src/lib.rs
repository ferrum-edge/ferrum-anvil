//! The Apache JMeter adapter (failure-matrix case LOAD-012).
//!
//! * [`export`]: a declared, supported subset of an Anvil HTTP load plan as a
//!   JMeter 5.x test plan (`.jmx`), run with `jmeter -n`. Every step is
//!   prepared by Anvil's own request preparation, so JMeter sends the same
//!   method, URL, headers and body. Settings JMeter cannot reproduce are
//!   refused (every reason at once) or listed in the export report, never
//!   dropped. A request Anvil sends with strict certificate verification is
//!   refused, because JMeter's HTTP samplers accept any certificate. Secrets
//!   are JMeter properties, written only on the explicit secret-export path.
//! * [`jtl`]: JMeter result files (CSV or XML JTL) into Anvil's
//!   [`anvil_domain::load::LoadReport`], streamed with bounded memory and
//!   strict input validation (no DTD, no entity expansion, size, sample and
//!   record limits), so a JMeter run is viewed and compared like an Anvil run.
//! * [`jmx`]: the test plan writer and JMeter's string escaping.
//!
//! See `docs/load.md#jmeter-adapter-load-012`.

pub mod export;
pub mod jmx;
pub mod jtl;

pub use export::{Export, ExportInput, ExportOptions, ExportRefused, ExportReport, JMETER_VERSION, export};
pub use jtl::{JtlError, JtlFormat, JtlLimits, JtlOptions, import_jtl};

/// Engine identifier of a report imported from JMeter results.
pub const ENGINE_NAME: &str = "apache-jmeter";

/// Version of this adapter (recorded in export reports).
pub fn adapter_version() -> String {
    format!("anvil-jmeter/{}", env!("CARGO_PKG_VERSION"))
}
