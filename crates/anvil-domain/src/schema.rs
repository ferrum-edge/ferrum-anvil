//! JSON Schemas for the published data contracts (`contracts/schemas/`).
//! TypeScript bindings for the desktop renderer are generated from these.

use schemars::{JsonSchema, schema_for};

pub fn all() -> Vec<(&'static str, serde_json::Value)> {
    fn s<T: JsonSchema>() -> serde_json::Value {
        serde_json::to_value(schema_for!(T)).expect("schema serializes")
    }
    vec![
        ("Workspace", s::<crate::workspace::Workspace>()),
        ("Folder", s::<crate::workspace::Folder>()),
        ("RequestDefinition", s::<crate::workspace::RequestDefinition>()),
        ("RequestRevision", s::<crate::workspace::RequestRevision>()),
        ("RequestSpec", s::<crate::request::RequestSpec>()),
        ("Environment", s::<crate::workspace::Environment>()),
        ("Scenario", s::<crate::workspace::Scenario>()),
        ("Dataset", s::<crate::workspace::Dataset>()),
        ("UserProfile", s::<crate::workspace::UserProfile>()),
        ("TlsProfile", s::<crate::tls::TlsProfile>()),
        ("ProxyProfile", s::<crate::tls::ProxyProfile>()),
        ("IntegrationProfile", s::<crate::integration::IntegrationProfile>()),
        ("AppSettings", s::<crate::settings::AppSettings>()),
        ("EffectiveSettings", s::<crate::settings::EffectiveSettings>()),
        ("ExecutionRecord", s::<crate::execution::ExecutionRecord>()),
        ("ExecutionEvent", s::<crate::events::ExecutionEvent>()),
        ("SessionCommand", s::<crate::events::SessionCommand>()),
        ("DiagnosticFinding", s::<crate::diagnostics::DiagnosticFinding>()),
        ("LoadPlan", s::<crate::load::LoadPlan>()),
        ("LoadReport", s::<crate::load::LoadReport>()),
        ("RunReport", s::<crate::runner::RunReport>()),
        ("RunEvent", s::<crate::runner::RunEvent>()),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn schemas_generate() {
        let all = super::all();
        assert!(all.len() >= 20);
        for (n, v) in all {
            assert!(v.get("$schema").is_some() || v.get("title").is_some(), "{n}");
        }
    }
}
