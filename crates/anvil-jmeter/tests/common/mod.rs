//! Shared builders for the adapter's tests: execution contexts, plans and
//! a small reader for exported `.jmx` documents.
#![allow(dead_code)]

use anvil_domain::assertions::{Assertion, AssertionKind};
use anvil_domain::load::{ConnectionMode, LoadPlan, Workload};
use anvil_domain::request::RequestSpec;
use anvil_domain::settings::{RedirectPolicy, SettingsOverrides};
use anvil_domain::tls::TlsProfile;
use anvil_domain::{Id, Timestamp};
use anvil_engine::ExecutionContext;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_jmeter::{Export, ExportInput, ExportOptions, ExportRefused};
use anvil_load::{Dataset, DatasetFormat, LoadJob};
use std::collections::HashMap;

/// A step whose request does not follow redirects (a redirect-following
/// request is exported only when every hop behaves alike; see the tests that
/// cover it).
pub fn step(mut spec: RequestSpec) -> (Id, ExecutionContext) {
    if spec.settings.redirects.is_none() {
        spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    }
    let id = Id::new();
    let mut c = ExecutionContext::standalone(spec);
    c.request_id = Some(id);
    c.isolation = "ws-jmeter-test".into();
    (id, c)
}

pub fn layer(label: &str, vars: &[(&str, &str, bool)]) -> VarLayer {
    VarLayer {
        label: label.into(),
        vars: vars.iter().map(|(n, v, s)| VarEntry { name: n.to_string(), value: v.to_string(), secret: *s, literal: false }).collect(),
    }
}

/// Select a TLS profile (verifying or not) for the request.
pub fn with_tls_profile(c: &mut ExecutionContext, verify: bool) {
    let profile = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: if verify { "strict".into() } else { "unverified test system".into() },
        verify,
        use_system_roots: true,
        extra_roots_pem: vec![],
        client_identity: None,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    c.settings_layers.push(("tls".into(), SettingsOverrides { tls_profile_id: Some(profile.id), ..Default::default() }));
    c.tls_profiles.push(profile);
}

pub fn iterations(iterations: u64, concurrency: u64) -> Workload {
    Workload::Iterations { iterations, concurrency }
}

pub fn dataset(csv: &str) -> Dataset {
    Dataset::parse(DatasetFormat::Csv, csv.as_bytes().to_vec()).expect("valid dataset")
}

pub fn assertion(kind: AssertionKind) -> Assertion {
    Assertion { enabled: true, label: String::new(), kind }
}

pub fn plan(workload: Workload, chain: Vec<Id>) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "fixture plan".into(),
        workload,
        chain,
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: ConnectionMode::Persistent,
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

/// A plan with its frozen contexts and request names.
pub struct Fx {
    pub plan: LoadPlan,
    pub job: LoadJob,
    pub names: HashMap<Id, String>,
}

impl Fx {
    pub fn new(workload: Workload, steps: Vec<(Id, ExecutionContext, &str)>, dataset: Option<Dataset>) -> Self {
        let chain: Vec<Id> = steps.iter().map(|(id, _, _)| *id).collect();
        let names = steps.iter().map(|(id, _, n)| (*id, n.to_string())).collect();
        let requests = steps.into_iter().map(|(id, c, _)| (id, c)).collect();
        Fx { plan: plan(workload, chain), job: LoadJob { requests, dataset }, names }
    }

    pub fn export(&self, opts: &ExportOptions) -> Result<Export, ExportRefused> {
        anvil_jmeter::export(&ExportInput { plan: &self.plan, job: &self.job, request_names: &self.names }, opts)
    }
}

/// An exported `.jmx`: each element is followed by a `<hashTree>` with its children.
pub struct Doc<'a> {
    pub doc: roxmltree::Document<'a>,
}

pub type N<'a> = roxmltree::Node<'a, 'a>;

impl<'a> Doc<'a> {
    pub fn parse(text: &'a str) -> Self {
        let doc = roxmltree::Document::parse(text).expect("a well-formed JMX document");
        assert_eq!(doc.root_element().tag_name().name(), "jmeterTestPlan");
        Doc { doc }
    }

    pub fn all(&'a self, tag: &str) -> Vec<N<'a>> {
        self.doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == tag).collect()
    }

    pub fn first(&'a self, tag: &str) -> N<'a> {
        *self.all(tag).first().unwrap_or_else(|| panic!("no <{tag}> in the plan"))
    }

    pub fn attr(&self, n: N<'a>, name: &str) -> String {
        n.attribute(name).unwrap_or_default().to_string()
    }

    /// The text of the property named `name` within the element.
    pub fn prop(&self, n: N<'a>, name: &str) -> String {
        n.descendants()
            .find(|d| d.is_element() && d.attribute("name") == Some(name))
            .map(|d| d.text().unwrap_or_default().to_string())
            .unwrap_or_else(|| panic!("no property {name} in <{}>", n.tag_name().name()))
    }

    /// The element's children (in the `<hashTree>` that follows it) with this tag.
    pub fn children(&self, n: N<'a>, tag: &str) -> Vec<N<'a>> {
        let tree = n.next_sibling_element().filter(|t| t.tag_name().name() == "hashTree").expect("a hashTree after the element");
        tree.children().filter(|c| c.is_element() && c.tag_name().name() == tag).collect()
    }

    pub fn child(&self, n: N<'a>, tag: &str) -> N<'a> {
        *self.children(n, tag).first().unwrap_or_else(|| panic!("no <{tag}> under <{}>", n.tag_name().name()))
    }

    /// The element whose `<hashTree>` holds `n`, which must have this tag.
    pub fn parent_of(&self, n: N<'a>, tag: &str) -> N<'a> {
        let owner = n.parent_element().and_then(|t| t.prev_sibling_element()).expect("an owner element");
        assert_eq!(owner.tag_name().name(), tag);
        owner
    }

    /// The (name, value) pairs of a sampler's HTTP Header Manager.
    pub fn headers(&self, sampler: N<'a>) -> Vec<(String, String)> {
        let hm = self.child(sampler, "HeaderManager");
        hm.descendants()
            .filter(|d| d.attribute("elementType") == Some("Header"))
            .map(|h| (self.prop(h, "Header.name"), self.prop(h, "Header.value")))
            .collect()
    }
}

/// Every assertion kind is constructible here (keeps the import used).
pub fn status_200() -> AssertionKind {
    AssertionKind::StatusIn { values: vec![200] }
}
