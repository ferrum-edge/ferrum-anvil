use anvil_domain::Id;
use anvil_domain::secret::SecretRef;
use anvil_engine::ExecutionContext;
use anvil_engine::context::SecretResolver;
use anvil_engine::vars::{Resolver, VarEntry, VarLayer};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

struct IndexedSecrets(HashMap<(usize, usize), SecretRef>);

impl SecretResolver for IndexedSecrets {
    fn variable_secret(&self, layer: usize, variable: usize) -> Option<SecretRef> {
        self.0.get(&(layer, variable)).cloned()
    }

    fn resolve(&self, reference: &SecretRef) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(reference.label.clone()))
    }
}

fn entry(name: &str, secret: bool) -> VarEntry {
    // Custom positional resolvers need not use the app's deferred sentinel.
    VarEntry { name: name.into(), value: "public".into(), secret, literal: false }
}

fn resolver(ctx: &ExecutionContext) -> Resolver {
    Resolver::new(ctx.var_layers.clone(), None).with_secrets(ctx.secrets.clone())
}

#[test]
fn filtering_preserves_vault_identity_across_layers_and_repeated_filters() {
    let mut ctx = ExecutionContext::standalone(anvil_domain::request::RequestSpec::http("GET", "https://example.test"));
    ctx.var_layers = vec![
        VarLayer {
            label: "workspace".into(),
            vars: vec![entry("drop-a", true), entry("keep-a", true), entry("drop-b", true), entry("keep-b", true), entry("label", false)],
        },
        VarLayer { label: "emptied".into(), vars: vec![entry("drop-c", true)] },
        VarLayer { label: "folder".into(), vars: vec![entry("keep-c", true)] },
    ];
    ctx.secrets = Arc::new(IndexedSecrets(HashMap::from([
        ((0, 0), SecretRef { id: Id::new(), label: "removed-a".into() }),
        ((0, 1), SecretRef { id: Id::new(), label: "value-a".into() }),
        ((0, 2), SecretRef { id: Id::new(), label: "removed-b".into() }),
        ((0, 3), SecretRef { id: Id::new(), label: "value-b".into() }),
        ((1, 0), SecretRef { id: Id::new(), label: "removed-c".into() }),
        ((2, 0), SecretRef { id: Id::new(), label: "value-c".into() }),
    ])));
    let original = ctx.clone();
    ctx.retain_variables(|entry| !entry.name.starts_with("drop-"));
    assert_eq!(ctx.var_layers.len(), 3);
    assert!(ctx.var_layers[1].vars.is_empty(), "empty layers must not shift the following layer");
    assert!(ctx.secrets.variable_secret(1, 0).is_none(), "removed vault bindings are unavailable");
    let r = resolver(&ctx);
    assert_eq!(r.resolve("{{keep-a}}/{{keep-b}}/{{keep-c}}/{{label}}", "test").unwrap(), "value-a/value-b/value-c/public");
    assert!(r.resolve("{{drop-a}}", "test").is_err());
    assert_eq!(*r.used_secrets.lock(), vec!["value-a", "value-b", "value-c"]);

    ctx.retain_variables(|entry| entry.name != "keep-a");
    assert_eq!(resolver(&ctx).resolve("{{keep-b}}/{{label}}", "test").unwrap(), "value-b/public");
    assert!(resolver(&ctx).resolve("{{keep-a}}", "test").is_err());
    assert_eq!(
        resolver(&original).resolve("{{drop-a}}/{{keep-a}}", "test").unwrap(),
        "removed-a/value-a",
        "frozen contexts remain unchanged"
    );

    // Neither appended entries nor layers can inherit a removed positional binding.
    ctx.var_layers[0].vars.push(entry("appended", false));
    ctx.var_layers.push(VarLayer { label: "run".into(), vars: vec![entry("run", false)] });
    assert!(ctx.secrets.variable_secret(0, 2).is_none());
    assert!(ctx.secrets.variable_secret(3, 0).is_none());
    assert_eq!(resolver(&ctx).resolve("{{appended}}/{{run}}", "test").unwrap(), "public/public");

    ctx.retain_variables(|_| false);
    assert!(ctx.var_layers.iter().all(|layer| layer.vars.is_empty()));
    assert!(ctx.secrets.variable_secret(0, 0).is_none());
    assert!(resolver(&ctx).resolve("{{keep-b}}", "test").is_err());
}
