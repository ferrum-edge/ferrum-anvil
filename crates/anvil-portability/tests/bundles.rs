//! DATA-001..DATA-008 bundle scenarios.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::request::{
    AttachmentRef, Body, GrpcMode, GrpcSchemaSource, GrpcSpec, GrpcWire, KeyValue, MultipartContent, MultipartPart, Protocol, RequestSpec,
};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::tls::TlsProfile;
use anvil_domain::workspace::*;
use anvil_portability::bundle::{self, BundleError, BundleKind, ExportMode, ExportOptions};
use anvil_portability::plan::{self, ConflictPolicy, Existing, ExistingWorkspace};
use anvil_portability::{PortableGraph, SecretValue};
use anvil_storage::KdfParams;
use std::collections::HashSet;
use std::io::Write;

fn sample() -> PortableGraph {
    let ws = Workspace {
        meta: Meta::new(),
        name: "Payments".into(),
        description: "".into(),
        settings: Default::default(),
        variables: vec![Variable::plain("baseUrl", "https://api.example.com")],
        auth: AuthConfig::Inherit,
        active_environment_id: None,
    };
    let f1 = Folder {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        parent_id: None,
        name: "Orders".into(),
        description: "".into(),
        sort_key: 1.0,
        settings: Default::default(),
        variables: vec![],
        auth: AuthConfig::Inherit,
        tags: vec![],
        import_root: false,
        import_environment_ids: vec![],
        use_workspace_scope: false,
    };
    let f2 = Folder { meta: Meta::new(), parent_id: Some(f1.meta.id), name: "Refunds".into(), sort_key: 2.0, ..f1.clone() };
    let secret_id = Id::new();
    let mut spec = RequestSpec::http("POST", "{{baseUrl}}/orders");
    spec.headers.push(KeyValue::new("X-API-Key", "LITERAL-KEY-12345"));
    spec.headers.push(KeyValue { enabled: false, ..KeyValue::new("X-Disabled", "keep-me") });
    spec.body = Body::Json { text: r#"{"amount": 10}"#.into() };
    spec.auth = AuthConfig::Basic { username: "svc".into(), password: SensitiveValue::template("basic-password-xyz") };
    let r1 = RequestDefinition {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        folder_id: Some(f2.meta.id),
        name: "Create order".into(),
        description: "".into(),
        tags: vec!["smoke".into()],
        favorite: true,
        sort_key: 1.0,
        spec,
        revision_id: None,
    };
    let mut spec2 = RequestSpec::http("GET", "{{baseUrl}}/orders");
    spec2.auth = AuthConfig::ApiKey {
        name: "api_key".into(),
        value: SensitiveValue::Secret { secret: SecretRef { id: secret_id, label: "orders key".into() } },
        location: KeyLocation::Query,
    };
    let r2 = RequestDefinition {
        meta: Meta::new(),
        name: "List".into(),
        folder_id: Some(f1.meta.id),
        spec: spec2,
        sort_key: 2.0,
        favorite: false,
        ..r1.clone()
    };
    let env = Environment {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        name: "prod".into(),
        variables: vec![Variable {
            name: "token".into(),
            value: SensitiveValue::template("env-secret-token"),
            secret: true,
            enabled: true,
            description: "".into(),
        }],
    };
    let tls = TlsProfile {
        id: Id::new(),
        workspace_id: ws.meta.id,
        name: "lab".into(),
        verify: false,
        use_system_roots: false,
        extra_roots_pem: vec!["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into()],
        client_identity: None,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let mut g = PortableGraph {
        workspaces: vec![ws.clone()],
        folders: vec![f1, f2],
        requests: vec![r1, r2],
        environments: vec![env],
        tls_profiles: vec![tls],
        ..Default::default()
    };
    g.secrets.insert(
        secret_id.to_string(),
        SecretValue { label: "orders key".into(), value: "VAULT-SECRET-999".into(), workspace_id: Some(ws.meta.id.to_string()) },
    );
    g.attachments.insert(hex_sha(b"attachment bytes"), b"attachment bytes".to_vec());
    g
}

fn hex_sha(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

fn opts(mode: ExportMode, pass: Option<&str>) -> ExportOptions<'_> {
    ExportOptions {
        kind: BundleKind::Workspace,
        mode,
        passphrase: pass,
        include_history: false,
        kdf: KdfParams::testing(),
        app_version: "test",
    }
}

fn text_of(bytes: &[u8]) -> String {
    // Decompress every entry and concatenate (to search for leaks).
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut s = String::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut b).unwrap();
        s.push_str(&String::from_utf8_lossy(&b));
    }
    s
}

#[test]
fn data_001_share_safely_roundtrip_preserves_structure_and_excludes_secrets() {
    let g = sample();
    let (bytes, preview) = bundle::write(&g, &opts(ExportMode::ShareSafely, None)).unwrap();
    let all = text_of(&bytes);
    for leaked in ["LITERAL-KEY-12345", "basic-password-xyz", "env-secret-token", "VAULT-SECRET-999"] {
        assert!(!all.contains(leaked), "{leaked} leaked into a share-safely bundle");
    }
    assert!(preview.manifest.excluded.iter().any(|e| e.contains("orders key")));
    let opened = bundle::open(&bytes, None).unwrap();
    let og = opened.graph;
    assert_eq!(og.folders.len(), 2);
    assert_eq!(og.requests.len(), 2);
    let create = og.requests.iter().find(|r| r.name == "Create order").unwrap();
    assert_eq!(create.folder_id, g.requests[0].folder_id, "nested folder placement preserved");
    assert!(create.favorite && create.tags == vec!["smoke".to_string()]);
    assert!(create.spec.headers.iter().any(|h| h.name == "X-Disabled" && !h.enabled && h.value == "keep-me"), "disabled headers preserved");
    assert!(
        create.spec.headers.iter().any(|h| h.name == "X-API-Key" && h.value.starts_with("{{")),
        "literal key replaced by a placeholder"
    );
    assert_eq!(og.attachments.len(), 1);
    assert!(og.secrets.is_empty());
}

#[test]
fn data_003_encrypted_transfer_restores_exact_values() {
    let g = sample();
    let (bytes, _) = bundle::write(&g, &opts(ExportMode::EncryptedTransfer, Some("correct horse battery"))).unwrap();
    let all = text_of(&bytes);
    for leaked in ["LITERAL-KEY-12345", "basic-password-xyz", "env-secret-token", "VAULT-SECRET-999"] {
        assert!(!all.contains(leaked), "{leaked} visible in an encrypted bundle");
    }
    let opened = bundle::open(&bytes, Some("correct horse battery")).unwrap();
    assert!(opened.secrets_restored);
    let mut expected = g.clone();
    let _ = anvil_portability::validate::validate_and_normalize(&mut expected).unwrap();
    assert_eq!(opened.graph.requests, expected.requests, "requests restored byte-for-byte");
    assert_eq!(opened.graph.environments, expected.environments);
    assert_eq!(opened.graph.secrets, g.secrets);
}

#[test]
fn data_004_wrong_passphrase_fails_safely() {
    let g = sample();
    let (bytes, _) = bundle::write(&g, &opts(ExportMode::FullBackup, Some("correct horse battery"))).unwrap();
    assert!(matches!(bundle::open(&bytes, Some("wrong passphrase!")), Err(BundleError::WrongPassphrase)));
    assert!(matches!(bundle::open(&bytes, None), Err(BundleError::PassphraseRequired)));
}

#[test]
fn data_005_corrupt_or_truncated_bundles_are_rejected() {
    let (bytes, _) = bundle::write(&sample(), &opts(ExportMode::ShareSafely, None)).unwrap();
    assert!(bundle::open(&bytes[..bytes.len() / 2], None).is_err(), "truncated");
    // Modify one entry but keep a valid zip: rewrite objects.json.
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(&bytes[..])).unwrap();
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut b).unwrap();
        if name == "workspace/objects.json" {
            b = String::from_utf8(b).unwrap().replace("Payments", "Tampered").into_bytes();
        }
        w.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(&b).unwrap();
    }
    let tampered = w.finish().unwrap().into_inner();
    assert!(matches!(bundle::open(&tampered, None), Err(BundleError::Checksum(_))));
}

fn zip_with(entries: &[(&str, &[u8])], symlink: Option<&str>) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, b) in entries {
        w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(b).unwrap();
    }
    if let Some(s) = symlink {
        w.add_symlink(s, "/etc/passwd", zip::write::SimpleFileOptions::default()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn data_007_traversal_symlink_and_bomb_are_rejected() {
    let traversal = zip_with(&[("manifest.json", b"{}"), ("../../evil.sh", b"x")], None);
    assert!(matches!(bundle::open(&traversal, None), Err(BundleError::Unsafe(..))));
    let absolute = zip_with(&[("/etc/cron.d/x", b"x")], None);
    assert!(matches!(bundle::open(&absolute, None), Err(BundleError::Unsafe(..))));
    let link = zip_with(&[("manifest.json", b"{}")], Some("attachments/0000000000000000000000000000000000000000000000000000000000000000"));
    assert!(matches!(bundle::open(&link, None), Err(BundleError::Unsafe(..))));
    // Highly compressible 300 MB entry disguised as an attachment.
    let big = vec![0u8; 300 * 1024 * 1024];
    let name = format!("attachments/{}", "a".repeat(64));
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(name, zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)).unwrap();
    w.write_all(&big).unwrap();
    let bomb = w.finish().unwrap().into_inner();
    assert!(bomb.len() < 2 * 1024 * 1024);
    assert!(matches!(bundle::open(&bomb, None), Err(BundleError::Limits(_))));
}

#[test]
fn data_008_imports_never_activate_bypass_or_trust() {
    let mut g = sample();
    g.scenarios.push(Scenario {
        meta: Meta::new(),
        workspace_id: g.workspaces[0].meta.id,
        name: "s".into(),
        description: "".into(),
        steps: vec![],
        dataset_id: None,
        iterations: 1,
        stop_on_failure: false,
        trusted: true,
    });
    g.integrations.push(anvil_domain::integration::IntegrationProfile {
        id: Id::new(),
        workspace_id: g.workspaces[0].meta.id,
        name: "lab gateway".into(),
        kind: anvil_domain::integration::IntegrationKind::FerrumGateway {
            hosts: vec![anvil_domain::tls::HostBinding { host: "api.example.com".into(), port: None }],
            compatibility_id: "ferrum-edge-0.9.5".into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    g.requests[0].spec.settings.redirects =
        Some(anvil_domain::settings::RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    g.workspaces[0].settings.early_data =
        Some(anvil_domain::settings::EarlyDataPolicy { enabled: true, extra_methods: vec!["PUT".into()] });
    let (bytes, _) = bundle::write(&g, &opts(ExportMode::ShareSafely, None)).unwrap();
    let opened = bundle::open(&bytes, None).unwrap();
    assert!(opened.graph.tls_profiles.iter().all(|t| t.verify), "verification bypass is not imported as active");
    assert!(opened.graph.scenarios.iter().all(|s| !s.trusted));
    assert!(opened.warnings.iter().any(|w| w.contains("re-enabled")));
    let anvil_domain::integration::IntegrationKind::FerrumGateway { require_verified_tls, .. } = &opened.graph.integrations[0].kind;
    assert!(*require_verified_tls, "plain-HTTP marker trust is not imported as active");
    assert!(
        opened.graph.requests.iter().all(|r| r.spec.settings.redirects.as_ref().is_none_or(|p| !p.forward_credentials_cross_origin)),
        "cross-origin credential forwarding is not imported as active"
    );
    assert!(opened.warnings.iter().any(|w| w.contains("other origins")));
    assert!(
        opened.graph.workspaces.iter().all(|w| w.settings.early_data.as_ref().is_none_or(|e| !e.enabled)),
        "replayable 0-RTT early data is not imported as active"
    );
    assert!(opened.warnings.iter().any(|w| w.contains("0-RTT early data")));
}

/// SPIFFE Workload API sources need no secret, so an import draws on the
/// importing machine's identity: "send a failing JWT-SVID" is never
/// imported, and the profiles that use the identity are named. A JWT-SVID
/// held as a value is a secret like any other (placeholder when shared).
#[test]
fn data_008_workload_api_sources_are_flagged_and_send_anyway_is_not_imported() {
    use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
    let mut g = sample();
    let jwt = |source: JwtSvidSource| JwtSvidConfig {
        source,
        audiences: vec!["spiffe://example.org/api".into()],
        endpoint: "unix:///run/spire/sockets/agent.sock".into(),
        spiffe_id: None,
        verify_with_bundles: true,
        send_despite_failed_checks: true,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    };
    g.requests[0].spec.auth = AuthConfig::JwtSvid { config: jwt(JwtSvidSource::WorkloadApi) };
    g.requests[1].spec.auth = AuthConfig::Multi {
        profiles: vec![AuthConfig::JwtSvid {
            config: jwt(JwtSvidSource::Value { token: SensitiveValue::template("eyJ.LITERAL.jwtsvid") }),
        }],
    };
    g.tls_profiles[0].client_identity =
        Some(anvil_domain::tls::ClientIdentity::WorkloadApi { endpoint: String::new(), spiffe_id: None, trust_bundle: true });
    let (bytes, _) = bundle::write(&g, &opts(ExportMode::ShareSafely, None)).unwrap();
    assert!(!text_of(&bytes).contains("eyJ.LITERAL.jwtsvid"), "a JWT-SVID value is not shared");
    let opened = bundle::open(&bytes, None).unwrap();
    for r in &opened.graph.requests {
        let cfg = match &r.spec.auth {
            AuthConfig::JwtSvid { config } => config,
            AuthConfig::Multi { profiles } => match &profiles[0] {
                AuthConfig::JwtSvid { config } => config,
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        };
        assert!(!cfg.send_despite_failed_checks, "send-anyway is not imported as active");
    }
    assert!(opened.warnings.iter().any(|w| w.contains("2 JWT-SVID auth profile(s) sent tokens that failed")), "{:?}", opened.warnings);
    assert!(opened.warnings.iter().any(|w| w.contains("1 JWT-SVID auth profile(s) fetch tokens from this machine's SPIFFE Workload API")));
    assert!(opened.warnings.iter().any(|w| w.contains("TLS profile(s) lab present this machine's X.509-SVID")));
}

#[test]
fn imports_never_open_an_import_root_and_list_every_linked_file() {
    let mut g = sample();
    let ws = g.workspaces[0].meta.id;
    let env = g.environments[0].meta.id;
    g.folders[0].import_root = true;
    g.folders[0].use_workspace_scope = true;
    g.folders[0].import_environment_ids = vec![env, Id::new()];
    let upload = AttachmentRef::LinkedFile { path: "/home/user/upload.bin".into() };
    g.requests[0].spec.body = Body::Binary { attachment: upload, content_type: None };
    g.datasets.push(Dataset {
        meta: Meta::new(),
        workspace_id: ws,
        name: "rows".into(),
        format: DatasetFormat::Csv,
        attachment: AttachmentRef::LinkedFile { path: "/home/user/rows.csv".into() },
        sensitive_columns: vec![],
    });
    let (bytes, preview) = bundle::write(&g, &opts(ExportMode::EncryptedTransfer, Some("correct horse battery"))).unwrap();
    assert!(preview.manifest.device_bindings.iter().any(|d| d.contains("datasets")), "{:?}", preview.manifest.device_bindings);

    let opened = bundle::open(&bytes, Some("correct horse battery")).unwrap();
    let root = opened.graph.folders.iter().find(|f| f.meta.id == g.folders[0].meta.id).unwrap();
    assert!(root.import_root, "the boundary is kept");
    assert!(!root.use_workspace_scope, "the device-local choice is not");
    assert_eq!(root.import_environment_ids, vec![env], "only environments of its own workspace in the bundle");
    assert!(opened.warnings.iter().any(|w| w.contains("imported collection")), "{:?}", opened.warnings);
    let expected = vec!["request 'Create order': /home/user/upload.bin".to_string(), "dataset 'rows': /home/user/rows.csv".to_string()];
    assert_eq!(opened.graph.linked_files(), expected);
    assert!(opened.warnings.iter().any(|w| w.contains("/home/user/rows.csv")), "{:?}", opened.warnings);

    // A duplicate's import root names the copied environment.
    let mut dup = opened.graph.clone();
    plan::remap_all(&mut dup).unwrap();
    let root = dup.folders.iter().find(|f| f.import_root).unwrap();
    assert_eq!(root.import_environment_ids, vec![dup.environments[0].meta.id]);
    assert_ne!(root.import_environment_ids, vec![env]);
}

#[test]
fn data_006_conflict_policies_and_duplicate_remap() {
    let g = sample();
    let existing = Existing { objects: g.requests.iter().map(|r| r.meta.id).collect(), ..Default::default() };
    let merge = plan::plan(&g, &existing, ConflictPolicy::Merge);
    assert_eq!(merge.skipped_existing, 2);
    let replace = plan::plan(&g, &existing, ConflictPolicy::Replace);
    assert_eq!(replace.to_replace, 2);
    let mut dup = g.clone();
    plan::remap_all(&mut dup).unwrap();
    let new_ids: HashSet<Id> = dup.requests.iter().map(|r| r.meta.id).collect();
    assert!(new_ids.is_disjoint(&existing.objects));
    // References follow the remap.
    let folder_ids: HashSet<Id> = dup.folders.iter().map(|f| f.meta.id).collect();
    assert!(dup.requests.iter().all(|r| r.folder_id.map(|f| folder_ids.contains(&f)).unwrap_or(true)));
    assert!(dup.folders.iter().all(|f| f.workspace_id == dup.workspaces[0].meta.id));
    // Duplicating twice is deterministic in shape (idempotent structure).
    assert_eq!(dup.object_count(), g.object_count());
}

/// Re-pack a bundle after `edit` has changed its entries, recomputing the
/// checksums (they detect corruption, not deliberate edits).
fn repack(bytes: &[u8], edit: impl Fn(&str, &mut Vec<u8>)) -> Vec<u8> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut entries = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut b).unwrap();
        entries.push((f.name().to_string(), b));
    }
    let mut checks: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (n, b) in &mut entries {
        edit(n.as_str(), b);
        if n != "checksums.json" {
            checks.insert(n.clone(), hex_sha(b));
        }
    }
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, b) in &entries {
        w.start_file(n.clone(), zip::write::SimpleFileOptions::default()).unwrap();
        if n == "checksums.json" {
            w.write_all(&serde_json::to_vec(&checks).unwrap()).unwrap();
        } else {
            w.write_all(b).unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

/// Re-pack a bundle after editing one JSON entry.
fn edit_json(bytes: &[u8], entry: &str, edit: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
    repack(bytes, |n, b| {
        if n == entry {
            let mut v: serde_json::Value = serde_json::from_slice(b).unwrap();
            edit(&mut v);
            *b = serde_json::to_vec(&v).unwrap();
        }
    })
}

#[test]
fn future_format_is_refused() {
    let (bytes, _) = bundle::write(&sample(), &opts(ExportMode::ShareSafely, None)).unwrap();
    let fut = edit_json(&bytes, "manifest.json", |m| m["format_version"] = 99.into());
    assert!(matches!(bundle::open(&fut, None), Err(BundleError::FutureFormat { found: 99, .. })));
}

#[test]
fn bundles_written_at_a_newer_schema_are_refused() {
    let supported = anvil_domain::SCHEMA_VERSION;
    let future = supported + 100;
    let (bytes, preview) = bundle::write(&sample(), &opts(ExportMode::ShareSafely, None)).unwrap();
    assert_eq!(preview.manifest.schema_version, supported);
    bundle::open(&bytes, None).expect("the current schema opens");

    let fut = edit_json(&bytes, "manifest.json", |m| m["schema_version"] = future.into());
    let e = bundle::open(&fut, None).unwrap_err();
    assert!(matches!(e, BundleError::FutureSchema { found, supported: s } if found == future && s == supported), "{e}");
    assert!(e.to_string().contains("newer Anvil"), "{e}");

    // Older than any schema this build can read or migrate.
    let old = edit_json(&bytes, "manifest.json", |m| m["schema_version"] = 0.into());
    let e = bundle::open(&old, None).unwrap_err();
    assert!(matches!(e, BundleError::UnsupportedSchema { found: 0, .. }), "{e}");

    // One object written at a newer schema is enough to refuse the bundle.
    let obj = edit_json(&bytes, "workspace/objects.json", |o| o["workspaces"][0]["schema_version"] = future.into());
    let e = bundle::open(&obj, None).unwrap_err();
    assert!(matches!(e, BundleError::FutureSchema { found, .. } if found == future), "{e}");

    // Encrypted bundles are refused before a passphrase is asked for.
    let (enc, _) = bundle::write(&sample(), &opts(ExportMode::EncryptedTransfer, Some("correct horse battery"))).unwrap();
    let fut = edit_json(&enc, "manifest.json", |m| m["schema_version"] = future.into());
    assert!(matches!(bundle::open(&fut, None), Err(BundleError::FutureSchema { .. })));
    assert!(matches!(bundle::open(&fut, Some("correct horse battery")), Err(BundleError::FutureSchema { .. })));
}

#[test]
fn out_of_range_kdf_costs_are_refused_before_deriving() {
    use bundle::{MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM};
    let pass = "correct horse battery";
    let (bytes, preview) = bundle::write(&sample(), &opts(ExportMode::EncryptedTransfer, Some(pass))).unwrap();
    assert!(preview.secrets_included > 0);
    let with_costs = |m: u32, t: u32, p: u32| {
        edit_json(&bytes, "manifest.json", move |v| {
            v["vault"]["kdf"]["m_cost"] = m.into();
            v["vault"]["kdf"]["t_cost"] = t.into();
            v["vault"]["kdf"]["p_cost"] = p.into();
        })
    };
    let refused = [
        (u32::MAX, 1, 1),
        (MAX_KDF_MEMORY_KIB + 1, 1, 1),
        (1024, MAX_KDF_ITERATIONS + 1, 1),
        (1024, u32::MAX, 1),
        (1024, 1, MAX_KDF_PARALLELISM + 1),
        (1024, 1, u32::MAX),
        // Within each bound, but over the memory x passes budget.
        (MAX_KDF_MEMORY_KIB, 5, 1),
        (0, 1, 1),
        (1024, 0, 1),
        (1024, 1, 0),
        // Argon2 needs 8 KiB per lane.
        (31, 1, 4),
    ];
    for (m, t, p) in refused {
        let b = with_costs(m, t, p);
        // Refused without deriving: the result is not a wrong-passphrase
        // failure, and no passphrase is needed to get it.
        let e = bundle::open(&b, Some(pass)).unwrap_err();
        assert!(matches!(e, BundleError::UnsupportedKdf(_)), "m={m} t={t} p={p}: {e}");
        assert!(matches!(bundle::open(&b, None), Err(BundleError::UnsupportedKdf(_))), "m={m} t={t} p={p}");
    }
    // A salt outside 8..=64 bytes is refused the same way.
    use base64::Engine;
    for len in [4, 65, 256] {
        let salt = base64::engine::general_purpose::STANDARD.encode(vec![7u8; len]);
        let b = edit_json(&bytes, "manifest.json", move |v| v["vault"]["salt_b64"] = salt.clone().into());
        assert!(matches!(bundle::open(&b, Some(pass)), Err(BundleError::UnsupportedKdf(_))), "salt of {len} bytes");
    }
    // The bounds themselves, the export defaults and the test costs are allowed.
    for ok in [
        KdfParams::interactive(),
        KdfParams::testing(),
        KdfParams { m_cost: MAX_KDF_MEMORY_KIB, t_cost: 4, p_cost: 1, ..KdfParams::interactive() },
        KdfParams { m_cost: 1024, t_cost: MAX_KDF_ITERATIONS, p_cost: MAX_KDF_PARALLELISM, ..KdfParams::interactive() },
        KdfParams { m_cost: 32, t_cost: 1, p_cost: 4, ..KdfParams::interactive() },
    ] {
        bundle::check_kdf(&ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
    }
    // In-range costs other than the ones written still reach the vault (and
    // fail its authentication, since the key differs).
    let b = with_costs(2048, 1, 1);
    assert!(matches!(bundle::open(&b, Some(pass)), Err(BundleError::WrongPassphrase)));
    // Exports refuse costs they could not open again.
    let too_costly = KdfParams { m_cost: MAX_KDF_MEMORY_KIB + 1, ..KdfParams::interactive() };
    let e = bundle::write(&sample(), &ExportOptions { kdf: too_costly, ..opts(ExportMode::EncryptedTransfer, Some(pass)) }).unwrap_err();
    assert!(matches!(e, BundleError::UnsupportedKdf(_)), "{e}");
}

fn with_revision(g: &mut PortableGraph) -> RequestRevision {
    let r = &mut g.requests[0];
    let rev = RequestRevision {
        id: Id::new(),
        request_id: r.meta.id,
        created_at: chrono::Utc::now(),
        spec_sha256: "0".repeat(64),
        spec: r.spec.clone(),
    };
    r.revision_id = Some(rev.id);
    g.revisions.push(rev.clone());
    rev
}

#[test]
fn duplicate_remap_gives_revisions_and_secrets_fresh_identities() {
    let mut g = sample();
    let rev = with_revision(&mut g);
    let ws_id = g.workspaces[0].meta.id;
    let req_id = g.requests[0].meta.id;
    let secret_id = g.secrets.keys().next().unwrap().clone();
    // Text that only looks like an id is user data, not a reference.
    g.requests[0].description = req_id.to_string();
    g.requests[0].spec.headers.push(KeyValue::new("X-Workspace", ws_id.to_string()));

    let mut dup = g.clone();
    let map = plan::remap_all(&mut dup).unwrap();
    let new_ws = dup.workspaces[0].meta.id;
    assert_ne!(new_ws, ws_id);
    let copy = dup.requests.iter().find(|r| r.name == "Create order").unwrap();
    assert_ne!(copy.meta.id, req_id);

    // The revision is a new object that belongs to the copied request.
    assert_eq!(dup.revisions.len(), 1);
    let copy_rev = &dup.revisions[0];
    assert_ne!(copy_rev.id, rev.id, "a copied revision never reuses the source's id");
    assert_eq!(copy_rev.request_id, copy.meta.id);
    assert_eq!(copy.revision_id, Some(copy_rev.id));
    assert_eq!(map.get(&rev.id), Some(&copy_rev.id));

    // The secret gets a new id, the copied workspace owns it, and references follow.
    assert_eq!(dup.secrets.len(), 1);
    let (new_secret, value) = dup.secrets.iter().next().unwrap();
    assert_ne!(*new_secret, secret_id);
    assert_eq!(value.workspace_id, Some(new_ws.to_string()));
    assert_eq!(value.value, "VAULT-SECRET-999");
    let list = dup.requests.iter().find(|r| r.name == "List").unwrap();
    let AuthConfig::ApiKey { value: SensitiveValue::Secret { secret }, .. } = &list.spec.auth else { panic!("{:?}", list.spec.auth) };
    assert_eq!(secret.id.to_string(), *new_secret);

    // User text is left alone.
    assert_eq!(copy.description, req_id.to_string());
    assert!(copy.spec.headers.iter().any(|h| h.name == "X-Workspace" && h.value == ws_id.to_string()));

    // The remapped graph passes the same validation an opened bundle does.
    anvil_portability::validate::validate_and_normalize(&mut dup).unwrap();
}

#[test]
fn encrypted_bundle_keeps_revisions_and_secret_owners_through_a_round_trip() {
    let mut g = sample();
    let rev = with_revision(&mut g);
    let (bytes, _) = bundle::write(&g, &opts(ExportMode::EncryptedTransfer, Some("correct horse battery"))).unwrap();
    let opened = bundle::open(&bytes, Some("correct horse battery")).unwrap();
    assert_eq!(opened.graph.revisions.len(), 1);
    assert_eq!(opened.graph.revisions[0].id, rev.id);
    let ws = g.workspaces[0].meta.id.to_string();
    assert!(opened.graph.secrets.values().all(|s| s.workspace_id.as_deref() == Some(ws.as_str())));
}

#[test]
fn validation_refuses_foreign_secret_owners_and_reused_ids() {
    use anvil_portability::validate::validate_and_normalize;
    let invalid = |g: &mut PortableGraph, needle: &str| match validate_and_normalize(g) {
        Err(BundleError::Invalid(m)) => assert!(m.contains(needle), "{m}"),
        other => panic!("expected an invalid bundle ({needle}), got {other:?}"),
    };
    // A secret owned by a workspace that is not in the bundle.
    let mut g = sample();
    g.secrets.values_mut().for_each(|s| s.workspace_id = Some(Id::new().to_string()));
    invalid(&mut g, "belongs to a workspace that is not in the bundle");
    let mut g = sample();
    g.secrets.values_mut().for_each(|s| s.workspace_id = None);
    invalid(&mut g, "belongs to a workspace that is not in the bundle");
    // A secret whose id is not an id.
    let mut g = sample();
    let v = g.secrets.values().next().unwrap().clone();
    g.secrets.insert("not-an-id".into(), v);
    invalid(&mut g, "invalid id");
    // Two objects with one id.
    let mut g = sample();
    g.environments[0].meta.id = g.requests[0].meta.id;
    invalid(&mut g, "reuses the id");
    // A revision repeated with different contents.
    let mut g = sample();
    let rev = with_revision(&mut g);
    g.revisions.push(RequestRevision { spec_sha256: "1".repeat(64), ..rev.clone() });
    invalid(&mut g, "appears twice");
    // A revision that reuses another object's id.
    let mut g = sample();
    with_revision(&mut g);
    g.revisions[0].id = g.folders[0].meta.id;
    invalid(&mut g, "reuses the id");
}

#[test]
fn validation_collapses_repeated_revisions_and_drops_orphans() {
    let mut g = sample();
    let rev = with_revision(&mut g);
    g.revisions.push(rev.clone());
    g.revisions.push(RequestRevision { id: Id::new(), request_id: Id::new(), ..rev.clone() });
    let warnings = anvil_portability::validate::validate_and_normalize(&mut g).unwrap();
    assert_eq!(g.revisions, vec![rev]);
    assert!(warnings.iter().any(|w| w.contains("1 request revision(s)")), "{warnings:?}");
}

#[test]
fn plan_lists_secret_conflicts_and_secrets_owned_outside_the_bundle() {
    let g = sample();
    let ws = g.workspaces[0].meta.id;
    let secret: Id = g.secrets.keys().next().unwrap().parse().unwrap();
    let listed = format!("secret 'orders key' ({secret})");
    let stored = |owner: Option<Id>| Existing { secrets: [(secret, owner)].into_iter().collect(), ..Default::default() };

    // Nothing stored: nothing conflicts, and the secret counts as created.
    let fresh = plan::plan(&g, &Existing::default(), ConflictPolicy::Replace);
    assert!(fresh.conflicts.is_empty() && fresh.foreign_secrets.is_empty(), "{fresh:?}");
    assert_eq!(fresh.to_create, g.object_count() + 1);

    // Stored under a workspace of the bundle: a conflict Replace may overwrite.
    let own = plan::plan(&g, &stored(Some(ws)), ConflictPolicy::Replace);
    assert_eq!(own.conflicts, vec![listed.clone()]);
    assert_eq!(own.to_replace, 1);
    assert!(own.foreign_secrets.is_empty(), "{own:?}");

    // Stored under another workspace, or under none: listed as foreign for every policy.
    for owner in [Some(Id::new()), None] {
        for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace, ConflictPolicy::Duplicate] {
            let p = plan::plan(&g, &stored(owner), policy);
            assert_eq!(p.conflicts, vec![listed.clone()], "{policy:?}");
            assert_eq!(p.foreign_secrets, vec![listed.clone()], "{policy:?}");
        }
    }
    let merge = plan::plan(&g, &stored(Some(Id::new())), ConflictPolicy::Merge);
    assert_eq!(merge.skipped_existing, 1);
}

#[test]
fn plan_lists_stored_workspaces_the_bundle_claims_and_objects_stored_in_another_workspace() {
    let g = sample();
    let ws = g.workspaces[0].meta.id;
    let folder = &g.folders[0];

    // A workspace stored here under a bundle workspace's id is listed with its
    // local name for Merge and Replace; a Duplicate copy claims none.
    let claimed = Existing { workspaces: [(ws, "Local payments".to_string())].into_iter().collect(), ..Default::default() };
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        let p = plan::plan(&g, &claimed, policy);
        assert_eq!(p.existing_workspaces, vec![ExistingWorkspace { id: ws, name: "Local payments".into() }], "{policy:?}");
    }
    assert!(plan::plan(&g, &claimed, ConflictPolicy::Duplicate).existing_workspaces.is_empty());
    assert!(plan::plan(&g, &Existing::default(), ConflictPolicy::Merge).existing_workspaces.is_empty());

    // A folder stored in its own workspace is an ordinary conflict.
    let stored = |kind: &str, owner: Option<Id>| Existing {
        owners: [((kind.to_string(), folder.meta.id), owner)].into_iter().collect(),
        ..Default::default()
    };
    assert!(plan::plan(&g, &stored("folder", Some(ws)), ConflictPolicy::Replace).foreign_objects.is_empty());
    // Stored in another workspace, or in none: listed for Merge and Replace.
    // A Duplicate copy gets a fresh id, so it lands on nothing stored.
    let listed = format!("folder 'Orders' ({})", folder.meta.id);
    for owner in [Some(Id::new()), None] {
        for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
            assert_eq!(plan::plan(&g, &stored("folder", owner), policy).foreign_objects, vec![listed.clone()], "{policy:?}");
        }
        assert!(plan::plan(&g, &stored("folder", owner), ConflictPolicy::Duplicate).foreign_objects.is_empty());
    }
    // The same id under another kind is a different stored object.
    assert!(plan::plan(&g, &stored("request", Some(Id::new())), ConflictPolicy::Replace).foreign_objects.is_empty());
}

fn proxy(workspace_id: Id) -> anvil_domain::tls::ProxyProfile {
    anvil_domain::tls::ProxyProfile {
        id: Id::new(),
        workspace_id,
        name: "corp".into(),
        kind: Default::default(),
        address: "proxy.example.com:3128".into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        tls_profile_id: None,
        hbone: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn integration(workspace_id: Id) -> anvil_domain::integration::IntegrationProfile {
    anvil_domain::integration::IntegrationProfile {
        id: Id::new(),
        workspace_id,
        name: "lab gateway".into(),
        kind: anvil_domain::integration::IntegrationKind::FerrumGateway {
            hosts: vec![],
            compatibility_id: "ferrum-edge-0.9.5".into(),
            require_verified_tls: true,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn dataset(workspace_id: Id) -> Dataset {
    Dataset {
        meta: Meta::new(),
        workspace_id,
        name: "rows".into(),
        format: DatasetFormat::Csv,
        attachment: stored(&hex_sha(b"attachment bytes")),
        sensitive_columns: vec![],
    }
}

fn scenario(workspace_id: Id, requests: &[Id]) -> Scenario {
    Scenario {
        meta: Meta::new(),
        workspace_id,
        name: "smoke".into(),
        description: String::new(),
        steps: requests.iter().map(|r| ScenarioStep { request_id: *r, enabled: true, delay_ms: 0 }).collect(),
        dataset_id: None,
        iterations: 1,
        stop_on_failure: false,
        trusted: false,
    }
}

fn load_plan(workspace_id: Id, chain: &[Id]) -> anvil_domain::load::LoadPlan {
    serde_json::from_value(serde_json::json!({
        "id": Id::new(),
        "workspace_id": workspace_id,
        "name": "soak",
        "workload": { "model": "iterations", "iterations": 1, "concurrency": 1 },
        "chain": chain,
        "created_at": chrono::Utc::now(),
        "updated_at": chrono::Utc::now(),
    }))
    .unwrap()
}

#[test]
fn validation_refuses_objects_and_references_outside_their_workspace() {
    use anvil_portability::validate::validate_and_normalize;
    let invalid = |mut g: PortableGraph, needle: &str| match validate_and_normalize(&mut g) {
        Err(BundleError::Invalid(m)) => assert!(m.contains(needle), "{needle}: {m}"),
        other => panic!("expected an invalid bundle ({needle}), got {other:?}"),
    };
    let foreign = Id::new();
    let base = sample();
    let ws = base.workspaces[0].meta.id;
    let request = base.requests[0].meta.id;
    // A second workspace in the same bundle: references may not cross into it.
    let mut two = base.clone();
    let mut other = two.workspaces[0].clone();
    other.meta = Meta::new();
    other.name = "Other".into();
    let other_ws = other.meta.id;
    two.workspaces.push(other);
    let mut other_req = two.requests[0].clone();
    other_req.meta = Meta::new();
    other_req.workspace_id = other_ws;
    other_req.folder_id = None;
    let other_req_id = other_req.meta.id;
    two.requests.push(other_req);
    let mut other_env = two.environments[0].clone();
    other_env.meta = Meta::new();
    other_env.workspace_id = other_ws;
    let other_env_id = other_env.meta.id;
    two.environments.push(other_env);
    let other_data = dataset(other_ws);
    let other_data_id = other_data.meta.id;
    two.datasets.push(other_data);
    let mut ok = two.clone();
    ok.scenarios.push(scenario(other_ws, &[other_req_id]));
    ok.load_plans.push(load_plan(ws, &[request]));
    validate_and_normalize(&mut ok).expect("references within their own workspace are valid");

    // Workspace-scoped objects of a workspace that is not in the bundle.
    let with = |edit: &dyn Fn(&mut PortableGraph)| {
        let mut g = base.clone();
        edit(&mut g);
        g
    };
    let outside = "belongs to a workspace that is not in the bundle";
    invalid(with(&|g| g.tls_profiles[0].workspace_id = foreign), outside);
    invalid(with(&|g| g.proxy_profiles.push(proxy(foreign))), outside);
    invalid(with(&|g| g.integrations.push(integration(foreign))), outside);
    invalid(with(&|g| g.datasets.push(dataset(foreign))), outside);
    invalid(with(&|g| g.scenarios.push(scenario(foreign, &[]))), outside);
    invalid(with(&|g| g.load_plans.push(load_plan(foreign, &[]))), outside);

    // Folder and request references into another workspace of the bundle.
    let mut g = two.clone();
    g.folders[1].workspace_id = other_ws;
    invalid(g, "has a parent that is not in the bundle or its workspace");
    let mut g = two.clone();
    g.requests[0].workspace_id = other_ws;
    invalid(g, "is in a folder that is not in the bundle or its workspace");

    // Scenario and load plan references outside the bundle or into another workspace.
    for step in [Id::new(), other_req_id] {
        let mut g = two.clone();
        g.scenarios.push(scenario(ws, &[request, step]));
        invalid(g, "scenario 'smoke' runs a request that is not in the bundle or its workspace");
        let mut g = two.clone();
        g.load_plans.push(load_plan(ws, &[step]));
        invalid(g, "load plan 'soak' runs a request that is not in the bundle or its workspace");
        let mut g = two.clone();
        let mut p = load_plan(ws, &[]);
        p.mix.push(anvil_domain::load::WeightedStep { request_id: step, weight: 1 });
        g.load_plans.push(p);
        invalid(g, "load plan 'soak' runs a request that is not in the bundle or its workspace");
    }
    for data in [Id::new(), other_data_id] {
        let mut g = two.clone();
        g.scenarios.push(Scenario { dataset_id: Some(data), ..scenario(ws, &[request]) });
        invalid(g, "scenario 'smoke' uses a dataset that is not in the bundle or its workspace");
        let mut g = two.clone();
        g.load_plans.push(anvil_domain::load::LoadPlan { dataset_id: Some(data), ..load_plan(ws, &[request]) });
        invalid(g, "load plan 'soak' uses a dataset that is not in the bundle or its workspace");
    }
    for env in [Id::new(), other_env_id] {
        let mut g = two.clone();
        g.load_plans.push(anvil_domain::load::LoadPlan { environment_id: Some(env), ..load_plan(ws, &[request]) });
        invalid(g, "load plan 'soak' uses an environment that is not in the bundle or its workspace");
    }
}

#[test]
fn a_request_keeps_only_a_revision_of_its_own_from_the_bundle() {
    let mut g = sample();
    let rev = with_revision(&mut g);
    let owner = rev.request_id;
    // One request names a revision of a different request, another one a
    // revision the bundle does not carry.
    g.requests[1].revision_id = Some(rev.id);
    let borrowed = g.requests[1].meta.id;
    let mut third = g.requests[0].clone();
    third.meta = Meta::new();
    third.name = "Third".into();
    third.revision_id = Some(Id::new());
    let third_id = third.meta.id;
    g.requests.push(third);

    anvil_portability::validate::validate_and_normalize(&mut g).unwrap();
    let revision_of = |id: Id| g.requests.iter().find(|r| r.meta.id == id).unwrap().revision_id;
    assert_eq!(revision_of(owner), Some(rev.id), "a request keeps its own revision");
    assert_eq!(revision_of(borrowed), None, "another request's revision is dropped");
    assert_eq!(revision_of(third_id), None, "a revision the bundle does not carry is dropped");

    // A Duplicate copy therefore never points at a revision outside itself.
    let mut dup = g.clone();
    plan::remap_all(&mut dup).unwrap();
    let copied: HashSet<Id> = dup.revisions.iter().map(|r| r.id).collect();
    assert!(dup.requests.iter().filter_map(|r| r.revision_id).all(|r| copied.contains(&r)));
}

fn stored(sha256: &str) -> AttachmentRef {
    AttachmentRef::Stored { sha256: sha256.into(), size: 16, file_name: "upload.bin".into(), media_type: None }
}

fn file_part(attachment: AttachmentRef, enabled: bool) -> MultipartPart {
    MultipartPart { name: "file".into(), enabled, content: MultipartContent::File { attachment, file_name: None }, content_type: None }
}

fn grpc(schema: GrpcSchemaSource) -> RequestSpec {
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9");
    spec.protocol = Protocol::Grpc;
    spec.grpc = Some(GrpcSpec {
        service: "lab.Echo".into(),
        method: "Say".into(),
        mode: GrpcMode::Unary,
        schema,
        messages: vec!["{}".into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: true,
        wire: GrpcWire::Grpc,
    });
    spec
}

/// Every place a request names a stored attachment, next to one the bundle
/// carries (`carried`), with `sha256` as the other.
fn stored_specs(carried: &str, sha256: &str) -> Vec<(&'static str, RequestSpec)> {
    let with_body = |body: Body| RequestSpec { body, ..RequestSpec::http("POST", "http://127.0.0.1:9/upload") };
    vec![
        ("binary body", with_body(Body::Binary { attachment: stored(sha256), content_type: None })),
        ("multipart part", with_body(Body::Multipart { parts: vec![file_part(stored(carried), true), file_part(stored(sha256), true)] })),
        ("disabled multipart part", with_body(Body::Multipart { parts: vec![file_part(stored(sha256), false)] })),
        ("gRPC proto file", grpc(GrpcSchemaSource::ProtoFiles { files: vec![stored(carried), stored(sha256)] })),
        ("gRPC descriptor set", grpc(GrpcSchemaSource::DescriptorSet { attachment: stored(sha256) })),
    ]
}

#[test]
fn a_stored_attachment_is_imported_only_with_its_bytes() {
    let carried = hex_sha(b"attachment bytes");
    let elsewhere = hex_sha(b"bytes the bundle does not carry");
    let reopen = |g: &PortableGraph| bundle::open(&bundle::write(g, &opts(ExportMode::ShareSafely, None)).unwrap().0, None);
    let refused = |g: &PortableGraph, needle: &str, label: &str| match reopen(g) {
        Err(BundleError::Invalid(m)) => assert!(m.contains(needle), "{label}: {m}"),
        other => panic!("{label}: expected the bundle to be refused, got {other:?}"),
    };
    // A request or dataset naming stored bytes the bundle does not carry.
    for (label, spec) in stored_specs(&carried, &elsewhere) {
        let mut g = sample();
        g.requests[0].spec = spec;
        refused(&g, "request 'Create order' uses a stored attachment that the bundle does not carry", label);
    }
    let mut g = sample();
    let ws = g.workspaces[0].meta.id;
    g.datasets.push(Dataset { attachment: stored(&elsewhere), ..dataset(ws) });
    refused(&g, "dataset 'rows' uses a stored attachment that the bundle does not carry", "dataset");

    // With their bytes in the bundle, the same references import.
    let mut g = sample();
    let base = g.requests[0].clone();
    for (label, spec) in stored_specs(&carried, &carried) {
        g.requests.push(RequestDefinition { meta: Meta::new(), name: label.into(), spec, ..base.clone() });
    }
    g.datasets.push(dataset(g.workspaces[0].meta.id));
    let opened = reopen(&g).expect("every stored attachment travels with its bytes");
    assert_eq!(opened.graph.requests.len(), 2 + stored_specs(&carried, &carried).len());
    assert_eq!(opened.graph.attachments.get(&carried).map(Vec::as_slice), Some(&b"attachment bytes"[..]));
    // A linked local file names no stored bytes.
    let mut g = sample();
    g.requests[0].spec.body = Body::Binary { attachment: AttachmentRef::LinkedFile { path: "/tmp/a.bin".into() }, content_type: None };
    reopen(&g).expect("a linked local file is not a stored attachment");
}
