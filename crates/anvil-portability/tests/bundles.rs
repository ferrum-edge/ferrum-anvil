//! DATA-001..DATA-008 bundle scenarios.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::tls::TlsProfile;
use anvil_domain::workspace::*;
use anvil_portability::bundle::{self, BundleError, BundleKind, ExportMode, ExportOptions};
use anvil_portability::plan::{self, ConflictPolicy};
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
fn data_006_conflict_policies_and_duplicate_remap() {
    let g = sample();
    let existing: HashSet<Id> = g.requests.iter().map(|r| r.meta.id).collect();
    let merge = plan::plan(&g, &existing, ConflictPolicy::Merge);
    assert_eq!(merge.skipped_existing, 2);
    let replace = plan::plan(&g, &existing, ConflictPolicy::Replace);
    assert_eq!(replace.to_replace, 2);
    let mut dup = g.clone();
    plan::remap_all(&mut dup);
    let new_ids: HashSet<Id> = dup.requests.iter().map(|r| r.meta.id).collect();
    assert!(new_ids.is_disjoint(&existing));
    // References follow the remap.
    let folder_ids: HashSet<Id> = dup.folders.iter().map(|f| f.meta.id).collect();
    assert!(dup.requests.iter().all(|r| r.folder_id.map(|f| folder_ids.contains(&f)).unwrap_or(true)));
    assert!(dup.folders.iter().all(|f| f.workspace_id == dup.workspaces[0].meta.id));
    // Duplicating twice is deterministic in shape (idempotent structure).
    assert_eq!(dup.object_count(), g.object_count());
}

#[test]
fn future_format_is_refused() {
    let (bytes, _) = bundle::write(&sample(), &opts(ExportMode::ShareSafely, None)).unwrap();
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(&bytes[..])).unwrap();
    let mut entries = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut b).unwrap();
        entries.push((f.name().to_string(), b));
    }
    let mut checks: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (n, b) in entries.iter_mut() {
        if n == "manifest.json" {
            let mut m: serde_json::Value = serde_json::from_slice(b).unwrap();
            m["format_version"] = 99.into();
            *b = serde_json::to_vec(&m).unwrap();
        }
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
    let fut = w.finish().unwrap().into_inner();
    assert!(matches!(bundle::open(&fut, None), Err(BundleError::FutureFormat { found: 99, .. })));
}
