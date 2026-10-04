//! Opt-in hosted resource qualification. Never run as part of ordinary tests.
//! Generation and opening run in separate processes so fixture allocation does
//! not contaminate opening RSS. Only synthetic data and scalar metrics are logged.

use anvil_portability::bundle::{self, BundleError, BundleKind, ExportMode, ExportOptions};
use anvil_portability::graph::PortableGraph;
use anvil_storage::crypto::KdfParams;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;

const MIB: u64 = 1024 * 1024;
const CASES: [&str; 7] =
    ["proposal_exact", "released_exact", "entry_over", "total_over", "invalid_manifest", "invalid_checksums", "metadata_exact"];

fn fixture_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ANVIL_RESOURCE_FIXTURES").expect("hosted fixture directory"))
}

fn assert_snapshot() -> String {
    let variant = std::env::var("ANVIL_RESOURCE_VARIANT").expect("hosted variant");
    let snapshot = std::env::var("ANVIL_RESOURCE_EXPECTED_SNAPSHOT").expect("hosted snapshot");
    let Some(built_variant) = option_env!("ANVIL_RESOURCE_BUILD_VARIANT") else {
        panic!("qualification binary is missing its embedded variant");
    };
    let Some(built_snapshot) = option_env!("ANVIL_RESOURCE_BUILD_SNAPSHOT") else {
        panic!("qualification binary is missing its embedded snapshot");
    };
    assert_eq!(variant, built_variant, "measured binary must match the named variant");
    assert_eq!(snapshot, built_snapshot, "measured binary must match the exact snapshot");
    let (total, entry) = match variant.as_str() {
        "candidate" => (64 * MIB, 32 * MIB),
        "preflight" | "released" => (1024 * MIB, 512 * MIB),
        _ => panic!("unknown qualification variant"),
    };
    assert_eq!(bundle::MAX_TOTAL_BYTES, total);
    assert_eq!(bundle::MAX_ENTRY_BYTES, entry);
    assert_eq!(bundle::MAX_ENTRIES, 20_000);
    assert_eq!(bundle::MAX_RATIO, 200);
    println!("variant={variant} snapshot={snapshot} total_limit={total} entry_limit={entry}");
    variant
}

fn base_files() -> BTreeMap<String, Vec<u8>> {
    let opts = ExportOptions {
        kind: BundleKind::Workspace,
        mode: ExportMode::ShareSafely,
        passphrase: None,
        include_history: false,
        kdf: KdfParams::testing(),
        app_version: "synthetic-resource-qualification",
    };
    let (bytes, _) = bundle::write(&PortableGraph::default(), &opts).unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut files = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        files.insert(entry.name().to_string(), data);
    }
    files.remove("checksums.json");
    files
}

// A bounded 16 KiB synthetic tile, repeated while hashing/writing. No allocation
// follows an untrusted declaration. The largest inflated fixture is exactly the
// released 1 GiB limit; its compressed archive is capped at 64 MiB below.
fn tile(seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..16 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn chunks(length: u64, tile: &[u8], mut consume: impl FnMut(&[u8])) {
    assert!(length <= 512 * MIB);
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(tile.len() as u64) as usize;
        consume(&tile[..count]);
        remaining -= count as u64;
    }
}

fn attachment_name(length: u64, tile: &[u8]) -> String {
    let mut hash = Sha256::new();
    chunks(length, tile, |data| hash.update(data));
    format!("attachments/{}", hex::encode(hash.finalize()))
}

fn checksums(files: &BTreeMap<String, Vec<u8>>, names: &[String]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<_, _> = files.iter().map(|(name, data)| (name.clone(), hex::encode(Sha256::digest(data)))).collect();
    for name in names {
        out.insert(name.clone(), name.strip_prefix("attachments/").unwrap().into());
    }
    out
}

fn generate(case: &str, path: &Path) {
    let mut files = base_files();
    let attachment_count = if case == "metadata_exact" {
        0
    } else if case == "entry_over" {
        1
    } else {
        2
    };
    let mut manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
    manifest["counts"]["attachments"] = attachment_count.into();
    files.insert("manifest.json".into(), serde_json::to_vec_pretty(&manifest).unwrap());
    if case == "invalid_manifest" {
        files.insert("manifest.json".into(), b"{}".to_vec());
    }
    if case == "metadata_exact" {
        let padding = 32 * MIB - files["manifest.json"].len() as u64;
        let old = manifest["app_version"].as_str().unwrap();
        manifest["app_version"] = format!("{old}{}", "x".repeat(padding as usize)).into();
        files.insert("manifest.json".into(), serde_json::to_vec_pretty(&manifest).unwrap());
        assert_eq!(files["manifest.json"].len() as u64, 32 * MIB);
    }
    // Names/digests have fixed encoded lengths, so metadata overhead is exact
    // before attachment hashes are known. Fixtures include this overhead.
    let placeholders: Vec<_> = (0..attachment_count).map(|index| format!("attachments/{index:064x}")).collect();
    let overhead = files.values().map(|data| data.len() as u64).sum::<u64>()
        + serde_json::to_vec_pretty(&checksums(&files, &placeholders)).unwrap().len() as u64;
    let total = match case {
        "released_exact" => 1024 * MIB,
        "total_over" => 64 * MIB + 1,
        "entry_over" => overhead + 32 * MIB + 1,
        "metadata_exact" => overhead,
        _ => 64 * MIB,
    };
    assert!(total <= 1024 * MIB);
    let first = if case == "released_exact" { 512 * MIB } else { 32 * MIB };
    let lengths = match attachment_count {
        0 => Vec::new(),
        1 => vec![32 * MIB + 1],
        _ => vec![first, total - overhead - first],
    };
    let tiles: Vec<_> = (0..attachment_count).map(|index| tile(index as u64 + 17)).collect();
    let names: Vec<_> = lengths.iter().zip(&tiles).map(|(length, tile)| attachment_name(*length, tile)).collect();
    let mut digests = checksums(&files, &names);
    if case == "invalid_checksums" {
        digests.insert("manifest.json".into(), "0".repeat(64));
    }
    files.insert("checksums.json".into(), serde_json::to_vec_pretty(&digests).unwrap());
    assert_eq!(files.values().map(|data| data.len() as u64).sum::<u64>(), overhead);
    let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
    let deflated = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for ((name, length), tile) in names.iter().zip(&lengths).zip(&tiles) {
        writer.start_file(name.as_str(), deflated).unwrap();
        chunks(*length, tile, |data| writer.write_all(data).unwrap());
    }
    for (name, data) in &files {
        // The metadata boundary uses Stored to remain within the ratio policy.
        let options = if case == "metadata_exact" {
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
        } else {
            deflated
        };
        writer.start_file(name.as_str(), options).unwrap();
        writer.write_all(data).unwrap();
    }
    let file = writer.finish().unwrap();
    assert!(file.metadata().unwrap().len() <= 64 * MIB);
    // File::create is write-only, including the handle returned by finish.
    drop(file);
    let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
    let mut expanded = 0;
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index).unwrap();
        assert!(entry.size() / entry.compressed_size().max(1) <= 200);
        expanded += entry.size();
    }
    assert_eq!(expanded, total);
    println!("fixture={case} inflated_bytes={total}");
}

#[test]
#[ignore = "bounded fixture generation for GitHub-hosted resource qualification only"]
fn generate_resource_fixtures() {
    assert_eq!(assert_snapshot(), "candidate");
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for case in CASES {
        generate(case, &dir.join(format!("{case}.zip")));
    }
}

#[test]
#[ignore = "run each case in a fresh process under the hosted OS RSS collector"]
fn measure_resource_open() {
    let variant = assert_snapshot();
    let case = std::env::var("ANVIL_RESOURCE_CASE").expect("hosted case");
    assert!(CASES.contains(&case.as_str()));
    let path = fixture_dir().join(format!("{case}.zip"));
    assert!(std::fs::metadata(&path).unwrap().len() <= 64 * MIB);
    let bytes = std::fs::read(path).unwrap();
    let expected_retained = {
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        let mut total = 0;
        for index in 0..archive.len() {
            let entry = archive.by_index_raw(index).unwrap();
            if entry.name().starts_with("attachments/") {
                total += entry.size();
            }
        }
        total
    };
    let result = bundle::open(&bytes, None);
    match case.as_str() {
        "invalid_manifest" => assert!(matches!(result, Err(BundleError::NotABundle(_)))),
        "invalid_checksums" => assert!(matches!(result, Err(BundleError::Checksum(_)))),
        "released_exact" | "entry_over" | "total_over" if variant == "candidate" => {
            assert!(matches!(result, Err(BundleError::Limits(_))));
        }
        _ => {
            let opened = result.unwrap();
            let retained = opened.graph.attachments.values().map(|data| data.len() as u64).sum::<u64>();
            assert_eq!(retained, expected_retained);
            assert!(retained <= bundle::MAX_TOTAL_BYTES);
            if case == "metadata_exact" {
                assert!(opened.manifest.app_version.len() as u64 > 31 * MIB);
            } else {
                assert!(retained > 31 * MIB);
            }
            println!("retained_attachment_bytes={retained}");
        }
    }
    println!("case={case} accepted_total_limit={}", bundle::MAX_TOTAL_BYTES);
}
