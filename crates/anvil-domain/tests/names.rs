//! `names_match`: the one case-ignoring rule for finding a workspace, an
//! environment or a Ferrum gateway profile by its name.

use anvil_domain::workspace::names_match;

#[test]
fn ascii_case_is_ignored() {
    assert!(names_match("Lab", "lab"));
    assert!(names_match("LAB gateway", "lab GATEWAY"));
    assert!(names_match("", ""));
}

#[test]
fn case_is_ignored_beyond_ascii() {
    assert!(names_match("Café", "CAFÉ"));
    assert!(names_match("CAFÉ", "café"));
    assert!(names_match("Ünïcödé", "üNÏCÖDÉ"));
    assert!(names_match("ΑΘΗΝΑ", "αθηνα"));
}

#[test]
fn different_names_do_not_match() {
    assert!(!names_match("Café", "Cafe"));
    assert!(!names_match("Lab", "Lab "));
    assert!(!names_match("Lab", "Labs"));
    // Lowercasing only: no wider case folding.
    assert!(!names_match("straße", "STRASSE"));
}
