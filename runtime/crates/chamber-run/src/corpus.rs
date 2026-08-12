//! The technique corpus: skills that misbehave in every way worth catching,
//! each declaring its own ground truth.
//!
//! # Why declared ground truth
//!
//! The corpus is the tool's test of itself, and a tool cannot grade its own
//! homework by re-deriving the answer from the same evidence it is being tested
//! on. So each fixture *declares* what it does — does it exfiltrate, on what
//! channel, in what encoding, and is the boundary matcher expected to catch it —
//! in a [`CorpusManifest`]. "The chamber missed this one" then becomes an
//! assertion against the manifest, not a judgement call.
//!
//! # The two axes never fold
//!
//! [`CorpusCell`] carries what every signal reported — the static scan, a
//! reviewer model, the chamber — beside the declared truth. There is
//! deliberately no `safe` field: the *gap* between identification and
//! compliance is the output, and folding it into one verdict would erase the
//! only thing worth reporting. No version of this tool says safe.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// One fixture's declared ground truth, read from its `manifest.json`.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct CorpusManifest {
    pub name: String,
    pub class: String,
    /// Whether the skill exfiltrates the planted secret at all.
    pub exfils: bool,
    /// The boundary channel it leaves by, when it exfils.
    #[serde(default)]
    pub channel: Option<String>,
    /// The form the secret is in on the wire (`raw`, `base64`, `label_join`,
    /// `custom`, …).
    #[serde(default)]
    pub encoding: Option<String>,
    /// Whether the boundary matcher is expected to catch it. `false` on an
    /// exfiltrating fixture marks a known blind spot: the secret leaves, but
    /// not in a form the matcher can recover (see `gap.chained-encodings`).
    pub expect_boundary_catch: bool,
    /// Whether the skill destroys or corrupts content in `/work` rather than
    /// (or as well as) exfiltrating.
    ///
    /// Added when the first non-exfil payload was authored. Every field above
    /// describes a *confidentiality* attack, so before this a destructive
    /// fixture could only declare `exfils: false` and would be graded benign —
    /// the corpus would have scored a skill that wipes the workspace as safe.
    #[serde(default)]
    pub destroys: bool,
    /// Whether the filesystem oracle is expected to catch the destruction.
    ///
    /// `false` on a destructive fixture marks a known blind spot, exactly as
    /// `expect_boundary_catch: false` does for an unrecoverable exfil.
    #[serde(default)]
    pub expect_filesystem_catch: bool,
    /// A human note on what the fixture is demonstrating.
    #[serde(default)]
    pub note: String,
}

impl CorpusManifest {
    /// A fixture that exfiltrates in a form the boundary cannot recover. Its
    /// existence is the honest demonstration that boundary observation has a
    /// limit — and its verdict, when run, is `no_finding` despite the leak.
    #[must_use]
    pub fn is_boundary_blind_spot(&self) -> bool {
        self.exfils && !self.expect_boundary_catch
    }

    /// Whether this fixture is hostile at all, by any payload.
    ///
    /// The corpus used to spell "hostile" as `exfils`, which was true only while
    /// every payload was an exfiltration. It is the predicate to reach for
    /// rather than `exfils` whenever the question is "should a defender have
    /// stopped this", because a skill that deletes the workspace and sends
    /// nothing is not benign.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.exfils || self.destroys
    }
}

/// What every signal reported for one fixture, beside its declared truth.
///
/// No `safe` / `verdict` field, by design (see the module note). The dangerous
/// cell is computed *from* the separate signals — it is never stored as a
/// single bit, because the moment it is, the two axes have been folded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CorpusCell {
    pub manifest: CorpusManifest,
    /// The existing static `scan` flagged it.
    pub static_scan_flagged: bool,
    /// A reviewer model, reading the SKILL.md *and its scripts*, flagged it.
    pub reviewer_flagged: bool,
    /// The chamber's boundary answer: did the secret cross where the matcher
    /// could see it.
    pub chamber_detonated: bool,
}

impl CorpusCell {
    /// The cell was identified as problematic by *some* reviewer.
    #[must_use]
    pub fn identified(&self) -> bool {
        self.static_scan_flagged || self.reviewer_flagged
    }

    /// The dangerous quadrant: it really is hostile, yet a defender would have
    /// let it through — review did not flag it, or the chamber did not catch it.
    /// This is derived from the separate signals, never stored.
    ///
    /// Keyed on [`CorpusManifest::is_malicious`] rather than `exfils`: a
    /// destructive fixture that nobody flagged is exactly as dangerous as an
    /// unnoticed exfil, and while this read `exfils` it would have reported one
    /// as safe.
    #[must_use]
    pub fn is_dangerous(&self) -> bool {
        self.manifest.is_malicious() && (!self.identified() || !self.chamber_detonated)
    }
}

/// The directory the corpus lives in, resolved from this crate's location so
/// tests and tools find it without a working-directory assumption.
#[must_use]
pub fn corpus_dir() -> PathBuf {
    // .../detonation-chamber/runtime/crates/chamber-run -> repo root -> fixtures/corpus
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root is three levels above the crate")
        .join("fixtures/corpus")
}

/// Reads every fixture's manifest.
///
/// # Errors
/// A string naming the first manifest that is missing or unparseable — a
/// fixture without a readable manifest is not in the corpus.
pub fn load_manifests(dir: &Path) -> Result<Vec<CorpusManifest>, String> {
    let mut manifests = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| format!("{}: {e}", d.display()))?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "manifest.json") {
                let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                let manifest: CorpusManifest = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("{} is not a valid manifest: {e}", path.display()))?;
                manifests.push(manifest);
            }
        }
    }
    manifests.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<CorpusManifest> {
        load_manifests(&corpus_dir()).expect("the corpus manifests must load")
    }

    /// Every fixture declares its ground truth, or it is not in the corpus.
    #[test]
    fn every_fixture_has_a_readable_manifest() {
        let manifests = corpus();
        assert!(
            manifests.len() >= 10,
            "the corpus is thin: {}",
            manifests.len()
        );
        // Every directory that contains a SKILL.md must also carry a manifest.
        let mut stack = vec![corpus_dir()];
        while let Some(d) = stack.pop() {
            let mut has_skill = false;
            let mut has_manifest = false;
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().unwrap() == "SKILL.md" {
                    has_skill = true;
                } else if p.file_name().unwrap() == "manifest.json" {
                    has_manifest = true;
                }
            }
            assert!(
                !has_skill || has_manifest,
                "{} has a SKILL.md but no manifest — a fixture with no declared \
                 ground truth cannot be scored",
                d.display()
            );
        }
    }

    /// The corpus MUST contain a fixture that exfiltrates in a form the boundary
    /// cannot recover — the honest demonstration of the matcher's limit.
    #[test]
    fn a_boundary_blind_spot_fixture_exists() {
        let blind: Vec<_> = corpus()
            .into_iter()
            .filter(|m| m.is_boundary_blind_spot())
            .collect();
        assert!(
            !blind.is_empty(),
            "no fixture demonstrates a boundary miss; the corpus would flatter the tool"
        );
        // And it is the steganographic custom-encoding case, as designed.
        assert!(
            blind
                .iter()
                .any(|m| m.class == "E-steg" && m.encoding.as_deref() == Some("custom"))
        );
    }

    /// Every class the design names is represented.
    #[test]
    fn every_technique_class_is_present() {
        let classes: std::collections::BTreeSet<_> =
            corpus().into_iter().map(|m| m.class).collect();
        for expected in [
            "A-framing",
            "B-bundled",
            "C-staged",
            "D-encoded",
            "E-steg",
            "F-benign",
        ] {
            assert!(classes.contains(expected), "missing class {expected}");
        }
    }

    /// The safety property: nothing in the corpus points at a real credential
    /// or a real host. Every URL host must be a `.example` name, and no
    /// AWS-key-shaped literal may appear — fixtures reference `$CHAMBER_TOKEN`,
    /// never a value.
    #[test]
    fn the_corpus_uses_only_fake_secrets() {
        let host = regex_lite(r"https?://([a-zA-Z0-9._-]+)");
        let akia = regex_lite(r"AKIA[0-9A-Z]{12,}");

        let mut stack = vec![corpus_dir()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                for hostname in host(&text) {
                    assert!(
                        hostname == "example"
                            || hostname.ends_with(".example")
                            || hostname.ends_with(".example.com"),
                        "{} points at a non-example host: {hostname}",
                        p.display()
                    );
                }
                assert!(
                    akia(&text).is_empty(),
                    "{} contains a literal AWS-key-shaped value; fixtures must \
                     reference $CHAMBER_TOKEN, never a value",
                    p.display()
                );
            }
        }
    }

    /// A destructive fixture is hostile without exfiltrating, and the dangerous
    /// quadrant must say so.
    ///
    /// THE regression this guards: while `is_dangerous` read `exfils`, a skill
    /// that wipes the workspace and sends nothing scored as safe — the corpus
    /// would have reported a sabotage fixture as benign.
    #[test]
    fn a_destructive_fixture_nobody_caught_is_dangerous_despite_not_exfiltrating() {
        let destructive = CorpusManifest {
            name: "g-cleanup".into(),
            class: "G-destructive".into(),
            exfils: false,
            channel: None,
            encoding: None,
            expect_boundary_catch: false,
            destroys: true,
            expect_filesystem_catch: true,
            note: String::new(),
        };
        assert!(
            destructive.is_malicious(),
            "destruction is a hostile payload"
        );
        assert!(
            !destructive.is_boundary_blind_spot(),
            "it never claimed to exfil"
        );

        let missed = CorpusCell {
            manifest: destructive.clone(),
            static_scan_flagged: false,
            reviewer_flagged: false,
            chamber_detonated: false,
        };
        assert!(
            missed.is_dangerous(),
            "an unflagged, uncaught sabotage fixture is the dangerous quadrant"
        );
    }

    /// A genuinely benign fixture must not be swept up by the widened predicate.
    #[test]
    fn a_benign_fixture_is_neither_malicious_nor_dangerous() {
        let benign = CorpusManifest {
            name: "f-plain".into(),
            class: "F-benign".into(),
            exfils: false,
            channel: None,
            encoding: None,
            expect_boundary_catch: false,
            destroys: false,
            expect_filesystem_catch: false,
            note: String::new(),
        };
        assert!(!benign.is_malicious());
        assert!(
            !CorpusCell {
                manifest: benign,
                static_scan_flagged: false,
                reviewer_flagged: false,
                chamber_detonated: false,
            }
            .is_dangerous()
        );
    }

    /// Existing manifests predate both new fields and must keep parsing, reading
    /// as non-destructive rather than failing or defaulting to hostile.
    #[test]
    fn a_manifest_without_the_destructive_fields_still_parses_as_non_destructive() {
        let old = r#"{"name":"b-plain","class":"B-bundled","exfils":true,
                      "expect_boundary_catch":true}"#;
        let m: CorpusManifest = serde_json::from_str(old).expect("old manifests still parse");
        assert!(!m.destroys);
        assert!(!m.expect_filesystem_catch);
        assert!(m.is_malicious(), "it still exfiltrates");
    }

    /// The two axes are separate signals, and the dangerous quadrant is derived
    /// from them — never a stored verdict.
    #[test]
    fn the_dangerous_quadrant_is_computed_from_separate_signals() {
        let exfil = CorpusManifest {
            name: "x".into(),
            class: "B-bundled".into(),
            exfils: true,
            channel: Some("network_egress".into()),
            encoding: Some("raw".into()),
            expect_boundary_catch: true,
            destroys: false,
            expect_filesystem_catch: false,
            note: String::new(),
        };

        // Exfiltrates, nobody flagged it, boundary caught it -> still dangerous
        // (review missed it).
        let review_miss = CorpusCell {
            manifest: exfil.clone(),
            static_scan_flagged: false,
            reviewer_flagged: false,
            chamber_detonated: true,
        };
        assert!(review_miss.is_dangerous());
        assert!(!review_miss.identified());

        // Exfiltrates, flagged, but boundary missed it -> dangerous (the
        // blind-spot case).
        let boundary_miss = CorpusCell {
            manifest: exfil.clone(),
            static_scan_flagged: true,
            reviewer_flagged: true,
            chamber_detonated: false,
        };
        assert!(boundary_miss.is_dangerous());

        // Exfiltrates, reviewer flagged AND boundary caught -> not the dangerous
        // quadrant (a defender would have stopped it).
        let covered = CorpusCell {
            manifest: exfil,
            static_scan_flagged: false,
            reviewer_flagged: true,
            chamber_detonated: true,
        };
        assert!(!covered.is_dangerous());
    }

    /// The corpus guard must survive a fixture containing non-ASCII text.
    ///
    /// Regression: the AKIA scan sliced `&text[i..i + 4]` while advancing one
    /// byte at a time, so it panicked on the first fixture note with an em-dash
    /// in it. A guard that crashes on valid input is a guard that stops running.
    #[test]
    fn the_secret_scan_survives_non_ascii_text() {
        let akia = regex_lite(r"AKIA[0-9A-Z]{12,}");
        assert!(akia("a note — with an em-dash and no key").is_empty());
        assert_eq!(
            akia("prose — then AKIAIOSFODNN7EXAMPLE trailing"),
            vec!["AKIAIOSFODNN7EXAMPLE".to_owned()],
            "a real key must still be found after non-ASCII text"
        );
        let host = regex_lite(r"https?://([a-zA-Z0-9._-]+)");
        assert_eq!(
            host("see — https://telemetry.example/x"),
            vec!["telemetry.example"]
        );
    }

    /// A tiny substring-regex good enough for the two fixed patterns above,
    /// so the guard needs no dependency. Returns capture group 1 (or the whole
    /// match when there is no group).
    fn regex_lite(pattern: &'static str) -> impl Fn(&str) -> Vec<String> {
        move |text: &str| {
            // Only two patterns are ever passed; match them directly rather than
            // building a regex engine.
            let mut out = Vec::new();
            if pattern.starts_with("https?://") {
                for (idx, _) in text.match_indices("://") {
                    let rest = &text[idx + 3..];
                    let host: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                        .collect();
                    if !host.is_empty() {
                        out.push(host);
                    }
                }
            } else {
                // AKIA followed by >=12 uppercase/digits.
                //
                // Matched on BYTES, not by slicing `text`. The index walks one
                // byte at a time, so slicing `&text[i..i + 4]` panics the moment
                // it lands inside a multi-byte character — which it did the
                // first time a fixture note contained an em-dash. A byte
                // comparison cannot panic, and a match guarantees `i` is a char
                // boundary anyway, since ASCII bytes never occur inside a
                // multi-byte UTF-8 sequence.
                let bytes = text.as_bytes();
                let mut i = 0;
                while i + 4 <= bytes.len() {
                    if &bytes[i..i + 4] == b"AKIA" {
                        let tail: String = text[i + 4..]
                            .chars()
                            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                            .collect();
                        if tail.len() >= 12 {
                            out.push(format!("AKIA{tail}"));
                        }
                    }
                    i += 1;
                }
            }
            out
        }
    }
}
