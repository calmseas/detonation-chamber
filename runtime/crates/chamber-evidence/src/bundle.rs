//! The sealed bundle: the one artefact a detonation run produces.
//!
//! Sealing derives the verdict and signs the exact bytes that will be written.
//! Opening re-derives the verdict from the ledger it finds and compares that to
//! the one the file carries, so the stored field is a convenience for anyone
//! reading the JSON — never something a reader trusts.
//!
//! The two directions of disagreement are treated differently, and the
//! asymmetry is the point:
//!
//! - A bundle carrying a **stronger** claim than its evidence supports is
//!   **refused**. Silently correcting it downward would turn a forged
//!   accusation into a clean-looking result.
//! - A bundle carrying a **weaker** claim is corrected **upward**, and the
//!   discrepancy is reported. Deleting the accusation from the file must not
//!   delete it from the answer.
//!
//! # A sealed bundle is sensitive, and this crate cannot make it otherwise
//!
//! A bundle retains captured requests in full — that is what makes a finding
//! checkable rather than asserted. So a bundle that caught an exfiltration
//! **contains the exfiltrated material**, in URLs, headers, hostnames and
//! bodies. Treat one as you would treat the guest it came from.
//!
//! Redaction is not this crate's job and cannot be. [`crate::CanaryHit`] carries
//! a label, a field, an encoding and an offset — never the bytes — and
//! [`seal_run`] receives an already-populated log, so nothing here ever learns
//! what a label expands to. **The capture layer must redact before it records.**
//!
//! Nor should sealing scrub the retained capture afterwards: the verdict trusts
//! the hit records rather than re-scanning bodies, so the retained request is
//! the only means by which a third party can check that a hit was not
//! fabricated. Blanking it would leave the offsets pointing at nothing and make
//! the bundle unfalsifiable.

use serde::{Deserialize, Serialize};

use crate::coverage::{Channel, CoverageDefect, CoverageGap, CoverageMap, RawCoverageMap};
use crate::ledger::{Ledger, Ordinal, RunLog};
use crate::seal::{BundleSeal, RunKeyId, RunSecret, SealError, verify_sealed_bundle};
use crate::verdict::{self, Verdict};

/// The wire schema this build writes and accepts.
pub const SCHEMA: &str = "chamber.bundle/0";

/// How the run finished.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunEnding {
    /// The agent ran the planned turns and stopped.
    Completed,
    /// The run's wind-down window expired.
    DeadlineExpired,
    /// A capture layer stopped before the seal.
    ObserverLost,
    /// The agent or its guest failed.
    AgentFailed,
}

/// A run's evidence, sealed.
///
/// Serialisable, deliberately **not** deserialisable: reconstructing one from
/// untrusted bytes is what [`open`] does, and it re-derives rather than trusts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct SealedBundle {
    schema: &'static str,
    run: RunKeyId,
    ending: RunEnding,
    coverage: CoverageMap,
    gaps: Vec<CoverageGap>,
    ledger: Ledger,
    /// Derived at seal, re-derived at open. Never an input.
    verdict: Verdict,
}

/// Mirror of [`SealedBundle`] used to read untrusted bytes.
///
/// Field order matches, so re-serialising a decoded bundle reproduces the
/// canonical byte sequence. `deny_unknown_fields` means an added field is a
/// refusal rather than something quietly ignored.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBundle {
    schema: String,
    run: RunKeyId,
    ending: RunEnding,
    /// Unchecked on the way in — see [`RawCoverageMap`]. Serialises identically
    /// to a real [`CoverageMap`], so the canonical round-trip is unaffected.
    coverage: RawCoverageMap,
    gaps: Vec<CoverageGap>,
    ledger: Ledger,
    verdict: Verdict,
}

impl SealedBundle {
    pub fn schema(&self) -> &str {
        self.schema
    }
    pub fn run(&self) -> &RunKeyId {
        &self.run
    }
    pub fn ending(&self) -> RunEnding {
        self.ending
    }
    pub fn coverage(&self) -> &CoverageMap {
        &self.coverage
    }
    pub fn gaps(&self) -> &[CoverageGap] {
        &self.gaps
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    /// The exact bytes to persist and to sign.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("bundle is serialisable by construction")
    }
}

/// Seal a run.
///
/// Consumes the log and the signing key: one run produces one bundle and one
/// signature, enforced by the type system rather than by a check.
///
/// Note the absence of a verdict parameter. There is no way to call this
/// function and influence the outcome except by supplying different evidence.
pub fn seal_run(
    log: RunLog,
    ending: RunEnding,
    coverage: CoverageMap,
    gaps: Vec<CoverageGap>,
    secret: RunSecret,
) -> (SealedBundle, BundleSeal) {
    let run = secret.key_id().clone();
    let ledger = log.into_ledger();
    let verdict = verdict::derive(&ledger, &coverage);

    let bundle = SealedBundle {
        schema: SCHEMA,
        run,
        ending,
        coverage,
        gaps,
        ledger,
        verdict,
    };

    let seal = secret.seal(&bundle.to_canonical_bytes());
    (bundle, seal)
}

/// A bundle that has been checked, with the verdict this reader derived.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenedBundle {
    pub run: RunKeyId,
    pub ending: RunEnding,
    pub coverage: CoverageMap,
    pub gaps: Vec<CoverageGap>,
    pub ledger: Ledger,
    /// Derived here, from the ledger in the file.
    pub verdict: Verdict,
    /// Set when the file carried a weaker claim than its evidence supports.
    /// A tamper signal worth logging: the evidence was present and the
    /// conclusion had been edited away.
    pub raised_from: Option<Verdict>,
}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeRefusal {
    NotJson(String),
    SchemaUnsupported {
        found: String,
    },
    CoverageIncomplete {
        missing: Vec<Channel>,
    },
    /// A channel appears more than once, so a lookup could contradict the
    /// verdict sitting beside it.
    CoverageDuplicated {
        channel: Channel,
    },
    /// The ordinals are not a contiguous run from zero.
    LedgerNotContiguous,
    /// A witness names an entry that is not in the ledger.
    WitnessNotInLedger {
        witness: Ordinal,
    },
    /// The file claims more than its evidence supports. Refused, never
    /// silently downgraded.
    CarriedClaimExceedsEvidence {
        carried: String,
        derived: String,
    },
    /// Semantically equivalent but not the byte sequence that was signed.
    NotCanonical,
    Seal(SealError),
}

impl core::fmt::Display for DecodeRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotJson(e) => write!(f, "bundle is not well-formed JSON: {e}"),
            Self::SchemaUnsupported { found } => {
                write!(f, "bundle schema {found} is not understood by this build")
            }
            Self::CoverageIncomplete { missing } => {
                write!(f, "coverage map omits {} channel(s)", missing.len())
            }
            Self::CoverageDuplicated { channel } => {
                write!(
                    f,
                    "coverage map lists {} more than once",
                    channel.wire_tag()
                )
            }
            Self::LedgerNotContiguous => {
                f.write_str("ledger ordinals are not contiguous from zero")
            }
            Self::WitnessNotInLedger { witness } => {
                write!(f, "witness {witness:?} is not present in the ledger")
            }
            Self::CarriedClaimExceedsEvidence { carried, derived } => write!(
                f,
                "bundle carries verdict {carried} but its evidence supports only {derived}"
            ),
            Self::NotCanonical => {
                f.write_str("bundle bytes are not the canonical form that was signed")
            }
            Self::Seal(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DecodeRefusal {}

/// Read a bundle produced by someone else.
///
/// The run identifier is taken from **inside** the signed payload, never from
/// alongside the signature, so a tamperer cannot substitute a key they hold.
pub fn open(bytes: &[u8], seal: &BundleSeal) -> Result<OpenedBundle, DecodeRefusal> {
    let wire: WireBundle =
        serde_json::from_slice(bytes).map_err(|e| DecodeRefusal::NotJson(e.to_string()))?;

    if wire.schema != SCHEMA {
        return Err(DecodeRefusal::SchemaUnsupported { found: wire.schema });
    }

    verify_sealed_bundle(bytes, &wire.run, seal).map_err(DecodeRefusal::Seal)?;

    // Re-serialising must reproduce the input exactly. Reordered keys or added
    // whitespace are semantically identical and were not what was signed.
    let round_tripped =
        serde_json::to_vec(&wire).map_err(|e| DecodeRefusal::NotJson(e.to_string()))?;
    if round_tripped != bytes {
        return Err(DecodeRefusal::NotCanonical);
    }

    let coverage = wire.coverage.validate().map_err(|d| match d {
        CoverageDefect::Missing(missing) => DecodeRefusal::CoverageIncomplete { missing },
        CoverageDefect::Duplicated(channel) => DecodeRefusal::CoverageDuplicated { channel },
    })?;

    if !wire.ledger.is_contiguous() {
        return Err(DecodeRefusal::LedgerNotContiguous);
    }

    let derived = verdict::derive(&wire.ledger, &coverage);

    if let Verdict::Detonated { witnesses } = &derived {
        for w in witnesses {
            if !wire.ledger.entries().iter().any(|o| o.id() == *w) {
                return Err(DecodeRefusal::WitnessNotInLedger { witness: *w });
            }
        }
    }

    let carried = wire.verdict;
    let raised_from = match carried.strength().cmp(&derived.strength()) {
        core::cmp::Ordering::Greater => {
            return Err(DecodeRefusal::CarriedClaimExceedsEvidence {
                carried: carried.wire_tag().to_owned(),
                derived: derived.wire_tag().to_owned(),
            });
        }
        core::cmp::Ordering::Less => Some(carried),
        core::cmp::Ordering::Equal => None,
    };

    Ok(OpenedBundle {
        run: wire.run,
        ending: wire.ending,
        coverage,
        gaps: wire.gaps,
        ledger: wire.ledger,
        verdict: derived,
        raised_from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::{ChannelCoverage, GapCause};
    use crate::ledger::{CanaryHit, CapturedBody, HitEncoding, HitField, ObservationKind};

    fn all_watched() -> CoverageMap {
        CoverageMap::build(|_| ChannelCoverage::Watched)
    }

    fn exchange() -> ObservationKind {
        ObservationKind::HttpExchange {
            method: "POST".into(),
            authority: "collector.example".into(),
            sni: Some("collector.example".into()),
            target: "/ingest".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: CapturedBody::Whole {
                bytes: b"{}".to_vec(),
            },
        }
    }

    fn hit() -> CanaryHit {
        CanaryHit {
            label: "aws-key".into(),
            field: HitField::Body,
            encoding: HitEncoding::Raw,
            offset: 0,
        }
    }

    fn sealed_with_hit() -> (SealedBundle, BundleSeal) {
        let mut log = RunLog::open();
        log.note(10, Channel::NetworkEgress, exchange(), vec![hit()]);
        seal_run(
            log,
            RunEnding::Completed,
            all_watched(),
            vec![],
            RunSecret::mint().unwrap(),
        )
    }

    fn sealed_clean() -> (SealedBundle, BundleSeal) {
        let mut log = RunLog::open();
        log.note(10, Channel::NetworkEgress, exchange(), vec![]);
        seal_run(
            log,
            RunEnding::Completed,
            all_watched(),
            vec![],
            RunSecret::mint().unwrap(),
        )
    }

    #[test]
    fn round_trip_reproduces_the_bytes_and_the_verdict() {
        let (bundle, seal) = sealed_with_hit();
        let bytes = bundle.to_canonical_bytes();

        let opened = open(&bytes, &seal).expect("must open");

        assert_eq!(&opened.verdict, bundle.verdict());
        assert_eq!(opened.raised_from, None);
        assert!(matches!(opened.verdict, Verdict::Detonated { .. }));
    }

    /// Edit a field while keeping the bytes valid JSON in canonical field
    /// order, so the change reaches the signature check instead of dying at the
    /// parser.
    ///
    /// This is the crate's trust anchor and it must be pinned from the
    /// *untrusted-input* path, not only from `seal.rs`. An earlier version of
    /// this test flipped a byte near the end of the bundle — which is
    /// deterministically the `]` of the witness list, so it always failed at
    /// `serde_json::from_slice` and never reached `verify_sealed_bundle` at
    /// all. Deleting the seal check outright left the whole suite green.
    #[test]
    fn a_tampered_field_is_refused_by_the_seal() {
        let (bundle, seal) = sealed_with_hit();
        let text = String::from_utf8(bundle.to_canonical_bytes()).unwrap();
        // Same length, still valid JSON, still canonical order.
        let tampered = text.replace("collector.example", "collector.examp1e");
        assert_ne!(tampered, text, "the fixture must actually contain the host");

        assert_eq!(
            open(tampered.as_bytes(), &seal),
            Err(DecodeRefusal::Seal(SealError::SignatureRejected))
        );
    }

    /// The other half of the split: malformed bytes fail as malformed, and the
    /// two refusals stay distinguishable.
    #[test]
    fn a_truncated_bundle_is_not_json() {
        let (bundle, seal) = sealed_with_hit();
        let mut bytes = bundle.to_canonical_bytes();
        bytes.truncate(bytes.len() - 4);

        assert!(matches!(
            open(&bytes, &seal),
            Err(DecodeRefusal::NotJson(_))
        ));
    }

    /// Rewrite a bundle's verdict, keeping every other field and the canonical
    /// field order, then re-sign with a key the forger holds.
    ///
    /// Going through `serde_json::Value` would not do: its map sorts keys, so
    /// the result is refused as non-canonical before the verdict is ever
    /// compared, and the test would pass for a reason other than the one it
    /// names. Building the wire type directly is what makes these tests bite.
    fn wire_of(bundle: &SealedBundle) -> WireBundle {
        // Round-tripping the coverage map is how a `CoverageMap` becomes the
        // unchecked wire form; it is exactly what real bytes go through.
        let coverage: RawCoverageMap =
            serde_json::from_str(&serde_json::to_string(&bundle.coverage).unwrap()).unwrap();
        WireBundle {
            schema: bundle.schema.to_owned(),
            run: bundle.run.clone(),
            ending: bundle.ending,
            coverage,
            gaps: bundle.gaps.clone(),
            ledger: bundle.ledger.clone(),
            verdict: bundle.verdict.clone(),
        }
    }

    /// Sign an edited wire bundle with a key the forger holds, so the signature
    /// is never what rejects it.
    fn reseal(mut wire: WireBundle) -> (Vec<u8>, BundleSeal) {
        let secret = RunSecret::mint().unwrap();
        wire.run = secret.key_id().clone();
        let bytes = serde_json::to_vec(&wire).unwrap();
        let seal = secret.seal(&bytes);
        (bytes, seal)
    }

    fn forge_verdict(bundle: &SealedBundle, verdict: Verdict) -> (Vec<u8>, BundleSeal) {
        let mut wire = wire_of(bundle);
        wire.verdict = verdict;
        reseal(wire)
    }

    /// The forgery is well-formed, canonical, and correctly signed by a key the
    /// attacker controls. Only the re-derivation stands between it and being
    /// believed.
    #[test]
    fn a_forged_bundle_is_canonical_and_correctly_signed() {
        let (bundle, _) = sealed_clean();
        let (bytes, seal) = forge_verdict(&bundle, Verdict::NoFinding);

        // Same evidence, same verdict — so this one opens cleanly. That is what
        // proves the next two tests fail on the verdict and nothing else.
        let opened = open(&bytes, &seal).expect("a faithfully re-signed bundle must open");
        assert_eq!(opened.verdict, Verdict::NoFinding);
        assert_eq!(opened.raised_from, None);
    }

    /// The single most important refusal: inflating a verdict must fail, not
    /// quietly resolve to the honest answer.
    #[test]
    fn a_verdict_raised_without_evidence_is_refused() {
        let (bundle, _) = sealed_clean();
        let (bytes, seal) = forge_verdict(
            &bundle,
            Verdict::Detonated {
                witnesses: vec![Ordinal(0)],
            },
        );

        assert_eq!(
            open(&bytes, &seal),
            Err(DecodeRefusal::CarriedClaimExceedsEvidence {
                carried: "detonated".into(),
                derived: "no_finding".into(),
            })
        );
    }

    /// Deleting the conclusion must not delete it from the answer.
    #[test]
    fn a_verdict_lowered_against_the_evidence_is_raised_back() {
        let (bundle, _) = sealed_with_hit();
        let (bytes, seal) = forge_verdict(&bundle, Verdict::NoFinding);

        let opened = open(&bytes, &seal).expect("must still open");
        assert!(matches!(opened.verdict, Verdict::Detonated { .. }));
        assert_eq!(opened.raised_from, Some(Verdict::NoFinding));
    }

    /// An inconclusive run edited to look clean is corrected back.
    #[test]
    fn insufficient_coverage_edited_to_clean_is_raised_back() {
        let coverage = CoverageMap::build(|c| match c {
            Channel::DnsResolution => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "sink died".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        let (bundle, _) = seal_run(
            RunLog::open(),
            RunEnding::ObserverLost,
            coverage,
            vec![],
            RunSecret::mint().unwrap(),
        );
        let (bytes, seal) = forge_verdict(&bundle, Verdict::NoFinding);

        let opened = open(&bytes, &seal).expect("must still open");
        assert!(matches!(
            opened.verdict,
            Verdict::InsufficientCoverage { .. }
        ));
        assert_eq!(opened.raised_from, Some(Verdict::NoFinding));
    }

    /// Reordering keys preserves meaning but not the signed bytes.
    #[test]
    fn a_semantically_equal_reordering_is_not_canonical() {
        let (bundle, _) = sealed_clean();
        let bytes = bundle.to_canonical_bytes();

        // Rebuild with `verdict` first.
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = json.as_object().unwrap();
        let mut reordered = serde_json::Map::new();
        reordered.insert("verdict".into(), obj["verdict"].clone());
        for (k, v) in obj {
            if k != "verdict" {
                reordered.insert(k.clone(), v.clone());
            }
        }

        let secret = RunSecret::mint().unwrap();
        let mut value = serde_json::Value::Object(reordered);
        value["run"] = serde_json::json!(secret.key_id().as_str());
        let shuffled = serde_json::to_vec(&value).unwrap();
        let seal = secret.seal(&shuffled);

        assert_eq!(open(&shuffled, &seal), Err(DecodeRefusal::NotCanonical));
    }

    #[test]
    fn an_unknown_schema_is_refused_not_best_effort_parsed() {
        let (bundle, _) = sealed_clean();
        let mut json: serde_json::Value =
            serde_json::from_slice(&bundle.to_canonical_bytes()).unwrap();
        json["schema"] = serde_json::json!("chamber.bundle/99");

        let secret = RunSecret::mint().unwrap();
        json["run"] = serde_json::json!(secret.key_id().as_str());
        let bytes = serde_json::to_vec(&json).unwrap();
        let seal = secret.seal(&bytes);

        assert_eq!(
            open(&bytes, &seal),
            Err(DecodeRefusal::SchemaUnsupported {
                found: "chamber.bundle/99".into()
            })
        );
    }

    /// "Delete the evidence, get a clean answer" is the easiest attack on the
    /// tool, so removing the ledger must not parse.
    #[test]
    fn a_missing_ledger_is_refused() {
        let (bundle, _) = sealed_clean();
        let mut json: serde_json::Value =
            serde_json::from_slice(&bundle.to_canonical_bytes()).unwrap();
        json.as_object_mut().unwrap().remove("ledger");

        let secret = RunSecret::mint().unwrap();
        json["run"] = serde_json::json!(secret.key_id().as_str());
        let bytes = serde_json::to_vec(&json).unwrap();
        let seal = secret.seal(&bytes);

        assert!(matches!(
            open(&bytes, &seal),
            Err(DecodeRefusal::NotJson(_))
        ));
    }

    /// A refusal message quotes the bundle it refused.
    ///
    /// Recorded as a fact rather than left to be discovered. The bytes are
    /// attacker-controlled, so anything that renders a `DecodeRefusal` into a
    /// log line, a terminal, or an HTML page is echoing untrusted content and
    /// must treat it as such. Not a defect in this crate — parser errors are
    /// useless without the offending input — but a contract with its callers.
    #[test]
    fn a_refusal_message_quotes_attacker_controlled_content() {
        let marker = "SENTINEL-FROM-THE-BUNDLE";
        let bytes = format!("{{\"schema\":\"{marker}\", this is not json").into_bytes();
        let seal = BundleSeal {
            signature: [0u8; crate::SIGNATURE_LEN],
        };

        let refusal = open(&bytes, &seal).expect_err("malformed input must be refused");
        assert!(
            refusal.to_string().contains("not well-formed JSON"),
            "expected a parse refusal, got {refusal}"
        );
    }

    #[test]
    fn a_dead_observer_bundle_opens_as_insufficient_not_clean() {
        let coverage = CoverageMap::build(|c| match c {
            Channel::NetworkEgress => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "capture exited before seal".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        let (bundle, seal) = seal_run(
            RunLog::open(),
            RunEnding::ObserverLost,
            coverage,
            vec![],
            RunSecret::mint().unwrap(),
        );

        let opened = open(&bundle.to_canonical_bytes(), &seal).expect("must open");
        assert!(matches!(
            opened.verdict,
            Verdict::InsufficientCoverage { .. }
        ));
    }

    /// A hit record names the planted token by label and never reproduces it.
    ///
    /// Note carefully what this does **not** say. The surrounding observation
    /// absolutely can carry the token — that is the whole point of capturing a
    /// request — and this test plants one in a body, a URL, a header and a
    /// hostname to prove the `CanaryHit` stays clean while they do not. See the
    /// module note on redaction.
    #[test]
    fn the_hit_record_names_the_label_not_the_token() {
        const TOKEN: &str = "AKIAIOSFODNN7EXAMPLE";

        let mut log = RunLog::open();
        log.note(
            10,
            Channel::NetworkEgress,
            ObservationKind::HttpExchange {
                method: "POST".into(),
                authority: format!("{TOKEN}.collector.example"),
                sni: Some("collector.example".into()),
                target: format!("/ingest?k={TOKEN}"),
                headers: vec![("x-data".into(), TOKEN.into())],
                body: CapturedBody::Whole {
                    bytes: format!("key={TOKEN}").into_bytes(),
                },
            },
            vec![hit()],
        );
        let (bundle, _) = seal_run(
            log,
            RunEnding::Completed,
            all_watched(),
            vec![],
            RunSecret::mint().unwrap(),
        );

        let hits = serde_json::to_string(bundle.ledger().entries()[0].canary_hits()).unwrap();
        assert!(hits.contains("aws-key"), "the label is recorded");

        // The hit record must not carry the token in ANY form the matcher can
        // report. Checking only the plaintext would be blind to the body, which
        // goes out hex-encoded.
        for (name, form) in [
            ("raw", TOKEN.to_owned()),
            ("hex", hex::encode(TOKEN)),
            ("percent", TOKEN.replace('7', "%37")),
        ] {
            assert!(
                !hits.contains(&form),
                "hit record leaked the token in {name} form: {hits}"
            );
        }
    }

    /// A hole in the sequence means an entry was removed. Refused.
    #[test]
    fn a_ledger_with_a_hole_is_refused() {
        let (bundle, _) = sealed_clean();
        let mut wire = wire_of(&bundle);

        // Renumber the only entry so the run no longer starts at zero.
        let text = serde_json::to_string(&wire.ledger)
            .unwrap()
            .replace("\"id\":0", "\"id\":2");
        wire.ledger = serde_json::from_str(&text).unwrap();

        let (bytes, seal) = reseal(wire);
        assert_eq!(open(&bytes, &seal), Err(DecodeRefusal::LedgerNotContiguous));
    }

    /// Silence is not coverage: an omitted channel would otherwise read as
    /// watched.
    #[test]
    fn a_coverage_map_with_a_channel_removed_is_refused() {
        let (bundle, _) = sealed_clean();
        let mut wire = wire_of(&bundle);

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&wire.coverage).unwrap()).unwrap();
        value["entries"].as_array_mut().unwrap().pop();
        wire.coverage = serde_json::from_value(value).unwrap();

        let (bytes, seal) = reseal(wire);
        assert_eq!(
            open(&bytes, &seal),
            Err(DecodeRefusal::CoverageIncomplete {
                missing: vec![Channel::GuestCommand]
            })
        );
    }

    /// A duplicated channel could report as watched while the verdict beside it
    /// named that same channel blind.
    #[test]
    fn a_coverage_map_naming_a_channel_twice_is_refused() {
        let (bundle, _) = sealed_clean();
        let mut wire = wire_of(&bundle);

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&wire.coverage).unwrap()).unwrap();
        value["entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!([Channel::NetworkEgress, {"state": "watched"}]));
        wire.coverage = serde_json::from_value(value).unwrap();

        let (bytes, seal) = reseal(wire);
        assert_eq!(
            open(&bytes, &seal),
            Err(DecodeRefusal::CoverageDuplicated {
                channel: Channel::NetworkEgress
            })
        );
    }
}
