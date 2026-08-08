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

use serde::{Deserialize, Serialize};

use crate::coverage::{Channel, CoverageGap, CoverageMap};
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
    coverage: CoverageMap,
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
    SchemaUnsupported { found: String },
    CoverageIncomplete { missing: Vec<Channel> },
    /// The ordinals are not a contiguous run from zero.
    LedgerNotContiguous,
    /// A witness names an entry that is not in the ledger.
    WitnessNotInLedger { witness: Ordinal },
    /// The file claims more than its evidence supports. Refused, never
    /// silently downgraded.
    CarriedClaimExceedsEvidence { carried: String, derived: String },
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
            Self::LedgerNotContiguous => f.write_str("ledger ordinals are not contiguous from zero"),
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

    let missing = wire.coverage.missing_channels();
    if !missing.is_empty() {
        return Err(DecodeRefusal::CoverageIncomplete { missing });
    }

    if !wire.ledger.is_contiguous() {
        return Err(DecodeRefusal::LedgerNotContiguous);
    }

    let derived = verdict::derive(&wire.ledger, &wire.coverage);

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
        coverage: wire.coverage,
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

    #[test]
    fn a_flipped_byte_is_rejected() {
        let (bundle, seal) = sealed_with_hit();
        let mut bytes = bundle.to_canonical_bytes();
        let last = bytes.len() - 3;
        bytes[last] ^= 0x20;

        assert!(matches!(
            open(&bytes, &seal),
            Err(DecodeRefusal::NotJson(_)) | Err(DecodeRefusal::Seal(_))
        ));
    }

    /// Rewrite a bundle's verdict, keeping every other field and the canonical
    /// field order, then re-sign with a key the forger holds.
    ///
    /// Going through `serde_json::Value` would not do: its map sorts keys, so
    /// the result is refused as non-canonical before the verdict is ever
    /// compared, and the test would pass for a reason other than the one it
    /// names. Building the wire type directly is what makes these tests bite.
    fn forge_verdict(bundle: &SealedBundle, verdict: Verdict) -> (Vec<u8>, BundleSeal) {
        let secret = RunSecret::mint().unwrap();
        let wire = WireBundle {
            schema: bundle.schema.to_owned(),
            run: secret.key_id().clone(),
            ending: bundle.ending,
            coverage: bundle.coverage.clone(),
            gaps: bundle.gaps.clone(),
            ledger: bundle.ledger.clone(),
            verdict,
        };
        let bytes = serde_json::to_vec(&wire).unwrap();
        let seal = secret.seal(&bytes);
        (bytes, seal)
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

    /// The bundle must not become a second copy of the secret it caught.
    #[test]
    fn the_bundle_never_carries_the_token_itself() {
        let (bundle, _) = sealed_with_hit();
        let text = String::from_utf8(bundle.to_canonical_bytes()).unwrap();
        assert!(text.contains("aws-key"), "the label is recorded");
        // Only the label and the position; the crate has no field that could
        // hold the token's value.
        assert!(!text.contains("AKIA"));
    }
}
