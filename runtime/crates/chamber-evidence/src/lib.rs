//! Evidence for one detonation run.
//!
//! The governing property of this crate: **a verdict is derived from
//! observations, never asserted by a caller.** No constructor, no setter and no
//! decode path accepts a verdict as an input, and opening a bundle re-derives
//! the verdict from the ledger rather than trusting the field it finds there.
//!
//! The consequence is deliberate: this crate can report that something
//! misbehaved. It cannot report that something is safe. There is no verdict
//! meaning "clean", and an absence of findings is always reported alongside the
//! set of channels that were not watched — so it can never be read as a
//! certificate.

pub mod bundle;
pub mod coverage;
pub mod gaps;
pub mod ledger;
pub mod seal;
pub mod verdict;

pub use bundle::{DecodeRefusal, OpenedBundle, RunEnding, SCHEMA, SealedBundle, open, seal_run};
pub use coverage::{
    Channel, ChannelCoverage, CoverageDefect, CoverageGap, CoverageMap, GapCause, RawCoverageMap,
};
pub use ledger::{
    CanaryHit, CapturedBody, Digest32, HitEncoding, HitField, InferenceUsage, Ledger, Observation,
    ObservationKind, Ordinal, RunLog,
};
pub use seal::{
    BundleSeal, EntropyUnavailable, KeyIdError, PUBLIC_KEY_LEN, RunKeyId, RunSecret, SIGNATURE_LEN,
    SealError, encode_run_key_id, verify_sealed_bundle,
};
pub use verdict::Verdict;

/// Lowercase hex for byte strings on the wire.
///
/// Captured bodies are arbitrary bytes and are frequently not valid UTF-8, so
/// they cannot go out as JSON strings; an array of numbers would be unreadable
/// in an artefact whose purpose is to be inspected by someone who did not run
/// it.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(&text).map_err(D::Error::custom)
    }
}
