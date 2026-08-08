//! Run identity and the signature over a sealed bundle.
//!
//! Each detonation run mints one keypair, places exactly one signature with
//! it, and throws it away. The identity ties one bundle to one execution and
//! nothing more — it names no long-lived party, so there is no revocation
//! story and nothing to rotate.
//!
//! Two properties carry the weight here.
//!
//! The secret must be unreachable. It comes from the operating system's
//! entropy source, stays in this process's memory, and has no route to a file,
//! a log line, an error, or a `Debug` rendering. That last one is easy to lose
//! by accident: structured logging prints whatever it is given, so deriving
//! `Debug` on a type carrying key material is enough to put that material into
//! every log sink as soon as somebody adds it to a trace call.
//!
//! The published identifier must be sufficient on its own to check a
//! signature. The identifier *is* the key: decoding the string yields the
//! verifying bytes, so someone holding only the bundle file and this string
//! can confirm authorship offline — no registry, no network, no clock.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// Raw ed25519 public key length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Raw ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;

/// The `did:key` method prefix this crate emits and accepts.
const METHOD_PREFIX: &str = "did:key:";

/// Unsigned-varint encoding of the multicodec code for an ed25519 public key.
///
/// Two bytes, and that is the entire hazard. The code is 0xed, but multicodec
/// prefixes are varints, so 0xed alone is an unterminated first byte. Writing
/// one byte still base58-encodes without complaint and yields a plausible
/// identifier with a different leading fragment — a wrong answer that looks
/// exactly like a right one. `one_byte_multicodec_prefix_is_loud` exists to
/// keep that mistake noisy.
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Stand-in printed where the secret would otherwise appear.
const REDACTION_PLACEHOLDER: &str = "<sealed>";

/// A run's public identifier: a `did:key` string over the ed25519 public key.
///
/// Canonical by construction — one key encodes to exactly one string — so two
/// identifiers may be compared as strings without a normalisation pass.
#[derive(Clone, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct RunKeyId(String);

impl RunKeyId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Recover the verifying key from the identifier.
    ///
    /// This is a pure string-to-bytes decode. It is the only resolution step
    /// anywhere in this crate, and it consults nothing outside its argument.
    pub fn public_key_bytes(&self) -> Result<[u8; PUBLIC_KEY_LEN], KeyIdError> {
        let body = self
            .0
            .strip_prefix(METHOD_PREFIX)
            .ok_or(KeyIdError::MissingMethodPrefix)?;

        let (base, bytes) =
            multibase::decode(body).map_err(|_| KeyIdError::UnsupportedMultibase)?;
        if base != multibase::Base::Base58Btc {
            return Err(KeyIdError::UnsupportedMultibase);
        }

        let rest = bytes
            .strip_prefix(&ED25519_PUB_MULTICODEC[..])
            .ok_or(KeyIdError::UnsupportedMulticodec)?;

        let raw: [u8; PUBLIC_KEY_LEN] = rest
            .try_into()
            .map_err(|_| KeyIdError::WrongKeyLength { found: rest.len() })?;

        // A well-formed length is not a well-formed key. Reject here, so a
        // malformed identifier fails at the identifier rather than surfacing
        // later as a confusing signature rejection.
        //
        // Both checks are needed, and the order matters. `from_bytes` alone is
        // not enough: it accepts a y coordinate that is not reduced mod p and
        // silently reduces it, so two different identifiers would decode to the
        // same key and the "one key, one string" property would be false.
        if !is_canonical_field_element(&raw) {
            return Err(KeyIdError::NonCanonicalPublicKey);
        }
        VerifyingKey::from_bytes(&raw).map_err(|_| KeyIdError::NonCanonicalPublicKey)?;

        Ok(raw)
    }
}

impl fmt::Display for RunKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for RunKeyId {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let candidate = RunKeyId(s.to_owned());
        // Parsing that accepts a string it cannot decode would hand the caller
        // an identifier that fails much later, at verification.
        candidate.public_key_bytes()?;
        Ok(candidate)
    }
}

/// Is this point encoding reduced mod p?
///
/// An ed25519 public key is the little-endian y coordinate with the top bit
/// carrying the sign of x. A y that is not less than p = 2^255 - 19 is a
/// non-canonical encoding of a point that also has a canonical one, so
/// accepting it would let two identifiers name the same key.
fn is_canonical_field_element(raw: &[u8; PUBLIC_KEY_LEN]) -> bool {
    // p in little-endian bytes.
    const P_LE: [u8; PUBLIC_KEY_LEN] = {
        let mut p = [0xffu8; PUBLIC_KEY_LEN];
        p[0] = 0xed;
        p[PUBLIC_KEY_LEN - 1] = 0x7f;
        p
    };

    let mut y = *raw;
    y[PUBLIC_KEY_LEN - 1] &= 0x7f; // drop the sign bit; it is not part of y

    // Compare as big integers, most significant byte first.
    for i in (0..PUBLIC_KEY_LEN).rev() {
        if y[i] != P_LE[i] {
            return y[i] < P_LE[i];
        }
    }
    // Exactly p is itself non-canonical (it encodes zero).
    false
}

/// Encode a raw public key as its canonical identifier.
///
/// Deterministic and infallible; the published encoding vectors assert against
/// this function directly.
pub fn encode_run_key_id(public_key: &[u8; PUBLIC_KEY_LEN]) -> RunKeyId {
    let mut payload = Vec::with_capacity(ED25519_PUB_MULTICODEC.len() + PUBLIC_KEY_LEN);
    payload.extend_from_slice(&ED25519_PUB_MULTICODEC);
    payload.extend_from_slice(public_key);

    // `multibase::encode` contributes the base-58 marker itself. Prepending
    // another produces a well-formed string for a different key.
    let encoded = multibase::encode(multibase::Base::Base58Btc, payload);
    RunKeyId(format!("{METHOD_PREFIX}{encoded}"))
}

/// A run's signing key.
///
/// Deliberately not `Clone`, not `Copy`, not serialisable, and not printable
/// beyond its public identifier.
pub struct RunSecret {
    /// Holds the seed and zeroes it on drop. There is deliberately no second
    /// copy of the secret anywhere in this struct.
    signing: SigningKey,
    key_id: RunKeyId,
}

impl RunSecret {
    /// Mint a fresh key from the operating system's entropy source.
    ///
    /// There is deliberately no constructor that accepts a seed. One would be
    /// the route by which a fixture key, an environment variable, or a config
    /// file becomes the key that signs real evidence.
    pub fn mint() -> Result<Self, EntropyUnavailable> {
        let mut seed = Zeroizing::new([0u8; PUBLIC_KEY_LEN]);
        getrandom::fill(seed.as_mut()).map_err(|_| EntropyUnavailable)?;

        // `seed` is zeroed when it drops at the end of this function; the
        // signing key keeps the only remaining copy.
        let signing = SigningKey::from_bytes(&seed);
        // Derived once, here, and cached. Deriving it again at each use invites
        // the two derivations drifting apart, which surfaces as a bundle that
        // verifies against nothing — and surfaces at a third party, not here.
        let key_id = encode_run_key_id(&signing.verifying_key().to_bytes());

        Ok(Self { signing, key_id })
    }

    pub fn key_id(&self) -> &RunKeyId {
        &self.key_id
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign the bundle's persisted bytes, consuming the key.
    ///
    /// Taking `self` by value makes a second signature a compile error rather
    /// than a runtime check: one run, one bundle, one signature.
    ///
    /// The argument is the exact byte sequence that will be written. Signing a
    /// typed value and re-serialising it later admits ordering and formatting
    /// drift between what was signed and what is stored.
    pub fn seal(self, bundle_bytes: &[u8]) -> BundleSeal {
        BundleSeal {
            signature: self.signing.sign(bundle_bytes).to_bytes(),
        }
    }

    /// The real seed, for leak assertions.
    ///
    /// This must stay a `cfg(test)` item compiled inside this crate. An
    /// integration test under `tests/` links the library without `cfg(test)`,
    /// so the accessor would not exist there and the leak test would get
    /// rewritten to assert on something derived — which cannot fail, and so
    /// would pass forever while the seed was written out beside it.
    #[cfg(test)]
    pub(crate) fn seed_for_leak_tests(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.to_bytes()
    }
}

impl fmt::Debug for RunSecret {
    /// Hand-written, and it must stay hand-written.
    ///
    /// Prints the public identifier, which is what makes a run diagnosable,
    /// and a fixed placeholder where the key would be. A `Debug` that printed
    /// nothing would satisfy a leak test that only checks for absence while
    /// destroying the diagnostic value, so the test pins both halves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunSecret")
            .field("key_id", &self.key_id.as_str())
            .field("secret", &REDACTION_PLACEHOLDER)
            .finish()
    }
}

/// A detached signature over a bundle's persisted bytes.
///
/// It carries no identifier. A signature that travelled with its own claim of
/// authorship would let a tamperer swap in a key they hold and re-sign; the
/// identifier is read from the signed payload instead, where editing it breaks
/// the signature.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BundleSeal {
    #[serde(with = "hex_signature")]
    pub signature: [u8; SIGNATURE_LEN],
}

/// Lowercase hex on the wire.
///
/// serde has no array impl at this length, and a 64-element array of JSON
/// numbers would be unreadable in an artefact whose whole purpose is to be
/// inspected by someone who did not run it.
mod hex_signature {
    use super::SIGNATURE_LEN;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8; SIGNATURE_LEN], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; SIGNATURE_LEN], D::Error> {
        let text = String::deserialize(d)?;
        let raw = hex::decode(&text).map_err(D::Error::custom)?;
        raw.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!(
                "signature is {} bytes, expected {SIGNATURE_LEN}",
                v.len()
            ))
        })
    }
}

/// Check a bundle's signature.
///
/// Pure: no I/O, no clock, no resolution. `claimed_by` must come from inside
/// the signed payload. There is deliberately no two-argument form, because one
/// would recover the key from data the attacker supplies alongside the
/// signature and would then be self-consistent for any key they chose.
pub fn verify_sealed_bundle(
    bundle_bytes: &[u8],
    claimed_by: &RunKeyId,
    seal: &BundleSeal,
) -> Result<(), SealError> {
    let raw = claimed_by.public_key_bytes().map_err(SealError::KeyId)?;
    let verifying = VerifyingKey::from_bytes(&raw).map_err(|_| SealError::SignatureRejected)?;
    let signature = Signature::from_bytes(&seal.signature);

    verifying
        .verify_strict(bundle_bytes, &signature)
        .map_err(|_| SealError::SignatureRejected)
}

/// The OS entropy source was unavailable.
///
/// Carries no detail: there is nothing a caller can do differently, and an
/// error type near key generation is a place secrets leak into logs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EntropyUnavailable;

impl fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operating system entropy source unavailable")
    }
}

impl std::error::Error for EntropyUnavailable {}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeyIdError {
    MissingMethodPrefix,
    UnsupportedMultibase,
    UnsupportedMulticodec,
    WrongKeyLength { found: usize },
    NonCanonicalPublicKey,
}

impl fmt::Display for KeyIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMethodPrefix => {
                f.write_str("identifier does not start with the did:key method prefix")
            }
            Self::UnsupportedMultibase => f.write_str("identifier is not base58btc multibase"),
            Self::UnsupportedMulticodec => {
                f.write_str("identifier does not carry the ed25519 public key multicodec")
            }
            Self::WrongKeyLength { found } => write!(
                f,
                "identifier holds {found} key bytes, expected {PUBLIC_KEY_LEN}"
            ),
            Self::NonCanonicalPublicKey => {
                f.write_str("identifier does not decode to a valid ed25519 public key")
            }
        }
    }
}

impl std::error::Error for KeyIdError {}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SealError {
    KeyId(KeyIdError),
    SignatureRejected,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyId(e) => write!(f, "unusable run identifier: {e}"),
            Self::SignatureRejected => {
                f.write_str("signature does not verify against the claimed run identifier")
            }
        }
    }
}

impl std::error::Error for SealError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Published Ed25519 example from the W3C CCG `did:key` method spec.
    ///
    /// An external pin on the string format. A one-byte multicodec prefix, a
    /// doubled multibase marker, or a different base all fail to reproduce it.
    const W3C_DID_KEY_ED25519_EXAMPLE: &str =
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// RFC 8032 section 7.1, TEST 1.
    const RFC8032_T1_SEED: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_T1_PUBLIC: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_T1_MESSAGE: &str = "";
    const RFC8032_T1_SIGNATURE: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    /// RFC 8032 section 7.1, TEST 2.
    const RFC8032_T2_SEED: &str =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const RFC8032_T2_PUBLIC: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const RFC8032_T2_MESSAGE: &str = "72";
    const RFC8032_T2_SIGNATURE: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v = hex::decode(s).expect("test vector is valid hex");
        v.try_into().expect("test vector has the expected length")
    }

    /// Full-string equality, deliberately not a prefix check.
    ///
    /// `starts_with` passes under double-prefixing, which is one of the two
    /// mistakes this test exists to catch.
    #[test]
    fn key_id_matches_published_vector() {
        let id: RunKeyId = W3C_DID_KEY_ED25519_EXAMPLE
            .parse()
            .expect("published vector must decode");
        let raw = id.public_key_bytes().expect("published vector must decode");

        assert_eq!(raw.len(), PUBLIC_KEY_LEN);
        assert_eq!(
            encode_run_key_id(&raw).as_str(),
            W3C_DID_KEY_ED25519_EXAMPLE,
            "re-encoding the published identifier must reproduce it exactly"
        );
    }

    /// The highest-value test in the crate: it converts a silent, plausible
    /// wrong answer into a failure.
    #[test]
    fn one_byte_multicodec_prefix_is_loud() {
        let raw = unhex::<PUBLIC_KEY_LEN>(RFC8032_T1_PUBLIC);

        let correct = encode_run_key_id(&raw);

        let mut payload = vec![ED25519_PUB_MULTICODEC[0]];
        payload.extend_from_slice(&raw);
        let one_byte = format!(
            "{METHOD_PREFIX}{}",
            multibase::encode(multibase::Base::Base58Btc, payload)
        );

        assert_ne!(
            one_byte,
            correct.as_str(),
            "a one-byte prefix must not produce the canonical identifier"
        );
        // And it must not merely differ in the tail — the leading fragment is
        // what a human eyeballs, so pin that it changes too.
        assert_ne!(
            &one_byte[..METHOD_PREFIX.len() + 4],
            &correct.as_str()[..METHOD_PREFIX.len() + 4],
            "the mis-encoded form must be visibly different at the front"
        );
        // The decoder must refuse it rather than normalise it.
        assert_eq!(
            RunKeyId(one_byte).public_key_bytes(),
            Err(KeyIdError::UnsupportedMulticodec)
        );
    }

    /// Derivation alone would not catch an argument-order or domain-separation
    /// error in the signing path, so both vectors assert the full signature.
    #[test]
    fn rfc8032_derivation_and_signature() {
        for (seed_hex, public_hex, message_hex, signature_hex) in [
            (
                RFC8032_T1_SEED,
                RFC8032_T1_PUBLIC,
                RFC8032_T1_MESSAGE,
                RFC8032_T1_SIGNATURE,
            ),
            (
                RFC8032_T2_SEED,
                RFC8032_T2_PUBLIC,
                RFC8032_T2_MESSAGE,
                RFC8032_T2_SIGNATURE,
            ),
        ] {
            let seed = unhex::<PUBLIC_KEY_LEN>(seed_hex);
            let signing = SigningKey::from_bytes(&seed);

            assert_eq!(
                signing.verifying_key().to_bytes(),
                unhex::<PUBLIC_KEY_LEN>(public_hex),
                "public key derivation must match the published vector"
            );

            let message = hex::decode(message_hex).expect("vector message is hex");
            assert_eq!(
                signing.sign(&message).to_bytes(),
                unhex::<SIGNATURE_LEN>(signature_hex),
                "signature must match the published vector"
            );
        }
    }

    /// Pins both halves. Absence alone would be satisfied by a `Debug` that
    /// printed nothing.
    #[test]
    fn debug_redacts_both_directions() {
        let secret = RunSecret::mint().expect("entropy available under test");
        let rendered = format!("{secret:?}");

        assert!(
            rendered.contains(REDACTION_PLACEHOLDER),
            "the placeholder must be present: {rendered}"
        );
        assert!(
            rendered.contains(secret.key_id().as_str()),
            "the public identifier must survive redaction: {rendered}"
        );

        let seed = secret.seed_for_leak_tests();
        assert!(
            !rendered.contains(&hex::encode(seed)),
            "hex-encoded seed leaked into Debug"
        );
        assert!(
            !rendered.contains(&format!("{seed:?}")),
            "byte-array rendering of the seed leaked into Debug"
        );
    }

    /// The only test covering the production mint path.
    ///
    /// The RFC vectors prove derivation from a *fixed* seed and the W3C vector
    /// proves the encoder; neither shows that the identifier `mint` publishes
    /// actually corresponds to whatever key `seal` ends up signing with.
    #[test]
    fn mint_seal_verify_round_trip() {
        let secret = RunSecret::mint().expect("entropy available under test");
        let key_id = secret.key_id().clone();
        let bytes = b"{\"schema\":\"chamber.bundle/0\"}";

        let seal = secret.seal(bytes);

        assert_eq!(verify_sealed_bundle(bytes, &key_id, &seal), Ok(()));
    }

    #[test]
    fn flipped_byte_is_rejected() {
        let secret = RunSecret::mint().expect("entropy available under test");
        let key_id = secret.key_id().clone();
        let bytes = b"observation ledger".to_vec();
        let seal = secret.seal(&bytes);

        let mut tampered = bytes.clone();
        tampered[0] ^= 0x01;

        assert_eq!(
            verify_sealed_bundle(&tampered, &key_id, &seal),
            Err(SealError::SignatureRejected)
        );
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let a = RunSecret::mint().expect("entropy available under test");
        let b = RunSecret::mint().expect("entropy available under test");
        let impostor = b.key_id().clone();
        let bytes = b"observation ledger";

        let seal = a.seal(bytes);

        assert_eq!(
            verify_sealed_bundle(bytes, &impostor, &seal),
            Err(SealError::SignatureRejected)
        );
    }

    #[test]
    fn two_mints_differ() {
        let a = RunSecret::mint().expect("entropy available under test");
        let b = RunSecret::mint().expect("entropy available under test");
        assert_ne!(a.key_id(), b.key_id());
        assert_ne!(a.seed_for_leak_tests(), b.seed_for_leak_tests());
    }

    #[test]
    fn error_types_carry_no_key_material() {
        let secret = RunSecret::mint().expect("entropy available under test");
        let seed_hex = hex::encode(secret.seed_for_leak_tests());
        let seed_debug = format!("{:?}", secret.seed_for_leak_tests());
        let key_id = secret.key_id().clone();
        let seal = secret.seal(b"payload");

        // Every public error type in the crate, both renderings.
        //
        // An earlier version of this test checked only the error from
        // `verify_sealed_bundle`, whose failing arm is a unit variant with
        // nowhere to put a seed — so it could not have failed however badly
        // the rest of the crate leaked.
        let mut rendered = Vec::new();

        let seal_error =
            verify_sealed_bundle(b"different payload", &key_id, &seal).expect_err("must reject");
        rendered.push(format!("{seal_error:?}"));
        rendered.push(format!("{seal_error}"));

        for e in [
            KeyIdError::MissingMethodPrefix,
            KeyIdError::UnsupportedMultibase,
            KeyIdError::UnsupportedMulticodec,
            KeyIdError::WrongKeyLength { found: 31 },
            KeyIdError::NonCanonicalPublicKey,
        ] {
            rendered.push(format!("{e:?}"));
            rendered.push(format!("{e}"));
            rendered.push(format!("{:?}", SealError::KeyId(e.clone())));
            rendered.push(format!("{}", SealError::KeyId(e)));
        }

        rendered.push(format!("{EntropyUnavailable:?}"));
        rendered.push(format!("{EntropyUnavailable}"));

        for text in rendered {
            assert!(!text.contains(&seed_hex), "hex seed leaked into: {text}");
            assert!(
                !text.contains(&seed_debug),
                "byte-array seed leaked into: {text}"
            );
        }
    }

    #[test]
    fn identifier_rejects_malformed_input() {
        use KeyIdError::*;

        let cases: [(&str, KeyIdError); 3] = [
            (
                "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                MissingMethodPrefix,
            ),
            (
                "did:key:6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                UnsupportedMultibase,
            ),
            (
                "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                UnsupportedMulticodec,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                RunKeyId(input.to_owned()).public_key_bytes(),
                Err(expected.clone()),
                "input {input} should fail with {expected:?}"
            );
        }
    }

    /// A well-formed length is not a well-formed key.
    #[test]
    fn non_curve_point_is_rejected_at_the_identifier() {
        let mut payload = ED25519_PUB_MULTICODEC.to_vec();
        // All-ones is not a canonical ed25519 point encoding.
        payload.extend_from_slice(&[0xff; PUBLIC_KEY_LEN]);
        let id = RunKeyId(format!(
            "{METHOD_PREFIX}{}",
            multibase::encode(multibase::Base::Base58Btc, payload)
        ));

        assert_eq!(
            id.public_key_bytes(),
            Err(KeyIdError::NonCanonicalPublicKey)
        );
    }
}
