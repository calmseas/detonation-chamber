//! The environment the artefact runs in, built one deliberate binding at a
//! time.
//!
//! # Nothing is inherited
//!
//! [`EnvDraft::empty`] is the only constructor. There is no `from_host_env`, no
//! `inherit`, no allowlist-the-rest. Every variable that reaches the cell was
//! named by someone, carries a [`Rationale`] saying why, and is visible in the
//! sealed digest. The host's environment on a developer laptop contains
//! credentials, proxy settings and tokens that nobody decided to hand to a
//! hostile artefact, and a default that inherits them is a default that leaks
//! them.
//!
//! # Two ways a `--env-file` betrays you, both closed here
//!
//! **A newline in a value injects a line.** The file is `KEY=VALUE` per line,
//! so a value containing `\n` writes a second, unrelated binding — and the
//! obvious source of such a value is [`EnvDraft::adopt_one`], which reads the
//! *host* environment. An adopted variable whose value ends
//! `"\nSSL_CERT_FILE=/tmp/theirs"` re-points the trust anchor after it was
//! placed, or overwrites a planted canary so the run detects nothing. Rejected
//! at bind time, not at seal time, so the caller learns which binding did it.
//!
//! **A name that collides silently wins or loses depending on order.** Every
//! duplicate is an error. That is not tidiness: it is what makes the
//! trust-anchor ordering self-enforcing. [`EnvDraft::place_trust_anchor`] binds
//! `SSL_CERT_FILE` and its siblings, so a later `adopt_one("SSL_CERT_FILE")`
//! from the host is *already* a duplicate-name error rather than a silent
//! redirection of the chamber's own TLS interception.
//!
//! # Values never reach a log
//!
//! `Debug` is redacted on both [`EnvDraft`] and [`SealedEnv`]. A canary printed
//! into a test failure, a panic message or a CI log has left the boundary, and
//! the bundle would then be reporting on a leak that the harness itself caused.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use chamber_evidence::Digest32;
use sha2::{Digest as _, Sha256};

use crate::docker::EnvFile;

/// A variable name that cannot corrupt an env file.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct VarName(String);

/// Why a name was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    /// Contains `=`, a newline, or other control characters — any of which
    /// change how the env file parses rather than merely looking odd.
    Malformed {
        name: String,
        offending: char,
    },
    /// POSIX-shaped names only: leading digits are not portable and are a
    /// reliable sign the caller is constructing names from data.
    LeadingDigit {
        name: String,
    },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an environment variable name cannot be empty"),
            Self::Malformed { name, offending } => write!(
                f,
                "{name:?} contains {offending:?}, which would change how the env file parses"
            ),
            Self::LeadingDigit { name } => write!(f, "{name:?} starts with a digit"),
        }
    }
}

impl std::error::Error for NameError {}

impl VarName {
    /// # Errors
    /// [`NameError`] naming the character that made it unusable.
    pub fn parse(name: &str) -> Result<Self, NameError> {
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if let Some(bad) = name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
        {
            return Err(NameError::Malformed {
                name: name.to_owned(),
                offending: bad,
            });
        }
        if name.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(NameError::LeadingDigit {
                name: name.to_owned(),
            });
        }
        Ok(Self(name.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a variable is in the cell at all.
///
/// Carried rather than inferred: six months later, "who asked for this and what
/// breaks without it" is not recoverable from the name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rationale {
    pub reason: &'static str,
    pub required_by: &'static str,
}

/// A binding that was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum BindError {
    /// Already bound. See the module note — this is load-bearing, not tidiness.
    Duplicate { name: VarName },
    /// The value would inject additional lines into the env file.
    ValueWouldInjectLines { name: VarName },
    /// The value contains a NUL, which cannot survive the process boundary.
    ValueHasNul { name: VarName },
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { name } => write!(
                f,
                "{name} is already bound. If this is a host variable being \
                 adopted over one the chamber placed (a trust anchor, a planted \
                 canary), that is the collision this error exists to catch"
            ),
            Self::ValueWouldInjectLines { name } => write!(
                f,
                "the value for {name} contains a newline, which would write an \
                 extra KEY=VALUE line into the env file and silently rebind \
                 something else"
            ),
            Self::ValueHasNul { name } => write!(f, "the value for {name} contains a NUL byte"),
        }
    }
}

impl std::error::Error for BindError {}

/// A host variable that could not be adopted.
#[derive(Debug, PartialEq, Eq)]
pub enum AdoptError {
    /// Not set on the host. An error rather than a skip: a caller that asked
    /// for a specific variable and silently got nothing has a cell configured
    /// differently from the one it thinks it configured.
    NotSetOnHost {
        name: VarName,
    },
    Bind(BindError),
}

impl fmt::Display for AdoptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSetOnHost { name } => {
                write!(
                    f,
                    "{name} is not set on the host, so there is nothing to adopt"
                )
            }
            Self::Bind(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdoptError {}

/// The writable root inside the cell. The rootfs is read-only; this is the
/// tmpfs everything that must write is pointed at.
#[derive(Clone, Debug)]
pub struct GuestRoot(PathBuf);

impl GuestRoot {
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Where the per-run CA landed and which variables steer trust at it.
#[derive(Clone, Debug)]
pub struct AnchorPlacement {
    pub pem_path: PathBuf,
    pub steered: Vec<VarName>,
}

/// Where a canary was planted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlantSite {
    GuestEnvVar(VarName),
    GuestFile(PathBuf),
}

/// The canaries this run intends to plant.
///
/// Deliberately separate from the draft: the matrix's row 2 plants **nothing**
/// and must still seal, because "plant nothing and watch the same code path
/// derive no finding from real egress" is the mutation that proves the tool
/// fires on the canary rather than on egress.
#[derive(Clone, Debug, Default)]
pub struct CanaryPlacements {
    sites: Vec<(String, PlantSite)>,
}

impl CanaryPlacements {
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Declares that the canary labelled `label` belongs in `name`.
    pub fn plant_env(&mut self, label: impl Into<String>, name: VarName) {
        self.sites
            .push((label.into(), PlantSite::GuestEnvVar(name)));
    }

    pub fn plant_file(&mut self, label: impl Into<String>, at: impl Into<PathBuf>) {
        self.sites
            .push((label.into(), PlantSite::GuestFile(at.into())));
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    pub fn sites(&self) -> impl Iterator<Item = &(String, PlantSite)> {
        self.sites.iter()
    }
}

/// A seal that was refused.
#[derive(Debug)]
pub enum EnvSealError {
    /// A canary was declared for a variable that was never bound.
    ///
    /// The failure this prevents is the worst kind available to this tool: the
    /// run completes, the artefact exfiltrates nothing because there was
    /// nothing to find, and the bundle reports no finding. A false negative
    /// that looks exactly like a clean result.
    CanaryNotPlanted {
        label: String,
        name: VarName,
        bound: Vec<String>,
    },
}

impl fmt::Display for EnvSealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanaryNotPlanted { label, name, bound } => write!(
                f,
                "canary {label:?} was declared for {name}, which is not bound. \
                 The run would complete with nothing to find and report no \
                 finding — indistinguishable from a clean result. Bound names: [{}]",
                bound.join(", ")
            ),
        }
    }
}

impl std::error::Error for EnvSealError {}

/// The environment being assembled.
///
/// Ordered, so the sealed digest is stable across runs that bind the same
/// things in a different order.
#[derive(Default)]
pub struct EnvDraft {
    bindings: BTreeMap<VarName, (String, Rationale)>,
    /// Recorded so the cell mounts its tmpfs exactly where these variables
    /// point. See [`EnvDraft::redirect_scratch`].
    scratch_root: Option<PathBuf>,
}

/// Redacted: values here include planted canaries.
impl fmt::Debug for EnvDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvDraft")
            .field("names", &self.bindings.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl EnvDraft {
    /// The only constructor. See the module note.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// # Errors
    /// [`BindError`] if the name is taken or the value would corrupt the file.
    pub fn set(&mut self, name: VarName, value: String, why: Rationale) -> Result<(), BindError> {
        if self.bindings.contains_key(&name) {
            return Err(BindError::Duplicate { name });
        }
        if value.contains('\n') || value.contains('\r') {
            return Err(BindError::ValueWouldInjectLines { name });
        }
        if value.contains('\0') {
            return Err(BindError::ValueHasNul { name });
        }
        self.bindings.insert(name, (value, why));
        Ok(())
    }

    /// Copies exactly one variable from the host environment.
    ///
    /// One at a time, by name, with a reason. The value is checked as strictly
    /// as any other — more relevant here than anywhere else, because this is
    /// the one binding whose content nobody in this process chose.
    ///
    /// # Errors
    /// [`AdoptError`] if it is unset on the host or the binding is refused.
    pub fn adopt_one(&mut self, name: VarName, why: Rationale) -> Result<(), AdoptError> {
        let value = std::env::var(name.as_str())
            .map_err(|_| AdoptError::NotSetOnHost { name: name.clone() })?;
        self.set(name, value, why).map_err(AdoptError::Bind)
    }

    /// Points the things that must write at the cell's tmpfs, and records where
    /// that tmpfs must be mounted.
    ///
    /// The path is carried into [`SealedEnv`] rather than left for the caller
    /// to repeat, because the two must agree and nothing would notice if they
    /// did not: an environment saying `/work` beside a cell mounting
    /// `/scratch` gives a read-only rootfs and writes that fail at the moment
    /// the artefact tries them — which reads as the artefact misbehaving.
    ///
    /// # Errors
    /// [`BindError`] if any of them is already bound.
    pub fn redirect_scratch(&mut self, root: &GuestRoot) -> Result<(), BindError> {
        let why = Rationale {
            reason: "the rootfs is read-only; anything that writes must be sent to the tmpfs",
            required_by: "chamber-isolation::EnvDraft::redirect_scratch",
        };
        for var in ["TMPDIR", "HOME"] {
            let name = VarName::parse(var).expect("literal name is well-formed");
            self.set(name, root.path().display().to_string(), why)?;
        }
        self.scratch_root = Some(root.path().to_owned());
        Ok(())
    }

    /// Steers TLS trust at the per-run CA.
    ///
    /// The certificate is written into the cell's tmpfs and pointed at by
    /// environment variable rather than installed into the system trust store:
    /// `update-ca-certificates` fails silently on a read-only rootfs, and the
    /// anchor must be fresh per run — a shared one destroys per-run attribution
    /// and one leak compromises every run that ever used it.
    ///
    /// Call this **before** adopting anything from the host. Any host variable
    /// that would re-point trust is then already a duplicate-name error.
    ///
    /// Runtimes that ignore these variables — a Java keystore, a statically
    /// embedded root set — are `gap.trust-anchor-steering`, not a silent TLS
    /// failure.
    ///
    /// # Errors
    /// [`BindError`] if any of the four is already bound.
    pub fn place_trust_anchor(&mut self, pem_path: &Path) -> Result<AnchorPlacement, BindError> {
        let why = Rationale {
            reason: "steers TLS trust at the per-run CA so the boundary can decrypt and observe",
            required_by: "chamber-isolation::EnvDraft::place_trust_anchor",
        };
        let mut steered = Vec::new();
        for var in [
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
        ] {
            let name = VarName::parse(var).expect("literal name is well-formed");
            self.set(name.clone(), pem_path.display().to_string(), why)?;
            steered.push(name);
        }
        Ok(AnchorPlacement {
            pem_path: pem_path.to_owned(),
            steered,
        })
    }

    #[must_use]
    pub fn is_bound(&self, name: &VarName) -> bool {
        self.bindings.contains_key(name)
    }

    /// Freezes the environment, checking that every declared canary is
    /// actually there.
    ///
    /// # Errors
    /// [`EnvSealError::CanaryNotPlanted`] if a canary was declared for a
    /// variable that was never bound.
    pub fn seal(self, canaries: &CanaryPlacements) -> Result<SealedEnv, EnvSealError> {
        for (label, site) in canaries.sites() {
            if let PlantSite::GuestEnvVar(name) = site
                && !self.bindings.contains_key(name)
            {
                return Err(EnvSealError::CanaryNotPlanted {
                    label: label.clone(),
                    name: name.clone(),
                    bound: self.bindings.keys().map(ToString::to_string).collect(),
                });
            }
        }
        Ok(SealedEnv {
            bindings: self.bindings,
            scratch_root: self.scratch_root,
        })
    }
}

/// A frozen environment.
pub struct SealedEnv {
    bindings: BTreeMap<VarName, (String, Rationale)>,
    scratch_root: Option<PathBuf>,
}

/// Redacted: this is the type that holds planted canaries.
impl fmt::Debug for SealedEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedEnv")
            .field("names", &self.bindings.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl SealedEnv {
    /// The exact bytes handed to the engine.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, (value, _)) in &self.bindings {
            out.extend_from_slice(format!("{name}={value}\n").as_bytes());
        }
        out
    }

    /// A commitment to the environment, for the bundle.
    ///
    /// Over the same bytes the cell receives, so it commits to what actually
    /// happened rather than to a re-rendering of it.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        Digest32(hasher.finalize().into())
    }

    /// The names bound, without their values. Safe to log; the digest is what
    /// commits to the contents.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.bindings.keys().map(ToString::to_string).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Why a given variable is present.
    #[must_use]
    pub fn rationale(&self, name: &VarName) -> Option<Rationale> {
        self.bindings.get(name).map(|(_, why)| *why)
    }

    /// Where the cell must mount its writable tmpfs, if scratch was redirected.
    ///
    /// The cell reads this rather than being told separately, so the mount and
    /// the variables pointing at it cannot drift apart.
    #[must_use]
    pub fn scratch_root(&self) -> Option<&Path> {
        self.scratch_root.as_deref()
    }

    /// Whether a variable of this name is bound, without exposing its value.
    ///
    /// For tests that need to assert a binding landed without reaching for the
    /// value itself — `#[cfg(test)]` cannot do this: it would vanish from the
    /// compiled rlib that other crates' test binaries link against, since
    /// `cfg(test)` only takes effect for the crate being compiled as a test,
    /// not for a downstream crate's own test build. Presence-only, so it stays
    /// consistent with this type's redacted `Debug`.
    #[must_use]
    pub fn contains_binding(&self, name: &str) -> bool {
        self.bindings.keys().any(|k| k.as_str() == name)
    }

    /// Writes the 0600 file the engine reads with `--env-file`.
    ///
    /// Never `-e KEY=VALUE`: that puts every value, canaries included, in the
    /// host process table for the container's whole lifetime, where any user on
    /// the machine can read them out of `ps`.
    ///
    /// # Errors
    /// [`std::io::Error`] if the file cannot be written.
    pub fn to_env_file(&self) -> std::io::Result<EnvFile> {
        let pairs: Vec<(String, String)> = self
            .bindings
            .iter()
            .map(|(name, (value, _))| (name.to_string(), value.clone()))
            .collect();
        EnvFile::write(&pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn why() -> Rationale {
        Rationale {
            reason: "test",
            required_by: "test",
        }
    }

    fn name(n: &str) -> VarName {
        VarName::parse(n).expect("well-formed test name")
    }

    #[test]
    fn a_name_with_an_equals_sign_is_refused() {
        assert!(matches!(
            VarName::parse("FOO=BAR"),
            Err(NameError::Malformed { .. })
        ));
    }

    #[test]
    fn a_name_with_a_newline_is_refused() {
        assert!(matches!(
            VarName::parse("FOO\nBAR"),
            Err(NameError::Malformed { .. })
        ));
    }

    #[test]
    fn empty_and_leading_digit_names_are_refused() {
        assert_eq!(VarName::parse(""), Err(NameError::Empty));
        assert!(matches!(
            VarName::parse("1FOO"),
            Err(NameError::LeadingDigit { .. })
        ));
    }

    /// The injection this module exists to stop. A value ending in a newline
    /// plus another binding writes TWO lines into the env file, and the second
    /// one silently re-points whatever it names.
    #[test]
    fn a_value_containing_a_newline_cannot_be_bound() {
        let mut draft = EnvDraft::empty();
        let err = draft
            .set(
                name("INNOCENT"),
                "ok\nSSL_CERT_FILE=/tmp/attacker.pem".into(),
                why(),
            )
            .unwrap_err();
        assert!(matches!(err, BindError::ValueWouldInjectLines { .. }));
    }

    #[test]
    fn a_carriage_return_is_refused_too() {
        let mut draft = EnvDraft::empty();
        assert!(draft.set(name("X"), "a\rb".into(), why()).is_err());
    }

    /// The ordering guarantee from the design: the trust anchor is placed
    /// first, so a host variable that would redirect it collides rather than
    /// quietly winning.
    #[test]
    fn adopting_a_trust_variable_after_placement_is_a_duplicate() {
        let mut draft = EnvDraft::empty();
        draft
            .place_trust_anchor(Path::new("/work/chamber-ca.pem"))
            .expect("place the anchor");

        let err = draft
            .set(name("SSL_CERT_FILE"), "/tmp/theirs.pem".into(), why())
            .unwrap_err();
        assert!(matches!(err, BindError::Duplicate { .. }), "{err}");
    }

    #[test]
    fn placing_the_anchor_steers_all_four_runtimes() {
        let mut draft = EnvDraft::empty();
        let placement = draft
            .place_trust_anchor(Path::new("/work/chamber-ca.pem"))
            .expect("place the anchor");
        assert_eq!(placement.steered.len(), 4);
        for var in [
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
        ] {
            assert!(draft.is_bound(&name(var)), "{var} not steered");
        }
    }

    /// A canary declared but never bound would produce a run with nothing to
    /// find, reported as no finding.
    #[test]
    fn sealing_refuses_a_canary_that_was_never_planted() {
        let mut canaries = CanaryPlacements::none();
        canaries.plant_env("api-token", name("CHAMBER_TOKEN"));

        let err = EnvDraft::empty().seal(&canaries).unwrap_err();
        let EnvSealError::CanaryNotPlanted { label, name: n, .. } = &err;
        assert_eq!(label, "api-token");
        assert_eq!(n.as_str(), "CHAMBER_TOKEN");
    }

    #[test]
    fn sealing_accepts_a_canary_that_was_planted() {
        let mut draft = EnvDraft::empty();
        draft
            .set(name("CHAMBER_TOKEN"), "canary-value".into(), why())
            .unwrap();
        let mut canaries = CanaryPlacements::none();
        canaries.plant_env("api-token", name("CHAMBER_TOKEN"));

        assert!(draft.seal(&canaries).is_ok());
    }

    /// Matrix row 2 plants nothing and must still seal — that row is the
    /// mutation proving the tool fires on the canary rather than on egress.
    #[test]
    fn planting_nothing_still_seals() {
        let sealed = EnvDraft::empty()
            .seal(&CanaryPlacements::none())
            .expect("an empty plant set is legitimate");
        assert!(sealed.is_empty());
    }

    /// A file-site canary is not an env binding, so it must not be demanded of
    /// the draft.
    #[test]
    fn a_file_canary_does_not_require_an_env_binding() {
        let mut canaries = CanaryPlacements::none();
        canaries.plant_file("dotenv", "/work/.env");
        assert!(EnvDraft::empty().seal(&canaries).is_ok());
    }

    #[test]
    fn the_digest_is_order_independent() {
        let mut a = EnvDraft::empty();
        a.set(name("ALPHA"), "1".into(), why()).unwrap();
        a.set(name("BETA"), "2".into(), why()).unwrap();

        let mut b = EnvDraft::empty();
        b.set(name("BETA"), "2".into(), why()).unwrap();
        b.set(name("ALPHA"), "1".into(), why()).unwrap();

        let (a, b) = (
            a.seal(&CanaryPlacements::none()).unwrap(),
            b.seal(&CanaryPlacements::none()).unwrap(),
        );
        assert_eq!(a.digest().0, b.digest().0);
    }

    #[test]
    fn the_digest_changes_when_a_value_changes() {
        let mut a = EnvDraft::empty();
        a.set(name("ALPHA"), "1".into(), why()).unwrap();
        let mut b = EnvDraft::empty();
        b.set(name("ALPHA"), "2".into(), why()).unwrap();

        assert_ne!(
            a.seal(&CanaryPlacements::none()).unwrap().digest().0,
            b.seal(&CanaryPlacements::none()).unwrap().digest().0
        );
    }

    /// A canary in a panic message, a test failure or a CI log has left the
    /// boundary — and the bundle would then be reporting a leak the harness
    /// itself caused.
    #[test]
    fn debug_never_prints_a_value() {
        let mut draft = EnvDraft::empty();
        draft
            .set(name("CHAMBER_TOKEN"), "super-secret-canary".into(), why())
            .unwrap();

        let drafted = format!("{draft:?}");
        assert!(!drafted.contains("super-secret-canary"), "{drafted}");
        assert!(drafted.contains("CHAMBER_TOKEN"), "{drafted}");

        let sealed = draft.seal(&CanaryPlacements::none()).unwrap();
        let printed = format!("{sealed:?}");
        assert!(!printed.contains("super-secret-canary"), "{printed}");
    }

    #[test]
    fn nothing_is_inherited_from_the_host() {
        // SAFETY: single-threaded test process; the variable is unique to it.
        unsafe { std::env::set_var("CHAMBER_TEST_MUST_NOT_LEAK", "host-value") };
        let sealed = EnvDraft::empty()
            .seal(&CanaryPlacements::none())
            .expect("seal");
        assert!(sealed.is_empty(), "the draft picked up host state");
        assert!(!sealed.names().iter().any(|n| n.contains("CHAMBER_TEST")));
    }

    #[test]
    fn adopting_an_unset_variable_is_an_error_not_a_skip() {
        let mut draft = EnvDraft::empty();
        let err = draft
            .adopt_one(name("CHAMBER_DEFINITELY_NOT_SET_XYZ"), why())
            .unwrap_err();
        assert!(matches!(err, AdoptError::NotSetOnHost { .. }));
    }

    #[test]
    fn scratch_redirection_points_at_the_tmpfs() {
        let mut draft = EnvDraft::empty();
        draft
            .redirect_scratch(&GuestRoot::at("/work"))
            .expect("redirect");
        assert!(draft.is_bound(&name("TMPDIR")));
        assert!(draft.is_bound(&name("HOME")));
    }

    /// The cell mounts its tmpfs from this, so it must survive the seal. If it
    /// did not, the cell would get a read-only rootfs with nowhere to write and
    /// the failure would look like the artefact misbehaving.
    #[test]
    fn the_scratch_root_survives_sealing() {
        let mut draft = EnvDraft::empty();
        draft
            .redirect_scratch(&GuestRoot::at("/work"))
            .expect("redirect");
        let sealed = draft.seal(&CanaryPlacements::none()).expect("seal");
        assert_eq!(sealed.scratch_root(), Some(Path::new("/work")));
    }

    /// No redirection, no mount. A cell that mounted a tmpfs nobody asked for
    /// would hand the artefact a writable location the environment never
    /// mentions.
    #[test]
    fn without_redirection_there_is_no_scratch_root() {
        let sealed = EnvDraft::empty()
            .seal(&CanaryPlacements::none())
            .expect("seal");
        assert_eq!(sealed.scratch_root(), None);
    }

    #[test]
    fn the_env_file_is_0600_and_holds_every_binding() {
        use std::os::unix::fs::PermissionsExt as _;

        let mut draft = EnvDraft::empty();
        draft.set(name("ALPHA"), "1".into(), why()).unwrap();
        draft.set(name("BETA"), "2".into(), why()).unwrap();
        let sealed = draft.seal(&CanaryPlacements::none()).unwrap();

        let file = sealed.to_env_file().expect("write the env file");
        let mode = std::fs::metadata(file.path())
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "env file is {mode:o}, not 0600");

        let text = std::fs::read_to_string(file.path()).expect("read back");
        assert!(text.contains("ALPHA=1"));
        assert!(text.contains("BETA=2"));
    }
}
