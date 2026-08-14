//! The boundary itself.
//!
//! Everything here needs a Linux guest, which is why it is a crate rather than
//! a module: it means `cargo test -p chamber-evidence` stays container-free and
//! the container gate is a crate boundary rather than a runtime `if`.
//!
//! # Built so far
//!
//! - [`docker`] — the container engine, driven by its CLI. Containers are
//!   destroyed by the id captured at create, never by name or label.
//! - [`preflight`] — the three structural asserts that must pass before any
//!   containment claim is believable. All three are version-dependent and all
//!   three fail silently if merely assumed.
//! - [`probe`] — the outcome vocabulary the adversary probe reports in, and the
//!   reader for it.
//! - [`warden`] — the namespace owner: the fabric, the ruleset, the NFLOG
//!   collector and the tarpit route, with the ordering between them encoded as
//!   types rather than as a convention.
//! - [`env`] — the environment the artefact runs in, where nothing is
//!   inherited and every binding is named, justified and sealed.
//! - [`cell`] — the agent cell, which can only be started into a chamber that
//!   is already armed and already being observed.
//!
//! What remains: `probe_host`/`adjudicate` (deciding whether this host can host
//! a chamber at all), and the seal-before-teardown token, which cannot be
//! minted honestly until the capture layer runs in the chamber. See [`cell`].
//!
//! # The ordering constraint that cannot be recovered
//!
//! **The unarmed positive control is written before the first nftables rule.**
//!
//! Once a ruleset exists there is no way back to a state in which the probe
//! could have been observed succeeding. A probe broken by a typo — a wrong
//! hostname, a port that was never listening, an image that lacks the tool it
//! shells out to — fails for its own reasons and passes every containment test
//! anyone will ever write against it. Eleven confident greens, none of which
//! distinguish "the chamber blocked it" from "it never ran".
//!
//! So the baseline comes first: the same probe, the same targets, on a network
//! with nothing blocking it, and it must *succeed*. Every armed assertion is
//! then written as a delta against that baseline rather than as an absolute.
//! See `chamber-e2e`'s containment suite, where the control lives.
//!
//! # Two things that will look wrong later and are not
//!
//! Recorded here because both are load-bearing and both read as mistakes to
//! someone tidying up:
//!
//! 1. **The tarpit route** (`ip route add default via <capture>`). Measured on
//!    this engine: without it the probe is blocked identically — its own output
//!    byte for byte the same — while `c_drop_out` stays at **0** and no frame
//!    is logged; with it, the same blocked probe leaves **6**. An off-subnet
//!    packet is otherwise rejected by the *routing* layer with `ENETUNREACH`
//!    and never reaches netfilter at all. The chamber is contained and
//!    **blind**, and blindness is indistinguishable from success to a one-sided
//!    test. Safe only because containment does not depend on it: the output
//!    policy is `drop`, forwarding is off, and no NAT exists for the subnet.
//!
//! 2. **The reset is scoped, never `flush ruleset`.** A full flush destroys
//!    Docker's own `ip nat` table — the one that DNATs `127.0.0.11` to the
//!    embedded resolver — and kills DNS for the entire network namespace. The
//!    live ruleset says so itself: *"table ip nat is managed by iptables-nft,
//!    do not touch!"*. Only `table inet chamber; delete table inet chamber;`.

pub mod cell;
pub mod docker;
pub mod env;
pub mod preflight;
pub mod probe;
pub mod warden;

pub use cell::{AgentCell, EMPTY_BOUNDING_SET, GuestImage};
pub use docker::{
    Attach, Container, ContainerSpec, Docker, DockerUnavailable, EngineError, EnvFile, ExecOutcome,
    Network, NetworkSpec, build_image, build_image_for_platform, build_image_with_dockerfile,
};
pub use env::{
    AdoptError, AnchorPlacement, BindError, CanaryPlacements, EnvDraft, EnvSealError, GuestRoot,
    NameError, PlantSite, Rationale, SealedEnv, VarName,
};
pub use preflight::{AssertOutcome, Preflight, PreflightFailure, StructuralAssert};
pub use probe::{MalformedRow, ProbeReport, ProbeRow, Reach, RowId};
pub use warden::{ArmedWarden, CellError, DropCounters, NetFabric, ObservedWarden, Warden};
