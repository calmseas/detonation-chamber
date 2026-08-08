//! The warden: the container that owns the namespace the agent lives in.
//!
//! # The ordering is a type, not a convention
//!
//! Three of this crate's prohibitions are orderings, and all three are silently
//! fatal — they produce a chamber that looks armed, passes a one-sided test,
//! and has lost the evidence:
//!
//! - the tarpit route must not be added **before** the ruleset loads;
//! - the agent must not start **before** the NFLOG collector is confirmed
//!   running;
//! - the reset must be scoped, never a full flush.
//!
//! A comment saying so is worth very little at 2am. So the states are separate
//! types and the transitions are the only way between them:
//!
//! ```text
//! Warden  --load_ruleset-->  ArmedWarden  --start_drop_collector-->  ObservedWarden
//! ```
//!
//! [`ObservedWarden`] is the only one with `add_tarpit_route`, and the only one
//! an agent cell can attach to. Getting the order wrong is not a test failure;
//! it does not compile.
//!
//! # Why the tarpit route exists, since it looks like a mistake
//!
//! `ip route add default via <capture>` in a chamber whose entire purpose is to
//! have no route out reads as an error, and deleting it is the obvious tidy-up.
//! It is load-bearing, and this was measured rather than reasoned about:
//!
//! | | probe result | `c_drop_out` |
//! |---|---|---|
//! | without the route | blocked | **0** |
//! | with the route | blocked | **6** |
//!
//! The probe's own output is byte-identical in both runs. Without the route an
//! off-subnet packet is rejected by the *routing* layer with `ENETUNREACH` and
//! never enters netfilter at all — so nothing is counted and nothing is logged.
//! The chamber is contained and **blind**, and a suite that only asks "did the
//! probe fail?" passes in both states.
//!
//! It is safe only because containment does not depend on it. Three other
//! things hold the boundary: the output policy is `drop`, `DOCKER-INTERNAL`
//! drops both directions on the bridge, and there is no MASQUERADE for the
//! subnet. [`crate::preflight`] asserts all three before any of this is
//! trusted.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::docker::{Attach, Container, ContainerSpec, EngineError, Network, NetworkSpec};

/// Where the ruleset is written inside the warden.
const RULESET_PATH: &str = "/tmp/chamber.nft";
/// Where the collector's frames and its own startup chatter land.
const FRAMES_PATH: &str = "/tmp/chamber-drops.log";
const COLLECTOR_STDERR: &str = "/tmp/chamber-drops.err";
/// The NFLOG group the ruleset's egress drops are logged to.
const EGRESS_LOG_GROUP: u8 = 1;

const OP_WINDOW: Duration = Duration::from_secs(60);
/// How long the collector gets to announce itself before we call it dead.
const COLLECTOR_WINDOW: Duration = Duration::from_secs(20);

/// Something the chamber could not be brought up to do.
#[derive(Debug)]
pub enum CellError {
    Engine(EngineError),
    RulesetUnreadable {
        path: String,
        detail: String,
    },
    /// The collector was started and never announced itself.
    ///
    /// Treated as fatal rather than warned about: every armed negative in the
    /// containment suite is corroborated by a captured frame, so a chamber
    /// whose collector is not running cannot produce evidence — it can only
    /// produce unfalsifiable greens.
    CollectorNeverListened {
        stderr: String,
    },
    CountersUnreadable {
        raw: String,
        detail: String,
    },
}

impl std::fmt::Display for CellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "{e}"),
            Self::RulesetUnreadable { path, detail } => {
                write!(f, "could not read the ruleset at {path}: {detail}")
            }
            Self::CollectorNeverListened { stderr } => write!(
                f,
                "the NFLOG collector never reported listening, so no drop \
                 evidence can be produced. Only ONE collector may bind a given \
                 NFLOG group -- a second one exits silently. Its stderr:\n{stderr}"
            ),
            Self::CountersUnreadable { raw, detail } => {
                write!(
                    f,
                    "could not read the counters ({detail}); nft said:\n{raw}"
                )
            }
        }
    }
}

impl std::error::Error for CellError {}

impl From<EngineError> for CellError {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

/// The chamber's networks. One, in Slice 0.
///
/// The uplink network and the inference lane are deliberately absent: with an
/// empty allowlist the observer never forwards upstream, so no route to the
/// internet exists anywhere in the chamber. That is strictly stronger than a
/// design with an uplink, and materially less to get wrong.
#[derive(Debug)]
pub struct NetFabric {
    egress: Network,
}

impl NetFabric {
    pub const NETWORK: &'static str = "chamber-egress";
    pub const SUBNET: &'static str = "10.66.0.0/24";
    /// The observer: proxy on 3128, DNS on 53. One address because one process
    /// — a shared monotonic ordinal across DNS and HTTP is what makes an
    /// interleaving recoverable from the bundle alone.
    pub const CAPTURE_IP: &'static str = "10.66.0.10";
    pub const WARDEN_IP: &'static str = "10.66.0.6";

    /// Raises the egress network.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn raise() -> Result<Self, EngineError> {
        let egress = Network::raise(NetworkSpec {
            name: Self::NETWORK.to_owned(),
            subnet: Self::SUBNET.to_owned(),
            internal: true,
        })?;
        Ok(Self { egress })
    }

    #[must_use]
    pub fn egress(&self) -> &Network {
        &self.egress
    }

    /// # Errors
    /// [`EngineError`] if a container is still attached.
    pub fn destroy(self) -> Result<(), EngineError> {
        self.egress.destroy()
    }
}

/// The nftables counters, read from the live ruleset.
///
/// Counters sit *before* the rate limit on every path, so these totals are
/// exact even when a flood washes out the logged detail of individual packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DropCounters {
    pub dns_ok: u64,
    pub proxy_ok: u64,
    pub drop_out: u64,
    pub drop_in: u64,
    pub drop_fwd: u64,
}

#[derive(Deserialize)]
struct NftDocument {
    nftables: Vec<NftEntry>,
}

#[derive(Deserialize)]
struct NftEntry {
    counter: Option<NftCounter>,
}

#[derive(Deserialize)]
struct NftCounter {
    name: String,
    packets: u64,
}

impl DropCounters {
    /// Parses `nft -j list counters table inet chamber`.
    ///
    /// # Errors
    /// [`CellError::CountersUnreadable`] carrying what nft actually said, which
    /// is the only useful thing when the ruleset failed to load and the command
    /// succeeded against an empty table.
    fn parse(raw: &str) -> Result<Self, CellError> {
        let doc: NftDocument =
            serde_json::from_str(raw).map_err(|e| CellError::CountersUnreadable {
                raw: raw.to_owned(),
                detail: e.to_string(),
            })?;

        let mut counters = Self::default();
        let mut seen = 0;
        for entry in doc.nftables.iter().filter_map(|e| e.counter.as_ref()) {
            let slot = match entry.name.as_str() {
                "c_dns_ok" => &mut counters.dns_ok,
                "c_proxy_ok" => &mut counters.proxy_ok,
                "c_drop_out" => &mut counters.drop_out,
                "c_drop_in" => &mut counters.drop_in,
                "c_drop_fwd" => &mut counters.drop_fwd,
                _ => continue,
            };
            *slot = entry.packets;
            seen += 1;
        }

        // An empty or partial read means the table is not loaded. Returning
        // zeroes instead would be indistinguishable from a chamber that saw
        // nothing, which is the reading that turns a broken ruleset into a
        // clean run.
        if seen < 5 {
            return Err(CellError::CountersUnreadable {
                raw: raw.to_owned(),
                detail: format!("found {seen} of the 5 chamber counters"),
            });
        }
        Ok(counters)
    }
}

/// A warden with no ruleset yet.
///
/// The tarpit route is not reachable from here, and that is checked rather than
/// asserted — adding it before the ruleset loads is one of the orderings that
/// cannot be recovered:
///
/// ```compile_fail,E0599
/// fn too_early(w: chamber_isolation::Warden) {
///     w.add_tarpit_route().unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct Warden {
    container: Container,
}

impl Warden {
    /// Starts the warden on the fabric, holding `CAP_NET_ADMIN` and nothing
    /// else.
    ///
    /// # Errors
    /// [`CellError`] if the engine refuses.
    pub fn start(fabric: &NetFabric, image: &str) -> Result<Self, CellError> {
        let container = Container::create(&ContainerSpec {
            image: image.to_owned(),
            attach: Attach::Network {
                network: fabric.egress().name().to_owned(),
                ip: Some(NetFabric::WARDEN_IP.to_owned()),
            },
            // The one capability in the chamber. The agent cell that shares
            // this namespace gets none, which is what makes the ruleset
            // something it cannot reach rather than something it declines to
            // touch.
            cap_add: vec!["NET_ADMIN".into()],
            argv: vec!["sleep".into(), "infinity".into()],
            sysctls: vec![],
            env_file: None,
            dns: vec![],
        })?;
        container.start()?;
        Ok(Self { container })
    }

    #[must_use]
    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    /// Loads the ruleset, and only then is a tarpit route or an agent possible.
    ///
    /// The file is fed over stdin rather than bind-mounted: a mount would give
    /// the namespace a handle on host state.
    ///
    /// # Errors
    /// [`CellError`] if the file cannot be read or nft refuses it.
    pub fn load_ruleset(self, ruleset: &Path) -> Result<ArmedWarden, CellError> {
        let bytes = std::fs::read(ruleset).map_err(|e| CellError::RulesetUnreadable {
            path: ruleset.display().to_string(),
            detail: e.to_string(),
        })?;

        self.container.exec_with_stdin(
            &["sh", "-c", &format!("cat > {RULESET_PATH}")],
            &bytes,
            OP_WINDOW,
        )?;
        self.container
            .exec_with_stdin(&["nft", "-f", RULESET_PATH], &[], OP_WINDOW)?;

        Ok(ArmedWarden { warden: self })
    }

    /// Removes the warden.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn destroy(self) -> Result<(), EngineError> {
        self.container.destroy(OP_WINDOW)
    }
}

/// A warden whose ruleset is loaded, with no collector yet.
///
/// Still not enough to attach an agent to. Starting the artefact before the
/// NFLOG collector is confirmed running means the first thing it does is the
/// one thing never recorded:
///
/// ```compile_fail,E0599
/// fn unobserved(w: chamber_isolation::ArmedWarden) {
///     w.add_tarpit_route().unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct ArmedWarden {
    warden: Warden,
}

impl ArmedWarden {
    #[must_use]
    pub fn container_id(&self) -> &str {
        self.warden.container_id()
    }

    /// # Errors
    /// [`CellError`] if nft cannot be read.
    pub fn counters(&self) -> Result<DropCounters, CellError> {
        let out = self.warden.container.exec(
            &["nft", "-j", "list", "counters", "table", "inet", "chamber"],
            OP_WINDOW,
        )?;
        DropCounters::parse(&out.stdout)
    }

    /// Starts the NFLOG collector and **confirms it is listening**.
    ///
    /// Starting it proves nothing: `docker exec -d` returns as soon as the
    /// process is spawned, and tcpdump can exit immediately afterwards. Two
    /// ways that happens in practice, both silent — the group is already bound
    /// by another collector (only one may bind a given NFLOG group; a second
    /// exits without a word), or the interface does not exist.
    ///
    /// So this waits for tcpdump's own `listening on nflog:N` line before
    /// returning, and that line is the only thing that produces an
    /// [`ObservedWarden`].
    ///
    /// # Errors
    /// [`CellError::CollectorNeverListened`] with the collector's stderr.
    pub fn start_drop_collector(self) -> Result<ObservedWarden, CellError> {
        let command = format!(
            "tcpdump -i nflog:{EGRESS_LOG_GROUP} -l -nn > {FRAMES_PATH} 2> {COLLECTOR_STDERR}"
        );
        self.warden
            .container
            .exec_detached(&["sh", "-c", &command], OP_WINDOW)?;

        let deadline = Instant::now() + COLLECTOR_WINDOW;
        loop {
            let seen = self
                .warden
                .container
                .exec(&["cat", COLLECTOR_STDERR], OP_WINDOW)
                .map(|o| o.stdout)
                .unwrap_or_default();

            if seen.contains("listening on") {
                return Ok(ObservedWarden { armed: self });
            }
            if Instant::now() >= deadline {
                return Err(CellError::CollectorNeverListened { stderr: seen });
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn destroy(self) -> Result<(), EngineError> {
        self.warden.destroy()
    }
}

/// A warden that is armed *and* observed. The only state an agent may join.
#[derive(Debug)]
pub struct ObservedWarden {
    armed: ArmedWarden,
}

impl ObservedWarden {
    #[must_use]
    pub fn container_id(&self) -> &str {
        self.armed.container_id()
    }

    /// # Errors
    /// [`CellError`] if nft cannot be read.
    pub fn counters(&self) -> Result<DropCounters, CellError> {
        self.armed.counters()
    }

    /// Adds the route that makes drops observable. See the module note — this
    /// looks wrong and is not.
    ///
    /// `add` rather than `replace`, deliberately: a pre-existing default route
    /// means the network is not the `--internal` one this assumes, and that
    /// should surface as an error rather than be quietly overwritten.
    ///
    /// # Errors
    /// [`CellError`] if the route cannot be added.
    pub fn add_tarpit_route(&self) -> Result<(), CellError> {
        self.armed.warden.container.exec_with_stdin(
            &[
                "ip",
                "route",
                "add",
                "default",
                "via",
                NetFabric::CAPTURE_IP,
            ],
            &[],
            OP_WINDOW,
        )?;
        Ok(())
    }

    /// Everything the collector has captured so far.
    ///
    /// tcpdump's default decode is enough for the corroborations the suite
    /// needs: a dropped TCP SYN prints its exact 5-tuple, and a dropped DNS
    /// query prints its QNAME — so a blocked exfil attempt still yields the
    /// domain it was aimed at.
    ///
    /// # Errors
    /// [`CellError`] if the frames cannot be read.
    pub fn captured_frames(&self) -> Result<String, CellError> {
        let out = self
            .armed
            .warden
            .container
            .exec(&["cat", FRAMES_PATH], OP_WINDOW)?;
        Ok(out.stdout)
    }

    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn destroy(self) -> Result<(), EngineError> {
        self.armed.destroy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact shape nft 1.0.9 emitted in the warden image.
    const LIVE: &str = r#"{"nftables": [
      {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
      {"counter": {"family": "inet", "name": "c_dns_ok", "table": "chamber", "handle": 4, "packets": 0, "bytes": 0}},
      {"counter": {"family": "inet", "name": "c_proxy_ok", "table": "chamber", "handle": 5, "packets": 0, "bytes": 0}},
      {"counter": {"family": "inet", "name": "c_drop_out", "table": "chamber", "handle": 6, "packets": 6, "bytes": 360}},
      {"counter": {"family": "inet", "name": "c_drop_in", "table": "chamber", "handle": 7, "packets": 0, "bytes": 0}},
      {"counter": {"family": "inet", "name": "c_drop_fwd", "table": "chamber", "handle": 8, "packets": 0, "bytes": 0}}]}"#;

    #[test]
    fn reads_the_live_counter_output() {
        let counters = DropCounters::parse(LIVE).expect("live nft output parses");
        assert_eq!(counters.drop_out, 6);
        assert_eq!(counters.dns_ok, 0);
        assert_eq!(counters.drop_in, 0);
    }

    /// The distinction that matters most here: a table that did not load reads
    /// as an error, never as a chamber that saw nothing.
    #[test]
    fn an_unloaded_table_is_an_error_not_a_row_of_zeroes() {
        let empty =
            r#"{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]}"#;
        let err = DropCounters::parse(empty).unwrap_err();
        assert!(
            matches!(err, CellError::CountersUnreadable { .. }),
            "expected an error, got {err:?}"
        );
    }

    /// A partial ruleset — someone deleting a counter — must not silently read
    /// the survivors as the whole picture.
    #[test]
    fn a_partial_counter_set_is_an_error() {
        let partial = r#"{"nftables": [
          {"counter": {"family": "inet", "name": "c_drop_out", "table": "chamber", "handle": 6, "packets": 9, "bytes": 1}}]}"#;
        assert!(DropCounters::parse(partial).is_err());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(DropCounters::parse("nft: command not found").is_err());
    }

    /// The addresses the ruleset and the probe table both hardcode. If these
    /// drift apart, the accept rules stop matching the observer and every run
    /// silently loses DNS and the proxy.
    #[test]
    fn the_fabric_addresses_are_inside_the_subnet() {
        assert!(NetFabric::CAPTURE_IP.starts_with("10.66.0."));
        assert!(NetFabric::WARDEN_IP.starts_with("10.66.0."));
        assert_eq!(NetFabric::SUBNET, "10.66.0.0/24");
        assert_ne!(NetFabric::CAPTURE_IP, NetFabric::WARDEN_IP);
    }
}
