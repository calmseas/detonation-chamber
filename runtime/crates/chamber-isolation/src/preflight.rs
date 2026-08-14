//! The three structural asserts.
//!
//! Three independent things must fail before a packet escapes the chamber: the
//! guest's own routing table, Docker's `DOCKER-INTERNAL` DROP pair, and the
//! absence of NAT for the subnet. This module measures all three. It does not
//! assume any of them, and that is the entire point — every one is
//! version-dependent, and every one fails *silently*.
//!
//! The specific hazard is engine drift. Docker 29.5.2 strips the default route
//! from a container on an `--internal` network, so an off-subnet packet dies at
//! the routing layer; older engines leave the route in place and rely only on
//! the host DROP rules. A chamber built against the first behaviour and run on
//! the second is weaker than its own test suite believes, with nothing
//! anywhere reporting the difference.
//!
//! # An assert that could not be measured did not hold
//!
//! Each check answers two questions, not one: did the inspection run, and what
//! did it find. They collapse dangerously — "found no `default` route" and
//! "produced no output" are the same string — and the collapse always favours
//! the answer that lets the run proceed. So a check that cannot show it ran
//! reports *did not hold*, and the run refuses to arm with the evidence
//! attached. A refusal is recoverable; a chamber that believes it has no
//! egress is not.
//!
//! # These describe the chamber network, not any network
//!
//! [`Preflight::run`] is meaningful only against an `--internal` network. A
//! non-internal one — the scratch network the unarmed control runs on — has no
//! `DOCKER-INTERNAL` pair by design, and asserting otherwise would be asserting
//! that the positive control is broken.

use std::time::Duration;

use crate::docker::{Attach, Container, ContainerSpec, EngineError, Network};

/// How long any single inspection may take.
const INSPECT_WINDOW: Duration = Duration::from_secs(60);

/// One of the three things that must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralAssert {
    /// A container on the chamber network has no `default via` route, so an
    /// off-subnet packet has nowhere to go before netfilter is even consulted.
    NoDefaultRoute,
    /// The NAT table carries no MASQUERADE for the chamber subnet, so even a
    /// packet that reached the host would leave with an unroutable source.
    NoMasqueradeForSubnet,
    /// Docker's own `DOCKER-INTERNAL` chain drops traffic in both directions
    /// across this network's bridge.
    DockerInternalDropPair,
}

impl StructuralAssert {
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::NoDefaultRoute => "no `default via` route in the guest",
            Self::NoMasqueradeForSubnet => "no MASQUERADE for the chamber subnet",
            Self::DockerInternalDropPair => "DOCKER-INTERNAL drops both directions on the bridge",
        }
    }
}

/// What one assert measured, and the text it measured it from.
///
/// The evidence is retained whether or not the assert held. A preflight that
/// reports only a boolean leaves the next person re-deriving the engine state
/// by hand at exactly the moment they are least able to.
#[derive(Debug, Clone)]
pub struct AssertOutcome {
    pub which: StructuralAssert,
    pub held: bool,
    pub evidence: String,
}

/// A preflight that did not hold.
#[derive(Debug)]
pub struct PreflightFailure {
    pub failures: Vec<AssertOutcome>,
}

impl std::fmt::Display for PreflightFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} of the structural asserts did not hold; the chamber is not what the suite assumes:",
            self.failures.len()
        )?;
        for outcome in &self.failures {
            writeln!(
                f,
                "  - {}\n    evidence: {}",
                outcome.which.description(),
                outcome.evidence.trim()
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for PreflightFailure {}

/// The measured state of the three asserts.
#[derive(Debug)]
pub struct Preflight {
    outcomes: Vec<AssertOutcome>,
}

impl Preflight {
    /// Measures all three against a live `--internal` network.
    ///
    /// `guest_image` supplies the routing check (it needs `ip`); the netfilter
    /// checks run in `inspector_image` attached to the engine host's own
    /// namespace, because they are properties of the host and cannot be
    /// observed from inside an isolated one.
    ///
    /// # Errors
    /// [`EngineError`] if an inspection could not be performed at all. An
    /// assert that ran and did *not* hold is a result, not an error — read it
    /// with [`Preflight::into_result`].
    pub fn run(
        network: &Network,
        guest_image: &str,
        inspector_image: &str,
    ) -> Result<Self, EngineError> {
        let mut outcomes = Vec::with_capacity(3);
        outcomes.push(Self::check_no_default_route(network, guest_image)?);

        let nat = Self::inspect(inspector_image, "nat")?;
        outcomes.push(Self::check_no_masquerade(network, &nat));

        let filter = Self::inspect(inspector_image, "filter")?;
        outcomes.push(Self::check_docker_internal(network, &filter));

        Ok(Self { outcomes })
    }

    /// Runs `iptables-save -t <table>` in the engine host's namespace.
    fn inspect(inspector_image: &str, table: &str) -> Result<String, EngineError> {
        let container = Container::create(&ContainerSpec {
            image: inspector_image.to_owned(),
            attach: Attach::Host,
            // Reading the host's netfilter tables needs these two and nothing
            // more. `--privileged` would also work and is deliberately not
            // used: an inspector that only reads should not be able to write.
            cap_add: vec!["NET_ADMIN".into(), "NET_RAW".into()],
            argv: vec!["iptables-save".into(), "-t".into(), table.to_owned()],
            entrypoint: None,
            sysctls: vec![],
            env_file: None,
            dns: vec![],
            read_only: false,
            tmpfs: vec![],
            volumes: vec![],
        })?;
        container.start()?;
        container.wait(INSPECT_WINDOW)?;
        let logs = container.logs()?;
        container.destroy(INSPECT_WINDOW)?;
        Ok(logs.stdout)
    }

    /// Runs `ip route` in the guest image on the chamber network.
    ///
    /// # `ip` is the entrypoint, not the command
    ///
    /// `argv` alone is not enough. An image that declares an `ENTRYPOINT`
    /// receives `argv` as *arguments to that entrypoint*, so `ip route` never
    /// runs — and the exec-consequence relay image declares one
    /// (`execrelayd`). Without its config in the environment `execrelayd`
    /// refuses to start, writes the refusal to stderr and exits non-zero,
    /// leaving stdout empty. A check that reads "no `default` line" out of an
    /// empty stdout records the assert as *held*, which is how the egress
    /// assert that gates arming came to pass without ever being measured on
    /// every exec-consequence run. Overriding the entrypoint fixes the
    /// general case; [`Preflight::judge_routing_table`] refuses to be fooled
    /// by the specific one.
    fn check_no_default_route(
        network: &Network,
        guest_image: &str,
    ) -> Result<AssertOutcome, EngineError> {
        let container = Container::create(&ContainerSpec {
            image: guest_image.to_owned(),
            attach: Attach::Network {
                network: network.name().to_owned(),
                // The address is irrelevant: this container exists only to
                // print its own routing table.
                ip: None,
            },
            cap_add: vec![],
            entrypoint: Some("ip".to_owned()),
            argv: vec!["route".into()],
            sysctls: vec![],
            env_file: None,
            dns: vec![],
            read_only: false,
            tmpfs: vec![],
            volumes: vec![],
        })?;
        container.start()?;
        let exit_code = container.wait(INSPECT_WINDOW)?;
        let logs = container.logs()?;
        container.destroy(INSPECT_WINDOW)?;

        Ok(Self::judge_routing_table(
            exit_code,
            &logs.stdout,
            &logs.stderr,
        ))
    }

    /// Decides what a routing table — or the absence of one — proves.
    ///
    /// The absence of a `default` line is evidence of isolation **only if a
    /// routing table was printed at all**. A command that never ran produces
    /// exactly the same "no `default` line" as a genuinely isolated cell, and
    /// the two are not the same measurement: the first says nothing, and
    /// reading it as the second is a safety gate reporting a result it never
    /// obtained.
    ///
    /// So two things must both be true before this assert may hold: `ip route`
    /// exited zero, and its stdout contains at least one line that is
    /// recognisably a route. Anything else is *not held* — fail-closed, in
    /// line with the rest of the chamber. That also covers the neighbouring
    /// failures: a guest image with no `ip`, an entrypoint that ignored its
    /// arguments, a container that died before it printed.
    ///
    /// The cost of being wrong in this direction is a legible refusal to arm
    /// carrying the stderr that explains it. The cost of being wrong in the
    /// other direction is a chamber that believes it has no egress.
    fn judge_routing_table(exit_code: i32, stdout: &str, stderr: &str) -> AssertOutcome {
        let destinations: Vec<&str> = stdout.lines().filter_map(route_destination).collect();
        let measured = exit_code == 0 && !destinations.is_empty();
        let has_default = destinations.contains(&"default");

        AssertOutcome {
            which: StructuralAssert::NoDefaultRoute,
            held: measured && !has_default,
            evidence: if measured {
                stdout.to_owned()
            } else {
                format!(
                    "`ip route` printed no routing table and exited {exit_code}, so it was not \
                     measured: the absence of a `default` line here is the absence of any output, \
                     not evidence of isolation.\n  stdout: {}\n  stderr: {}",
                    excerpt(stdout),
                    excerpt(stderr),
                )
            },
        }
    }

    fn check_no_masquerade(network: &Network, nat_table: &str) -> AssertOutcome {
        let offending: Vec<&str> = nat_table
            .lines()
            .filter(|line| line.contains("MASQUERADE") && line.contains(network.subnet()))
            .collect();

        AssertOutcome {
            which: StructuralAssert::NoMasqueradeForSubnet,
            held: offending.is_empty(),
            evidence: if offending.is_empty() {
                format!(
                    "no MASQUERADE line mentions {}; nat table has {} rules",
                    network.subnet(),
                    nat_table.lines().filter(|l| l.starts_with("-A")).count()
                )
            } else {
                offending.join("\n")
            },
        }
    }

    /// The DROP pair is matched against **this network's** bridge, not merely
    /// found somewhere in the chain.
    ///
    /// Docker names a bridge `br-` plus the first twelve characters of the
    /// network id, so the pair can be tied to the network that was actually
    /// raised. Asserting only that `DOCKER-INTERNAL` contains *a* pair would
    /// pass on a host where some unrelated internal network was up and ours was
    /// not — which is the exact state a failed `network create` leaves behind.
    fn check_docker_internal(network: &Network, filter_table: &str) -> AssertOutcome {
        let bridge = bridge_name(network.id());

        let outbound = filter_table.lines().any(|line| {
            line.contains("DOCKER-INTERNAL")
                && line.contains(&format!("-o {bridge}"))
                && line.contains("-j DROP")
        });
        let inbound = filter_table.lines().any(|line| {
            line.contains("DOCKER-INTERNAL")
                && line.contains(&format!("-i {bridge}"))
                && line.contains("-j DROP")
        });

        let found: Vec<&str> = filter_table
            .lines()
            .filter(|line| line.contains("DOCKER-INTERNAL"))
            .collect();

        AssertOutcome {
            which: StructuralAssert::DockerInternalDropPair,
            held: outbound && inbound,
            evidence: format!(
                "bridge={bridge} outbound_drop={outbound} inbound_drop={inbound}\n{}",
                found.join("\n")
            ),
        }
    }

    #[must_use]
    pub fn outcomes(&self) -> &[AssertOutcome] {
        &self.outcomes
    }

    #[must_use]
    pub fn all_held(&self) -> bool {
        self.outcomes.iter().all(|o| o.held)
    }

    /// Collapses to a single pass/fail, keeping every failure's evidence.
    ///
    /// # Errors
    /// [`PreflightFailure`] listing each assert that did not hold.
    pub fn into_result(self) -> Result<(), PreflightFailure> {
        let failures: Vec<AssertOutcome> = self.outcomes.into_iter().filter(|o| !o.held).collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(PreflightFailure { failures })
        }
    }
}

/// The bridge interface Docker creates for a network id.
fn bridge_name(network_id: &str) -> String {
    let short: String = network_id.chars().take(12).collect();
    format!("br-{short}")
}

/// Route types `ip route` may print ahead of the destination.
///
/// `ip` omits `unicast` in the common case and prints the rest, so
/// `blackhole 10.1.0.0/24` is a route line whose first token is not its
/// destination.
const ROUTE_TYPES: [&str; 9] = [
    "unicast",
    "local",
    "broadcast",
    "multicast",
    "throw",
    "unreachable",
    "prohibit",
    "blackhole",
    "nat",
];

/// The destination of one routing-table line, or `None` if the line is not a
/// route at all.
///
/// `ip route` prints one route per line, destination first — `default via
/// 10.66.0.1 dev eth0`, `10.66.0.0/24 dev eth0 scope link src 10.66.0.2` —
/// optionally preceded by a route type. Recognising the destination is what
/// lets the check tell "a table with no default route" from "not a table":
/// a usage banner, a daemon's startup refusal and an empty stream all yield
/// no destinations, and none of them measured anything.
fn route_destination(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    let destination = if ROUTE_TYPES.contains(&first) {
        tokens.next()?
    } else {
        first
    };

    (destination == "default" || is_address_like(destination)).then_some(destination)
}

/// Whether a token could be an address or prefix, in either family.
///
/// Deliberately loose — it separates `10.66.0.0/24` and `fe80::/64` from
/// `dev`, `execrelayd:` and `Usage:`, which is all it is asked to do. Parsing
/// addresses properly here would buy nothing: the question is whether the
/// guest printed a routing table, not whether the engine's addresses are
/// well-formed.
fn is_address_like(token: &str) -> bool {
    let host = token.split('/').next().unwrap_or(token);
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && host.chars().any(|c| c == '.' || c == ':')
}

/// A bounded, trimmed excerpt for an evidence string.
///
/// The stderr of a daemon that refused to start is the single most useful
/// thing in the failure, and also the one field with no bound on its length.
fn excerpt(text: &str) -> String {
    const LIMIT: usize = 400;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "<empty>".to_owned();
    }
    let mut out: String = trimmed.chars().take(LIMIT).collect();
    if trimmed.chars().nth(LIMIT).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_is_br_plus_twelve_id_characters() {
        // Measured against a live engine: network id
        // 0ca7ee56342b2935de87cfd6d36865b1a4969988d5b48f6d12e3ad85a9e6e0ad
        // produced the rules `-A DOCKER-INTERNAL ! -s 10.66.0.0/24 -o
        // br-0ca7ee56342b -j DROP` and its inbound twin.
        assert_eq!(
            bridge_name("0ca7ee56342b2935de87cfd6d36865b1a4969988d5b48f6d12e3ad85a9e6e0ad"),
            "br-0ca7ee56342b"
        );
    }

    /// A shorter id must not panic on the boundary. Not a shape the engine is
    /// known to produce, but `&id[..12]` would panic here and the difference
    /// only shows up on an engine nobody tested against.
    #[test]
    fn bridge_name_survives_a_short_id() {
        assert_eq!(bridge_name("abc"), "br-abc");
    }

    fn network_evidence(subnet: &str, id: &str) -> Network {
        Network::for_test(id.to_owned(), subnet.to_owned())
    }

    #[test]
    fn masquerade_for_another_subnet_is_not_ours() {
        // The default docker0 bridge always has this rule. Reading it as the
        // chamber's would fail every preflight on every machine.
        let nat = "-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n";
        let out =
            Preflight::check_no_masquerade(&network_evidence("10.66.0.0/24", "deadbeef"), nat);
        assert!(out.held, "{}", out.evidence);
    }

    #[test]
    fn masquerade_for_our_subnet_fails_the_assert() {
        let nat = "-A POSTROUTING -s 10.66.0.0/24 ! -o br-x -j MASQUERADE\n";
        let out =
            Preflight::check_no_masquerade(&network_evidence("10.66.0.0/24", "deadbeef"), nat);
        assert!(!out.held);
    }

    #[test]
    fn drop_pair_on_our_bridge_holds() {
        let id = "0ca7ee56342b2935de87";
        let filter = "\
-A DOCKER-INTERNAL ! -s 10.66.0.0/24 -o br-0ca7ee56342b -j DROP
-A DOCKER-INTERNAL ! -d 10.66.0.0/24 -i br-0ca7ee56342b -j DROP
";
        let out = Preflight::check_docker_internal(&network_evidence("10.66.0.0/24", id), filter);
        assert!(out.held, "{}", out.evidence);
    }

    /// The assert this module exists for. Another internal network's DROP pair
    /// is present and ours is absent — a one-sided "does DOCKER-INTERNAL have
    /// a pair?" check passes here, and the chamber has no isolation at all.
    #[test]
    fn another_networks_drop_pair_does_not_satisfy_ours() {
        let filter = "\
-A DOCKER-INTERNAL ! -s 10.99.0.0/24 -o br-ffffffffffff -j DROP
-A DOCKER-INTERNAL ! -d 10.99.0.0/24 -i br-ffffffffffff -j DROP
";
        let out = Preflight::check_docker_internal(
            &network_evidence("10.66.0.0/24", "0ca7ee56342b2935de87"),
            filter,
        );
        assert!(
            !out.held,
            "a pair belonging to another bridge was accepted as ours: {}",
            out.evidence
        );
    }

    /// The routing table a genuinely isolated cell prints: its own subnet and
    /// nothing else. This is the case the assert exists to recognise, and the
    /// one every stricter reading of the output risks breaking.
    #[test]
    fn a_table_without_a_default_route_holds() {
        // Measured on a live `--internal` network, busybox `ip` in alpine
        // 3.20 — two spaces before `src` included, as it prints them.
        let out = Preflight::judge_routing_table(
            0,
            "10.66.0.0/24 dev eth0 scope link  src 10.66.0.2\n",
            "",
        );
        assert!(out.held, "{}", out.evidence);
        assert!(
            out.evidence.contains("10.66.0.0/24"),
            "the table itself must survive as the evidence: {}",
            out.evidence
        );
    }

    #[test]
    fn a_default_route_fails_the_assert() {
        let out = Preflight::judge_routing_table(
            0,
            "default via 10.66.0.1 dev eth0 \n10.66.0.0/24 dev eth0 scope link  src 10.66.0.2\n",
            "",
        );
        assert!(!out.held);
    }

    /// The bug this whole path was rewritten for.
    ///
    /// `execrelayd` is the exec-consequence relay image's `ENTRYPOINT`.
    /// Handed no config it refuses to start, writes that to **stderr** and
    /// exits non-zero — so `ip route` never runs and stdout is empty. Reading
    /// that as "no `default` line, therefore isolated" made the egress assert
    /// that gates arming vacuous on every exec-consequence run: it would have
    /// reported `held` just the same on a host whose cells *did* have a
    /// default route, because it was never looking at a routing table.
    #[test]
    fn an_empty_table_from_a_refusing_entrypoint_does_not_hold() {
        let out = Preflight::judge_routing_table(
            1,
            "",
            "execrelayd: refusing to start — CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 is absent, \
             malformed, or invalid\n",
        );
        assert!(
            !out.held,
            "a check that never ran was reported as isolation confirmed: {}",
            out.evidence
        );
        assert!(
            out.evidence.contains("execrelayd"),
            "the stderr that explains the empty table is the whole diagnosis and must be kept: {}",
            out.evidence
        );
        assert!(
            out.evidence.contains("exited 1"),
            "the exit status is what distinguishes this from an empty table: {}",
            out.evidence
        );
    }

    /// Exit zero is not enough on its own. An entrypoint that accepts any
    /// arguments and prints nothing exits zero, and there is no routing table
    /// behind that silence either.
    #[test]
    fn an_empty_table_does_not_hold_even_on_a_clean_exit() {
        let out = Preflight::judge_routing_table(0, "", "");
        assert!(!out.held, "{}", out.evidence);
    }

    /// Output is not enough either: it has to look like a routing table. A
    /// non-zero exit is the *usual* signal that the command never ran, not a
    /// guaranteed one — busybox prints usage for an unknown applet, and an
    /// image whose entrypoint greets and exits does so successfully.
    #[test]
    fn output_that_is_not_a_routing_table_does_not_hold() {
        let out = Preflight::judge_routing_table(
            0,
            "BusyBox v1.36.1 (2024-01-01) multi-call binary.\nUsage: ip [OPTIONS] ...\n",
            "",
        );
        assert!(
            !out.held,
            "a usage banner was accepted as a routing table: {}",
            out.evidence
        );
    }

    /// The looser shapes `ip route` can print must still read as a table, or
    /// the fail-closed rule above starts refusing genuinely isolated cells.
    #[test]
    fn typed_and_v6_routes_are_still_a_table() {
        let out = Preflight::judge_routing_table(
            0,
            "blackhole 10.1.0.0/24\nfe80::/64 dev eth0 proto kernel metric 256 pref medium\n",
            "",
        );
        assert!(out.held, "{}", out.evidence);
    }

    /// A default route announced with its type spelled out is the same default
    /// route. Matching only on the line's first token would miss it.
    #[test]
    fn a_typed_default_route_is_still_a_default_route() {
        let out = Preflight::judge_routing_table(0, "unicast default via 10.66.0.1 dev eth0\n", "");
        assert!(!out.held, "{}", out.evidence);
    }

    /// One direction is not containment. An outbound-only drop still lets the
    /// host reach into the cell.
    #[test]
    fn a_half_pair_does_not_hold() {
        let id = "0ca7ee56342b2935de87";
        let filter = "-A DOCKER-INTERNAL ! -s 10.66.0.0/24 -o br-0ca7ee56342b -j DROP\n";
        let out = Preflight::check_docker_internal(&network_evidence("10.66.0.0/24", id), filter);
        assert!(!out.held);
    }
}
