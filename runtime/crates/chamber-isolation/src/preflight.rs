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
            sysctls: vec![],
            env_file: None,
            dns: vec![],
            read_only: false,
            tmpfs: vec![],
        })?;
        container.start()?;
        container.wait(INSPECT_WINDOW)?;
        let logs = container.logs()?;
        container.destroy(INSPECT_WINDOW)?;
        Ok(logs.stdout)
    }

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
            argv: vec!["ip".into(), "route".into()],
            sysctls: vec![],
            env_file: None,
            dns: vec![],
            read_only: false,
            tmpfs: vec![],
        })?;
        container.start()?;
        container.wait(INSPECT_WINDOW)?;
        let logs = container.logs()?;
        container.destroy(INSPECT_WINDOW)?;

        let routes = logs.stdout;
        let has_default = routes
            .lines()
            .any(|line| line.split_whitespace().next() == Some("default"));

        Ok(AssertOutcome {
            which: StructuralAssert::NoDefaultRoute,
            held: !has_default,
            evidence: routes,
        })
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
