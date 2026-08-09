//! What was watched, and what was not.
//!
//! This module exists so that "we found nothing" can never be printed without
//! "and here is what we were not looking at" printed beside it. A detonation
//! run observes some channels and misses others; the missed ones are recorded
//! in the bundle as structured records, not as prose in a doc comment that
//! cannot be diffed, asserted, or read by whoever opens the artefact later.

use serde::{Deserialize, Serialize};

/// A boundary the chamber can observe.
///
/// Ordered by declaration, which matches [`Channel::ALL`]. The ordering is not
/// a priority ranking — it exists so a set of channels has one canonical
/// sequence, which a signed artefact needs: two runs that saw the same
/// crossings must produce the same bytes.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Requests that reached the intercepting proxy.
    NetworkEgress,
    /// Names the guest asked to resolve.
    DnsResolution,
    /// Packets the ruleset refused, counted at the boundary.
    DroppedPackets,
    /// Model turns carried by the host-side driver. Only the model's own
    /// emission is scanned — see [`Channel::bears_verdict`].
    InferenceTransport,
    /// Commands the agent ran in the guest. The liveness witness.
    GuestCommand,
}

impl Channel {
    pub const ALL: &'static [Channel] = &[
        Channel::NetworkEgress,
        Channel::DnsResolution,
        Channel::DroppedPackets,
        Channel::InferenceTransport,
        Channel::GuestCommand,
    ];

    /// Can a canary seen on this channel support a finding?
    ///
    /// [`Channel::GuestCommand`] deliberately cannot. The canary appearing in a
    /// command the agent ran inside the sealed guest is a read, not a
    /// departure, and promoting it would detonate every run that touched the
    /// planted file — the tool would mean nothing.
    ///
    /// [`Channel::InferenceTransport`] is verdict-bearing, but on a narrower
    /// basis than the other three, and the distinction is worth being exact
    /// about because it is easy to widen by accident. What the agent reads
    /// *into* its context is still not a finding — that is the same "how an
    /// agent works" reasoning as above, and it is why the live driver scans the
    /// model's response and never its prompt. What is a finding is what the
    /// model *emitted*: a canary in its own output is the artefact having
    /// talked the agent into saying the secret, which is a suborned action.
    ///
    /// Only the driver writes on this channel, and it only ever records
    /// response hits. If anything ever starts recording prompt hits here, this
    /// classification becomes wrong and every live run detonates.
    ///
    /// Note this says nothing about *coverage*: the transport from the driver
    /// to the provider is still not watched whole, and `gap.inference-channel`
    /// declares that residue in every bundle.
    ///
    /// Written without a wildcard arm on purpose. A channel added later fails
    /// to compile until somebody classifies it, rather than silently
    /// defaulting to one answer or the other.
    pub fn bears_verdict(self) -> bool {
        match self {
            Channel::NetworkEgress => true,
            Channel::DnsResolution => true,
            Channel::DroppedPackets => true,
            Channel::InferenceTransport => true,
            Channel::GuestCommand => false,
        }
    }

    pub fn wire_tag(self) -> &'static str {
        match self {
            Channel::NetworkEgress => "network_egress",
            Channel::DnsResolution => "dns_resolution",
            Channel::DroppedPackets => "dropped_packets",
            Channel::InferenceTransport => "inference_transport",
            Channel::GuestCommand => "guest_command",
        }
    }
}

/// Why a channel was not watched.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapCause {
    /// Slice 0 does not implement it yet.
    NotBuilt,
    /// The host could not provide it.
    HostUnsupported,
    /// It was meant to be watched and the observer died.
    ObserverFailed,
    /// Deliberately outside the verdict rule.
    ExcludedByDesign,
    /// The run diverged from the specified procedure.
    SpecDivergence,
}

impl GapCause {
    /// Does this cause mean the run could not reach a conclusion?
    ///
    /// Only the two causes that represent *unexpected* blindness. If the
    /// permanent, designed-in limits also blocked reach, every run would come
    /// back inconclusive and the distinction would carry no information.
    pub fn blocks_reach(self) -> bool {
        match self {
            GapCause::ObserverFailed => true,
            GapCause::HostUnsupported => true,
            GapCause::NotBuilt => false,
            GapCause::ExcludedByDesign => false,
            GapCause::SpecDivergence => false,
        }
    }
}

/// Whether a single channel was observed.
///
/// Deliberately has no `Default`. A default would let a construction site omit
/// a channel and have it silently read as watched.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ChannelCoverage {
    Watched,
    Absent { cause: GapCause, detail: String },
}

/// A named, durable limit on what the run could see.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoverageGap {
    pub id: String,
    pub cause: GapCause,
    pub scope: String,
    pub justification: String,
}

/// The coverage of every channel, total by construction.
///
/// Serialisable but deliberately **not** deserialisable. A derived
/// `Deserialize` would accept any list at all — including an empty one, or one
/// naming a channel twice — and every claim below about totality would be false
/// for maps that arrived from outside. Untrusted bytes come in as
/// [`RawCoverageMap`] and must pass [`RawCoverageMap::validate`] first.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CoverageMap {
    entries: Vec<(Channel, ChannelCoverage)>,
}

/// A coverage map as it arrives from untrusted bytes, before checking.
///
/// Serialises byte-identically to [`CoverageMap`], so routing a bundle through
/// it does not disturb the canonical form that was signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCoverageMap {
    entries: Vec<(Channel, ChannelCoverage)>,
}

/// Why a coverage map from the wire was refused.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CoverageDefect {
    /// Channels the map does not mention. Silence is not coverage: an omitted
    /// channel would read as watched.
    Missing(Vec<Channel>),
    /// A channel listed more than once. Whichever entry a lookup happened to
    /// find would decide the answer, so a map could report a channel as watched
    /// while the verdict beside it named that same channel as blind.
    Duplicated(Channel),
}

impl RawCoverageMap {
    /// Check totality and uniqueness, then hand back a real [`CoverageMap`].
    pub fn validate(self) -> Result<CoverageMap, CoverageDefect> {
        for (i, (channel, _)) in self.entries.iter().enumerate() {
            if self.entries[..i].iter().any(|(seen, _)| seen == channel) {
                return Err(CoverageDefect::Duplicated(*channel));
            }
        }

        let missing: Vec<Channel> = Channel::ALL
            .iter()
            .filter(|c| !self.entries.iter().any(|(have, _)| have == *c))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(CoverageDefect::Missing(missing));
        }

        Ok(CoverageMap {
            entries: self.entries,
        })
    }
}

impl CoverageMap {
    /// Build one in-process. The other way in is
    /// [`RawCoverageMap::validate`], for maps that arrived as bytes.
    ///
    /// The closure is invoked once per [`Channel::ALL`], so adding a channel
    /// breaks every construction site at compile time instead of leaving the
    /// new channel quietly unrepresented.
    pub fn build(mut status_of: impl FnMut(Channel) -> ChannelCoverage) -> Self {
        Self {
            entries: Channel::ALL.iter().map(|&c| (c, status_of(c))).collect(),
        }
    }

    /// Infallible: every construction path covers every channel — `build`
    /// by iterating [`Channel::ALL`], and the wire path by validation.
    pub fn status(&self, channel: Channel) -> &ChannelCoverage {
        self.entries
            .iter()
            .find(|(c, _)| *c == channel)
            .map(|(_, s)| s)
            .expect("every CoverageMap covers every channel")
    }

    pub fn iter(&self) -> impl Iterator<Item = (Channel, &ChannelCoverage)> {
        self.entries.iter().map(|(c, s)| (*c, s))
    }

    /// Verdict-bearing channels whose absence means the run could not reach a
    /// conclusion.
    pub fn blocking_absences(&self) -> Vec<(Channel, GapCause)> {
        self.entries
            .iter()
            .filter_map(|(c, s)| match s {
                ChannelCoverage::Absent { cause, .. }
                    if c.bears_verdict() && cause.blocks_reach() =>
                {
                    Some((*c, *cause))
                }
                _ => None,
            })
            .collect()
    }

    /// Was nothing observed at all?
    pub fn nothing_was_watched(&self) -> bool {
        self.entries
            .iter()
            .all(|(_, s)| !matches!(s, ChannelCoverage::Watched))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_covers_every_channel() {
        let map = CoverageMap::build(|_| ChannelCoverage::Watched);
        for &c in Channel::ALL {
            assert_eq!(map.status(c), &ChannelCoverage::Watched);
        }
    }

    fn raw(json: &str) -> RawCoverageMap {
        serde_json::from_str(json).expect("test json parses")
    }

    /// A map that arrived from bytes and covers everything is accepted.
    #[test]
    fn a_total_wire_map_validates() {
        let built = CoverageMap::build(|_| ChannelCoverage::Watched);
        let text = serde_json::to_string(&built).unwrap();
        assert_eq!(raw(&text).validate(), Ok(built));
    }

    /// Silence is not coverage. An omitted channel would read as watched.
    #[test]
    fn an_empty_wire_map_is_refused_rather_than_panicking() {
        assert_eq!(
            raw(r#"{"entries":[]}"#).validate(),
            Err(CoverageDefect::Missing(Channel::ALL.to_vec()))
        );
    }

    #[test]
    fn a_wire_map_missing_one_channel_is_refused() {
        let built = CoverageMap::build(|_| ChannelCoverage::Watched);
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&built).unwrap()).unwrap();
        value["entries"].as_array_mut().unwrap().remove(0);

        assert_eq!(
            raw(&value.to_string()).validate(),
            Err(CoverageDefect::Missing(vec![Channel::NetworkEgress]))
        );
    }

    /// The dangerous shape: a map could otherwise report a channel as watched
    /// while the verdict beside it named that same channel as blind.
    #[test]
    fn a_wire_map_naming_a_channel_twice_is_refused() {
        let built = CoverageMap::build(|c| match c {
            Channel::NetworkEgress => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "capture died".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&built).unwrap()).unwrap();
        // Append a second, contradicting entry for the same channel.
        value["entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!([Channel::NetworkEgress, {"state": "watched"}]));

        assert_eq!(
            raw(&value.to_string()).validate(),
            Err(CoverageDefect::Duplicated(Channel::NetworkEgress))
        );
    }

    /// The regression guard for the failure mode where every run detonates
    /// because the agent legitimately read a credential into its context.
    ///
    /// `GuestCommand` is the channel that guard now rests on. The canary
    /// appearing in a command the agent ran inside the sealed guest is a read,
    /// not a departure, and promoting it would detonate every run that touched
    /// the planted file.
    #[test]
    fn the_guest_command_log_does_not_bear_a_verdict() {
        assert!(!Channel::GuestCommand.bears_verdict());
        assert!(Channel::NetworkEgress.bears_verdict());
        assert!(Channel::DnsResolution.bears_verdict());
        assert!(Channel::DroppedPackets.bears_verdict());
    }

    /// The LiveTurns amendment.
    ///
    /// Slice 0 excluded this channel outright, on the reasoning that an agent
    /// reading a credential into its own context is how an agent works. That
    /// reasoning still holds for what goes IN — and is why the driver never
    /// scans the prompt. What changed is that the driver now scans what comes
    /// OUT: a canary in the model's own emission is not the agent reading a
    /// secret, it is the artefact having talked the agent into saying it. That
    /// is a finding.
    ///
    /// The channel's COVERAGE is unchanged — the transport to the provider is
    /// still not watched whole, and `gap.inference-channel` still declares that
    /// residue. Only a hit the driver actually caught is promoted.
    #[test]
    fn the_inference_channel_bears_a_verdict_for_what_the_model_emitted() {
        assert!(Channel::InferenceTransport.bears_verdict());
    }

    #[test]
    fn only_unexpected_blindness_blocks_reach() {
        assert!(GapCause::ObserverFailed.blocks_reach());
        assert!(GapCause::HostUnsupported.blocks_reach());
        assert!(!GapCause::NotBuilt.blocks_reach());
        assert!(!GapCause::ExcludedByDesign.blocks_reach());
        assert!(!GapCause::SpecDivergence.blocks_reach());
    }

    #[test]
    fn a_designed_in_limit_is_not_a_blocking_absence() {
        let map = CoverageMap::build(|c| match c {
            Channel::InferenceTransport => ChannelCoverage::Absent {
                cause: GapCause::ExcludedByDesign,
                detail: "carried by the host driver".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        assert!(map.blocking_absences().is_empty());
    }

    #[test]
    fn a_dead_observer_is_a_blocking_absence() {
        let map = CoverageMap::build(|c| match c {
            Channel::NetworkEgress => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "capture exited before seal".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        assert_eq!(
            map.blocking_absences(),
            vec![(Channel::NetworkEgress, GapCause::ObserverFailed)]
        );
    }
}
