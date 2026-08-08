//! The limits every Slice 0 bundle must declare.
//!
//! A tool that reports "no finding" while quietly not looking at half the
//! available channels is worse than no tool, because it converts an unknown
//! into a reassurance. So the things this build cannot see are enumerated
//! here, in code, and emitted into **every** bundle — not left in a README
//! that ships separately from the artefact and rots at a different rate.
//!
//! These are the *permanent, designed-in* limits. They are distinct from a
//! channel that was supposed to be watched and was not, which is recorded as
//! an [`crate::ChannelCoverage::Absent`] with a cause that blocks the run from
//! reaching a conclusion at all.

use crate::coverage::{CoverageGap, GapCause};

/// The gaps this build always has.
///
/// Callers include these in every bundle. `chamber-run` should append any
/// run-specific gaps to them rather than replacing them.
pub fn slice0() -> Vec<CoverageGap> {
    vec![
        CoverageGap {
            id: "gap.ledger-integrity".into(),
            cause: GapCause::NotBuilt,
            scope: "The observation log is written by the capture process and read by the host. \
                    There is no collector-side signature and no hash chain."
                .into(),
            justification: "Re-derivation at decode defends the verdict FIELD, not the ledger. \
                            An attacker who deletes an entry and renumbers the rest produces an \
                            internally consistent bundle that opens as no_finding. Sequence \
                            contiguity catches carelessness, not tampering. Slice 0 is not \
                            tamper-proof and must not be described as such."
                .into(),
        },
        CoverageGap {
            id: "gap.inference-channel".into(),
            cause: GapCause::ExcludedByDesign,
            scope: "Model turns are carried by the host-side driver and are observed, but are \
                    excluded from the verdict rule."
                .into(),
            justification: "An agent reading a credential into its own context is how an agent \
                            works, not evidence of exfiltration; treating it as a finding would \
                            detonate every run. The consequence is that a payload which \
                            exfiltrates THROUGH the model transport itself is unobserved as a \
                            finding."
                .into(),
        },
        CoverageGap {
            id: "gap.no-baseline-arm".into(),
            cause: GapCause::NotBuilt,
            scope: "One run, one arm. No benign control run to diff against.".into(),
            justification: "Without a baseline, \"the agent would have done that anyway\" is \
                            unanswerable. A finding here means a planted token crossed the \
                            boundary, not that the artefact caused it to."
                .into(),
        },
        CoverageGap {
            id: "gap.dormant-payload".into(),
            cause: GapCause::ExcludedByDesign,
            scope: "One run, a bounded number of turns, one clock, one hostname.".into(),
            justification: "Payloads conditioned on the date, the host, or the number of prior \
                            runs will not fire here. Absence of a finding says nothing about \
                            what a different run would show."
                .into(),
        },
        CoverageGap {
            id: "gap.sandbox-aware".into(),
            cause: GapCause::ExcludedByDesign,
            scope: "An artefact that detects the chamber and behaves while observed.".into(),
            justification: "Inherited wholesale from decades of malware detonation. There is no \
                            general answer, and claiming one would be dishonest."
                .into(),
        },
        CoverageGap {
            id: "gap.udp-quic".into(),
            cause: GapCause::NotBuilt,
            scope: "QUIC (UDP 443) and DNS-over-QUIC (UDP 853) are dropped and counted, not \
                    decoded."
                .into(),
            justification: "No SNI or QNAME is recovered from a QUIC initial packet, so such \
                            traffic is visible as volume at layer 3 and not as content."
                .into(),
        },
        CoverageGap {
            id: "gap.filesystem-channel".into(),
            cause: GapCause::NotBuilt,
            scope: "No filesystem or exec observation inside the guest beyond the tool-call log."
                .into(),
            justification: "Data staged on disk for some later run, rather than sent, is \
                            unobserved."
                .into(),
        },
        CoverageGap {
            id: "gap.chained-encodings".into(),
            cause: GapCause::NotBuilt,
            scope: "Raw, hex, percent, base64, base64url and DNS-label-joined forms are searched. \
                    Nested or chained encodings are not."
                .into(),
            justification: "A token compressed then base64-encoded, or run through a custom \
                            alphabet, would not match. The searched set is a floor, not a proof \
                            of coverage."
                .into(),
        },
        CoverageGap {
            id: "gap.supervisor-death".into(),
            cause: GapCause::NotBuilt,
            scope: "If the host orchestrator dies, no bundle is produced at all.".into(),
            justification: "A guest dying still seals a bundle; the supervisor dying does not. \
                            Do not read the single-writer design as covering this case."
                .into(),
        },
        CoverageGap {
            id: "gap.kernel-boundary".into(),
            cause: GapCause::ExcludedByDesign,
            scope: "The guest shares a kernel with the host.".into(),
            justification: "Namespace and capability isolation are kernel-enforced, so a kernel \
                            escape defeats every layer at once. This contains a hostile \
                            prompt-driven agent, not a kernel exploit."
                .into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_gap_is_identified_uniquely() {
        let ids: HashSet<_> = slice0().into_iter().map(|g| g.id).collect();
        assert_eq!(ids.len(), slice0().len(), "gap ids must be unique");
    }

    /// The limit most likely to be overstated away. If Slice 0 ever stops
    /// declaring it, someone is about to call the bundle tamper-proof.
    #[test]
    fn the_ledger_integrity_limit_is_always_declared() {
        assert!(
            slice0().iter().any(|g| g.id == "gap.ledger-integrity"),
            "a bundle that does not declare this invites being read as tamper-proof"
        );
    }

    /// A permanent limit must not make every run inconclusive — otherwise the
    /// distinction between "designed-in" and "something broke" carries no
    /// information and gets ignored.
    #[test]
    fn no_permanent_gap_blocks_a_run_from_reaching_a_conclusion() {
        for gap in slice0() {
            assert!(
                !gap.cause.blocks_reach(),
                "{} would make every run inconclusive",
                gap.id
            );
        }
    }

    /// Each gap has to say what was not covered and why, in terms a reader who
    /// did not run the tool can act on. A bare id is a checkbox.
    #[test]
    fn every_gap_explains_itself() {
        for gap in slice0() {
            assert!(gap.id.starts_with("gap."), "{} is misnamed", gap.id);
            assert!(
                gap.scope.len() > 30,
                "{} does not say what was uncovered",
                gap.id
            );
            assert!(
                gap.justification.len() > 60,
                "{} does not say why it matters",
                gap.id
            );
        }
    }
}
