//! A named grouping of what the guest is told, network-side and exec-side.

use crate::consequence::ConsequencePlan;
use crate::exec_consequence::ExecConsequencePlan;

/// What a detonation plan's boundary tells the guest, across both
/// interception surfaces.
///
/// Groups `DetonationPlan`'s two independently-optional fabrication plans
/// under one name. `consequence` governs the network boundary's answers (see
/// [`crate::consequence`]); `exec_consequence` governs the guest's
/// exec-interception relay (see [`crate::exec_consequence`]). They are not
/// redundant and not merged: a plan may set either, both, or neither, and
/// `exec_consequence` additionally has a hard coupling to guest-image
/// identity enforced at arming (`check_exec_relay_capability` in
/// `chamber-run`) — this type changes nothing about that validation, only
/// where the two fields live.
#[derive(Debug, Clone, Default)]
pub struct RealismProfile {
    /// `None` — the default — is the `403 blocked by the detonation chamber`
    /// refusal. `Some` turns on consequence mode: the boundary fabricates a
    /// response so the artefact's request appears to succeed, removing the
    /// tell that a 403 from every host would otherwise hand an eval-aware
    /// model. It grants no egress — the response is built inside the
    /// observer, and the request is discarded exactly as a refused one is.
    pub consequence: Option<ConsequencePlan>,
    /// `None` is "no exec interception". `Some` requires a guest image that
    /// carries the exec-relay entrypoint — arming refuses in either
    /// direction if this and the image disagree.
    pub exec_consequence: Option<ExecConsequencePlan>,
}
