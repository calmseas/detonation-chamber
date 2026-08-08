//! The boundary observer.
//!
//! Everything the guest sends passes through here: an intercepting proxy that
//! terminates TLS and records the whole plaintext request, and a DNS sink that
//! logs every name asked for. Both write into one observation sequence, which
//! is why they are one process and one crate — a shared monotonic ordinal is
//! what makes interleaving recoverable from the bundle alone, and two
//! independent daemons writing two log formats cannot produce it.
//!
//! # Built so far
//!
//! - [`canary`] — matching planted tokens across the encodings an artefact
//!   might use. Pure, synchronous, and independently testable.
//!
//! The proxy, the DNS sink and the observation writer are not built yet. Two
//! constraints on writing them, recorded here because both are recoverable
//! only if honoured in order:
//!
//! 1. **Write the CONNECT-passthrough test before the refusal logic.** The
//!    proxy library dispatches its request handler for the outer CONNECT
//!    *before* the tunnel exists. An "empty allowlist, so refuse everything"
//!    handler therefore refuses the CONNECT, TLS is never intercepted, and the
//!    run produces a log full of CONNECT lines and no plaintext at all — while
//!    looking like it worked.
//! 2. **An intercept predicate returning `false` means "tunnel transparently",
//!    not "block".** It opens a real socket to the origin and copies bytes
//!    both ways. A `false` in either predicate turns the containment proxy into
//!    a working egress path.

pub mod canary;
#[cfg(feature = "observer")]
pub mod dns;
#[cfg(feature = "observer")]
pub mod proxy;
pub mod recorder;
pub mod writer;

pub use canary::{Canary, CanarySet};
#[cfg(feature = "observer")]
pub use dns::DnsSink;
#[cfg(feature = "observer")]
pub use proxy::InterceptingProxy;
pub use recorder::Recorder;
pub use writer::{LedgerFile, LedgerWriter, read_ledger};
