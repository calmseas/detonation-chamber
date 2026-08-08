//! What the adversary probe reported, and how to read it.
//!
//! # Absence is not containment
//!
//! The governing rule of this module: **a row that is missing must never read
//! as a row that was blocked.** They are the two states a containment suite
//! most needs to tell apart, and they are trivially confusable — a probe that
//! died on its second technique, an image missing the tool a row shells out to,
//! a typo in a row name, all produce *no output for that row*, and a reader
//! that treats "not reached" as "was stopped" turns each of them into a
//! confident green tick.
//!
//! So [`ProbeReport::reach`] returns an `Option` and every caller must say what
//! it means by absence. [`ProbeReport::require`] is the form that refuses to
//! guess.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

/// One technique in the probe table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowId {
    /// Connect to an off-subnet address with no DNS involved at all.
    TcpIpLiteral,
    /// A DNS query straight at a public resolver, bypassing the cell's own.
    UdpDnsDirect,
    /// The capture host, on a port it does not serve.
    TcpCaptureWrongPort,
    /// ICMP echo to an off-subnet address.
    IcmpEcho,
    /// An HTTP(S) fetch.
    Https,
    /// Name resolution through the runtime's real resolver path.
    Getaddrinfo,
    /// A datagram to a high UDP port — the QUIC/HTTP-3 shape.
    UdpHigh,
    /// Attempt to destroy the ruleset that contains the cell.
    NftFlush,
    /// Attempt to install a default route.
    IpRouteAdd,
    /// Attempt to read the ruleset.
    NftList,
    /// The capability bounding set the cell actually holds.
    Capbnd,
}

impl fmt::Display for RowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::TcpIpLiteral => "tcp_ip_literal",
            Self::UdpDnsDirect => "udp_dns_direct",
            Self::TcpCaptureWrongPort => "tcp_capture_wrong_port",
            Self::IcmpEcho => "icmp_echo",
            Self::Https => "https",
            Self::Getaddrinfo => "getaddrinfo",
            Self::UdpHigh => "udp_high",
            Self::NftFlush => "nft_flush",
            Self::IpRouteAdd => "ip_route_add",
            Self::NftList => "nft_list",
            Self::Capbnd => "capbnd",
        };
        f.write_str(name)
    }
}

/// Whether a technique got where it was aimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// The technique worked. In an unarmed run this is the required result; in
    /// an armed one it is a containment failure.
    Reached,
    /// The technique did not work. Meaningful *only* against a baseline in
    /// which the same row, aimed the same way, reached.
    Blocked,
}

/// One line of the probe's output.
#[derive(Debug, Clone, Deserialize)]
pub struct ProbeRow {
    pub row: RowId,
    #[serde(rename = "ok")]
    pub reached: bool,
    pub target: String,
    pub detail: String,
}

impl ProbeRow {
    #[must_use]
    pub fn reach(&self) -> Reach {
        if self.reached {
            Reach::Reached
        } else {
            Reach::Blocked
        }
    }
}

/// A probe output line that could not be read.
#[derive(Debug)]
pub struct MalformedRow {
    pub line: String,
    pub detail: String,
}

impl fmt::Display for MalformedRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unreadable probe line {:?}: {}", self.line, self.detail)
    }
}

impl std::error::Error for MalformedRow {}

/// Everything one probe run reported.
#[derive(Debug, Default)]
pub struct ProbeReport {
    rows: BTreeMap<RowId, ProbeRow>,
}

impl ProbeReport {
    /// Reads the probe's stdout, one JSON object per line.
    ///
    /// Blank lines are skipped; anything else that will not parse is an error
    /// rather than a skipped line. A probe whose output drifted from this
    /// reader is a probe nobody is actually reading, and silently ignoring the
    /// lines it emits is how that goes unnoticed for months.
    ///
    /// # Errors
    /// [`MalformedRow`] naming the first line that would not parse.
    pub fn parse(stdout: &str) -> Result<Self, MalformedRow> {
        let mut rows = BTreeMap::new();
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parsed: ProbeRow = serde_json::from_str(line).map_err(|e| MalformedRow {
                line: line.to_owned(),
                detail: e.to_string(),
            })?;
            rows.insert(parsed.row, parsed);
        }
        Ok(Self { rows })
    }

    /// The reach of one row, or `None` if the probe never reported it.
    ///
    /// Callers must handle `None` explicitly. See the module note: absence is
    /// not containment.
    #[must_use]
    pub fn reach(&self, row: RowId) -> Option<Reach> {
        self.rows.get(&row).map(ProbeRow::reach)
    }

    #[must_use]
    pub fn get(&self, row: RowId) -> Option<&ProbeRow> {
        self.rows.get(&row)
    }

    /// The row, or an explanation naming what the probe *did* report.
    ///
    /// # Errors
    /// A message listing the rows that were present, which is the information
    /// needed to tell a crashed probe from a renamed row.
    pub fn require(&self, row: RowId) -> Result<&ProbeRow, String> {
        self.rows.get(&row).ok_or_else(|| {
            let present: Vec<String> = self.rows.keys().map(ToString::to_string).collect();
            format!(
                "probe never reported row `{row}` — it cannot be treated as blocked. \
                 Rows actually reported: [{}]",
                present.join(", ")
            )
        })
    }

    pub fn rows(&self) -> impl Iterator<Item = &ProbeRow> {
        self.rows.values()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNARMED_BASELINE: &str = r#"
{"row":"tcp_ip_literal","ok":true,"target":"8.8.8.8:443","detail":"connected"}
{"row":"udp_dns_direct","ok":true,"target":"1.1.1.1/probe.invalid","detail":"answered status=NXDOMAIN"}
{"row":"icmp_echo","ok":true,"target":"8.8.8.8","detail":"reply received"}
{"row":"https","ok":true,"target":"http://10.77.0.50/","detail":"http_code=200"}
{"row":"getaddrinfo","ok":true,"target":"anything.example","detail":"resolved_to=10.77.0.50"}
{"row":"udp_high","ok":true,"target":"8.8.8.8:443","detail":"datagram accepted by stack"}
"#;

    /// The literal output of the first unarmed run on a live engine.
    #[test]
    fn reads_the_measured_unarmed_baseline() {
        let report = ProbeReport::parse(UNARMED_BASELINE).expect("baseline parses");
        for row in [
            RowId::TcpIpLiteral,
            RowId::UdpDnsDirect,
            RowId::IcmpEcho,
            RowId::Https,
            RowId::Getaddrinfo,
            RowId::UdpHigh,
        ] {
            assert_eq!(report.reach(row), Some(Reach::Reached), "row {row}");
        }
    }

    #[test]
    fn a_blocked_row_reads_as_blocked() {
        let report = ProbeReport::parse(
            r#"{"row":"tcp_ip_literal","ok":false,"target":"8.8.8.8:443","detail":"rc=1"}"#,
        )
        .unwrap();
        assert_eq!(report.reach(RowId::TcpIpLiteral), Some(Reach::Blocked));
    }

    /// The distinction the whole module exists for.
    #[test]
    fn a_missing_row_is_not_a_blocked_row() {
        let report = ProbeReport::parse("").unwrap();
        assert_eq!(report.reach(RowId::TcpIpLiteral), None);
        assert_ne!(report.reach(RowId::TcpIpLiteral), Some(Reach::Blocked));
    }

    /// The failure names what was there instead, because "row missing" alone
    /// does not distinguish a crashed probe from a renamed row.
    #[test]
    fn require_reports_which_rows_were_present() {
        let report = ProbeReport::parse(
            r#"{"row":"icmp_echo","ok":true,"target":"8.8.8.8","detail":"reply"}"#,
        )
        .unwrap();
        let err = report.require(RowId::TcpIpLiteral).unwrap_err();
        assert!(err.contains("tcp_ip_literal"), "{err}");
        assert!(err.contains("icmp_echo"), "{err}");
    }

    /// A probe whose output drifted must fail loudly, not lose the row.
    #[test]
    fn an_unknown_row_name_is_an_error_not_a_skip() {
        let err = ProbeReport::parse(r#"{"row":"teleport","ok":true,"target":"x","detail":"y"}"#)
            .unwrap_err();
        assert!(err.line.contains("teleport"));
    }

    #[test]
    fn truncated_output_fails_rather_than_dropping_the_line() {
        let truncated = r#"{"row":"tcp_ip_literal","ok":true,"target":"8.8.8"#;
        assert!(ProbeReport::parse(truncated).is_err());
    }

    #[test]
    fn blank_lines_are_skipped() {
        let report = ProbeReport::parse("\n\n").unwrap();
        assert!(report.is_empty());
    }
}
