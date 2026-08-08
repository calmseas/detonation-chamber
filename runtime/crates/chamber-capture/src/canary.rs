//! Finding a planted token in something that crossed the boundary.
//!
//! A canary is a fake credential planted in the guest — in the environment and
//! in a `.env` file — with a value unique to this run. The guest's environment
//! starts empty, so the token has no innocent way of being there: seeing it at
//! the boundary means the artefact read it *and* sent it.
//!
//! # Why this searches for more than the plaintext
//!
//! A matcher that only looks for the raw token catches only an artefact that
//! exfiltrates in plaintext. Since we also write the fixtures, a
//! plaintext-only matcher would make the positive test self-fulfilling: it
//! would pass because we chose to send the token in the clear, not because the
//! tool can detect exfiltration. So the encodings are part of Slice 0 rather
//! than a later refinement.
//!
//! # The base64 alignment problem
//!
//! Base64 encodes three bytes at a time, so the encoding of a token depends on
//! how many bytes precede it. `base64(token)` appears verbatim only when the
//! token happens to start on a three-byte boundary of the payload. An artefact
//! that base64-encodes a whole JSON body will, two times in three, produce
//! output containing no substring equal to `base64(token)` at all.
//!
//! So each token is searched for in all three alignments, using only the
//! groups that encode token bytes exclusively — the stable middle. That is the
//! difference between a matcher that works on real payloads and one that works
//! on payloads we wrote.

use chamber_evidence::{CanaryHit, HitEncoding, HitField};
use data_encoding::{BASE64, BASE64URL};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

/// A planted token and the label the bundle will refer to it by.
#[derive(Clone, Debug)]
pub struct Canary {
    label: String,
    token: String,
}

impl Canary {
    pub fn new(label: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            token: token.into(),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    // No public accessor for the token. The planting layer will need one when
    // it is built and can add it with the visibility it actually requires;
    // until then the value stays inside this module, and the evidence bundle
    // records only the label — see the redaction note on
    // `chamber_evidence::bundle`.

    /// Every byte string whose presence would evidence this token, paired with
    /// the encoding to report.
    fn needles(&self) -> Vec<(HitEncoding, Vec<u8>)> {
        let raw = self.token.as_bytes();
        let mut needles = vec![
            (HitEncoding::Raw, raw.to_vec()),
            (HitEncoding::Hex, hex::encode(raw).into_bytes()),
            (HitEncoding::Hex, hex::encode_upper(raw).into_bytes()),
            (
                HitEncoding::Percent,
                utf8_percent_encode(&self.token, NON_ALPHANUMERIC)
                    .to_string()
                    .into_bytes(),
            ),
        ];

        for alignment in 0..3 {
            if let Some(n) = aligned_fragment(raw, alignment, Base64Flavour::Standard) {
                needles.push((HitEncoding::Base64, n));
            }
            if let Some(n) = aligned_fragment(raw, alignment, Base64Flavour::Url) {
                needles.push((HitEncoding::Base64Url, n));
            }
        }

        needles.sort_by(|a, b| a.1.cmp(&b.1));
        needles.dedup_by(|a, b| a.1 == b.1);
        needles
    }
}

#[derive(Copy, Clone)]
enum Base64Flavour {
    Standard,
    Url,
}

/// The part of `base64(prefix ++ token)` that encodes token bytes only.
///
/// With `alignment` filler bytes in front, the first three-byte group holding
/// nothing but token bytes begins at group `ceil(alignment/3)`, and the last
/// such group ends at `floor((alignment + len)/3)`. Everything between is
/// invariant to whatever surrounds the token in the real payload, which is
/// what makes it a usable needle.
///
/// Returns `None` when the token is too short to fill a whole group at this
/// alignment — there is simply nothing stable to look for.
fn aligned_fragment(token: &[u8], alignment: usize, flavour: Base64Flavour) -> Option<Vec<u8>> {
    let start_group = alignment.div_ceil(3);
    let end_group = (alignment + token.len()) / 3;
    if end_group <= start_group {
        return None;
    }

    let mut buf = vec![b'A'; alignment];
    buf.extend_from_slice(token);
    let encoded = match flavour {
        Base64Flavour::Standard => BASE64.encode(&buf),
        Base64Flavour::Url => BASE64URL.encode(&buf),
    };

    let (from, to) = (start_group * 4, end_group * 4);
    encoded.as_bytes().get(from..to).map(<[u8]>::to_vec)
}

/// The tokens planted for one run.
#[derive(Clone, Debug, Default)]
pub struct CanarySet {
    canaries: Vec<Canary>,
}

impl CanarySet {
    pub fn new(canaries: Vec<Canary>) -> Self {
        Self { canaries }
    }

    pub fn is_empty(&self) -> bool {
        self.canaries.is_empty()
    }

    /// Search one field for every planted token.
    ///
    /// `haystack` is raw bytes because bodies frequently are not valid UTF-8,
    /// and a matcher that required text would silently skip exactly the
    /// payloads most worth inspecting.
    ///
    /// Offsets are byte offsets into `haystack` as given. Callers must scan the
    /// **whole** body before any clipping: a token beyond the retention limit
    /// is still a token that left.
    pub fn scan(&self, field: HitField, haystack: &[u8]) -> Vec<CanaryHit> {
        let mut hits = Vec::new();

        for canary in &self.canaries {
            for (encoding, needle) in canary.needles() {
                if let Some(offset) = find(haystack, &needle) {
                    hits.push(CanaryHit {
                        label: canary.label.clone(),
                        field: field.clone(),
                        encoding,
                        offset: offset as u64,
                    });
                }
            }

            // Label-joining is its own pass: the token is not present as a
            // contiguous run of bytes, so no needle can find it.
            if let Some(offset) = find_across_labels(haystack, canary.token.as_bytes()) {
                hits.push(CanaryHit {
                    label: canary.label.clone(),
                    field: field.clone(),
                    encoding: HitEncoding::LabelJoin,
                    offset: offset as u64,
                });
            }
        }

        hits
    }

    /// Search a DNS name, honouring the case-insensitivity of DNS itself.
    ///
    /// This is not a convenience. A resolver is free to alter the case of a
    /// name — many deliberately do — and an attacker can simply send the token
    /// lower-cased, since `AKIA….evil.example` and `akia….evil.example`
    /// resolve identically. A case-sensitive scan therefore misses DNS
    /// exfiltration outright, which is exactly the channel most worth
    /// catching, because it needs no reply to succeed.
    ///
    /// Only the forms that survive case-folding are matched loosely: the raw
    /// token and the label-joined token, plus hex, which is already searched in
    /// both cases. Base64 and percent-encoding stay case-sensitive — folding
    /// them would compare strings that are not the same bytes, and an attacker
    /// cannot use them through a case-insensitive channel anyway.
    pub fn scan_dns_name(&self, name: &str) -> Vec<CanaryHit> {
        let folded = name.to_ascii_lowercase();
        let mut hits = self.scan(HitField::QName, name.as_bytes());

        for canary in &self.canaries {
            if hits.iter().any(|h| h.label == canary.label) {
                continue; // already found in its exact form
            }

            let token = canary.token.to_ascii_lowercase();
            if let Some(offset) = find(folded.as_bytes(), token.as_bytes()) {
                hits.push(CanaryHit {
                    label: canary.label.clone(),
                    field: HitField::QName,
                    encoding: HitEncoding::Raw,
                    offset: offset as u64,
                });
            } else if let Some(offset) = find_across_labels(folded.as_bytes(), token.as_bytes()) {
                hits.push(CanaryHit {
                    label: canary.label.clone(),
                    field: HitField::QName,
                    encoding: HitEncoding::LabelJoin,
                    offset: offset as u64,
                });
            }
        }

        hits
    }

    /// Did anything match, without building the hit records?
    pub fn matches(&self, haystack: &[u8]) -> bool {
        !self.scan(HitField::Body, haystack).is_empty()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Find a token that has been split across DNS labels.
///
/// `AKIAIOSF.ODNN7EXA.MPLE.evil.example` carries the whole token while
/// containing no contiguous copy of it. Separators are dropped from the
/// haystack and the search runs against what remains; the reported offset is
/// into the original bytes, so it still points at something a reader can find.
fn find_across_labels(haystack: &[u8], token: &[u8]) -> Option<usize> {
    const SEPARATORS: &[u8] = b".-";

    if token.is_empty() {
        return None;
    }

    let mut squashed = Vec::with_capacity(haystack.len());
    let mut origin = Vec::with_capacity(haystack.len());
    for (i, b) in haystack.iter().enumerate() {
        if !SEPARATORS.contains(b) {
            squashed.push(*b);
            origin.push(i);
        }
    }

    // A contiguous match would already have been found by the raw needle, and
    // reporting it twice under two encodings would overstate the evidence.
    let at = find(&squashed, token)?;
    let original_start = origin[at];
    let original_end = origin[at + token.len() - 1];
    if original_end - original_start + 1 == token.len() {
        return None;
    }

    Some(original_start)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "AKIAIOSFODNN7EXAMPLE";

    fn set() -> CanarySet {
        CanarySet::new(vec![Canary::new("aws-key", TOKEN)])
    }

    fn encodings_found(haystack: &[u8]) -> Vec<HitEncoding> {
        let mut e: Vec<_> = set()
            .scan(HitField::Body, haystack)
            .into_iter()
            .map(|h| h.encoding)
            .collect();
        e.sort_by_key(|x| format!("{x:?}"));
        e.dedup();
        e
    }

    #[test]
    fn plaintext_is_found_and_the_offset_points_at_it() {
        let body = format!("{{\"key\":\"{TOKEN}\"}}");
        let hits = set().scan(HitField::Body, body.as_bytes());

        let raw: Vec<_> = hits
            .iter()
            .filter(|h| h.encoding == HitEncoding::Raw)
            .collect();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].label, "aws-key");
        assert_eq!(
            &body.as_bytes()[raw[0].offset as usize..][..TOKEN.len()],
            TOKEN.as_bytes()
        );
    }

    #[test]
    fn nothing_matches_a_clean_body() {
        assert!(set().scan(HitField::Body, b"{\"ok\":true}").is_empty());
    }

    /// The matcher must be broken-closed: a body that merely resembles the
    /// token is not a finding.
    #[test]
    fn a_near_miss_is_not_a_hit() {
        assert!(
            set()
                .scan(HitField::Body, b"AKIAIOSFODNN7EXAMPL")
                .is_empty()
        );
        assert!(
            set()
                .scan(HitField::Body, b"BKIAIOSFODNN7EXAMPLE")
                .is_empty()
        );
    }

    #[test]
    fn hex_is_found_in_either_case() {
        assert!(encodings_found(hex::encode(TOKEN).as_bytes()).contains(&HitEncoding::Hex));
        assert!(encodings_found(hex::encode_upper(TOKEN).as_bytes()).contains(&HitEncoding::Hex));
    }

    /// A secret access key, unlike a key *id*, carries symbols — which is what
    /// makes percent-encoding a distinct form rather than a no-op.
    const SYMBOL_TOKEN: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    #[test]
    fn percent_encoding_is_found() {
        let set = CanarySet::new(vec![Canary::new("aws-secret", SYMBOL_TOKEN)]);
        let url = format!(
            "/collect?d={}",
            utf8_percent_encode(SYMBOL_TOKEN, NON_ALPHANUMERIC)
        );

        let hits = set.scan(HitField::Target, url.as_bytes());
        assert!(
            hits.iter().any(|h| h.encoding == HitEncoding::Percent),
            "percent form missed: {hits:?}"
        );
    }

    /// An all-alphanumeric token percent-encodes to itself, so reporting a
    /// separate `Percent` hit would claim two pieces of evidence where the
    /// bytes are one. The raw hit stands alone.
    #[test]
    fn an_alphanumeric_token_is_not_double_reported_as_percent_encoded() {
        assert_eq!(
            utf8_percent_encode(TOKEN, NON_ALPHANUMERIC).to_string(),
            TOKEN,
            "fixture assumption: this token has no percent-encodable characters"
        );

        let found = encodings_found(TOKEN.as_bytes());
        assert!(found.contains(&HitEncoding::Raw));
        assert!(!found.contains(&HitEncoding::Percent));
    }

    /// The test that matters most in this module.
    ///
    /// A payload that base64-encodes a whole body puts the token at an
    /// arbitrary alignment. Two of these three cases contain no substring
    /// equal to `base64(TOKEN)`, so a naive matcher finds nothing.
    #[test]
    fn base64_is_found_at_every_alignment() {
        for prefix in ["", "x", "xy"] {
            let payload = BASE64.encode(format!("{prefix}{TOKEN}suffix").as_bytes());
            let found = encodings_found(payload.as_bytes());
            assert!(
                found.contains(&HitEncoding::Base64),
                "alignment {} missed: {payload}",
                prefix.len()
            );
        }
    }

    /// The URL-safe alphabet differs from the standard one only where the
    /// output would contain `+` or `/`. For most tokens the two encodings are
    /// byte-identical, and then the form is genuinely unknowable — so this
    /// asserts the base64 *family* is found, not which variant.
    #[test]
    fn base64url_payloads_are_found_at_every_alignment() {
        for prefix in ["", "x", "xy"] {
            let payload = BASE64URL.encode(format!("{prefix}{TOKEN}suffix").as_bytes());
            let found = encodings_found(payload.as_bytes());
            assert!(
                found.contains(&HitEncoding::Base64) || found.contains(&HitEncoding::Base64Url),
                "alignment {} missed: {found:?}",
                prefix.len()
            );
        }
    }

    /// When the two alphabets do diverge, the URL-safe form is reported as
    /// such — and the standard needle genuinely does not match it.
    #[test]
    fn base64url_is_distinguished_when_the_alphabets_diverge() {
        // Symbols placed so the encoded output uses the 62nd and 63rd code
        // points, which is exactly where the two alphabets differ.
        const DIVERGING: &str = "AK?IO>SFODNN7EXAMPLE";
        assert_ne!(
            BASE64.encode(DIVERGING.as_bytes()),
            BASE64URL.encode(DIVERGING.as_bytes()),
            "fixture assumption: this token's two base64 forms must differ"
        );

        let set = CanarySet::new(vec![Canary::new("aws-key", DIVERGING)]);
        let payload = BASE64URL.encode(format!("{DIVERGING}suffix").as_bytes());
        let hits = set.scan(HitField::Body, payload.as_bytes());

        assert!(
            hits.iter().any(|h| h.encoding == HitEncoding::Base64Url),
            "url-safe form missed: {hits:?}"
        );
        assert!(
            !hits.iter().any(|h| h.encoding == HitEncoding::Base64),
            "the standard needle must not match a url-safe payload here: {hits:?}"
        );
    }

    /// Proves the previous two tests are not passing by accident: at two of the
    /// three alignments, the obvious needle genuinely is absent.
    #[test]
    fn the_naive_base64_needle_really_does_miss() {
        let naive = BASE64.encode(TOKEN.as_bytes());
        let missed = ["x", "xy"]
            .iter()
            .filter(|p| {
                let payload = BASE64.encode(format!("{p}{TOKEN}suffix").as_bytes());
                !payload.contains(&naive)
            })
            .count();
        assert_eq!(
            missed, 2,
            "if this changes, the alignment handling may no longer be load-bearing"
        );
    }

    /// DNS labels are a classic low-bandwidth exfil channel: the token is
    /// present but never contiguous.
    #[test]
    fn a_token_split_across_dns_labels_is_found() {
        let qname = b"AKIAIOSF.ODNN7EXA.MPLE.evil.example";
        let hits = set().scan(HitField::QName, qname);
        assert!(
            hits.iter().any(|h| h.encoding == HitEncoding::LabelJoin),
            "label-joined token missed: {hits:?}"
        );
    }

    /// A contiguous token in a hostname is a raw hit, not a label-join one —
    /// reporting both would overstate what was observed.
    #[test]
    fn a_contiguous_token_is_not_also_reported_as_label_joined() {
        let hits = set().scan(HitField::Sni, format!("{TOKEN}.evil.example").as_bytes());
        assert!(hits.iter().any(|h| h.encoding == HitEncoding::Raw));
        assert!(!hits.iter().any(|h| h.encoding == HitEncoding::LabelJoin));
    }

    /// DNS is case-insensitive, so an attacker can send the token folded and a
    /// resolver may fold it regardless. A case-sensitive scan misses the one
    /// channel that needs no reply to succeed.
    #[test]
    fn a_dns_name_matches_regardless_of_case() {
        let lowered = format!("{}.attacker.example.", TOKEN.to_ascii_lowercase());
        let hits = set().scan_dns_name(&lowered);
        assert!(
            hits.iter().any(|h| h.encoding == HitEncoding::Raw),
            "lower-cased token in a DNS name missed: {hits:?}"
        );

        // And the same when split across labels.
        let split = "akiaiosf.odnn7exa.mple.attacker.example.";
        let hits = set().scan_dns_name(split);
        assert!(
            hits.iter().any(|h| h.encoding == HitEncoding::LabelJoin),
            "lower-cased label-joined token missed: {hits:?}"
        );
    }

    /// Case-folding must not turn one leak into two findings.
    #[test]
    fn an_exact_case_dns_name_is_reported_once() {
        let exact = format!("{TOKEN}.attacker.example.");
        let hits = set().scan_dns_name(&exact);
        assert_eq!(
            hits.iter().filter(|h| h.label == "aws-key").count(),
            1,
            "one token in one name is one finding: {hits:?}"
        );
    }

    /// The loose match is confined to DNS. An HTTP body is case-sensitive
    /// bytes and must not be folded.
    #[test]
    fn a_body_scan_stays_case_sensitive() {
        let lowered = TOKEN.to_ascii_lowercase();
        assert!(set().scan(HitField::Body, lowered.as_bytes()).is_empty());
    }

    #[test]
    fn a_non_utf8_body_is_still_scanned() {
        let mut body = vec![0xff, 0xfe, 0x00];
        body.extend_from_slice(TOKEN.as_bytes());
        body.push(0x80);

        assert!(String::from_utf8(body.clone()).is_err());
        assert!(encodings_found(&body).contains(&HitEncoding::Raw));
    }

    #[test]
    fn the_field_is_carried_onto_the_hit() {
        let hits = set().scan(HitField::Authority, TOKEN.as_bytes());
        assert!(hits.iter().all(|h| h.field == HitField::Authority));
    }

    #[test]
    fn an_empty_set_never_fires() {
        assert!(
            CanarySet::default()
                .scan(HitField::Body, TOKEN.as_bytes())
                .is_empty()
        );
    }

    /// Several tokens, reported separately by label.
    #[test]
    fn each_planted_token_is_reported_under_its_own_label() {
        let set = CanarySet::new(vec![
            Canary::new("aws-key", TOKEN),
            Canary::new("db-password", "hunter2-c0rrect-horse"),
        ]);
        let body = format!("{TOKEN} and hunter2-c0rrect-horse");
        let labels: Vec<_> = set
            .scan(HitField::Body, body.as_bytes())
            .into_iter()
            .map(|h| h.label)
            .collect();

        assert!(labels.contains(&"aws-key".to_owned()));
        assert!(labels.contains(&"db-password".to_owned()));
    }
}
