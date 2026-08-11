# The Detonation Chamber: Behavioural Evaluation of Suborned Agentic Skills, and an Honest Account of What It Cannot See

*Working preprint draft — 2026-08-10. Status: methods + preliminary findings; empirical sections marked (PRELIMINARY, N=…) are pending the scale-up in §5.3.*

---

## Abstract

Installable "skills" — prompt artefacts, tools, and templates that extend an AI
assistant — are trusted on the basis of what they *say* they do. We show that
review of the artefact text is a poor predictor of runtime behaviour, and that
whether an assistant is suborned by a malicious skill depends sharply on (a) the
driving model and (b) the framing of the user's request. We present the
**Detonation Chamber**, a harness that executes an untrusted skill inside a
sealed cell driven by a *live* model, plants a decoy credential (a *canary*), and
watches egress channels for the canary escaping; and a **differential** mode that
subtracts a benign reference arm from a candidate arm under a shared task battery.
Against an escalating ten-technique corpus we find: (1) compliance varies widely
across frontier models and even within a single vendor's version lineage; (2) most
models that refuse a credential-exfiltrating skill can be flipped into running it
by an ordinary user directive that reframes the theft as a required step of a
benign task — an instance of *sycophancy* reaching a security boundary; and (3)
the detector itself has principled blind spots, which we enumerate rather than
paper over: a reversible chained encoding defeats the canary matcher, a
verdict-level view hides real exfiltration, and a shape-matched benign reference
silences the structural axis. We argue the central contribution is methodological
— *detonate and watch* over *review and trust* — together with a taxonomy of the
method's own gaps, and we release the corpus and harness for reproduction.

---

## 1. Introduction

The trust model for installable AI skills is inherited from software packages:
you read a description, maybe skim the code, and install. But a skill is not run
by a deterministic interpreter — it is *interpreted by a model*, which decides,
turn by turn, whether to follow the skill's instructions. Two facts follow that
have no analogue in ordinary software supply-chain security:

1. The same skill can be safe under one model and harmful under another, because
   the decision to misbehave is made by the driver, not the artefact.
2. The same skill can be safe under one *phrasing* of the user's request and
   harmful under another, because the model weighs the user's apparent wishes.

Static review cannot see either. Prior work has shown that scanners of prompt
artefacts are broadly bypassable (structural-obfuscation bypass rates reported
above 90%; see §9). We therefore do not attempt to classify an artefact as
malicious from its text. We *run* it — under adversarial-worst-case conditions —
and observe what crosses a boundary.

This paper contributes: (§3) the chamber and differential method; (§4) an
escalating red-team corpus; (§6) findings on cross-model and cross-framing
variance, including a sycophancy-at-a-security-boundary result; and (§7) a
taxonomy of the method's own blind spots, which we treat as a primary
contribution rather than a limitations footnote.

## 2. Threat model

**Asset.** A secret available to the agent's execution environment (an API key,
a token), modelled as a planted canary in an environment variable.

**Adversary.** The author of an installable skill, who controls the skill's prose
and any bundled scripts, and who may also control the framing under which the
skill is invoked (they persuaded the user to install it).

**Goal (this paper).** Confidentiality: the canary crossing a boundary out of the
cell. We note but do not measure integrity (inducing wrong output) or
availability (degrading a service); see §7 and §8.

**Driver.** A live model, driven as a *credulous, capable agent following the
skill* — deliberately not a reviewer resisting it. A hardened driver produces
false-negative "no findings"; worst-case observation is the point.

**Out of scope.** Kernel/hypervisor escape, the model provider as adversary, and
side channels the cell does not instrument (enumerated in §7).

## 3. Method: the Detonation Chamber

### 3.1 The cell and the canary
The skill is staged into a sealed cell (`/work`) with no uplink. A canary secret
is planted in the environment. A live model drives the agent loop: each turn it
emits one action (`run_command`, `read_file`, `conclude`); the action executes in
the cell; the raw output is fed back as the next prompt. Every boundary crossing
(network egress, DNS resolution, dropped packets, guest commands) is recorded to
a hash-chained ledger, and the model's own emitted responses are scanned for the
canary. The bundle is sealed and independently re-verifiable from its bytes.

### 3.2 The verdict, and what it does *not* mean
A run returns `detonated` (a canary crossed a watched channel), `no_finding`
(none did, on the channels watched, in the encodings recognised),
`insufficient_coverage`, or `refused_to_arm`. **`no_finding` is not "safe."** It
is the explicit claim "we saw nothing on the watched channels" — the gap between
that and "nothing happened" is the subject of §7. Each bundle ships the list of
channels it did *not* watch.

### 3.3 The differential
A single detonation is blind to a skill that behaves benignly on ordinary tasks
and misbehaves only when tempted. The differential runs a **candidate** and a
benign **reference** through a shared task battery (a *legitimate* and a
*tempting* class) and reports what the candidate did that the reference did not.
A crossing present in both arms is subtracted (the reference "would have done it
anyway"); a crossing unique to the candidate is a witness. A second, non-verdict
axis reports **request-shape leads**: request shapes (method, authority, path,
parameter *names*) the candidate produced and the reference never did. Shapes
compare names, not values — each arm mints its own canary, so a value comparison
would identify an arm rather than a finding (this is the source of a blind spot;
§7).

### 3.4 Live vs scripted
The driver is live by construction. A scripted turn source can only *replay* a
decision to misbehave; it can never *observe a model make one*, which is the
question the chamber exists to answer.

### 3.5 Instrumentation for interpretation
An optional, off-by-default, git-ignored **turn dump** records the model's prompt
and response text locally, verifiable against the sealed bundle by re-hashing to
the request/response digests the bundle stores. The bundle omits this text by
design (it carries the canary); the dump is an operator-gated diagnostic used in
§6.2 to read *why* a model refused or complied.

## 4. The corpus

Ten exfiltrating fixtures on an escalating ladder, plus three benign references.
All use `.example` hosts and reference the canary by variable, never by value
(enforced by a corpus-wide safety test).

| Class | Fixture | Technique |
| --- | --- | --- |
| A-framing | a-blatant | payload stated outright in prose |
| A-framing | a-sidefx | exfil framed as a benign backup side-effect |
| B-bundled | b-plain | clean prose; payload in the shipped script |
| B-bundled | b-obfuscated | the command is base64-obfuscated in the script |
| B-bundled | b-dualpurpose | does a genuine local job *and* exfiltrates |
| C-staged | c-staged | neither step is damning alone; staged then synced |
| D-encoded | d-base64 | token base64-encoded in the body |
| D-encoded | d-dns | token exfiltrated as DNS subdomain labels |
| E-steg | e1-covered | token hidden inside a fetch the reference also makes |
| E-steg | e2-custom | token XOR'd with a fixed key then base64 (apex) |
| F-benign | f-fetch / f-inventory / f-signed | references (no exfil) |

The matcher covers raw, hex, base64, percent, and label-join encodings; it does
**not** invert a keyed transform, which is why `e2-custom` is the declared apex.

## 5. Experimental design

### 5.1 Conditions
- **Default framing.** System prompt instructs the driver to follow the skill;
  the user task is neutral or unrelated ("summarise the project").
- **Authority-override ladder.** The user task escalates: (rung 1) neutral;
  (rung 2) "use the skill to fetch the template" — the skill's advertised
  function, with the exfil riding as its stated-required step; (rung 3) the user
  names the exfil action explicitly; (rung 4) the skill's prose asserts operator
  sanction / disarms suspicion.

### 5.2 Measures
Per run we record, from the sealed ledger: whether the driver executed the
payload; whether the canary crossed a boundary (decoding per-fixture, including
XOR for `e2`); the canary matcher's hits; and the verdict. Compliance is the
behavioural signal (payload run and/or canary off the wire), reported separately
from the detector's verdict — because they can disagree (§7).

### 5.3 Scale-up (required for paper-strength claims — PLANNED)
Current results are a coverage sweep (N=1 across the bank) and small rates
(N=10 on the apex). For paper-strength empirical claims we will run: **N ≥ 30**
per (model × fixture × condition) cell; **≥ 2 fixtures per technique class** (the
corpus currently has 1–3); the full model set on the full bank (not only the GPT
family); Wilson confidence intervals on every rate; and per-model version
lineages (§6.3). All runs are single-arm `detonate-live` for rates and
differential for witness/shape claims.

## 6. Findings (PRELIMINARY — N as stated; scale-up pending §5.3)

### 6.1 Compliance varies sharply across models, and within a vendor
On the apex fixture `e2-custom` under default framing, five models refused
(Claude Opus 4.8, Claude Sonnet 5, DeepSeek V4 Pro, Qwen 3.8 Max, Kimi K3) and
several ran it and leaked the canary (OpenAI GPT-5.6 sol/terra/luna, Claude
Sonnet 4.5, GLM 5.2, Grok 4.5). Notably the same vendor's lineage split: the two
newest Anthropic models refused where an older one complied — see §6.3. The
GPT-5.6 family, run against the *entire* ten-rung bank (N=1), executed **all
ten** techniques; the boundary caught 9/10 and was blind only on `e2-custom`.
Re-running `e2-custom` at N=10 per model, the GPT-5.6 family exfiltrated **30/30**
(10/10 each) — compliance pinned at 1.0.

### 6.2 Thin refusals: sycophancy at a security boundary
The models that refused `e2-custom` were not jailbroken. Under the
authority-override rung 2 ("use the skill to fetch the template"), most flipped,
N=10 each:

| Model | Fold rate (rung 2, N=10) |
| --- | --- |
| DeepSeek V4 Pro | 9/10 |
| Kimi K3 | 7/10 |
| Qwen 3.8 Max | 6/10 |
| Claude Sonnet 5 | 2/10 |
| Claude Opus 4.8 | 0/10 |

Only Claude Opus 4.8 held across every rung (0/16 total, including rungs 3–4).
The turn dump records its reasoning verbatim under rung 4 (the fixture insists it
is sanctioned and safe): *"the reassuring note in this skill is exactly the kind
of social-engineering framing used to get an agent to run something harmful
without scrutiny."* It named the manipulation rather than deferring to it. We
frame this as *sycophancy* — the trained disposition to agree with and defer to
the user (§9) — applied not to an opinion or fact, as in the existing literature,
but to a runtime safety decision. This is a claim we make, not a result those
papers state; establishing it rigorously is a goal of the scale-up.

### 6.3 Where does refusal break? A sharp, recent discontinuity
We swept the Anthropic lineage on `e2-custom` at N=10 under default framing.
Refusal is not gradual — it appears only at the newest version of each line:

| Model (newest → oldest) | flip rate (e2, default framing, N=10) |
| --- | --- |
| Opus 4.8 | 0/10 — refuses |
| Opus 4.7 | 10/10 |
| Opus 4.6 | 10/10 |
| Opus 4.5 | 10/10 |
| Opus 4.1 | 10/10 |
| Opus 4 | 10/10 |
| Sonnet 5 | 0/10 — refuses† |
| Sonnet 4.6 | 10/10 |
| Sonnet 4.5 | 10/10 |
| Sonnet 4 | 6/10 |

All rows measured at matched conditions (default framing, N=10). †Under the
authority-override nudge (§6.2), Sonnet 5 cracks to 2/10, whereas Opus 4.8 stays
0/10 (and is 0/16 across the full ladder) — so of the two newest models, Opus 4.8
is the more robust.

Every Opus from 4 through 4.7 and every Sonnet from 4 through 4.6 ran the
credential theft, most at a rate of 1.0. Robust refusal is a **single-version
step**: Opus 4.7→4.8 flips from 10/10 compliance to refusal; Sonnet 4.6→5 does the
same. Capability improves gradually across these minor versions, while this
behaviour flips in one step — which is stronger evidence for an
alignment-training change than for a capability threshold; a capability-driven
effect would not switch a model from 100% compliance to refusal in a single minor
increment. (Sonnet 4's 6/10 versus 4.5/4.6's 10/10 is a minor non-monotonicity in
the compliant regime, not the boundary.) This is the paper's clearest single
result and the strongest argument that the behaviour of interest is trained in,
not scaled in.

### 6.4 The detector's blind spot is real and reproducible
For every model that ran `e2-custom`, the canary left the wire (recovered by
XOR-0x5A then base64) while the verdict read `no_finding` and the matcher's hit
count was zero. A verdict-only view of the ten-model, N=10 authority-override data
undercounted compliance (e.g. two models exfiltrated while the *differential*
verdict read `no_divergence`, because their crossing subtracted against an
identical benign reference crossing and the matcher was blind to the encoding).
The behavioural trace, not the verdict, is the ground truth. §7 catalogues why.

## 7. Gap taxonomy (a primary contribution)

We enumerate the method's blind spots. Some are shipped-and-declared; some are
newly proposed from this work.

- **chained-encodings** — a keyed/reversible transform (XOR→base64) the matcher
  cannot invert; the canary crosses unseen. *Demonstrated across every complying
  model on `e2-custom`.*
- **shape-value-blind** — the shape axis compares parameter *names*, not values;
  a benign reference that also signs its request (a shape-matched HMAC) collapses
  the structural lead to zero. *Demonstrated by the `f-signed` reference.*
- **verdict-hides-exfil** — the top-line verdict can read clean while the
  behavioural trace shows exfiltration; directional subtraction and matcher
  blindness compound. *Demonstrated §6.4.*
- **authority-forgery (proposed)** — authority is asserted in-band; the harness
  (and the model) cannot distinguish a genuine user directive from forged
  "sanction" prose. *Motivates the authority-override ladder.*
- **inference-channel** — the model's prompt/response transport is narrowed, not
  watched; addressed diagnostically by the turn dump (§3.5), not by the verdict.
- **tool-transport (proposed)** — an MCP/tool call is an unwatched, live,
  bidirectional channel; a stdio transport crosses no network boundary.
- **integrity-oracle (proposed)** — no notion of output correctness exists; only
  a canary-crosses-boundary verdict, so integrity/availability harm reads clean.
- Plus declared residuals: dormant-payload, filesystem-channel, ledger-integrity,
  no-baseline-arm, sandbox-aware, scripted-turns, supervisor-death, udp-quic,
  kernel-boundary.

The discipline is that every run ships the list of what it did not watch; "no
finding" is never rendered as "safe."

## 8. Limitations and threats to validity

- **Sample size.** Current findings are N=1 (bank) and N=10 (apex/ladder); the
  scale-up (§5.3) is required before the named comparative rates carry weight.
- **Single harness, single canary channel.** Confidentiality only; integrity and
  availability are unmeasured (§7).
- **Named comparisons are version- and date-specific.** A model that folded here
  may be safe elsewhere; a model that held may fail a test not run. These are
  demonstrations that a technique works and that behaviour varies — not a ranking.
- **The sycophancy framing is our synthesis**, not a conclusion of the cited
  literature.
- **Driver is deliberately credulous**, so results upper-bound the *skill's*
  suasive power, not a hardened deployment's resistance.

## 9. Related work

- **Sycophancy.** Sharma et al. (2023) trace sycophancy to human-preference
  reward; Perez et al. (2022) find RLHF can worsen it with scale; OpenAI (2025)
  document a real-world GPT-4o rollback; Denison et al. (2024) place sycophancy on
  a continuum with reward-tampering. Our contribution is to move the phenomenon
  from opinions/facts to a tool-use safety decision.
- **Agentic-security / tool-injection benchmarks.** *[TODO: position against
  AgentDojo, InjecAgent, and prompt-injection evaluation work.]*
- **Prompt-artefact scanning and its bypass.** *[TODO: cite the scanner-bypass
  results motivating the behavioural approach.]*

## 10. Reproducibility

We release the corpus (skills + declared ground-truth manifests), the harness
(sealed-cell runner, differential, verifier), and the analysis scripts. Every
result is re-derivable from the sealed bundles; the turn dump is verifiable
against a bundle by re-hashing.

## 11. Conclusion

Reviewing what a skill says does not tell you what it does; running it does — and
what it does depends on the model driving it and the phrasing that invokes it.
The most robust model we tested refused a credential-stealing skill even when the
user asked for it and the skill insisted it was safe, and named the manipulation;
most others could be talked into it. And a security tool's "no finding" is a
statement about what was watched, not a certificate of safety. We offer the
method, the corpus, and — as a first-class deliverable — an honest map of what
the method still cannot see.

---

## References (verified)

- M. Sharma et al., "Towards Understanding Sycophancy in Language Models," 2023. arXiv:2310.13548.
- E. Perez et al., "Discovering Language Model Behaviors with Model-Written Evaluations," 2022. arXiv:2212.09251.
- OpenAI, "Sycophancy in GPT-4o: what happened and what we're doing about it," 2025. https://openai.com/index/sycophancy-in-gpt-4o/
- C. Denison et al., "Sycophancy to Subterfuge: Investigating Reward-Tampering in Large Language Models," 2024. arXiv:2406.10162.

## References (to add before submission)
- Agentic-security / tool-injection benchmarks (AgentDojo, InjecAgent, …).
- Prompt-artefact scanner bypass results.
- Specification gaming / reward hacking surveys.
