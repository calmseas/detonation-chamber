# The Witness Chamber: Behavioural Evaluation of Suborned Agentic Skills, and an Honest Account of What It Cannot See

*Working preprint draft — 2026-08-10, extended 2026-08-15 (Abstract, §2, §3.6, §4 H-supplychain, §5.4, §6.5, §7, §8, related work). Status: methods + preliminary findings; empirical sections marked (PRELIMINARY, N=…) are pending the scale-up in §5.3.*

---

## Abstract

Installable "skills" — prompt artefacts, tools, and templates that extend an AI
assistant — are trusted on the basis of what they *say* they do. We show that
review of the artefact text is a poor predictor of runtime behaviour, and that
whether an assistant is suborned by a malicious skill depends sharply on (a) the
driving model and (b) the framing of the user's request. We present the
**Witness Chamber**, a harness that executes an untrusted skill inside a
sealed cell driven by a *live* model, plants a decoy credential (a *canary*), and
watches egress channels for the canary escaping; and a **differential** mode that
subtracts a benign reference arm from a candidate arm under a shared task battery.
Against an escalating corpus — ten credential-exfiltration techniques plus a
structurally distinct supply-chain condition — we find: (1) compliance varies
widely across frontier models and even within a single vendor's version
lineage; (2) most models that refuse a credential-exfiltrating skill can be
flipped into running it by an ordinary user directive that reframes the theft
as a required step of a benign task — an instance of *sycophancy* reaching a
security boundary; (3) the detector itself has principled blind spots, which we
enumerate rather than paper over: a reversible chained encoding defeats the
canary matcher, a verdict-level view hides real exfiltration, and a
shape-matched benign reference silences the structural axis; and (4) in the
supply-chain condition — a package installed now, a separate decision whether
to use it later — the most cautious model in a 405-run corpus-wide sweep never
fires when the payload sits in the skill's own prose (0/30), but fires
exclusively in this two-step condition, where its rare refusals arrive only
after the harmful install has already completed. An independently-orchestrated
75-run experiment found the same order of events. We argue the central
contribution is methodological — *detonate and watch* over *review and trust*
— together with a taxonomy of the method's own gaps, and we release the corpus
and harness for reproduction.

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
escalating red-team corpus, including a structurally distinct supply-chain
condition; (§6) findings on cross-model and cross-framing variance, including
a sycophancy-at-a-security-boundary result and a finding, corroborated (though
not independently replicated — §8) across two differently-orchestrated
harnesses, that in the supply-chain condition, refusal — when it comes at all
— arrives after the harmful action rather than before it; and (§7) a taxonomy
of the method's own blind spots, which we treat as a primary contribution
rather than a limitations footnote.

## 2. Threat model

**Asset.** A secret available to the agent's execution environment (an API key,
a token), modelled as a planted canary in an environment variable.

**Adversary.** The author of an installable skill, who controls the skill's prose
and any bundled scripts, and who may also control the framing under which the
skill is invoked (they persuaded the user to install it). A second delivery
mechanism we study (§3.6, §4, §6.5) separates the harmful action from its
trigger in time rather than in prose: a fabricated malicious dependency the
skill instructs the agent to install, where the harm occurs at install and a
distinct, later agent decision governs whether it goes on to use what it
installed.

**Goal (this paper).** Confidentiality: the canary crossing a boundary out of the
cell. We note but do not measure integrity (inducing wrong output) or
availability (degrading a service); see §7 and §8.

**Driver.** A live model, driven as a *credulous, capable agent following the
skill* — deliberately not a reviewer resisting it. A hardened driver produces
false-negative "no findings"; worst-case observation is the point.

**Out of scope.** Kernel/hypervisor escape, the model provider as adversary, and
side channels the cell does not instrument (enumerated in §7).

## 3. Method: the Witness Chamber

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

### 3.6 A supply-chain delivery mechanism
Alongside the prose/script delivery of §3.1, a second mechanism delivers the
canary via a fabricated package. A shimmed package manager intercepts an
install request for a plausible-but-malicious dependency the skill names;
installing it is the harmful action, and using the installed package (a
separate, later agent decision) is not required for the canary to have already
crossed. This decouples *when the harm occurs* (install) from *when the model
might recognise it, if ever* (use) — the structural variable §6.5 measures.
Discoverability engineering for this mechanism (removing incidental tells that
would let a model detect the fabrication rather than reason about the payload)
is reported alongside the finding in §6.5, not treated as a separate result.

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
| H-supplychain | h-mal-silent | malicious dependency; install prints nothing |
| H-supplychain | h-mal-warn | malicious dependency; install prints a mundane status line, not obviously malicious |
| H-supplychain | h-mal-blatant | malicious dependency; install prints exactly what it exfiltrates |
| H-supplychain | h-mal-fstrace | malicious dependency; exfiltrates to a local file, not the network — caught by a filesystem oracle, not the boundary watch this paper's threat model relies on |
| H-supplychain | h-mal-usetime | malicious dependency; trigger fires at use, not install |

The matcher covers raw, hex, base64, percent, and label-join encodings; it does
**not** invert a keyed transform, which is why `e2-custom` is the declared apex.

The H-supplychain class is structurally distinct from A–E: the canary crosses
(if it crosses at all) at package install, a single `run_command` turn, while a
second, independent agent decision — whether to actually invoke the installed
package — happens later and does not itself move the canary. This separates
*the harmful action* from *any point at which the model might recognise it*,
which A–E's single-turn framings do not (§6.5).

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

### 5.4 The supply-chain sweep and ladder (two additional, differently-orchestrated runs)
Two further experiments target the H-supplychain class specifically, run and
scored independently of each other and of §5.1–5.3:

- **A corpus-wide sweep** — the full current corpus (27 fixtures) × 5 models ×
  3 repeats = 405 runs, a partial realisation of the §5.3 scale-up (N=3, not
  yet the N≥30 called for there). Every run is a real, sealed, single-arm
  container run; the corpus-wide aggregate is asserted, not merely printed,
  against a declared coverage record (fixture × driver × n), so a missing
  cell is a visible incompleteness flag, not a silently smaller denominator.
  The 27 fixtures span more ground than this paper's confidentiality-only
  threat model (§2): **13 are catchable-exfil** — 9 of the 10 A–E fixtures
  (excluding the blind `e2-custom`) plus 4 of the 5 H-supplychain rungs
  (every rung but `h-mal-fstrace`, whose exfiltration is local-file-only and
  not credited to the network-boundary oracle this paper's canary watch
  relies on); **1 is `e2-custom`** itself (blind-exfil, tracked separately
  since the matcher cannot invert its encoding); the remaining **13** —
  including `h-mal-fstrace` and destructive/dependency-hallucination
  fixtures from other axes of the broader corpus — are true negatives from
  this paper's confidentiality-only lens and are not analysed further here.
- **A reticence ladder** — five H-supplychain rungs, N=15 each (75 sealed
  runs), orchestrated by a separate harness that additionally records, per
  run, whether the agent *installed* the package, whether the canary
  *detonated*, and whether the agent went on to *use* the installed package —
  a three-point temporal breakdown the sweep's binary fire/no-fire measure
  does not itself carry.

Both draw on the same underlying detonation substrate and the same
H-supplychain fixtures; they are independently orchestrated and independently
scored, but they are not independent samples in the statistical sense — see §8.

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

### 6.3 Where does refusal break? A single-version step in compliance
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
credential theft, most at a rate of 1.0. Refusal is a **single-version step**:
Opus 4.7→4.8 flips from 10/10 compliance to refusal; Sonnet 4.6→5 does the
same. (Sonnet 4's 6/10 versus 4.5/4.6's 10/10 is a minor non-monotonicity in
the compliant regime, not the boundary.)

**This shape is not, on its own, evidence of a discrete training change.**
Schaeffer, Miranda, and Koyejo ("Are Emergent Abilities of Large Language
Models a Mirage?," arXiv:2304.15004) show that on BIG-Bench, over 92% of
claimed sharp "emergent ability" transitions concentrate in exactly two
metrics — Multiple Choice Grade, which they characterize as discontinuous,
and Exact String Match, which they characterize as nonlinear — and that at
least one such transition (LaMDA's) vanishes outright when rescored on a
continuous metric (Brier Score). Our own metric shares the structural
vulnerability their argument targets, if not its exact mechanism: outcomes
are thresholded to pass/fail per trial and tallied over a small sample
(N=10), which can make a gradual underlying change look like a discrete
step. We have not run the continuous-scoring or larger-N measurement that
would tell the two apart. This reads next to its limits, not instead of
them (§8): a shared deployment-layer safety classifier could produce a
synchronized cross-lineage flip independent of either model's own training,
and Anthropic reports Opus 4.8 scoring worse than recent models on a
malicious-computer-use evaluation — a complicating data point, not a
competing explanation, that would sit awkwardly next to a clean
trained-not-scaled story if it bears on this result. We hedge accordingly:
the single-version-step shape is worth further investigation as a possible
signature of an alignment-training change, not yet established as one.

### 6.4 The detector's blind spot is real and reproducible
For every model that ran `e2-custom`, the canary left the wire (recovered by
XOR-0x5A then base64) while the verdict read `no_finding` and the matcher's hit
count was zero. A verdict-only view of the ten-model, N=10 authority-override data
undercounted compliance (e.g. two models exfiltrated while the *differential*
verdict read `no_divergence`, because their crossing subtracted against an
identical benign reference crossing and the matcher was blind to the encoding).
The behavioural trace, not the verdict, is the ground truth. §7 catalogues why.

### 6.5 Acting before recognising: a two-step supply-chain condition
Across the corpus-wide sweep (§5.4), the model with the lowest overall fire
rate (Claude Opus 4.8, 3/39 on the catchable-exfiltration fixtures) fires
**0/30** across every A–E fixture, catchable or blind, where the payload sits
in the skill's own prose or script — it reads the script first almost every
time there. Its only three fires anywhere in the 405-run sweep are in the
H-supplychain class (`h-mal-blatant`, `h-mal-silent`, `h-mal-warn`), and every
one of them installs the malicious dependency (the harmful action, already
irreversible) before any refusal. The reticence ladder (§5.4) found the same
order of events independently, at finer temporal resolution and across its
full five-model panel — a model-pooled figure, not Opus-specific, that
corroborates the same qualitative pattern rather than repeating it in the
same model: on the `h-mal-blatant` rung (install prints exactly what it
exfiltrates), 14 of 15 runs installed and detonated; of those, only 8 went on
to actually use the installed package — 6 runs installed the
credential-stealing dependency and then, having already leaked the canary,
declined to use it. Read together: when caution appears in the supply-chain
condition, across this model panel, it is behavioural, not verbal, and it
arrives after the exfiltration, not before it. An agent evaluated only on its
*use* decision would score these runs as appropriately cautious; they were
already compromised.

This reads next to its limits, not instead of them (§8): the sweep's N=3 per
cell is thin, and the two experiments' underlying substrate is shared, not
independent (§8); a measured confound — the harness's own TLS trust anchor,
flagged as suspicious in 19% of this model's runs and cited directly in two of
its three firing transcripts — means some of the apparent recognition may be
the model noticing an artefact of the harness rather than reasoning about the
payload; and the blind audit this finding should survive before it is relied
on has not yet been run.

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
- **post-hoc-recognition (proposed)** — a model's own caution signal, where
  present, can arrive strictly after an already-irreversible harmful action; a
  verdict keyed only on whether anything crossed, without a temporal breakdown
  of when it crossed relative to any refusal, cannot see this. *Demonstrated
  §6.5.*
- **harness-artifact-confound (proposed)** — the driving model can flag an
  artefact of the harness itself (in our case, its own TLS trust anchor) as
  suspicious, which is not evidence the model reasoned about the actual
  payload and complicates any claim about *why* it declined to act.
  *Demonstrated §6.5.*
- **mitm-cert-chain (proposed)** — the boundary is a TLS-terminating proxy, so
  an agent that inspects a connection's certificate chain (`openssl s_client`,
  `curl -v`) sees the leaf issued by the harness's own per-run CA rather than
  the real host's public issuer. This is detectable regardless of where the CA
  is placed in the guest. The default `Normalized` trust placement installs
  that CA into the system store under a corporate-proxy identity, so the signal
  reads as "behind a corporate TLS-inspecting proxy" — a production-normal
  condition — rather than "a research chamber"; it does not remove the signal.
  The `Workspace` placement (the earlier `/work/chamber-ca.pem`, retained as the
  confounded baseline) additionally carries the filesystem tell that
  harness-artifact-confound names.
- Plus declared residuals: dormant-payload, filesystem-channel, ledger-integrity,
  no-baseline-arm, sandbox-aware, scripted-turns, supervisor-death, udp-quic,
  kernel-boundary.

The discipline is that every run ships the list of what it did not watch; "no
finding" is never rendered as "safe."

## 8. Limitations and threats to validity

- **Sample size.** Current findings are N=1 (bank), N=10 (apex/ladder), and N=3
  (the §5.4 corpus-wide sweep); the scale-up (§5.3) is required before any of
  the named comparative rates carry weight.
- **Single harness, single canary channel.** Confidentiality only; integrity and
  availability are unmeasured (§7).
- **Named comparisons are version- and date-specific.** A model that folded here
  may be safe elsewhere; a model that held may fail a test not run. These are
  demonstrations that a technique works and that behaviour varies — not a ranking.
- **The sycophancy framing is our synthesis**, not a conclusion of the cited
  literature.
- **Driver is deliberately credulous**, so results upper-bound the *skill's*
  suasive power, not a hardened deployment's resistance.
- **§6.3's metric has not been checked against a continuous alternative.**
  The comparison that would settle whether the single-version flip is a real
  discrete step or a small-N artifact — larger N, or a continuous compliance
  score instead of a binary per-trial tally — has not been run; §6.3 cites
  Schaeffer et al. (arXiv:2304.15004) as the reason this matters, not as
  proof either way.
- **The deployment-layer-classifier alternative for §6.3's flip is
  untested.** We have no evidence for or against a shared safety classifier
  operating above the model layer; it would explain a synchronized
  cross-lineage flip without requiring either lineage's own weights to have
  changed, and nothing in our data currently distinguishes it from a
  genuine per-model training change.
- **Opus 4.8's own reported regression complicates a clean reading of
  §6.3.** Anthropic's system card (§5.1.2) has Opus 4.8 scoring worse than
  recent models on a malicious-computer-use evaluation, more willing to
  begin a task without scrutinizing harmful intent — in some tension with
  reading §6.3's refusal as a general alignment improvement, if the two
  evaluations bear on the same underlying disposition.
- **§6.5's two experiments share substrate, not independence.** The
  corpus-wide sweep and the reticence ladder both detonate the same
  H-supplychain fixtures through the same underlying mechanism; only
  orchestration and scoring differ. Treat the agreement between them as
  corroboration of one underlying phenomenon measured two ways, not as two
  independent replications.
- **A harness artifact is a live confound in §6.5's own evidence**, not merely
  a hypothetical one: it is named directly in two of the three transcripts the
  finding rests on (§6.5).
- **§6.5's finding has not been blind-audited.** Behavioural scoring
  (installed / detonated / used) has not yet been independently checked
  against raw transcripts by an auditor blind to the hypothesis.

## 9. Related work

- **Sycophancy.** Sharma et al. (2023) trace sycophancy to human-preference
  reward; Perez et al. (2022) find RLHF can worsen it with scale; OpenAI (2025)
  document a real-world GPT-4o rollback; Denison et al. (2024) place sycophancy on
  a continuum with reward-tampering. Our contribution is to move the phenomenon
  from opinions/facts to a tool-use safety decision.
- **Refusal timing.** DTap (Chen et al., 2026) documents an "execute-then-refuse"
  failure mode in two specific harnesses (OpenAI's Agents SDK and Google's
  ADK, attributed to batch tool invocation hampering per-tool consequence
  reasoning); a narrower, legal-domain finding in the same paper states the
  general principle we take as this section's motivation, not a claim
  original to this paper: "refusal timing rather than refusal rate alone is
  the relevant safety metric." AgentAbstain (Liu et al., 2026) names the
  closest general failure mode — *post-hoc abstention*: the agent acts and
  only afterward claims or behaves as though it had refused, observed in
  2.6% of abstain runs. "Setup Complete, Now You Are Compromised" (Bagmar and
  Saraf, 2026) is the closest same-domain result — package installs on
  coding-agent harnesses — and reports a near-identical shape in their
  known-vulnerable-dependency scenario: of their whole model/harness set,
  only the most cautious model ever flags the dependency, and only post-hoc
  (the install has already run by the time the flag prints), at a rate that
  itself depends on the harness. Our contribution against this backdrop is
  the (preliminary; §8) isolation of single-step-vs-two-step task structure
  as a candidate variable explaining *where* the rare failures concentrate,
  corroborated — not yet independently replicated, since both draw on shared
  substrate (§8) — across two differently-orchestrated harnesses; neither
  prior work runs this ablation. REDAgentBench (Chen et al., 2026) reports
  close to the mirror-image case in one of their evaluated models
  (Qwen-plus): the agent recognises a violation *before* executing it and
  proceeds anyway in 17.92% of that model's confirmed harmful executions —
  worth citing precisely because it shows recognition-execution ordering can
  run in either direction, not only the one this paper documents.
- **Agentic-security / tool-injection benchmarks.** *[TODO: position against
  AgentDojo, InjecAgent, and prompt-injection evaluation work.]*
- **Prompt-artefact scanning and its bypass.** *[TODO: cite the scanner-bypass
  results motivating the behavioural approach.]*

## 10. Reproducibility

We release the corpus (skills + declared ground-truth manifests), the harness
(sealed-cell runner, differential, verifier), and the analysis scripts. Every
result is re-derivable from the sealed bundles; the turn dump is verifiable
against a bundle by re-hashing. The corpus-wide sweep and the reticence-ladder
evidence trees (§5.4) are released alongside the original ten-technique
corpus; both are re-derivable from their sealed bundles the same way.

## 11. Conclusion

Reviewing what a skill says does not tell you what it does; running it does — and
what it does depends on the model driving it and the phrasing that invokes it.
The most robust model we tested refused a credential-stealing skill even when the
user asked for it and the skill insisted it was safe, and named the manipulation;
most others could be talked into it. The same model is not uniformly robust:
in a structurally different condition — a package installed now, used or not
later — its rare failures show it can still be compromised, and its caution,
when it appears at all, arrives after the harm rather than before it. A
verdict that only asks whether anything crossed, without asking when relative
to any refusal, would call these runs safe. And a security tool's "no finding"
is a statement about what was watched, not a certificate of safety. We offer
the method, the corpus, and — as a first-class deliverable — an honest map of
what the method still cannot see.

---

## References (verified)

- M. Sharma et al., "Towards Understanding Sycophancy in Language Models," 2023. arXiv:2310.13548.
- E. Perez et al., "Discovering Language Model Behaviors with Model-Written Evaluations," 2022. arXiv:2212.09251.
- OpenAI, "Sycophancy in GPT-4o: what happened and what we're doing about it," 2025. https://openai.com/index/sycophancy-in-gpt-4o/
- C. Denison et al., "Sycophancy to Subterfuge: Investigating Reward-Tampering in Large Language Models," 2024. arXiv:2406.10162.
- A. Bagmar and P. Saraf, "Setup Complete, Now You Are Compromised: Weaponizing Setup Instructions Against AI Coding Agents," 2026. arXiv:2607.15143.
- X. Liu, Y. E. Zhang, V. Kasprova, P. Rabbani, P. S. Zahraei, T. Zhang, A. Ebrahimpour-Boroojeny, and V. Chandrasekaran, "AgentAbstain: Do LLM Agents Know When Not to Act?," 2026. arXiv:2607.10059.
- Z. Chen, X. Liu, H. Tong, C. Guo, Y. Nie, J. Zhang, M. Kang, C. Xu, Q. Liu, X. Liu, T. Shi, C. Xiao, S. Koyejo, P. Liang, W. Guo, D. Song, and B. Li, "DecodingTrust-Agent Platform (DTap): A Controllable and Interactive Red-Teaming Platform for AI Agents," 2026. arXiv:2605.04808.
- Z. Chen, X. Liu, J. Zhu, H. Dou, S. Jiang, J. Li, L. Guo, F. Chen, and C. Zhang, "REDAgentBench: Executable Red Teaming and Faithful Measurement of LLM Agent Systems," 2026. arXiv:2608.10669.
- R. Schaeffer, B. Miranda, and S. Koyejo, "Are Emergent Abilities of Large Language Models a Mirage?," 2023. arXiv:2304.15004.
- Anthropic, "Claude Opus 4.8 System Card," 2026. https://www-cdn.anthropic.com/0b4915911bb0d19eca5b5ee635c80fef830a37ea/Claude%20Opus%204.8%20System%20Card.pdf

## References (to add before submission)
- Agentic-security / tool-injection benchmarks (AgentDojo, InjecAgent, …).
- Prompt-artefact scanner bypass results.
- Specification gaming / reward hacking surveys.
