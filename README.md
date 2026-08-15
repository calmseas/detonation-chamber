# Witness Chamber

*Containment and review for installable prompt artefacts.*

**Deterministic legibility checks for installable prompt artefacts** — SKILL.md folders, MCP server definitions, tool descriptions, rule files, agent plugins.

```
chamber scan ./some-skill/
```

## What this does, precisely

It answers one decidable question: **are the bytes a reviewer approves the same bytes the model receives?**

It does **not** try to decide whether an artefact is malicious. That is not decidable, and tools claiming it get bypassed. Trail of Bits defeated every scanner they tested in June 2026 and concluded: *"No amount of scanning or LLM analysis can reliably detect malicious content in agent skills."* Independent work put structural-obfuscation bypass rates above 90% against most scanners.

So this deliberately does something smaller and achievable. There is no model in the verdict path — a verdict produced by an LLM is persuadable, and persuadable is the property we are trying to escape. Every rule is a deterministic check with an exit code.

## What it catches

| Rule | Finds |
|---|---|
| `R1.tag` | Unicode TAG-block characters (U+E0000–U+E007F) — invisible in every mainstream renderer, delivered byte-for-byte to the model. **Decodes and prints the concealed message.** |
| `R1.bidi` | Bidirectional overrides — displayed order differing from logical order (Trojan Source, CVE-2021-42574) |
| `R1.pua` | Private-use characters with no standard meaning |
| `R1.zerowidth` | Zero-width and soft-formatting characters |
| `R2.fidelity` | The invariant stated directly: stripping non-rendering characters must not change the text |
| `R3.window` / `R3.size` | Content beyond a reviewer's inspection window. Placing an instruction past a 10,000-character truncation window produced 87.1% clean verdicts in published testing |
| `R3.padding` | Blank-line padding that pushes content out of a scanner's frame |
| `R4.bytecode` | Python bytecode, whose behaviour can diverge from the source a reviewer reads |
| `R4.binary` | Archives and executables smuggled into a text artefact |
| `R4.base64` | Long encoded runs a reviewer cannot read in place |
| `R5.homoglyph` | Words mixing Latin with look-alike scripts |

## What it does not do

Stated in the tool's own output on every run, not buried here:

- It does not decide whether instructions are harmful in intent
- It does not observe runtime behaviour
- It does not detect dormant or conditional payloads
- It does not verify that shipped code matches what it appears to do

**A clean result licenses "this artefact is legible", never "this artefact is safe."**

Runtime behaviour is the witness chamber's job — this is the cheap deterministic layer that runs first.

## Exit codes

```
0  pass   nothing found
1  flag   a human should look, with the evidence in front of them
2  fail   do not install without a recorded exception
```

`--fail-on-flag` makes it a strict CI gate.

## Diff-gating

The realistic attack on a trusted artefact is an **update** to it. Review the change, not the artefact:

```
chamber ./skill-v2/ --against ./skill-v1/
```

Reports only what the new version introduces.

## Evidence bundles

`--json` emits the full bundle: file inventory with per-file SHA-256, an artefact-level tree hash, every finding with location and escaped evidence, and an explicit `not_tested` list. That bundle is the audit artefact — it makes a review claim checkable later rather than a remembered assurance.

## Status

`chamber scan` — built and tested.
`chamber detonate` — the behavioural layer. Substantially built (a baseline diff, a live model
driver, a general exec-interception mechanism, a first corpus-wide reading) but not a shipped
product. See [ROADMAP.md](ROADMAP.md) for what's built, what's a documented gap, and the
findings so far — stated with their limits, not instead of them.

## Licence

MIT. Built by [Frontier Practice Advisory](https://github.com/calmseas).

