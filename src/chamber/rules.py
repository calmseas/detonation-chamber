"""The checks themselves.

Every rule here is deterministic and answers a *decidable* question. None of
them tries to decide whether an artefact is malicious -- that is not decidable,
and tools that claim it get bypassed (Trail of Bits, 3 June 2026: "no amount of
scanning or LLM analysis can reliably detect malicious content in agent skills").

What IS decidable is whether an artefact is **legible**: whether the bytes a
human approves are the bytes the model receives. That is the gap Rashidi
documented in the Model Context Protocol (arXiv:2607.05744) -- "nothing in the
protocol requires the rendered approval view and the bytes delivered to the
model to match" -- and it is what these rules close.

A rule never returns a boolean. It returns evidence: what was found, where, and
the offending bytes escaped so they survive being pasted into a terminal, a
ticket or a report.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

# --- severity -----------------------------------------------------------------
FAIL = "fail"  # no legitimate use; do not install without a recorded exception
FLAG = "flag"  # legitimate uses exist; a human decides, with the evidence


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    detail: str
    line: int | None = None
    col: int | None = None
    evidence: str = ""
    # Set when a rule can recover concealed content (see decode_tag_block).
    decoded: str | None = None


# --- character classes --------------------------------------------------------
#
# TAG block. U+E0020..U+E007E are TAG SPACE .. TAG TILDE and map 1:1 onto ASCII
# 0x20..0x7E, so an entire instruction can be written in them. No mainstream
# terminal, chat client or IDE assigns them a glyph, which is precisely why they
# defeat a human reviewer and a naive string sanitiser simultaneously.
TAG_START, TAG_END = 0xE0000, 0xE007F

# Trojan Source (CVE-2021-42574). Bidi overrides and isolates let displayed
# order differ from logical order, so the reviewer reads one thing and the
# tokeniser another.
BIDI = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # embeddings + overrides
    0x2066, 0x2067, 0x2068, 0x2069,          # isolates
}

# Private Use Area. No standard meaning, renders inconsistently or not at all.
PUA_RANGES = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))

# Variation selectors form a byte-smuggling carrier (Butler, 2025). Two ranges,
# treated differently because their legitimate use differs:
#
#   - The SUPPLEMENT (U+E0100-E01EF) is the ideographic variation database. It
#     never appears in an English prose artefact, and any text payload -- whose
#     bytes are ≥0x20 and therefore map here -- always uses it. So a single one
#     is already smuggling: FAIL on sight.
#   - The BASIC range (U+FE00-FE0F) includes VS15/VS16, the emoji-presentation
#     selectors. A LONE one after an emoji (❤️ = ❤ + U+FE0F) is completely
#     ordinary. Only a RUN of them is a carrier. So a lone basic selector is
#     legitimate-but-verify (FLAG); a run is concealment (FAIL).
VS_SUPPLEMENT = (0xE0100, 0xE01EF)
VS_BASIC = (0xFE00, 0xFE0F)
VARIATION_SELECTORS = (VS_BASIC, VS_SUPPLEMENT)  # full carrier, for decoding

# Invisible formatting with no legitimate business in a prompt artefact: the
# invisible math operators, combining grapheme joiner, Mongolian vowel
# separator, and the Hangul fillers that render as blank width.
INVISIBLE_OPS = {0x2061, 0x2062, 0x2063, 0x2064, 0x034F, 0x180E, 0x3164, 0xFFA0}

# Zero-width and soft formatting. These DO have legitimate uses (emoji ZWJ
# sequences, Persian/Indic joiners), so they flag rather than fail.
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x00AD, 0x2060, 0xFEFF}


def _in_ranges(cp: int, ranges) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _in_pua(cp: int) -> bool:
    return _in_ranges(cp, PUA_RANGES)


def _in_vs(cp: int) -> bool:
    return _in_ranges(cp, VARIATION_SELECTORS)


def is_nonglyph(cp: int) -> bool:
    """The single definition of "produces no glyph a reviewer sees", used by
    BOTH the classifier (R1) and the fidelity invariant (R2).

    The original bug was two rules maintaining separate blocklists: a code
    point could be missing from one and present in the other, so R2 stripped it
    (no fidelity finding) while R1 never listed it (no classification finding),
    and it survived into the model. One predicate closes that seam permanently.
    """
    # A lone basic variation selector (VS15/VS16) is legitimate emoji
    # presentation, so it is NOT counted as concealing here -- otherwise R2
    # would fire on every emoji-with-styling. The supplement range, which any
    # real payload uses, stays in the set. Runs of basic selectors are handled
    # by check_characters, which can see the run that this per-codepoint
    # predicate cannot.
    return (TAG_START <= cp <= TAG_END
            or cp in BIDI
            or cp in INVISIBLE_OPS
            or cp in ZERO_WIDTH
            or _in_pua(cp)
            or _in_ranges(cp, (VS_SUPPLEMENT,)))


def decode_tag_block(text: str) -> str:
    """Recover the ASCII hidden in TAG-block characters.

    This is the payoff of the whole rule: rather than reporting "suspicious
    invisible characters found", we hand the reviewer the concealed message.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            ascii_cp = cp - TAG_START
            out.append(chr(ascii_cp) if 0x20 <= ascii_cp <= 0x7E else "")
    return "".join(out)


def decode_variation_selectors(text: str) -> bytes:
    """Recover the byte stream hidden in variation selectors.

    VS1-16 carry byte values 0..15; the supplement carries 16..255. Together
    they are a full byte alphabet, so the concealed content may be arbitrary
    bytes rather than ASCII -- we hand back bytes and let the caller decode.
    """
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def _escape(s: str, limit: int = 120) -> str:
    """Render evidence safely -- invisible characters become visible escapes."""
    shown = "".join(
        ch if ch.isprintable() and ord(ch) < 0x2000 else f"\\u{{{ord(ch):04X}}}"
        for ch in s[:limit]
    )
    return shown + ("…" if len(s) > limit else "")


def _positions(text: str):
    """Yield (index, char, line, col) so findings can cite a location."""
    line = col = 1
    for i, ch in enumerate(text):
        yield i, ch, line, col
        if ch == "\n":
            line, col = line + 1, 1
        else:
            col += 1


# --- R1 / R2: legibility ------------------------------------------------------

def check_characters(path: str, text: str) -> list[Finding]:
    """Characters that reach the model but never reach the reviewer's eye.

    R1 (classification) and R2 (render fidelity) are the same evidence read two
    ways, so they are produced together: the offending code points, and -- where
    recoverable -- what they actually say.
    """
    findings: list[Finding] = []
    tag_hits: list[tuple[int, int]] = []
    vs_hits: list[tuple[int, int]] = []

    for _, ch, line, col in _positions(text):
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            tag_hits.append((line, col))
        elif _in_vs(cp):
            vs_hits.append((line, col))
        elif cp in BIDI:
            findings.append(Finding(
                "R1.bidi", FAIL, path, line=line, col=col,
                detail=f"bidirectional control U+{cp:04X} ({unicodedata.name(ch, '?')}) — "
                       "displayed order can differ from logical order (Trojan Source, CVE-2021-42574)",
                evidence=_escape(ch),
            ))
        elif _in_pua(cp):
            findings.append(Finding(
                "R1.pua", FAIL, path, line=line, col=col,
                detail=f"private-use character U+{cp:04X} — no standard meaning, renders inconsistently",
                evidence=_escape(ch),
            ))
        elif cp in INVISIBLE_OPS:
            findings.append(Finding(
                "R1.invisible", FAIL, path, line=line, col=col,
                detail=f"invisible formatting character U+{cp:04X} ({unicodedata.name(ch, '?')}) — "
                       "renders as no or blank width; no legitimate use in a prompt artefact",
                evidence=_escape(ch),
            ))
        elif cp in ZERO_WIDTH:
            findings.append(Finding(
                "R1.zerowidth", FLAG, path, line=line, col=col,
                detail=f"zero-width/soft character U+{cp:04X} ({unicodedata.name(ch, '?')}) — "
                       "legitimate in emoji and some scripts; verify it belongs here",
                evidence=_escape(ch),
            ))

    if tag_hits:
        decoded = decode_tag_block(text)
        line, col = tag_hits[0]
        findings.append(Finding(
            "R1.tag", FAIL, path, line=line, col=col,
            detail=f"{len(tag_hits)} Unicode TAG-block characters — invisible in every mainstream "
                   "renderer, delivered byte-for-byte to the model (arXiv:2607.05744)",
            evidence=f"first at line {line} col {col}",
            decoded=decoded or None,
        ))

    if vs_hits:
        raw = decode_variation_selectors(text)
        # A real byte-stream payload decodes to mostly-printable text. Adjacent
        # styled emoji (each carrying VS16) also produce a run of selectors, but
        # decode to control bytes (0x0F …) -- the same printability gate that
        # separates a smuggled command from a hash separates a carrier here from
        # ordinary emoji presentation. The supplement range is never emoji
        # styling, so its presence is a carrier regardless.
        supplement = any(0xE0100 <= cp <= 0xE01EF for cp in map(ord, text))
        carrier = supplement or _decode_printable_ratio(raw) > 0.8
        line, col = vs_hits[0]
        if carrier:
            decoded = _escape(raw.decode("utf-8", "replace"), 200) if raw else None
            findings.append(Finding(
                "R1.varsel", FAIL, path, line=line, col=col,
                detail=f"{len(vs_hits)} Unicode variation selectors — invisible carrier for a byte "
                       "stream (Butler, 2025); delivered to the model, absent from the reviewer's view",
                evidence=f"first at line {line} col {col}",
                decoded=decoded,
            ))
        else:
            findings.append(Finding(
                "R1.varsel", FLAG, path, line=line, col=col,
                detail=f"{len(vs_hits)} variation selector(s) — ordinary for emoji presentation (❤️), "
                       "but verify they are attached to emoji and not concealing data",
                evidence=f"line {line} col {col}",
            ))

    return findings


def check_render_fidelity(path: str, text: str) -> list[Finding]:
    """The invariant, stated directly: stripping everything that produces no
    glyph must not change the text. If it does, the artefact carries content
    that reaches the model and not the reviewer."""
    stripped = "".join(ch for ch in text if not is_nonglyph(ord(ch)))
    if stripped == text:
        return []
    return [Finding(
        "R2.fidelity", FAIL, path,
        detail=f"approval-view text differs from delivered text by {len(text) - len(stripped)} "
               "character(s) — what a reviewer reads is not what the model receives",
        evidence=f"{len(text)} delivered vs {len(stripped)} visible",
    )]


# --- R3: truncation and padding ----------------------------------------------

def check_size(path: str, text: str, *, review_window: int = 10_000,
               hard_limit: int = 100_000, max_blank_run: int = 20,
               max_line: int = 2_000) -> list[Finding]:
    """Content a reviewer will never see because it is out of frame.

    The review_window default of 10,000 characters is not arbitrary: placing a
    malicious instruction beyond a reviewer's truncation window produced 87.1%
    clean verdicts and 0% classified malicious (Saha, Faghih & Feizi, 2026).
    """
    findings: list[Finding] = []

    if len(text) > hard_limit:
        findings.append(Finding(
            "R3.size", FAIL, path,
            detail=f"{len(text):,} characters exceeds the {hard_limit:,} hard limit — "
                   "no reviewer or scanner reads this far",
            evidence=f"{len(text):,} chars",
        ))
    elif len(text) > review_window:
        findings.append(Finding(
            "R3.window", FLAG, path,
            detail=f"{len(text):,} characters exceeds the {review_window:,} review window — "
                   "content past that point is unlikely to have been read",
            evidence=f"{len(text):,} chars",
        ))

    # "Blank-ish" means blank OR near-empty (a lone space, dot or dash used as
    # a run-breaker). The original rule counted only strictly-empty lines, so a
    # near-empty line every 20 rows reset the counter and slid a payload out of
    # frame while every run stayed under threshold.
    run = start = blankish_total = 0
    lines = text.splitlines()
    for n, raw in enumerate(lines, 1):
        if len(raw.strip()) <= 1:
            if run == 0:
                start = n
            run += 1
            blankish_total += 1
        else:
            if run > max_blank_run:
                findings.append(Finding(
                    "R3.padding", FAIL, path, line=start,
                    detail=f"{run} consecutive blank/near-empty lines — padding pushes content out "
                           "of a scanner's inspection window (Trail of Bits, June 2026)",
                    evidence=f"lines {start}–{start + run - 1}",
                ))
            run = 0
        if len(raw) > max_line:
            findings.append(Finding(
                "R3.longline", FLAG, path, line=n,
                detail=f"line is {len(raw):,} characters — content scrolls out of view",
                evidence=_escape(raw[:80]),
            ))
    if run > max_blank_run:
        findings.append(Finding(
            "R3.padding", FAIL, path, line=start,
            detail=f"{run} consecutive blank/near-empty lines at end of file",
            evidence=f"lines {start}–{start + run - 1}",
        ))

    # Cumulative check: a file that is MOSTLY vertical whitespace is padded
    # even when no single run is long and the total stays under the window.
    if len(lines) >= 200 and blankish_total > 4 * (len(lines) - blankish_total):
        findings.append(Finding(
            "R3.vertical", FAIL, path,
            detail=f"{blankish_total:,} of {len(lines):,} lines are blank or near-empty — the file "
                   "is mostly vertical whitespace, which pushes real content out of frame",
            evidence=f"{blankish_total:,}/{len(lines):,} lines blank-ish",
        ))

    return findings


# --- R4: structure ------------------------------------------------------------

_MAGIC = {
    b"PK\x03\x04": ("zip/docx/xlsx archive", FLAG),
    b"\x1f\x8b": ("gzip stream", FLAG),
    b"\xfd7zXZ": ("xz archive", FLAG),
    b"BZh": ("bzip2 archive", FLAG),
    b"\xcf\xfa\xed\xfe": ("Mach-O binary", FAIL),
    b"\x7fELF": ("ELF binary", FAIL),
}

# Base64 appears two ways in real files: one long run, or wrapped across lines
# (MIME wraps at 76). Matching a single unbroken run misses the wrapped case,
# and widening the character class to include whitespace would match ordinary
# prose. So: detect base64-shaped LINES and group consecutive ones.
#
# The thresholds are LOW on purpose -- a whole `curl … | sh` base64-encodes to
# ~44 characters, so a 200-char floor let real command payloads through. The
# false positives that floor was guarding against are handled instead by a
# decode gate (_looks_like_hidden_text): a short base64-shaped token only flags
# if it decodes to mostly-printable bytes, which a concealed instruction does
# and a hash, id or random token does not.
_B64_LINE = re.compile(r"^[A-Za-z0-9+/=]{24,}$")
_B64_INLINE = re.compile(r"[A-Za-z0-9+/=]{24,}")
_B64_MIN_CHARS = 24

# Ascii85 / base85 uses a different, wider alphabet (0x21-0x75), disjoint enough
# from base64 that the base64 matcher never sees it.
_A85_INLINE = re.compile(r"[\x21-\x75]{30,}")


def _decode_printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(raw)


def _looks_like_hidden_text(blob: str, alphabet: str) -> tuple[bytes, bool]:
    """Decode a candidate blob; report whether it looks like concealed text.

    Returns (decoded_bytes, is_suspicious). Suspicious means it decoded to
    mostly-printable content -- the property that separates a smuggled
    instruction from an ordinary hash or opaque token.
    """
    try:
        if alphabet == "base64":
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        else:  # ascii85
            raw = base64.a85decode(blob, foldspaces=False)
    except Exception:
        return b"", False
    return raw, _decode_printable_ratio(raw) > 0.8


def check_binary(path: str, data: bytes) -> list[Finding]:
    """Executable or archived content smuggled into a text artefact."""
    findings: list[Finding] = []
    for magic, (what, sev) in _MAGIC.items():
        if data.startswith(magic):
            findings.append(Finding(
                "R4.binary", sev, path,
                detail=f"{what} — an installable prompt artefact should be readable text",
                evidence=magic.hex(),
            ))
    # Python bytecode: source and .pyc can diverge, and the reviewer reads source.
    if path.endswith(".pyc") or data[:4] in (b"\x6f\x0d\x0d\x0a", b"\xa7\x0d\x0d\x0a", b"\xcb\x0d\x0d\x0a"):
        findings.append(Finding(
            "R4.bytecode", FAIL, path,
            detail="Python bytecode — behaviour can diverge from the source a reviewer reads "
                   "(Trail of Bits bypass, June 2026)",
            evidence=data[:4].hex(),
        ))
    return findings


def check_encoded_blobs(path: str, text: str) -> list[Finding]:
    """Long base64: legitimate in a data file, rarely in an instruction.

    Handles both the single-run and the line-wrapped forms -- the wrapped form
    is what you actually meet in the wild, and matching only unbroken runs
    silently misses it.
    """
    findings: list[Finding] = []
    blocks: list[tuple[int, list[str]]] = []
    current: list[str] = []
    start = 0

    for n, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if _B64_LINE.match(stripped):
            # Whole line is base64-shaped: part of a wrapped block.
            if not current:
                start = n
            current.append(stripped)
            continue
        if current:
            blocks.append((start, current))
            current = []
        # Otherwise look for a run embedded mid-line ("data: QUJD…"). Prose
        # cannot match this because the class excludes whitespace.
        for m in _B64_INLINE.finditer(raw):
            blocks.append((n, [m.group(0)]))
        for m in _A85_INLINE.finditer(raw):
            blocks.append((n, [m.group(0), "\x00a85"]))  # tag marks the alphabet
    if current:
        blocks.append((start, current))

    seen: set[tuple[int, str]] = set()
    for line, chunk in blocks:
        alphabet = "ascii85" if chunk[-1:] == ["\x00a85"] else "base64"
        blob = "".join(c for c in chunk if c != "\x00a85")
        if len(blob) < _B64_MIN_CHARS:
            continue

        raw, suspicious = _looks_like_hidden_text(blob, alphabet)
        # A long blob is worth a FLAG for illegibility regardless; a SHORT one
        # only earns a finding if it decodes to concealed text, so ordinary
        # tokens, ids and hashes stay quiet.
        if len(blob) < 200 and not suspicious:
            continue
        key = (line, blob[:40])
        if key in seen:
            continue
        seen.add(key)

        preview = _escape(raw.decode("utf-8", "replace"), 80) if raw else None
        span = f"line {line}" if len(chunk) - (chunk[-1:] == ["\x00a85"]) == 1 \
            else f"lines {line}–{line + len(chunk) - 2}"
        sev = FAIL if suspicious else FLAG
        findings.append(Finding(
            "R4.encoded", sev, path, line=line,
            detail=f"{len(blob):,} characters of {alphabet} across {span} — "
                   + ("decodes to readable text a reviewer never sees"
                      if suspicious else "content a reviewer cannot read in place"),
            evidence=_escape(blob[:60]),
            decoded=preview or None,
        ))
    return findings


# --- R5: homoglyphs -----------------------------------------------------------

# Scripts treated as ASCII-confusable for the mixed-script rule. Cyrillic is the
# reliable homoglyph vector -- it carries a full set of Latin look-alikes
# (а е о р с х у і ѕ). Greek is deliberately EXCLUDED: its letters are
# overwhelmingly maths symbols (π θ ζ ω Σ Γ) that resemble no ASCII letter, so
# including it flagged every equation. The handful of genuinely-confusable Greek
# letters (ο ρ ν) need a real Unicode confusables table -- a roadmap item -- not
# a blanket script match that cries wolf on maths.
_CONFUSABLE_SCRIPTS = ("LATIN", "CYRILLIC", "ARMENIAN")

# Blocks whose whole purpose is styled Latin/digits -- a token drawn from these
# reads as ASCII but is not ASCII (mathematical alphanumerics, fullwidth forms).
_STYLED_LATIN = ((0x1D400, 0x1D7FF), (0xFF21, 0xFF5A), (0x2460, 0x24FF))


def _script(ch: str) -> str | None:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for s in _CONFUSABLE_SCRIPTS:
        if name.startswith(s):
            return s
    return None


def check_mixed_script(path: str, text: str) -> list[Finding]:
    """Homoglyph spoofing, in the two forms with a clean discriminator:

    - MIXED-script word: a look-alike substituted INTO an ASCII-shaped word,
      `cliеnt` with one Cyrillic е, or `ѕtg_clients` with a Cyrillic ѕ. Requires
      at least two ASCII letters in the token -- a lone Greek ζ or π used as a
      maths symbol shares a "word" with parens and digits but is content, not a
      spoof, and must not flag.
    - STYLED-Latin token: built from the Mathematical Alphanumeric or Fullwidth
      blocks, which exist ONLY as ASCII-letter look-alikes (`𝖼𝗅𝗂𝖾𝗇𝗍` reads
      "client"). These ranges are specific and unambiguous, so this fires
      regardless of the surrounding script mix.

    Deliberately NOT attempted here: treating every non-Latin letter as an ASCII
    confusable. Greek ζ and Cyrillic ж resemble no ASCII letter, and a blanket
    rule false-positives on genuine maths and Russian. A full Unicode
    confusables table is the roadmap item; until then this covers the reliable
    cases and defers the rest rather than crying wolf.
    """
    findings = []
    for n, raw in enumerate(text.splitlines(), 1):
        flagged = False
        for word in re.findall(r"\S+", raw):
            # Styled-Latin: any character from a look-alike-only block spoofs.
            if any(_in_ranges(ord(c), _STYLED_LATIN) for c in word):
                findings.append(Finding(
                    "R5.homoglyph", FLAG, path, line=n,
                    detail="token uses mathematical/fullwidth look-alikes of ASCII letters — "
                           "reads as ASCII but compares unequal to the name it imitates",
                    evidence=_escape(word, 40),
                ))
                flagged = True
                break
            # Mixed-script: needs an ASCII-shaped host word to be spoofing one.
            if sum(1 for c in word if c.isascii() and c.isalpha()) < 2:
                continue
            scripts = {s for s in (_script(c) for c in word) if s}
            if len(scripts) > 1:
                findings.append(Finding(
                    "R5.homoglyph", FLAG, path, line=n,
                    detail=f"word mixes {' + '.join(sorted(scripts))} — look-alike characters "
                           "read identically and compare unequal",
                    evidence=_escape(word, 40),
                ))
                flagged = True
                break
        if flagged:
            continue  # one homoglyph finding per line is signal enough
    return findings


TEXT_RULES = (check_characters, check_render_fidelity, check_size,
              check_encoded_blobs, check_mixed_script)
