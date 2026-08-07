"""Deterministic legibility checks for installable prompt artefacts."""
from .rules import FAIL, FLAG, Finding, decode_tag_block, decode_variation_selectors
from .scan import diff_scan, scan_path, to_json

__all__ = ["FAIL", "FLAG", "Finding", "decode_tag_block", "decode_variation_selectors", "diff_scan", "scan_path", "to_json"]
__version__ = "0.1.0"
