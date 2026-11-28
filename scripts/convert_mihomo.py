#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert the repository's Quantumult X blocklists into Mihomo rule sets.

Inputs (QX native, one rule per line):

    HOST,example.com,reject
    HOST-SUFFIX,example.com,reject
    HOST-WILDCARD,ulog*.example.com,reject
    HOST-KEYWORD,tracker,reject
    IP-CIDR,1.2.3.0/24,reject
    IP6-CIDR,2001:db8::/32,reject

Outputs, all under ``rules/mihomo/``:

    <Name>-domain.txt       behavior: domain    (plain text: bare domains / +.suffix)
    <Name>-domain.mrs       compiled by mihomo convert-ruleset domain text ...
    <Name>-classical.list   behavior: classical (plain text: DOMAIN-*/IP-CIDR* rules)

Three names are emitted: Anti-AdBlock, Anti-AdBlock-Extra, and Anti-AdBlock-All
(the union of the first two, deduplicated).  Every file is sorted and unique.

Nothing is silently dropped: every unrecognised or invalid rule is counted and
sampled in the log and in ``rules/mihomo/report.json``.

Usage:
    python scripts/convert_mihomo.py                     # convert from rules/*.list
    python scripts/convert_mihomo.py --local FILE=PATH ...  # override inputs
    python scripts/convert_mihomo.py --out DIR           # change output directory
    python scripts/convert_mihomo.py --mihomo /path/to/mihomo  # also compile .mrs

The .mrs compilation normally happens in GitHub Actions with the official
mihomo binary; --mihomo is for local verification.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

GENERATOR = "adblock-tracking-filters/convert-mihomo"

DEFAULT_SOURCES = {
    "Anti-AdBlock": "rules/Anti-AdBlock.list",
    "Anti-AdBlock-Extra": "rules/Anti-AdBlock-Extra.list",
}

# A domain label in a QX blocklist should be ASCII and free of characters that
# make no sense in a hostname.  Mihomo's trie is permissive (it only rejects
# empty labels, trailing dots and misplaced wildcards), so this is a *stricter*
# pre-filter: anything rejected here would either be invalid to Mihomo or
# match nothing useful.  Rejected items are logged, never silently discarded.
LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$")
DOMAIN_RE = re.compile(r"^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")

# Lines starting with any of these are comments.
COMMENT_PREFIXES = ("#", ";", "//")

SUPPORTED_QX_TYPES = {
    "HOST", "HOST-SUFFIX", "HOST-WILDCARD", "HOST-KEYWORD",
    "IP-CIDR", "IP6-CIDR",
}


class ConvertError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


class Stats:
    """Per-source counters plus bounded samples for anything skipped."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.samples: dict[str, list[str]] = {}

    def add(self, key: str, sample: str | None = None, limit: int = 20) -> None:
        self.counts[key] += 1
        if sample is not None:
            bucket = self.samples.setdefault(key, [])
            if len(bucket) < limit:
                bucket.append(sample[:200])

    def as_dict(self) -> dict:
        return {
            "counts": dict(sorted(self.counts.items())),
            "samples": {k: v for k, v in sorted(self.samples.items())},
        }


# --------------------------------------------------------------------------- #
# parsing helpers
# --------------------------------------------------------------------------- #

def strip_comment(raw: str) -> str:
    """Remove a trailing QX comment and surrounding whitespace.

    QX uses ``#``, ``;`` and ``//`` as comment markers.  A comment may follow
    a rule on the same line, e.g. ``HOST-SUFFIX,a.com,reject ; note``.
    """
    line = raw.strip()
    # Find the earliest comment marker.  For ``#`` and ``;`` anywhere in the
    # line; for ``//`` only when it follows a comma (so a value can never be
    # a URL here anyway).  Domains never legitimately contain these chars.
    cut = len(line)
    for marker in ("#", ";"):
        idx = line.find(marker)
        if idx != -1:
            cut = min(cut, idx)
    idx = line.find("//")
    if idx != -1:
        cut = min(cut, idx)
    return line[:cut].strip()


def clean_tokens(raw: str) -> list[str]:
    """Split one QX rule into stripped, non-empty comma-separated fields."""
    line = strip_comment(raw)
    if not line or line.startswith(COMMENT_PREFIXES):
        return []
    return [field.strip() for field in line.split(",") if field.strip()]


def valid_domain(domain: str) -> bool:
    """Conservative check matching Mihomo's domain-syntax expectations."""
    if not domain or len(domain) > 253:
        return False
    if domain.endswith(".") or domain.startswith("."):
        return False
    if any(ch.isspace() for ch in domain):
        return False
    return bool(DOMAIN_RE.match(domain)) and all(
        LABEL_RE.match(label) for label in domain.split(".")
    )


def valid_wildcard(pattern: str) -> bool:
    """Validate a HOST-WILDCARD pattern before emitting DOMAIN-WILDCARD.

    Mihomo's DOMAIN-WILDCARD uses ``component/wildcard.Match``: ``*`` matches
    zero or more characters and ``?`` matches exactly one.  Unlike its domain
    trie, the wildcard matcher allows multiple wildcards inside one label, so
    QX patterns like ``counter*-yadro*-ru.example.com`` are kept as-is.
    Only regex-style characters (``[](){}|\\``) and whitespace are rejected.
    """
    if not pattern or len(pattern) > 253 or pattern.startswith(".") or pattern.endswith("."):
        return False
    if any(ch.isspace() for ch in pattern):
        return False
    if "." not in pattern:
        return False
    if not re.match(r"^[a-z0-9_*?.-]+$", pattern):
        return False
    # A whole-label ``*`` / ``?`` is fine (e.g. ``events.*.oci.oraclecloud.com``);
    # only a pattern made entirely of wildcards would be too broad to emit.
    return any(ch.isalnum() for ch in pattern)


def valid_keyword(keyword: str) -> bool:
    return bool(keyword) and len(keyword) <= 100 and bool(
        re.match(r"^[a-z0-9_.*?+@-]+$", keyword)
    )


def valid_cidr(value: str, *, v6: bool) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return net.version == (6 if v6 else 4)


# --------------------------------------------------------------------------- #
# conversion
# --------------------------------------------------------------------------- #

class Converter:
    def __init__(self) -> None:
        self.domain: set[str] = set()
        self.classical: set[str] = set()
        self.stats = Stats()

    def feed_file(self, path: Path) -> None:
        log(f"- reading {path}")
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig", errors="replace")
        self.stats.add("source_lines", None)
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            tokens = clean_tokens(raw_line)
            if not tokens:
                self.stats.add("comment_or_blank")
                continue
            self.stats.add("source_rules")
            self._convert(tokens, lineno)

    def feed_text(self, text: str, label: str) -> None:
        log(f"- reading {label}")
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            tokens = clean_tokens(raw_line)
            if not tokens:
                self.stats.add("comment_or_blank")
                continue
            self.stats.add("source_rules")
            self._convert(tokens, lineno)

    def _convert(self, tokens: list[str], lineno: int) -> None:
        kind = tokens[0].upper()
        if kind not in SUPPORTED_QX_TYPES:
            self.stats.add("skipped_unsupported_type", f"L{lineno} " + ",".join(tokens))
            return
        if len(tokens) < 2:
            self.stats.add("skipped_missing_value", f"L{lineno} " + ",".join(tokens))
            return
        # Field 2 is the value/pattern; everything after it is the policy
        # action (reject/direct, or a policy group) and is deliberately dropped.
        value = tokens[1].strip().lower().lstrip(".")

        if kind == "HOST":
            # A bare IP in a HOST rule is rare; it is still a valid exact host
            # match, so keep it only if it parses as a domain-like label.
            if not value:
                self.stats.add("skipped_invalid_domain", f"L{lineno} HOST")
                return
            if not valid_domain(value) and not self._looks_like_ip(value):
                self.stats.add("skipped_invalid_domain", f"L{lineno} HOST,{value}")
                return
            self.domain.add(value)
            self.stats.add("domain_host")
            return

        if kind == "HOST-SUFFIX":
            if not valid_domain(value):
                self.stats.add("skipped_invalid_domain", f"L{lineno} HOST-SUFFIX,{value}")
                return
            self.domain.add("+." + value)
            self.stats.add("domain_suffix")
            return

        if kind == "HOST-WILDCARD":
            if not valid_wildcard(value):
                self.stats.add("skipped_invalid_wildcard", f"L{lineno} HOST-WILDCARD,{value}")
                return
            self.classical.add(f"DOMAIN-WILDCARD,{value}")
            self.stats.add("classical_wildcard")
            return

        if kind == "HOST-KEYWORD":
            if not valid_keyword(value):
                self.stats.add("skipped_invalid_keyword", f"L{lineno} HOST-KEYWORD,{value}")
                return
            self.classical.add(f"DOMAIN-KEYWORD,{value}")
            self.stats.add("classical_keyword")
            return

        if kind in ("IP-CIDR", "IP6-CIDR"):
            v6 = kind == "IP6-CIDR"
            if not valid_cidr(value, v6=v6):
                self.stats.add("skipped_invalid_cidr", f"L{lineno} {kind},{value}")
                return
            target = "IP-CIDR6" if v6 else "IP-CIDR"
            self.classical.add(f"{target},{value},no-resolve")
            self.stats.add("classical_ipcidr6" if v6 else "classical_ipcidr")
            return

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True


def merge(converters: list[Converter]) -> Converter:
    out = Converter()
    for conv in converters:
        out.domain |= conv.domain
        out.classical |= conv.classical
        for key, count in conv.stats.counts.items():
            out.stats.counts[key] += count
        for key, samples in conv.stats.samples.items():
            out.stats.samples.setdefault(key, []).extend(samples)
    out.stats.add("source_files", None)
    return out


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def write_outputs(out_dir: Path, results: dict[str, Converter]) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "generator": GENERATOR,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "outputs": {},
    }
    for name, conv in results.items():
        domain_text = "\n".join(sorted(conv.domain)) + "\n"
        classical_text = "\n".join(sorted(conv.classical)) + "\n"
        (out_dir / f"{name}-domain.txt").write_text(domain_text, encoding="utf-8", newline="\n")
        (out_dir / f"{name}-classical.list").write_text(classical_text, encoding="utf-8", newline="\n")
        report["outputs"][name] = {
            "domain": len(conv.domain),
            "classical": len(conv.classical),
            "total": len(conv.domain) + len(conv.classical),
            "stats": conv.stats.as_dict(),
        }
        log(
            f"= {name}: domain {len(conv.domain)}, classical {len(conv.classical)}, "
            f"skip {sum(v for k, v in conv.stats.counts.items() if k.startswith('skipped_'))}"
        )
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def compile_mrs(out_dir: Path, names: list[str], binary: str) -> None:
    """Run the official mihomo binary to compile each domain text file."""
    for name in names:
        src = out_dir / f"{name}-domain.txt"
        dst = out_dir / f"{name}-domain.mrs"
        log(f"- compiling {src.name} -> {dst.name}")
        cmd = [binary, "convert-ruleset", "domain", "text", str(src), str(dst)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[:500]
            raise ConvertError(
                f"mihomo convert-ruleset failed for {src.name} "
                f"(exit {result.returncode}): {detail}"
            )
        if not dst.exists() or dst.stat().st_size == 0:
            raise ConvertError(f"{dst.name} is missing or empty")
        log(f"  ok: {dst.stat().st_size} bytes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="rules/mihomo", help="output directory")
    parser.add_argument("--local", nargs="*", default=[], metavar="NAME=PATH",
                        help="override an input with a local QX file")
    parser.add_argument("--mihomo", default=None,
                        help="path to mihomo binary; if given, compile .mrs locally")
    args = parser.parse_args(argv)
    overrides = dict(item.split("=", 1) for item in args.local)

    out_dir = Path(args.out)
    converters: list[Converter] = []

    for name, default_path in DEFAULT_SOURCES.items():
        path = Path(overrides.get(name, default_path))
        conv = Converter()
        if not path.exists():
            raise ConvertError(f"input missing: {path} (use --local NAME=PATH)")
        conv.feed_file(path)
        converters.append(conv)

    results = {name: conv for name, conv in zip(DEFAULT_SOURCES, converters)}
    results["Anti-AdBlock-All"] = merge(converters)

    # Atomic-ish write: build in a temp dir, then replace each file.
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-mihomo-"))
    try:
        write_outputs(tmp, results)
        if args.mihomo:
            compile_mrs(tmp, list(results), args.mihomo)
        out_dir.mkdir(parents=True, exist_ok=True)
        for src in sorted(tmp.iterdir()):
            os.replace(src, out_dir / src.name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    log(f"\nwritten to {out_dir}/")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConvertError as exc:
        log(f"! FAILED: {exc}")
        sys.exit(1)
