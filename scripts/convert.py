#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert AdGuard filter lists into Quantumult X subscriptions.

Design goals, in priority order:

1. Never widen the blocking scope of an upstream rule.  A rule we cannot
   translate faithfully is skipped and reported, never approximated into
   something broader.
2. Never publish a truncated or obviously wrong download.  A broken run
   leaves the previous good files untouched.
3. Always emit a machine-readable report of what was skipped and why.

Only Quantumult X native output is produced, so the subscription never needs
a resource parser.

Usage:
    python scripts/convert.py                     # normal run (Actions)
    python scripts/convert.py --lean              # drop rules inside !#if blocks
    python scripts/convert.py --dry-run           # analyse, write nothing
    python scripts/convert.py --local spy=path    # use a local file instead of HTTP
    python scripts/convert.py --allow-small       # skip the byte-size floor (tests)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GENERATOR = "qx-adguard-tracking"
USER_AGENT = "qx-adguard-tracking/1.0 (+https://github.com/)"

RAW = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/"

SOURCES = {
    "spyware": {
        "name": "Spyware",
        "url": RAW + "filter_3_Spyware/filter.txt",
        "min_bytes": 5_000_000,
        "emit": "list+rewrite",
    },
    "trackparam": {
        "name": "TrackParam",
        "url": RAW + "filter_17_TrackParam/filter.txt",
        "min_bytes": 100_000,
        "emit": "report-only",
    },
}

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# Hosts that are shared infrastructure; blocking them as a whole would break
# unrelated sites, so they are refused even if upstream lists them.
SHARED_HOST_DENYLIST = {
    "github.io", "gitlab.io", "cloudfront.net", "azureedge.net",
    "s3.amazonaws.com", "herokuapp.com", "appspot.com", "blogspot.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "googleusercontent.com", "akamai.net", "fastly.net",
    "typekit.net", "sharepoint.com", "windows.net", "cloudapp.net",
}

# Every AdGuard platform constant evaluates to false for us: Quantumult X is
# not an AdGuard client.  AdGuard documents that constants which are absent
# are treated as false as well; we only keep this set so we can distinguish
# "known platform" from "genuinely unknown" in the report.
KNOWN_CONSTANTS = {
    "adguard", "adguard_ext_chromium", "adguard_ext_chromium_mv3",
    "adguard_ext_firefox", "adguard_ext_edge", "adguard_ext_safari",
    "adguard_ext_opera", "adguard_ext_android_cb", "adguard_app_windows",
    "adguard_app_mac", "adguard_app_android", "adguard_app_ios",
    "adguard_app_cli", "ext_ublock",
}

# AdGuard separator character class: `^` means "any char that is not a letter,
# digit, _ - . %".  End of string also matches.
ADG_SEPARATOR = r"(?:[^0-9A-Za-z_.%-]|$)"

COSMETIC_MARKERS = ("#%#", "#@%#", "#$#", "#@$#", "##", "#@#", "#?#", "#@?#", "$$")


class ConvertError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# logging / stats
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    print(msg, flush=True)


class Stats:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.samples: dict[str, list[str]] = {}

    def add(self, key: str, sample: str | None = None, limit: int = 25) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1
        if sample is not None:
            bucket = self.samples.setdefault(key, [])
            if len(bucket) < limit:
                bucket.append(sample)

    def as_dict(self) -> dict:
        return {
            "counts": dict(sorted(self.counts.items())),
            "samples": {k: v for k, v in sorted(self.samples.items())},
        }


# --------------------------------------------------------------------------- #
# download + integrity
# --------------------------------------------------------------------------- #

def fetch(url: str, min_bytes: int, retries: int = 4) -> bytes:
    last: Exception | None = None
    for attempt in range(retries):
        if attempt:
            wait = min(2 ** attempt, 20)
            log(f"  retry {attempt}/{retries - 1} in {wait}s ...")
            time.sleep(wait)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=120) as resp:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                declared = resp.headers.get("Content-Length")
                raw = resp.read()
            if "text/html" in ctype:
                raise ConvertError(f"server returned HTML (content-type {ctype})")
            if declared and declared.isdigit() and len(raw) != int(declared):
                raise ConvertError(
                    f"received {len(raw)} bytes but Content-Length says {declared} "
                    "-> truncated transfer"
                )
            if len(raw) < min_bytes:
                raise ConvertError(
                    f"payload only {len(raw)} bytes, expected >= {min_bytes} "
                    "(truncated or error page?)"
                )
            return raw
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = exc
            log(f"  network error: {exc}")
    raise ConvertError(f"download failed after {retries} attempts: {last}")


def decode_payload(raw: bytes, src: dict, strict: bool = True) -> str:
    """Decode and sanity-check a downloaded filter file."""
    if strict and not raw.endswith(b"\n"):
        raise ConvertError(
            "payload does not end with a newline -> almost certainly truncated"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConvertError(f"payload is not valid UTF-8: {exc}") from exc
    return text


def check_tail(text: str) -> None:
    """Reject a payload whose last line is an obvious fragment.

    The strong truncation signals are the Content-Length comparison in
    ``fetch()`` and the trailing-newline requirement in ``decode_payload()``.
    This is the cheap third net: a transfer cut mid-token leaves a line like
    ``||`` or ``@@||example.co`` behind.  It deliberately accepts any
    well-formed last line rather than insisting on a particular rule shape,
    because the last line of a real filter can be a comment, an ``@@``
    exception, a cosmetic rule, or a plain pattern.
    """
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        if len(line) < 4 or line.endswith("|"):
            raise ConvertError(f"last line of payload looks incomplete: {line!r}")
        return


# --------------------------------------------------------------------------- #
# conditional directives (!#if / !#else / !#endif)
# --------------------------------------------------------------------------- #

TOKEN_RE = re.compile(r"\s*(&&|\|\||!|\(|\)|[A-Za-z_][A-Za-z0-9_]*)\s*")


class Condition:
    """Tiny recursive-descent evaluator for AdGuard !#if expressions."""

    def __init__(self) -> None:
        self.unknown: set[str] = set()

    def evaluate(self, expr: str) -> bool:
        tokens = self._tokenize(expr)
        self._pos = 0
        self._tokens = tokens
        value = self._parse_or()
        if self._pos != len(self._tokens):
            raise ConvertError(f"unparsed trailing tokens in condition: {expr!r}")
        return value

    @staticmethod
    def _tokenize(expr: str) -> list[str]:
        tokens: list[str] = []
        pos = 0
        while pos < len(expr):
            m = TOKEN_RE.match(expr, pos)
            if not m:
                if expr[pos:].strip() == "":
                    break
                raise ConvertError(f"invalid character in condition: {expr!r}")
            tokens.append(m.group(1))
            pos = m.end()
        return tokens

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise ConvertError("unexpected end of condition")
        self._pos += 1
        return tok

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._peek() == "||":
            self._next()
            rhs = self._parse_and()
            value = value or rhs
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._peek() == "&&":
            self._next()
            rhs = self._parse_not()
            value = value and rhs
        return value

    def _parse_not(self) -> bool:
        if self._peek() == "!":
            self._next()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._next()
        if tok == "(":
            value = self._parse_or()
            if self._next() != ")":
                raise ConvertError("unbalanced parenthesis in condition")
            return value
        if tok in (")", "&&", "||", "!"):
            raise ConvertError(f"unexpected token {tok!r} in condition")
        if tok not in KNOWN_CONSTANTS:
            self.unknown.add(tok)
        return False  # every platform constant is false for Quantumult X


class CondStack:
    def __init__(self) -> None:
        self.frames: list[dict] = []

    @property
    def active(self) -> bool:
        return all(f["active"] for f in self.frames)

    def push(self, value: bool) -> None:
        parent = self.active
        self.frames.append(
            {"parent": parent, "taken": value, "active": parent and value}
        )

    def else_(self) -> None:
        if not self.frames:
            raise ConvertError("!#else without matching !#if")
        frame = self.frames[-1]
        frame["active"] = frame["parent"] and not frame["taken"]
        frame["taken"] = True

    def pop(self) -> None:
        if not self.frames:
            raise ConvertError("!#endif without matching !#if")
        self.frames.pop()


# --------------------------------------------------------------------------- #
# domain helpers
# --------------------------------------------------------------------------- #

LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class Psl:
    def __init__(self, path: Path) -> None:
        self.exact: set[str] = set()
        self.wildcard: set[str] = set()
        self.exception: set[str] = set()
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                self.exception.add(line[1:])
            elif line.startswith("*."):
                self.wildcard.add(line[2:])
            else:
                self.exact.add(line)

    @property
    def loaded(self) -> bool:
        return bool(self.exact)

    def is_public_suffix(self, domain: str) -> bool:
        if not self.exact:
            return False
        if domain in self.exception:
            return False
        if domain in self.exact:
            return True
        parent = domain.split(".", 1)[1] if "." in domain else ""
        return parent in self.wildcard


def normalize_domain(raw: str) -> str | None:
    domain = raw.strip().lower().rstrip(".")
    if not domain:
        return None
    if domain.startswith("*."):
        domain = domain[2:]
    domain = domain.lstrip(".")
    if not domain or len(domain) > 253:
        return None
    if any(ord(ch) > 127 for ch in domain):
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not all(LABEL_RE.match(label) for label in domain.split(".")):
        return None
    if domain.count(".") == 0:
        return None
    tld = domain.rsplit(".", 1)[-1]
    if not tld or tld.isdigit() or len(tld) < 2:
        return None
    if tld == "onion":
        return None
    return domain


# --------------------------------------------------------------------------- #
# rule classification
# --------------------------------------------------------------------------- #

def cosmetic_marker_index(line: str) -> int:
    first = -1
    for marker in COSMETIC_MARKERS:
        idx = line.find(marker)
        if idx != -1 and (first == -1 or idx < first):
            first = idx
    return first


def split_modifiers(pattern: str) -> tuple[str, list[str]]:
    if "$" not in pattern:
        return pattern, []
    base, mods = pattern.split("$", 1)
    return base, [t.strip() for t in mods.split(",") if t.strip()]


def host_to_regex(host: str) -> str:
    return r"(?:[a-z0-9-]+\.)*" + re.escape(host)


def path_to_regex(path: str) -> str:
    out: list[str] = []
    for ch in path:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(ADG_SEPARATOR)
        elif ch == "|":
            out.append(r"\|")
        else:
            out.append(re.escape(ch))
    return "".join(out)


class Conversion:
    def __init__(self, psl: Psl) -> None:
        self.psl = psl
        self.host_suffix: set[str] = set()
        self.host_exact: set[str] = set()
        self.host_wildcard: set[str] = set()
        self.rewrites: dict[str, dict] = {}  # regex -> {host, sample}
        self.allow: set[str] = set()
        self.badfilter: set[str] = set()
        self.stats = Stats()

    # -- helpers ---------------------------------------------------------- #

    def _domain_ok(self, domain: str, sample: str) -> bool:
        if domain in SHARED_HOST_DENYLIST:
            self.stats.add("domain_shared_host_refused", sample)
            return False
        if self.psl.is_public_suffix(domain):
            self.stats.add("domain_public_suffix_refused", sample)
            return False
        return True

    # -- main entry ------------------------------------------------------- #

    def feed(self, text: str, *, lean: bool = False) -> None:
        cond = CondStack()
        evaluator = Condition()
        hint_pending = False
        pending_lines: list[tuple[int, str]] = []

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line:
                continue

            if line.startswith("!"):
                if line.startswith("!#"):
                    directive = line[2:].strip()
                    if directive.startswith("if"):
                        expr = directive[2:].strip()
                        value = evaluator.evaluate(expr) if expr else False
                        cond.push(False if lean else value)
                        self.stats.add("directive_if")
                    elif directive.startswith("else"):
                        cond.else_()
                        self.stats.add("directive_else")
                    elif directive.startswith("endif"):
                        cond.pop()
                        self.stats.add("directive_endif")
                    elif directive.startswith("include"):
                        raise ConvertError(
                            f"line {lineno}: !#include is not supported "
                            "(would silently drop a whole section)"
                        )
                elif line.startswith("!+"):
                    hint_pending = True
                    self.stats.add("platform_hint", line)
                continue

            if not cond.active:
                self.stats.add("skipped_inactive_condition", line)
                continue
            if hint_pending:
                hint_pending = False
                self.stats.add("skipped_platform_hint", line)
                continue

            pending_lines.append((lineno, line))

        if cond.frames:
            raise ConvertError(
                "unbalanced !#if / !#endif (file would be mis-parsed silently)"
            )
        if evaluator.unknown:
            self.stats.counts["unknown_condition_constants"] = len(evaluator.unknown)
            self.stats.samples["unknown_condition_constants"] = sorted(evaluator.unknown)

        # Second pass: $badfilter must be able to remove rules that appear
        # earlier, so collect them first.
        for _, line in pending_lines:
            if "$badfilter" in line:
                self._collect_badfilter(line)

        for _, line in pending_lines:
            if "$badfilter" in line:
                continue
            self._convert_line(line)

        # Apply allowlist exceptions and badfilter removals last.
        for domain in self.allow:
            self.host_suffix.discard(domain)
            self.host_exact.discard(domain)
        for pattern in self.badfilter:
            self.host_suffix.discard(pattern)
            self.host_exact.discard(pattern)
            self.host_wildcard.discard(pattern)

    # -- per-rule --------------------------------------------------------- #

    def _collect_badfilter(self, line: str) -> None:
        pattern, _ = split_modifiers(line)
        if pattern.startswith("@@"):
            pattern = pattern[2:]
        if pattern.startswith("||"):
            pattern = pattern[2:]
            pattern = pattern.rstrip("^")
        if "/" not in pattern and pattern:
            self.badfilter.add(pattern.lower())
            self.stats.add("badfilter_removed", line)

    def _convert_line(self, line: str) -> None:
        marker = cosmetic_marker_index(line)
        dollar = line.find("$")
        if marker != -1 and (dollar == -1 or marker <= dollar):
            self.stats.add("skipped_cosmetic_or_scriptlet", line)
            return

        if line.startswith("@@"):
            self._convert_exception(line)
            return

        if line.startswith("||"):
            self._convert_host_rule(line)
            return

        if line.startswith("/") and line.rstrip().endswith("/"):
            self.stats.add("skipped_regex_rule", line)
            return

        if line.startswith("|"):
            self.stats.add("skipped_unknown_anchor", line)
            return

        if line.startswith("$"):
            # standalone modifier rule, e.g. `$removeparam=utm_source`, which
            # applies to every request on every site
            _, mods = split_modifiers(line)
            name = mods[0].split("=")[0] if mods else "unknown"
            name = re.sub(r"[^a-z0-9]+", "_", name.lower())[:24]
            self.stats.add("skipped_generic_" + name, line)
            return

        self.stats.add("skipped_plain_pattern", line)

    def _convert_exception(self, line: str) -> None:
        body = line[2:]
        pattern, mods = split_modifiers(body)
        if mods and any(m not in ("important", "document") for m in mods):
            self.stats.add("skipped_exception_modifier", line)
            return
        pattern = pattern.lstrip("|").rstrip("^")
        if "/" in pattern or "*" in pattern or not pattern:
            self.stats.add("skipped_exception_unsupported", line)
            return
        domain = normalize_domain(pattern)
        if not domain:
            self.stats.add("skipped_exception_bad_domain", line)
            return
        self.allow.add(domain)
        self.stats.add("exception_allowlisted", line)

    def _convert_host_rule(self, line: str) -> None:
        body = line[2:]
        pattern, mods = split_modifiers(body)
        if mods:
            tokens = set(mods)
            if tokens == {"important"}:
                pass  # priority only, does not narrow the match
            elif tokens == {"third-party"}:
                self.stats.add("skipped_third_party", line)
                return
            elif tokens == {"~third-party"}:
                self.stats.add("skipped_first_party_only", line)
                return
            else:
                self.stats.add("skipped_modifier_" + re.sub(r"[^a-z0-9]+", "_", mods[0].split("=")[0])[:24], line)
                return

        terminated = pattern.endswith("^")
        core = pattern[:-1] if terminated else pattern

        if "/" in core:
            host, rest = core.split("/", 1)
            self._emit_rewrite(host, "/" + rest, line, terminated)
            return

        if "|" in core or " " in core:
            self.stats.add("skipped_malformed", line)
            return

        if not terminated:
            # `||host` without the separator also matches host.attacker.tld,
            # so it cannot be expressed as a suffix rule faithfully.
            self.stats.add("skipped_no_separator", line)
            return

        if "*" in core or "?" in core:
            if not self._wildcard_ok(core):
                return
            self.host_wildcard.add(core.lower())
            self.stats.add("host_wildcard", line)
            return

        if IPV4_RE.match(core):
            if all(0 <= int(p) <= 255 for p in core.split(".")):
                self.host_exact.add(core)
                self.stats.add("host_ip", line)
                return
            self.stats.add("skipped_invalid_ip", line)
            return

        domain = normalize_domain(core)
        if not domain:
            self.stats.add("skipped_invalid_domain", line)
            return
        if not self._domain_ok(domain, line):
            return
        self.host_suffix.add(domain)
        self.stats.add("host_suffix", line)

    def _wildcard_ok(self, pattern: str) -> bool:
        # `*.example.com` blocks every subdomain of a live domain; too broad
        # to publish automatically, and upstream rarely means it that way.
        if pattern.startswith("*."):
            self.stats.add("skipped_wildcard_too_broad", pattern)
            return False
        if "." not in pattern:
            self.stats.add("skipped_wildcard_too_broad", pattern)
            return False
        literal_tail = pattern.split("*")[-1].split("?")[-1]
        if literal_tail.startswith(".") and len(literal_tail) < 4:
            self.stats.add("skipped_wildcard_too_broad", pattern)
            return False
        if not re.match(r"^[A-Za-z0-9*?._-]+$", pattern):
            self.stats.add("skipped_wildcard_charset", pattern)
            return False
        return True

    def _emit_rewrite(self, host: str, path: str, line: str, terminated: bool) -> None:
        if "*" in host or "?" in host:
            self.stats.add("skipped_rewrite_wildcard_host", line)
            return
        domain = normalize_domain(host)
        if not domain:
            self.stats.add("skipped_rewrite_bad_host", line)
            return
        if not path.startswith("/"):
            self.stats.add("skipped_rewrite_bad_path", line)
            return
        body = path[:-1] if path.endswith("^") else path
        if not body.strip("/"):
            self.stats.add("skipped_rewrite_empty_path", line)
            return

        regex = "(?i)^https?://" + host_to_regex(domain) + r"(?::\d+)?" + path_to_regex(body)
        if terminated:
            # `^` at the end of an AdGuard mask means "separator or end of
            # string"; without it the regex would also match /advertisement.
            regex += ADG_SEPARATOR
        regex = regex.replace(" ", r"\x20")
        if len(regex) > 300:
            self.stats.add("skipped_rewrite_too_long", line)
            return
        self.rewrites.setdefault(regex, {"host": domain, "sample": line})
        self.stats.add("rewrite", line)


# --------------------------------------------------------------------------- #
# output builders
# --------------------------------------------------------------------------- #

def build_list(conv: Conversion, header: list[str]) -> str:
    lines = list(header)
    for domain in sorted(conv.host_suffix):
        lines.append(f"HOST-SUFFIX,{domain},reject")
    for ip in sorted(conv.host_exact):
        lines.append(f"HOST,{ip},reject")
    for pattern in sorted(conv.host_wildcard):
        lines.append(f"HOST-WILDCARD,{pattern},reject")
    return "\n".join(lines) + "\n"


def build_rewrite(conv: Conversion, header: list[str]) -> str:
    lines = list(header)
    hosts: list[str] = []
    for regex in sorted(conv.rewrites):
        info = conv.rewrites[regex]
        lines.append(f"{regex} url reject")
        if info["host"] not in hosts:
            hosts.append(info["host"])
    lines.append("")
    if hosts:
        entries: list[str] = []
        for host in sorted(hosts):
            entries.append(f"*.{host}")
            entries.append(host)
        lines.append("hostname = " + ",".join(entries))
    return "\n".join(lines) + "\n"


def header_block(
    title: str, sources: list[str], counts: list[tuple[str, int]]
) -> list[str]:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    out = [
        f"# NAME: {title}",
        f"# GENERATOR: {GENERATOR}",
    ]
    for index, source in enumerate(sources, 1):
        key = "SOURCE" if index == 1 else f"SOURCE-{index}"
        out.append(f"# {key}: {source}")
    out.append(f"# UPDATED: {stamp}")
    for key, value in counts:
        out.append(f"# {key}: {value}")
    out.append("#")
    out.append("# 保守转换：无法忠实表达语义的规则一律跳过，明细见 report.json")
    return out


def build_skipped(conv: Conversion, source_label: str) -> str:
    lines = [f"# skipped rules from {source_label}", "#"]
    for key in sorted(conv.stats.counts):
        if not key.startswith("skipped_"):
            continue
        lines.append(f"# ---- {key}: {conv.stats.counts[key]}")
        for sample in conv.stats.samples.get(key, []):
            lines.append(sample)
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# guards
# --------------------------------------------------------------------------- #

def guard_against_regression(
    prev: dict | None, new_total: int, new_rewrite: int, force: bool
) -> None:
    if not prev or force:
        return
    prev_out = prev.get("outputs", {})
    checks = [
        ("Tracking.list", prev_out.get("Tracking.list", {}).get("rules", 0), new_total),
        ("Tracking.rewrite.conf", prev_out.get("Tracking.rewrite.conf", {}).get("rules", 0), new_rewrite),
    ]
    problems: list[str] = []
    for name, before, after in checks:
        if before >= 1000 and after == 0:
            problems.append(f"{name}: {before} -> 0")
        elif before >= 1000 and abs(after - before) / before > 0.25:
            problems.append(f"{name}: {before} -> {after} ({after / before:.0%})")
    if problems:
        raise ConvertError(
            "output size changed unexpectedly, refusing to publish: "
            + "; ".join(problems)
            + " (use --force to override)"
        )


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def load_source(key: str, src: dict, args) -> tuple[str, dict]:
    meta: dict = {"name": src["name"], "url": src["url"]}
    if key in args.local:
        path = Path(args.local[key])
        raw = path.read_bytes()
        meta["url"] = f"local:{path.name}"
    else:
        log(f"- downloading {src['name']} ...")
        raw = fetch(src["url"], 0 if args.allow_small else src["min_bytes"])
    text = decode_payload(raw, src, strict=not args.force)
    if not args.allow_small:
        if args.force:
            log("  WARNING: --force given, tail integrity check skipped")
        else:
            check_tail(text)
    meta.update(
        bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest()[:16],
        lines=len(text.splitlines()),
    )
    log(f"  ok: {meta['bytes']} bytes, {meta['lines']} lines")
    return text, meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="rules", help="output directory")
    parser.add_argument("--data", default="data", help="cache directory (PSL)")
    parser.add_argument("--lean", action="store_true", help="drop rules inside !#if blocks")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="ignore regression guard")
    parser.add_argument("--allow-small", action="store_true", help="skip size floor (testing)")
    parser.add_argument(
        "--local", nargs="*", default=[], metavar="KEY=PATH",
        help="read a source from a local file instead of HTTP",
    )
    args = parser.parse_args(argv)
    args.local = dict(item.split("=", 1) for item in args.local)

    out_dir = Path(args.out)
    data_dir = Path(args.data)

    # --- PSL -------------------------------------------------------------
    psl_path = data_dir / "public_suffix_list.dat"
    if not psl_path.exists() and not args.dry_run:
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            log("- downloading public suffix list ...")
            raw = fetch(PSL_URL, 100_000)
            psl_path.write_bytes(raw)
            log(f"  ok: {len(raw)} bytes")
        except (ConvertError, OSError) as exc:
            log(f"  WARNING: could not fetch PSL ({exc}); public-suffix guard disabled")
    psl = Psl(psl_path)
    log(f"- PSL loaded: {'yes' if psl.loaded else 'NO (guard disabled)'}")

    # --- convert ---------------------------------------------------------
    report: dict = {
        "generator": GENERATOR,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lean": args.lean,
        "psl_loaded": psl.loaded,
        "sources": {},
        "outputs": {},
        "warnings": [],
    }
    if not psl.loaded:
        report["warnings"].append("public suffix list unavailable; guard disabled")

    conv = Conversion(psl)
    texts: dict[str, tuple[str, dict]] = {}
    for key, src in SOURCES.items():
        text, meta = load_source(key, src, args)
        texts[key] = (text, meta)

    for key, src in SOURCES.items():
        text, meta = texts[key]
        before = dict(conv.stats.counts)
        conv.feed(text, lean=args.lean)
        delta = {
            k: v - before.get(k, 0) for k, v in conv.stats.counts.items()
            if v - before.get(k, 0)
        }
        meta["stats"] = dict(sorted(delta.items()))
        meta["emit"] = src["emit"]
        report["sources"][key] = meta

    skip_reasons = sorted(k for k in conv.stats.counts if k.startswith("skipped_"))
    report["sources"]["trackparam"]["note"] = (
        "Quantumult X 无法删除 URL 查询参数：rewrite 只有 reject*/302/307/"
        "header/body/script。$removeparam 规则全部跳过，不做近似转换。"
    )

    list_total = len(conv.host_suffix) + len(conv.host_exact) + len(conv.host_wildcard)

    all_sources = [SOURCES[key]["url"] for key in SOURCES]
    list_header = header_block(
        "AdGuard Spyware -> Quantumult X",
        all_sources,
        [
            ("HOST-SUFFIX", len(conv.host_suffix)),
            ("HOST", len(conv.host_exact)),
            ("HOST-WILDCARD", len(conv.host_wildcard)),
            ("TOTAL", list_total),
        ],
    )
    rewrite_header = header_block(
        "AdGuard Spyware Rewrite",
        all_sources,
        [
            ("REJECT", len(conv.rewrites)),
            ("MITM", len({v["host"] for v in conv.rewrites.values()})),
            ("TOTAL", len(conv.rewrites)),
        ],
    )

    list_text = build_list(conv, list_header)
    rewrite_text = build_rewrite(conv, rewrite_header)
    skipped_text = build_skipped(conv, "spyware + trackparam (see report.json)")

    report["outputs"]["Tracking.list"] = {
        "rules": list_total,
        "bytes": len(list_text.encode()),
    }
    report["outputs"]["Tracking.rewrite.conf"] = {
        "rules": len(conv.rewrites),
        "bytes": len(rewrite_text.encode()),
        "mitm_hosts": len({v["host"] for v in conv.rewrites.values()}),
    }
    report["skipped_reasons"] = {k: conv.stats.counts[k] for k in skip_reasons}
    report["skipped_samples"] = {
        k: conv.stats.samples.get(k, []) for k in skip_reasons
    }

    log("")
    log(f"= Tracking.list        {list_total} rules "
        f"({len(list_text.encode()) / 1024 / 1024:.1f} MB) "
        f"[suffix {len(conv.host_suffix)} / host {len(conv.host_exact)} "
        f"/ wildcard {len(conv.host_wildcard)}]")
    log(f"= Tracking.rewrite.conf {len(conv.rewrites)} rules "
        f"({len({v['host'] for v in conv.rewrites.values()})} mitm hosts)")
    for key in skip_reasons:
        log(f"  skip {key}: {conv.stats.counts[key]}")

    if args.dry_run:
        log("\n(dry run, nothing written)")
        return 0

    prev_path = out_dir / "report.json"
    prev = None
    if prev_path.exists():
        try:
            prev = json.loads(prev_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            prev = None
    try:
        guard_against_regression(prev, list_total, len(conv.rewrites), args.force)
    except ConvertError as exc:
        log(f"! {exc}")
        return 1

    # --- atomic write ----------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-rules-"))
    try:
        (tmp / "Tracking.list").write_text(list_text, encoding="utf-8", newline="\n")
        (tmp / "Tracking.rewrite.conf").write_text(rewrite_text, encoding="utf-8", newline="\n")
        (tmp / "skipped.txt").write_text(skipped_text, encoding="utf-8", newline="\n")
        (tmp / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        for name in ("Tracking.list", "Tracking.rewrite.conf", "skipped.txt", "report.json"):
            os.replace(tmp / name, out_dir / name)
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
