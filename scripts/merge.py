#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Merge several Quantumult X filter lists into one deduplicated list.

Sources:

* ``217heidai/adblockfilters`` ``adblockqx.conf``  — AdGuard/EasyList/OISD merge
* ``privacy-protection-tools/anti-AD``             — Chinese ad domains
* this repository's own ``rules/Tracking.list``    — AdGuard Spyware, converted

All three are already native Quantumult X syntax, so this is a set operation,
not a conversion.  Two things are removed:

1. duplicates — the same domain in several sources;
2. shadowed rules — ``a.example.com`` when ``example.com`` is already present.
   ``host-suffix`` matches by suffix, so the child rule could never fire.

Any source failing to download aborts the run and leaves the previous file in
place, because silently publishing a list that lost 250k entries is worse than
publishing yesterday's list.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from convert import (  # noqa: E402
    ConvertError,
    Psl,
    SHARED_HOST_DENYLIST,
    decode_payload,
    fetch,
    log,
    normalize_domain,
    wildcard_parent,
)

GENERATOR = "qx-adguard-tracking/merge"

SOURCES = {
    "adguard-dns": {
        "name": "217heidai/adblockfilters (adblockqx)",
        "url": "https://github.com/217heidai/adblockfilters/releases/download/rule/adblockqx.conf",
        "min_bytes": 5_000_000,
        "homepage": "https://github.com/217heidai/adblockfilters",
    },
    "anti-ad": {
        "name": "privacy-protection-tools/anti-AD",
        "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-quanx.txt",
        "min_bytes": 2_000_000,
        "homepage": "https://github.com/privacy-protection-tools/anti-AD",
    },
    "tracking": {
        "name": "qx-adguard-tracking (Tracking.list)",
        "url": "https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list",
        "min_bytes": 3_000_000,
        "homepage": "https://github.com/karllagerfeld-cn/qx-adguard-tracking",
        "prefer_local": "rules/Tracking.list",
    },
}

ALLOWED_TYPES = {"host", "host-suffix", "host-wildcard"}
MIN_TOTAL = 200_000


def parse_lines(text: str, label: str, stats: dict) -> tuple[set, set, set]:
    """Return (suffixes, wildcards, ips) found in a QX filter file."""
    suffixes: set[str] = set()
    wildcards: set[str] = set()
    ips: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 3:
            stats["skipped_malformed"] = stats.get("skipped_malformed", 0) + 1
            continue
        kind, domain, policy = parts[0].lower(), parts[1], parts[2]
        if kind not in ALLOWED_TYPES:
            key = "skipped_type_" + kind
            stats[key] = stats.get(key, 0) + 1
            continue
        if policy.lower() != "reject":
            key = "skipped_policy_" + policy.lower()
            stats[key] = stats.get(key, 0) + 1
            continue
        if "*" in domain or "?" in domain:
            if kind == "host-wildcard":
                wildcards.add(domain.lower())
            else:
                stats["skipped_wildcard_in_suffix"] = stats.get("skipped_wildcard_in_suffix", 0) + 1
            continue
        if kind == "host" and domain.count(".") == 3 and all(p.isdigit() for p in domain.split(".")):
            ips.add(domain)
            continue
        normalized = normalize_domain(domain)
        if not normalized:
            stats["skipped_invalid_domain"] = stats.get("skipped_invalid_domain", 0) + 1
            continue
        suffixes.add(normalized)

    return suffixes, wildcards, ips


def prune_shadowed(suffixes: set) -> tuple[set, int]:
    """Drop ``a.example.com`` when ``example.com`` is already blocked."""
    kept: set[str] = set()
    shadowed = 0
    for domain in sorted(suffixes, key=lambda d: (d.count("."), d)):
        parts = domain.split(".")
        if any(".".join(parts[i:]) in kept for i in range(1, len(parts))):
            shadowed += 1
            continue
        kept.add(domain)
    return kept, shadowed


def header_block(counts: list[tuple[str, int]], provenance: list[str]) -> list[str]:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    out = [
        "# NAME: Merged Ad Block -> Quantumult X",
        f"# GENERATOR: {GENERATOR}",
        f"# UPDATED: {stamp}",
    ]
    for index, item in enumerate(provenance, 1):
        key = "SOURCE" if index == 1 else f"SOURCE-{index}"
        out.append(f"# {key}: {item}")
    out.append("#")
    out.append("# 三份 QX 原生规则合并去重，已剔除被父域覆盖的子域规则。")
    for key, value in counts:
        out.append(f"# {key}: {value}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="rules")
    parser.add_argument("--data", default="data")
    parser.add_argument("--local", nargs="*", default=[], metavar="KEY=PATH")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    args.local = dict(item.split("=", 1) for item in args.local)

    out_dir = Path(args.out)
    psl = Psl(Path(args.data) / "public_suffix_list.dat")
    log(f"- PSL loaded: {'yes' if psl.loaded else 'NO (guard disabled)'}")

    all_suffix: set[str] = set()
    all_wildcard: set[str] = set()
    all_ip: set[str] = set()
    report: dict = {
        "generator": GENERATOR,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "psl_loaded": psl.loaded,
        "sources": {},
    }

    for key, src in SOURCES.items():
        stats: dict[str, int] = {}
        local_path = args.local.get(key)
        if not local_path and src.get("prefer_local"):
            candidate = Path(src["prefer_local"])
            if candidate.exists():
                local_path = str(candidate)

        if local_path:
            raw = Path(local_path).read_bytes()
            used = f"local:{Path(local_path).name}"
        else:
            log(f"- downloading {src['name']} ...")
            raw = fetch(src["url"], src["min_bytes"])
            used = src["url"]

        text = decode_payload(raw, src, strict=not args.force)
        suffixes, wildcards, ips = parse_lines(text, key, stats)
        log(
            f"  ok: {len(raw)} bytes -> {len(suffixes)} suffix / "
            f"{len(wildcards)} wildcard / {len(ips)} ip"
        )

        before_s = len(all_suffix)
        all_suffix |= suffixes
        all_wildcard |= wildcards
        all_ip |= ips
        report["sources"][key] = {
            "name": src["name"],
            "url": used,
            "bytes": len(raw),
            "rules": len(suffixes) + len(wildcards) + len(ips),
            "new": len(all_suffix) - before_s,
            "stats": dict(sorted(stats.items())),
        }

    if not psl.loaded:
        report["warnings"] = ["public suffix list unavailable; guard disabled"]

    # Safety net: never publish a public suffix or a shared host as a rule.
    refused_psl = 0
    refused_shared = 0
    safe: set[str] = set()
    for domain in all_suffix:
        if psl.is_public_suffix(domain):
            refused_psl += 1
            continue
        if domain in SHARED_HOST_DENYLIST:
            refused_shared += 1
            continue
        safe.add(domain)

    pruned, shadowed = prune_shadowed(safe)

    wildcards_kept: set[str] = set()
    wildcard_shadowed = 0
    for pattern in all_wildcard:
        parent = wildcard_parent(pattern)
        if parent and (parent in pruned or parent in all_ip):
            wildcard_shadowed += 1
            continue
        wildcards_kept.add(pattern)

    total = len(pruned) + len(wildcards_kept) + len(all_ip)
    log("")
    log(f"= merged: {len(all_suffix)} suffix -> {len(pruned)} after shadow pruning")
    log(f"= wildcard kept {len(wildcards_kept)} (shadowed {wildcard_shadowed}) / ip {len(all_ip)}")
    log(f"= TOTAL {total}")

    report.update(
        suffix_input=len(all_suffix),
        suffix_kept=len(pruned),
        shadowed_by_parent=shadowed,
        wildcard_kept=len(wildcards_kept),
        wildcard_shadowed=wildcard_shadowed,
        ip_kept=len(all_ip),
        refused_public_suffix=refused_psl,
        refused_shared_host=refused_shared,
        total=total,
    )

    provenance = [SOURCES[k]["url"] for k in SOURCES]
    header = header_block(
        [
            ("HOST-SUFFIX", len(pruned)),
            ("HOST-WILDCARD", len(wildcards_kept)),
            ("HOST", len(all_ip)),
            ("TOTAL", total),
        ],
        provenance,
    )

    body: list[str] = list(header)
    body.extend(f"HOST-SUFFIX,{d},reject" for d in sorted(pruned))
    body.extend(f"HOST,{ip},reject" for ip in sorted(all_ip))
    body.extend(f"HOST-WILDCARD,{p},reject" for p in sorted(wildcards_kept))
    text_out = "\n".join(body) + "\n"

    if total < MIN_TOTAL and not args.force:
        log(f"! only {total} rules, expected >= {MIN_TOTAL}; refusing to publish")
        return 1

    prev_path = out_dir / "merged-report.json"
    if prev_path.exists() and not args.force:
        try:
            prev = json.loads(prev_path.read_text(encoding="utf-8"))
            before = int(prev.get("total", 0))
            if before >= 1000 and abs(total - before) / before > 0.25:
                log(f"! total jumped {before} -> {total}; refusing to publish")
                return 1
        except (ValueError, OSError):
            pass

    if args.dry_run:
        log("(dry run, nothing written)")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-merged-"))
    try:
        (tmp / "Merged.list").write_text(text_out, encoding="utf-8", newline="\n")
        (tmp / "merged-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        for name in ("Merged.list", "merged-report.json"):
            os.replace(tmp / name, out_dir / name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    log(f"\nwritten {out_dir}/Merged.list ({len(text_out.encode()) / 1024 / 1024:.1f} MB)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConvertError as exc:
        log(f"! FAILED: {exc}")
        sys.exit(1)
