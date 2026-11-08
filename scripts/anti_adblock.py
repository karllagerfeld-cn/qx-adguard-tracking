#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build Anti-AdBlock and Anti-AdBlock-Extra.

Anti-AdBlock
    Merge of ``217heidai/adblockfilters`` (adblockqx.conf) and
    ``privacy-protection-tools/anti-AD`` (anti-ad-quanx.txt), deduplicated.
    Both are already Quantumult X native syntax, so this is a set operation.

Anti-AdBlock-Extra
    The difference: rules present in this repository's ``Tracking.list`` but
    absent from Anti-AdBlock.  Subscribe to it *next to* Anti-AdBlock to pick up
    the CNAME-cloaking entries the two big lists do not carry.

Both outputs are ``host-suffix`` / ``host-wildcard`` with ``reject``.
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

GENERATOR = "qx-adguard-tracking/anti-adblock"

SOURCES = {
    "adblockqx": {
        "name": "217heidai/adblockfilters (adblockqx.conf)",
        "url": "https://github.com/217heidai/adblockfilters/releases/download/rule/adblockqx.conf",
        "min_bytes": 5_000_000,
        "homepage": "https://github.com/217heidai/adblockfilters",
    },
    "anti-ad": {
        "name": "privacy-protection-tools/anti-AD (anti-ad-quanx.txt)",
        "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-quanx.txt",
        "min_bytes": 2_000_000,
        "homepage": "https://github.com/privacy-protection-tools/anti-AD",
    },
}

TRACKING_LIST = "rules/Tracking.list"
TRACKING_URL = (
    "https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list"
)

ALLOWED_TYPES = {"host", "host-suffix", "host-wildcard"}
MIN_TOTAL = 200_000
MAX_EXTRA = 20_000  # a bigger diff means Anti-AdBlock silently lost its content


def parse_lines(text: str, stats: dict) -> tuple[set, set, set]:
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
    kept: set[str] = set()
    shadowed = 0
    for domain in sorted(suffixes, key=lambda d: (d.count("."), d)):
        parts = domain.split(".")
        if any(".".join(parts[i:]) in kept for i in range(1, len(parts))):
            shadowed += 1
            continue
        kept.add(domain)
    return kept, shadowed


def is_covered(domain: str, pool: set) -> bool:
    """True when ``domain`` or any of its parents is in ``pool``."""
    parts = domain.split(".")
    return any(".".join(parts[i:]) in pool for i in range(len(parts)))


def build_extra(
    track_suffix: set, track_wc: set, anti_suffix: set, anti_wc: set
) -> tuple[set, set]:
    extra_suffix = {d for d in track_suffix if not is_covered(d, anti_suffix)}
    extra_wc: set[str] = set()
    for pattern in track_wc:
        if pattern in anti_wc:
            continue
        parent = wildcard_parent(pattern)
        if parent and is_covered(parent, anti_suffix):
            continue
        extra_wc.add(pattern)
    return extra_suffix, extra_wc


def header_block(
    title: str, stamps: list[str], counts: list[tuple[str, int]], note: str
) -> list[str]:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    out = [f"# NAME: {title}", f"# GENERATOR: {GENERATOR}", f"# UPDATED: {stamp}"]
    for index, item in enumerate(stamps, 1):
        key = "SOURCE" if index == 1 else f"SOURCE-{index}"
        out.append(f"# {key}: {item}")
    out.append("#")
    out.append(f"# {note}")
    for key, value in counts:
        out.append(f"# {key}: {value}")
    return out


def write_atomic(out_dir: Path, payload: dict[str, str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-anti-"))
    try:
        for name, text in payload.items():
            (tmp / name).write_text(text, encoding="utf-8", newline="\n")
        for name in payload:
            os.replace(tmp / name, out_dir / name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="rules")
    parser.add_argument("--data", default="data")
    parser.add_argument("--tracking", default=TRACKING_LIST)
    parser.add_argument("--local", nargs="*", default=[], metavar="KEY=PATH")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    args.local = dict(item.split("=", 1) for item in args.local)

    out_dir = Path(args.out)
    psl = Psl(Path(args.data) / "public_suffix_list.dat")
    log(f"- PSL loaded: {'yes' if psl.loaded else 'NO (guard disabled)'}")

    report: dict = {
        "generator": GENERATOR,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "psl_loaded": psl.loaded,
        "sources": {},
    }

    all_suffix: set[str] = set()
    all_wc: set[str] = set()
    all_ip: set[str] = set()

    for key, src in SOURCES.items():
        stats: dict[str, int] = {}
        local = args.local.get(key)
        if local:
            raw = Path(local).read_bytes()
            used = f"local:{Path(local).name}"
        else:
            log(f"- downloading {src['name']} ...")
            raw = fetch(src["url"], src["min_bytes"])
            used = src["url"]

        text = decode_payload(raw, src, strict=not args.force)
        suffixes, wildcards, ips = parse_lines(text, stats)
        log(f"  ok: {len(raw)} bytes -> {len(suffixes)} suffix / {len(wildcards)} wildcard")

        before = len(all_suffix)
        all_suffix |= suffixes
        all_wc |= wildcards
        all_ip |= ips
        report["sources"][key] = {
            "name": src["name"],
            "url": used,
            "homepage": src["homepage"],
            "bytes": len(raw),
            "rules": len(suffixes) + len(wildcards) + len(ips),
            "new": len(all_suffix) - before,
            "stats": dict(sorted(stats.items())),
        }

    # Safety net before publishing.
    safe: set[str] = set()
    refused_psl = refused_shared = 0
    for domain in all_suffix:
        if psl.is_public_suffix(domain):
            refused_psl += 1
            continue
        if domain in SHARED_HOST_DENYLIST:
            refused_shared += 1
            continue
        safe.add(domain)

    pruned, shadowed = prune_shadowed(safe)
    wc_kept = {p for p in all_wc if (wildcard_parent(p) or "") not in pruned}
    wc_shadowed = len(all_wc) - len(wc_kept)

    total = len(pruned) + len(wc_kept) + len(all_ip)
    log("")
    log(f"= Anti-AdBlock: {len(pruned)} suffix + {len(wc_kept)} wildcard = {total}")

    # ---- Anti-AdBlock-Extra ------------------------------------------- #
    track_path = Path(args.tracking)
    if track_path.exists():
        track_raw = track_path.read_bytes()
        track_used = f"local:{track_path.name}"
        log(f"- tracking list: {track_used} ({len(track_raw)} bytes)")
    else:
        log("- tracking list missing locally, downloading ...")
        track_raw = fetch(TRACKING_URL, 3_000_000)
        track_used = TRACKING_URL
    track_text = decode_payload(track_raw, {"name": "Tracking.list"}, strict=not args.force)
    track_suffix, track_wc, track_ip = parse_lines(track_text, {})

    extra_suffix, extra_wc = build_extra(track_suffix, track_wc, pruned, wc_kept)
    extra_total = len(extra_suffix) + len(extra_wc) + len(track_ip)
    log(f"= Anti-AdBlock-Extra: {len(extra_suffix)} suffix + {len(extra_wc)} wildcard = {extra_total}")

    if total < MIN_TOTAL and not args.force:
        log(f"! Anti-AdBlock only {total} rules (expected >= {MIN_TOTAL}); refusing to publish")
        return 1
    if extra_total > MAX_EXTRA and not args.force:
        log(
            f"! Extra is {extra_total} rules, far above the usual ~2k. "
            "Anti-AdBlock probably lost its content; refusing to publish"
        )
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    anti_lines = header_block(
        "Anti-AdBlock -> Quantumult X",
        [SOURCES["adblockqx"]["url"], SOURCES["anti-ad"]["url"]],
        [("HOST-SUFFIX", len(pruned)), ("HOST-WILDCARD", len(wc_kept)), ("TOTAL", total)],
        "adblockqx + anti-ad 合并去重，已剔除被父域覆盖的子域规则；每 8 小时重建（比 adblockqx 晚 10 分钟）。",
    )
    anti_body = list(anti_lines)
    anti_body.extend(f"HOST-SUFFIX,{d},reject" for d in sorted(pruned))
    anti_body.extend(f"HOST,{ip},reject" for ip in sorted(all_ip))
    anti_body.extend(f"HOST-WILDCARD,{p},reject" for p in sorted(wc_kept))

    extra_lines = header_block(
        "Anti-AdBlock-Extra -> Quantumult X",
        [TRACKING_URL, SOURCES["adblockqx"]["url"], SOURCES["anti-ad"]["url"]],
        [("HOST-SUFFIX", len(extra_suffix)), ("HOST-WILDCARD", len(extra_wc)), ("TOTAL", extra_total)],
        "只包含 Anti-AdBlock 没有、而 Tracking.list 有的条目；与 Anti-AdBlock 同时订阅。",
    )
    extra_body = list(extra_lines)
    extra_body.extend(f"HOST-SUFFIX,{d},reject" for d in sorted(extra_suffix))
    extra_body.extend(f"HOST-WILDCARD,{p},reject" for p in sorted(extra_wc))

    report.update(
        anti_adblock={
            "suffix": len(pruned),
            "wildcard": len(wc_kept),
            "total": total,
            "shadowed_by_parent": shadowed,
            "wildcard_shadowed": wc_shadowed,
            "refused_public_suffix": refused_psl,
            "refused_shared_host": refused_shared,
        },
        extra={
            "tracking_source": track_used,
            "tracking_rules": len(track_suffix) + len(track_wc) + len(track_ip),
            "suffix": len(extra_suffix),
            "wildcard": len(extra_wc),
            "total": extra_total,
        },
    )

    if args.dry_run:
        log("(dry run, nothing written)")
        return 0

    prev_path = out_dir / "anti-adblock-report.json"
    if prev_path.exists() and not args.force:
        try:
            prev = json.loads(prev_path.read_text(encoding="utf-8"))
            before = int(prev.get("anti_adblock", {}).get("total", 0))
            if before >= 1000 and abs(total - before) / before > 0.25:
                log(f"! Anti-AdBlock jumped {before} -> {total}; refusing to publish")
                return 1
        except (ValueError, OSError):
            pass

    write_atomic(
        out_dir,
        {
            "Anti-AdBlock.list": "\n".join(anti_body) + "\n",
            "Anti-AdBlock-Extra.list": "\n".join(extra_body) + "\n",
            "anti-adblock-report.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        },
    )
    log(f"\nwritten to {out_dir}/ (stamp {stamp})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConvertError as exc:
        log(f"! FAILED: {exc}")
        sys.exit(1)
