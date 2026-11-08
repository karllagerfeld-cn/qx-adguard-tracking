#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-test for convert.py.  No network, no side effects outside a temp dir.

Run:  python scripts/selftest.py
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import convert  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok   {name}")
    else:
        FAILURES.append(name + (f"  [{detail}]" if detail else ""))
        print(f"  FAIL {name}  {detail}")


FIXTURE = """\
! header comment
||plain.example.com^
||third.example.com^$third-party
||dommod.example.com^$domain=foo.com
||1.2.3.4^
||255.255.255.999^
||wild*.example.com^
||*.example.com^
||path.example.com/tracking/
||deep.example.com/ad^
||keepme.example.com^
||novsep.example.com
@@||plain.example.com^
@@||allow.example.com^$document
||badfilter.example.com^
||badfilter.example.com^$badfilter
a.com##.ad
a.com#%#//scriptlet('set-constant', 'x', 'noopFunc')
a.com$$script[tag-content="ad"]
a.com#$#.x{display:none}
/^https?:\\/\\/regex\\.example\\.com\\/ad/
plainpattern.com
|single.example.com^
!#if (!ext_ublock)
||cond-in.example.com^
!#endif
!#if (adguard_app_ios)
||cond-out.example.com^
!#else
||cond-else.example.com^
!#endif
!+ PLATFORM(ext_ff)
||hinted.example.com^
||co.uk^
||github.io^
"""


def make_conv(psl_entries: list[str] | None = None) -> convert.Conversion:
    tmp = Path(tempfile.mkdtemp(prefix="selftest-psl-"))
    psl_path = tmp / "psl.dat"
    psl_path.write_text("\n".join(psl_entries or ["co.uk", "com.cn", "*.ck"]), encoding="utf-8")
    return convert.Conversion(convert.Psl(psl_path))


def test_conditions() -> None:
    print("condition evaluator")
    ev = convert.Condition()
    check("!ext_ublock is true", ev.evaluate("!ext_ublock") is True)
    check("adguard_app_ios is false", ev.evaluate("adguard_app_ios") is False)
    check(
        "!a && !b is true",
        ev.evaluate("!adguard_ext_safari && !adguard_app_ios") is True,
    )
    check(
        "or with known true",
        ev.evaluate("adguard_app_windows || !ext_ublock") is True,
    )
    check("parens", ev.evaluate("!(adguard_app_ios || adguard_app_mac)") is True)
    check("unknown constant is false", ev.evaluate("some_new_platform") is False)
    check("unknown recorded", "some_new_platform" in ev.unknown)

    bad = False
    try:
        convert.Condition().evaluate("a &&")
    except convert.ConvertError:
        bad = True
    check("malformed expression raises", bad)


def test_rules() -> None:
    print("rule classification")
    conv = make_conv()
    try:
        conv.feed(FIXTURE)
    except convert.ConvertError as exc:
        check("fixture contains no !#include", False, str(exc))
        return

    counts = conv.stats.counts
    check("plain domain -> host-suffix", "keepme.example.com" in conv.host_suffix)
    check("third-party skipped", "third.example.com" not in conv.host_suffix)
    check("third-party counted", counts.get("skipped_third_party") == 1)
    check("$domain= skipped", "dommod.example.com" not in conv.host_suffix)
    check("ipv4 -> HOST", "1.2.3.4" in conv.host_exact)
    check("invalid ip skipped", counts.get("skipped_invalid_ip") == 1)
    check("wildcard host kept", "wild*.example.com" in conv.host_wildcard)
    check("too-broad wildcard refused", "*.example.com" not in conv.host_wildcard)
    check("no separator skipped", counts.get("skipped_no_separator") == 1)
    check("exception allowlists", "allow.example.com" in conv.allow)
    check("allowlist removes block", "plain.example.com" not in conv.host_suffix)
    check("badfilter removes block", "badfilter.example.com" not in conv.host_suffix)
    check("cosmetic skipped", counts.get("skipped_cosmetic_or_scriptlet") == 4)
    check("regex rule skipped", counts.get("skipped_regex_rule") == 1)
    check("plain pattern skipped", counts.get("skipped_plain_pattern") >= 1)
    check("inactive cond skipped", "cond-out.example.com" not in conv.host_suffix)
    check("active cond kept", "cond-in.example.com" in conv.host_suffix)
    check("else branch kept", "cond-else.example.com" in conv.host_suffix)
    check("platform hint skips next rule", "hinted.example.com" not in conv.host_suffix)
    check("public suffix refused", counts.get("domain_public_suffix_refused") == 1)
    check("shared host refused", counts.get("domain_shared_host_refused") == 1)

    print("rewrite generation")
    regexes = list(conv.rewrites)
    tracking = [r for r in regexes if "path" in r]
    check("path rule became rewrite", len(tracking) == 1, str(regexes))
    if tracking:
        r = tracking[0]
        check("case-insensitive prefix", r.startswith("(?i)^https?://"))
        check("subdomain wildcard", "(?:[a-z0-9-]+\\.)*" in r)
        check("port allowed", r"(?::\d+)?" in r)
        check("path literal", "/tracking/" in r)
        check("no space in regex", " " not in r)
        compiled = re.compile(r)
        check(
            "matches upstream url",
            bool(compiled.match("https://a.path.example.com/tracking/px.gif?x=1")),
        )
        check(
            "does not match lookalike host",
            not compiled.match("https://path.example.com.evil.tld/tracking/"),
        )

    sep = [r for r in regexes if r.endswith(convert.ADG_SEPARATOR)]
    check("separator class used for ^ terminator", len(sep) == 1, str(regexes))
    if sep:
        compiled = re.compile(sep[0])
        check("matches query after path", bool(compiled.match("https://deep.example.com/ad?v=1")))
        check("matches hash after path", bool(compiled.match("https://deep.example.com/ad#top")))
        check("matches exact path end", bool(compiled.match("https://deep.example.com/ad")))
        check("rejects longer path", not compiled.match("https://deep.example.com/advertisement"))

    print("output")
    header = convert.header_block("t", ["src-a", "src-b"], [("TOTAL", 1)])
    list_text = convert.build_list(conv, header)
    check("no CR in list", "\r" not in list_text)
    body = [l for l in list_text.splitlines() if l and not l.startswith("#")]
    allowed = re.compile(r"^(HOST|HOST-SUFFIX|HOST-WILDCARD),[^,\s]+,reject$")
    check("only whitelisted types", all(allowed.match(l) for l in body), str(body[:3]))
    for kind in ("HOST-SUFFIX", "HOST", "HOST-WILDCARD"):
        group = [l for l in body if l.startswith(kind + ",")]
        check(f"{kind} block sorted", group == sorted(group))
    check("no duplicate domains", len({l.split(",")[1] for l in body}) == len(body))

    rewrite_text = convert.build_rewrite(conv, header)
    check("no CR in rewrite", "\r" not in rewrite_text)
    check("hostname line present", "\nhostname = " in rewrite_text)
    check(
        "every rule has action",
        all(
            l.endswith(" url reject")
            for l in rewrite_text.splitlines()
            if l and not l.startswith("#") and not l.startswith("hostname")
        ),
    )


def test_payload_guards() -> None:
    print("payload guards")
    good = b"! x\r\n||a.example.com^\r\n||b.example.com^\r\n"
    check("good payload decodes", convert.decode_payload(good, {}).startswith("! x"))
    no_newline = b"! x\r\n||a.example.com^\r\n||b.exam"
    try:
        convert.decode_payload(no_newline, {})
        check("truncated payload rejected", False)
    except convert.ConvertError:
        check("truncated payload rejected", True)

    check("tail ok", convert.check_tail("||a.example.com^\n") is None)
    check(
        "tail accepts exception rule",
        convert.check_tail("||a.example.com^\n@@||b.example.com/*&x=1$removeparam\n") is None,
    )
    try:
        convert.check_tail("||a.example.com^\n||")
        check("tail guard rejects partial rule", False)
    except convert.ConvertError:
        check("tail guard rejects partial rule", True)

    print("domain helpers")
    check("idn -> punycode", convert.normalize_domain("пример.рф") == "xn--e1afmkfd.xn--p1ai")
    check("leading dot stripped", convert.normalize_domain(".a.example.com") == "a.example.com")
    check("single label rejected", convert.normalize_domain("localhost") is None)
    check("onion rejected", convert.normalize_domain("x.onion") is None)
    check("underbar kept", convert.normalize_domain("a_b.example.com") == "a_b.example.com")


def test_unbalanced() -> None:
    print("directive balance")
    conv = make_conv()
    try:
        conv.feed("!#if (ext_ublock)\n||a.example.com^\n")
        check("unbalanced !#if raises", False)
    except convert.ConvertError:
        check("unbalanced !#if raises", True)

    conv2 = make_conv()
    try:
        conv2.feed("||a.example.com^\n!#endif\n")
        check("stray !#endif raises", False)
    except convert.ConvertError:
        check("stray !#endif raises", True)

    conv3 = make_conv()
    try:
        conv3.feed("!#include x.txt\n")
        check("!#include raises", False)
    except convert.ConvertError:
        check("!#include raises", True)


def test_regression_guard() -> None:
    print("regression guard")
    prev = {"outputs": {"Tracking.list": {"rules": 100000}}}
    try:
        convert.guard_against_regression(prev, 50000, 0, force=False)
        check("50% drop refused", False)
    except convert.ConvertError:
        check("50% drop refused", True)
    convert.guard_against_regression(prev, 99000, 0, force=False)
    check("small change allowed", True)
    convert.guard_against_regression(prev, 10, 0, force=True)
    check("--force overrides", True)


def main() -> int:
    test_conditions()
    test_rules()
    test_payload_guards()
    test_unbalanced()
    test_regression_guard()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED:")
        for item in FAILURES:
            print("  -", item)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
