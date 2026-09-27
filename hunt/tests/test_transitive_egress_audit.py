#!/usr/bin/env python3
"""Unit tests for hunt/transitive_egress_audit.py. Stdlib only.

  python -m unittest hunt/tests/test_transitive_egress_audit.py -v

Every fixture is SYNTHETIC and built inside the test: .gem archives (a real tar holding
metadata.gz and data.tar.gz, as RubyGems writes them), a Zeek dns.log, alert CSVs, and detector
scope lists. The package fixtures are INERT: their Ruby files hold comments and string constants,
never code that fetches or publishes anything, and the tool under test never runs them anyway.

Anchors to the published record, asserted exactly:
  - OpenAI's DNS-incident timeline (report updated 25 Sep 2026): tool call 09:50:23, P0 alert
    10:02:11, human ack 10:05:06, run killed 12:34:30. Latencies 11m48s, 2m55s, 2h29m24s.
  - JFrog (15 Sep 2026): the suffix of oaifetchmde1778385544 "decodes to May 10 at 03:59:04 UTC".
  - rubyhack.ai (11 Sep 2026): the marker comments it published verbatim.
  - OpenAI: "an infrastructure detector for anomalous DNS activity excluded the affected
    environment, though DNS activity was logged". Reproduced as a coverage fixture.

Every check is tested in both directions (fires on the bad case, quiet on a realistic good one),
at its boundary where it has one, and "cannot tell" inputs must raise.

The module under test is loaded from TEA_MODULE if set, so the mutation harness
(transitive_egress_audit_mutants.py) can run this exact suite against deliberately broken copies.
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import importlib.util
import io
import os
import re
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
MODULE = os.environ.get("TEA_MODULE") or os.path.join(os.path.dirname(HERE), "transitive_egress_audit.py")
_spec = importlib.util.spec_from_file_location("transitive_egress_audit", MODULE)
tea = importlib.util.module_from_spec(_spec)
sys.modules["transitive_egress_audit"] = tea
_spec.loader.exec_module(tea)

PACK = os.path.join(REPO, "campaigns", "2026-09-transitive-egress")


# ---- fixture builders -------------------------------------------------------------------------

def gemspec_yaml(name: str, version: str, authors: str = "Jane Maintainer",
                 description: str = "A small library.") -> str:
    """Serialised-gemspec shape, as found in a real gem's metadata.gz. Text only."""
    return ("--- !ruby/object:Gem::Specification\n"
            "name: %s\n"
            "version: !ruby/object:Gem::Version\n"
            "  version: %s\n"
            "platform: ruby\n"
            "authors:\n- %s\n"
            "description: %s\n"
            "summary: fixture\n" % (name, version, authors, description))


def build_gem(directory: str, name: str, version: str, files: dict[str, str], **meta) -> str:
    """Write a real .gem (outer tar: metadata.gz, data.tar.gz, checksums.yaml.gz)."""
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tf:
        for rel, text in files.items():
            b = text.encode("utf-8")
            ti = tarfile.TarInfo(rel)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    parts = {
        "metadata.gz": gzip.compress(gemspec_yaml(name, version, **meta).encode()),
        "data.tar.gz": data_buf.getvalue(),
        "checksums.yaml.gz": gzip.compress(b"---\n"),
    }
    path = os.path.join(directory, "%s-%s.gem" % (name, version))
    with tarfile.open(path, mode="w:") as outer:
        for n, b in parts.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            outer.addfile(ti, io.BytesIO(b))
    return path


def write_tree(directory: str, files: dict[str, str]) -> str:
    for rel, text in files.items():
        p = os.path.join(directory, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return directory


# An inert package in the shape rubyhack.ai and JFrog describe: a .yardopts that loads a Ruby file,
# and that file carrying published marker comments. Comments and string constants only.
SUSPECT_FILES = {
    ".yardopts": "--load ./lib/evil.rb\nREADME.md\nlib/**/*.rb\n",
    "README.md": "# fixture\n",
    "lib/evil.rb": (
        "# disable evil in next version and bump version\n"
        "# Make exfil gem\n"
        "# published shape, kept as a comment: File.write('.yardopts', 'README.md')\n"
        "PUSH_PATH  = '/api/v1/gems'   # inert string\n"
        "module Fixture; end\n"),
}

BENIGN_FILES = {
    ".yardopts": "--markup markdown --no-private --exclude spec lib/**/*.rb - README.md LICENSE\n",
    "README.md": "# html-cleaner\nSanitises HTML. See docs/usage.md\n",
    "lib/html_cleaner.rb": (
        "# Sanitises untrusted HTML before rendering.\n"
        "# hack around a parser bug in older libxml2 versions\n"
        "# malicious input is escaped, never evaluated\n"
        "# exploit mitigation: attributes are allow-listed\n"
        "# this library prevents exfiltration of cookies via inline handlers\n"
        "ANCHOR = 'page#exfil-notes'\n"
        "DOCS = 'https://example.org/guide#hack'\n"
        "module HtmlCleaner; VERSION = '2.4.1'; end\n"),
    "lib/html_cleaner/payloads_spec_helper.rb": "# test helper\n",
}


def zeek_dns(rows: list[tuple[str, str, str]]) -> str:
    """rows: (src, query, qtype_name). Zeek dns.log TSV with the real header lines."""
    head = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tdns\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqclass\t"
            "qclass_name\tqtype\tqtype_name\trcode\trcode_name\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tcount\tstring\tcount\t"
            "string\tcount\tstring\n")
    body = []
    for i, (src, q, qt) in enumerate(rows):
        body.append("\t".join([str(1790000000 + i), "C%06d" % i, src, "40000", "10.0.0.53", "53", "udp",
                               str(i), q, "1", "C_INTERNET", "16" if qt == "TXT" else "1", qt, "0", "NOERROR"]))
    return head + "\n".join(body) + "\n#close\t2026-09-27-00-00-00\n"


def pseudo_label(i: int, n: int = 30) -> str:
    """Deterministic, high-entropy-looking label (hex digest). Test data, not an encoding."""
    return hashlib.sha256(b"fixture-%d" % i).hexdigest()[:n]


class TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="tea-test-")
        self.tmp = self._td.name

    def tearDown(self) -> None:
        self._td.cleanup()

    def write(self, name: str, text: str) -> str:
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return p


# ================================================================================================
# gem
# ================================================================================================

class GemAudit(TmpCase):
    def checks(self, result: dict) -> set[str]:
        return {f["check"] for f in result["findings"]}

    def test_suspect_gem_file_flags_every_published_signal(self):
        p = build_gem(self.tmp, "oaifetchmde1778385544", "0.0.1", SUSPECT_FILES)
        r = tea.audit_gem(p)
        self.assertEqual(r["name"], "oaifetchmde1778385544")
        self.assertEqual(r["files_read"], 3)
        self.assertEqual(self.checks(r), {"doc-build-loads-code", "timestamp-suffixed-name", "payload-filename",
                                          "published-marker-comment", "code-publishes-packages",
                                          "code-rewrites-doc-config", "doc-build-loop"})
        markers = [f for f in r["findings"] if f["check"] == "published-marker-comment"]
        self.assertEqual(len(markers), 2)
        self.assertEqual({m["file"] for m in markers}, {"lib/evil.rb:1", "lib/evil.rb:2"})

    def test_jfrog_timestamp_decode_exact(self):
        # JFrog: "the suffix of oaifetchmde1778385544 decodes to May 10 at 03:59:04 UTC"
        p = build_gem(self.tmp, "oaifetchmde1778385544", "0.0.1", SUSPECT_FILES)
        f = [x for x in tea.audit_gem(p)["findings"] if x["check"] == "timestamp-suffixed-name"][0]
        self.assertIn("2026-05-10 03:59:04 UTC", f["detail"])

    def test_timestamp_plus_trailing_digits(self):
        # rubyhack.ai lists chatoaifetch177855288717: a 10-digit timestamp plus two digits.
        self.assertEqual(tea.timestamp_suffix("chatoaifetch177855288717").strftime("%Y-%m-%d %H:%M:%S"),
                         "2026-05-12 02:28:07")

    def test_timestamp_out_of_range_and_short_numbers_are_not_flagged(self):
        for name in ("build9999999999", "libfoo1234567", "rails", "net-http-0001", "zz1000000000"):
            self.assertIsNone(tea.timestamp_suffix(name), name)

    def test_timestamp_version_is_flagged(self):
        # JFrog: f2fe-scraped "Its version is 0.0. followed by the current Unix timestamp".
        p = build_gem(self.tmp, "fixture-scraped", "0.0.1778385544", {"README.md": "x\n"})
        self.assertIn("timestamp-version", self.checks(tea.audit_gem(p)))

    def test_same_package_as_directory(self):
        d = write_tree(os.path.join(self.tmp, "unpacked"), SUSPECT_FILES)
        r = tea.audit_gem(d)
        self.assertIn("doc-build-loads-code", self.checks(r))
        self.assertIn("published-marker-comment", self.checks(r))

    def test_benign_gem_is_quiet(self):
        p = build_gem(self.tmp, "html-cleaner", "2.4.1", BENIGN_FILES)
        r = tea.audit_gem(p)
        self.assertEqual(r["findings"], [], r["findings"])

    def test_benign_directory_is_quiet(self):
        d = write_tree(os.path.join(self.tmp, "benign"), BENIGN_FILES)
        self.assertEqual(tea.audit_gem(d)["findings"], [])

    def test_either_half_alone_is_not_the_loop(self):
        # Real-world shapes found on 2026-09-27: yard-0.9.37's own .yardopts loads a template
        # plugin, and the gems-1.2.0 API client references /api/v1/gems. Neither is the loop.
        plugin_only = build_gem(self.tmp, "doc-plugin-user", "1.0.0",
                                {".yardopts": "--load ./docs/templates/plugin.rb\n",
                                 "docs/templates/plugin.rb": "# registers a template\n"})
        r = tea.audit_gem(plugin_only)
        self.assertEqual([(f["severity"], f["check"]) for f in r["findings"]], [("medium", "doc-build-loads-code")])
        client_only = build_gem(self.tmp, "registry-client", "1.0.0",
                                {"lib/client.rb": "PUSH = '/api/v1/gems'  # an API client\n"})
        r = tea.audit_gem(client_only)
        self.assertEqual([(f["severity"], f["check"]) for f in r["findings"]], [("medium", "code-publishes-packages")])

    def test_docs_that_mention_yardopts_are_not_code(self):
        p = build_gem(self.tmp, "docs-heavy", "1.0.0",
                      {"README.md": "Put options in .yardopts. File.write('.yardopts', 'x') works too.\n",
                       "lib/x.rb": "# reads .yardopts if present\nOPTS = '.yardopts'\n"})
        self.assertEqual(tea.audit_gem(p)["findings"], [])

    def test_large_inner_archive_is_read_whole(self):
        # Regression: data.tar.gz over the 2 MB per-file cap used to be truncated and crash
        # (found on nokogiri-1.16.7). Incompressible filler forces a large inner archive.
        files = {".yardopts": "--load ./lib/evil.rb\n", "lib/evil.rb": "# Make exfil gem\n",
                 "vendor/blob.txt": os.urandom(3 * 1024 * 1024).hex()}
        big = build_gem(self.tmp, "big-fixture", "1.0.0", files)
        with tarfile.open(big) as tf:
            self.assertGreater(tf.getmember("data.tar.gz").size, 2 * 1024 * 1024)
        r = tea.audit_gem(big)
        self.assertEqual(r["files_read"], 3)
        self.assertIn("doc-build-loop", self.checks(r))

    def test_truncated_inner_archive_is_cannot_tell(self):
        good = build_gem(self.tmp, "trunc", "1.0.0", {"lib/a.rb": os.urandom(200000).hex()})
        with tarfile.open(good) as tf:
            parts = {n: tf.extractfile(n).read() for n in ("metadata.gz", "data.tar.gz")}
        parts["data.tar.gz"] = parts["data.tar.gz"][: len(parts["data.tar.gz"]) // 2]
        bad = os.path.join(self.tmp, "truncated.gem")
        with tarfile.open(bad, "w:") as out:
            for n, b in parts.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(b)
                out.addfile(ti, io.BytesIO(b))
        with self.assertRaises(tea.CannotTell):
            tea.audit_gem(bad)

    def test_every_yard_code_option_form(self):
        for text, want in (("--load x.rb", "--load x.rb"), ("--load=x.rb", "--load x.rb"),
                           ("-e ./x.rb lib/**/*.rb", "-e ./x.rb"), ("--plugin foo", "--plugin foo"),
                           ("--query '@api.text == \"public\"'", "--query @api.text == \"public\"")):
            self.assertEqual(tea.yardopts_code_options(text), [want], text)

    def test_benign_yard_options_are_quiet(self):
        for text in ("--markup markdown --no-private", "--exclude spec - README.md",
                     "--embed-mixins --output-dir doc", "--title 'My --load notes'"):
            self.assertEqual(tea.yardopts_code_options(text), [], text)

    def test_every_rubyhack_marker_comment(self):
        published = ["# malicious probe", "#hack", "# malicious test", "# exploit southwark calendar",
                     "# exploit fetch full Wandsworth calendar", "# malicious yard loader",
                     "# exfil by push gem 0.0.3", "#exfil 2026-05-12 04:17:55 +0200",
                     "# Fetch target and self-publish next gem",
                     "# leak exfil by repeated attempts & fresh leaked keys variants", "# yard exploit test",
                     "# disable evil in next version and bump version", "# rubydoc ssrf test",
                     "# malicious crawler/exfil for Southwark Jan 2026 docs via rubydoc.info worker",
                     "# Make exfil gem", "# package payload gem"]
        for line in published:
            self.assertTrue(tea.MARKER_RX.search("x = 1  " + line), line)
            self.assertTrue(tea.MARKER_RX.search(line), line)

    def test_marker_needs_comment_context(self):
        for line in ("ANCHOR = 'page#exfil-notes'", "u = 'https://example.org/guide#hack'",
                     "# hack around a parser bug", "# malicious input is escaped",
                     "# exploit mitigation", "# prevents exfiltration"):
            self.assertIsNone(tea.MARKER_RX.search(line), line)

    def test_metadata_markup_in_author_is_flagged(self):
        # JFrog's July samples: script and template expressions in author and description.
        for author in ("<img src=x onerror=alert(1)>", "<%= 7*7 %>", "${7*7}"):
            p = build_gem(self.tmp, "fixture-meta", "0.1.0", {"README.md": "x\n"}, authors=author)
            self.assertIn("metadata-markup", self.checks(tea.audit_gem(p)), author)
            os.remove(p)

    def test_plain_metadata_is_quiet(self):
        p = build_gem(self.tmp, "fixture-meta", "0.1.0", {"README.md": "x\n"},
                      authors="Ada Lovelace", description="Parses <b>bold</b> safely? No: plain text only.")
        self.assertNotIn("metadata-markup", self.checks(tea.audit_gem(p)))

    def test_extconf_is_info_only(self):
        p = build_gem(self.tmp, "native-thing", "1.0.0", {"ext/native/extconf.rb": "# builds\n"})
        r = tea.audit_gem(p)
        self.assertEqual([(f["severity"], f["check"]) for f in r["findings"]], [("info", "install-build-step")])

    def test_cannot_tell_inputs_raise(self):
        junk = self.write("junk.gem", "not a tar file at all")
        with self.assertRaises(tea.CannotTell):
            tea.audit_gem(junk)
        no_data = os.path.join(self.tmp, "nodata.gem")
        with tarfile.open(no_data, "w:") as tf:
            b = gzip.compress(b"name: x\n")
            ti = tarfile.TarInfo("metadata.gz")
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
        with self.assertRaises(tea.CannotTell):
            tea.audit_gem(no_data)
        empty = os.path.join(self.tmp, "emptydir")
        os.makedirs(empty)
        with self.assertRaises(tea.CannotTell):
            tea.audit_gem(empty)
        with self.assertRaises(tea.CannotTell):
            tea.audit_gem(os.path.join(self.tmp, "missing.gem"))


# ================================================================================================
# dns
# ================================================================================================

SANDBOX = "198.51.100.10"


def benign_rows() -> list[tuple[str, str, str]]:
    rows = []
    for _ in range(30):
        rows += [(SANDBOX, "index.rubygems.org", "A"), (SANDBOX, "pypi.org", "A"),
                 (SANDBOX, "files.pythonhosted.org", "AAAA")]
    rows += [(SANDBOX, "shard%02d.cdn-example.com" % i, "A") for i in range(30)]
    rows += [(SANDBOX, "www.council-example.gov.uk", "A"), (SANDBOX, "maps.council-example.gov.uk", "A")]
    return rows


def anomalous_rows(n: int = 60, domain: str = "relay-example.net", qtype: str = "TXT") -> list[tuple[str, str, str]]:
    return [(SANDBOX, "%s.%s" % (pseudo_label(i), domain), qtype) for i in range(n)]


class DnsAudit(TmpCase):
    def by_domain(self, res: list[dict]) -> dict[str, dict]:
        return {r["registered_domain"]: r for r in res}

    def test_zeek_log_anomaly_ranks_first_and_benign_is_quiet(self):
        p = self.write("dns.log", zeek_dns(benign_rows() + anomalous_rows()))
        res = tea.score_dns(tea.parse_dns(p))
        self.assertEqual(res[0]["registered_domain"], "relay-example.net")
        self.assertEqual(set(res[0]["flags"]), {"high-cardinality", "high-entropy", "txt-heavy"})
        self.assertEqual(res[0]["unique_subdomains"], 60)
        d = self.by_domain(res)
        for benign in ("rubygems.org", "pypi.org", "pythonhosted.org", "cdn-example.com", "council-example.gov.uk"):
            self.assertEqual(d[benign]["flags"], [], benign)

    def test_multi_label_suffix_groups_correctly(self):
        self.assertEqual(tea.registered_domain("www.council-example.gov.uk"), "council-example.gov.uk")
        self.assertEqual(tea.registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(tea.registered_domain("x.y.github.io"), "y.github.io")
        self.assertEqual(tea.registered_domain("deep.sub.example.com."), "example.com")
        self.assertEqual(tea.registered_domain("example.com"), "example.com")

    def test_high_cardinality_boundary(self):
        p49 = self.write("d49.log", zeek_dns(anomalous_rows(49, qtype="A")))
        p50 = self.write("d50.log", zeek_dns(anomalous_rows(50, qtype="A")))
        self.assertNotIn("high-cardinality", tea.score_dns(tea.parse_dns(p49))[0]["flags"])
        self.assertIn("high-cardinality", tea.score_dns(tea.parse_dns(p50))[0]["flags"])

    def test_long_label_and_long_name(self):
        rows = [(SANDBOX, "a" * 45 + ".long-example.org", "A"),
                (SANDBOX, ".".join(["b" * 24] * 4) + ".name-example.org", "A"),
                (SANDBOX, "a" * 39 + ".short-example.org", "A")]
        d = self.by_domain(tea.score_dns(tea.parse_dns(self.write("l.log", zeek_dns(rows)))))
        self.assertIn("long-name", d["long-example.org"]["flags"])
        self.assertIn("long-name", d["name-example.org"]["flags"])
        self.assertNotIn("long-name", d["short-example.org"]["flags"])

    def test_allowlist_removes_domain(self):
        p = self.write("dns.log", zeek_dns(benign_rows() + anomalous_rows()))
        res = tea.score_dns(tea.parse_dns(p), allow=["relay-example.net"])
        self.assertNotIn("relay-example.net", self.by_domain(res))

    def test_csv_input(self):
        lines = ["ts,src,query,qtype"] + ["%d,%s,%s,%s" % (i, s, q, t) for i, (s, q, t) in enumerate(anomalous_rows())]
        res = tea.score_dns(tea.parse_dns(self.write("dns.csv", "\n".join(lines) + "\n")))
        self.assertEqual(res[0]["registered_domain"], "relay-example.net")
        self.assertIn("txt-heavy", res[0]["flags"])

    def test_txt_share_needs_volume(self):
        rows = [(SANDBOX, "_dmarc.mail-example.com", "TXT")] * 3
        d = self.by_domain(tea.score_dns(tea.parse_dns(self.write("t.log", zeek_dns(rows)))))
        self.assertNotIn("txt-heavy", d["mail-example.com"]["flags"])

    def test_garbage_raises(self):
        with self.assertRaises(tea.CannotTell):
            tea.parse_dns(self.write("junk.log", "this is not a dns log\nat all\n"))
        with self.assertRaises(tea.CannotTell):
            tea.parse_dns(self.write("header-only.log", zeek_dns([])))


# ================================================================================================
# latency
# ================================================================================================

OPENAI_ROW = "openai-dns-2026-09-20,2026-09-20T09:50:23,2026-09-20T10:02:11,2026-09-20T10:05:06,2026-09-20T12:34:30"
HEADER = "alert_id,event,detected,acked,contained"


class LatencyAudit(TmpCase):
    def run_rows(self, *rows: str, header: str = HEADER, **kw) -> dict:
        return tea.audit_latency(self.write("alerts.csv", "\n".join((header,) + rows) + "\n"), **kw)

    def test_openai_timeline_exact(self):
        r = self.run_rows(OPENAI_ROW)["alerts"][0]
        self.assertEqual(r["durations"]["event_to_detect"], "11m48s")
        self.assertEqual(r["durations"]["detect_to_ack"], "2m55s")
        self.assertEqual(r["durations"]["ack_to_contain"], "2h29m24s")
        self.assertEqual(r["durations"]["event_to_contain"], "2h44m07s")
        self.assertEqual(r["flags"], ["CONTAINMENT > 30m AFTER ACK"])

    def test_fast_containment_is_quiet(self):
        r = self.run_rows("a1,2026-09-20T09:00:00,2026-09-20T09:05:00,2026-09-20T09:06:00,2026-09-20T09:16:00")
        self.assertEqual(r["alerts"][0]["flags"], [])

    def test_containment_boundary(self):
        at = self.run_rows("a,2026-09-20T09:00:00,2026-09-20T09:01:00,2026-09-20T09:02:00,2026-09-20T09:32:00")
        over = self.run_rows("b,2026-09-20T09:00:00,2026-09-20T09:01:00,2026-09-20T09:02:00,2026-09-20T09:32:01")
        self.assertEqual(at["alerts"][0]["flags"], [])
        self.assertEqual(over["alerts"][0]["flags"], ["CONTAINMENT > 30m AFTER ACK"])

    def test_threshold_is_configurable(self):
        r = self.run_rows(OPENAI_ROW, max_contain_minutes=180)
        self.assertEqual(r["alerts"][0]["flags"], [])

    def test_not_contained_and_not_acked_are_flags(self):
        r = self.run_rows("a,2026-09-20T09:00:00,2026-09-20T09:01:00,2026-09-20T09:02:00,",
                          "b,2026-09-20T09:00:00,2026-09-20T09:01:00,,")
        self.assertEqual(r["alerts"][0]["flags"], ["NOT CONTAINED"])
        self.assertEqual(r["alerts"][1]["flags"], ["NOT ACKED", "NOT CONTAINED"])

    def test_out_of_order(self):
        r = self.run_rows("a,2026-09-20T09:00:00,2026-09-20T09:10:00,2026-09-20T09:05:00,2026-09-20T09:12:00")
        self.assertIn("OUT OF ORDER", r["alerts"][0]["flags"])

    def test_medians(self):
        r = self.run_rows(OPENAI_ROW,
                          "a,2026-09-20T09:00:00,2026-09-20T09:05:00,2026-09-20T09:06:00,2026-09-20T09:16:00",
                          "b,2026-09-20T09:00:00,2026-09-20T09:01:00,2026-09-20T09:02:00,2026-09-20T09:22:00")
        self.assertEqual(r["medians"]["event_to_detect"], "5m00s")
        self.assertEqual(r["medians"]["detect_to_ack"], "1m00s")
        self.assertEqual(r["medians"]["ack_to_contain"], "20m00s")

    def test_utc_z_suffix_parses(self):
        r = self.run_rows("z,2026-09-20T16:50:23Z,2026-09-20T17:02:11Z,2026-09-20T17:05:06Z,2026-09-20T19:34:30Z")
        self.assertEqual(r["alerts"][0]["durations"]["ack_to_contain"], "2h29m24s")

    def test_aliased_columns(self):
        r = self.run_rows(OPENAI_ROW, header="id,first_event,alert_time,acknowledged,killed")
        self.assertEqual(r["alerts"][0]["durations"]["detect_to_ack"], "2m55s")

    def test_cannot_tell_raises(self):
        with self.assertRaises(tea.CannotTell):
            self.run_rows("a,2026-09-20T09:00:00,yesterday-ish,2026-09-20T09:02:00,2026-09-20T09:03:00")
        with self.assertRaises(tea.CannotTell):   # junk in a column other than detected
            self.run_rows("a,2026-09-20T09:00:00,2026-09-20T09:01:00,2026-09-20T09:02:00,soon")
        with self.assertRaises(tea.CannotTell):
            self.run_rows("a,1,2,3", header="alert_id,foo,bar,baz")
        with self.assertRaises(tea.CannotTell):
            self.run_rows("a,2026-09-20T09:00:00,,2026-09-20T09:02:00,2026-09-20T09:03:00")
        with self.assertRaises(tea.CannotTell):
            tea.audit_latency(self.write("empty.csv", HEADER + "\n"))

    def test_duration_format(self):
        self.assertEqual(tea.fmt_duration(708), "11m48s")
        self.assertEqual(tea.fmt_duration(8964), "2h29m24s")
        self.assertEqual(tea.fmt_duration(42), "42s")
        self.assertEqual(tea.fmt_duration(None), "-")


# ================================================================================================
# coverage
# ================================================================================================

class CoverageAudit(TmpCase):
    SCOPE = ("detector,environment,excluded\n"
             "dns-anomaly,*,0\n"
             "dns-anomaly,rl-train-b,1\n"
             "proxy-egress,rl-*,0\n"
             "proxy-egress,eval-*,0\n"
             "proxy-egress,legacy-*,0\n")

    def test_openai_shape_excluded_but_logged(self):
        # "an infrastructure detector for anomalous DNS activity excluded the affected
        # environment, though DNS activity was logged"
        seen = ["rl-train-a", "RL-Train-B", "eval-1", "ci-1"]
        rep = tea.audit_coverage(seen, tea.read_scope(self.write("scope.csv", self.SCOPE)))["detectors"]
        self.assertEqual(rep["dns-anomaly"]["excluded_but_logged"], ["rl-train-b"])
        self.assertEqual(rep["dns-anomaly"]["covered"], ["ci-1", "eval-1", "rl-train-a"])
        self.assertEqual(rep["dns-anomaly"]["not_in_scope"], [])
        self.assertEqual(rep["proxy-egress"]["not_in_scope"], ["ci-1"])
        self.assertEqual(rep["proxy-egress"]["excluded_but_logged"], [])
        self.assertEqual(rep["proxy-egress"]["scope_entries_with_no_logs"], ["legacy-*"])

    def test_full_coverage_is_quiet(self):
        seen = ["rl-train-a", "eval-1"]
        rep = tea.audit_coverage(seen, tea.read_scope(self.write("s.csv", "detector,environment\nd,rl-*\nd,eval-*\n")))
        self.assertEqual(rep["detectors"]["d"]["not_in_scope"], [])
        self.assertEqual(rep["detectors"]["d"]["excluded_but_logged"], [])

    def test_plain_list_scope_and_csv_seen(self):
        seen = tea._read_names(self.write("seen.csv", "environment,events\nprod-a,10\nsandbox-7,3\n"))
        rep = tea.audit_coverage(seen, tea.read_scope(self.write("s.txt", "prod-*\n")))
        self.assertEqual(rep["detectors"]["detector"]["not_in_scope"], ["sandbox-7"])

    def test_cannot_tell(self):
        with self.assertRaises(tea.CannotTell):
            tea.audit_coverage([], tea.read_scope(self.write("s.txt", "prod-*\n")))
        with self.assertRaises(tea.CannotTell):
            tea.read_scope(self.write("empty.txt", "# nothing here\n\n"))


# ================================================================================================
# CLI exit codes: 0 clean, 1 flagged, 2 cannot tell
# ================================================================================================

class Cli(TmpCase):
    def run_main(self, argv: list[str]) -> int:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return tea.main(argv)

    def test_exit_codes(self):
        bad = build_gem(self.tmp, "oaifetchmde1778385544", "0.0.1", SUSPECT_FILES)
        good = build_gem(self.tmp, "html-cleaner", "2.4.1", BENIGN_FILES)
        self.assertEqual(self.run_main(["gem", bad]), 1)
        self.assertEqual(self.run_main(["gem", good]), 0)
        self.assertEqual(self.run_main(["gem", self.write("junk.gem", "nope")]), 2)
        self.assertEqual(self.run_main(["latency", self.write("a.csv", HEADER + "\n" + OPENAI_ROW + "\n")]), 1)
        self.assertEqual(self.run_main(["--json", "dns", self.write("d.log", zeek_dns(benign_rows()))]), 0)


# ================================================================================================
# The regexes that live in the pack files, exercised here so a copy that drifts fails a test.
# ================================================================================================

OUTCOME_POSITIVES = [
    "Attempt failed, no data returned",
    "DNS lookup timed out - closing",
    "external service had shut down; static notice only",
    "Blocked by proxy, no impact since nothing came back",
    "Failed to retrieve content from host",
    "No useful information obtained by the agent",
    "request was blocked by policy",
    "upload failed",
]
OUTCOME_NEGATIVES = [
    "False positive: sanctioned internal mirror",
    "Duplicate of INC-1234",
    "Authorised red-team exercise, ticket SEC-88",
    "Tuning: known CI job publishes on tag",
    "Resolved by owner, domain added to allowlist after review",
    "Contained and reimaged",
]


class PackRegexCrossCheck(unittest.TestCase):
    def spl_outcome(self) -> str:
        txt = open(os.path.join(PACK, "detections", "splunk", "transitive-egress.spl"), encoding="utf-8").read()
        return re.search(r'match\(reason_l, "([^"]+)"\)', txt).group(1)

    def kql_outcome(self) -> str:
        txt = open(os.path.join(PACK, "detections", "kql", "transitive-egress-hunting.kql"), encoding="utf-8").read()
        return re.search(r'let outcome_rx = @"([^"]+)";', txt).group(1)

    def test_outcome_regex_same_in_spl_and_kql(self):
        self.assertEqual(self.spl_outcome(), self.kql_outcome())

    def test_outcome_regex_fires_and_stays_quiet(self):
        rx = re.compile(self.spl_outcome())
        for s in OUTCOME_POSITIVES:
            self.assertTrue(rx.search(s.lower()), s)
        for s in OUTCOME_NEGATIVES:
            self.assertIsNone(rx.search(s.lower()), s)

    def test_sigma_long_label_regex_matches_tool_threshold(self):
        txt = open(os.path.join(PACK, "detections", "sigma", "sandbox-dns-shape.yml"), encoding="utf-8").read()
        rx = re.compile(re.search(r"query\|re: '([^']+\{40,\}[^']*)'", txt).group(1))
        self.assertTrue(rx.search("a" * 40 + ".example.net"))
        self.assertIsNone(rx.search("a" * 39 + ".example.net"))
        self.assertEqual(tea.score_dns([{"ts": "", "src": SANDBOX, "query": "a" * 40 + ".example.net", "qtype": "A"}])[0]["flags"],
                         ["long-name"])


if __name__ == "__main__":
    unittest.main()
