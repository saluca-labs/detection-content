#!/usr/bin/env python3
"""Transitive egress audit: read-only checks for agent sandboxes, package registries and the
teams that watch them. Stdlib only.

  python hunt/transitive_egress_audit.py gem      PATH [PATH ...]      # .gem file or unpacked dir
  python hunt/transitive_egress_audit.py dns      LOG  [--allow FILE]  # Zeek dns.log or CSV
  python hunt/transitive_egress_audit.py latency  ALERTS.csv [--max-contain-minutes 30]
  python hunt/transitive_egress_audit.py coverage --seen FILE --scope FILE

Companion to campaigns/2026-09-transitive-egress. Every subcommand READS. Nothing is executed,
installed, extracted to disk, resolved or fetched:

  gem       opens a .gem (a plain tar holding metadata.gz and data.tar.gz) or walks an unpacked
            directory, and reads files as text. It flags documentation-build configuration that
            loads code (.yardopts --load, -e, --plugin, --query), package names and versions with
            a Unix-timestamp suffix, the marker comments rubyhack.ai published as indicators, the
            payload file names it published, package code that references a registry publish or
            webhook API, and markup or template expressions in package metadata (JFrog's July
            samples). Ruby is never run and YAML is never loaded: metadata is read as text, which
            is what JFrog recommends ("Inspect suspicious values as text rather than loading
            gemspec code or unsafe YAML objects").
  dns       scores sandbox DNS per registered domain: queries, unique subdomains, longest name
            and label, mean label entropy, and the share of non-address record types. Ranked.
  latency   per-alert event-to-detect, detect-to-ack and ack-to-contain, with medians, from a
            CSV of timestamps. Containment more than 30 minutes after acknowledgement is flagged
            by default: that is OpenAI's own stated standard ("If they cannot conclusively
            determine within 30 minutes that the flag is a false positive, those teams are
            expected to pause the activity").
  coverage  environments seen in DNS or proxy logs versus each detector's scope and exclusion
            list. "logged is not detected": OpenAI's DNS report records that "an infrastructure
            detector for anomalous DNS activity excluded the affected environment, though DNS
            activity was logged".

CANNOT TELL IS NOT A PASS. An input that yields nothing parseable, a timestamp that does not
parse, or an empty scope list raises. It never reports clean.

Exit codes: 0 nothing flagged, 1 something flagged, 2 input could not be evaluated.

Every threshold is a starting point taken from the published record, not from telemetry.

Author: Cristian Ruvalcaba and the Saluca Agentic AI Research Team, 2026-09-27. Apache-2.0.
Defensive use only.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import gzip
import io
import json
import math
import os
import re
import shlex
import statistics
import sys
import tarfile
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_FILE_BYTES = 2 * 1024 * 1024     # read at most this much of any one file
MAX_FILES = 5000                     # and at most this many files per package
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024  # a .gem's inner data.tar.gz is read whole, up to this size


class CannotTell(ValueError):
    """The input could not be evaluated. Never a pass."""


# =============================================================================================
# gem
# =============================================================================================

# YARD options that make the documentation build run code: --load/-e FILE loads a Ruby file,
# --plugin NAME loads a plugin, --query evaluates a Ruby expression against each object.
YARD_CODE_OPTS = ("--load", "-e", "--plugin", "--query")

# Marker comments rubyhack.ai published verbatim as found in campaign packages ("# malicious
# probe", "#hack", "# malicious test", "# exploit southwark calendar", "# malicious yard loader",
# "# exfil by push gem 0.0.3", "# Fetch target and self-publish next gem", "# leak exfil by
# repeated attempts ...", "# yard exploit test", "# disable evil in next version and bump
# version", "# rubydoc ssrf test", "# malicious crawler/exfil ...", "# Make exfil gem",
# "# package payload gem"). A comment is a '#' at the start of a line or after whitespace.
# The generic words are pinned to the published phrases: "# hack around a bug", "# malicious
# input is escaped" and "# exploit mitigation" are ordinary comments in ordinary libraries.
# "#hack" matches only as the whole comment. "exfil" matches as a word, not inside exfiltration.
MARKER_RX = re.compile(
    r"(?:^|\s)#\s*(?:malicious\s+(?:probe|test|yard\s+loader|crawler)\b|hack\s*$|"
    r"exploit\s+(?:southwark|fetch\s+full)\b|(?:make\s+|leak\s+)?exfil\b|"
    r"disable\s+evil\b|yard\s+exploit\b|rubydoc\s+ssrf\b|package\s+payload\s+gem\b|"
    r"fetch\s+target\s+and\s+self-publish\b)",
    re.I | re.M)

# Payload file names rubyhack.ai published (hack.rb, evil.rb, inject.rb, exploit.rb, ssrf.rb) and
# JFrog/rubyhack's payload.rb. Weak alone: common words.
PAYLOAD_NAMES = {"hack.rb", "evil.rb", "inject.rb", "exploit.rb", "ssrf.rb", "payload.rb"}

# Package code that talks to a registry's write API. JFrog: payloads "attempt to POST it to
# RubyGems' /api/v1/gems endpoint"; webhook registration via /api/v1/web_hooks.
PUBLISH_RX = re.compile(r"/api/+v1/+(?:gems|web_hooks)\b|\bgem\s+push\b|upload\.pypi\.org", re.I)

# Code that WRITES the package's own documentation-build configuration: the self-disarming
# pattern rubyhack.ai published ("# disable evil in next version and bump version", followed by a
# File.write of .yardopts). A bare mention of .yardopts is not enough: YARD itself mentions it in
# fourteen files (checked against yard-0.9.37, 2026-09-27).
DOC_CONFIG_WRITE_RX = re.compile(r"""(?:File|IO)\.(?:write|open|binwrite)\s*\(?\s*['"][^'"]*\.yardopts['"]""")
CODE_SUFFIXES = (".rb", ".rake", ".gemspec", "Rakefile", "Gemfile")

# Markup or template expressions in metadata (JFrog: XSS probes in description and author,
# ERB and expression-language probes in author).
METADATA_MARKUP_RX = re.compile(r"<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*svg|<%|\$\{", re.I)

# A 10-digit Unix timestamp at the end of a name, optionally followed by up to three more digits
# (rubyhack.ai lists chatoaifetch177855288717: a timestamp plus two digits).
TS_SUFFIX_RX = re.compile(r"(?<!\d)(\d{10})(\d{0,3})$")
TS_MIN = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
TS_MAX = datetime(2031, 1, 1, tzinfo=timezone.utc).timestamp()


def timestamp_suffix(name: str) -> datetime | None:
    """The UTC time a trailing Unix-timestamp suffix decodes to, or None."""
    m = TS_SUFFIX_RX.search(name.strip())
    if not m:
        return None
    ts = int(m.group(1))
    if not (TS_MIN <= ts < TS_MAX):
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _is_text(b: bytes) -> bool:
    return b"\x00" not in b[:8192]


def _read_member(tf: tarfile.TarFile, m: tarfile.TarInfo, cap: int = MAX_FILE_BYTES) -> bytes:
    fh = tf.extractfile(m)
    return fh.read(cap) if fh else b""


def load_package(path: str) -> tuple[list[tuple[str, bytes]], str]:
    """Return ([(relative path, bytes)], metadata text). Reads only; never writes to disk."""
    files: list[tuple[str, bytes]] = []
    meta = ""
    if os.path.isdir(path):
        for root, dirs, names in os.walk(path, followlinks=False):
            dirs.sort()
            for n in sorted(names):
                full = os.path.join(root, n)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                if len(files) >= MAX_FILES:
                    raise CannotTell("%s: more than %d files; refusing to report a partial scan" % (path, MAX_FILES))
                with open(full, "rb") as fh:
                    files.append((os.path.relpath(full, path).replace("\\", "/"), fh.read(MAX_FILE_BYTES)))
        for rel, data in files:
            if rel.endswith(".gemspec") or rel == "metadata":
                meta += data.decode("utf-8", "replace") + "\n"
    elif os.path.isfile(path):
        try:
            outer = tarfile.open(path, mode="r:")
        except tarfile.TarError as exc:
            raise CannotTell("%s: not a readable .gem (tar) file: %s" % (path, exc))
        with outer:
            members = {m.name: m for m in outer.getmembers() if m.isfile()}
            if "data.tar.gz" not in members:
                raise CannotTell("%s: no data.tar.gz inside; not a .gem" % path)
            if "metadata.gz" in members:
                try:
                    meta = gzip.decompress(_read_member(outer, members["metadata.gz"])).decode("utf-8", "replace")
                except OSError as exc:
                    raise CannotTell("%s: metadata.gz unreadable: %s" % (path, exc))
            # The inner archive is read WHOLE. Truncating it at the per-file cap made every gem with
            # a data.tar.gz over 2 MB crash (found on nokogiri-1.16.7, 2026-09-27). A cap is
            # still needed, and exceeding it is "cannot tell", never a partial pass.
            data_member = members["data.tar.gz"]
            if data_member.size > MAX_ARCHIVE_BYTES:
                raise CannotTell("%s: data.tar.gz is %d bytes, over the %d-byte cap; cannot tell"
                                 % (path, data_member.size, MAX_ARCHIVE_BYTES))
            try:
                inner = tarfile.open(fileobj=io.BytesIO(_read_member(outer, data_member, MAX_ARCHIVE_BYTES)),
                                     mode="r:gz")
                with inner:
                    for m in inner.getmembers():
                        if not m.isfile():
                            continue
                        if len(files) >= MAX_FILES:
                            raise CannotTell("%s: more than %d files; refusing to report a partial scan"
                                             % (path, MAX_FILES))
                        files.append((m.name[2:] if m.name.startswith("./") else m.name, _read_member(inner, m)))
            except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
                raise CannotTell("%s: data.tar.gz unreadable: %s" % (path, exc))
    else:
        raise CannotTell("%s: no such file or directory" % path)
    if not files:
        raise CannotTell("%s: no files read; cannot tell" % path)
    return files, meta


def _meta_field(meta: str, field_name: str) -> str | None:
    m = re.search(r"^%s:\s*(.+)$" % re.escape(field_name), meta, re.M)
    return m.group(1).strip().strip("'\"") if m else None


def _meta_version(meta: str) -> str | None:
    # Serialised gemspec: "version: !ruby/object:Gem::Version\n  version: 0.0.1"
    m = re.search(r"^version:.*\n\s+version:\s*(\S+)", meta, re.M) or re.search(r"^version:\s*(\S+)", meta, re.M)
    return m.group(1).strip("'\"") if m else None


def yardopts_code_options(text: str) -> list[str]:
    """Options in a .yardopts file that make the build load or evaluate code."""
    try:
        tokens = shlex.split(text, comments=False, posix=True)
    except ValueError:
        tokens = text.split()
    found = []
    for i, t in enumerate(tokens):
        opt = t.split("=", 1)[0]
        if opt in YARD_CODE_OPTS:
            val = t.split("=", 1)[1] if "=" in t else (tokens[i + 1] if i + 1 < len(tokens) else "")
            found.append("%s %s" % (opt, val))
    return found


def audit_gem(path: str) -> dict:
    files, meta = load_package(path)
    findings: list[dict] = []

    def add(sev: str, check: str, where: str, detail: str) -> None:
        findings.append({"severity": sev, "check": check, "file": where, "detail": detail})

    name = _meta_field(meta, "name") or os.path.basename(path.rstrip("/\\"))
    version = _meta_version(meta) or ""
    if name.endswith(".gem"):
        name = name[:-4]
    when = timestamp_suffix(name)
    if when:
        add("medium", "timestamp-suffixed-name", "metadata", "name %r ends in a Unix timestamp: %s UTC"
            % (name, when.strftime("%Y-%m-%d %H:%M:%S")))
    for part in version.split("."):
        vwhen = timestamp_suffix(part)
        if vwhen:
            add("medium", "timestamp-version", "metadata", "version %r carries a Unix timestamp: %s UTC"
                % (version, vwhen.strftime("%Y-%m-%d %H:%M:%S")))
            break
    for fld in ("authors", "email", "description", "summary", "homepage"):
        block = re.search(r"^%s:(.*(?:\n[ \-].*)*)" % fld, meta, re.M)
        if block and METADATA_MARKUP_RX.search(block.group(1)):
            add("high", "metadata-markup", "metadata", "%s contains markup or a template expression" % fld)

    for rel, data in files:
        base = rel.rsplit("/", 1)[-1]
        if not _is_text(data):
            continue
        text = data.decode("utf-8", "replace")
        if base == ".yardopts":
            for opt in yardopts_code_options(text):
                add("medium", "doc-build-loads-code", rel, "documentation build configuration loads code: %s" % opt)
        if base == "extconf.rb":
            add("info", "install-build-step", rel, "native extension build step: runs code at install time")
        if base.lower() in PAYLOAD_NAMES:
            add("medium", "payload-filename", rel, "file name published as a campaign indicator: %s" % base)
        for lineno, line in enumerate(text.splitlines(), 1):
            if MARKER_RX.search(line):
                add("high", "published-marker-comment", "%s:%d" % (rel, lineno), line.strip()[:160])
        if base.endswith(CODE_SUFFIXES):
            if PUBLISH_RX.search(text):
                add("medium", "code-publishes-packages", rel,
                    "references a registry publish or webhook API (registry API clients do this legitimately)")
            if DOC_CONFIG_WRITE_RX.search(text):
                add("high", "code-rewrites-doc-config", rel,
                    "code writes .yardopts (the self-disarming pattern rubyhack.ai describes)")

    # The loop the sources describe needs both halves in one package: a documentation build that
    # loads code, and code that publishes or carries the published markers. Either half alone has
    # legitimate owners (YARD's own .yardopts loads a template plugin; the gems API client
    # references /api/v1/gems). Together they are the finding.
    got = {f["check"] for f in findings}
    if "doc-build-loads-code" in got and got & {"code-publishes-packages", "published-marker-comment",
                                                 "code-rewrites-doc-config"}:
        add("high", "doc-build-loop", "package",
            "documentation build loads code AND the package carries publish code or published markers")
    return {"path": path, "name": name, "version": version, "files_read": len(files), "findings": findings}


# =============================================================================================
# dns
# =============================================================================================

# Multi-label public suffixes common enough to matter, so example.co.uk groups as one domain.
# Not the Public Suffix List; pass --suffix-list with a PSL file for exact grouping.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "co.in", "co.za", "com.sg",
    "com.tw", "com.hk", "co.kr", "com.tr", "com.ar", "github.io", "herokuapp.com",
    "cloudfront.net", "amazonaws.com", "azurewebsites.net", "appspot.com", "vercel.app",
    "netlify.app", "pages.dev", "workers.dev",
}
ODD_QTYPES = {"TXT", "NULL", "ANY", "*", "NS", "16", "10", "255", "2"}


def registered_domain(name: str, suffixes: set[str] | None = None) -> str:
    labels = [x for x in name.lower().rstrip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    sfx = suffixes if suffixes is not None else MULTI_SUFFIXES
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in sfx:
            return ".".join(labels[-(n + 1):])
    return ".".join(labels[-2:])


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def parse_dns(path: str) -> list[dict]:
    """Zeek dns.log (TSV with #fields) or CSV with ts, src, query, qtype columns."""
    rows: list[dict] = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        head = fh.readline()
        fh.seek(0)
        if head.startswith("#separator") or head.startswith("#fields"):
            fields: list[str] = []
            for line in fh:
                line = line.rstrip("\r\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if not line or line.startswith("#") or not fields:
                    continue
                vals = line.split("\t")
                if len(vals) != len(fields):
                    continue
                r = dict(zip(fields, vals))
                q = r.get("query", "-")
                if q in ("-", "(empty)", ""):
                    continue
                rows.append({"ts": r.get("ts", ""), "src": r.get("id.orig_h", ""), "query": q,
                             "qtype": (r.get("qtype_name") or r.get("qtype") or "").upper()})
        else:
            for r in csv.DictReader(fh):
                r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
                q = r.get("query") or r.get("qname") or r.get("query_name")
                if not q:
                    continue
                rows.append({"ts": r.get("ts", ""), "src": r.get("src") or r.get("src_ip") or r.get("client", ""),
                             "query": q, "qtype": (r.get("qtype") or r.get("qtype_name") or r.get("record_type") or "").upper()})
    if not rows:
        raise CannotTell("%s: no parseable DNS queries; cannot tell" % path)
    return rows


def score_dns(rows: list[dict], allow: list[str] | None = None, suffixes: set[str] | None = None,
              min_unique: int = 50, long_label: int = 40, long_name: int = 100,
              min_entropy: float = 3.5, min_left_len: int = 16, txt_share: float = 0.5,
              txt_min: int = 10) -> list[dict]:
    allow_l = [a.lower().strip(".") for a in (allow or []) if a.strip()]
    by: dict[str, dict] = defaultdict(lambda: {"queries": 0, "subs": set(), "max_name": 0,
                                                "max_label": 0, "odd": 0, "srcs": set()})
    for r in rows:
        q = r["query"].lower().rstrip(".")
        if any(q == a or q.endswith("." + a) for a in allow_l):
            continue
        reg = registered_domain(q, suffixes)
        d = by[reg]
        d["queries"] += 1
        left = q[: -len(reg)].rstrip(".") if q != reg else ""
        if left:
            d["subs"].add(left)
        d["max_name"] = max(d["max_name"], len(q))
        d["max_label"] = max(d["max_label"], max(len(x) for x in q.split(".")))
        if r["qtype"] in ODD_QTYPES:
            d["odd"] += 1
        if r["src"]:
            d["srcs"].add(r["src"])
    out = []
    for reg, d in by.items():
        subs = d["subs"]
        ent = statistics.mean(shannon(s.replace(".", "")) for s in subs) if subs else 0.0
        left_len = statistics.mean(len(s) for s in subs) if subs else 0.0
        share = d["odd"] / d["queries"]
        flags = []
        if len(subs) >= min_unique:
            flags.append("high-cardinality")
        if d["max_label"] >= long_label or d["max_name"] >= long_name:
            flags.append("long-name")
        if ent >= min_entropy and left_len >= min_left_len:
            flags.append("high-entropy")
        if share >= txt_share and d["queries"] >= txt_min:
            flags.append("txt-heavy")
        out.append({"registered_domain": reg, "queries": d["queries"], "unique_subdomains": len(subs),
                    "max_name_len": d["max_name"], "max_label_len": d["max_label"],
                    "mean_entropy": round(ent, 2), "mean_left_len": round(left_len, 1),
                    "odd_type_share": round(share, 2), "sources": sorted(d["srcs"]), "flags": flags})
    out.sort(key=lambda x: (-len(x["flags"]), -x["unique_subdomains"], -x["queries"], x["registered_domain"]))
    return out


# =============================================================================================
# latency
# =============================================================================================

STAGES = (("event_to_detect", "event", "detected"), ("detect_to_ack", "detected", "acked"),
          ("ack_to_contain", "acked", "contained"), ("event_to_contain", "event", "contained"))
ALIASES = {"event": ("event", "event_time", "first_event", "first_activity"),
           "detected": ("detected", "detected_time", "alert_time", "created"),
           "acked": ("acked", "acked_time", "ack", "acknowledged"),
           "contained": ("contained", "contained_time", "killed", "stopped")}


def parse_ts(s: str) -> datetime:
    s = s.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise CannotTell("unparseable timestamp %r; cannot tell" % s)
    return dt


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    neg = seconds < 0
    s = int(round(abs(seconds)))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        txt = "%dh%02dm%02ds" % (h, m, sec)
    elif m:
        txt = "%dm%02ds" % (m, sec)
    else:
        txt = "%ds" % sec
    return ("-" + txt) if neg else txt


def audit_latency(path: str, max_contain_minutes: float = 30.0) -> dict:
    with open(path, encoding="utf-8", newline="") as fh:
        raw_rows = list(csv.DictReader(fh))
    if not raw_rows:
        raise CannotTell("%s: no alert rows; cannot tell" % path)
    cols = {c.strip().lower(): c for c in raw_rows[0].keys() if c}
    colmap = {}
    for key, names in ALIASES.items():
        for n in names:
            if n in cols:
                colmap[key] = cols[n]
                break
    if "detected" not in colmap:
        raise CannotTell("%s: no detected-time column (one of %s)" % (path, ", ".join(ALIASES["detected"])))
    id_col = cols.get("alert_id") or cols.get("id")
    alerts = []
    for i, r in enumerate(raw_rows, 1):
        t = {}
        for key, col in colmap.items():
            v = (r.get(col) or "").strip()
            t[key] = parse_ts(v) if v else None
        if t.get("detected") is None:
            raise CannotTell("%s row %d: no detected time" % (path, i))
        durs = {}
        for stage, a, b in STAGES:
            if t.get(a) is not None and t.get(b) is not None:
                durs[stage] = (t[b] - t[a]).total_seconds()
            else:
                durs[stage] = None
        flags = []
        if t.get("acked") is None:
            flags.append("NOT ACKED")
        if t.get("contained") is None:
            flags.append("NOT CONTAINED")
        if any(v is not None and v < 0 for v in durs.values()):
            flags.append("OUT OF ORDER")
        if durs["ack_to_contain"] is not None and durs["ack_to_contain"] > max_contain_minutes * 60:
            flags.append("CONTAINMENT > %gm AFTER ACK" % max_contain_minutes)
        alerts.append({"alert_id": (r.get(id_col) if id_col else str(i)), "seconds": durs,
                       "durations": {k: fmt_duration(v) for k, v in durs.items()}, "flags": flags})
    medians = {}
    for stage, _, _ in STAGES:
        vals = [a["seconds"][stage] for a in alerts if a["seconds"][stage] is not None and a["seconds"][stage] >= 0]
        medians[stage] = fmt_duration(statistics.median(vals)) if vals else "-"
    return {"alerts": alerts, "medians": medians, "max_contain_minutes": max_contain_minutes}


# =============================================================================================
# coverage
# =============================================================================================

def _read_names(path: str, column: str = "environment") -> list[str]:
    """One name per line, or a CSV with an 'environment' column. Lower-cased."""
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if lines and column in [c.strip().lower() for c in lines[0].split(",")]:
        out = []
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if row.get(column):
                out.append(row[column].lower())
        return out
    return [ln.strip().lower() for ln in lines]


def read_scope(path: str) -> dict[str, dict[str, list[str]]]:
    """CSV detector,environment[,excluded] or a plain list (one detector named 'detector')."""
    with open(path, encoding="utf-8", newline="") as fh:
        text = fh.read()
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    scope: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"include": [], "exclude": []})
    if lines and "," in lines[0] and "detector" in lines[0].lower():
        for r in csv.DictReader(io.StringIO("\n".join(lines))):
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
            det, env = r.get("detector", ""), r.get("environment", "").lower()
            if not det or not env:
                continue
            excluded = r.get("excluded", "").lower() in ("1", "true", "yes", "y", "excluded")
            scope[det]["exclude" if excluded else "include"].append(env)
    else:
        for ln in lines:
            scope["detector"]["include"].append(ln.strip().lower())
    if not scope or not any(v["include"] or v["exclude"] for v in scope.values()):
        raise CannotTell("%s: empty detector scope; cannot tell" % path)
    return scope


def audit_coverage(seen: list[str], scope: dict[str, dict[str, list[str]]]) -> dict:
    seen_set = sorted({s.strip().lower() for s in seen if s and s.strip()})
    if not seen_set:
        raise CannotTell("no environments seen in logs; cannot tell")
    report = {}
    for det, sc in sorted(scope.items()):
        def matches(env: str, pats: list[str]) -> bool:
            return any(fnmatch.fnmatchcase(env, p) for p in pats)
        excluded_logged = [e for e in seen_set if matches(e, sc["exclude"])]
        covered = [e for e in seen_set if matches(e, sc["include"]) and e not in excluded_logged]
        gaps = [e for e in seen_set if e not in covered and e not in excluded_logged]
        stale = [p for p in sc["include"] if not any(fnmatch.fnmatchcase(e, p) for e in seen_set)]
        report[det] = {"covered": covered, "excluded_but_logged": excluded_logged,
                       "not_in_scope": gaps, "scope_entries_with_no_logs": stale}
    return {"environments_seen": len(seen_set), "detectors": report}


# =============================================================================================
# CLI
# =============================================================================================

def _emit(obj, as_json: bool, text: str) -> None:
    print(json.dumps(obj, indent=2, default=str) if as_json else text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("gem", help="inspect .gem files or unpacked gem directories (read only)")
    p.add_argument("paths", nargs="+")
    p = sub.add_parser("dns", help="score sandbox DNS per registered domain")
    p.add_argument("log")
    p.add_argument("--allow", help="file of allowlisted zones, one per line")
    p.add_argument("--suffix-list", help="Public Suffix List file for exact registered-domain grouping")
    p.add_argument("--min-unique", type=int, default=50)
    p.add_argument("--long-label", type=int, default=40)
    p.add_argument("--long-name", type=int, default=100)
    p = sub.add_parser("latency", help="alert -> ack -> containment latencies from a CSV")
    p.add_argument("csv")
    p.add_argument("--max-contain-minutes", type=float, default=30.0)
    p = sub.add_parser("coverage", help="environments in logs versus detector scope")
    p.add_argument("--seen", required=True, help="environments seen in logs: one per line, or CSV with 'environment'")
    p.add_argument("--scope", required=True, help="CSV detector,environment[,excluded] or one environment per line")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "gem":
            results = [audit_gem(p) for p in a.paths]
            lines = []
            for r in results:
                lines.append("%s  (%s %s, %d files read)" % (r["path"], r["name"], r["version"], r["files_read"]))
                for f in r["findings"]:
                    lines.append("  %-6s %-26s %s  %s" % (f["severity"], f["check"], f["file"], f["detail"]))
                if not r["findings"]:
                    lines.append("  nothing flagged")
            _emit(results, a.json, "\n".join(lines))
            return 1 if any(r["findings"] for r in results) else 0
        if a.cmd == "dns":
            allow = open(a.allow, encoding="utf-8").read().split() if a.allow else None
            sfx = None
            if a.suffix_list:
                sfx = {ln.strip().lower() for ln in open(a.suffix_list, encoding="utf-8")
                       if ln.strip() and not ln.startswith("//")}
            res = score_dns(parse_dns(a.log), allow=allow, suffixes=sfx, min_unique=a.min_unique,
                            long_label=a.long_label, long_name=a.long_name)
            lines = ["%-34s %8s %7s %8s %9s %7s %6s  %s" % ("registered domain", "queries", "unique",
                                                            "max_name", "max_label", "entropy", "odd%", "flags")]
            for r in res:
                lines.append("%-34s %8d %7d %8d %9d %7.2f %6d  %s" % (
                    r["registered_domain"][:34], r["queries"], r["unique_subdomains"], r["max_name_len"],
                    r["max_label_len"], r["mean_entropy"], round(100 * r["odd_type_share"]), ",".join(r["flags"]) or "-"))
            _emit(res, a.json, "\n".join(lines))
            return 1 if any(r["flags"] for r in res) else 0
        if a.cmd == "latency":
            res = audit_latency(a.csv, a.max_contain_minutes)
            lines = ["%-16s %14s %14s %14s %16s  %s" % ("alert", "event->detect", "detect->ack",
                                                         "ack->contain", "event->contain", "flags")]
            for r in res["alerts"]:
                d = r["durations"]
                lines.append("%-16s %14s %14s %14s %16s  %s" % (str(r["alert_id"])[:16], d["event_to_detect"],
                             d["detect_to_ack"], d["ack_to_contain"], d["event_to_contain"], ", ".join(r["flags"]) or "-"))
            m = res["medians"]
            lines.append("%-16s %14s %14s %14s %16s" % ("MEDIAN", m["event_to_detect"], m["detect_to_ack"],
                                                         m["ack_to_contain"], m["event_to_contain"]))
            _emit(res, a.json, "\n".join(lines))
            return 1 if any(r["flags"] for r in res["alerts"]) else 0
        if a.cmd == "coverage":
            res = audit_coverage(_read_names(a.seen), read_scope(a.scope))
            lines = ["%d environments seen in logs" % res["environments_seen"]]
            flagged = False
            for det, r in res["detectors"].items():
                lines.append("\n%s" % det)
                for k in ("excluded_but_logged", "not_in_scope", "scope_entries_with_no_logs", "covered"):
                    lines.append("  %-28s %s" % (k, ", ".join(r[k]) or "-"))
                flagged = flagged or bool(r["excluded_but_logged"] or r["not_in_scope"])
            _emit(res, a.json, "\n".join(lines))
            return 1 if flagged else 0
    except CannotTell as exc:
        print("CANNOT TELL: %s" % exc, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
