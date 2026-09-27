#!/usr/bin/env python3
"""public_scan_search - find laundered-vantage activity against your own hosts.

READ-ONLY. This tool never submits a scan, never sends a probe, and never writes anywhere but
stdout and stderr. It searches public scan indices, imports files you already have, and parses
access logs. Stdlib only.

Why it exists. In September 2026 Transluce found AI agents probing data sites (UNM, Data USA,
AIHW) through urlquery.net's sandbox browser. The victims' own logs would show a scanner. The
complete record sat in urlquery.net's PUBLIC scan history, which is how Transluce found it. This
tool turns that method into a routine a site owner can run, and adds the site-side sequence
analysis for the logs you do own. See campaigns/2026-09-laundered-vantage/README.md.

A QUIET RESULT FROM A PUBLIC INDEX MEANS NOTHING WAS PUBLISHED, NOT THAT NOTHING HAPPENED. Private
scans, and services that do not publish, leave no record here.

Subcommands:

  urlscan --host H [--since YYYY-MM-DD] [--max N]
      Search urlscan.io's documented Search API, GET https://urlscan.io/api/v1/search/?q=domain:H,
      and classify every submitted URL and final page URL. Optional API key from the environment
      variable URLSCAN_API_KEY (sent as the documented `API-Key` header). Never a CLI argument.
      --since filters on task.time client-side.

  urlquery --host H [--field domain|fqdn] [--max N]
      urlquery.net DOES document a public search API (checked 2026-09-26): Public API v1 at
      https://urlquery.net/doc/api/public/v1, spec at https://urlquery.net/static/swagger/api.json,
      operation GET https://api.urlquery.net/public/v1/search/reports/?query=...&limit=&offset=,
      with a REQUIRED `x-apikey` header (the endpoint returned 401 without one on 2026-09-26). The
      key is read from URLQUERY_API_KEY; with no key this mode refuses and exits 2 rather than
      reporting a pass. The spec gives no response schema. The fields read here (reports[],
      report_id, date, url.addr, final.url.addr, tags) come from urlquery's own Go client,
      github.com/urlquery/urlquery-api-go models.go (ReportOverview, SearchResponse). An unexpected
      shape raises. Query syntax is the one Transluce used: http.url.domain:H / http.url.fqdn:H.

  urlquery --dataset DIR --host H
      No key needed. Import Transluce's published dataset (urlquery-agent-activity-2026-09-23.zip,
      v5, unpacked): methods.json maps each search query to a source label, report-sources.csv maps
      reports to labels, all-reports.csv holds the report rows. Reports whose method query or
      markers name H are listed. THE DATASET CARRIES NO SUBMITTED URLS (its README: "no full report
      JSON, response bodies, screenshots, submitted code"), so these rows are listed, never
      classified. Open the report links to see what was sent.

  urlquery --report FILE [FILE...]
      Import saved urlquery reports: the JSON report (url.addr, final.url.addr) or the page saved
      as text, where the URL follows a line reading "URL" or "Finishing URL". Classifies them.

  logs FILE [--window SECONDS] [--scope path|host] [--nonprod-window SECONDS]
      Classify a web access log in Apache/nginx combined format, optionally prefixed with a virtual
      host (Apache vhost_combined: "host:port ip - - [...] ..."). Reports:
        probe       requests carrying probe grammar in the query string
        escalation  a refusal (4xx/5xx) for a source and endpoint, then probe grammar from the same
                    source within --window seconds (default 600). --scope path keys on
                    source+host+path (default), --scope host on source+host.
        nonprod     a file fetched from a pp./staging./preprod./dev./uat. host within
                    --nonprod-window (default 3600) after the same file name was refused on a
                    production host of the same site. Needs the vhost field; if no line has one,
                    this check reports that it could not run.
      Unparseable lines are counted and reported. A file with zero parseable lines is an error.

  classify URL [URL...]
      Probe-grammar classifier. Reads path, query AND fragment, because public scan records keep
      the submitted fragment even though a server never receives it.

Exit status: 0 nothing found, 1 findings, 2 usage or input error. "Cannot tell" is an error, never
a pass: a missing key, an unreadable file, an unexpected API shape, or a log with no parseable
line exits 2.

Author: Cristian Ruvalcaba and the Saluca Agentic AI Research Team, 2026-09-26
Apache-2.0. Defensive use only. The probe patterns below are quoted from Transluce's report as
indicators; nothing here generates or sends them.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------------------------
# Probe grammar
# ---------------------------------------------------------------------------------------------
# Each family is matched against the DECODED, lower-cased query string and fragment. The families
# are the ones in Transluce's published probes (UNM tok=expt0..8, Data USA's 12 suffixes, the AIHW
# reflected-script probe). They are generic on purpose: the agents sent existence checks, not
# weaponised exploits, and so does every commodity scanner. A match is a hunt lead, not a verdict.

PROBE_FAMILIES: dict[str, re.Pattern] = {
    # ../etc/passwd, /etc/passwd, ..%2F..%2Fetc%2Fpasswd once decoded, cat /etc/passwd
    "traversal": re.compile(r"etc/passwd|(?:\.\./){2,}|(?:\.\.\\){2,}"),
    # %00 is checked on the RAW text too, because decoding turns it into a NUL byte
    "null-byte": re.compile(r"\x00|%00"),
    "sqli": re.compile(r"\bunion\s+(?:all\s+)?select\b|'\s*or\s+1\s*=\s*1|\bor\s+1\s*=\s*1\s*--"),
    "template": re.compile(r"\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}"),
    "xss": re.compile(r"<\s*script\b|<\s*svg\b[^>]*\bonload\s*=|\bonerror\s*=\s*alert|"
                      r"<\s*img\b[^>]*\bonerror\s*=|javascript:\s*alert"),
    "html-injection": re.compile(r"<\s*(?:img|iframe|svg|object|embed)\b"),
    "command": re.compile(r"\b(?:wget|curl)\s+\S*\.[a-z]{2,}|\bcat\s+/etc/"),
    "php-probe": re.compile(r"wp-admin\.php|\beval\s*\(\s*base64_decode"),
    "open-redirect": re.compile(r"\bredirect=\S*evil\.com"),
    "junk-extension": re.compile(r"=\.(?:exe|dll|php|asp|jsp)\b"),
}
# Numbered experiment markers, matched on the raw query: tok=expt0 .. tok=expt8 at UNM.
MARKER = re.compile(r"(?:^|[?&#;])tok=expt\d+\b", re.I)


def _decode(text: str) -> str:
    """Percent-decode up to three times (double encoding is common in probe URLs), '+' as space."""
    out = text.replace("+", " ")
    for _ in range(3):
        nxt = urllib.parse.unquote(out)
        if nxt == out:
            break
        out = nxt
    return out.lower()


@dataclass
class Classification:
    url: str
    families: list[str] = field(default_factory=list)
    marker: str | None = None

    @property
    def is_probe(self) -> bool:
        return bool(self.families or self.marker)


def classify_url(url: str) -> Classification:
    """Classify one URL. Probe grammar is looked for in the query and the fragment. The path is
    checked for traversal only, so '/man/5/passwd' on a documentation site is not a probe."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("empty URL")
    raw = url.strip()
    # IIIF and some APIs put ';' in the path; urlsplit keeps it in the path, which is what we want.
    parts = urllib.parse.urlsplit(raw if "://" in raw else "http://" + raw)
    query_raw, frag_raw = parts.query, parts.fragment
    # A path that carries a '?'-less probe, e.g. '...default.jpg?UNION SELECT...' is still a query.
    haystack = _decode(query_raw) + "\n" + _decode(frag_raw)
    fams = [name for name, rx in PROBE_FAMILIES.items() if rx.search(haystack)]
    if "null-byte" not in fams and ("%00" in query_raw or "%00" in frag_raw):
        fams.append("null-byte")
    path_dec = _decode(parts.path)
    if "traversal" not in fams and re.search(r"(?:\.\./){2,}.*etc/", path_dec):
        fams.append("traversal")
    # xss implies html-injection; report the stronger family only
    if "xss" in fams and "html-injection" in fams:
        fams.remove("html-injection")
    m = MARKER.search("?" + query_raw) or MARKER.search("#" + frag_raw)
    return Classification(raw, sorted(fams), m.group(0).lstrip("?&#;") if m else None)


# ---------------------------------------------------------------------------------------------
# Access logs
# ---------------------------------------------------------------------------------------------

_COMBINED = (r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)'
             r'(?: HTTP/[0-9.]+)?" (?P<status>\d{3}) (?P<size>\S+)'
             r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?\s*$')
LOG_VHOST = re.compile(r"^(?P<vhost>[A-Za-z0-9.\-]+(?::\d+)?) " + _COMBINED)
LOG_PLAIN = re.compile(r"^" + _COMBINED)

NONPROD_PREFIXES = ("pp", "staging", "stage", "preprod", "pre-prod", "dev", "uat")
# Second-level labels under which the registrable domain has three labels (aihw.gov.au).
_THREE_LABEL_SUFFIXES = {"gov.au", "edu.au", "com.au", "org.au", "net.au", "gov.uk", "ac.uk",
                         "co.uk", "org.uk", "gov.nz", "govt.nz", "co.nz", "gc.ca", "gov.in"}


@dataclass
class LogEvent:
    line: int
    ts: datetime
    ip: str
    host: str | None
    method: str
    path: str
    query: str
    status: int
    url: str


def _parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")


def parse_log(path: str) -> tuple[list[LogEvent], int, int]:
    """Returns (events, total non-blank lines, unparseable lines). Raises if nothing parses."""
    events: list[LogEvent] = []
    total = bad = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            total += 1
            m = LOG_VHOST.match(line) or LOG_PLAIN.match(line)
            if not m:
                bad += 1
                continue
            try:
                ts = _parse_ts(m.group("ts"))
            except ValueError:
                bad += 1
                continue
            gd = m.groupdict()
            host = gd.get("vhost")
            if host:
                host = host.split(":")[0].lower()
            target = m.group("target")
            if target.startswith(("http://", "https://")):
                sp = urllib.parse.urlsplit(target)
                host = host or sp.hostname
                target = sp.path + ("?" + sp.query if sp.query else "")
            p, _, q = target.partition("?")
            url = "http://%s%s" % (host or "unknown-host", target)
            events.append(LogEvent(n, ts, m.group("ip"), host, m.group("method"), p, q,
                                   int(m.group("status")), url))
    if not events:
        # CANNOT TELL IS NOT A PASS: a log in a format we do not read must not report "clean".
        raise ValueError("%s: 0 of %d line(s) parsed as combined or vhost_combined log format; "
                         "refusing to report a clean result on nothing" % (path, total))
    return events, total, bad


def site_of(host: str) -> str:
    labels = host.lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _THREE_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_nonprod(host: str) -> bool:
    first = host.lower().split(".")[0]
    return first in NONPROD_PREFIXES


def is_refusal(status: int) -> bool:
    return 400 <= status <= 599


def find_escalations(events: list[LogEvent], window: int = 600, scope: str = "path") -> list[dict]:
    """A refusal for (source, endpoint) followed within `window` seconds by probe grammar from the
    same source against the same endpoint. The probe must come AFTER the refusal."""
    if scope not in ("path", "host"):
        raise ValueError("scope must be 'path' or 'host'")

    def key(e: LogEvent):
        return (e.ip, e.host, e.path) if scope == "path" else (e.ip, e.host)

    refusals: dict[tuple, list[LogEvent]] = defaultdict(list)
    out: dict[tuple, dict] = {}
    for e in sorted(events, key=lambda x: (x.ts, x.line)):
        c = classify_url(e.url)
        if c.is_probe:
            for r in refusals.get(key(e), []):
                dt = (e.ts - r.ts).total_seconds()
                if 0 <= dt <= window:
                    f = out.setdefault(key(e), {
                        "check": "escalation", "source": e.ip, "host": e.host,
                        "endpoint": e.path if scope == "path" else "*",
                        "first_refusal": r.ts.isoformat(), "refusal_status": r.status,
                        "first_probe": e.ts.isoformat(), "probes": 0, "families": set(),
                        "lines": []})
                    f["probes"] += 1
                    f["families"].update(c.families or ["marker"])
                    f["lines"].append(e.line)
                    f["last_probe"] = e.ts.isoformat()
                    break
        if is_refusal(e.status):
            refusals[key(e)].append(e)
    rows = []
    for f in out.values():
        f["families"] = ",".join(sorted(f["families"]))
        f["lines"] = ",".join(str(x) for x in f["lines"][:20])
        rows.append(f)
    return rows


def find_probes(events: list[LogEvent]) -> list[dict]:
    rows = []
    for e in events:
        c = classify_url(e.url)
        if c.is_probe:
            rows.append({"check": "probe", "line": e.line, "time": e.ts.isoformat(), "source": e.ip,
                         "host": e.host, "status": e.status,
                         "families": ",".join(c.families) or "-", "marker": c.marker or "-",
                         "path": e.path})
    return rows


def find_nonprod_fallback(events: list[LogEvent], window: int = 3600) -> list[dict] | None:
    """A file fetched from a non-production host of a site, within `window` seconds after the same
    file name was refused on a production host of that site. Keyed on file name, not source,
    because laundering can change the source between the two. Returns None when no event carries
    a host, so the caller can say the check could not run instead of reporting it clean."""
    if not any(e.host for e in events):
        return None
    refused: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    out: dict[tuple, dict] = {}
    for e in sorted(events, key=lambda x: (x.ts, x.line)):
        if not e.host:
            continue
        base = e.path.rstrip("/").rsplit("/", 1)[-1]
        if "." not in base:
            continue
        k = (site_of(e.host), base.lower())
        if is_nonprod(e.host):
            for r in refused.get(k, []):
                dt = (e.ts - r.ts).total_seconds()
                if 0 <= dt <= window:  # same-site fallback window
                    f = out.setdefault((e.host, k), {
                        "check": "nonprod", "nonprod_host": e.host, "file": base,
                        "refused_on": r.host, "refusal_status": r.status,
                        "first_refusal": r.ts.isoformat(), "first_nonprod": e.ts.isoformat(),
                        "nonprod_requests": 0, "sources": set()})
                    f["nonprod_requests"] += 1
                    f["sources"].add(e.ip)
                    break
        elif is_refusal(e.status):
            refused[k].append(e)
    rows = []
    for f in out.values():
        f["sources"] = ",".join(sorted(f["sources"]))
        rows.append(f)
    return rows


# ---------------------------------------------------------------------------------------------
# Public scan indices
# ---------------------------------------------------------------------------------------------

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
URLQUERY_SEARCH = "https://api.urlquery.net/public/v1/search/reports/"
USER_AGENT = "saluca-public-scan-search/1.0 (read-only; +https://github.com/saluca-labs/detection-content)"


def http_get_json(url: str, headers: dict[str, str]) -> dict:
    """The only network call in this tool. Tests replace it with a recorded fixture."""
    req = urllib.request.Request(url, headers=dict(headers, **{"User-Agent": USER_AGENT,
                                                                "Accept": "application/json"}))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP %d from %s" % (e.code, url.split("?")[0]))
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        raise RuntimeError("cannot read %s: %s" % (url.split("?")[0], e))


_HOST_RX = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$")


def _check_host(host: str) -> str:
    h = (host or "").strip().lower()
    if not _HOST_RX.match(h):
        raise ValueError("--host must be a bare hostname such as data.example.gov, got %r" % host)
    return h


def _scan_row(service: str, scan_id: str, when: str, submitted: str, final: str | None) -> dict:
    urls = [u for u in (submitted, final) if u]
    if not urls:
        raise ValueError("%s result %s carries no URL" % (service, scan_id))
    classes = [classify_url(u) for u in urls]
    fams = sorted({f for c in classes for f in c.families})
    marker = next((c.marker for c in classes if c.marker), None)
    return {"service": service, "id": scan_id, "time": when, "submitted_url": submitted,
            "final_url": final or "-", "probe": any(c.is_probe for c in classes),
            "families": ",".join(fams) or "-", "marker": marker or "-"}


def search_urlscan(host: str, since: str | None = None, max_results: int = 1000,
                   fetch=http_get_json, page_size: int = 100) -> list[dict]:
    host = _check_host(host)
    since_dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc) if since else None
    headers = {}
    key = os.environ.get("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    rows: list[dict] = []
    search_after = None
    page_size = min(page_size, max_results)
    while len(rows) < max_results:
        params = {"q": "domain:%s" % host, "size": str(page_size)}
        if search_after:
            params["search_after"] = search_after
        data = fetch(URLSCAN_SEARCH + "?" + urllib.parse.urlencode(params), headers)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("urlscan response has no 'results' list; the API shape changed")
        results = data["results"]
        for r in results:
            try:
                task, page = r["task"], r.get("page") or {}
                when = task["time"]
                row = _scan_row("urlscan", r["_id"], when, task["url"], page.get("url"))
            except (KeyError, TypeError):
                raise ValueError("urlscan result missing task.url/task.time/_id; the API shape changed")
            if since_dt and datetime.fromisoformat(when.replace("Z", "+00:00")) < since_dt:
                continue
            rows.append(row)
        if len(results) < page_size or not results:
            break
        sort = results[-1].get("sort")
        if not sort:
            break
        search_after = ",".join(str(x) for x in sort)
    return rows[:max_results]


def search_urlquery(host: str, field_name: str = "domain", max_results: int = 1000,
                    fetch=http_get_json) -> list[dict]:
    host = _check_host(host)
    if field_name not in ("domain", "fqdn"):
        raise ValueError("--field must be domain or fqdn")
    key = os.environ.get("URLQUERY_API_KEY")
    if not key:
        raise RuntimeError("urlquery.net search requires an API key (x-apikey header; the endpoint "
                           "returns 401 without one). Set URLQUERY_API_KEY, or use --dataset or "
                           "--report to import files instead. Refusing to report a clean result.")
    rows: list[dict] = []
    offset, limit = 0, min(100, max_results)
    while len(rows) < max_results:
        params = {"query": "http.url.%s:%s" % (field_name, host), "limit": str(limit),
                  "offset": str(offset)}
        data = fetch(URLQUERY_SEARCH + "?" + urllib.parse.urlencode(params), {"x-apikey": key})
        if not isinstance(data, dict) or not isinstance(data.get("reports"), list):
            raise ValueError("urlquery response has no 'reports' list; the API shape changed")
        for r in data["reports"]:
            try:
                final = ((r.get("final") or {}).get("url") or {}).get("addr")
                rows.append(_scan_row("urlquery", r["report_id"], r["date"], r["url"]["addr"], final))
            except (KeyError, TypeError):
                raise ValueError("urlquery report missing report_id/date/url.addr; the API shape changed")
        if len(data["reports"]) < limit:
            break
        offset += limit
    return rows[:max_results]


def import_transluce_dataset(directory: str, host: str) -> list[dict]:
    """Rows from Transluce's dataset whose collection method names `host`. Listed, not classified:
    the dataset holds report links and labels, not submitted URLs."""
    host = _check_host(host)
    need = ["methods.json", "report-sources.csv", "all-reports.csv"]
    for n in need:
        if not os.path.isfile(os.path.join(directory, n)):
            raise FileNotFoundError("%s is not an unpacked Transluce dataset: %s missing" % (directory, n))
    with open(os.path.join(directory, "methods.json"), encoding="utf-8") as fh:
        methods = json.load(fh)
    if not isinstance(methods, list):
        raise ValueError("methods.json is not a list; dataset format changed")
    site = site_of(host)
    labels = set()
    for m in methods:
        hay = " ".join([str(m.get("query", ""))] + [str(x) for x in m.get("markers", [])]).lower()
        if host in hay or site in hay:
            if m.get("label"):
                labels.add(m["label"])
    ids: dict[str, str] = {}
    with open(os.path.join(directory, "report-sources.csv"), encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        if not {"report_id", "data_source", "matched_sources"} <= set(rd.fieldnames or []):
            raise ValueError("report-sources.csv columns changed")
        for r in rd:
            matched = {s.strip() for s in (r["matched_sources"] or "").split(";") if s.strip()}
            if r["data_source"] in labels or matched & labels:
                ids[r["report_id"]] = r["data_source"]
    rows = []
    with open(os.path.join(directory, "all-reports.csv"), encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        if not {"report_id", "report_url", "report_date_utc", "confidence", "broad_class"} <= set(rd.fieldnames or []):
            raise ValueError("all-reports.csv columns changed")
        for r in rd:
            if r["report_id"] in ids:
                rows.append({"service": "urlquery (Transluce dataset)", "id": r["report_id"],
                             "time": r["report_date_utc"], "data_source": ids[r["report_id"]],
                             "confidence": r["confidence"] or "-", "class": r["broad_class"],
                             "url": r["report_url"],
                             "note": "dataset has no submitted URL; open the report to classify"})
    return rows


def import_saved_reports(paths: list[str]) -> list[dict]:
    rows = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        submitted = final = None
        rid = os.path.basename(p)
        when = "-"
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict):
            try:
                submitted = doc["url"]["addr"]
            except (KeyError, TypeError):
                raise ValueError("%s: JSON report has no url.addr" % p)
            final = ((doc.get("final") or {}).get("url") or {}).get("addr")
            rid = doc.get("report_id", rid)
            when = doc.get("date", when)
        else:
            lines = [ln.strip() for ln in text.splitlines()]
            for i, ln in enumerate(lines[:-1]):
                nxt = next((x for x in lines[i + 1:] if x), None)
                if ln == "URL" and submitted is None:
                    submitted = nxt
                elif ln == "Finishing URL" and final is None:
                    final = nxt
            if not submitted:
                raise ValueError("%s: no 'URL' line found; not a saved urlquery report" % p)
        rows.append(_scan_row("urlquery (saved report)", rid, when, submitted, final))
    return rows


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------

def _emit(rows: list[dict], as_json: bool) -> None:
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    for r in rows:
        print("  ".join("%s=%s" % (k, v) for k, v in r.items()))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("urlscan", help="search urlscan.io public scans for a host")
    p.add_argument("--host", required=True)
    p.add_argument("--since", help="YYYY-MM-DD, filters on scan time")
    p.add_argument("--max", type=int, default=1000)

    p = sub.add_parser("urlquery", help="urlquery.net: API search (key), Transluce dataset, or saved reports")
    p.add_argument("--host")
    p.add_argument("--field", default="domain", choices=["domain", "fqdn"])
    p.add_argument("--max", type=int, default=1000)
    p.add_argument("--dataset", help="unpacked Transluce urlquery-agent-activity dataset directory")
    p.add_argument("--report", nargs="+", help="saved urlquery report files (JSON or page text)")

    p = sub.add_parser("logs", help="access log: probes, escalation after refusal, non-prod fallback")
    p.add_argument("file")
    p.add_argument("--window", type=int, default=600)
    p.add_argument("--scope", default="path", choices=["path", "host"])
    p.add_argument("--nonprod-window", type=int, default=3600)

    p = sub.add_parser("classify", help="probe-grammar classifier")
    p.add_argument("urls", nargs="+")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "classify":
            rows = []
            for u in args.urls:
                c = classify_url(u)
                rows.append({"url": u, "probe": c.is_probe, "families": ",".join(c.families) or "-",
                             "marker": c.marker or "-"})
            _emit(rows, args.json)
            flagged = [r for r in rows if r["probe"]]
            print("# %d of %d URL(s) carry probe grammar" % (len(flagged), len(rows)), file=sys.stderr)
            return 1 if flagged else 0
        if args.cmd == "urlscan":
            rows = search_urlscan(args.host, args.since, args.max)
            _emit(rows, args.json)
            flagged = [r for r in rows if r["probe"]]
            print("# urlscan.io: %d public scan(s) of %s, %d carrying probe grammar. Private scans "
                  "are not visible; quiet is not clean." % (len(rows), args.host, len(flagged)),
                  file=sys.stderr)
            return 1 if flagged else 0
        if args.cmd == "urlquery":
            modes = [bool(args.dataset), bool(args.report)]
            if sum(modes) > 1:
                ap.error("choose one of: --host (API), --dataset with --host, or --report")
            if args.report:
                rows = import_saved_reports(args.report)
                _emit(rows, args.json)
                flagged = [r for r in rows if r["probe"]]
                print("# %d saved report(s), %d carrying probe grammar" % (len(rows), len(flagged)),
                      file=sys.stderr)
                return 1 if flagged else 0
            if not args.host:
                ap.error("--host is required for API search and --dataset import")
            if args.dataset:
                rows = import_transluce_dataset(args.dataset, args.host)
                _emit(rows, args.json)
                print("# Transluce dataset: %d report(s) whose collection method names %s. Listed, "
                      "not classified: the dataset carries no submitted URLs." % (len(rows), args.host),
                      file=sys.stderr)
                return 1 if rows else 0
            rows = search_urlquery(args.host, args.field, args.max)
            _emit(rows, args.json)
            flagged = [r for r in rows if r["probe"]]
            print("# urlquery.net: %d public report(s) for %s, %d carrying probe grammar. Private "
                  "scans are not visible; quiet is not clean." % (len(rows), args.host, len(flagged)),
                  file=sys.stderr)
            return 1 if flagged else 0
        if args.cmd == "logs":
            events, total, bad = parse_log(args.file)
            probes = find_probes(events)
            esc = find_escalations(events, args.window, args.scope)
            nonprod = find_nonprod_fallback(events, args.nonprod_window)
            rows = esc + (nonprod or []) + probes
            _emit(rows, args.json)
            print("# %d line(s), %d parsed, %d UNPARSEABLE" % (total, len(events), bad), file=sys.stderr)
            print("# %d escalation(s) after refusal (window %ds, scope %s), %d probe request(s)"
                  % (len(esc), args.window, args.scope, len(probes)), file=sys.stderr)
            if nonprod is None:
                print("# non-prod fallback: COULD NOT RUN, no line carries a virtual host "
                      "(use vhost_combined format)", file=sys.stderr)
            else:
                print("# %d non-prod fallback(s) (window %ds)" % (len(nonprod), args.nonprod_window),
                      file=sys.stderr)
            return 1 if rows else 0
    except (OSError, ValueError, RuntimeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
