#!/usr/bin/env python3
"""Create a Zenodo DRAFT deposition for a campaign analysis, and stop.

WORKFLOW.md has referenced this script since the repository was consolidated, but it did not
exist: each campaign so far grew its own copy in its own working directory, with two
different token conventions between them. That is open item 2 in the research-to-detection
paper runbook. This is the shared one.

  python tools/zenodo_deposit.py 2026-09-agent-collusion
  python tools/zenodo_deposit.py 2026-09-agent-collusion --no-archive
  python tools/zenodo_deposit.py 2026-09-agent-collusion --deposition 1234567   # update

What it does:
  1. reads campaigns/<slug>/.zenodo.json as the metadata source of truth
  2. creates a deposition, letting Zenodo reserve the DOI (never supplies its own)
  3. uploads the paper PDF, the paper markdown, and a source archive of the repository
  4. sets metadata using ONLY writable fields
  5. prints the reserved DOI and the edit URL, and STOPS

IT NEVER PUBLISHES. A DOI is permanent and publishing is a human action. There is no flag
to publish and adding one would be a mistake.

Conventions this encodes, each of which has cost someone an hour at least once:
  - Authorization: Bearer header, never the access_token URL parameter, which leaks the
    token into tracebacks and shell history.
  - communities uses the key "identifier", not "id". Using "id" returns a 400.
  - On update, send only writable fields. Echoing a GET response back verbatim includes
    read-only keys such as prereserve_doi and returns a 400.
  - The .env is read with a native Windows path. A git-bash /c/... path raises
    FileNotFoundError under Windows Python because it cannot resolve MSYS mounts.
  - A bucket PUT with the same filename OVERWRITES. That is how you replace a file and how
    you destroy one by accident.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://zenodo.org/api"
ENV_PATH = r"C:\AI\daily-brief\.env"

WRITABLE = {
    "upload_type", "publication_type", "access_right", "license", "title", "creators",
    "description", "keywords", "related_identifiers", "notes", "communities", "version",
    "publication_date", "language", "subjects", "contributors", "references",
}


def token() -> str:
    tok = os.environ.get("ZENODO_API_TOKEN")
    if tok:
        return tok.strip()
    try:
        env = open(ENV_PATH, encoding="utf-8").read()
    except FileNotFoundError:
        sys.exit("no ZENODO_API_TOKEN in the environment and %s is not readable" % ENV_PATH)
    m = re.search(r'^\s*ZENODO_API_TOKEN\s*=\s*"?([^"\r\n]+)"?', env, re.M)
    if not m:
        sys.exit("ZENODO_API_TOKEN not found in %s" % ENV_PATH)
    return m.group(1).strip()


def call(method: str, url: str, tok: str, payload=None, raw: bytes | None = None):
    headers = {"Authorization": "Bearer " + tok, "User-Agent": "saluca-detection-content"}
    data = raw
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    elif raw is not None:
        headers["Content-Type"] = "application/octet-stream"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            body = r.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:1200]
        sys.exit("%s %s -> HTTP %s\n%s" % (method, url.split("?")[0], e.code, detail))


def source_archive(slug: str) -> str | None:
    """git archive of HEAD. Named for the campaign so the deposit says what it contains."""
    out = os.path.join(ROOT, "detection-content-%s-source.zip" % slug)
    try:
        subprocess.run(
            ["git", "-C", ROOT, "archive", "--format=zip",
             "--prefix=detection-content-%s/" % slug, "-o", out, "HEAD"],
            check=True, capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print("  ! source archive skipped: %s" % exc)
        return None
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("slug", help="campaign directory name under campaigns/")
    ap.add_argument("--deposition", help="update an existing draft instead of creating one")
    ap.add_argument("--no-archive", action="store_true", help="skip the source zip")
    args = ap.parse_args(argv)

    camp = os.path.join(ROOT, "campaigns", args.slug)
    meta_path = os.path.join(camp, ".zenodo.json")
    if not os.path.isfile(meta_path):
        sys.exit("no .zenodo.json in %s" % camp)
    metadata = json.load(open(meta_path, encoding="utf-8"))
    metadata = {k: v for k, v in metadata.items() if k in WRITABLE}

    if "doi" in metadata:
        sys.exit("refusing to run: .zenodo.json supplies its own doi, which suppresses the "
                 "reserved DOI. Remove it.")
    comms = metadata.get("communities") or []
    if any("identifier" not in c for c in comms):
        sys.exit("communities entries must use the key 'identifier', not 'id'")

    tok = token()

    if args.deposition:
        dep = call("GET", "%s/deposit/depositions/%s" % (API, args.deposition), tok)
        print("updating existing draft %s" % args.deposition)
    else:
        dep = call("POST", "%s/deposit/depositions" % API, tok, payload={})
        print("created deposition %s" % dep["id"])

    if dep.get("state") == "done" or dep.get("submitted"):
        sys.exit("deposition %s is already published. This script does not modify published "
                 "records; Zenodo records are immutable and that is the point." % dep["id"])

    files = []
    for name in sorted(os.listdir(camp)):
        if name.endswith(".pdf") or (name.endswith(".md") and name != "README.md"):
            files.append(os.path.join(camp, name))
    archive = None
    if not args.no_archive:
        archive = source_archive(args.slug)
        if archive:
            files.append(archive)
    if not files:
        sys.exit("no paper files found in %s" % camp)

    bucket = dep["links"]["bucket"]
    for path in files:
        name = os.path.basename(path)
        with open(path, "rb") as fh:
            call("PUT", "%s/%s" % (bucket, name), tok, raw=fh.read())
        print("  uploaded %s (%d KB)" % (name, os.path.getsize(path) // 1024))
    if archive:
        os.remove(archive)

    dep = call("PUT", "%s/deposit/depositions/%s" % (API, dep["id"]), tok,
               payload={"metadata": metadata})

    m = dep.get("metadata", {})
    doi = (m.get("prereserve_doi") or {}).get("doi") or dep.get("doi") or "(not reserved)"
    print("")
    print("  reserved DOI : %s" % doi)
    print("  communities  : %s" % ", ".join(c["identifier"] for c in m.get("communities", [])))
    print("  files        : %s" % ", ".join(f["filename"] for f in dep.get("files", [])))
    print("  state        : %s" % dep.get("state"))
    print("  edit         : https://zenodo.org/deposit/%s" % dep["id"])
    print("")
    print("NOT PUBLISHED. Cristian publishes manually.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
