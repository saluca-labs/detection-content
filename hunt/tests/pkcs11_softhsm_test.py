#!/usr/bin/env python3
"""Integration test: run `rsa_oracle_audit.py pkcs11` against a REAL PKCS#11 token (SoftHSM2).

Builds a throwaway container, creates a SoftHSM2 token, and provisions four RSA keys whose
mechanism policy is known in advance:

  pss-only        CKA_ALLOWED_MECHANISMS = [CKM_RSA_PKCS_PSS]     -> ok
  raw-allowed     CKA_ALLOWED_MECHANISMS = [CKM_RSA_X_509]        -> RAW RSA PERMITTED
  unrestricted    no CKA_ALLOWED_MECHANISMS                       -> UNRESTRICTED
  raw-1024        CKA_ALLOWED_MECHANISMS = [CKM_RSA_X_509], 1024  -> RAW RSA PERMITTED + UNDER 2048

then runs the audit and requires exactly those verdicts. Key provisioning happens in this test
harness, never in the audit tool, which stays read-only (see test_source_is_read_only).

Needs Docker. Nothing touches the host beyond a read-only bind mount of hunt/.

  python hunt/tests/pkcs11_softhsm_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HUNT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INNER = r'''
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq softhsm2 >/dev/null
pip install -q python-pkcs11 >/dev/null 2>&1
MOD=/usr/lib/softhsm/libsofthsm2.so
mkdir -p /tmp/tokens
printf 'directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > /tmp/softhsm2.conf
export SOFTHSM2_CONF=/tmp/softhsm2.conf
softhsm2-util --init-token --free --label audit-test --so-pin 1234 --pin 5678 >/dev/null
python - <<'PY'
import struct
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.attributes import AttributeMapper
m = AttributeMapper()
m.register_handler(Attribute.ALLOWED_MECHANISMS,
                   lambda v: struct.pack("%dL" % len(v), *[int(x) for x in v]),
                   lambda b: struct.unpack("%dL" % (len(b) // struct.calcsize("L")), b))
lib = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so")
tok = lib.get_token(token_label="audit-test")
with tok.open(user_pin="5678", rw=True, attribute_mapper=m) as s:
    def mk(label, bits, allowed):
        priv = {Attribute.SIGN: True, Attribute.DECRYPT: True, Attribute.PRIVATE: True,
                Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False}
        if allowed is not None:
            priv[Attribute.ALLOWED_MECHANISMS] = allowed
        s.generate_keypair(KeyType.RSA, bits, label=label, id=label.encode(), store=True,
                           private_template=priv)
    mk("pss-only", 2048, [Mechanism.RSA_PKCS_PSS])
    mk("raw-allowed", 2048, [Mechanism.RSA_X_509])
    mk("unrestricted", 2048, None)
    mk("raw-1024", 1024, [Mechanism.RSA_X_509])
    # Does the restriction actually close the oracle on this token? One raw operation per key,
    # in the HARNESS (never in the audit tool). The PSS-only key must refuse it.
    from pkcs11 import ObjectClass
    for label in ("pss-only", "raw-allowed"):
        key = s.get_key(object_class=ObjectClass.PRIVATE_KEY, label=label)
        try:
            key.sign(b"\x00" * 255 + b"\x02", mechanism=Mechanism.RSA_X_509)
            print("ENFORCE %s raw-sign=ALLOWED" % label)
        except pkcs11.exceptions.PKCS11Error as e:
            print("ENFORCE %s raw-sign=REFUSED (%s)" % (label, type(e).__name__))
PY
export PKCS11_PIN=5678
set +e
python /hunt/rsa_oracle_audit.py --json pkcs11 --module "$MOD" --token-label audit-test
echo "AUDIT_EXIT=$?"
'''

EXPECT = {
    "pss-only": ("ok: restricted", False),
    "raw-allowed": ("RAW RSA PERMITTED", False),
    "unrestricted": ("UNRESTRICTED", False),
    "raw-1024": ("RAW RSA PERMITTED", True),
}


def main() -> int:
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    # Bytes, not text: in text mode Windows rewrites \n as \r\n on the way into the container and
    # bash then fails on every line.
    proc = subprocess.run(
        ["docker", "run", "--rm", "-i", "-e", "DEBIAN_FRONTEND=noninteractive",
         "-v", "%s:/hunt:ro" % HUNT, "python:3.12-slim", "bash", "-s"],
        input=INNER.encode("utf-8"), capture_output=True, env=env)
    out = proc.stdout.decode("utf-8", "replace")
    proc_err = proc.stderr.decode("utf-8", "replace")
    if "AUDIT_EXIT=" not in out:
        sys.stderr.write(proc_err[-4000:])
        raise SystemExit("container setup failed before the audit ran")
    body, _, tail = out.rpartition("AUDIT_EXIT=")
    code = int(tail.strip().splitlines()[0])
    if "[" not in body:
        sys.stderr.write(proc_err[-4000:])
        raise SystemExit("audit produced no JSON (exit %d); see stderr above" % code)
    rows = json.loads(body[body.index("["):])
    by_label = {r["label"]: r for r in rows}

    failures = []
    if set(by_label) != set(EXPECT):
        failures.append("keys found %s, expected %s" % (sorted(by_label), sorted(EXPECT)))
    for label, (prefix, small) in EXPECT.items():
        r = by_label.get(label)
        if not r:
            continue
        if not r["finding"].startswith(prefix):
            failures.append("%s: got %r, expected to start with %r" % (label, r["finding"], prefix))
        if small != ("UNDER 2048" in r["finding"]):
            failures.append("%s: key-size flag wrong in %r" % (label, r["finding"]))
        print("%-13s bits=%-5s allowed=%-28s %s" % (label, r["bits"], r["allowed_mechanisms"], r["finding"][:60]))
    if "ENFORCE pss-only raw-sign=REFUSED" not in out:
        failures.append("SoftHSM2 did not refuse a raw operation on the PSS-only key")
    if "ENFORCE raw-allowed raw-sign=ALLOWED" not in out:
        failures.append("raw operation on the raw-allowed key did not succeed (control check is not proving anything)")
    for line in out.splitlines():
        if line.startswith("ENFORCE"):
            print(line)
    if code != 1:
        failures.append("audit exit %d, expected 1 (findings present)" % code)
    for f in failures:
        print("FAIL", f)
    print("pkcs11 audit against SoftHSM2: %s" % ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
