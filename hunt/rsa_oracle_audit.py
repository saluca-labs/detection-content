#!/usr/bin/env python3
"""rsa_oracle_audit - find and watch raw RSA signing oracles (ePrint 2026/2131).

READ-ONLY. This tool never signs, never decrypts, never generates a query, and never modifies a
key or a policy. It inventories where raw RSA exists, audits what HSM keys are allowed to do, and
reconciles records you already have. It does not assist in carrying out the attack.

Four subcommands, in the order a defender needs them:

  scan-code PATH...
      Inventory raw (unpadded) RSA private-key operations in source trees. Stdlib regex, for
      estates without Semgrep; the Semgrep rules in the campaign pack are more precise.

  pkcs11 --module LIB [--token-label L] [--pin-env VAR]
      Audit every RSA private key on a PKCS#11 token: is it allowed to perform CKM_RSA_X_509?
      A key with NO CKA_ALLOWED_MECHANISMS restriction is reported too, because unset means the
      token decides, and on many tokens that means every mechanism. Needs `pip install
      python-pkcs11`. The PIN is read from an environment variable, never from the command line.

  reconcile --ledger CSV --observed CSV     (signatures)
  reconcile --tokens CSV                    (blind-RSA token issuers)
      The detection that still works after the attacker has left. A signature that verifies under
      your key and is not in your signing ledger was not produced by your signer. For token
      issuers: per key, distinct redemptions must never exceed issuances.

  shape --modulus-bits N --inputs FILE [--expect-padding SCHEME]
      Check raw-operation inputs. Short inputs are the attack as published (small primes and
      values far below the modulus). THIS IS A TRIPWIRE: blinding with the public key defeats it.
      With --expect-padding it performs the structural check a padding-enforcement gate would
      apply, which blinding does NOT defeat, because a blinded value will not carry your padding.

Exit status: 0 nothing found, 1 findings, 2 usage or input error. "Cannot tell" is an error,
never a pass: an unreadable file, an unparseable row, or a missing column exits 2.

Author: Cristian Ruvalcaba and the Saluca Agentic AI Research Team, 2026-09-26
Apache-2.0. Defensive use only.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass

# ---------------------------------------------------------------------------------------------
# scan-code
# ---------------------------------------------------------------------------------------------

@dataclass
class CodeHit:
    path: str
    line: int
    rule: str
    text: str


CODE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("java-cipher-nopadding", re.compile(r'Cipher\.getInstance\(\s*"RSA/[A-Za-z0-9]+/NoPadding"', re.I)),
    ("android-padding-none", re.compile(r"ENCRYPTION_PADDING_NONE")),
    ("openssl-private-no-padding", re.compile(r"RSA_private_(?:de|en)crypt\s*\([^;]*RSA_NO_PADDING")),
    ("openssl-evp-no-padding", re.compile(r"EVP_PKEY_CTX_set_rsa_padding\s*\([^;]*RSA_NO_PADDING")),
    ("pkcs11-ckm-rsa-x-509", re.compile(r"\bCKM_RSA_X_509\b|Mechanism\.RSA_X_509\b")),
    ("python-pow-private-exponent", re.compile(r"\b(?:pow|powmod)\s*\(.*\.d\s*,")),
    ("pycryptodome-private-primitive", re.compile(r"\._decrypt(?:_to_bytes)?\s*\(")),
    ("go-bigint-private-exponent", re.compile(r"\.Exp\([^)]*\.D\s*,")),
    ("node-private-no-padding", re.compile(r"private(?:De|En)crypt\s*\([^;]*RSA_NO_PADDING")),
    ("cli-openssl-raw", re.compile(r"rsautl[^\n]*-raw|rsa_padding_mode:none")),
    ("cli-pkcs11-tool-raw", re.compile(r"pkcs11-tool[^\n]*RSA-X-509")),
    ("blind-rsa-library", re.compile(r"blindrsa|blind_rsa_signatures|blind-rsa-signatures|rsabssa", re.I)),
]

CODE_EXTS = {".py", ".java", ".kt", ".go", ".c", ".h", ".cc", ".cpp", ".hpp", ".js", ".ts",
             ".rs", ".sh", ".ps1", ".toml", ".mod", ".txt", ".json", ".yml", ".yaml"}
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build"}


def _walk(root: str):
    if os.path.isfile(root):
        yield root
        return
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            yield os.path.join(d, f)


def scan_code(paths: list[str]) -> list[CodeHit]:
    hits: list[CodeHit] = []
    for root in paths:
        if not os.path.exists(root):
            raise FileNotFoundError(root)
        for path in _walk(root):
            if os.path.splitext(path)[1].lower() not in CODE_EXTS:
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for n, line in enumerate(fh, 1):
                        for rule, rx in CODE_PATTERNS:
                            if rx.search(line):
                                hits.append(CodeHit(path, n, rule, line.strip()[:200]))
            except OSError as e:
                raise OSError("cannot read %s: %s" % (path, e))
    return hits


# ---------------------------------------------------------------------------------------------
# pkcs11
# ---------------------------------------------------------------------------------------------

@dataclass
class KeyFinding:
    token: str
    label: str
    key_id: str
    bits: int | None
    can_sign: bool | None
    can_decrypt: bool | None
    allowed_mechanisms: list[str] | None
    finding: str


def audit_pkcs11(module: str, token_label: str | None, pin: str | None) -> list[KeyFinding]:
    try:
        import pkcs11
        from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism
        from pkcs11.exceptions import AttributeTypeInvalid, AttributeSensitive
    except ImportError:
        raise RuntimeError("pkcs11 mode needs python-pkcs11: pip install python-pkcs11")

    # python-pkcs11 ships no handler for CKA_ALLOWED_MECHANISMS (found 2026-09-26: reading it
    # raises NotImplementedError "Can't handle attribute type 0x40000600"), which is the one
    # attribute this audit exists to read. It is an array of CK_ULONG, and CK_ULONG is C
    # `unsigned long` on every platform PKCS#11 defines, which is exactly struct's native 'L'.
    import struct

    def pack_mechs(values):
        return struct.pack("%dL" % len(values), *[int(v) for v in values])

    def unpack_mechs(raw):
        n = len(raw) // struct.calcsize("L")
        out = []
        for v in struct.unpack("%dL" % n, raw[: n * struct.calcsize("L")]):
            try:
                out.append(Mechanism(v))
            except ValueError:
                out.append(v)  # vendor-defined mechanism: keep the number, never drop it
        return tuple(out)

    open_kwargs = {}
    try:
        from pkcs11.attributes import AttributeMapper
        mapper = AttributeMapper()
        mapper.register_handler(Attribute.ALLOWED_MECHANISMS, pack_mechs, unpack_mechs)
        open_kwargs["attribute_mapper"] = mapper
    except ImportError:
        # python-pkcs11 < 0.8 keeps its handlers in a module-level table instead.
        import pkcs11.attributes as pa
        pa.ATTRIBUTE_TYPES[Attribute.ALLOWED_MECHANISMS] = (pack_mechs, unpack_mechs)

    lib = pkcs11.lib(module)
    tokens = list(lib.get_tokens(token_label=token_label) if token_label else lib.get_tokens())
    if not tokens:
        raise RuntimeError("no tokens found%s" % (" with label %r" % token_label if token_label else ""))

    def attr(obj, a):
        try:
            return obj[a]
        except (AttributeTypeInvalid, AttributeSensitive, KeyError):
            return None

    out: list[KeyFinding] = []
    for tok in tokens:
        # Read-only session. user_pin is needed because private key objects are private objects.
        with tok.open(user_pin=pin, **open_kwargs) as session:
            for key in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                            Attribute.KEY_TYPE: KeyType.RSA}):
                label = attr(key, Attribute.LABEL) or ""
                kid = attr(key, Attribute.ID)
                kid = kid.hex() if isinstance(kid, (bytes, bytearray)) else str(kid or "")
                modulus = attr(key, Attribute.MODULUS)
                bits = len(modulus) * 8 if modulus else None
                can_sign = attr(key, Attribute.SIGN)
                can_decrypt = attr(key, Attribute.DECRYPT)
                allowed = attr(key, Attribute.ALLOWED_MECHANISMS)
                names = None
                if allowed is not None:
                    names = [m.name if isinstance(m, Mechanism) else str(m) for m in allowed]
                usable = bool(can_sign) or bool(can_decrypt)
                if not usable:
                    finding = "ok: key cannot sign or decrypt"
                elif allowed is None or len(allowed) == 0:
                    finding = ("UNRESTRICTED: no CKA_ALLOWED_MECHANISMS; raw RSA is permitted if the "
                               "token supports it. Restrict to the padded mechanism you use.")
                elif Mechanism.RSA_X_509 in allowed:
                    finding = ("RAW RSA PERMITTED: CKM_RSA_X_509 is in CKA_ALLOWED_MECHANISMS. "
                               "Justify it (software padding or blind signing), count its operations, "
                               "and set a rotation budget.")
                else:
                    finding = "ok: restricted to padded mechanisms"
                if bits is not None and bits < 2048 and not finding.startswith("ok: key cannot"):
                    finding += " KEY UNDER 2048 BITS."
                out.append(KeyFinding(tok.label.strip(), label, kid, bits, can_sign, can_decrypt,
                                      names, finding))
    return out


# ---------------------------------------------------------------------------------------------
# reconcile
# ---------------------------------------------------------------------------------------------

def _rows(path: str, required: set[str]) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("%s is missing column(s): %s" % (path, ", ".join(sorted(missing))))
        rows = list(reader)
    for i, r in enumerate(rows, 2):
        for c in required:
            if not (r.get(c) or "").strip():
                raise ValueError("%s line %d has an empty %s" % (path, i, c))
    return rows


def reconcile_signatures(ledger: str, observed: str) -> list[dict]:
    """Observed signatures (key_label, sig_sha256) absent from the ledger (key_label, sig_sha256)."""
    signed = {(r["key_label"].strip(), r["sig_sha256"].strip().lower())
              for r in _rows(ledger, {"key_label", "sig_sha256"})}
    seen: dict[tuple[str, str], int] = defaultdict(int)
    for r in _rows(observed, {"key_label", "sig_sha256"}):
        seen[(r["key_label"].strip(), r["sig_sha256"].strip().lower())] += 1
    return [{"key_label": k, "sig_sha256": s, "times_seen": n,
             "finding": "verifies under this key but is NOT in the signing ledger"}
            for (k, s), n in sorted(seen.items()) if (k, s) not in signed]


def reconcile_tokens(tokens: str) -> list[dict]:
    """Per key: distinct redeemed token ids must not exceed issuance count."""
    issued: dict[str, int] = defaultdict(int)
    redeemed: dict[str, set] = defaultdict(set)
    for r in _rows(tokens, {"event_type", "key_label", "token_id"}):
        et = r["event_type"].strip().lower()
        if et == "issue":
            issued[r["key_label"].strip()] += 1
        elif et == "redeem":
            redeemed[r["key_label"].strip()].add(r["token_id"].strip())
        else:
            raise ValueError("unknown event_type %r (expected issue or redeem)" % r["event_type"])
    out = []
    for k in sorted(set(issued) | set(redeemed)):
        surplus = len(redeemed[k]) - issued[k]
        if surplus > 0:
            out.append({"key_label": k, "issued": issued[k], "redeemed_distinct": len(redeemed[k]),
                        "surplus": surplus,
                        "finding": "REDEMPTIONS EXCEED ISSUANCE: forgery, or a gap in the issuance log"})
    return out


# ---------------------------------------------------------------------------------------------
# shape
# ---------------------------------------------------------------------------------------------

def _parse_input(tok: str) -> int:
    tok = tok.strip()
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    if re.fullmatch(r"[0-9a-fA-F]+", tok) and re.search(r"[a-fA-F]", tok):
        return int(tok, 16)
    return int(tok, 10)


def padding_ok(value: int, k_bytes: int, scheme: str) -> bool:
    """Necessary structural conditions for a padded encoded message of k_bytes. Not a full
    verification of the scheme: it is the cheap check a gate in front of a raw RSA call can apply
    to refuse inputs that could not have come from your own padding code."""
    if value < 0 or value.bit_length() > k_bytes * 8:
        return False
    em = value.to_bytes(k_bytes, "big")
    if scheme == "pkcs1v15-sign":
        # EM = 0x00 || 0x01 || PS (>= 8 bytes of 0xFF) || 0x00 || T     (RFC 8017 section 9.2)
        if em[0] != 0x00 or em[1] != 0x01:
            return False
        i = 2
        while i < len(em) and em[i] == 0xFF:
            i += 1
        return (i - 2) >= 8 and i < len(em) and em[i] == 0x00
    if scheme == "iso9796-2":
        # Leading bits 01 in the most significant byte; trailer 0xBC (implicit hash) or 0x..CC.
        return (em[0] >> 6) == 0b01 and (em[-1] == 0xBC or em[-1] == 0xCC)
    if scheme == "x931":
        # Header nibble 0x6 (0x6A or 0x6B), trailer ends 0xCC.
        return (em[0] >> 4) == 0x6 and em[-1] == 0xCC
    raise ValueError("unknown padding scheme %r" % scheme)


def shape(modulus_bits: int, inputs_file: str, expect_padding: str | None,
          short_margin: int = 64) -> tuple[list[dict], int]:
    k_bytes = (modulus_bits + 7) // 8
    findings, total = [], 0
    with open(inputs_file, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            total += 1
            try:
                v = _parse_input(line)
            except ValueError:
                raise ValueError("%s line %d is not an integer (decimal or hex)" % (inputs_file, n))
            reasons = []
            if v.bit_length() <= modulus_bits - short_margin:
                reasons.append("short input: %d bits against a %d-bit modulus" % (v.bit_length(), modulus_bits))
            if expect_padding and not padding_ok(v, k_bytes, expect_padding):
                reasons.append("does not carry %s structure" % expect_padding)
            if reasons:
                findings.append({"line": n, "bits": v.bit_length(), "finding": "; ".join(reasons)})
    if total == 0:
        raise ValueError("%s contains no inputs; refusing to report a pass on nothing" % inputs_file)
    return findings, total


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------

def _emit(rows: list, as_json: bool) -> None:
    rows = [asdict(r) if hasattr(r, "__dataclass_fields__") else r for r in rows]
    if as_json:
        print(json.dumps(rows, indent=2))
        return
    for r in rows:
        print("  ".join("%s=%s" % (k, v) for k, v in r.items()))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan-code", help="inventory raw RSA in source trees")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("pkcs11", help="audit RSA key mechanism policy on a PKCS#11 token")
    p.add_argument("--module", required=True, help="path to the PKCS#11 library")
    p.add_argument("--token-label")
    p.add_argument("--pin-env", default="PKCS11_PIN",
                   help="environment variable holding the user PIN (default PKCS11_PIN)")

    p = sub.add_parser("reconcile", help="ledger vs observed signatures, or token issuance vs redemption")
    p.add_argument("--ledger")
    p.add_argument("--observed")
    p.add_argument("--tokens")

    p = sub.add_parser("shape", help="raw-operation input tripwire and padding gate check")
    p.add_argument("--modulus-bits", type=int, required=True)
    p.add_argument("--inputs", required=True, help="one integer per line, decimal or 0x-hex")
    p.add_argument("--expect-padding", choices=["pkcs1v15-sign", "iso9796-2", "x931"])
    p.add_argument("--short-margin", type=int, default=64)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "scan-code":
            rows = scan_code(args.paths)
            _emit(rows, args.json)
            print("# %d raw-RSA site(s)" % len(rows), file=sys.stderr)
        elif args.cmd == "pkcs11":
            rows = audit_pkcs11(args.module, args.token_label, os.environ.get(args.pin_env))
            _emit(rows, args.json)
            flagged = [r for r in rows if not r.finding.startswith("ok")]
            print("# %d RSA private key(s), %d flagged" % (len(rows), len(flagged)), file=sys.stderr)
            rows = flagged
        elif args.cmd == "reconcile":
            if args.tokens and not (args.ledger or args.observed):
                rows = reconcile_tokens(args.tokens)
            elif args.ledger and args.observed and not args.tokens:
                rows = reconcile_signatures(args.ledger, args.observed)
            else:
                ap.error("reconcile needs either --ledger and --observed, or --tokens")
            _emit(rows, args.json)
            print("# %d finding(s)" % len(rows), file=sys.stderr)
        elif args.cmd == "shape":
            rows, total = shape(args.modulus_bits, args.inputs, args.expect_padding, args.short_margin)
            _emit(rows, args.json)
            print("# %d of %d input(s) flagged%s" % (
                len(rows), total,
                "" if args.expect_padding else " (tripwire only: blinding defeats this; use --expect-padding for the gate check)"),
                file=sys.stderr)
    except (OSError, ValueError, RuntimeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    return 1 if rows else 0


if __name__ == "__main__":
    sys.exit(main())
