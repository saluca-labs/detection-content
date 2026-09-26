#!/usr/bin/env python3
"""Unit tests for hunt/rsa_oracle_audit.py. Stdlib only.

  python -m unittest hunt/tests/test_rsa_oracle_audit.py -v

Every check is tested in both directions: it must fire on the bad case AND stay quiet on the good
one, so a check that always passes or always fails cannot hide here. "Cannot tell" inputs (empty
files, missing columns, unknown values) must raise, not pass.
"""
from __future__ import annotations

import csv
import os
import random
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import rsa_oracle_audit as audit  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "semgrep")


def _csv(rows: list[dict], cols: list[str]) -> str:
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    return path


def _lines(values: list) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for v in values:
            fh.write("%s\n" % v)
    return path


def pkcs1v15_em(k: int, t: bytes) -> int:
    ps = b"\xff" * (k - len(t) - 3)
    return int.from_bytes(b"\x00\x01" + ps + b"\x00" + t, "big")


class ScanCode(unittest.TestCase):
    def test_every_expected_fixture_line_is_found_and_no_other(self):
        expected = set()
        for name in os.listdir(FIXTURES):
            with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if "EXPECT:" in line:
                        expected.add((name, n))
        self.assertGreater(len(expected), 10, "fixtures lost their annotations")
        got = {(os.path.basename(h.path), h.line) for h in audit.scan_code([FIXTURES])}
        self.assertEqual(expected - got, set(), "positive fixture lines missed")
        self.assertEqual(got - expected, set(), "negative fixture lines flagged")

    def test_missing_path_is_an_error_not_a_clean_result(self):
        with self.assertRaises(FileNotFoundError):
            audit.scan_code([os.path.join(HERE, "does-not-exist")])


class ReconcileSignatures(unittest.TestCase):
    cols = ["key_label", "sig_sha256"]

    def test_signature_absent_from_ledger_is_flagged(self):
        ledger = _csv([{"key_label": "k1", "sig_sha256": "aa"}, {"key_label": "k1", "sig_sha256": "bb"}], self.cols)
        observed = _csv([{"key_label": "k1", "sig_sha256": "AA"}, {"key_label": "k1", "sig_sha256": "bb"},
                         {"key_label": "k1", "sig_sha256": "cc"}, {"key_label": "k1", "sig_sha256": "cc"}], self.cols)
        out = audit.reconcile_signatures(ledger, observed)
        self.assertEqual([(r["sig_sha256"], r["times_seen"]) for r in out], [("cc", 2)])

    def test_fully_ledgered_is_quiet(self):
        ledger = _csv([{"key_label": "k1", "sig_sha256": "aa"}], self.cols)
        observed = _csv([{"key_label": "k1", "sig_sha256": "aa"}], self.cols)
        self.assertEqual(audit.reconcile_signatures(ledger, observed), [])

    def test_same_signature_under_another_key_is_not_ledgered(self):
        ledger = _csv([{"key_label": "k1", "sig_sha256": "aa"}], self.cols)
        observed = _csv([{"key_label": "k2", "sig_sha256": "aa"}], self.cols)
        self.assertEqual(len(audit.reconcile_signatures(ledger, observed)), 1)

    def test_missing_column_is_an_error(self):
        ledger = _csv([{"key_label": "k1"}], ["key_label"])
        observed = _csv([{"key_label": "k1", "sig_sha256": "aa"}], self.cols)
        with self.assertRaises(ValueError):
            audit.reconcile_signatures(ledger, observed)

    def test_empty_value_is_an_error(self):
        ledger = _csv([{"key_label": "k1", "sig_sha256": ""}], self.cols)
        observed = _csv([{"key_label": "k1", "sig_sha256": "aa"}], self.cols)
        with self.assertRaises(ValueError):
            audit.reconcile_signatures(ledger, observed)


class ReconcileTokens(unittest.TestCase):
    cols = ["event_type", "key_label", "token_id"]

    def test_redemption_surplus_is_flagged(self):
        rows = [{"event_type": "issue", "key_label": "k", "token_id": "-"}] * 2 + [
            {"event_type": "redeem", "key_label": "k", "token_id": t} for t in ("t1", "t2", "t3", "t3")]
        out = audit.reconcile_tokens(_csv(rows, self.cols))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["surplus"], 1)

    def test_balanced_is_quiet(self):
        rows = [{"event_type": "issue", "key_label": "k", "token_id": "-"}] * 3 + [
            {"event_type": "redeem", "key_label": "k", "token_id": t} for t in ("t1", "t2", "t2")]
        self.assertEqual(audit.reconcile_tokens(_csv(rows, self.cols)), [])

    def test_unknown_event_type_is_an_error(self):
        rows = [{"event_type": "mint", "key_label": "k", "token_id": "t"}]
        with self.assertRaises(ValueError):
            audit.reconcile_tokens(_csv(rows, self.cols))


class Shape(unittest.TestCase):
    bits = 2048
    k = 256

    def test_published_attack_queries_are_short(self):
        # The attack queries rational primes and small a - b*m values. Any of those is tiny.
        path = _lines([2, 3, 65537, 2**36 - 5, (2**300) - 12345])
        findings, total = audit.shape(self.bits, path, None)
        self.assertEqual((len(findings), total), (5, 5))

    def test_blinded_query_evades_the_tripwire_but_not_the_padding_gate(self):
        # The documented limitation, asserted: a blinded query is full width and uniformly random,
        # so the short-input tripwire says nothing. The padding gate still refuses it.
        rng = random.Random(20260926)
        blinded = rng.getrandbits(self.bits - 1) | (1 << (self.bits - 2))
        path = _lines([hex(blinded)])
        self.assertEqual(audit.shape(self.bits, path, None)[0], [], "tripwire should NOT see a blinded query")
        self.assertEqual(len(audit.shape(self.bits, path, "pkcs1v15-sign")[0]), 1, "padding gate must refuse it")

    def test_real_pkcs1v15_encoding_passes_the_gate(self):
        t = bytes.fromhex("3031300d060960864801650304020105000420") + bytes(range(32))
        path = _lines([hex(pkcs1v15_em(self.k, t))])
        self.assertEqual(audit.shape(self.bits, path, "pkcs1v15-sign")[0], [])

    def test_pkcs1v15_with_short_padding_string_fails(self):
        t = bytes(self.k - 3 - 7)  # only 7 bytes of 0xFF, spec requires at least 8
        em = int.from_bytes(b"\x00\x01" + b"\xff" * 7 + b"\x00" + t, "big")
        self.assertFalse(audit.padding_ok(em, self.k, "pkcs1v15-sign"))

    def test_iso9796_and_x931_structures(self):
        iso_ok = int.from_bytes(b"\x6a" + bytes(self.k - 2) + b"\xbc", "big")
        iso_bad = int.from_bytes(b"\x2a" + bytes(self.k - 2) + b"\xbc", "big")
        x931_ok = int.from_bytes(b"\x6b" + b"\xbb" * (self.k - 4) + b"\xba\x33\xcc", "big")
        x931_bad = int.from_bytes(b"\x6b" + b"\xbb" * (self.k - 4) + b"\xba\x33\xcd", "big")
        self.assertTrue(audit.padding_ok(iso_ok, self.k, "iso9796-2"))
        self.assertFalse(audit.padding_ok(iso_bad, self.k, "iso9796-2"))
        self.assertTrue(audit.padding_ok(x931_ok, self.k, "x931"))
        self.assertFalse(audit.padding_ok(x931_bad, self.k, "x931"))

    def test_value_wider_than_modulus_fails_the_gate(self):
        self.assertFalse(audit.padding_ok(1 << (self.bits + 1), self.k, "pkcs1v15-sign"))

    def test_empty_input_file_is_an_error(self):
        with self.assertRaises(ValueError):
            audit.shape(self.bits, _lines(["# only a comment"]), None)

    def test_garbage_input_is_an_error(self):
        with self.assertRaises(ValueError):
            audit.shape(self.bits, _lines(["not-a-number"]), None)

    def test_unknown_scheme_is_an_error(self):
        with self.assertRaises(ValueError):
            audit.padding_ok(1, self.k, "pss")


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        quiet = _lines([hex(pkcs1v15_em(256, bytes(51)))])
        loud = _lines([65537])
        self.assertEqual(audit.main(["shape", "--modulus-bits", "2048", "--inputs", quiet]), 0)
        self.assertEqual(audit.main(["shape", "--modulus-bits", "2048", "--inputs", loud]), 1)
        self.assertEqual(audit.main(["shape", "--modulus-bits", "2048", "--inputs", "/no/such/file"]), 2)

    def test_source_is_read_only(self):
        # Guard the tool's promise: no signing, decrypting, key generation or policy writes.
        with open(audit.__file__, encoding="utf-8") as fh:
            src = fh.read()
        for forbidden in (r"\.sign\(", r"\.decrypt\(", r"generate_keypair", r"\.copy\(", r"set_attribute",
                          r"rw=True", r"\.destroy\("):
            self.assertIsNone(re.search(forbidden, src), "rsa_oracle_audit.py must stay read-only: %s" % forbidden)


if __name__ == "__main__":
    unittest.main()
