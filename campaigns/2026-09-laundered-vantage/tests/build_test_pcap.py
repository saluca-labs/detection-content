#!/usr/bin/env python3
"""Build a synthetic pcap to check the Suricata rules in this pack fire, and do not fire.

Positives are TLS ClientHellos (SNI) and plain HTTP requests from a sandbox address to each
laundering service. Negatives are near-misses that must stay silent: lookalike names that a plain
endswith would match, a subdomain of a named relay, the same services from outside SANDBOX_NET,
and an httpbin request that is not a base64 page. A rule set that fires on everything, or on
nothing, fails this test. No payload is sent to anything: this writes a file.

  python build_test_pcap.py out.pcap

Loaded by tools/suricata_test.py, which requires EXPECT_COUNTS to match EXACTLY. Requires scapy.
"""
from __future__ import annotations

import sys

from scapy.all import IP, TCP, load_layer, raw, wrpcap  # type: ignore

load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello  # type: ignore  # noqa: E402
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName  # type: ignore  # noqa: E402
from scapy.layers.tls.record import TLS  # type: ignore  # noqa: E402

SANDBOX = "198.51.100.10"   # inside SANDBOX_NET (198.51.100.0/24 in tools/suricata_test.py)
OFFICE = "10.2.2.20"        # HOME_NET, not SANDBOX_NET
EXT = "203.0.113.80"        # stands in for every service's address

pkts = []
_port = [41000]


def session(src: str, dst: str, payload: bytes, dport: int, reply: bytes = b"") -> None:
    """Handshake, one client payload, an optional server reply, FIN. Enough for app-layer parsing."""
    _port[0] += 1
    sp = _port[0]
    c, s = 1000, 7000
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="S", seq=c))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="SA", seq=s, ack=c + 1))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="A", seq=c + 1, ack=s + 1))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="PA", seq=c + 1, ack=s + 1) / payload)
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="A", seq=s + 1, ack=c + 1 + len(payload)))
    if reply:
        pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="PA", seq=s + 1,
                                               ack=c + 1 + len(payload)) / reply)
    s_end = s + 1 + len(reply)
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="FA", seq=c + 1 + len(payload), ack=s_end))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="FA", seq=s_end, ack=c + 2 + len(payload)))


def tls_hello(src: str, sni: str) -> None:
    hello = TLS(msg=[TLSClientHello(ciphers=[0x1301, 0xC02F],
                                    ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())])])])
    session(src, EXT, raw(hello), 443)


def http_get(src: str, host: str, uri: str) -> None:
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n" % (uri, host)).encode()
    session(src, EXT, req, 80, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


# ---- positives ---------------------------------------------------------------------------------
tls_hello(SANDBOX, "urlquery.net")                             # 9200200
tls_hello(SANDBOX, "api.urlquery.net")                         # 9200200 (subdomain)
tls_hello(SANDBOX, "urlscan.io")                               # 9200201
tls_hello(SANDBOX, "r.jina.ai")                                # 9200202
tls_hello(SANDBOX, "markdown.new")                             # 9200203
tls_hello(SANDBOX, "eu.httpbin.org")                           # 9200204
tls_hello(SANDBOX, "httpbun.com")                              # 9200205
http_get(SANDBOX, "httpbin.org", "/get")                       # 9200206
http_get(SANDBOX, "eu.httpbin.org", "/base64/PGgxPnRlc3Q8L2gxPg==?p=p0000000001")  # 9200206 + 9200207
tls_hello(SANDBOX, "production-sfo.browserless.io")            # 9200208
tls_hello(SANDBOX, "api.mail.gw")                              # 9200209
tls_hello(SANDBOX, "milankarman.github.io")                    # 9200210
tls_hello(SANDBOX, "blogsflow.liftbrandfulfillment.com")       # 9200211

# ---- negatives: must stay silent ---------------------------------------------------------------
tls_hello(SANDBOX, "noturlquery.net")          # lookalike: plain endswith would match, dotprefix must not
tls_hello(SANDBOX, "urlscan.io.example.com")   # suffix trick
tls_hello(SANDBOX, "jina.ai")                  # the vendor's main site, not the reader
tls_hello(SANDBOX, "fakehttpbin.org")          # lookalike
tls_hello(SANDBOX, "browserless.io.example.net")
tls_hello(SANDBOX, "gmail.gw.example.com")
tls_hello(SANDBOX, "other.milankarman.github.io")   # not the named relay
tls_hello(SANDBOX, "liftbrandfulfillment.com")      # parent of the named relay
tls_hello(SANDBOX, "example.github.io")
tls_hello(OFFICE, "urlquery.net")              # an analyst, not a sandbox
tls_hello(OFFICE, "r.jina.ai")
http_get(OFFICE, "httpbin.org", "/base64/PGgxPnRlc3Q8L2gxPg==")
http_get(SANDBOX, "notreallyhttpbin.org", "/base64/PGgxPnRlc3Q8L2gxPg==")
http_get(SANDBOX, "data.example.gov", "/base64/files/report.csv")   # base64 path, wrong host

EXPECT_COUNTS = {9200200: 2, 9200201: 1, 9200202: 1, 9200203: 1, 9200204: 1, 9200205: 1,
                 9200206: 2, 9200207: 1, 9200208: 1, 9200209: 1, 9200210: 1, 9200211: 1}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "laundered-vantage-selftest.pcap"
    wrpcap(out, pkts)
    print("wrote %d packets to %s" % (len(pkts), out))
