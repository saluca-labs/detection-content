#!/usr/bin/env python3
"""Build a synthetic pcap to check the Suricata rules in this pack fire, and do not fire.

Positives: TLS ClientHellos (SNI), plain HTTP requests (standing in for a decrypted feed) and DNS
queries from a sandbox address. Negatives are near-misses that must stay silent: installs and
reads against the same registries, lookalike and suffix-trick host names, the same actions from
outside SANDBOX_NET, and DNS names one character under each length threshold. A rule set that
fires on everything, or on nothing, fails this test. Nothing is sent anywhere: this writes a file.

  python build_test_pcap.py out.pcap

Loaded by tools/suricata_test.py, which requires EXPECT_COUNTS to match EXACTLY. Requires scapy.
"""
from __future__ import annotations

import sys

from scapy.all import DNS, DNSQR, IP, TCP, UDP, load_layer, raw, wrpcap  # type: ignore

load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello  # type: ignore  # noqa: E402
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName  # type: ignore  # noqa: E402
from scapy.layers.tls.record import TLS  # type: ignore  # noqa: E402

SANDBOX = "198.51.100.10"   # inside SANDBOX_NET (198.51.100.0/24 in tools/suricata_test.py)
OFFICE = "10.2.2.20"        # HOME_NET, not SANDBOX_NET
EXT = "203.0.113.80"        # stands in for every service's address
RESOLVER = "10.0.0.53"      # the sanctioned internal resolver: the rules must see DNS to it

pkts = []
_port = [42000]
_dnsid = [100]


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


def http(src: str, method: str, host: str, uri: str) -> None:
    body = b"x" if method in ("POST", "PUT") else b""
    req = ("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: test\r\nAccept: */*\r\n" % (method, uri, host)).encode()
    if body:
        req += b"Content-Type: application/octet-stream\r\nContent-Length: 1\r\n"
    req += b"\r\n" + body
    session(src, EXT, req, 80, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def dns_query(src: str, name: str, qtype: str = "A") -> None:
    _port[0] += 1
    _dnsid[0] += 1
    pkts.append(IP(src=src, dst=RESOLVER) / UDP(sport=_port[0], dport=53) /
                DNS(id=_dnsid[0], rd=1, qd=DNSQR(qname=name, qtype=qtype)))


def name_of(labels: list[int], suffix: str = "example.net") -> str:
    """A name built from labels of the given lengths, then the suffix. Inert filler characters."""
    return ".".join("a" * n for n in labels) + "." + suffix


# ---- positives ---------------------------------------------------------------------------------
tls_hello(SANDBOX, "upload.pypi.org")                                  # 9200300

http(SANDBOX, "POST", "rubygems.org", "/api/v1/gems")                  # 9200301
http(SANDBOX, "POST", "rubygems.org", "/api/v1//gems")                 # 9200301 (JFrog spelling)
http(SANDBOX, "POST", "rubygems.org", "//api/v1/gems?x=2")             # 9200301 (JFrog spelling)
http(SANDBOX, "POST", "rubygems.org", "/api/v1/web_hooks")             # 9200302
http(SANDBOX, "POST", "upload.pypi.org", "/legacy/")                   # 9200303
http(SANDBOX, "PUT", "registry.npmjs.org", "/some-package")            # 9200304
http(SANDBOX, "PUT", "crates.io", "/api/v1/crates/new")                # 9200305

tls_hello(SANDBOX, "api.imgur.com")                                    # 9200310
tls_hello(SANDBOX, "api.imgbb.com")                                    # 9200311
tls_hello(SANDBOX, "freeimage.host")                                   # 9200312
tls_hello(SANDBOX, "postimages.org")                                   # 9200313
tls_hello(SANDBOX, "catbox.moe")                                       # 9200314
tls_hello(SANDBOX, "litterbox.catbox.moe")                             # 9200314 (subdomain)
tls_hello(SANDBOX, "0x0.st")                                           # 9200315
tls_hello(SANDBOX, "tmpfiles.org")                                     # 9200316
tls_hello(SANDBOX, "temp.sh")                                          # 9200317
tls_hello(SANDBOX, "uguu.se")                                          # 9200318
tls_hello(SANDBOX, "pixeldrain.com")                                   # 9200319
tls_hello(SANDBOX, "store1.gofile.io")                                 # 9200320
tls_hello(SANDBOX, "bashupload.com")                                   # 9200321
tls_hello(SANDBOX, "paste.rs")                                         # 9200322
tls_hello(SANDBOX, "api.paste.ee")                                     # 9200323
http(SANDBOX, "POST", "0x0.st", "/")                                   # 9200324
http(SANDBOX, "POST", "bashupload.com", "/report.txt")                 # 9200324

dns_query(SANDBOX, name_of([24, 24, 24, 24]), "TXT")                   # 9200330: 111 chars, longest label 24
dns_query(SANDBOX, name_of([45]))                                      # 9200331: one 45-char label, 57 chars
dns_query(SANDBOX, name_of([50, 50]), "TXT")                           # 9200330 + 9200331

# ---- negatives: must stay silent ---------------------------------------------------------------
tls_hello(SANDBOX, "pypi.org")                         # install path, not upload
tls_hello(SANDBOX, "files.pythonhosted.org")           # install path
tls_hello(SANDBOX, "rubygems.org")                     # install and publish share SNI: deliberately no rule
tls_hello(SANDBOX, "upload.pypi.org.example.com")      # suffix trick against the bsize match
http(SANDBOX, "GET", "rubygems.org", "/api/v1/gems/rails.json")        # read
http(SANDBOX, "GET", "rubygems.org", "/api/v1/gems")                   # GET, not POST
http(SANDBOX, "POST", "rubygems.org", "/api/v1/gems/rails/owners")     # a different write, not a push
http(SANDBOX, "GET", "rubygems.org", "/api/v1/web_hooks")              # listing hooks, not registering
http(SANDBOX, "POST", "notrubygems.org", "/api/v1/gems")               # lookalike host
http(SANDBOX, "GET", "registry.npmjs.org", "/left-pad")                # install
http(SANDBOX, "GET", "crates.io", "/api/v1/crates/serde")              # read
http(SANDBOX, "PUT", "crates.io", "/api/v1/crates/serde/1.0.0/yank")   # not a publish
http(OFFICE, "POST", "rubygems.org", "/api/v1/gems")                   # a maintainer, not a sandbox
http(OFFICE, "PUT", "crates.io", "/api/v1/crates/new")
tls_hello(SANDBOX, "imgur.com")                        # the site, not the upload API
tls_hello(SANDBOX, "i.imgur.com")                      # image reads
tls_hello(SANDBOX, "notcatbox.moe")                    # lookalike: plain endswith would match, dotprefix must not
tls_hello(SANDBOX, "catbox.moe.example.com")           # suffix trick
tls_hello(SANDBOX, "0x0.st.example.net")
tls_hello(SANDBOX, "xtemp.sh")
tls_hello(SANDBOX, "paste.rs.example.com")
tls_hello(SANDBOX, "fakegofile.io")
tls_hello(SANDBOX, "notpixeldrain.com")
tls_hello(OFFICE, "api.imgur.com")                     # a person at a desk
tls_hello(OFFICE, "0x0.st")
http(SANDBOX, "GET", "0x0.st", "/abc.txt")             # a read
http(SANDBOX, "POST", "not0x0.st", "/")                # lookalike
http(SANDBOX, "POST", "tmpfiles.org.example.com", "/") # suffix trick against the pcre anchor
http(OFFICE, "POST", "0x0.st", "/")
dns_query(SANDBOX, "index.rubygems.org")
dns_query(SANDBOX, name_of([39, 39, 7]))               # 99 chars, longest label 39: one under both thresholds
dns_query(OFFICE, name_of([50, 50]), "TXT")            # the same long name from outside SANDBOX_NET

EXPECT_COUNTS = {
    9200300: 1, 9200301: 3, 9200302: 1, 9200303: 1, 9200304: 1, 9200305: 1,
    9200310: 1, 9200311: 1, 9200312: 1, 9200313: 1, 9200314: 2, 9200315: 1, 9200316: 1,
    9200317: 1, 9200318: 1, 9200319: 1, 9200320: 1, 9200321: 1, 9200322: 1, 9200323: 1,
    9200324: 2, 9200330: 2, 9200331: 2,
}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "transitive-egress-selftest.pcap"
    wrpcap(out, pkts)
    print("wrote %d packets to %s" % (len(pkts), out))
