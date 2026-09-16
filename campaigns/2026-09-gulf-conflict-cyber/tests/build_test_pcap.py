#!/usr/bin/env python3
"""Build a synthetic pcap to check the Suricata rules in this pack fire, and do not fire.

Every positive case carries the request STRUCTURE a rule keys on, with inert values (no
working command, no real exploit chain). Every negative case is a benign near-miss that must
stay silent. A rule set that fires on everything, or on nothing, fails this test.

  python build_test_pcap.py out.pcap
  suricata -r out.pcap -S ../detections/suricata/gulf-conflict-cyber.rules \
      --set vars.address-groups.OT_NET="[192.0.2.0/24]" \
      --set vars.address-groups.HOME_NET="[192.0.2.0/24,10.0.0.0/8]" -l <dir>

Expected sids: see EXPECT below. Requires scapy.
"""
from __future__ import annotations

import sys

from scapy.all import DNS, DNSQR, IP, TCP, UDP, wrpcap  # type: ignore

EXT = "203.0.113.50"      # TEST-NET-3, stands in for an internet source
CAM = "192.0.2.10"        # TEST-NET-1, in OT_NET / HOME_NET
CLIENT = "10.1.1.5"
RESOLVER = "10.1.1.53"
CISA_IP = "185.82.73.162"  # from AA26-097A

pkts = []
_port = [40000]


def http_session(src: str, dst: str, request: bytes, dport: int = 80) -> None:
    """A complete TCP handshake, one request, a 200 response and FIN, so app-layer parsing runs."""
    _port[0] += 1
    sp = _port[0]
    c, s = 1000, 5000
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="S", seq=c))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="SA", seq=s, ack=c + 1))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="A", seq=c + 1, ack=s + 1))
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="PA", seq=c + 1, ack=s + 1) / request)
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="PA", seq=s + 1,
                                           ack=c + 1 + len(request)) / resp)
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dport, flags="FA",
                                           seq=c + 1 + len(request), ack=s + 1 + len(resp)))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sp, flags="FA",
                                           seq=s + 1 + len(resp), ack=c + 2 + len(request)))


def req(method: str, uri: str, body: bytes = b"") -> bytes:
    head = "%s %s HTTP/1.1\r\nHost: cam\r\nContent-Length: %d\r\n\r\n" % (method, uri, len(body))
    return head.encode() + body


def syn(src: str, dst: str, dport: int) -> None:
    _port[0] += 1
    pkts.append(IP(src=src, dst=dst) / TCP(sport=_port[0], dport=dport, flags="S"))


def dns(name: str) -> None:
    _port[0] += 1
    pkts.append(IP(src=CLIENT, dst=RESOLVER) / UDP(sport=_port[0], dport=53) /
                DNS(id=_port[0] & 0xFFFF, rd=1, qd=DNSQR(qname=name)))


# ---- positives ------------------------------------------------------------------------
for p in (44818, 2222, 102, 502, 22):                              # 9200100-9200104
    syn(EXT, CAM, p)
http_session(EXT, CAM, req("GET", "/Security/users?auth=YWRtaW46MTEK"))           # 9200110
http_session(EXT, CAM, req("PUT", "/SDK/webLanguage",
                           b"<?xml version='1.0'?><language>$(true)</language>"))  # 9200111
http_session(EXT, CAM, req("POST", "/RPC2_Login",
                           b'{"method":"global.login","params":{"clientType":"NetKeyboard"}}'))  # 9200112
http_session(EXT, CAM, req("GET", "/php/ping.php?jsondata%5Bip%5D=x%3Btrue"))      # 9200113
http_session(EXT, CAM, req("POST", "/bic/ssoService/v1/applyCT",
                           b'{"a":{"@type":"inert.Placeholder"}}'))                # 9200114
syn(CISA_IP, CAM, 443)                                                             # 9200120
syn(CLIENT, CISA_IP, 443)                                                          # 9200121
dns("dubaicustoms.top")                                                            # 9200130
dns("portal.sapb-aramco.com")                                                      # 9200130
dns("api.ra-backup.com")                                                           # 9200131
dns("cache3.filehost36.sbs")                                                       # 9200132

# ---- negatives: must stay silent -------------------------------------------------------
syn(EXT, CAM, 443)                                          # ordinary web port
syn(CLIENT, CAM, 502)                                       # internal source, not EXTERNAL_NET
http_session(EXT, CAM, req("GET", "/Security/users?auth=dXNlcjpwYXNz"))   # different auth value
http_session(EXT, CAM, req("PUT", "/SDK/webLanguage",
                           b"<?xml version='1.0'?><language>English</language>"))  # benign language
http_session(EXT, CAM, req("POST", "/RPC2_Login",
                           b'{"method":"global.login","params":{"clientType":"Web3.0"}}'))
http_session(EXT, CAM, req("GET", "/php/ping.php?jsondata%5Bip%5D=192.0.2.1"))     # plain address
http_session(EXT, CAM, req("POST", "/bic/ssoService/v1/applyCT", b'{"token":"abc"}'))
syn(CLIENT, "185.82.73.200", 443)                           # same /24, not listed
dns("dubaicustoms.gov.ae")                                  # the real one
dns("www.aramco.com")
dns("filehost.example.com")
dns("mega.nz")

EXPECT = {9200100, 9200101, 9200102, 9200103, 9200104, 9200110, 9200111, 9200112,
          9200113, 9200114, 9200120, 9200121, 9200130, 9200131, 9200132}
# 9200130 fires twice (two positives). Every other expected sid fires exactly once.
EXPECT_COUNTS = {sid: 1 for sid in EXPECT} | {9200130: 2}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "gulf-conflict-selftest.pcap"
    wrpcap(out, pkts)
    print("wrote %d packets to %s" % (len(pkts), out))
