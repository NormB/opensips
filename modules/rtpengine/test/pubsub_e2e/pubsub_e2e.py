#!/usr/bin/env python3
#
# pubsub_e2e.py -- end-to-end checks for rtpengine_subscribe_request(),
# rtpengine_subscribe_answer(), rtpengine_unsubscribe() and
# rtpengine_publish() against a live rtpengine.
#
# A two-party call is set up directly over the ng protocol (offer + answer)
# with local UDP sockets as the caller, the callee and a subscriber.  The
# functions under test are then driven through OpenSIPS (see
# opensips.cfg.in), and the checks look at real RTP: the subscriber must get
# a copy of the caller's media while the callee keeps receiving it, the copy
# must stop after the unsubscribe, and refused requests must fail.
#
# Usage: pubsub_e2e.py --ng HOST:PORT --sip HOST:PORT [--ping]
# Exit: 0 all checks passed, 1 a check failed, 77 rtpengine not reachable.
#

import argparse
import base64
import os
import random
import re
import socket
import sys
import time

# ---------------------------------------------------------------- bencode


def benc(v):
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(benc(i) for i in v) + b"e"
    if isinstance(v, dict):
        return b"d" + b"".join(benc(k) + benc(v[k]) for k in v) + b"e"
    raise TypeError(type(v))


def bdec(b, i=0):
    c = b[i:i + 1]
    if c == b"i":
        e = b.index(b"e", i)
        return int(b[i + 1:e]), e + 1
    if c == b"l":
        i, out = i + 1, []
        while b[i:i + 1] != b"e":
            v, i = bdec(b, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i, out = i + 1, {}
        while b[i:i + 1] != b"e":
            k, i = bdec(b, i)
            v, i = bdec(b, i)
            out[k.decode()] = v
        return out, i + 1
    colon = b.index(b":", i)
    n = int(b[i:colon])
    return b[colon + 1:colon + 1 + n], colon + 1 + n


class Ng:
    def __init__(self, addr):
        host, port = addr.rsplit(":", 1)
        self.addr = (host, int(port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)

    def cmd(self, d):
        cookie = b"%x" % random.getrandbits(48)
        self.sock.sendto(cookie + b" " + benc(d), self.addr)
        while True:
            data, _ = self.sock.recvfrom(65535)
            if data.startswith(cookie + b" "):
                return bdec(data[len(cookie) + 1:])[0]

# ---------------------------------------------------------------- SIP


class Sip:
    def __init__(self, addr):
        host, port = addr.rsplit(":", 1)
        self.addr = (host, int(port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(3)
        self.cseq = 0

    def message(self, op, call_id, from_tag, to_tag=None, flags=None,
                sdp=None):
        """Send one MESSAGE; return (status, {header: value})."""
        self.cseq += 1
        lport = self.sock.getsockname()[1]
        hdrs = [
            "MESSAGE sip:pubsub@%s:%d SIP/2.0" % self.addr,
            "Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%x;rport"
            % (lport, random.getrandbits(48)),
            "From: <sip:tester@example.org>;tag=%s" % from_tag,
            "To: <sip:pubsub@example.org>%s"
            % (";tag=" + to_tag if to_tag else ""),
            "Call-ID: %s" % call_id,
            "CSeq: %d MESSAGE" % self.cseq,
            "Max-Forwards: 70",
            "X-Op: %s" % op,
        ]
        if flags is not None:
            hdrs.append("X-Flags: %s" % flags)
        if sdp is not None:
            hdrs.append("X-Sdp: %s" % base64.b64encode(sdp.encode()).decode())
        hdrs += ["Content-Length: 0", "", ""]
        self.sock.sendto("\r\n".join(hdrs).encode(), self.addr)
        while True:
            data = self.sock.recv(65535).decode(errors="replace")
            if "CSeq: %d MESSAGE" % self.cseq not in data:
                continue
            lines = data.split("\r\n")
            status = int(lines[0].split()[1])
            out = {}
            for line in lines[1:]:
                if not line:
                    break
                k, _, v = line.partition(":")
                out[k.strip().lower()] = v.strip()
            return status, out

# ---------------------------------------------------------------- media


def sdp(port, direction, sess):
    return ("v=0\r\no=- %d 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n"
            "t=0 0\r\nm=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
            "a=%s\r\n" % (sess, port, direction))


def sdp_media(text):
    """(address, port) of the first audio stream of an SDP."""
    c = re.search(r"^c=IN IP[46] (\S+)", text, re.M)
    m = re.search(r"^m=audio (\d+) ", text, re.M)
    if not c or not m:
        return None
    return c.group(1), int(m.group(1))


def udp(port=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.setblocking(False)
    return s


def drain(s):
    n = 0
    while True:
        try:
            s.recv(2048)
            n += 1
        except BlockingIOError:
            return n


class Rtp:
    def __init__(self, sock, ssrc):
        self.sock, self.ssrc, self.seq, self.ts = sock, ssrc, 1, 0

    def send(self, dst, count, gap=0.02):
        for _ in range(count):
            hdr = bytes([0x80, 0x00]) + self.seq.to_bytes(2, "big") + \
                self.ts.to_bytes(4, "big") + self.ssrc.to_bytes(4, "big")
            self.sock.sendto(hdr + b"\xff" * 160, dst)
            self.seq = (self.seq + 1) & 0xffff
            self.ts += 160
            time.sleep(gap)

# ---------------------------------------------------------------- checks


failures = 0


def check(cond, what):
    global failures
    print("  %s: %s" % ("ok  " if cond else "FAIL", what))
    if not cond:
        failures += 1
    return cond


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ng", default="127.0.0.1:2223")
    ap.add_argument("--sip", default="127.0.0.1:5098")
    ap.add_argument("--ping", action="store_true")
    a = ap.parse_args()

    ng = Ng(a.ng)
    try:
        pong = ng.cmd({"command": "ping"})
    except (OSError, ValueError):
        pong = None
    if not pong or pong.get("result") != b"pong":
        print("SKIP: no rtpengine answering ng ping on %s" % a.ng)
        return 77
    if a.ping:
        return 0

    sip = Sip(a.sip)
    rnd = "%x" % random.getrandbits(32)
    call_id, caller, callee = "ps-%s" % rnd, "caller-%s" % rnd, "callee-%s" % rnd
    pub_call = "ps-pub-%s" % rnd
    a_sock, b_sock, s_sock, p_sock = udp(), udp(), udp(), udp()
    a_port, b_port = a_sock.getsockname()[1], b_sock.getsockname()[1]
    s_port, p_port = s_sock.getsockname()[1], p_sock.getsockname()[1]
    rtp_a, rtp_b, rtp_s = Rtp(a_sock, 0x1111), Rtp(b_sock, 0x2222), Rtp(s_sock, 0x3333)

    def relay_port(port):
        # any port of rtpengine's own range (its port-min/port-max are
        # configurable), i.e. not one of this test's endpoints
        return 0 < port < 65536 and port not in (a_port, b_port, s_port, p_port)

    try:
        print("== call set-up over ng (offer + answer)")
        off = ng.cmd({"command": "offer", "call-id": call_id,
                      "from-tag": caller, "sdp": sdp(a_port, "sendrecv", 1),
                      "flags": ["trust-address"], "replace": ["origin"]})
        ans = ng.cmd({"command": "answer", "call-id": call_id,
                      "from-tag": caller, "to-tag": callee,
                      "sdp": sdp(b_port, "sendrecv", 2),
                      "flags": ["trust-address"], "replace": ["origin"]})
        if not check(off.get("result") == b"ok" and ans.get("result") == b"ok",
                     "offer and answer accepted"):
            return 1
        to_callee = sdp_media(off["sdp"].decode())   # where B sends
        to_caller = sdp_media(ans["sdp"].decode())   # where A sends
        # latch both legs, then make sure A -> B flows
        rtp_b.send(to_callee, 3)
        rtp_a.send(to_caller, 3)
        time.sleep(0.2)
        drain(a_sock), drain(b_sock)
        rtp_a.send(to_caller, 25)
        time.sleep(0.2)
        check(drain(b_sock) >= 20, "baseline: callee receives the caller's RTP")

        print("== subscribe request (in-dialog MESSAGE: To carries the callee tag)")
        st, h = sip.message("subscribe-request", call_id, caller, to_tag=callee,
                            flags="from-tag=%s" % caller)
        check(st == 200, "subscribe request succeeds (%d %s)" % (st, h.get("x-err", "")))
        tag = h.get("x-tag", "")
        offer_sdp = base64.b64decode(h.get("x-sdp", "")).decode(errors="replace")
        check(tag != "", "subscription tag returned")
        check(tag not in (caller, callee),
              "subscription tag is not a call leg's tag (got %r)" % tag)
        check("a=sendonly" in offer_sdp, "subscription offer is sendonly")
        fork_src = sdp_media(offer_sdp)
        check(fork_src is not None and relay_port(fork_src[1]),
              "subscription offer has an rtpengine port (%r)" % (fork_src,))

        print("== subscribe answer (from the same in-dialog context)")
        st, h = sip.message("subscribe-answer", call_id, caller, to_tag=callee,
                            flags="to-tag=%s" % tag,
                            sdp=sdp(s_port, "recvonly", 3))
        check(st == 200, "subscribe answer succeeds (%d %s)" % (st, h.get("x-err", "")))

        print("== media with the subscription active")
        if fork_src:
            rtp_s.send(fork_src, 2)      # latch the subscriber
        time.sleep(0.2)
        drain(b_sock), drain(s_sock)
        rtp_a.send(to_caller, 50)
        time.sleep(0.3)
        got_b, got_s = drain(b_sock), drain(s_sock)
        check(got_b >= 40, "callee still receives the caller's RTP (%d/50)" % got_b)
        check(got_s >= 40, "subscriber receives a copy (%d/50)" % got_s)

        print("== unsubscribe")
        st, h = sip.message("unsubscribe", call_id, caller, to_tag=callee,
                            flags="to-tag=%s" % tag)
        check(st == 200, "unsubscribe succeeds (%d %s)" % (st, h.get("x-err", "")))
        time.sleep(0.2)
        drain(b_sock), drain(s_sock)
        rtp_a.send(to_caller, 50)
        time.sleep(0.3)
        got_b, got_s = drain(b_sock), drain(s_sock)
        check(got_b >= 40, "callee still receives after the unsubscribe (%d/50)" % got_b)
        check(got_s <= 2, "subscriber copy stopped (%d/50)" % got_s)

        print("== publish (a publisher's own INVITE context)")
        st, h = sip.message("publish", pub_call, "pub-%s" % rnd,
                            sdp=sdp(p_port, "sendonly", 4))
        check(st == 200, "publish succeeds (%d %s)" % (st, h.get("x-err", "")))
        pub_ans = base64.b64decode(h.get("x-sdp", "")).decode(errors="replace")
        check("a=recvonly" in pub_ans, "publish answer is recvonly")
        pm = sdp_media(pub_ans)
        check(pm is not None and relay_port(pm[1]),
              "publish answer has an rtpengine port (%r)" % (pm,))

        print("== refused requests")
        st, h = sip.message("subscribe-answer", call_id, caller,
                            sdp=sdp(s_port, "recvonly", 5))
        check(st == 500 and "to-tag" in h.get("x-err", ""),
              "subscribe answer without to-tag= is refused locally (%d %r)"
              % (st, h.get("x-err")))
        st, h = sip.message("unsubscribe", call_id, caller, to_tag=callee)
        check(st == 500 and "to-tag" in h.get("x-err", ""),
              "unsubscribe without to-tag= is refused locally, even in-dialog "
              "(%d %r)" % (st, h.get("x-err")))
        st, h = sip.message("subscribe-request", "ps-nosuch-%s" % rnd, caller,
                            flags="from-tag=%s" % caller)
        # (an rtpengine-side "Unknown call-ID" does not reach error_pv: the
        # module only fills it for local and node errors)
        check(st == 500, "subscribe request for an unknown call-id fails (%d)"
              % st)
        st, h = sip.message("subscribe-answer", call_id, caller,
                            flags="to-tag=nosuch-%s" % rnd,
                            sdp=sdp(s_port, "recvonly", 6))
        check(st == 500, "subscribe answer for an unknown subscription fails "
              "(%d %r)" % (st, h.get("x-err")))
        st, h = sip.message("publish", pub_call, "pub2-%s" % rnd, sdp="")
        check(st == 500, "publish with an empty body variable fails (%d)" % st)
        st, h = sip.message("subscribe-answer", call_id, caller,
                            flags="to-tag=%s" % tag, sdp="")
        check(st == 500, "subscribe answer with an empty body variable fails "
              "(%d)" % st)
    finally:
        for cid in (call_id, pub_call):
            try:
                ng.cmd({"command": "delete", "call-id": cid})
            except OSError:
                pass

    print("pubsub_e2e: %s (%d failure%s)" % ("FAILED" if failures else "PASSED",
          failures, "" if failures == 1 else "s"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
