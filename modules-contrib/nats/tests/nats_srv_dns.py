#!/usr/bin/env python3
#
# Copyright (C) 2026 OpenSIPS Solutions
# SPDX-License-Identifier: GPL-2.0-or-later
#
# nats_srv_dns.py -- a minimal DNS server (UDP, stdlib only) for the DNS
# SRV end-to-end test of the nats module.
#
# Usage: nats_srv_dns.py ADDR PORT DOMAIN REC [REC...]
#   REC = priority,weight,port,target
#
# Answers:
#   SRV  _nats._tcp.DOMAIN   -> the REC list (the target written as given)
#   A    each REC target     -> 127.0.0.1
#   AAAA each REC target     -> no data (NOERROR, no answer)
#   anything else            -> NXDOMAIN
# Each answered query is printed to stdout ("Q <type> <name>").

import socket
import struct
import sys

ADDR, PORT, DOMAIN = sys.argv[1], int(sys.argv[2]), sys.argv[3].lower().rstrip(".")
RECS = []
for r in sys.argv[4:]:
    pr, w, p, t = r.split(",")
    RECS.append((int(pr), int(w), int(p), t))
SRV_NAME = "_nats._tcp." + DOMAIN
TARGETS = {t.lower().rstrip(".") for (_, _, _, t) in RECS}


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def parse_question(msg):
    i, labels = 12, []
    while msg[i]:
        n = msg[i]
        labels.append(msg[i + 1:i + 1 + n].decode(errors="replace"))
        i += 1 + n
    qtype, qclass = struct.unpack("!HH", msg[i + 1:i + 5])
    return ".".join(labels).lower(), qtype, i + 5


def answer(msg):
    qid, flags = struct.unpack("!HH", msg[:4])
    name, qtype, qend = parse_question(msg)
    question = msg[12:qend]
    rcode, answers = 0, []
    if qtype == 33 and name == SRV_NAME:
        for (pr, w, p, t) in RECS:
            rdata = struct.pack("!HHH", pr, w, p) + encode_name(t)
            answers.append(struct.pack("!HHHIH", 0xC00C, 33, 1, 30, len(rdata)) + rdata)
    elif qtype == 1 and name in TARGETS:
        answers.append(struct.pack("!HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton("127.0.0.1"))
    elif name in TARGETS or name == SRV_NAME:
        pass                     # no data of this type
    else:
        rcode = 3                # NXDOMAIN
    print("Q %d %s" % (qtype, name), flush=True)
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | (flags & 0x0100) | rcode,
                      1, len(answers), 0, 0)
    return hdr + question + b"".join(answers)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ADDR, PORT))
    print("ready", flush=True)
    while True:
        msg, peer = s.recvfrom(4096)
        try:
            s.sendto(answer(msg), peer)
        except (IndexError, struct.error, UnicodeDecodeError):
            pass


main()
