#!/usr/bin/env python3
#
# Copyright (C) 2026 OpenSIPS Solutions
# SPDX-License-Identifier: GPL-2.0-or-later
#
# nats_ack_drop_proxy.py -- a TCP proxy between a NATS client and a
# nats-server that drops the first N JetStream publish acks on their way
# to the client, so a test can make an ack go missing on demand.
#
# Usage: nats_ack_drop_proxy.py LISTEN_PORT SERVER_PORT DROP_N [READY_FILE]
#
# Client to server: copied as-is.  Server to client: parsed as NATS
# protocol (INFO, PING, PONG, +OK, -ERR lines; MSG and HMSG with their
# payloads).  A MSG whose payload is a publish ack -- JSON starting with
# {"stream": -- is dropped while fewer than DROP_N have been dropped;
# everything else is forwarded unchanged.  Each dropped ack is printed
# to stdout ("dropped ack N: <payload>"), so the test can count them.
# READY_FILE, if given, is created once the proxy listens.
#
# Plaintext only: the proxy reads the protocol, so a TLS connection
# cannot go through it.

import socket
import sys
import threading

LISTEN, SERVER, DROP_N = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
READY = sys.argv[4] if len(sys.argv) > 4 else None

dropped = 0
lock = threading.Lock()


def pump_up(src, dst):
    """client -> server, unchanged"""
    try:
        while True:
            b = src.recv(65536)
            if not b:
                break
            dst.sendall(b)
    except OSError:
        pass
    for s in (src, dst):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def pump_down(src, dst):
    """server -> client, parsed; publish acks dropped while DROP_N lasts"""
    global dropped
    buf = b""
    try:
        while True:
            b = src.recv(65536)
            if not b:
                break
            buf += b
            out = b""
            while True:
                eol = buf.find(b"\r\n")
                if eol < 0:
                    break
                line = buf[:eol]
                words = line.split()
                op = words[0].upper() if words else b""
                if op in (b"MSG", b"HMSG"):
                    # MSG subj sid [reply] total / HMSG subj sid [reply] hdr total
                    total = int(words[-1])
                    end = eol + 2 + total + 2
                    if len(buf) < end:
                        break          # wait for the whole payload
                    frame = buf[:end]
                    body = buf[eol + 2:eol + 2 + total]
                    buf = buf[end:]
                    if op == b"MSG" and body.lstrip().startswith(b'{"stream":'):
                        with lock:
                            drop = dropped < DROP_N
                            if drop:
                                dropped += 1
                                n = dropped
                        if drop:
                            print("dropped ack %d: %s" % (n, body.decode(errors="replace")),
                                  flush=True)
                            continue
                    out += frame
                else:
                    out += buf[:eol + 2]
                    buf = buf[eol + 2:]
            if out:
                dst.sendall(out)
    except OSError:
        pass
    for s in (src, dst):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def serve(client):
    try:
        server = socket.create_connection(("127.0.0.1", SERVER))
    except OSError:
        client.close()
        return
    threading.Thread(target=pump_up, args=(client, server), daemon=True).start()
    threading.Thread(target=pump_down, args=(server, client), daemon=True).start()


def main():
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", LISTEN))
    ls.listen(64)
    if READY:
        open(READY, "w").close()
    while True:
        c, _ = ls.accept()
        serve(c)


main()
