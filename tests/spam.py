#!/usr/bin/env python3
"""Minimal bidirectional connected-UDP endpoint used by the tests.

One process, one socket: bind to (LOCAL, LPORT), connect() to (REMOTE, RPORT)
and then both send a fixed-size payload and drain whatever the peer sends back
on the same 4-tuple. Both ends of the test run this tool, so EGRESS (the
direction the scheduler is asked to limit) and INGRESS both flow at once.

The process comm is set to --comm (tgt|peer) so the scheduler can match the
flow against its rules.

Prints a single stats line at the end:
    SENT_BPS .. SENT_PKTS .. SENT_BYTES .. RECV_BPS .. RECV_PKTS .. RECV_BYTES
"""
import argparse
import ctypes
import select
import socket
import time

PR_SET_NAME = 15
BUFSZ = 4 * 1024 * 1024


def set_comm(name):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_SET_NAME, name.encode()[:15], 0, 0, 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--comm", default=None, help="process comm to match rules")
    ap.add_argument("--local", required=True)
    ap.add_argument("--lport", type=int, default=9001)
    ap.add_argument("--remote", required=True)
    ap.add_argument("--rport", type=int, default=9001)
    ap.add_argument("--dur", type=float, required=True)
    ap.add_argument("--size", type=int, default=1400)
    ap.add_argument("--rate", type=float, default=0.0, help="0 = unlimited")
    args = ap.parse_args()

    if args.comm:
        set_comm(args.comm)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFSZ)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFSZ)
    s.bind((args.local, args.lport))
    s.connect((args.remote, args.rport))

    payload = b"a" * args.size
    sent = pkts = recvd = rpkts = 0
    per_pkt = args.size * 8 / args.rate if args.rate > 0 else 0.0

    end = time.time() + abs(args.dur)
    while True:
        now = time.time()
        if now >= end:
            break
        try:
            s.send(payload)
            sent += args.size
            pkts += 1
        except OSError:
            pass
        while True:
            r, _, _ = select.select([s], [], [], 0)
            if not r:
                break
            try:
                chunk = s.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            recvd += len(chunk)
            rpkts += 1
        if per_pkt > 0:
            time.sleep(max(0.0, per_pkt - (time.time() - now)))

    s.close()
    dt = abs(args.dur) if args.dur else 1e-3
    print(
        f"SENT_BPS {sent * 8 / dt:.0f} SENT_PKTS {pkts} SENT_BYTES {sent} "
        f"RECV_BPS {recvd * 8 / dt:.0f} RECV_PKTS {rpkts} RECV_BYTES {recvd}"
    )
    return 0 if pkts > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
