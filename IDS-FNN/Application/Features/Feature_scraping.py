#!/usr/bin/env python3
"""
Real-time IDS Feature Extractor — NF-UQ-NIDS-v2 compatible
===========================================================
Captures live packets via AF_PACKET raw socket (Linux, requires root).

Architecture — strict separation of concerns:
  ┌─────────────────────────────────────────────────────────┐
  │  capture_loop (thread)                                  │
  │    Receives packets → parses → calls flow_table.update  │
  │    NEVER prints. NEVER calls json. NEVER emits output.  │
  └──────────────────────────┬──────────────────────────────┘
                             │ updates only
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  FlowTable (shared, thread-safe)                        │
  │    Keyed by (src_ip, dst_ip, src_port, dst_port, proto) │
  │    Each FlowState stores last_emitted_second = -1       │
  └──────────────────────────┬──────────────────────────────┘
                             │ reads only
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  output_loop (thread) — fires every 1 second            │
  │    current_second = int(time.time())                    │
  │    For each flow:                                       │
  │      if flow.last_emitted_second != current_second:     │
  │          print(json.dumps(flow.to_features()))          │
  │          flow.last_emitted_second = current_second      │
  │    This guarantees AT MOST ONE output per flow/second.  │
  └─────────────────────────────────────────────────────────┘

Usage:
    sudo python3 ids_extractor.py
    sudo python3 ids_extractor.py --iface eth0 --timeout 60 --tick 1.0
"""

import socket
import struct
import json
import time
import argparse
import threading
import queue
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════
#  L7_PROTO — deterministic nDPI v2.x protocol identification
#  Tier A: confirmed from NF-UQ-NIDS-v2 dataset rows
#  Tier B: inferred from nDPI v2.x ndpi_protocol_ids.h
#  Fallback: 0.0
# ══════════════════════════════════════════════════════════════════════

_L7_CONFIRMED: dict = {
    (6,   20): 21.0,    (6,   21): 21.0,    (6,   22): 178.0,
    (6,   25): 11.0,    (6,   80): 7.0,     (6,  110): 10.0,
    (6,  143): 123.0,   (6,  443): 91.0,    (6,  465): 11.0,
    (6,  587): 11.0,    (6,  993): 123.0,   (6,  995): 10.0,
    (6, 3306): 188.0,   (6, 3389): 183.0,   (6, 5061): 144.0,
    (6, 8080): 7.0,     (6, 8443): 91.0,    (17, 443): 91.0,
    (17,   53): 5.0,    (17,   67): 67.0,   (17,   68): 67.0,
    (17,   69): 106.0,  (17,  123): 119.0,  (17,  161): 99.0,
    (17,  162): 99.0,   (17,  514): 104.0,  (17, 1900): 109.0,
    (17, 5060): 144.0,  (17, 5353): 5.0,
}

_L7_INFERRED: dict = {
    (6,   23): 77.0,    (6,   43): 170.0,   (6,   88): 111.0,
    (6,  102): 211.0,   (6,  119): 93.0,    (6,  135): 127.0,
    (6,  139): 16.0,    (6,  179): 13.0,    (6,  389): 112.0,
    (6,  445): 16.0,    (6,  502): 44.0,    (6,  554): 50.0,
    (6,  631): 6.0,     (6,  636): 112.0,   (6,  873): 166.0,
    (6, 1080): 172.0,   (6, 1194): 159.0,   (6, 1352): 150.0,
    (6, 1433): 114.0,   (6, 1434): 114.0,   (6, 1494): 132.0,
    (6, 1521): 167.0,   (6, 1720): 158.0,   (6, 1723): 115.0,
    (6, 1935): 174.0,   (6, 2000): 164.0,   (6, 2049): 11.0,
    (6, 2775): 217.0,   (6, 3128): 131.0,   (6, 3200): 151.0,
    (6, 3868): 210.0,   (6, 4433): 91.0,    (6, 4443): 91.0,
    (6, 5432): 19.0,    (6, 5672): 250.0,   (6, 5900): 89.0,
    (6, 5938): 148.0,   (6, 6379): 182.0,   (6, 6443): 91.0,
    (6, 6667): 65.0,    (6, 8008): 7.0,     (6, 8009): 139.0,
    (6, 8888): 7.0,     (6, 9200): 7.0,     (6, 9418): 214.0,
    (6, 9443): 91.0,    (6, 11211): 40.0,
    (17,  137): 10.0,   (17,  138): 10.0,   (17,  500): 79.0,
    (17,  546): 103.0,  (17,  547): 103.0,  (17,  902): 28.0,
    (17, 1194): 159.0,  (17, 1812): 146.0,  (17, 1813): 146.0,
    (17, 2055): 128.0,  (17, 2123): 152.0,  (17, 2152): 152.0,
    (17, 3478): 78.0,   (17, 3479): 78.0,   (17, 3544): 240.0,
    (17, 3702): 153.0,  (17, 4500): 79.0,   (17, 4789): 193.0,
    (17, 5355): 154.0,  (17, 5683): 27.0,   (17, 6343): 129.0,
    (17, 51820): 232.0,
}

_L7_RAWPROTO: dict = {
    1: 81.0, 2: 82.0, 4: 86.0, 8: 83.0,
    47: 80.0, 50: 0.0, 51: 0.0, 58: 102.0,
    89: 85.0, 132: 84.0,
}


def get_l7_proto(ip_proto: int, dst_port: int, src_port: int = 0) -> float:
    for port in (dst_port, src_port):
        if port:
            v = _L7_CONFIRMED.get((ip_proto, port))
            if v is not None:
                return v
    for port in (dst_port, src_port):
        if port:
            v = _L7_INFERRED.get((ip_proto, port))
            if v is not None:
                return v
    return _L7_RAWPROTO.get(ip_proto, 0.0)


# ══════════════════════════════════════════════════════════════════════
#  Raw packet parsers — pure struct, no external libraries
# ══════════════════════════════════════════════════════════════════════

ETH_HDR       = 14
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17
IP_PROTO_ICMP = 1


def _now_ms() -> float:
    return time.time() * 1000.0


def parse_ethernet(raw: bytes):
    if len(raw) < ETH_HDR:
        return None
    eth_type = struct.unpack_from("!H", raw, 12)[0]
    offset = ETH_HDR
    if eth_type == 0x8100:                   # 802.1Q VLAN tag
        if len(raw) < ETH_HDR + 4:
            return None
        eth_type = struct.unpack_from("!H", raw, 16)[0]
        offset += 4
    if eth_type != 0x0800:                   # IPv4 only
        return None
    return raw[offset:]


def parse_ip(data: bytes):
    if not data or len(data) < 20:
        return None
    ver_ihl = data[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0xF) * 4
    if len(data) < ihl:
        return None
    return {
        "total_len": struct.unpack_from("!H", data, 2)[0],
        "ttl":       data[8],
        "proto":     data[9],
        "src_ip":    socket.inet_ntoa(data[12:16]),
        "dst_ip":    socket.inet_ntoa(data[16:20]),
        "payload":   data[ihl:],
    }


def parse_tcp(payload: bytes):
    if len(payload) < 20:
        return None
    data_offset = ((payload[12] >> 4) & 0xF) * 4
    return {
        "src_port":   struct.unpack_from("!H", payload, 0)[0],
        "dst_port":   struct.unpack_from("!H", payload, 2)[0],
        "seq":        struct.unpack_from("!I", payload, 4)[0],
        "flags":      payload[13],
        "window":     struct.unpack_from("!H", payload, 14)[0],
        "data_offset": data_offset,
        "payload_len": max(0, len(payload) - data_offset),
    }


def parse_udp(payload: bytes):
    if len(payload) < 8:
        return None
    return {
        "src_port": struct.unpack_from("!H", payload, 0)[0],
        "dst_port": struct.unpack_from("!H", payload, 2)[0],
    }


def parse_icmp(payload: bytes):
    return payload[0] if len(payload) >= 1 else 0


def dns_query_type(data: bytes) -> int:
    try:
        if len(data) < 12 or struct.unpack_from("!H", data, 4)[0] == 0:
            return 0
        offset = 12
        while offset < len(data):
            ln = data[offset]
            if ln == 0:
                offset += 1
                break
            if ln & 0xC0 == 0xC0:
                offset += 2
                break
            offset += ln + 1
        return struct.unpack_from("!H", data, offset)[0] if offset + 4 <= len(data) else 0
    except Exception:
        return 0


def dns_ttl_answer(data: bytes) -> int:
    try:
        if len(data) < 12:
            return 0
        flags = struct.unpack_from("!H", data, 2)[0]
        if not (flags & 0x8000):
            return 0
        qd = struct.unpack_from("!H", data, 4)[0]
        an = struct.unpack_from("!H", data, 6)[0]
        if an == 0:
            return 0
        offset = 12
        for _ in range(qd):
            while offset < len(data):
                ln = data[offset]
                if ln == 0:
                    offset += 1
                    break
                if ln & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += ln + 1
            offset += 4
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset]:
                offset += data[offset] + 1
            offset += 1
        return struct.unpack_from("!I", data, offset + 4)[0] if offset + 10 <= len(data) else 0
    except Exception:
        return 0


def ftp_ret_code(tcp_payload: bytes) -> int:
    try:
        t = tcp_payload[:8].decode("ascii", errors="ignore").strip()
        if len(t) >= 3 and t[:3].isdigit():
            code = int(t[:3])
            if 100 <= code <= 999:
                return code
    except Exception:
        pass
    return 0


# ══════════════════════════════════════════════════════════════════════
#  Packet size bucket — strict NF-UQ-NIDS-v2 boundaries
# ══════════════════════════════════════════════════════════════════════

def _bucket(size: int) -> int:
    if size <= 128:    return 0
    elif size <= 256:  return 1
    elif size <= 512:  return 2
    elif size <= 1024: return 3
    else:              return 4


# ══════════════════════════════════════════════════════════════════════
#  FlowState — holds all per-flow statistics
# ══════════════════════════════════════════════════════════════════════

class FlowState:
    __slots__ = [
        # 5-tuple identity
        "src_ip", "dst_ip", "src_port", "dst_port", "proto", "l7_proto",
        # timing
        "first_ts_ms", "last_ts_ms",
        "in_first_ts",  "in_last_ts",
        "out_first_ts", "out_last_ts",
        # counters
        "in_bytes",  "in_pkts",
        "out_bytes", "out_pkts",
        # TTL
        "min_ttl", "max_ttl",
        # sizes (needed for bucket and min/max calculations)
        "all_pkt_sizes",
        # TCP
        "tcp_flags_all", "tcp_flags_client", "tcp_flags_server",
        "tcp_win_max_in", "tcp_win_max_out",
        # retransmission tracking (sequence-number model)
        "in_seq_max",   "in_retx_bytes",  "in_retx_pkts",
        "out_seq_max",  "out_retx_bytes", "out_retx_pkts",
        # packet size buckets [0..4]
        "buckets",
        # protocol-specific fields
        "icmp_type",
        "dns_qtype", "dns_ttl",
        "ftp_code",
        # ── EMISSION CONTROL ──────────────────────────────────────────
        # Set to int(wall_second) each time the flow is printed.
        # The scheduler only prints a flow when:
        #   current_second != last_emitted_second
        # This guarantees at most ONE output per flow per second,
        # regardless of how many packets arrive.
        "last_emitted_second",
    ]

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, ts_ms):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto    = proto
        self.l7_proto = get_l7_proto(proto, dst_port, src_port)

        self.first_ts_ms = ts_ms
        self.last_ts_ms  = ts_ms
        self.in_first_ts  = None
        self.in_last_ts   = None
        self.out_first_ts = None
        self.out_last_ts  = None

        self.in_bytes  = 0;  self.in_pkts  = 0
        self.out_bytes = 0;  self.out_pkts = 0

        self.min_ttl = 255;  self.max_ttl = 0

        self.all_pkt_sizes = []

        self.tcp_flags_all    = 0
        self.tcp_flags_client = 0
        self.tcp_flags_server = 0
        self.tcp_win_max_in   = 0
        self.tcp_win_max_out  = 0

        self.in_seq_max    = None
        self.in_retx_bytes = 0;  self.in_retx_pkts  = 0
        self.out_seq_max   = None
        self.out_retx_bytes = 0; self.out_retx_pkts = 0

        self.buckets = [0, 0, 0, 0, 0]

        self.icmp_type = 0
        self.dns_qtype = 0;  self.dns_ttl = 0
        self.ftp_code  = 0

        # -1 means this flow has never been emitted
        self.last_emitted_second = -1

    # ── update — called by packet handler ONLY, never prints ──────────

    def update(self, direction: str, pkt_size: int, ts_ms: float,
               ttl: int, tcp=None, udp_payload=None,
               icmp_type_val=0, tcp_payload=b"", is_ftp=False):
        """
        Update flow statistics for one packet.
        NEVER prints. NEVER emits JSON. Statistics only.
        """
        # timestamp — only advance, never retreat
        if ts_ms > self.last_ts_ms:
            self.last_ts_ms = ts_ms

        # TTL
        if ttl < self.min_ttl: self.min_ttl = ttl
        if ttl > self.max_ttl: self.max_ttl = ttl

        # packet size tracking (both directions combined)
        self.all_pkt_sizes.append(pkt_size)
        self.buckets[_bucket(pkt_size)] += 1

        if direction == "in":
            self.in_bytes += pkt_size
            self.in_pkts  += 1
            if self.in_first_ts is None: self.in_first_ts = ts_ms
            self.in_last_ts = ts_ms

            if tcp is not None:
                self.tcp_flags_all    |= tcp["flags"]
                self.tcp_flags_client |= tcp["flags"]
                if tcp["window"] > self.tcp_win_max_in:
                    self.tcp_win_max_in = tcp["window"]
                pl = tcp["payload_len"]
                seq = tcp["seq"]
                if self.in_seq_max is None:
                    self.in_seq_max = seq + max(pl, 1)
                elif seq < self.in_seq_max:
                    self.in_retx_bytes += pkt_size
                    self.in_retx_pkts  += 1
                else:
                    self.in_seq_max = seq + max(pl, 1)
                if is_ftp and self.ftp_code == 0:
                    self.ftp_code = ftp_ret_code(tcp_payload)

        else:  # "out"
            self.out_bytes += pkt_size
            self.out_pkts  += 1
            if self.out_first_ts is None: self.out_first_ts = ts_ms
            self.out_last_ts = ts_ms

            if tcp is not None:
                self.tcp_flags_all    |= tcp["flags"]
                self.tcp_flags_server |= tcp["flags"]
                if tcp["window"] > self.tcp_win_max_out:
                    self.tcp_win_max_out = tcp["window"]
                pl = tcp["payload_len"]
                seq = tcp["seq"]
                if self.out_seq_max is None:
                    self.out_seq_max = seq + max(pl, 1)
                elif seq < self.out_seq_max:
                    self.out_retx_bytes += pkt_size
                    self.out_retx_pkts  += 1
                else:
                    self.out_seq_max = seq + max(pl, 1)
                if is_ftp and self.ftp_code == 0:
                    self.ftp_code = ftp_ret_code(tcp_payload)

        if icmp_type_val and self.icmp_type == 0:
            self.icmp_type = icmp_type_val

        if udp_payload is not None and self.l7_proto == 5.0:
            if self.dns_qtype == 0:
                self.dns_qtype = dns_query_type(udp_payload)
            if self.dns_ttl == 0:
                self.dns_ttl = dns_ttl_answer(udp_payload)

    # ── to_features — called by scheduler ONLY ────────────────────────

    def to_features(self) -> dict:
        """
        Compute and return the 37 NF-UQ-NIDS-v2 features + 5 metadata fields.
        Called by the output scheduler. Never called from packet handler.
        """
        flow_ms = self.last_ts_ms - self.first_ts_ms

        dur_in  = max(0, self.in_last_ts  - self.in_first_ts)  \
                  if self.in_first_ts  is not None and self.in_last_ts  is not None else 0
        dur_out = max(0, self.out_last_ts - self.out_first_ts) \
                  if self.out_first_ts is not None and self.out_last_ts is not None else 0

        sizes = self.all_pkt_sizes
        if sizes:
            longest  = max(sizes)
            shortest = min(sizes)
            min_ip   = min(sizes)   # min of ALL packets regardless of direction
            max_ip   = max(sizes)
        else:
            longest = shortest = min_ip = max_ip = 0

        # NF-UQ-NIDS-v2 confirmed formulas — unchanged:
        #   SRC_TO_DST_SECOND_BYTES   = IN_BYTES
        #   DST_TO_SRC_SECOND_BYTES   = OUT_BYTES
        #   SRC_TO_DST_AVG_THROUGHPUT = IN_BYTES  * 8000
        #   DST_TO_SRC_AVG_THROUGHPUT = OUT_BYTES * 8000
        s2d_sec = float(self.in_bytes)
        d2s_sec = float(self.out_bytes)
        s2d_tp  = self.in_bytes  * 8000
        d2s_tp  = self.out_bytes * 8000

        ts = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        return {
            "timestamp"                   : ts,
            "src_ip"                      : self.src_ip,
            "dst_ip"                      : self.dst_ip,
            "src_port"                    : self.src_port,
            "dst_port"                    : self.dst_port,
            "PROTOCOL"                    : self.proto,
            "L7_PROTO"                    : self.l7_proto,
            "IN_BYTES"                    : self.in_bytes,
            "IN_PKTS"                     : self.in_pkts,
            "OUT_BYTES"                   : self.out_bytes,
            "OUT_PKTS"                    : self.out_pkts,
            "TCP_FLAGS"                   : self.tcp_flags_all,
            "CLIENT_TCP_FLAGS"            : self.tcp_flags_client,
            "SERVER_TCP_FLAGS"            : self.tcp_flags_server,
            "FLOW_DURATION_MILLISECONDS"  : int(flow_ms),
            "DURATION_IN"                 : int(dur_in),
            "DURATION_OUT"                : int(dur_out),
            "MIN_TTL"                     : self.min_ttl if self.max_ttl > 0 else 0,
            "MAX_TTL"                     : self.max_ttl,
            "LONGEST_FLOW_PKT"            : longest,
            "SHORTEST_FLOW_PKT"           : shortest,
            "MIN_IP_PKT_LEN"              : min_ip,
            "MAX_IP_PKT_LEN"              : max_ip,
            "SRC_TO_DST_SECOND_BYTES"     : s2d_sec,
            "DST_TO_SRC_SECOND_BYTES"     : d2s_sec,
            "RETRANSMITTED_IN_BYTES"      : self.in_retx_bytes,
            "RETRANSMITTED_IN_PKTS"       : self.in_retx_pkts,
            "RETRANSMITTED_OUT_BYTES"     : self.out_retx_bytes,
            "RETRANSMITTED_OUT_PKTS"      : self.out_retx_pkts,
            "SRC_TO_DST_AVG_THROUGHPUT"   : s2d_tp,
            "DST_TO_SRC_AVG_THROUGHPUT"   : d2s_tp,
            "NUM_PKTS_UP_TO_128_BYTES"    : self.buckets[0],
            "NUM_PKTS_128_TO_256_BYTES"   : self.buckets[1],
            "NUM_PKTS_256_TO_512_BYTES"   : self.buckets[2],
            "NUM_PKTS_512_TO_1024_BYTES"  : self.buckets[3],
            "NUM_PKTS_1024_TO_1514_BYTES" : self.buckets[4],
            "TCP_WIN_MAX_IN"              : self.tcp_win_max_in,
            "TCP_WIN_MAX_OUT"             : self.tcp_win_max_out,
            "ICMP_TYPE"                   : self.icmp_type,
            "DNS_QUERY_TYPE"              : self.dns_qtype,
            "DNS_TTL_ANSWER"              : self.dns_ttl,
            "FTP_COMMAND_RET_CODE"        : self.ftp_code,
        }


# ══════════════════════════════════════════════════════════════════════
#  FlowTable — thread-safe in-memory store
#  Key: (src_ip, dst_ip, src_port, dst_port, proto)
# ══════════════════════════════════════════════════════════════════════

class FlowTable:
    def __init__(self, idle_timeout_s: float = 60.0):
        self._flows: dict = {}
        self._lock = threading.Lock()
        self._idle_ms = idle_timeout_s * 1000.0

    # ── called by packet handler — statistics update only, no output ──

    def update(self, src_ip, dst_ip, src_port, dst_port, proto,
               pkt_size, ts_ms, ttl,
               tcp=None, udp_payload=None, icmp_type_val=0,
               tcp_payload=b""):

        fwd = (src_ip, dst_ip, src_port, dst_port, proto)
        rev = (dst_ip, src_ip, dst_port, src_port, proto)

        l7 = get_l7_proto(proto, dst_port, src_port)
        is_ftp = l7 == 21.0

        with self._lock:

            flow = self._flows.get(fwd)

            if flow is not None:
                direction = "in"

            else:
                flow = self._flows.get(rev)

                if flow is not None:
                    direction = "out"

                else:
                    direction = "in"
                    flow = FlowState(src_ip, dst_ip, src_port, dst_port, proto, ts_ms)
                    self._flows[fwd] = flow

            flow.update(
                direction=direction,
                pkt_size=pkt_size,
                ts_ms=ts_ms,
                ttl=ttl,
                tcp=tcp,
                udp_payload=udp_payload,
                icmp_type_val=icmp_type_val,
                tcp_payload=tcp_payload,
                is_ftp=is_ftp,
            )

    # ── called by output scheduler — returns flows ready to emit ──────

    def emit_snapshot(self, current_second: int) -> list:

        results = []

        with self._lock:
            for flow in self._flows.values():

                if flow.in_pkts + flow.out_pkts == 0:
                    continue

                if flow.last_emitted_second >= current_second:
                    continue

                flow.last_emitted_second = current_second
                feat = flow.to_features()
                results.append(feat)

        return results

    # ── expire idle flows ─────────────────────────────────────────────

    def expire(self, now_ms: float) -> list:
        expired = []

        with self._lock:
            dead = [
                k for k, f in self._flows.items()
                if now_ms - f.last_ts_ms >= self._idle_ms
            ]

            for k in dead:
                expired.append(self._flows.pop(k))

        return expired

    # ── flush flows on shutdown ───────────────────────────────────────

    def flush(self) -> list:
        with self._lock:
            flows = list(self._flows.values())
            self._flows.clear()
        return flows
# ══════════════════════════════════════════════════════════════════════
#  capture_loop — packet handler thread
#  SOLE RESPONSIBILITY: receive packets, parse, call flow_table.update()
#  NEVER prints. NEVER calls json. NEVER emits output.
# ══════════════════════════════════════════════════════════════════════

def capture_loop(iface: str, flow_table: FlowTable, stop_event: threading.Event):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(0x0003))   # ETH_P_ALL
        sock.bind((iface, 0))
        sock.settimeout(1.0)
    except PermissionError:
        raise PermissionError("Raw socket requires root. Run with sudo.")

    while not stop_event.is_set():
        try:
            raw, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            continue

        ts_ms = _now_ms()

        ip_data = parse_ethernet(raw)
        if ip_data is None:
            continue

        ip = parse_ip(ip_data)
        if ip is None:
            continue

        proto    = ip["proto"]
        src_ip   = ip["src_ip"]
        dst_ip   = ip["dst_ip"]
        ttl      = ip["ttl"]
        pkt_size = ip["total_len"]
        payload  = ip["payload"]

        src_port    = 0
        dst_port    = 0
        tcp_parsed  = None
        udp_payload = None
        icmp_val    = 0
        tcp_pld     = b""

        if proto == IP_PROTO_TCP:
            tcp_parsed = parse_tcp(payload)
            if tcp_parsed is None:
                continue
            src_port = tcp_parsed["src_port"]
            dst_port = tcp_parsed["dst_port"]
            off = tcp_parsed["data_offset"]
            if off <= len(payload):
                tcp_pld = payload[off:]

        elif proto == IP_PROTO_UDP:
            udp = parse_udp(payload)
            if udp is None:
                continue
            src_port    = udp["src_port"]
            dst_port    = udp["dst_port"]
            udp_payload = payload[8:]

        elif proto == IP_PROTO_ICMP:
            icmp_val = parse_icmp(payload)

        # ── Update flow table only. NO printing here. ─────────────────
        flow_table.update(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            proto=proto, pkt_size=pkt_size,
            ts_ms=ts_ms, ttl=ttl,
            tcp=tcp_parsed, udp_payload=udp_payload,
            icmp_type_val=icmp_val, tcp_payload=tcp_pld,
        )
        # ── End of packet handler — nothing printed above this line ───

    sock.close()


# ══════════════════════════════════════════════════════════════════════
#  output_loop — scheduler thread
#  Fires every tick_s seconds (default 1.0).
#  The ONLY place in the program that prints JSON output.
#  Each flow is printed AT MOST ONCE per second.
# ══════════════════════════════════════════════════════════════════════

def output_loop(flow_table: FlowTable, tick_s: float, stop_event: threading.Event, feature_queue):
    last_second = None

    while not stop_event.is_set():

        now = time.time()
        current_second = int(now)

        # wait until a new second arrives
        if current_second == last_second:
            time.sleep(0.01)
            continue

        last_second = current_second
        now_ms = now * 1000.0

        # expire idle flows
        for flow in flow_table.expire(now_ms):

            if flow.in_pkts + flow.out_pkts == 0:
                continue

            flow.last_emitted_second = current_second
            feature_queue.put(flow.to_features())   # ← change here

        # emit active flows
        for feat in flow_table.emit_snapshot(current_second):
            feature_queue.put(feat)                 # ← change here

    # shutdown flush
    shutdown_second = int(time.time()) + 1

    for flow in flow_table.flush():

        if flow.in_pkts + flow.out_pkts == 0:
            continue

        flow.last_emitted_second = shutdown_second
        feature_queue.put(flow.to_features())      
                      
# ══════════════════════════════════════════════════════════════════════
#  Interface auto-detection
# ══════════════════════════════════════════════════════════════════════

def detect_interface() -> str:
    # 1. Default-route interface from /proc/net/route
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    iface = parts[0]
                    if iface and iface != "lo":
                        return iface
    except Exception:
        pass

    # 2. SIOCGIFCONF ioctl
    try:
        import fcntl, array
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buf = array.array("B", b"\x00" * 1024)
        addr, _ = buf.buffer_info()
        fcntl.ioctl(s.fileno(), 0x8912, struct.pack("iP", 1024, addr))
        s.close()
        data = bytes(buf)
        offset = 0
        while offset + 40 <= len(data):
            name = data[offset:offset+16].rstrip(b"\x00").decode("ascii", errors="ignore")
            offset += 40
            if name and name != "lo" and not name.startswith("docker") \
                    and not name.startswith("virbr"):
                return name
    except Exception:
        pass

    # 3. /sys/class/net
    try:
        import os
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface == "lo":
                continue
            try:
                state = open(f"/sys/class/net/{iface}/operstate").read().strip()
                if state == "up":
                    return iface
            except Exception:
                continue
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface != "lo":
                return iface
    except Exception:
        pass

    return "eth0"


# ══════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════
def raw_data():
    import queue

    iface = detect_interface()

    flow_table = FlowTable(idle_timeout_s=60)
    stop_event = threading.Event()
    feature_queue = queue.Queue()

    cap = threading.Thread(
        target=capture_loop,
        args=(iface, flow_table, stop_event),
        daemon=True
    )

    out = threading.Thread(
        target=output_loop,
        args=(flow_table, 1.0, stop_event, feature_queue),
        daemon=True
    )

    cap.start()
    out.start()

    while cap.is_alive():

        try:
            feat = feature_queue.get(timeout=0.1)
            yield feat

        except queue.Empty:
            pass

def main():
    import sys
    import queue

    parser = argparse.ArgumentParser(
        description="Real-time IDS feature extractor — NF-UQ-NIDS-v2 compatible"
    )
    parser.add_argument("--iface", default=None,
                        help="Network interface (auto-detected if omitted)")
    parser.add_argument("--timeout", default=60.0, type=float,
                        help="Flow idle timeout seconds (default: 60)")
    parser.add_argument("--tick", default=1.0, type=float,
                        help="Output interval seconds (default: 1.0)")
    args = parser.parse_args()

    iface = args.iface or detect_interface()

    print(
        f"[IDS] Listening on {iface} | idle-timeout={args.timeout}s | tick={args.tick}s",
        file=sys.stderr,
        flush=True,
    )

    flow_table = FlowTable(idle_timeout_s=args.timeout)
    stop_event = threading.Event()

    # queue for ML pipeline / downstream processing
    feature_queue = queue.Queue()

    # ─────────────────────────────────────────
    # Thread 1 — packet capture
    # ─────────────────────────────────────────
    cap = threading.Thread(
        target=capture_loop,
        args=(iface, flow_table, stop_event),
        daemon=True,
        name="capture",
    )

    # ─────────────────────────────────────────
    # Thread 2 — feature emission
    # ─────────────────────────────────────────
    out = threading.Thread(
        target=output_loop,
        args=(flow_table, args.tick, stop_event, feature_queue),
        daemon=True,
        name="output",
    )

    cap.start()
    out.start()

    try:
        while cap.is_alive():

            # read extracted features
            try:
                feat = feature_queue.get(timeout=0.1)

                # send to ML model / pipeline here
                # example:
                # model.predict(feat)

                # temporary debug
                # print(feat)

            except queue.Empty:
                pass

            time.sleep(0.01)

    except KeyboardInterrupt:
        pass

    finally:
        stop_event.set()
        cap.join(timeout=3)
        out.join(timeout=3)


if __name__ == "__main__":
    main()
