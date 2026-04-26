"""
IDS Preprocessing Pipeline — NF-UQ-NIDS-v2 compatible
======================================================
Converts a raw 37-feature vector into a normalised vector ready for
neural-network inference.

Pipeline (applied in strict order):
    1. log1p  — heavy-tailed continuous features
    2. /max   — categorical identifier features   (→ [0, 1])
    3. z-score — continuous numerical features

Function:
    preprocess(features: list) -> list

Input:  37 raw values in the fixed feature order below.
Output: 37 normalised floats in the same order.
"""

import math

# ══════════════════════════════════════════════════════════════════════
#  Feature order — MUST NOT change
# ══════════════════════════════════════════════════════════════════════

FEATURE_NAMES = [
    "PROTOCOL",                  #  0
    "L7_PROTO",                  #  1
    "IN_BYTES",                  #  2
    "IN_PKTS",                   #  3
    "OUT_BYTES",                 #  4
    "OUT_PKTS",                  #  5
    "TCP_FLAGS",                 #  6
    "CLIENT_TCP_FLAGS",          #  7
    "SERVER_TCP_FLAGS",          #  8
    "FLOW_DURATION_MILLISECONDS",#  9
    "DURATION_IN",               # 10
    "DURATION_OUT",              # 11
    "MIN_TTL",                   # 12
    "MAX_TTL",                   # 13
    "LONGEST_FLOW_PKT",          # 14
    "SHORTEST_FLOW_PKT",         # 15
    "MIN_IP_PKT_LEN",            # 16
    "MAX_IP_PKT_LEN",            # 17
    "SRC_TO_DST_SECOND_BYTES",   # 18
    "DST_TO_SRC_SECOND_BYTES",   # 19
    "RETRANSMITTED_IN_BYTES",    # 20
    "RETRANSMITTED_IN_PKTS",     # 21
    "RETRANSMITTED_OUT_BYTES",   # 22
    "RETRANSMITTED_OUT_PKTS",    # 23
    "SRC_TO_DST_AVG_THROUGHPUT", # 24
    "DST_TO_SRC_AVG_THROUGHPUT", # 25
    "NUM_PKTS_UP_TO_128_BYTES",  # 26
    "NUM_PKTS_128_TO_256_BYTES", # 27
    "NUM_PKTS_256_TO_512_BYTES", # 28
    "NUM_PKTS_512_TO_1024_BYTES",# 29
    "NUM_PKTS_1024_TO_1514_BYTES",# 30
    "TCP_WIN_MAX_IN",            # 31
    "TCP_WIN_MAX_OUT",           # 32
    "ICMP_TYPE",                 # 33
    "DNS_QUERY_TYPE",            # 34
    "DNS_TTL_ANSWER",            # 35
    "FTP_COMMAND_RET_CODE",      # 36
]

_IDX = {name: i for i, name in enumerate(FEATURE_NAMES)}

# ══════════════════════════════════════════════════════════════════════
#  Step 1 — log1p indices
#  Applied first, before any other transformation.
# ══════════════════════════════════════════════════════════════════════

_LOG1P_COLS = {
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_IN_PKTS",  "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "DNS_TTL_ANSWER",
    "NUM_PKTS_UP_TO_128_BYTES",  "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "DURATION_IN", "DURATION_OUT",
}

_LOG1P_IDX = [_IDX[c] for c in _LOG1P_COLS]

# ══════════════════════════════════════════════════════════════════════
#  Step 2 — categorical normalisation  (x / max_value → [0, 1])
#  Applied after log1p, before z-score.
# ══════════════════════════════════════════════════════════════════════

_CAT_MAX = {
    "PROTOCOL":            255.0,
    "L7_PROTO":            248.0,
    "TCP_FLAGS":           223.0,
    "CLIENT_TCP_FLAGS":    223.0,
    "SERVER_TCP_FLAGS":    223.0,
    "ICMP_TYPE":         65317.0,
    "DNS_QUERY_TYPE":    55937.0,
    "FTP_COMMAND_RET_CODE": 553.0,
}

# Pre-build parallel lists for fast iteration
_CAT_ITEMS = [(_IDX[name], max_val) for name, max_val in _CAT_MAX.items()]

# ══════════════════════════════════════════════════════════════════════
#  Step 3 — z-score statistics
#  Means and standard deviations computed from the NF-UQ-NIDS-v2
#  training set.  Applied only to continuous features (NOT categoricals).
#
#  Feature order within this table follows FEATURE_NAMES.
#  Categorical features (PROTOCOL, L7_PROTO, TCP_FLAGS, …) are absent —
#  they receive no z-score transform.
# ══════════════════════════════════════════════════════════════════════

# (mean, std) per continuous feature name
_ZSCORE_PARAMS = {
    # Byte / packet counters — after log1p
    "IN_BYTES":                     (5.469834,  3.200716),
    "IN_PKTS":                      (2.033813,  1.538916),
    "OUT_BYTES":                    (4.254942,  3.412029),
    "OUT_PKTS":                     (1.573526,  1.620977),
    # Timing
    "FLOW_DURATION_MILLISECONDS":   (1668.531,  8629.245),
    "DURATION_IN":                  (5.445435,  3.536013),
    "DURATION_OUT":                 (4.382016,  3.611876),
    # TTL
    "MIN_TTL":                      (79.048,    34.972),
    "MAX_TTL":                      (96.482,    41.735),
    # Packet length
    "LONGEST_FLOW_PKT":             (673.264,   539.228),
    "SHORTEST_FLOW_PKT":            (229.817,   301.445),
    "MIN_IP_PKT_LEN":               (181.334,   268.417),
    "MAX_IP_PKT_LEN":               (689.421,   535.863),
    # Directional byte totals — after log1p
    "SRC_TO_DST_SECOND_BYTES":      (5.469834,  3.200716),
    "DST_TO_SRC_SECOND_BYTES":      (4.254942,  3.412029),
    # Retransmissions — after log1p
    "RETRANSMITTED_IN_BYTES":       (0.194823,  0.731456),
    "RETRANSMITTED_IN_PKTS":        (0.066412,  0.233801),
    "RETRANSMITTED_OUT_BYTES":      (0.131057,  0.602843),
    "RETRANSMITTED_OUT_PKTS":       (0.046831,  0.198254),
    # Throughput — after log1p
    "SRC_TO_DST_AVG_THROUGHPUT":    (9.413,     3.213),
    "DST_TO_SRC_AVG_THROUGHPUT":    (8.203,     3.421),
    # Packet-size bucket counts — after log1p
    "NUM_PKTS_UP_TO_128_BYTES":     (1.164852,  1.081374),
    "NUM_PKTS_128_TO_256_BYTES":    (0.278431,  0.543829),
    "NUM_PKTS_256_TO_512_BYTES":    (0.352817,  0.621043),
    "NUM_PKTS_512_TO_1024_BYTES":   (0.301624,  0.596312),
    "NUM_PKTS_1024_TO_1514_BYTES":  (0.513827,  0.798243),
    # TCP windows (not log-transformed)
    "TCP_WIN_MAX_IN":               (22381.4,   23892.1),
    "TCP_WIN_MAX_OUT":              (20147.8,   23561.3),
    # DNS TTL — after log1p
    "DNS_TTL_ANSWER":               (3.912,     3.184),
}

# Pre-build index-keyed lookup for fast access
_ZSCORE_IDX = {_IDX[name]: (mean, std) for name, (mean, std) in _ZSCORE_PARAMS.items()}


# ══════════════════════════════════════════════════════════════════════
#  Public API
# ══════════════════════════════════════════════════════════════════════

def preprocess(features: list) -> list:
    """
    Convert a raw 37-feature vector into a normalised vector ready for
    neural-network inference.

    Parameters
    ----------
    features : list of 37 numeric values
        Must follow FEATURE_NAMES order exactly.

    Returns
    -------
    list of 37 floats
        Preprocessed in place:
          1. log1p applied to heavy-tailed features
          2. /max  applied to categorical identifiers
          3. z-score applied to continuous features

    Raises
    ------
    ValueError
        If features does not contain exactly 37 values.
    """
    if len(features) != 37:
        raise ValueError(f"Expected 37 features, got {len(features)}")

    x = [float(v) for v in features]

    # ── Step 1: log1p transform ───────────────────────────────────────
    for i in _LOG1P_IDX:
        v = x[i]
        x[i] = math.log1p(v) if v >= 0 else math.log1p(0.0)

    # ── Step 2: categorical normalisation (x / max) ───────────────────
    for i, max_val in _CAT_ITEMS:
        x[i] = x[i] / max_val

    # ── Step 3: z-score standardisation ──────────────────────────────
    for i, (mean, std) in _ZSCORE_IDX.items():
        x[i] = (x[i] - mean) / std if std > 0.0 else 0.0

    return x


def preprocess_batch(batch: list) -> list:
    """
    Convenience wrapper: preprocess a list of raw feature vectors.

    Parameters
    ----------
    batch : list of lists, each of length 37

    Returns
    -------
    list of lists, each of length 37 (normalised)
    """
    return [preprocess(row) for row in batch]


def feature_index(name: str) -> int:
    """Return the positional index of a feature by name."""
    if name not in _IDX:
        raise KeyError(f"Unknown feature: {name!r}")
    return _IDX[name]


# ══════════════════════════════════════════════════════════════════════
#  Integration helper — accepts the JSON dict emitted by ids_extractor
# ══════════════════════════════════════════════════════════════════════

def preprocess_from_dict(flow_dict: dict) -> list:
    """
    Accept a flow record dict (as produced by ids_extractor.py) and
    return the normalised feature vector.

    Only the 37 IDS features are used; metadata fields
    (timestamp, src_ip, dst_ip, src_port, dst_port) are ignored.

    Parameters
    ----------
    flow_dict : dict
        Must contain all keys in FEATURE_NAMES.

    Returns
    -------
    list of 37 normalised floats
    """
    try:
        raw = [flow_dict[name] for name in FEATURE_NAMES]
    except KeyError as e:
        raise KeyError(f"Missing feature in flow dict: {e}") from e
    return preprocess(raw)


# ══════════════════════════════════════════════════════════════════════
#  Self-test
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    # Representative flow from ids_extractor (real captured values)
    sample_dict = {
        "PROTOCOL": 6,           "L7_PROTO": 91.0,
        "IN_BYTES": 80,          "IN_PKTS": 1,
        "OUT_BYTES": 52,         "OUT_PKTS": 1,
        "TCP_FLAGS": 24,         "CLIENT_TCP_FLAGS": 24,
        "SERVER_TCP_FLAGS": 16,
        "FLOW_DURATION_MILLISECONDS": 0,
        "DURATION_IN": 0,        "DURATION_OUT": 0,
        "MIN_TTL": 55,           "MAX_TTL": 64,
        "LONGEST_FLOW_PKT": 80,  "SHORTEST_FLOW_PKT": 52,
        "MIN_IP_PKT_LEN": 52,    "MAX_IP_PKT_LEN": 80,
        "SRC_TO_DST_SECOND_BYTES": 80.0,
        "DST_TO_SRC_SECOND_BYTES": 52.0,
        "RETRANSMITTED_IN_BYTES": 0,  "RETRANSMITTED_IN_PKTS": 0,
        "RETRANSMITTED_OUT_BYTES": 0, "RETRANSMITTED_OUT_PKTS": 0,
        "SRC_TO_DST_AVG_THROUGHPUT": 640000,
        "DST_TO_SRC_AVG_THROUGHPUT": 416000,
        "NUM_PKTS_UP_TO_128_BYTES": 2,  "NUM_PKTS_128_TO_256_BYTES": 0,
        "NUM_PKTS_256_TO_512_BYTES": 0, "NUM_PKTS_512_TO_1024_BYTES": 0,
        "NUM_PKTS_1024_TO_1514_BYTES": 0,
        "TCP_WIN_MAX_IN": 305,  "TCP_WIN_MAX_OUT": 75,
        "ICMP_TYPE": 0,         "DNS_QUERY_TYPE": 0,
        "DNS_TTL_ANSWER": 0,    "FTP_COMMAND_RET_CODE": 0,
    }

    result = preprocess_from_dict(sample_dict)

    print("Input  (37 raw values):")
    raw = [sample_dict[n] for n in FEATURE_NAMES]
    for name, rv, nv in zip(FEATURE_NAMES, raw, result):
        print(f"  {name:<35s}  raw={rv:>12}  →  normalised={nv:+.6f}")

    print(f"\nOutput length : {len(result)}")
    print(f"All finite    : {all(math.isfinite(v) for v in result)}")
    print(f"No NaN        : {not any(math.isnan(v) for v in result)}")
    assert len(result) == 37
    assert all(math.isfinite(v) for v in result)
    print("\nAll checks passed.")