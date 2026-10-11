# Original HashSmash experiment (Cursor agent). Stdlib only; organizer sandbox.
"""Scaled grouped 55-byte message probe for sha256-r37-prefix-v1.

Each trial derives a 52-byte prefix from the organizer seed. Messages are
prefix || u for u in a bounded range (24-bit). The search event is a 16-bit
digest-xor mask on the low 16 bits of digest words H3 and H7.

Trial 0 verifies message decoding and reference digests on three distinct u.
"""

import json
import struct
import sys

M32 = 0xFFFFFFFF
IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
)


def ror(x, r):
    x &= M32
    return ((x >> r) | ((x << (32 - r)) & M32)) & M32


def ch(e, f, g):
    return (e & f) ^ ((~e) & M32 & g)


def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def digest55(msg55: bytes) -> bytes:
    assert len(msg55) == 55
    padded = msg55 + b"\x80" + (440).to_bytes(8, "big")
    words = list(struct.unpack(">16I", padded))
    rounds = 37
    for i in range(16, rounds):
        x, y = words[i - 15], words[i - 2]
        s0 = ror(x, 7) ^ ror(x, 18) ^ (x >> 3)
        s1 = ror(y, 17) ^ ror(y, 19) ^ (y >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = IV
    for i in range(rounds):
        s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        t1 = (h + s1 + ch(e, f, g) + K[i] + words[i]) & M32
        s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        t2 = (s0 + maj(a, b, c)) & M32
        a, b, c, d, e, f, g, h = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
    out = tuple((x + y) & M32 for x, y in zip(IV, (a, b, c, d, e, f, g, h)))
    return b"".join(w.to_bytes(4, "big") for w in out)


def msg(prefix52: bytes, u: int) -> bytes:
    return prefix52 + u.to_bytes(3, "big")


def masked_search(prefix52: bytes, u_values, mask: int):
    seen = {}
    for u in u_values:
        d = digest55(msg(prefix52, u))
        tag = int.from_bytes(d, "big") & mask
        if tag in seen and seen[tag] != u:
            return msg(prefix52, seen[tag]).hex(), msg(prefix52, u).hex()
        seen[tag] = u
    return None, None


def trial0(prefix52: bytes):
    for u in (0, 1, 0xFFFFFF):
        m = msg(prefix52, u)
        if len(m) != 55:
            raise ValueError("bad length")
        digest55(m)


def main():
    req = json.load(sys.stdin)
    if req["schema_version"] != 1 or req["target_profile"] != "sha256-r37-prefix-v1":
        raise ValueError("unexpected request")
    exp = req["experiment_id"]
    mask = int(req["event"]["mask_hex"], 16)
    trials = []
    for tr in req["trials"]:
        seed = bytes.fromhex(tr["seed"])
        prefix = (seed * 3)[:52]
        if tr["trial"] == 0:
            trial0(prefix)
        if exp == "cigts-mask-spread":
            u_range = range(32)
        elif exp == "cigts-mask-single-group":
            u_range = range(512)
        else:
            raise ValueError("experiment")
        a, b = masked_search(prefix, u_range, mask)
        trials.append({"trial": tr["trial"], "message_a_hex": a, "message_b_hex": b})
    json.dump({"schema_version": 1, "trials": trials}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
