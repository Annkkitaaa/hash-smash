# Original HashSmash experiment (Cursor agent). Stdlib only; organizer sandbox.
"""Grouped 55-byte sha256-r37 probe with eight-lane SWAR batch verification."""

import json
import struct
import sys

M32 = 0xFFFFFFFF
LANES = 8
SLOT = 32
CLAIMED_BATCH_OPS = 2723

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


class Ops:
    __slots__ = ("n",)

    def __init__(self):
        self.n = 0

    def tick(self, k=1):
        self.n += k


def _pack(values):
    w = 0
    for i, v in enumerate(values):
        w |= (v & M32) << (SLOT * i)
    return w & ((1 << 256) - 1)


def _unpack(w):
    return [(w >> (SLOT * i)) & M32 for i in range(LANES)]


def broadcast(v, ops):
    ops.tick(1)
    return _pack([v] * LANES)


def add8(a, b, ops):
    ops.tick(4)
    return _pack([(x + y) & M32 for x, y in zip(_unpack(a), _unpack(b))])


def xor8(a, b, ops):
    ops.tick(1)
    return _pack([x ^ y for x, y in zip(_unpack(a), _unpack(b))])


def and8(a, b, ops):
    ops.tick(1)
    return _pack([x & y for x, y in zip(_unpack(a), _unpack(b))])


def not8(a, ops):
    ops.tick(1)
    return _pack([(~x) & M32 for x in _unpack(a)])


def ror8(a, r, ops):
    ops.tick(3)
    return _pack([((x >> r) | ((x << (32 - r)) & M32)) & M32 for x in _unpack(a)])


def shr8(a, r, ops):
    ops.tick(2)
    return _pack([(x >> r) for x in _unpack(a)])


def ch8(e, f, g, ops):
    return xor8(and8(e, f, ops), and8(not8(e, ops), g, ops), ops)


def maj8(a, b, c, ops):
    return xor8(xor8(and8(a, b, ops), and8(a, c, ops), ops), and8(b, c, ops), ops)


def scalar_ror(x, r, ops):
    ops.tick(4)
    x &= M32
    return ((x >> r) | ((x << (32 - r)) & M32)) & M32


def scalar_ch(e, f, g, ops):
    ops.tick(3)
    return (e & f) ^ ((~e) & M32 & g)


def scalar_maj(a, b, c, ops):
    ops.tick(3)
    return (a & b) ^ (a & c) ^ (b & c)


def prefix_words(prefix52, ops):
    ops.tick(13)
    msg = prefix52 + b"\x00" * 3
    padded = msg + b"\x80" + (440).to_bytes(8, "big")
    return list(struct.unpack(">16I", padded))[:13]


def schedule_parallel_from_w12(w12, u_list, ops):
    packed = []
    for i in range(13):
        packed.append(broadcast(w12[i], ops))
    ops.tick(1)
    packed.append(_pack([((u << 8) | 0x80) & M32 for u in u_list]))
    packed.append(broadcast(0, ops))
    packed.append(broadcast(440, ops))
    for i in range(16, 37):
        x, y = packed[i - 15], packed[i - 2]
        s0 = xor8(xor8(ror8(x, 7, ops), ror8(x, 18, ops), ops), shr8(x, 3, ops), ops)
        s1 = xor8(xor8(ror8(y, 17, ops), ror8(y, 19, ops), ops), shr8(y, 10, ops), ops)
        wi = add8(add8(add8(packed[i - 16], s0, ops), packed[i - 7], ops), s1, ops)
        packed.append(wi)
    return packed


def rounds_0_12_from_w12(w12, ops):
    w = w12 + [0, 0, 440]
    a, b, c, d, e, f, g, h = IV
    for i in range(13):
        ops.tick(2)
        s1 = scalar_ror(e, 6, ops) ^ scalar_ror(e, 11, ops) ^ scalar_ror(e, 25, ops)
        t1 = (h + s1 + scalar_ch(e, f, g, ops) + K[i] + w[i]) & M32
        s0 = scalar_ror(a, 2, ops) ^ scalar_ror(a, 13, ops) ^ scalar_ror(a, 22, ops)
        t2 = (s0 + scalar_maj(a, b, c, ops)) & M32
        a, b, c, d, e, f, g, h = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
    return (a, b, c, d, e, f, g, h)


def rounds_13_36_lane8(state, w_packed, ops):
    a = broadcast(state[0], ops)
    b = broadcast(state[1], ops)
    c = broadcast(state[2], ops)
    d = broadcast(state[3], ops)
    e = broadcast(state[4], ops)
    f = broadcast(state[5], ops)
    g = broadcast(state[6], ops)
    h = broadcast(state[7], ops)
    for i in range(13, 37):
        wi = w_packed[i]
        s1 = xor8(xor8(ror8(e, 6, ops), ror8(e, 11, ops), ops), ror8(e, 25, ops), ops)
        t1 = add8(add8(add8(add8(h, s1, ops), ch8(e, f, g, ops), ops), broadcast(K[i], ops), ops), wi, ops)
        s0 = xor8(xor8(ror8(a, 2, ops), ror8(a, 13, ops), ops), ror8(a, 22, ops), ops)
        t2 = add8(s0, maj8(a, b, c, ops), ops)
        h, g, f, e, d, c, b, a = g, f, e, add8(d, t1, ops), c, b, a, add8(t1, t2, ops)
    return _unpack(a), _unpack(b), _unpack(c), _unpack(d), _unpack(e), _unpack(f), _unpack(g), _unpack(h)


def feedforward(states, ops):
    digests = []
    for lane in range(LANES):
        ops.tick(8)
        st = tuple((IV[j] + states[j][lane]) & M32 for j in range(8))
        digests.append(b"".join(x.to_bytes(4, "big") for x in st))
    return digests


def compress_batch8(prefix52, u_list):
    ops = Ops()
    ops.tick(22)
    w12 = prefix_words(prefix52, ops)
    state12 = rounds_0_12_from_w12(w12, ops)
    w_packed = schedule_parallel_from_w12(w12, u_list, ops)
    st = rounds_13_36_lane8(state12, w_packed, ops)
    digests = feedforward(st, ops)
    ops.tick(9 * LANES)
    return digests, ops.n


def ror(x, r):
    x &= M32
    return ((x >> r) | ((x << (32 - r)) & M32)) & M32


def ch(e, f, g):
    return (e & f) ^ ((~e) & M32 & g)


def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def digest55(msg55):
    assert len(msg55) == 55
    padded = msg55 + b"\x80" + (440).to_bytes(8, "big")
    words = list(struct.unpack(">16I", padded))
    for i in range(16, 37):
        x, y = words[i - 15], words[i - 2]
        s0 = ror(x, 7) ^ ror(x, 18) ^ (x >> 3)
        s1 = ror(y, 17) ^ ror(y, 19) ^ (y >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = IV
    for i in range(37):
        s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        t1 = (h + s1 + ch(e, f, g) + K[i] + words[i]) & M32
        s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        t2 = (s0 + maj(a, b, c)) & M32
        a, b, c, d, e, f, g, h = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
    out = tuple((x + y) & M32 for x, y in zip(IV, (a, b, c, d, e, f, g, h)))
    return b"".join(w.to_bytes(4, "big") for w in out)


def msg(prefix52, u):
    return prefix52 + u.to_bytes(3, "big")


def trial0_batch(prefix52):
    u_list = [0, 1, 2, 0x100, 0x1000, 0xFFFF00, 0xFFFFFF - 1, 0xFFFFFF]
    digests, ops = compress_batch8(prefix52, u_list)
    if ops != CLAIMED_BATCH_OPS:
        raise ValueError(f"batch_ops {ops} != {CLAIMED_BATCH_OPS}")
    for u, d in zip(u_list, digests):
        if digest55(msg(prefix52, u)) != d:
            raise ValueError("SWAR digest mismatch")


def masked_search(prefix52, u_values, mask):
    seen = {}
    for u in u_values:
        d = digest55(msg(prefix52, u))
        tag = int.from_bytes(d, "big") & mask
        if tag in seen and seen[tag] != u:
            return msg(prefix52, seen[tag]).hex(), msg(prefix52, u).hex()
        seen[tag] = u
    return None, None


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
            trial0_batch(prefix)
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
