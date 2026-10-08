"""Independent pure-Python verifier for vanity lookalike rows.

Derives the Ethereum address from each private key with a from-scratch
secp256k1 + Keccak-256 implementation (no shared code with vanity.c) and
checks it equals lookalike_address and matches the recipient prefix/suffix.

Usage: python scripts/verify_lookalikes.py <csv> [n]
"""
from __future__ import annotations

import csv
import random
import sys

# --- secp256k1 ---
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def inv(a: int, m: int = P) -> int:
    return pow(a, m - 2, m)


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def mul(k: int, point=(Gx, Gy)):
    result = None
    addend = point
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


# --- Keccak-256 (original padding) ---
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
PIL = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
M = (1 << 64) - 1


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M


def keccak_f(st):
    for rnd in range(24):
        bc = [st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20] for i in range(5)]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ rol(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                st[j + i] ^= t
        t = st[1]
        for i in range(24):
            j = PIL[i]
            bc0 = st[j]
            st[j] = rol(t, ROT[i])
            t = bc0
        for j in range(0, 25, 5):
            row = st[j:j + 5]
            for i in range(5):
                st[j + i] ^= (~row[(i + 1) % 5] & M) & row[(i + 2) % 5]
        st[0] ^= RC[rnd]


def keccak256(data: bytes) -> bytes:
    rate = 136
    st = [0] * 25
    i = 0
    while len(data) - i >= rate:
        blk = data[i:i + rate]
        for j in range(rate // 8):
            st[j] ^= int.from_bytes(blk[j * 8:j * 8 + 8], "little")
        keccak_f(st)
        i += rate
    tail = bytearray(data[i:])
    tail.append(0x01)
    while len(tail) < rate:
        tail.append(0)
    tail[-1] |= 0x80
    for j in range(rate // 8):
        st[j] ^= int.from_bytes(bytes(tail[j * 8:j * 8 + 8]), "little")
    keccak_f(st)
    return b"".join(st[j].to_bytes(8, "little") for j in range(4))


def addr_from_priv(hexkey: str) -> str:
    k = int(hexkey, 16)
    pt = mul(k)
    pub = pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    h = keccak256(pub)
    return "0x" + h[-20:].hex()


def main() -> None:
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    rows = [r for r in csv.DictReader(open(path, encoding="utf-8")) if r.get("lookalike_address")]
    random.seed(7)
    sample = random.sample(rows, min(n, len(rows)))
    ok = 0
    for r in sample:
        addr = addr_from_priv(r["lookalike_private_key"][2:])
        rec = r["recipient"].lower().replace("0x", "")
        la = r["lookalike_address"].lower().replace("0x", "")
        p = int(r["matched_prefix"])
        s = int(r["matched_suffix"])
        good = addr.lower() == r["lookalike_address"].lower() and la[:p] == rec[:p] and (s == 0 or la[-s:] == rec[-s:])
        if good:
            ok += 1
        else:
            print("FAIL:", r["victim"], r["recipient"], r["lookalike_address"], "derived:", addr)
    print(f"verified {ok}/{len(sample)} sampled rows (privkey controls address + prefix/suffix match)")


if __name__ == "__main__":
    main()
