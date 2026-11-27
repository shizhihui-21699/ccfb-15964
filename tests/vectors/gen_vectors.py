#!/usr/bin/env python3 -I
"""Independent reference implementation of RFC 5925/5926 KDF and MAC.

This generator is deliberately written from the RFC text alone (plus
RFC 4493 for AES-CMAC), sharing no code with the C library, so agreement
between the two is a real conformance signal rather than a tautology.

Outputs tests/vectors/vectors.json consumed by the C unit tests.
"""
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import socket
import struct
import sys

# ---------------------------------------------------------------- AES-128
_lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
_lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_lib.EVP_aes_128_ecb.restype = ctypes.c_void_p
_lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_char_p,
                                    ctypes.c_char_p]
_lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                   ctypes.POINTER(ctypes.c_int),
                                   ctypes.c_char_p, ctypes.c_int]
_lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(key) == 16 and len(block) == 16
    ctx = _lib.EVP_CIPHER_CTX_new()
    try:
        assert _lib.EVP_EncryptInit_ex(
            ctx, _lib.EVP_aes_128_ecb(), None, key, None) == 1
        out = ctypes.create_string_buffer(16)
        n = ctypes.c_int(0)
        assert _lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(n), block, 16) == 1
        return out.raw[:16]
    finally:
        _lib.EVP_CIPHER_CTX_free(ctx)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _left_shift(b: bytes) -> bytes:
    # Parentheses matter: shift first, then fold the 129th bit away.
    n = (int.from_bytes(b, "big") << 1) & ((1 << 128) - 1)
    return n.to_bytes(16, "big")


def cmac_subkeys(key: bytes):
    """RFC 4493 section 2.3 subkey generation."""
    L = aes128_encrypt_block(key, b"\x00" * 16)
    K1 = _left_shift(L)
    if L[0] & 0x80:
        K1 = _xor(K1, b"\x00" * 15 + b"\x87")
    K2 = _left_shift(K1)
    if K1[0] & 0x80:
        K2 = _xor(K2, b"\x00" * 15 + b"\x87")
    return K1, K2


def aes128_cmac(key: bytes, msg: bytes) -> bytes:
    """RFC 4493 AES-CMAC, variable-length message."""
    K1, K2 = cmac_subkeys(key)
    if len(msg) == 0:
        last = _xor(b"\x80" + b"\x00" * 15, K2)
        complete = b""
    else:
        tail_len = len(msg) % 16
        if tail_len == 0:
            # Full final block: K1, and all preceding blocks are complete.
            last = _xor(msg[-16:], K1)
            complete = msg[:-16]
        else:
            # Partial final block: 10^i padding then K2.
            tail = msg[-tail_len:]
            pad = b"\x80" + b"\x00" * (15 - tail_len)
            last = _xor(tail + pad, K2)
            complete = msg[:-tail_len]
    x = b"\x00" * 16
    for i in range(0, len(complete), 16):
        x = aes128_encrypt_block(key, _xor(x, complete[i:i + 16]))
    return aes128_encrypt_block(key, _xor(x, last))


# ------------------------------------------------------------- RFC 5926 KDF
# RFC 5926 3.1.1: label is the 6-character ASCII string "TCP-AO" with no
# NUL (confirmed by Linux struct kdf_input_block { u8 label[6]; memcpy 6 }).
LABEL = b"TCP-AO"


def kdf_prf(alg: str, master: bytes, block: bytes) -> bytes:
    if alg == "hmac-sha1":
        return hmac.new(master, block, hashlib.sha1).digest()
    if alg == "hmac-sha256":
        return hmac.new(master, block, hashlib.sha256).digest()
    if alg == "aes128-cmac":
        # RFC 5926 Figure 1: extract unless master is exactly 128 bits.
        k = master if len(master) == 16 else aes128_cmac(b"\x00" * 16, master)
        return aes128_cmac(k, block)
    raise ValueError(alg)


def kdf(alg: str, master: bytes, context: bytes, outlen: int) -> bytes:
    out_bits = outlen * 8
    stream = b""
    counter = 1
    while len(stream) < outlen:
        block = bytes([counter]) + LABEL + context + struct.pack(">H", out_bits)
        stream += kdf_prf(alg, master, block)
        counter += 1
    return stream[:outlen]


def v4_context(src, dst, sport, dport, sisn, disn):
    return (socket.inet_aton(src) + socket.inet_aton(dst)
            + struct.pack(">HHII", sport, dport, sisn, disn))


def mac(alg: str, tkey: bytes, maclen: int, message: bytes) -> bytes:
    if alg == "hmac-sha1":
        full = hmac.new(tkey, message, hashlib.sha1).digest()
    elif alg == "hmac-sha256":
        full = hmac.new(tkey, message, hashlib.sha256).digest()
    elif alg == "aes128-cmac":
        full = aes128_cmac(tkey, message)
    else:
        raise ValueError(alg)
    return full[:maclen]


def main():
    vectors = {"cases": []}

    # Fixed, non-random test material (documented test-only secrets).
    master16 = bytes(range(16))                      # 00..0f
    master20 = b"RFC5925-test-master-0123"[:20]
    master_var = b"regional-carrier-bgp-secret"     # 26 bytes, non-16 -> CMAC extract

    local = "192.0.2.1"
    remote = "198.51.100.2"
    lport, rport = 179, 41234
    lisn, risn = 0x11223344, 0x55667788

    ctx_send = v4_context(local, remote, lport, rport, lisn, risn)
    ctx_recv = v4_context(remote, local, rport, lport, risn, lisn)
    ctx_syn = v4_context(local, remote, lport, rport, lisn, 0)

    for alg, klen in (("hmac-sha1", 20),
                      ("aes128-cmac", 16),
                      ("hmac-sha256", 32)):
        for mk_name, mk in (("m16", master16), ("m20", master20),
                            ("mvar", master_var)):
            tk_send = kdf(alg, mk, ctx_send, klen)
            tk_recv = kdf(alg, mk, ctx_recv, klen)
            tk_syn = kdf(alg, mk, ctx_syn, klen)
            vectors["cases"].append({
                "name": f"kdf-{alg}-{mk_name}",
                "alg": alg,
                "master_hex": mk.hex(),
                "context_hex": ctx_send.hex(),
                "outlen": klen,
                "traffic_key_send_hex": tk_send.hex(),
                "traffic_key_recv_hex": tk_recv.hex(),
                "traffic_key_syn_hex": tk_syn.hex(),
            })

    # --- Whole-segment MAC vectors --------------------------------------
    # Minimal BGP-ish segment: 20-byte base header + 16-byte AO option
    # (kind 29, len 16, KeyID=7, RNextKeyID=9, 12-byte MAC) + 8-byte data.
    def build_segment(mac_value: bytes):
        # Wire layout: byte 12 high nibble is data offset in 32-bit words.
        # Base header (5) + 16-byte AO option = 9 words -> 0x90.
        # Field order: ..., dataoff/flags, window(8192), checksum(0), urg(0).
        th = struct.pack(">HHIIHHHH", rport, lport,
                         0x99aabbcc, 0x01020304,
                         (9 << 12), 8192, 0, 0)
        ao = struct.pack(">BBBB", 29, 16, 7, 9) + mac_value
        return th + ao + b"BGPUPDATE"[:8]

    sne = 0x00000002
    seg_template = build_segment(b"\x00" * 12)
    pseudo = (socket.inet_aton(local) + socket.inet_aton(remote)
              + b"\x00" + struct.pack(">B H", 6, len(seg_template)))
    message = struct.pack(">I", sne) + pseudo + seg_template

    for alg, tklen, mk in (("hmac-sha1", 20, master16),
                           ("aes128-cmac", 16, master_var),
                           ("hmac-sha256", 32, master20)):
        tkey = kdf(alg, mk, ctx_send, tklen)
        tag = mac(alg, tkey, 12, message)
        vectors["cases"].append({
            "name": f"mac-{alg}",
            "alg": alg,
            "master_hex": mk.hex(),
            "context_hex": ctx_send.hex(),
            "traffic_key_send_hex": tkey.hex(),
            "sne": sne,
            "pseudo_hex": pseudo.hex(),
            "segment_zeroed_hex": seg_template.hex(),
            "expected_mac_hex": tag.hex(),
            "maclen": 12,
        })

    # SNE rollover sequence for cross-checking both C implementations.
    vectors["sne_sequence"] = [
        # (seg_seq inputs around the 0x7fff boundary, expected RFC5925 SNE)
    ]
    prev_sne = 0
    seqs = [100, 0x7000, 0x7fff, 0x8000, 0x8001, 0xfffffff0,
            0x00000005, 0x00000006, 0x7ffe, 0x7fff, 0x8000, 0x8001]
    # RFC 5925 reference state machine, transcribed directly from 6.2.
    sne = 0
    prev = 0
    flag = 0
    for s in seqs:
        if flag == 0 and prev > 0x7fff and s < 0x7fff:
            sne += 1
            flag = 1
        use = sne - 1 if (flag == 1 and s > 0x7fff) else sne
        if prev < 0x7fff and s > 0x7fff:
            flag = 0
        prev = s
        vectors["sne_sequence"].append({"seq": s, "sne": use})

    out = os.path.join(os.path.dirname(__file__), "vectors.json")
    with open(out, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"wrote {out}: {len(vectors['cases'])} KDF/MAC cases, "
          f"{len(vectors['sne_sequence'])} SNE steps")


if __name__ == "__main__":
    sys.exit(main())
