# TCP-AO for hitless BGP key rollover

A C implementation of the TCP Authentication Option (RFC 5925) and its
cryptographic algorithms (RFC 5926), built to replace static, never-rotated
TCP MD5 passwords on regional-carrier BGP sessions with **hitless master-key
rollover**: keys change while the TCP session — and every BGP UPDATE riding
on it — stays up.

## Why TCP-AO solves the operational problem

| | TCP MD5 (RFC 2385) | TCP-AO (RFC 5925) |
|---|---|---|
| Keys per connection | 1 | many, indexed by KeyID |
| Change an active key | impractical; both peers must swap inside one MSL, so nobody dares | coordinated in-band via RNextKeyID, no session drop |
| Replay protection across SEQ rollover | none | 32-bit Sequence Number Extension (SNE) |
| MAC | MD5 (broken) | HMAC-SHA-1-96, AES-128-CMAC-96 (+ HMAC-SHA-256 on Linux) |
| Per-connection traffic keys | no | KDF over the 4-tuple and both ISNs |
| Legacy coexistence | — | a listener may hold MD5 keys for old peers and AO keys for upgraded peers (never the same peer) |

## Layered design

```
include/tcpao/        portable, kernel-independent public headers
src/
  crypto_openssl.c    HMAC-SHA1/256 + AES-128-CMAC via OpenSSL EVP
  kdf.c               RFC 5926 counter-mode KDF, RFC 5925 5.2 contexts
  sne.c               RFC 5925 6.2 SNE machine + Linux compute_sne()
  mac.c               RFC 5925 5.1 whole-segment MAC (byte-matches kernel)
  keystore.c          userspace MKT table, longest-prefix lookup
  rollover.c          pure hitless-rollover state machine (no syscalls)
  session.c           daemon-facing orchestration of a full rollover
  kernel_linux.c      Linux TCP_AO_* setsockopt adapter (Linux only)
  kernel_stub.c       non-Linux stubs so everything else is unit-testable
tools/keyctl.c        bgp-ao-keyctl operator CLI
tests/                conformance suite + independent Python reference
```

The KDF, MAC, SNE, keystore and rollover logic never touch a socket. Only
`kernel_linux.c` includes `<linux/tcp.h>`, which is why the entire crypto
and state-machine core builds and tests on a development laptop.

## Hitless rollover, step by step

The two peers cannot flip keys at the same instant. TCP-AO carries two IDs in
every segment: `KeyID` (the sender's current outgoing MKT) and `RNextKeyID`
(the RecvID the sender wants future *incoming* segments to use). The rollover
state machine in `rollover.c` drives four phases; throughout, both old and
new MKTs are installed, so in-flight segments signed with either validate.

1. **PREPARED** — install the new MKT alongside the old (old stays
   `current_key`), then set `rnext_key` to the new RecvID. Every outgoing
   segment now advertises the new ID in `RNextKeyID`. No traffic uses it yet.
2. **SWITCHING** — when the peer's segment arrives with an `RNextKeyID`
   matching an installed MKT, the kernel atomically moves `current_key`
   (RFC 5925 §7.5.2.e). This kernel observation — never a local timer — is
   the only authoritative switch trigger. Reordered old segments may flip
   `current_key` back ("backing up", RFC 5925 §6.1); the machine returns to
   PREPARED and restarts its drain clock rather than deleting anything early.
3. **RETIRING** — after `drain_ms` with **no increase** in `pkt_bad` /
   `pkt_key_not_found`, the old key is provably no longer needed.
4. **STABLE** — delete the old MKT (normal delete; an `EBUSY` here means the
   drain logic misjudged). One MKT remains.

A stall timer aborts a rollover whose peer never engages, removing the
half-installed new key and leaving the old one untouched. Because the old MKT
validates throughout, no authenticated segment — and therefore no BGP UPDATE —
is dropped.

### Why no route update is lost

- Both keys validate incoming segments for the entire overlap window.
- The old key is deleted only after a clean drain longer than the peer's
  maximum reorder/ACK delay, and only while failure counters are flat.
- TCP retransmits any segment that *is* dropped anyway; with both keys
  present validation never fails, so retransmission never has to cover a
  rekey-induced drop.

## Sequence Number Extension

`sne.c` provides both SNE variants. The RFC 5925 §6.2 state machine
(`PREV_SEQ` + `SNE_FLAG`, 0x7fff boundaries) is used for conformance and
userspace packet handling; `tcpao_sne_kernel()` mirrors Linux
`tcp_ao_compute_sne()`, which derives the SNE from `rcv_nxt`/`snd_una` over a
2^31 window. The SNE is the first thing fed to the MAC (big-endian), so a
replayed segment from a previous 32-bit sequence-number wrap fails
authentication even after the low 32 bits repeat. The test suite cross-checks
the two algorithms across millions of segments and multiple full wraps.

## Legacy MD5 coexistence

A `TCP_LISTEN` socket may carry both key *types* — `TCP_MD5SIG_EXT` for
RFC 2385-only boxes and `TCP_AO_ADD_KEY` for upgraded peers — but never both
for the same peer prefix (the kernel enforces this). An established
connection cannot migrate between the two options; migration happens by
configuring the upgraded peer's AO key and letting its session re-establish,
while the legacy fleet keeps working unchanged. See `tcpao_md5_listener_add()`.

## Kernel requirements

- Linux ≥ 6.10 with `CONFIG_TCP_AO=y`, plus `CONFIG_CRYPTO_CMAC`,
  `CONFIG_CRYPTO_HMAC`, `CONFIG_CRYPTO_SHA1`, `CONFIG_CRYPTO_SHA256`.
- uAPI: `TCP_AO_ADD_KEY`, `TCP_AO_DEL_KEY`, `TCP_AO_INFO`,
  `TCP_AO_GET_KEYS`, `TCP_AO_REPAIR` (`include/uapi/linux/tcp.h`).
- Probe at runtime with `tcpao_kernel_supported()`.
- `TCP_AO_REPAIR` checkpoints/restores ISNs and SNEs across a daemon restart
  so a long-lived BGP session survives process replacement.

## Building and testing

```sh
make test     # regenerate vectors, build, run the full suite
make cli      # build build/bgp-ao-keyctl
```

The suite runs on macOS and Linux (OpenSSL ≥ 1.1; Homebrew paths are detected
automatically). It contains:

- **KDF conformance** — every RFC 5926 counter-mode derivation reproduced
  byte-for-byte, including the AES-CMAC variable-length master-key extraction.
- **Segment MAC** — whole-segment tags match an independent Python reference;
  tamper and SNE-change detection asserted.
- **SNE** — RFC reference sequence plus 3M-segment cross-check against the
  Linux windowed algorithm across multiple wraps.
- **Rollover** — happy path, reorder back-off, stall abort, double-begin,
  retirement regression, all driven deterministically with a synthetic clock.
- **Keystore** — longest-prefix lookup, RFC 5925 ID-overlap rejection,
  secret wipe on delete.

### Independent reference and cross-implementation interop

`tests/vectors/gen_vectors.py` reimplements RFC 5925/5926 from the RFC text
alone (AES-CMAC hand-written per RFC 4493 and validated against the RFC's
printed examples plus an OpenSSL oracle) — it shares no code with the C
library, so agreement is a genuine conformance signal. Bidirectional
interop checks (C signs / Python verifies and vice versa) confirm the two
independent implementations produce identical traffic keys and segment tags.

## Operator tool

```sh
bgp-ao-keyctl -f <fd> key-add PEER/PREFIX SNDID RCVID ALG MACLEN HEXKEY [--current]
bgp-ao-keyctl -f <fd> info            # current_key, rnext, TCPAO* counters
bgp-ao-keyctl -f <fd> key-del PEER/PREFIX SNDID RCVID
bgp-ao-keyctl -f <fd> md5-add PEER/PREFIX HEXKEY   # legacy peer
bgp-ao-keyctl -f <fd> goodbye PEER/PREFIX SNDID RCVID
bgp-ao-keyctl -f <fd> require on|off
```

In production the CLI talks to the routing daemon's control socket (the
daemon owns the BGP socket fds); the `-f fd` form is for lab bring-up.

## Security notes

- Master keys live in process memory and are zeroized with
  `OPENSSL_cleanse` on every teardown/delete path; never logged.
- The MKT table rejects overlapping SendID/RecvID on the same connection
  identifier (RFC 5925 §3.1) so an incoming segment always matches exactly
  one MKT.
- Deciding when to *start* a key is a performance choice (the rollover
  protocol); deciding when to *remove* an old key is a security decision
  enforced by the drain + flat-counters gate. Force-delete
  (`tcpao_kernel_force_del_key`) exists only for a peer that ignores
  RNextKeyID and may break the session.
- Default 96-bit MACs; any length 4–16 bytes is supported per the kernel.
