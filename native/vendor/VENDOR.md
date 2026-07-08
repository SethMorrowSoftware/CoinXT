# Vendored third-party sources

These files are copied verbatim (no local patches) from **trezor-firmware**, directory `crypto/`.

- Upstream: https://github.com/trezor/trezor-firmware  (directory `crypto/`)
- License: **MIT** (see `LICENSE` in this directory)
- Pinned commit: `230cfe37e4c5fefb6ca117725d261a7b3646a995` (branch `main`, fetched 2026-07-02)

## Files (phases 1-2: hashes, KDFs, and the secp256k1 curve)

| file | purpose |
|---|---|
| `sha3.h` / `sha3.c` | Keccak-256 (Ethereum, 0x01 padding) and SHA3-256 (NIST FIPS-202, 0x06) |
| `sha2.h` / `sha2.c` | SHA-256 and SHA-512 |
| `ripemd160.h` / `ripemd160.c` | RIPEMD-160 (Bitcoin hash160) |
| `hmac.h` / `hmac.c` | HMAC-SHA256 / HMAC-SHA512 |
| `pbkdf2.h` / `pbkdf2.c` | PBKDF2-HMAC-SHA256/512 (BIP-39 seed derivation) |
| `bignum.h` / `bignum.c` | the 256-bit bignum the curve math runs on |
| `ecdsa.h` / `ecdsa.c` | ECDSA sign/verify/recover, pubkey derivation, ECDH |
| `secp256k1.h` / `secp256k1.c` | the secp256k1 curve parameters |
| `curves.h` / `curves.c` | curve name registry |
| `rfc6979.h` / `rfc6979.c` | deterministic k (RFC 6979) |
| `hmac_drbg.h` / `hmac_drbg.c` | the HMAC-DRBG rfc6979.c is built on |
| `hasher.h` / `hasher.c` | the hash dispatcher `ecdsa.c` links against |
| `blake256.*`, `blake2b.*`, `blake2_common.h`, `groestl.*`, `groestl_internal.h` | hash variants `hasher.c` dispatches to (link-time deps only; CoinXT never selects them) |
| `address.h` / `address.c`, `base58.h` / `base58.c`, `script.h` | link-time deps of `ecdsa.c`'s address helpers (CoinXT builds addresses in script and does not call these) |
| `rand.h` | declares `random_buffer` / `random32`; the implementation is CoinXT's (see below) |
| `bip32.h`, `ed25519-donna/ed25519.h` | headers only: `secp256k1.h` needs bip32.h's `curve_info` type, and bip32.h in turn needs ed25519.h's typedefs. `bip32.c` and the ed25519-donna `.c` files are NOT vendored: CoinXT transcribes trezor's secp256k1-only child-key derivation into `../coinxt.c` instead (see below) |
| `memzero.h` / `memzero.c` | best-effort secret wiping used by the hash contexts |
| `byte_order.h` | endianness macros used by `sha3.c` |
| `options.h` | trezor-crypto compile-time config (USE_KECCAK=1, USE_RFC6979=1, ...) |

Deliberately NOT vendored:

- `secp256k1.table` (the precomputed curve-point table): `options.h` sets `USE_PRECOMPUTED_CP` to 0,
  so `secp256k1.c` never includes it. If a future phase flips that flag for speed, vendor the table in
  the same change.
- `rand.c`: trezor-crypto requires an integrator-supplied `random_buffer`. CoinXT implements it in
  `../coinxt.c` over the OS CSPRNG. NOTE the phase-0 assumption ("nothing should call the RNG once
  signing is RFC 6979") turned out to be FALSE at this commit: `ecdsa.c` calls `random32()` on every
  curve operation for side-channel blinding (the Jacobian z randomization in `curve_to_jacobian`, and
  the scalar split in `tc_ecdsa_sign_digest`). That randomness never reaches an output (every result
  stays a pure function of the inputs, pinned by the KATs); it only randomizes the internal compute
  path, so wiring it to abort would have broken every call, and wiring it weakly would silently defeat
  upstream's hardening.
- the zkp / secp256k1-zkp files (`zkp_ecdsa.*`, `zkp_bip340.*`, `vendor/secp256k1-zkp`): only compiled
  under `USE_SECP256K1_ZKP_ECDSA`, which CoinXT does not define.
- `bip32.c` and the ed25519-donna `.c` files: `bip32.c` is multi-curve and drags the whole tree (aes,
  cardano, nem, nist256p1, the ed25519-donna subtree, mostly unconditional includes). CoinXT needs only
  the secp256k1 child-key derivation, so `../coinxt.c` transcribes trezor's OWN sequence
  (`hdnode_private_ckd_bip32`) over the audited primitives already vendored (hmac_sha512, bn_add/bn_mod,
  ecdsa_get_public_key33), pinned byte-for-byte to the official BIP-32 test vectors.

ABI 3 additions - BIP-32, BIP-340 Schnorr, BIP-341 Taproot - added NO new vendored files. Each is a
standard PUBLIC scheme (a key-derivation scheme or a signature scheme), transcribed step for step over
the primitives already vendored - the same discipline as the script-side address encoders, and the
opposite of hand-rolling a curve op or a hash. BIP-340/341 compose `scalar_multiply` (k*G),
`point_multiply` (k*P), `point_add`, `uncompress_coords` (lift_x), the `bn_*` modular arithmetic, and
`sha256`; the bn_* usage mirrors trezor's own `tc_ecdsa_sign_digest` / `_verify_digest`. Every path is
pinned to the official vectors (BIP-32, the BIP-340 test file including the invalid cases, BIP-86
Taproot addresses) in `../../tools/coin-kat.py`, and cross-checked against an independent BIP-340
reference. Vendoring secp256k1-zkp for Schnorr was considered and rejected: it is a far larger and
riskier surface than composing ops that are already audited here.

Later phases add `bip32.c` / `bip39.c` (HD + mnemonic; note bip32.c pulls the ed25519-donna subtree)
and the BIP-39 wordlist.

## Rules (CLAUDE.md)

- **Verbatim only.** Do not edit a vendored file in place. If a patch is ever unavoidable, record it here
  with a diff and a reason, and hash the patched file in `MANIFEST.sha256`.
- **Re-pin deliberately.** Bumping the upstream commit is its own change: update the SHA above, re-run
  `tools/coin-kat.py`, refresh `../MANIFEST.sha256`, and note anything that shifted.
- The MIT `LICENSE` ships alongside these files (redistribution requirement).

## Integrity

Every vendored file (and, from the packaging phase on, every shipped release binary) is pinned in
`../MANIFEST.sha256`, checked in CI. Verify locally with:

```sh
cd native && sha256sum -c MANIFEST.sha256
```

Any legitimate change to a vendored file (a re-pin, a recorded patch) refreshes the manifest in the
SAME change; a mismatch anywhere else means the tree is not what was reviewed.
