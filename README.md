# CoinXT

**Bitcoin and Ethereum cryptography for OpenXTalk (OXT) / the xTalk family.**

CoinXT gives an xTalk app the primitives a wallet or a dapp client is built from, by wrapping
**trezor-crypto** (the MIT-licensed, dependency-free C crypto core of the Trezor hardware wallet) behind
a thin C ABI and a livecodescript API. One wrap covers both chains:

- **secp256k1** keypairs, ECDSA (RFC 6979 deterministic), **recoverable** signatures and public-key
  recovery (Ethereum's `v` / `ecrecover`), ECDH, and Schnorr / BIP-340 (Taproot).
- **Hashes** both chains need: SHA-256/512, SHA3-256/512, **Keccak-256** (Ethereum's non-NIST padding),
  RIPEMD-160, plus HMAC and PBKDF2-HMAC-SHA512.
- **HD wallets:** BIP-32 derivation, BIP-39 mnemonics (SLIP-39 later).
- **Address and serialization formats:** Base58Check, Bech32 / Bech32m, hex, RLP, xprv/xpub, WIF, and the
  EIP-55 Ethereum checksum.

```
app (livecodescript)
   |
CoinXT (cx*)   src/coinxt.livecodescript
   |- encodings in SCRIPT   hex, Base58Check, Bech32/Bech32m, RLP, addresses (pure byte work)
   |- FFI seam              one .lcb module
CoinXT C shim (cnx_)   native/coinxt.c  +  vendored trezor-crypto (MIT, no external deps)
   |- curve + hashes in C   secp256k1, SHA2/SHA3/Keccak-256/RIPEMD-160, HMAC, PBKDF2, BIP-32, BIP-39
```

## What CoinXT is NOT

- **Not a wallet, node, or broadcaster.** It produces keys, addresses, and signed bytes. The app owns key
  storage, backup, the confirm-before-sign UX, and putting a signed transaction on the wire (optionally
  through Tor via OnionXT, a documentation-level composition).
- **Not new cryptography.** Every curve op and hash is trezor-crypto's. CoinXT adds no cipher of its own,
  the same rule SodiumXT and OnionXT hold.
- **Not hardware-wallet isolation.** It runs in a general-purpose OXT process; script variables are not
  locked memory. It is a strong, correct, self-contained crypto layer, not a secure element.

## Why trezor-crypto

MIT-licensed, plain C, **no external dependencies**, and it bundles secp256k1 (also MIT). That is exactly
what the family's FFI pattern wants: a self-contained C library with a buffer-in / buffer-out API and a
permissive license we can vendor and redistribute. It is the crypto core of a shipping hardware wallet,
so the curve and hash code is battle-tested. CoinXT vendors a subset of its `.c` files plus a small shim
and builds one shared library per platform. No autotools, no submodule tree.

## Layout

```
CoinXT/
  README.md                 you are here
  SPEC.md                   what CoinXT is: the C/script split, the ABI contract, formats, security model
  IMPLEMENTATION-PLAN.md    the phased build order
  CLAUDE.md                 the operational guide + the FFI/C-ABI law (read before touching the shim)
  CMakeLists.txt            the family build: the shared library + the ctest smoke test, all 5 platforms
  templates/
    CLAUDE.md               the portable xTalk/LiveCode/LCB lesson book (ALL the family's generic
                            engine lessons; copy it to the root of any NEW xTalk project)
  .github/workflows/ci.yml  the gates + the native platform matrix; commits refreshed binaries on main
  native/
    coinxt.c                the C shim (cnx_ ABI over the vendored crypto)
    build.sh                the no-dependency developer loop (plain lib + ASan/UBSan self-test)
    MANIFEST.sha256         integrity pins for the vendored SOURCES (the wordlist joins in phase 4)
    vendor/                 the vendored trezor-crypto subset (MIT) + VENDOR.md + LICENSE
  src/
    coinxt.lcb              the foreign-handler module (binds to cnx_*; needs an on-engine pass)
    coinxt.livecodescript   the public cx* API + the phase-3 encodings (hex, Base58Check, Bech32,
                            EIP-55), the BTC/ETH address builders, and BIP-39 mnemonics
    code/                   committed per-platform native libraries (coinxt.so/.dll/.dylib), laid
                            down by CI on main + pinned in src/code/MANIFEST.sha256
  data/
    bip39-english.txt       the canonical BIP-39 English wordlist (2048 words), embedded into
                            coinxt.livecodescript and integrity-checked by coin-kat.py
  tests/
    coinxt_smoke_test.c     walks every cnx_ export once (ctest on every CI lane; ASan via build.sh)
  tools/
    coin-kat.py             known-answer vectors (builds the shim headless, drives it via ctypes)
    package-extension.py    stages src/code/<arch>-<platform>/coinxt.<ext> + its manifest
    check-livecodescript.py the static gate for .lcb / .livecodescript (carried verbatim)
    check-docs-style.py     the house-style gate for .md (carried verbatim)
  examples/
    coinxt-demo.livecodescript    the self-building showcase stack: a branded, tabbed UI
                                  (keys, BTC + ETH addresses, sign/verify/tamper, ecrecover, ECDH,
                                  the Keccak-vs-SHA3 footgun, HMAC/PBKDF2 BIP-39 seed, self-test)
    coinxt-tests.livecodescript   the on-engine self-test harness: put cxSelfTest()
```

## The gates (run before any commit)

```sh
python3 tools/check-livecodescript.py         # static gate for the script layer
python3 tools/check-docs-style.py             # house-style gate for the docs
python3 tools/coin-kat.py --check             # builds the shim, runs the known-answer vectors
sh native/build.sh asan                       # ASan + UBSan native self-test
( cd native && sha256sum -c MANIFEST.sha256 ) # vendored-source integrity
```

All five run in CI (`.github/workflows/ci.yml`), which additionally builds the native library for the
full platform matrix (x86_64/x86 Linux, universal macOS, x86_64/x86 Windows via MinGW) on every push,
runs the C smoke test on each lane, verifies the committed binaries against `src/code/MANIFEST.sha256`,
and commits freshly built binaries back to `src/code/` on main so a clone ships a working extension
(the SodiumXT / TorrentXT model). There is no headless way to compile or run `.livecodescript` / `.lcb`
on OXT, so a script change additionally needs an on-engine pass; the honest status until then is
"designed and statically reasoned" (see [CLAUDE.md](CLAUDE.md)). On a real engine, run
`examples/coinxt-tests.livecodescript` (`put cxSelfTest()`) to re-pin the vectors through the cx* API.

## Status

**Phases 1-2 native done and externally verified; the script layer awaits its on-engine pass.** The
shim (`native/coinxt.c`, ABI 2) over the vendored trezor-crypto subset builds under ASan + UBSan and
exposes the full hash/KDF surface (SHA-256/512, SHA3-256, Keccak-256, RIPEMD-160, HMAC,
PBKDF2-HMAC-SHA512) and the secp256k1 curve surface (keypair, deterministic RFC 6979 ECDSA - always
low-s, recoverable signatures + `ecrecover`, ECDH). `tools/coin-kat.py` pins it all headless: the
classic public RFC 6979 vectors, the seckey range edges, the ecrecover round trip, and - the bar that
matters for a money library - CoinXT signatures VERIFY in the independent python-ecdsa library and
match its outputs byte for byte, in both directions. The `.lcb` foreign module and the public `cx*`
script API are written and pass the static gates; there is no headless OXT compiler, so their honest
status is "designed and statically reasoned; needs an on-engine pass", and the on-engine self-test
harness (`examples/coinxt-tests.livecodescript`) plus the self-building demo stack
(`examples/coinxt-demo.livecodescript`) are ready for that pass; the full stack ran 41/41 on a real
engine (see [CLAUDE.md](CLAUDE.md)). The build and packaging follow the family model: a CMake build, a
5-platform CI matrix, and per-platform binaries committed under `src/code/` on main. **Phase 3
(addresses) and BIP-39 mnemonics are now in**, pure script: hex, Base58Check, Bech32, EIP-55, the BTC
(P2PKH, P2WPKH) + ETH address builders, and `cxMnemonicFromEntropy` / `cxMnemonicValidate` /
`cxMnemonicToSeed` over the embedded 2048-word list - all transcription-verified against Python and
vector-locked in CI to the public BIP-173 / EIP-55 / Trezor BIP-39 vectors (needs an on-engine pass).
Next: BIP-32 HD derivation, the one piece that needs native work (vendored `bip32.c` + an ABI bump).
Schnorr / BIP-340 is deferred to a Taproot phase (upstream provides it only through secp256k1-zkp).

[SPEC.md](SPEC.md), [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md), and [CLAUDE.md](CLAUDE.md) are the
design and the running as-built log. Every deterministic path is pinned to a public known-answer vector,
and the "done" bar for a signing feature is that a CoinXT signature verifies in a mainstream external
library, not just in CoinXT.

CoinXT is an independent library: it does not depend on OnionXT (the two compose at the documentation
level only), and everything it needs (the static gates, the CI workflow, the portable engine-lesson
book, the vendored sources and their manifest) lives in this repository.

## A note on handling money

CoinXT deals with private keys and real funds, so the family's "compose an audited library, never
hand-roll crypto" rule counts double: the curve and hashes are trezor-crypto's, the app owns custody and
confirm-before-sign, and every checksum is verified on decode with a fail-closed error. See the security
model in [SPEC.md](SPEC.md) section 8 and the rules in [CLAUDE.md](CLAUDE.md).

## House style

ASCII only in `.livecodescript` / `.lcb`. No em-dashes anywhere (hyphens, commas, colons,
parentheses). Comment the *why*, densely. Enforced by the carried `check-livecodescript.py` and
`check-docs-style.py` gates.
