# CLAUDE.md - CoinXT

This file guides Claude Code (claude.ai/code) when working in the CoinXT sub-project.

> **Read the docs first.** [SPEC.md](SPEC.md) is the source of truth for WHAT CoinXT is (the C/script
> split, the ABI contract, the formats, the security model). [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md)
> is the phased HOW. This file is the operational as-built record and the hard-won-lesson list, in the
> same spirit as the sibling `CLAUDE.md` files (SodiumXT, OnionXT, TorrentXT). The portable
> [templates/CLAUDE.md](templates/CLAUDE.md) (carried into this project so it survives the split into
> its own repository) carries the generic xTalk/LCB engine lessons; this file adds what is specific
> to CoinXT: a native crypto shim that handles money.

House style: no em-dashes (hyphens, commas, colons, parentheses). ASCII only in `.lcb` /
`.livecodescript`, even in comments and strings. Comment the *why*, densely; match the surrounding style.

## What this is

**CoinXT** is a Bitcoin and Ethereum cryptography layer for OpenXTalk (OXT). It wraps **trezor-crypto**
(MIT, plain C, no external deps, the crypto core of a hardware wallet) behind a thin C ABI and a
livecodescript API, so an xTalk app can make keys, derive HD wallets from a mnemonic, build addresses,
and sign and verify for both chains. It adds no cryptography of its own; every curve op and hash is
trezor-crypto's.

```
app (livecodescript)
   |
CoinXT public API (cx*)   src/coinxt.livecodescript
   |- encodings in SCRIPT: hex, Base58Check, Bech32/Bech32m, RLP, xprv/xpub, WIF, EIP-55, addresses
   |- FFI seam: one .lcb module, unsafe ... end unsafe around every foreign call
CoinXT C shim (cnx_)   native/coinxt.c  +  vendored trezor-crypto subset
   |- curve + hashes in C: secp256k1 (ECDSA/recoverable/recover/ECDH/Schnorr),
      SHA2/SHA3/Keccak-256/RIPEMD-160, HMAC, PBKDF2, BIP-32 node math, BIP-39 seed
```

## How CoinXT differs from its siblings (read before you assume)

1. **Unlike OnionXT, CoinXT HAS a C shim, and it is central.** OnionXT is pure script over engine
   sockets; its FFI section is carried "just in case." CoinXT's whole point is the shim, so the
   **FFI/C-ABI conventions below are law from day one**, and every shim change builds under ASan + UBSan
   and bumps the ABI + `cxCheckABI()` on any ABI change (the SodiumXT / TorrentXT discipline).
2. **Unlike OnionXT, CoinXT does no I/O and holds no long-lived state.** No sockets, no daemon, no accept
   loop, no lifecycle. Every call is a pure, synchronous, deterministic function: bytes in, bytes out.
   The async/state-machine discipline OnionXT needed does NOT apply. There is nothing to close.
3. **Like SodiumXT, CoinXT is bytes-in / bytes-out crypto, and composes it.** It is closest to SodiumXT
   in shape (a stateless crypto wrap), but it wraps a different C library and covers a different domain
   (coin curves, hashes, HD wallets, address formats).
4. **CoinXT handles money.** A wrong byte is not a bug report, it is lost funds. Every rule below that
   says "fail closed" or "verify the checksum" or "compose audited code, never hand-roll" counts double.

## The rules that make this safe and correct

1. **Add no cryptography. Wrap trezor-crypto.** Every scalar multiply, signature, and hash is upstream,
   audited code. A missing primitive is a new vendored file or an upstream request, never a hand-rolled
   curve op or hash here. There is no CoinXT cipher.
2. **The app owns key custody; CoinXT is a calculator.** CoinXT holds a key only for the microseconds of
   one operation. Storage, backup, and confirm-before-sign are the app's. Document the boundary loudly.
3. **Sign only the exact digest the app hands you.** `cxSign` takes a 32-byte hash. CoinXT does not build
   your sighash / transaction preimage in the primitive layer, and even in the tx-building phase the app
   confirms the decoded human intent. A blind signer is a footgun.
4. **Fail closed on every malformed input.** A bad Base58Check / Bech32 / EIP-55 checksum, an
   out-of-range scalar, a wrong-length buffer, a non-canonical signature: return a clean `"CoinXT: ..."`
   error, never a wrong-but-plausible key or address. Verify every checksum on decode.
5. **Secret hygiene across the FFI (see below).** Private keys, seeds, chaincodes cross as `Data` /
   `Pointer`, are `memzero`ed in the shim after use, and are NEVER returned as a bridged C string. The
   script layer clears its own key variables the moment it is done, and the docs state the honest limit
   (OXT script variables are not locked memory).
6. **Deterministic by design.** RFC 6979 signing needs no randomness; fresh key material comes from the
   caller (compose SodiumXT `sxRandomBytes`). No output-affecting RNG in the shim (the OS CSPRNG feeds
   only upstream's internal side-channel blinding; see "Determinism and entropy"). Every operation is a
   pure function of its inputs, so every operation is KAT-testable.

## Commands

**Static gate for the script layer** (carried verbatim from OnionXT / SodiumXT; the checkers ship in
THIS project's `tools/` so CoinXT is self-contained when it moves to its own repository):
```sh
python3 tools/check-livecodescript.py
python3 tools/check-docs-style.py
```
It checks smart/curly quotes, em/en dashes, block balance, constants-before-use, the prefixed-token
shadow trap, the `put ... into ... after` malformation, and (for `.lcb`) a missing
`use com.livecode.foreign` and `textEncode`/`textDecode` used inside a module.

**The C shim builds under sanitizers** (from phase 1):
```sh
sh native/build.sh asan        # ASan + UBSan build of tests/coinxt_smoke_test.c, run
sh native/build.sh             # plain shared lib, bare token name coinxt.<ext>
```
Treat trezor-crypto headers as system headers (`-isystem`) so their warnings do not pollute `-Wall
-Wextra`. Bump `cnx_abi_version()` + the `.lcb` `cxCheckABI()` on every ABI change.

**The family build (CI matrix + packaging) is CMake** (the SodiumXT / TorrentXT model):
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCOINXT_BUILD_TESTS=ON
cmake --build build && ctest --test-dir build --output-on-failure
python3 tools/package-extension.py --build-dir build     # stage src/code/<arch>-<platform>/coinxt.<ext>
```
Keep the vendored-source list in `CMakeLists.txt` and `native/build.sh` in step. CI builds all five
platform lanes (x86_64/x86 linux, universal-mac, x86_64/x86 win32) on every push and commits the
refreshed binaries to `src/code/` on main only (`[skip ci]`; the TorrentXT lesson: a per-branch binary
commit collides with main's in an unresolvable add/add conflict). Windows lanes build with MinGW
(MSYS2), NOT MSVC: the vendored code uses gcc-isms (`__attribute__((packed))` in blake2b.c) and
vendored files are never patched.

**Known-answer vectors** (the correctness net for a money library):
```sh
python3 tools/coin-kat.py --check
```
Every deterministic path is pinned to a PUBLIC vector (RFC 6979, BIP-32/39, BIP-173/350, EIP-55,
Keccak), cross-checked against an independent implementation before pinning. A signature CoinXT makes
must also verify in a mainstream library, not just in CoinXT.

**There is no headless way to compile or run `.livecodescript` on OXT.** So a script change is "designed
and statically reasoned; needs an on-engine pass" until it has loaded the real `.lcb` in an engine and
round-tripped the `cx*` calls. The shim, by contrast, IS testable headless (the KAT harness can call it).

## The C-vs-script split (hold this line)

Anything that touches a private key or a curve point is **C** (audited trezor-crypto). Anything that is
checksummed byte-shuffling with no secret-dependent branch is **livecodescript**, pinned by a KAT. This
keeps the trusted native surface tiny (about 25 buffer-in / buffer-out functions, SPEC section 5.1) and
puts hex / Base58Check / Bech32 / RLP / address composition where they are easy to read, diff, and test,
exactly as OnionXT does base32 in script. Do NOT push encodings into the shim to "keep it together", and
do NOT re-implement a curve op in script to "avoid the FFI".

## FFI / C-ABI conventions (LAW here, not carried-for-later)

The single most expensive thing the family has learned. Change nothing here without a very good reason.

- **Byte buffers cross as `Pointer` + `CInt` length. An LCB `Data` does NOT auto-bridge to `void*`** (it
  marshals as an opaque `MCDataRef`). An **out** buffer is a raw block from the engine `<builtin>`
  `MCMemoryAllocate`, passed as a real `Pointer`; the shim writes into it and returns bytes written, or
  `-needed` (negative required size) when the block is too small, and the LCB layer re-allocates, retries,
  and copies back with `MCDataCreateWithBytes`. An **in** buffer passes `MCDataGetBytePtr(theData)` plus
  its length.
- **`MCMemoryAllocate`'s size is C `size_t`, so it marshals as `UIntSize`, NOT `CUInt`.** A 4-byte int
  into an 8-byte size slot on a 64-bit build corrupts the heap.
- **There is no 64-bit foreign int.** A value that can exceed 2^31 (a PBKDF2 iteration count is fine at
  32-bit; a satoshi amount is not) crosses as a decimal `ZStringUTF8` string, parsed in the shim.
- **Reals cross as `double`, booleans as `int` (0/1).** Exported symbols keep the stable `cnx_` prefix
  and are NEVER renamed once shipped (the `.lcb` `binds to` strings reference them by name; a rename is a
  silent bind failure at load). `<builtin>` handlers resolve by name, so no leading underscore.
- **Never RETURN a bridged C string** (`ZStringUTF8` / `NativeCString`) from a foreign handler: the
  engine adopts the returned pointer and later `free()`s it, so a static or library-owned return is
  free()-on-static, heap corruption on the first call. This is doubly dangerous with key material. Fill a
  caller buffer and return length / `-needed`.
- **Pass a null pointer only through an `optional Pointer`** parameter (e.g. an absent BIP-340 aux_rand);
  a plain `Pointer` rejects `nothing`.
- **Bump the ABI version on any ABI change**, and have `cxCheckABI()` throw a clear "reinstall CoinXT"
  error on skew instead of corrupting memory on first use. Expose every length constant from the shim as
  a function (`cnx_seckey_len` = 32, ...); never hardcode a size in LCB.
- **`textEncode` / `textDecode` are NOT available to an LCB module** (livecodescript only), so bytes
  cross as `Data` and text<->Data conversion stays in the livecodescript layer.
- **`unsafe ... end unsafe` brackets every foreign call**, and keep all `local` declarations at the TOP
  of the handler (a nested `local` has broken whole-script compilation). **`use com.livecode.foreign`**
  whenever a foreign type is named.

## Determinism and entropy

- **No output-affecting RNG in the shim.** trezor-crypto requires an integrator `random_buffer` /
  `random32`. The phase-0 plan was to wire it to ABORT ("nothing should call it once signing is
  RFC 6979"), but that assumption is FALSE at the vendored commit: `ecdsa.c` calls `random32()` on
  EVERY curve operation for side-channel blinding (`curve_to_jacobian` randomizes the Jacobian z
  coordinate; the signing path additionally splits the nonce with a random scalar), so an abort would
  break every call and a weak stub would silently defeat upstream's hardening. It is therefore wired to
  the OS CSPRNG (`getrandom` / `arc4random_buf` / `BCryptGenRandom`), used ONLY for that internal
  blinding: no output depends on it (every result stays KAT-pinned) and no key material ever comes from
  it. It aborts loudly if the OS cannot supply entropy rather than continue with weakened blinding.
- **Fresh key material is the caller's.** `cxNewSeckey(pEntropy32)` validates 32 caller-supplied bytes
  (from SodiumXT `sxRandomBytes`, or OS entropy). Seeds and mnemonics are deterministic from there.
- Because everything is a pure function of its inputs, the whole surface is pinned by `tools/coin-kat.py`.
  If a result is not reproducible, something is wrong.

## Secret hygiene

- Private keys / seeds / chaincodes: `Data` in, `Data`/`Pointer` across the FFI, `memzero`ed in the shim
  after the operation, never a returned bridged string. The `cx*` layer does `put empty into tSeckey` as
  soon as it is done with one.
- **Honest limit, documented:** OXT script variables are not locked (mlock) memory, so a seed held in
  script can be paged to disk. CoinXT on a general-purpose desktop is not hardware-wallet isolation; do
  not market it as such. The trust boundary is the machine.
- Do not log key material. Do not put a seckey or a seed in an error string, a status message, or a
  committed test fixture (KATs use PUBLIC test-vector keys only, which are burned and safe to publish).

## Encodings in script (the OnionXT base32 discipline)

- **Byte discipline:** build with `numToByte` / `binaryEncode`, parse with `byteToNum` / `binaryDecode`
  (a FUNCTION that fills an out var: `get binaryDecode(...)`), index with `byte x to y of`. Never `char`
  / `line` / `word` on binary. Keep a base32/base58/bech32 bit-buffer small and masked each step so a
  long payload never builds a > 2^53 integer (precision loss). Route integer div/mod through helpers and
  avoid `^` in a compound expression (some OXT parsers reject it).
- **Verify every checksum on decode and fail closed:** Base58Check's 4-byte double-SHA-256 tail,
  Bech32/Bech32m's polymod (constant 1 vs 0x2bc830a3, SegWit v0 vs v1+), EIP-55's mixed case. A corrupt
  address must be rejected, never coerced.
- **Keccak-256 is NOT SHA3-256.** Ethereum uses the original `0x01` padding; FIPS-202 uses `0x06`. Two
  different shim functions (`cnx_keccak256` vs `cnx_sha3_256`); never alias them. This is the classic
  Ethereum footgun.
- Pin every encoding to its public vector (BIP-173/350 including INVALID cases, EIP-55 examples, the RLP
  yellow-paper examples).

## LiveCodeScript / LCB / OXT gotchas (carried; see [templates/CLAUDE.md](templates/CLAUDE.md) for the full list)

The generic list applies verbatim. The ones most likely to bite CoinXT:
- No smart/curly quotes anywhere (fails OXT compilation).
- The prefixed-token-shadow trap (`t/p/s/k` name whose full spelling is a reserved token); the checker's
  `RESERVED` set is only as complete as we keep it - add any new one found on-engine.
- Operators that look like functions: `bitAnd`/`bitOr` are operators; `binaryDecode`/`binaryEncode` are
  functions that fill an out var; `^` may be rejected in a compound expression.
- `is a <type>` has no `is a string`; commands report via `the result`, functions return a value.
- `constant` is declared with `=` in livecodescript but with `is` in LCB; the wrong form is a
  compile error that kills the whole file (confirmed on-engine; the checker now gates it).
- A whole `.livecodescript` compiles as a unit; a syntax error in one handler breaks the file.

## Handles and long-lived state

CoinXT is stateless: there is nothing to open, close, or free. The BIP-32 HD node crosses the ABI as a
**fixed-size opaque byte blob** (version || depth || fingerprint || child || chaincode || key), NOT as a
handle into a C-side table, so no generation-tagged handle machinery is needed. Keep it that way; if a
future feature ever needs C-side state, use SodiumXT's generation-tagged handle-table pattern (positive
32-bit ints, 0 invalid, a stale handle a clean error), never a raw pointer through script.

## Testing and conformance

- Pin every deterministic path with a PUBLIC known-answer vector in `tools/coin-kat.py`, cross-checked
  against an independent implementation (Python `ecdsa` / `eth-utils` / `pycryptodome`) BEFORE pinning.
- The gold standard for a signing test: a signature CoinXT produces VERIFIES in a mainstream external
  library, and an HD wallet from a standard mnemonic reproduces a reference address byte for byte.
- Ship a demo and a pure offline self-test harness formatted like OnionXT's (sPass/sFail, KAT sections,
  a section that SKIPS rather than fails when an optional dependency is absent).

## Git / workflow

- Develop on a per-task branch; commit there, open a **draft PR** if none exists. Do not push to `main`
  without explicit permission.
- A script change is "done" once the static gates pass and it has had (or is clearly flagged as needing)
  an on-engine pass. A shim change is "done" once it builds clean under ASan + UBSan, the KATs pass, and
  the ABI + `cxCheckABI()` are bumped in the SAME change.
- Two manifests, two jobs (do not merge them): `native/MANIFEST.sha256` pins the vendored trezor-crypto
  SOURCES; `src/code/MANIFEST.sha256` pins the committed native BINARIES (written by
  `tools/package-extension.py`, verified by the CI `verify-binaries` job). A local native change
  refreshes the binary for YOUR platform via `package-extension.py` in the same change; CI refreshes
  all platforms on merge to main. Vendored trezor-crypto files are third-party code: record the
  upstream commit and any local patch in `VENDOR.md`; hash the sources and the wordlist in
  `native/MANIFEST.sha256`; never edit a vendored file in place silently.
- A change that needs a new SodiumXT primitive (e.g. a specific KDF) splits: the upstream feature lands
  first, then CoinXT composes it.
- **No em-dashes** in committed prose or docs. Comment the *why*, densely.

## As-built notes

Record on-engine and cross-library results here as they are learned: the exact trezor-crypto commit
vendored, any upstream quirk, the confirmed accepted-key formats, and each `VERIFY:` promoted to fact
once a CoinXT signature verifies externally.

**Phase 1, hash slice - DONE and verified (2026-07-02).** The FFI/build pipeline is proven end to end:

- Vendored the trezor-crypto SHA-3 unit (`sha3.c/h`, `memzero.c/h`, `byte_order.h`, `options.h`) at
  commit `230cfe37e4c5fefb6ca117725d261a7b3646a995` (see `native/vendor/VENDOR.md`; MIT `LICENSE`
  shipped). Note `byte_order.h` is header-only (there is no `byte_order.c` upstream; a fetch of it 404s).
- `native/coinxt.c` exposes `cnx_abi_version`, `cnx_keccak256`, `cnx_sha3_256`, and the length functions.
  It builds via `native/build.sh` (a plain shared lib for ctypes/LCB, and an ASan+UBSan self-test).
- Verified: the ASan/UBSan self-test runs clean; `cnx_keccak256` matches the published Ethereum vectors
  (`keccak256("")` = `c5d2...a470`), `cnx_sha3_256` matches Python `hashlib` (NIST FIPS-202), and the two
  are provably distinct (the Keccak-vs-SHA3 footgun guarded in `tools/coin-kat.py`).
- `tools/coin-kat.py --check` builds from source and runs the vectors headless (`self-check OK`). This is
  the CoinXT analogue of OnionXT's KAT harness; it grows with each phase.

Still to do in phase 1: nothing native-side for hashes; the `.lcb` foreign module (the on-engine binding)
is written and confirmed in a later step, since it needs a real OXT engine to load. Next up (phase 2):
the secp256k1 curve surface (keypair, ECDSA, recoverable, recover, ECDH), with a signature that must
verify in an independent library.

**Repo-prep - self-contained for the split (2026-07-07).** CoinXT no longer reaches outside its own
directory for anything; it is ready to become the root of its own repository (the procedure and the
post-split checklist were in MIGRATION.md, deleted once the move completed):

- The static gates (`tools/check-livecodescript.py`, `tools/check-docs-style.py`) are carried verbatim
  into `tools/`, alongside `tools/coin-kat.py`. Every `../` reference in the docs was retargeted.
- The portable xTalk/LCB lesson book is carried at `templates/CLAUDE.md`, synced byte-identical with
  OnionXT's copy at fork time (including the newest on-engine lessons: the `the detailedFiles` "bad
  factor", the unchecked `accept connections` bind failure, the CRLF returned by `read ... until crlf`,
  and the streaming no-quantifier read). After the split each repo maintains its own copy, the family
  pattern; keep appending to the living-gotcha log.
- CI ships at `.github/workflows/ci.yml`: both static gates, the vendored-source `MANIFEST.sha256`
  check, `coin-kat.py --check` (builds the shim from source, drives it via ctypes), and the ASan/UBSan
  self-test. It was dormant while CoinXT was nested (GitHub reads only the repo root's `.github/`) and
  went live on the split.
- `native/MANIFEST.sha256` pins every vendored trezor-crypto file now, ahead of the packaging phase
  (release binaries join it there). Refresh it in the same change as any vendor re-pin.

**Split complete; phases 1-2 native DONE and externally verified; script layer written (2026-07-08).**
CoinXT is now its own repository. The post-split checklist ran in this change: the CI workflow moved to
`.github/workflows/ci.yml` (the upload had dropped the leading dot, leaving CI dormant), MIGRATION.md
and the README staging paragraph were removed. Still the owner's call: a top-level project LICENSE (the
MIT file in `native/vendor/` covers only the vendored code) and protecting `main`.

- Vendored the full phase-1/2 trezor-crypto subset at the SAME pinned commit `230cfe3...` (sha2,
  ripemd160, hmac, pbkdf2, bignum, ecdsa, secp256k1, curves, rfc6979, hmac_drbg, plus ecdsa.c's
  link-time deps hasher/address/base58/blake256/blake2b/groestl and the header-only bip32.h /
  ed25519-donna/ed25519.h that secp256k1.h's `curve_info` needs; see VENDOR.md). The fetch pipeline was
  verified by re-fetching `sha3.c` and diffing byte-identical against the already-pinned copy.
  `secp256k1.table` is NOT needed (options.h sets `USE_PRECOMPUTED_CP 0`); the zkp/secp256k1-zkp path
  is compiled out (`USE_SECP256K1_ZKP_ECDSA` undefined).
- **Upstream quirk, the big one:** the phase-0 "wire the RNG to abort" plan was WRONG for this commit;
  `ecdsa.c` calls `random32()` on every curve op for side-channel blinding. Decision recorded in
  "Determinism and entropy" (and VENDOR.md): `random_buffer` is implemented in the shim over the OS
  CSPRNG, blinding-only, outputs stay KAT-pinned deterministic, loud abort on entropy failure.
- **Upstream quirk, conventions:** upstream return conventions are mixed (`ecdsa_sign_digest` /
  `_verify_digest` / `_recover_pub_from_sig` / `ecdh_multiply` return 0 on success; `ecdsa_read_pubkey`
  / `_uncompress_pubkey` return 1 on success; `_verify_digest` uses 1 for a bad pubkey and 2..5 for bad
  signatures). The shim normalizes ALL of it to the cnx_ codes. Upstream `ecdsa_sign_digest` enforces
  low-s itself (`s > n/2` is negated, recovery bit flipped), so cnx_ signatures are always canonical.
- `native/coinxt.c` now exports the full phase-1 hash/KDF surface (`cnx_sha256/512`, `cnx_ripemd160`,
  `cnx_hmac_sha256/512`, `cnx_pbkdf2_hmac_sha512`), the phase-2 curve surface (`cnx_seckey_verify`,
  `cnx_pubkey_from_seckey`, `cnx_pubkey_decompress`, `cnx_ecdsa_sign` / `_verify`,
  `cnx_ecdsa_sign_recoverable` / `_recover`, `cnx_ecdh` = raw SEC1 x-coordinate), `cnx_wipe` (the LCB
  layer's pre-deallocate secret scrub, added to SPEC 5.1), and the matching length functions.
  **ABI is 2**; recoverable signatures carry the RAW recid 0..3 (Ethereum's 27/EIP-155 offset is
  script-side presentation). Verification keeps upstream semantics (a mathematically valid high-s
  signature from another producer verifies; malformed r/s fail closed); everything CoinXT PRODUCES is
  low-s.
- Verified headless: ASan/UBSan self-test walks every export clean; `tools/coin-kat.py` pins the classic
  public RFC 6979 secp256k1 vectors (r, s, low-s, determinism), ecrecover round-trip (wrong recid
  rejected), seckey range edges (0, n, n-1, 2^256-1), ECDH symmetry, and the hash/HMAC/PBKDF2 surface
  against hashlib/hmac. **VERIFY promoted to fact:** CoinXT signatures verify in python-ecdsa (0.19.2),
  python-ecdsa's RFC 6979 signatures match CoinXT's after low-s normalization, pubkeys and the ECDH
  x-coordinate agree byte for byte, and python-ecdsa signatures verify in CoinXT. CI installs `ecdsa`
  so the external cross-check runs on every push.
- `src/coinxt.lcb` (the FFI seam; `cxb*` public handlers, all marshalling, all length checks, cnx_ code
  to "CoinXT: ..." throw mapping, `cxbCheckABI`) and `src/coinxt.livecodescript` (the public `cx*` API
  with the fail-closed string/boolean contract and the key-variable clearing) are written and pass the
  static gate. Honest status: **designed and statically reasoned; NEEDS AN ON-ENGINE PASS.** Confirm
  on-engine and record here: (a) the binds-to library element `"c:coinxt>..."` resolves to the shipped
  libcoinxt binary per platform; (b) whether `MCDataGetBytePtr` of an empty Data surfaces as `nothing`
  (the `cnxDataPtr` sentinel path); (c) that returning a non-nothing `optional Pointer` as `Pointer`
  compiles (same helper).
- Schnorr / BIP-340 was DEFERRED here, then DELIVERED in phase 4b by transcription rather than by
  vendoring secp256k1-zkp (see the phase-4b as-built note below); this line records the original call.
- Local build outputs (`native/libcoinxt.*`) are gitignored; committed per-platform binaries arrive
  deliberately in the packaging phase, pinned in `MANIFEST.sha256`.

Next up: phase 3 (encodings and addresses, pure script, KAT-pinned) and the on-engine pass for the
`.lcb` + `cx*` layer; then phase 4 (HD wallets + mnemonics; note bip32.c pulls the ed25519-donna
subtree, so plan that vendoring deliberately).

**Family build/CI, on-engine harness, and demo stack (2026-07-08, follow-up).** Pulled the packaging
and example machinery forward to the SodiumXT / TorrentXT shape, after reading both siblings' repos:

- `CMakeLists.txt` is the family build: one shared library from committed sources only (no external
  dependency, unlike both siblings), bare token name `coinxt.<ext>` (PREFIX ""), Windows linking
  bcrypt for the blinding RNG hook. `tests/coinxt_smoke_test.c` (promoted out of build.sh's heredoc)
  runs under ctest on every lane AND under `build.sh asan`. `native/build.sh` stays as the
  no-dependency developer loop; keep its vendor list in step with CMakeLists.txt.
- `tools/package-extension.py` (adapted from SodiumXT) stages `src/code/<arch>-<platform>/coinxt.<ext>`
  and writes `src/code/MANIFEST.sha256`. The engine resolves `"c:coinxt>"` from that packaged layout
  via the revLibraryMapping; this settles the phase-1 open question about the binds-to library element
  (same mechanism sodium.lcb uses, VERIFIED on-engine there).
- CI now mirrors the siblings: the fast `gates` job (the original five), a 5-lane `native` matrix
  (x86_64-linux, x86-linux -m32, universal-mac, x86_64/x86-win32 via MSYS2 MinGW; MSVC cannot build
  the vendored gcc-isms and vendored files are never patched), `verify-binaries` (blob/manifest drift
  gate, passes cleanly while src/code is still empty), `bundle`, and `commit-binaries` (main only,
  `[skip ci]`, needs Actions "Read and write" workflow permissions to push). Trigger is push-only plus
  workflow_dispatch (the TorrentXT lesson: pull_request would double every matrix run).
- `src/coinxt.lcb` was re-aligned, construct for construct, with the VERIFIED-on-engine sodium.lcb:
  `library org.openxtalk.library.coinxt` + metadata block, `use com.livecode.arithmetic` (for `<`),
  `MCDataGetLength` as CUInt (uindex_t) instead of byte-chunk syntax, locals as Integer/CBool,
  `_cnx_*` private foreign-handler names. One deliberate divergence, flagged in the header: an empty
  Data never reaches `MCDataGetBytePtr` (a 1-byte module-lifetime sentinel is passed with length 0).
- `examples/coinxt-tests.livecodescript` (`put cxSelfTest()`) re-pins the public vectors through the
  real cx* API on-engine (hashes, RFC 4231 HMAC, PBKDF2, RFC 6979, ecrecover, ECDH, the negative
  paths), reporting sPass/sFail like OnionXT's harness and skipping everything with one clear message
  if the extension is not loaded. `examples/coinxt-demo.livecodescript` is the self-building showcase
  stack (sodium-demo pattern: palette, prefix:role control names, one mouseUp router); its keys are
  loudly PUBLIC (the "correct horse battery staple" derivation) with optional SodiumXT entropy,
  capability-gated by try/catch. Both pass the static gate; both NEED AN ON-ENGINE PASS.

**FIRST ON-ENGINE PASS (2026-07-08): the whole native + FFI + script stack VERIFIED on a real
engine.** The harness's first full run reported 36 ok / 5 FAIL, and the 36 settle every open
question that mattered:

- **VERIFY promoted to fact:** the packaged extension loads, the `"c:coinxt>"` binds resolve against
  `code/<arch>-<platform>/coinxt.<ext>` (cxCheckABI passed: extension + native library + ABI 2
  match); the MinGW-built Windows binary works as shipped (imports only bcrypt/KERNEL32/msvcrt,
  verified by inspection AND by running); the empty-Data sentinel path works (`keccak256(empty)`
  matched its vector); and EVERY crypto path is byte-exact through all three layers on-engine:
  Keccak/SHA-2/SHA-3/RIPEMD/hash160/hash256, RFC 4231 HMAC, the BIP-39-shaped PBKDF2, seckey
  range edges, pubkey(1) == G both forms, decompress round trip, the classic RFC 6979 signature
  (low-s, deterministic, verifies under both pubkey forms), corrupt-signature rejection, ecrecover
  round trip (wrong recid rejected), and the pinned ECDH x-coordinate (symmetric across forms).
- The 5 FAILs were ONE bug, in the script layer's error contract: an error thrown inside an LCB
  handler reaches a livecodescript catch variable as the engine's STRUCTURED execution-error list
  (code,line,column,hint lines) with our "CoinXT: ..." text embedded as a hint, NOT verbatim (only
  script-level throws arrive verbatim), so `cxIsError`'s `begins with` test missed it. Fixed by
  normalizing at every catch site (`cxMakeError` in coinxt.livecodescript); recorded in the
  templates/CLAUDE.md living log. Needs one re-run to confirm 41/41.
- Two more paid-for-on-engine lessons from the same pass, both logged and gated where possible:
  livecodescript constants are declared with `=` (the `is` form is LCB-only; checker-gated), and
  calling a function in a not-yet-loaded sibling script library raises "Function: error in function
  handler" with the function name as hint (the examples now preflight inside try/catch and say
  which layer is missing).

**Phase 3 - encodings and addresses, pure script (2026-07-08).** The address layer that turns a key
into a fundable-looking address landed in `src/coinxt.livecodescript`, entirely in script over the
existing primitives (no native change, no ABI bump):

- New public API: `cxHexEncode` / `cxHexDecode`, `cxBase58CheckEncode` / `cxBase58CheckDecode`
  (byte-array long division, no big integer ever formed; the checksum is recomputed and compared on
  decode, fail closed), `cxBech32Encode` (8->5 bit repack with a MASKED accumulator, the BIP-173
  polymod with `bitXor` / factored `div`, bech32 const 1 for v0 and bech32m 0x2bc830a3 for v1+),
  `cxEthAddress` / `cxEthAddressChecksum` (Keccak-256 + the EIP-55 mixed-case rule), and
  `cxBtcAddressP2PKH` / `cxBtcAddressP2WPKH`. P2TR is deferred with Schnorr.
- **How a money-critical SCRIPT encoder is verified without an engine:** the exact livecodescript
  algorithm was transcribed 1:1 to Python and run against the canonical public vectors before pinning
  (this caught three mis-transcribed bech32 generator constants on the first pass -
  `0x26508e6d` / `0x1ea119fa` / `0x2a1462b3`, whose decimals I had wrong). The pinned addresses are the
  famous ones: `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` (BIP-173) and
  `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` (pk=1). `tools/coin-kat.py` now derives the pubkey from
  the real shim and reference-encodes it in Python, asserting the result equals those public vectors -
  so CI LOCKS the expected strings the on-engine harness checks (coin-kat cannot drive the
  livecodescript, only lock its expected outputs). `examples/coinxt-tests.livecodescript` runs the
  encoders on-engine (Base58Check round trip + corrupt-checksum rejection, all three address types,
  EIP-55 idempotence and fail-closed length check). Honest status: **designed, transcription-verified,
  and vector-locked; NEEDS AN ON-ENGINE PASS.**
- The demo grew an **Addresses** tab (eight tabs now; the tab labels were shortened so the row still
  fits the 900px window): one key -> P2PKH, P2WPKH, and Ethereum addresses, with copy buttons.

Next: BIP-39 seed phrases (pure script + the shipped 2048-word list; `mnemonic -> seed` already works
via `cxPbkdf2HmacSha512`), then BIP-32 HD derivation (the one piece that NEEDS native work - the child
key tweak is secp256k1 scalar/point math, so it means vendoring `bip32.c`, an ABI bump to 3, and
rebuilt binaries).

**Phase 4a - BIP-39 mnemonics, pure script (2026-07-08).** Seed phrases landed in
`src/coinxt.livecodescript`, still no native change (the `mnemonic -> seed` step is the existing
`cxPbkdf2HmacSha512`):

- New public API: `cxMnemonicFromEntropy` (entropy 16-32 bytes -> checksum bits from `cxSha256` ->
  11-bit word indices via a MASKED accumulator), `cxMnemonicValidate` (rebuilds the entropy bytes with
  a bounded byte buffer - NOT a 264-bit integer, which would blow past 2^53 - and re-checks the
  checksum, fail closed), and `cxMnemonicToSeed` (PBKDF2-HMAC-SHA512, 2048 iters, salt
  "mnemonic" + passphrase, 64 bytes).
- **The 2048-word English wordlist is EMBEDDED** in the `.livecodescript` (a `cxBip39Ensure` command
  builds a return-delimited cache once; lookups use `lineOffset` with `the wholeMatches`), so the
  library is self-contained. It is byte-identical to `data/bip39-english.txt` (the canonical list,
  sha256 `2f5eed...24dbda`). `tools/coin-kat.py` verifies that file's hash AND parses the embedded
  block out of the `.livecodescript` and asserts it equals the file, so the embed cannot silently
  drift. The bounded from-entropy and validate algorithms were transcribed 1:1 to Python and checked
  against the Trezor BIP-39 vectors (128 and 256 bit) before pinning; those vectors are locked in
  coin-kat and re-run on-engine in `examples/coinxt-tests.livecodescript` (generate, validate, reject
  a tampered checksum word, reject a non-word, derive the pinned seed, reject wrong-length entropy).
- **NFKD limit, documented:** the English wordlist and ASCII passphrases are already NFKD, so the seed
  is byte-exact; a non-ASCII passphrase would need NFKD the engine does not apply here.
- The demo's "Derive" tab became a **Seed** tab: click once to make a fresh 12-word phrase (SodiumXT
  entropy if present, else a fixed DEMO value), see the checksum validate green, and get the 64-byte
  master seed, with a note that deriving the account keys at `m/44'/.../...` is the next step.

Next (the last wallet piece): BIP-32 HD derivation. This is the one that NEEDS native work - the child
key tweak is secp256k1 scalar/point math - so it means vendoring `bip32.c` (which pulls the
ed25519-donna subtree), new `cnx_hdnode_*` exports, an ABI bump to 3, `cxCheckABI` to 3, and rebuilt
per-platform binaries.

**Phase 4b - BIP-32 HD, BIP-340 Schnorr, BIP-341 Taproot; ABI 3, TRANSCRIBED not vendored
(2026-07-08).** The three remaining curve features landed together in ONE ABI bump (to 3), so the
family never eats a second bump for a piece we could have batched. The key decision, twice: compose the
audited primitives already vendored, do NOT drag in a huge new tree.

- **BIP-32 CKD.** trezor's `bip32.c` is multi-curve and pulls aes/cardano/nem/nist256p1/ed25519-donna
  (mostly unconditional includes). CoinXT needs only secp256k1, so `native/coinxt.c` transcribes
  trezor's OWN `hdnode_private_ckd_bip32` sequence over hmac_sha512 + bn_add/bn_mod +
  ecdsa_get_public_key33. The node crosses the ABI as a 73-byte opaque blob
  (`depth|parent_fp|child|chaincode|priv`); xprv/xpub are FRAMED IN SCRIPT (version bytes +
  Base58Check), so no extra native call. `coin-kat.py` reconstructs each node's full xprv AND xpub the
  exact way `cxXprv`/`cxXpub` do (from the blob fields + the shim's pubkey) and asserts equality to the
  OFFICIAL BIP-32 vector-1 strings - which caught a mistyped master xpub (a dropped trailing `8`), the
  same self-defending reconstruction the address vectors use.
- **BIP-340 Schnorr.** Transcribed the BIP-340 reference pseudocode step for step over `scalar_multiply`
  (k*G), `point_multiply` (k*P), `point_add`, `uncompress_coords` (= lift_x), the `bn_*` modular
  arithmetic, and `sha256` (the tagged hash is `SHA256(SHA256(tag)||SHA256(tag)||m)`). The bn_*
  discipline (read_be, mod, multiply, add, subtract-for-negate, is_odd for even-y) MIRRORS trezor's own
  `tc_ecdsa_sign_digest` / `_verify_digest` - I read both before writing. Signing is deterministic:
  `aux_rand` is a CALLER-supplied optional 32-byte buffer (NULL -> 32 zero bytes, BIP-340's default),
  no shim RNG feeds the output. CoinXT signs a FIXED 32-byte message (like its ECDSA; Taproot always
  signs a 32-byte sighash), so the variable-length BIP-340 vectors (15-18) are out of scope by design.
  **VERIFY promoted to fact, headless:** the shim's signatures are byte-exact against BOTH the official
  BIP-340 vectors (rows 0-14) AND an independent BIP-340 reference implementation carried in
  `coin-kat.py`; verify accepts every valid case and fails closed on every invalid one (off-curve
  pubkey, `has_even_y(R)` false, `sG-eP` infinite, `r >= p`, `s >= n`, pubkey x past the field size).
- **BIP-341 Taproot.** `cnx_taproot_tweak_pubkey` computes the key-path output key
  `Q = P + int(hash_TapTweak(P))*G` (lift_x the internal key, add the tweak point), pinned to the
  official BIP-86 vectors (internal key -> output key -> `bc1p` address). `cxBtcAddressP2TR` does the
  tweak then Bech32m-frames the witness-v1 program. **A latent money bug surfaced here:**
  `cxBech32Encode`'s witness-v1+ bech32m constant was `719259665`, not `0x2bc830a3` (734539939) - the
  v1 path had NEVER been exercised (only P2WPKH/v0 shipped). Fixed, and locked: the livecodescript
  encoder was transcribed 1:1 to Python and shown to reproduce all three BIP-86 `bc1p` addresses (and
  still the BIP-173 `bc1q`). Lesson: an untested code path in a money encoder is a bug waiting for its
  first caller; add the KAT the moment the path becomes reachable.
- **The batch.** BIP-32 + Schnorr + Taproot in one ABI bump added ZERO new vendored files. Everything
  else (xprv/xpub, WIF, RLP, tx-building) stays script and needs no further native bump; the rich
  73-byte node blob keeps serialization script-side. The `.lcb` binds all seven new exports (aux_rand
  as an `optional Pointer`), and the `cx*` layer adds `cxHdFromSeed`/`cxHdDerive`/`cxHdDerivePath`
  (clears each intermediate parent node) / `cxHdSeckey`/`Pubkey`/`ChainCode` / `cxXprv`/`cxXpub`,
  `cxXonlyFromSeckey`/`cxSchnorrSign`/`cxSchnorrVerify`, and `cxTaprootOutputKey`/`cxBtcAddressP2TR`.
  The demo's Seed tab became a full **Wallet** tab (phrase -> seed -> BIP-84 account xpub -> first
  SegWit and Taproot receiving addresses), and Addresses grew a fourth (Taproot) line. Native done +
  externally verified under ASan/UBSan and coin-kat; the `.lcb` + `cx*` + demo layer is
  transcription- and vector-locked but **NEEDS AN ON-ENGINE PASS** (add testHd/testSchnorr/testTaproot
  to the 41/41 harness run, and confirm the `optional Pointer` NULL-aux path compiles/binds on-engine).

**ABI-3 on-engine pass + a Base58Check-decode bug (2026-07-08, follow-up).** The harness ran 72/74 on a
real engine. Everything ABI-3 is now VERIFIED on-engine: `cxCheckABI` matched (extension + ABI-3 native
library loaded and every new bind resolved, so the merged all-platform binaries are good and the
`optional Pointer` NULL-aux Schnorr path binds), and testHd (BIP-32 xprv/xpub + path), testSchnorr
(BIP-340 vector 0 + empty-aux default) and testTaproot (BIP-86 `bc1p`) all passed. The 2 FAILs were a
PRE-EXISTING phase-3 bug the new decode-side test finally exercised: `cxB58Decode` looked up each char
with `offset(char, alphabet)`, and **`the caseSensitive` defaults to FALSE**, so a lowercase Base58 digit
matched the earlier uppercase one (`g`->`G`) and the decode produced wrong bytes (then failed its own
checksum). Encode was unaffected (it indexes the alphabet directly). Fixed with `set the caseSensitive to
true` in `cxB58Decode` (and defensively in `cxBase58CheckDecode`, whose 4-byte checksum compare must be
byte-exact); transcribed 1:1 to Python to confirm the valid address now yields version 0x00 + the
`751e76e8...` hash160 and a corrupt checksum is still rejected. Logged in the templates/CLAUDE.md living
gotcha list (item 5.10). Lesson, again: the first time a money code-path is exercised end to end is when
its latent bug surfaces - the decode side had shipped untested behind an encode-only address flow.

**Phase 5 - wallet restore, WIF, nested SegWit, EIP-191, Bech32 decode; the demo becomes a wallet
showcase (2026-07-08).** All pure script: no native change, no ABI bump, binaries untouched (still
ABI 3).

- New public API in `src/coinxt.livecodescript`: `cxWifEncode` / `cxWifDecode` (WIF, version
  0x80/0xEF, the 0x01 compressed marker, key range re-checked on decode, fail closed),
  `cxBtcAddressP2SH_P2WPKH` (BIP-49 nested SegWit; REQUIRES the 33-byte compressed key - a 65-byte
  key would frame a script standard wallets cannot spend, so it fails closed), `cxEthPersonalHash`
  (EIP-191: 0x19 || "Ethereum Signed Message:" || 0x0A || decimal byte length || message, Keccak-256;
  sign it with `cxSignRecoverable`, recover the ADDRESS with `cxRecover` + `cxEthAddress`), and
  `cxBech32Decode` (the exact inverse of `cxBech32Encode`: rejects mixed case, bad characters, bad
  checksums, the WRONG CONSTANT for the witness version - v0 must be bech32, v1+ bech32m - bad 5->8
  padding, and bad program lengths, per BIP-173/350). Decode return contracts follow
  cxBase58CheckDecode's established shape: metadata lines first, binary payload LAST (`line N to -1`).
  Both new decoders set `the caseSensitive` (the item-5.10 lesson, applied at write time).
- Same verification discipline as phases 3/4, BEFORE pinning: each algorithm mirrored 1:1 in Python
  (`run_phase5_encoder_checks` in coin-kat) and run against the famous WIF pair of sk=1, the
  P2SH-P2WPKH address of pubkey(1), the BIP-173/350 valid AND invalid decode sets plus encode->decode
  round trips, and EIP-191 digests derived through TWO independent keccaks (the pure-Python reference
  and the shim) plus a shim-level personal-sign -> ecrecover -> address round trip.
- **The restore anchor** (`run_restore_checks`): the canonical "abandon...about" mnemonic, driven
  through the real shim HD nodes, reproduces the OFFICIAL BIP-84 and BIP-86 first addresses (strings
  printed in the BIPs themselves - they anchor the whole mnemonic -> seed -> path -> key -> address
  chain), plus the published BIP-44 / BIP-49 / ETH m/44'/60' firsts, the BIP-84 account xpub, and the
  first key's WIF. The on-engine harness re-runs the same chain (`testRestore`, `testWif`,
  `testBech32Decode`, `testEthPersonal`, and the P2SH vector in `testAddresses`).
- **The demo is now ten tabs.** Wallet RESTORES any typed/pasted BIP-39 phrase (the checksum gate
  first, fail closed on a typo) or generates 12/24 fresh words, then shows the first receiving
  address of EVERY standard account type (BIP-44/49/84/86 + Ethereum m/44'/60'), the watch-only
  account xpub, and the first key's WIF; it starts prefilled with the canonical test phrase so every
  line can be checked against any mainstream wallet. New Schnorr tab (BIP-340 sign / verify / tamper
  reject, plus the BIP-341 tweak to the bc1p address). The Ethereum tab now runs the EIP-191
  personal_sign flow end to end (sign a typed message, recover the signer's ADDRESS, v shown raw and
  as 27/28). New Decode tab: paste any address / WIF / xprv / xpub / 0x string and see it verified
  and taken apart - or REJECTED on one flipped character (Base58Check version classification, bech32
  witness-program classification, EIP-55 case check with the single-case "legal but unprotected"
  distinction, extended-key field breakdown, and loud THIS-IS-A-PRIVATE-KEY warnings on WIF/xprv).
  Addresses adds the nested-SegWit line and a mainnet/testnet toggle; Keys adds the WIF line.
- Honest status: headless-verified and vector-locked everywhere Python can reach; the new script
  paths and demo tabs NEED AN ON-ENGINE PASS (the new harness sections are the checklist; expect the
  count to grow from 74 to about 100).

**Phase 5b - RLP, the EIP-155 offline transaction, and the fidelity-listing round (2026-07-08).**
Still pure script: no native change, ABI 3, binaries untouched. This round makes the demo prove the
whole offline-signing chain and lets a restore be checked against another wallet at a glance:

- New public API: `cxRlpBytes` / `cxRlpList` / `cxRlpUIntBytes` / `cxRlpUIntDec`. The design is
  COMPOSABLE (encode each item, concatenate, wrap with `cxRlpList`; nest by wrapping again) so no
  nested list structure ever crosses an API boundary - this supersedes SPEC's earlier
  `cxRlpEncode(pList)` sketch, and `cxRlpDecode` is deferred until a consumer needs it.
  `cxRlpUIntDec` takes a DECIMAL string of any size (a wei amount is far past 2^53) and converts via
  the cxB58Encode byte-array multiply-accumulate, so no big integer is ever formed; it fails closed
  on a non-digit. Locked to the yellow-paper vectors in coin-kat and on-engine (`testRlp`).
- **The EIP-155 anchor:** the official example transaction printed in the EIP itself (key 0x46..46,
  nonce 9, 20 gwei, 21000 gas, to 0x3535..35, 1 ETH, chain 1) is reproduced BYTE FOR BYTE through
  the shim - signing hash, r, s, v=37, and the full raw tx - in coin-kat
  (`run_rlp_eip155_checks`), on-engine (`testEthTx`), and the demo self-test. That pins the whole
  chain: RLP -> keccak -> RFC 6979 recoverable sign -> EIP-155 v -> RLP reassembly. (Verified
  before pinning: the shim's deterministic signature IS the EIP's published r/s.)
- The demo's ETH tab builds and signs a complete EIP-155 transaction from ON-SCREEN fields - the
  confirm-before-sign posture rule 3 requires (the tx composition lives in the app layer; the
  library only encodes, hashes, signs). The to-address is EIP-55-gated: a wrong mixed-case checksum
  refuses to sign; single-case is accepted (it carries no checksum).
- The Wallet tab's restore now prints a TEN-address fidelity listing per chain (segwit receive
  #0..#9 plus change #0, eth accounts #0..#9), derived one `cxHdDerive` step at a time from a
  cached chain node, plus the account xprv beside the xpub (with its warning). The listing's
  continuation is anchored, not just row #0: receive #1 and change #0 are printed in BIP-84
  itself, and eth #1 is the published second account - all three pinned in coin-kat's
  RESTORE_VECTORS and re-run in `testRestore`.
- Keys shows the x-only (BIP-340) key form; Hashes adds the HMAC-SHA256/512 lines.
- Honest status: same as phase 5 - headless-verified and vector-locked everywhere Python can
  reach; the new script paths NEED AN ON-ENGINE PASS (`testRlp` / `testEthTx` / the extended
  `testRestore` are the checklist).

**Phase 5c - offline Bitcoin transactions (BIP-143) and the paste-your-own round (2026-07-08).**
Still pure script: no native change, ABI 3, binaries untouched. Two goals: sign a REAL Bitcoin
transaction offline, and let a user bring their own test material to every tab.

- New public API: `cxSigToDer` (strict BIP-66 DER from the raw 64-byte r||s; trims leading zeros,
  0x00-pads a set high bit), `cxAddressToScript` (scriptPubKey for ANY decodable address - P2PKH,
  P2SH, every witness version, both networks; the underlying checksum verification means a typo'd
  DESTINATION yields an error, never a spendable-looking script), and `cxBtcTxSignP2WPKH` (one
  P2WPKH or BIP-49 nested input, any standard outputs, BIP-143 SIGHASH_ALL, RFC 6979, witness
  serialization; returns txid & sighash & raw tx; fails closed on every malformed field AND on
  outputs exceeding the input - a negative fee can only be a mistake). This is the tx-building
  LAYER rule 3 anticipated: the caller shows fields + fee to a human; the library only encodes,
  hashes, signs.
- **The BIP-143 anchor:** the official P2SH-P2WPKH example in the BIP (every intermediate printed:
  hashPrevouts/hashSequence/hashOutputs, preimage, sighash, DER signature, final tx) is reproduced
  BYTE FOR BYTE through the shim - the deterministic RFC 6979 signature IS the published one, the
  same lucky-but-checkable fact as EIP-155. Locked in coin-kat (`run_btc_tx_checks`, with mirrors
  of all three functions and constructed DER padding/trimming edges plus a python-ecdsa DER parse
  cross-check when available), on-engine (`testBtcTx`), and the demo self-test. The example values
  were fetched from the BIP text itself, not memory (bips.dev 403'd; the raw GitHub mirror served
  it).
- **The demo is now eleven tabs.** New BTC Tx tab: funding outpoint / outputs / version-sequence-
  locktime fields, a native-vs-nested toggle, the fee always computed on screen, and a one-click
  "Load the BIP-143 example" preset (adopts the example's published key) so Sign visibly reproduces
  the BIP's raw bytes. Paste-your-own everywhere else: Keys imports a WIF or raw-hex key; Wallet
  gained a derivation-path explorer (any typed path -> all five address forms + pubkey + WIF +
  xprv/xpub); Sign verifies a PASTED pubkey + signature against the message (sign here, verify in
  python-ecdsa, or the reverse); ECDH combines YOUR key with a pasted peer pubkey; Hashes accepts
  0x-prefixed raw hex.
- Honest status: headless-verified and vector-locked everywhere Python can reach; the new script
  paths NEED AN ON-ENGINE PASS (`testBtcTx` + the new demo flows are the checklist).

**Demo layout pass - the 720p footprint (2026-07-08).** Pure geometry/presentation, demo file only
(no library, harness, KAT, or native change). The stack moved from 900x700 to 1200x680 so it fits a
1280x720 display with window chrome to spare, the family-demo posture (wide and shallow, not tall):

- One shared grid across all eleven tabs: content column x 48..1152 inside the 24..1176 panel,
  header at y 128, paragraph from 158, the primary action row at ~210-248, and ONE status-line
  position (y 596-628) on every tab, so the eye never hunts for the verdict.
- The tab bar is eleven equal 102px tabs on a 105px rhythm, flush with the panel edges, with FULL
  labels (Addresses, Ethereum, Hashes) instead of the 900px abbreviations.
- The 1104px mono column fits every value on one line: a 65-byte pubkey, a 64-byte signature, a
  full sha512/hmac512 (cxdShort, the truncating preview helper, is gone - nothing needs shortening
  now), xprv/xpub strings, and the BIP-143/EIP-155 raw txs wrap once instead of four times.
- Primary buttons lead every action row (the BTC Tx tab's Sign moved from right to first, matching
  the other tabs); copy/preset/toggle buttons follow.
- Still NEEDS AN ON-ENGINE PASS like every demo change (pure layout, so the checklist is visual:
  no clipped labels, the measured-height cxdLabel fitting still behaves at the new widths).

**Phase 6 - PSBT (BIP-174): the cold-signer surface (2026-07-08).** The demo-to-tool turn: CoinXT
now speaks the interchange format Sparrow / Electrum / Core exchange, so it works as an air-gapped
signer. Pure script over the existing primitives (no native change, ABI 3, binaries untouched).

- New public API: `cxPsbtDecode` (parse a base64/hex PSBT, report the intent: every input with
  outpoint/amount/type/sig-count, every output with address/amount, the fee when knowable - the
  confirm-before-sign view), `cxPsbtSign` (add SIGHASH_ALL partial signatures for the single-key
  SegWit inputs - native P2WPKH and BIP-49 nested - the key controls; pKey is a raw 32-byte seckey
  matched by pubkey hash OR a 73-byte HD master node, in which case the PSBT's own
  BIP32_DERIVATION entries are walked: fingerprint gate, per-entry path derivation via cxHdDerive,
  derived-pubkey-equals-entry AND program check), and `cxPsbtFinalize` (single-key witnesses built
  from the partial sigs; extracts txid + the broadcast-ready network tx). Multisig, legacy P2PKH,
  and Taproot inputs DECODE and report but do not sign here yet (recorded scope). Internal
  helpers throw "CoinXT: ..." (script-level throws arrive verbatim in catch); the public three
  catch and return the error-string contract. The engine's base64Encode WRAPS LINES; cxPsbtB64
  strips them (a paid-for gotcha, avoided at write time).
- Anchors, verified in Python mirrors BEFORE transcription (`run_psbt_checks` in coin-kat): the
  OFFICIAL BIP-174 creator vector parses and re-encodes BYTE-EXACT (order-preserving maps); a
  PSBT wrapping the official BIP-143 example signs to the BIP's PUBLISHED DER and finalizes to
  the BIP's PUBLISHED raw tx; an unrelated key returns the PSBT byte-identical (the BIP-174
  signer role); and an HD PSBT signs by walking m/84'/0'/0'/0/0 from the canonical mnemonic's
  master (fingerprint 73c5da0a, the well-known value for that mnemonic - an independent
  confirmation the fingerprint math is right). The same base64 pins run on-engine (`testPsbt`).
- **The demo is now twelve tabs.** The PSBT tab chains decode -> sign (by Keys-tab key, or by the
  Wallet tab's phrase via the PSBT's own derivation paths) -> finalize; the signed PSBT replaces
  the input field so the flow reads like a real signing session; prefilled with the wrapped
  BIP-143 example so the chain visibly ends at published bytes.
- Honest status: headless-verified and vector-locked everywhere Python can reach; NEEDS AN
  ON-ENGINE PASS (`testPsbt` is the checklist; watch the engine's base64 functions and the
  array-typed locals in the parser, the two most engine-sensitive pieces of this round).

**Phase 6b - EIP-712 typed structured data (2026-07-08).** The Ethereum half of the modern-signing
round; BIP-322 (its Bitcoin counterpart) is DEFERRED to the next round and recorded here so the
scope stays honest. Pure script (no native change, ABI 3, binaries untouched).

- New public API: `cxEip712TypeHash` / `cxEip712HashStruct` / `cxEip712WordUInt` /
  `cxEip712WordAddress` (EIP-55-gated like the tx signer) / `cxEip712WordHash` /
  `cxEip712Digest`. COMPOSABLE like RLP: encode each member as a 32-byte word, concatenate,
  hashStruct with the canonical type string; a nested struct's hash IS its parent's word, so no
  structure crosses an API. Sign the digest with cxSignRecoverable (v = recid + 27). This is the
  chain behind every wallet signTypedData prompt (token Permits, exchange orders, DAO votes,
  Sign-In with Ethereum).
- Anchor: the OFFICIAL example in the EIP itself (the Mail struct under the Ether Mail domain,
  signed by keccak256("cow")) reproduces BYTE FOR BYTE through the shim - digest, r, s, v = 28,
  and the famous signer address 0xCD2a...D826 - verified before pinning, locked in coin-kat
  (`run_eip712_checks`), on-engine (`testEip712`), and the demo self-test (digest pin).
- Demo: an EIP-712 button on the Ethereum tab signs the Mail example with the CURRENT key and
  shows the whole chain (domain separator, struct hash, digest, r||s, v, signer).
- Honest status: NEEDS AN ON-ENGINE PASS (`testEip712` is the checklist).

**Phase 6c - BIP-322 generic signed messages (2026-07-08).** The deferred Bitcoin half of the
modern-signing round, delivered. Pure script (no native change, ABI 3, binaries untouched).

- New public API: `cxBip322Hash` (the BIP0322-signed-message tagged hash), `cxBip322Sign` (the
  "simple" signature for the key's P2WPKH address: the message hash is wrapped in the BIP's
  virtual to_spend / to_sign transaction pair and signed exactly like a real spend via the
  existing BIP-143 path; the proof is the base64 witness stack), and `cxBip322Verify` (boolean,
  fail closed; bc1q addresses only, other types recorded as out of scope). `cxDerToSig` (private)
  is the strict inverse of cxSigToDer.
- Anchors, verified through the shim BEFORE pinning (`run_bip322_checks`, on-engine `testBip322`):
  the BIP's published message hashes and test address reproduce, and - the interop that matters -
  the BIP's PUBLISHED signatures (made by Bitcoin Core) VERIFY here. Core grinds low-R nonces, so
  its published bytes differ from our plain RFC 6979 signature; each side verifies the other,
  which is exactly what BIP-322 is for. Our own signature round-trips through cxBip322Verify.
- Demo: the Sign tab gained a BIP-322 row (sign a proof with the current key; check a pasted
  address + base64 proof against the message field - Sparrow / Core signatures verify here).
- Honest status: NEEDS AN ON-ENGINE PASS (`testBip322` is the checklist).

**Phase 7a - the tool workflow: files, watch-only profiles, gap-scan (2026-07-09).** Demo-layer
ONLY, deliberately: SPEC rule 2 says storage and workflow are the APP's, so no library function
was added and no new crypto path exists (nothing new to KAT; the static gates are the whole
check). The demo is now thirteen tabs; the new Tools tab holds:

- **Build watch-only profile**: fingerprint + the five account xpubs (BIP-44/49/84/86 + eth) +
  first addresses from the Wallet tab's phrase, composed text, NO private material - the export a
  coordinator or hot machine keeps.
- **Save/Load**: `ask file` / `answer file` + URL file: round-trips of the file box (profiles,
  PSBTs, raw tx hex). CoinXT itself still stores nothing.
- **Scan (is this address mine?)**: derives receive+change 0..19 of every standard chain from the
  phrase and looks for a pasted address - the defence against address-swap malware; ETH compares
  case-folded (EIP-55 is presentation), BTC exact.
- Deferred, recorded: QR generation for air-gap transfer is round 3b (a Reed-Solomon build that
  deserves its own vector-locked round); the opt-in online layer is round 4 and starts with a
  SPEC amendment.
- Honest status: NEEDS AN ON-ENGINE PASS (pure demo flows; `ask file`/`answer file`/URL file: are
  the engine-sensitive pieces).

**Phase 7b - QR air-gap transfer via the ENGINE's qrCreate (2026-07-09).** The owner pointed out
LC/OXT ships a QR generator, so the planned hand-rolled Reed-Solomon round was DROPPED - the
compose-audited-code rule applies to QR exactly as it does to crypto. The Tools tab gained a "QR
the file box" button + an image: `qrCreate <long id of image>, <text>, "M", 3` inside try/catch
(the SodiumXT capability-gate pattern), so a build without the library degrades to a clean
message instead of a wrong code. NEEDS AN ON-ENGINE PASS: confirm the qrCreate signature this
OXT build ships (args order/level/size) and record it here; the try/catch keeps a mismatch
harmless.

**Phase 8 - the OPTIONAL online layer (2026-07-09).** The one round that crosses the old "not a
broadcaster" line, so it opened with a SPEC amendment (section 1.1, owner-approved) FIRST: the
online layer is a SEPARATE, opt-in module, explicitly outside the trusted offline core, which is
unchanged and remains the security boundary.

- `src/coinxt-online.livecodescript` (new file, `cxo*` prefix, loaded with its own `start using`).
  It composes the ENGINE's HTTP (`URL` get / `post ... to URL`) to READ chain state (an address's
  UTXOs, confirmed balance, a fee rate) from an Esplora-compatible endpoint and to WRITE an
  already-signed tx. It NEVER touches a private key; signing stays in the core.
- The three invariants that keep it honest (SPEC 1.1), enforced: (a) an explorer answer is
  UNTRUSTED, so every response parser FAILS CLOSED and the human confirms amounts before the core
  signs (a parser bug can feed a wrong amount to the builder, never forge a signature; the
  on-screen fee is the backstop); (b) querying LEAKS your addresses and broadcasting reveals your
  IP - documented loudly, and the endpoint is configurable so the app can point at its own node or
  a Tor hidden service (OnionXT); (c) the default endpoint is a public TESTNET explorer, so a
  first run cannot spend mainnet coins.
- The response PARSERS are split from the HTTP verbs (`cxoParseUtxos` / `cxoParseBalance` /
  `cxoParseFeeRate` are PURE), so both coin-kat (`run_online_parse_checks`, a 1:1 Python mirror)
  and the on-engine harness (`testOnline`) drive them against the SAME Esplora-shape fixtures with
  NO network - including a 3000-blob fuzz that a parser must never crash on. Honest caveat,
  recorded: these are SCHEMA fixtures (the documented Esplora response shape), not a captured live
  response, and the thin HTTP verbs `cxoGet`/`cxoPost` need the on-engine pass. The targeted
  extraction is depth-aware (a nested key never matches at the wrong level - proven by the
  chain_stats-vs-mempool_stats balance test).
- Demo: a fourteenth tab, Online, testnet-first and capability-gated (every `cxo*` call in
  try/catch, the SodiumXT pattern, so a build without the module degrades cleanly): look up a
  balance / list UTXOs (the outpoints the BTC Tx tab needs) / broadcast a signed raw tx, with a
  mainnet/testnet toggle and loud privacy + irreversibility warnings.
- Honest status: parser-verified and vector-locked; NEEDS AN ON-ENGINE PASS (`testOnline` for the
  parsers; the live network verbs and the mainnet/testnet endpoints are the on-engine checklist).
