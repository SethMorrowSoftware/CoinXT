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
- Schnorr / BIP-340 is DEFERRED to a Taproot phase: this upstream commit provides it only through the
  bundled secp256k1-zkp (a much larger vendoring surface). The phase-0 open question is hereby decided.
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
