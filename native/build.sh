#!/bin/sh
# build.sh - build the CoinXT native shim.
#
# Two outputs, on purpose (CLAUDE.md "Commands"):
#   libcoinxt.<ext>  - a plain shared library the LCB module (and the ctypes KAT
#                      harness) loads. Built without sanitizers so it can be loaded
#                      into a non-instrumented host process.
#   cnx_selftest     - an ASan + UBSan executable that exercises the shim and is
#                      run to prove the native code is memory-clean.
#
# Usage:  sh native/build.sh          # build the shared library
#         sh native/build.sh asan     # build + run the ASan/UBSan self-test
#
# Run from the CoinXT/ directory (or anywhere; paths are resolved from this file).

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)   # .../CoinXT/native
ven="$here/vendor"

# The vendored trezor-crypto translation units phases 1-2 need. hasher/address/
# base58 and the blake/groestl units are link-time deps of ecdsa.c (its address
# helpers reference them; CoinXT itself never calls those paths - see VENDOR.md).
vendor_src="$ven/sha3.c $ven/sha2.c $ven/ripemd160.c $ven/hmac.c $ven/pbkdf2.c \
$ven/memzero.c $ven/bignum.c $ven/ecdsa.c $ven/secp256k1.c $ven/curves.c \
$ven/rfc6979.c $ven/hmac_drbg.c $ven/hasher.c $ven/address.c $ven/base58.c \
$ven/blake256.c $ven/blake2b.c $ven/groestl.c"

# Third-party headers are -isystem so their warnings do not pollute -Wall -Wextra.
warn="-Wall -Wextra"
inc="-isystem $ven"

case "${1:-lib}" in
  lib)
    # Pick the platform extension (best effort; default .so).
    ext=so
    case "$(uname -s 2>/dev/null || echo unknown)" in
      Darwin*) ext=dylib ;;
      MINGW*|MSYS*|CYGWIN*) ext=dll ;;
    esac
    out="$here/libcoinxt.$ext"
    cc -O2 $warn $inc -fPIC -shared "$here/coinxt.c" $vendor_src -o "$out"
    echo "built $out"
    ;;
  asan)
    tmp=$(mktemp -d)
    cat > "$tmp/selftest.c" <<'EOF'
/* ASan/UBSan self-test: walk every phase-1/2 export at least once so the
 * sanitizers see the real code paths (hashes, sign, verify, recover, ECDH).
 * Correctness is pinned in depth by tools/coin-kat.py; this proves the same
 * paths are memory- and UB-clean. */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
extern int cnx_abi_version(void);
extern int cnx_keccak256(const unsigned char *, size_t, unsigned char *);
extern int cnx_sha3_256(const unsigned char *, size_t, unsigned char *);
extern int cnx_sha256(const unsigned char *, size_t, unsigned char *);
extern int cnx_sha512(const unsigned char *, size_t, unsigned char *);
extern int cnx_ripemd160(const unsigned char *, size_t, unsigned char *);
extern int cnx_hmac_sha256(const unsigned char *, size_t, const unsigned char *, size_t, unsigned char *);
extern int cnx_hmac_sha512(const unsigned char *, size_t, const unsigned char *, size_t, unsigned char *);
extern int cnx_pbkdf2_hmac_sha512(const unsigned char *, size_t, const unsigned char *, size_t, int, unsigned char *, size_t);
extern int cnx_seckey_verify(const unsigned char *);
extern int cnx_pubkey_from_seckey(const unsigned char *, int, unsigned char *);
extern int cnx_pubkey_decompress(const unsigned char *, size_t, unsigned char *);
extern int cnx_ecdsa_sign(const unsigned char *, const unsigned char *, unsigned char *);
extern int cnx_ecdsa_verify(const unsigned char *, size_t, const unsigned char *, const unsigned char *);
extern int cnx_ecdsa_sign_recoverable(const unsigned char *, const unsigned char *, unsigned char *);
extern int cnx_ecdsa_recover(const unsigned char *, const unsigned char *, unsigned char *);
extern int cnx_ecdh(const unsigned char *, const unsigned char *, size_t, unsigned char *);
extern int cnx_wipe(unsigned char *, size_t);
static int eq(const unsigned char *b, const char *hexexp) {
  char h[65];
  for (int i = 0; i < 32; i++) sprintf(h + 2 * i, "%02x", b[i]);
  return strcmp(h, hexexp) == 0;
}
#define NEED(c, m) do { if (!(c)) { printf("%s FAIL\n", (m)); return 1; } } while (0)
int main(void) {
  unsigned char o[64], sk1[32], sk2[32], pub33[33], pub65[65], dec65[65];
  unsigned char sig[65], rec[65], sh1[32], sh2[32], hash[32];
  NEED(cnx_abi_version() == 2, "ABI");
  cnx_keccak256((const unsigned char *)"", 0, o);
  NEED(eq(o, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), "keccak empty");
  cnx_keccak256(NULL, 0, o); /* NULL-with-zero guard path */
  cnx_sha3_256((const unsigned char *)"abc", 3, o);
  NEED(eq(o, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), "sha3 abc");
  cnx_sha256((const unsigned char *)"abc", 3, o);
  NEED(eq(o, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256 abc");
  NEED(cnx_sha512((const unsigned char *)"abc", 3, o) == 0, "sha512 rc");
  NEED(cnx_ripemd160((const unsigned char *)"abc", 3, o) == 0, "ripemd rc");
  NEED(cnx_hmac_sha256((const unsigned char *)"k", 1, (const unsigned char *)"m", 1, o) == 0, "hmac256 rc");
  NEED(cnx_hmac_sha512((const unsigned char *)"k", 1, (const unsigned char *)"m", 1, o) == 0, "hmac512 rc");
  NEED(cnx_pbkdf2_hmac_sha512((const unsigned char *)"pw", 2, (const unsigned char *)"salt", 4, 8, o, 64) == 0, "pbkdf2 rc");
  /* two fixed keys; all-zero and all-ff (>= order) must be rejected */
  memset(sk1, 0x11, 32); memset(sk2, 0x22, 32);
  memset(o, 0x00, 32); NEED(cnx_seckey_verify(o) != 0, "zero key rejected");
  memset(o, 0xff, 32); NEED(cnx_seckey_verify(o) != 0, "overflow key rejected");
  NEED(cnx_seckey_verify(sk1) == 0, "sk1 valid");
  NEED(cnx_pubkey_from_seckey(sk1, 1, pub33) == 0, "pub33");
  NEED(cnx_pubkey_from_seckey(sk1, 0, pub65) == 0, "pub65");
  NEED(cnx_pubkey_decompress(pub33, 33, dec65) == 0, "decompress");
  NEED(memcmp(dec65, pub65, 65) == 0, "decompress matches");
  cnx_sha256((const unsigned char *)"digest", 6, hash);
  NEED(cnx_ecdsa_sign(sk1, hash, sig) == 0, "sign");
  NEED(cnx_ecdsa_verify(pub33, 33, hash, sig) == 0, "verify(33)");
  NEED(cnx_ecdsa_verify(pub65, 65, hash, sig) == 0, "verify(65)");
  sig[0] ^= 1;
  NEED(cnx_ecdsa_verify(pub33, 33, hash, sig) != 0, "corrupt sig rejected");
  sig[0] ^= 1;
  NEED(cnx_ecdsa_sign_recoverable(sk1, hash, sig) == 0, "sign recoverable");
  NEED(cnx_ecdsa_recover(sig, hash, rec) == 0, "recover");
  NEED(memcmp(rec, pub65, 65) == 0, "recover matches signer");
  /* ECDH symmetry: x(sk1 * P2) == x(sk2 * P1) */
  NEED(cnx_pubkey_from_seckey(sk2, 1, pub33) == 0, "pub2");
  NEED(cnx_ecdh(sk1, pub33, 33, sh1) == 0, "ecdh 1");
  NEED(cnx_pubkey_from_seckey(sk1, 0, pub65) == 0, "pub1");
  NEED(cnx_ecdh(sk2, pub65, 65, sh2) == 0, "ecdh 2");
  NEED(memcmp(sh1, sh2, 32) == 0, "ecdh symmetric");
  NEED(cnx_wipe(sh1, 32) == 0 && sh1[0] == 0 && sh1[31] == 0, "wipe");
  printf("cnx_selftest: OK (ASan/UBSan clean)\n");
  return 0;
}
EOF
    cc $warn -fsanitize=address,undefined $inc "$tmp/selftest.c" "$here/coinxt.c" $vendor_src -o "$tmp/cnx_selftest"
    "$tmp/cnx_selftest"
    rm -rf "$tmp"
    ;;
  *)
    echo "usage: sh build.sh [lib|asan]" >&2
    exit 2
    ;;
esac
