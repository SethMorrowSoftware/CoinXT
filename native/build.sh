#!/bin/sh
# build.sh - build the CoinXT native shim (the quick local path).
#
# Two outputs, on purpose (CLAUDE.md "Commands"):
#   coinxt.<ext>   - a plain shared library named with the BARE token (no "lib"
#                    prefix), the same name the packaged extension ships under
#                    src/code/<arch>-<platform>/ so the engine can resolve
#                    "c:coinxt>" (the SodiumXT model). Built without sanitizers
#                    so it can load into a non-instrumented host process.
#   cnx_selftest   - an ASan + UBSan build of tests/coinxt_smoke_test.c that
#                    exercises the shim and proves the walked paths memory-clean.
#
# The CI platform matrix and the packaged extension use CMakeLists.txt (the
# family build); this script is the no-dependency developer loop. Both compile
# the same sources, so keep the vendor list below in step with CMakeLists.txt.
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
    out="$here/coinxt.$ext"
    cc -O2 $warn $inc -fPIC -shared "$here/coinxt.c" $vendor_src -o "$out"
    echo "built $out"
    ;;
  asan)
    tmp=$(mktemp -d)
    cc $warn -fsanitize=address,undefined $inc \
       "$here/../tests/coinxt_smoke_test.c" "$here/coinxt.c" $vendor_src \
       -o "$tmp/cnx_selftest"
    "$tmp/cnx_selftest"
    echo "(ASan/UBSan clean)"
    rm -rf "$tmp"
    ;;
  *)
    echo "usage: sh build.sh [lib|asan]" >&2
    exit 2
    ;;
esac
