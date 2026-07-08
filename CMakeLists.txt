# CMakeLists.txt - build the CoinXT native shim (the family build).
#
# What this produces: ONE shared library compiled entirely from committed
# sources (native/coinxt.c + the vendored trezor-crypto subset), named with
# the bare token "coinxt" (no "lib" prefix), so the packaged extension can
# resolve "c:coinxt>" from src/code/<arch>-<platform>/coinxt.<ext> with no
# external runtime dependency (the SodiumXT / TorrentXT packaging model).
#
# Unlike SodiumXT (which must acquire and static-link a pinned libsodium) and
# TorrentXT (libtorrent), CoinXT has NO external dependency: the vendored
# sources are the whole supply chain, pinned in native/MANIFEST.sha256. That
# keeps every CI lane a plain compile.
#
# Windows note: the vendored code uses gcc-isms (__attribute__((packed)) in
# blake2b.c), and vendored files are never patched (VENDOR.md), so the Windows
# lanes build with MinGW (MSYS2), not MSVC - a recorded divergence from the
# siblings with the same shipped result. random_buffer's BCryptGenRandom needs
# bcrypt, linked below.

cmake_minimum_required(VERSION 3.16)

project(CoinXT
        VERSION 0.1.0
        DESCRIPTION "Bitcoin and Ethereum cryptography for OpenXTalk / xTalk via trezor-crypto"
        LANGUAGES C)

option(COINXT_BUILD_TESTS "Build the C smoke test (ctest)" OFF)
option(COINXT_SANITIZE    "Build library and smoke test under ASan + UBSan" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(COINXT_VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/native/vendor")

# The vendored trezor-crypto translation units phases 1-2 need; keep this list
# in step with native/build.sh (the no-CMake developer loop) and VENDOR.md.
set(COINXT_VENDOR_SRC
    "${COINXT_VENDOR_DIR}/sha3.c"
    "${COINXT_VENDOR_DIR}/sha2.c"
    "${COINXT_VENDOR_DIR}/ripemd160.c"
    "${COINXT_VENDOR_DIR}/hmac.c"
    "${COINXT_VENDOR_DIR}/pbkdf2.c"
    "${COINXT_VENDOR_DIR}/memzero.c"
    "${COINXT_VENDOR_DIR}/bignum.c"
    "${COINXT_VENDOR_DIR}/ecdsa.c"
    "${COINXT_VENDOR_DIR}/secp256k1.c"
    "${COINXT_VENDOR_DIR}/curves.c"
    "${COINXT_VENDOR_DIR}/rfc6979.c"
    "${COINXT_VENDOR_DIR}/hmac_drbg.c"
    "${COINXT_VENDOR_DIR}/hasher.c"
    "${COINXT_VENDOR_DIR}/address.c"
    "${COINXT_VENDOR_DIR}/base58.c"
    "${COINXT_VENDOR_DIR}/blake256.c"
    "${COINXT_VENDOR_DIR}/blake2b.c"
    "${COINXT_VENDOR_DIR}/groestl.c")

function(coinxt_common_flags target)
    # Our warnings apply to OUR code; the vendored headers are SYSTEM includes
    # so trezor-crypto's warnings never pollute -Wall -Wextra.
    target_compile_options(${target} PRIVATE -Wall -Wextra)
    target_include_directories(${target} SYSTEM PRIVATE "${COINXT_VENDOR_DIR}")
    if(COINXT_SANITIZE)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()

add_library(coinxt SHARED native/coinxt.c ${COINXT_VENDOR_SRC})
coinxt_common_flags(coinxt)
set_target_properties(coinxt PROPERTIES
    PREFIX ""                 # no "lib" prefix: the engine resolves the bare token
    OUTPUT_NAME "coinxt"
    C_VISIBILITY_PRESET default
    POSITION_INDEPENDENT_CODE ON)
if(WIN32)
    # random_buffer (the blinding-only RNG hook) uses BCryptGenRandom.
    target_link_libraries(coinxt PRIVATE bcrypt)
endif()

if(COINXT_BUILD_TESTS)
    enable_testing()
    # The smoke test links the same objects directly (not the shared lib), so
    # ctest exercises exactly the code that ships without rpath games.
    add_executable(coinxt_smoke_test tests/coinxt_smoke_test.c native/coinxt.c ${COINXT_VENDOR_SRC})
    coinxt_common_flags(coinxt_smoke_test)
    if(WIN32)
        target_link_libraries(coinxt_smoke_test PRIVATE bcrypt)
    endif()
    add_test(NAME coinxt_smoke_test COMMAND coinxt_smoke_test)
endif()
