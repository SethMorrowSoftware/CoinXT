#!/usr/bin/env python3
"""coin-kat.py - known-answer vectors for the CoinXT native shim.

CoinXT wraps trezor-crypto behind the cnx_ ABI. Unlike a pure-script library, the
native shim IS testable headless: this harness builds the shared library from the
vendored source, drives it through ctypes, and checks every deterministic output
against a PUBLIC known-answer vector, cross-checked against an independent
implementation before pinning. It is the CoinXT analogue of OnionXT's
onion-kat.py.

Coverage:
  phase 1  the hash/KDF surface: Keccak-256, SHA3-256, SHA-256/512, RIPEMD-160,
           HMAC-SHA256/512, PBKDF2-HMAC-SHA512, cross-checked live against
           Python's hashlib / hmac where the algorithm is available.
  phase 2  the secp256k1 surface: pubkey derivation, deterministic ECDSA
           (RFC 6979, always low-s), recoverable signatures + ecrecover,
           ECDH, and the negative paths (bad key / corrupt sig fail closed).
           The RFC 6979 vectors are the classic public secp256k1 set. The
           GOLD-STANDARD check (a CoinXT signature verifies in a mainstream
           external library, and CoinXT results match that library point for
           point) runs when the independent `ecdsa` package (python-ecdsa) is
           importable; without it those sections SKIP with a clear line and
           the pinned public vectors still run.

Usage:
  python3 coin-kat.py            # build + run the vectors, print each result
  python3 coin-kat.py --check    # same, but terse: one OK line or a non-zero exit

If no C compiler is available, the harness prints a clear skip line and exits 0
(so a docs-only environment does not fail); where cc exists, it runs for real.
"""

import ctypes
import hashlib
import hmac as hmac_mod
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NATIVE = os.path.normpath(os.path.join(HERE, "..", "native"))
VENDOR = os.path.join(NATIVE, "vendor")

ABI_EXPECTED = 2

# The independent external implementation for the curve cross-checks. Optional:
# sections that need it skip cleanly when it is absent.
try:
    import ecdsa as ext_ecdsa
    from ecdsa import SECP256k1
except ImportError:  # pragma: no cover - environment-dependent
    ext_ecdsa = None
    SECP256k1 = None

# ---------------------------------------------------------------------------
# Pinned public vectors
# ---------------------------------------------------------------------------

# Published Keccak-256 (Ethereum, 0x01 padding) vectors. These are burned-in,
# widely-cited answers; SHA3-256 is cross-checked live against hashlib instead.
KECCAK256 = {
    b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
}
SHA3_INPUTS = [b"", b"abc", b"The quick brown fox jumps over the lazy dog"]
SHA2_INPUTS = [b"", b"abc", b"The quick brown fox jumps over the lazy dog"]

# RIPEMD-160 vectors from the algorithm's published test suite (Dobbertin,
# Bosselaers, Preneel), used when hashlib lacks ripemd160 (OpenSSL 3 removed
# it from the default provider); when hashlib has it, we cross-check live too.
RIPEMD160 = {
    b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    b"message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
}

# secp256k1 group order (public curve parameter, needed for the low-s check).
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The classic public RFC 6979 / secp256k1 deterministic-signature vectors
# (fpgaminer's set, embedded in many wallet libraries' test suites; s values
# are the low-s / BIP-62 canonical form, which is what CoinXT must emit).
# Each entry: (seckey int, message bytes to sha256, expected r, expected s).
RFC6979 = [
    (0x1,
     b"Satoshi Nakamoto",
     0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
     0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5),
    (0x1,
     b"All those moments will be lost in time, like tears in rain. Time to die...",
     0x8600DBD41E348FE5C9465AB92D23E3DB8B98B873BEECD930736488696438CB6B,
     0x547FE64427496DB33BF66019DACBF0039C04199ABB0122918601DB38A72CFC21),
    (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,
     b"Satoshi Nakamoto",
     0xFD567D121DB66E382991534ADA77A6BD3106F0A1098C231E47993447CD6AF2D0,
     0x6B39CD0EB1BC8603E159EF5C20A5C8AD685A45B06CE9BEBED3F153D10D93BED5),
]

# The generator point of secp256k1 (a universally published curve parameter):
# the pubkey of seckey 1, compressed form.
G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def find_cc():
    for cc in (os.environ.get("CC"), "cc", "gcc", "clang"):
        if not cc:
            continue
        try:
            subprocess.run([cc, "--version"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True)
            return cc
        except (OSError, subprocess.CalledProcessError):
            continue
    return None


def build_lib(cc, out_path):
    src = [os.path.join(NATIVE, "coinxt.c")] + [
        os.path.join(VENDOR, f) for f in (
            "sha3.c", "sha2.c", "ripemd160.c", "hmac.c", "pbkdf2.c",
            "memzero.c", "bignum.c", "ecdsa.c", "secp256k1.c", "curves.c",
            "rfc6979.c", "hmac_drbg.c", "hasher.c", "address.c", "base58.c",
            "blake256.c", "blake2b.c", "groestl.c")]
    cmd = [cc, "-O2", "-Wall", "-Wextra", "-isystem", VENDOR,
           "-fPIC", "-shared", *src, "-o", out_path]
    subprocess.run(cmd, check=True)


def load(out_path):
    lib = ctypes.CDLL(out_path)
    lib.cnx_abi_version.restype = ctypes.c_int
    buf = ctypes.c_char_p
    size = ctypes.c_size_t
    cint = ctypes.c_int
    sigs = {
        # hash surface: (in, inlen, out)
        "cnx_keccak256": [buf, size, buf],
        "cnx_sha3_256": [buf, size, buf],
        "cnx_sha256": [buf, size, buf],
        "cnx_sha512": [buf, size, buf],
        "cnx_ripemd160": [buf, size, buf],
        # MACs / KDF
        "cnx_hmac_sha256": [buf, size, buf, size, buf],
        "cnx_hmac_sha512": [buf, size, buf, size, buf],
        "cnx_pbkdf2_hmac_sha512": [buf, size, buf, size, cint, buf, size],
        # curve surface
        "cnx_seckey_verify": [buf],
        "cnx_pubkey_from_seckey": [buf, cint, buf],
        "cnx_pubkey_decompress": [buf, size, buf],
        "cnx_ecdsa_sign": [buf, buf, buf],
        "cnx_ecdsa_verify": [buf, size, buf, buf],
        "cnx_ecdsa_sign_recoverable": [buf, buf, buf],
        "cnx_ecdsa_recover": [buf, buf, buf],
        "cnx_ecdh": [buf, buf, size, buf],
        # hygiene
        "cnx_wipe": [buf, size],
    }
    for fn, argtypes in sigs.items():
        f = getattr(lib, fn)
        f.restype = ctypes.c_int
        f.argtypes = argtypes
    return lib


class Kat:
    """Tiny pass/fail/skip collector so every section reports uniformly."""

    def __init__(self, verbose):
        self.verbose = verbose
        self.problems = []
        self.skips = []

    def check(self, name, ok, detail=""):
        if not ok:
            self.problems.append(f"{name}: {detail}" if detail else name)
        if self.verbose:
            print(f"  {name:44s} {'OK' if ok else 'FAIL'}")

    def skip(self, name, why):
        self.skips.append(f"{name} ({why})")
        if self.verbose:
            print(f"  {name:44s} SKIP ({why})")


def digest(lib, fn, data, outlen=32):
    out = ctypes.create_string_buffer(outlen)
    rc = getattr(lib, fn)(data, len(data), out)
    if rc != 0:
        raise RuntimeError(f"{fn} returned {rc}")
    return out.raw


def run_hash_kats(lib, kat):
    for data, exp in KECCAK256.items():
        kat.check(f"keccak256({data!r})",
                  digest(lib, "cnx_keccak256", data).hex() == exp)
    for data in SHA3_INPUTS:
        kat.check(f"sha3_256({data[:12]!r}) vs hashlib",
                  digest(lib, "cnx_sha3_256", data)
                  == hashlib.sha3_256(data).digest())
    for data in SHA2_INPUTS:
        kat.check(f"sha256({data[:12]!r}) vs hashlib",
                  digest(lib, "cnx_sha256", data)
                  == hashlib.sha256(data).digest())
        kat.check(f"sha512({data[:12]!r}) vs hashlib",
                  digest(lib, "cnx_sha512", data, 64)
                  == hashlib.sha512(data).digest())
    # The footgun guard: Keccak-256 and SHA3-256 of the same input MUST differ.
    kat.check("keccak256 != sha3_256 (no aliasing)",
              digest(lib, "cnx_keccak256", b"")
              != digest(lib, "cnx_sha3_256", b""))
    for data, exp in RIPEMD160.items():
        kat.check(f"ripemd160({data[:12]!r}) pinned",
                  digest(lib, "cnx_ripemd160", data, 20).hex() == exp)
    try:
        h = hashlib.new("ripemd160", b"CoinXT cross-check")
        kat.check("ripemd160 vs hashlib",
                  digest(lib, "cnx_ripemd160", b"CoinXT cross-check", 20)
                  == h.digest())
    except ValueError:
        kat.skip("ripemd160 vs hashlib", "hashlib lacks ripemd160")


def run_mac_kdf_kats(lib, kat):
    # HMAC cross-checked live against Python's hmac (RFC 2104/4231 conformant),
    # including an empty key and an empty message (both legal).
    cases = [(b"key", b"The quick brown fox jumps over the lazy dog"),
             (b"", b"message with empty key"),
             (b"key only", b""),
             (b"k" * 200, b"key longer than the block size")]
    for key, msg in cases:
        for fn, alg, outlen in (("cnx_hmac_sha256", "sha256", 32),
                                ("cnx_hmac_sha512", "sha512", 64)):
            out = ctypes.create_string_buffer(outlen)
            rc = getattr(lib, fn)(key, len(key), msg, len(msg), out)
            exp = hmac_mod.new(key, msg, alg).digest()
            kat.check(f"{fn}(klen={len(key)},mlen={len(msg)})",
                      rc == 0 and out.raw == exp)
    # PBKDF2-HMAC-SHA512 vs hashlib, including the BIP-39 shape
    # (2048 iterations, 64-byte key, "mnemonic"-prefixed salt).
    cases = [(b"password", b"salt", 1, 64),
             (b"password", b"salt", 2, 64),
             (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
              4096, 25),
             (b"abandon abandon ability", b"mnemonicTREZOR", 2048, 64)]
    for pw, salt, iters, outlen in cases:
        out = ctypes.create_string_buffer(outlen)
        rc = lib.cnx_pbkdf2_hmac_sha512(pw, len(pw), salt, len(salt), iters,
                                        out, outlen)
        exp = hashlib.pbkdf2_hmac("sha512", pw, salt, iters, outlen)
        kat.check(f"pbkdf2_hmac_sha512(iters={iters},outlen={outlen})",
                  rc == 0 and out.raw == exp)
    kat.check("pbkdf2 rejects iters=0",
              lib.cnx_pbkdf2_hmac_sha512(b"p", 1, b"s", 1, 0,
                                         ctypes.create_string_buffer(8), 8) != 0)


def sk_bytes(sk_int):
    return sk_int.to_bytes(32, "big")


def pubkey(lib, sk, compressed):
    out = ctypes.create_string_buffer(33 if compressed else 65)
    rc = lib.cnx_pubkey_from_seckey(sk, 1 if compressed else 0, out)
    if rc != 0:
        raise RuntimeError(f"cnx_pubkey_from_seckey returned {rc}")
    return out.raw


def run_curve_kats(lib, kat):
    # -- seckey validity: the [1, n-1] range, fail closed on both edges --
    kat.check("seckey 1 valid", lib.cnx_seckey_verify(sk_bytes(1)) == 0)
    kat.check("seckey n-1 valid",
              lib.cnx_seckey_verify(sk_bytes(SECP256K1_N - 1)) == 0)
    kat.check("seckey 0 rejected", lib.cnx_seckey_verify(sk_bytes(0)) != 0)
    kat.check("seckey n rejected",
              lib.cnx_seckey_verify(sk_bytes(SECP256K1_N)) != 0)
    kat.check("seckey 2^256-1 rejected",
              lib.cnx_seckey_verify(b"\xff" * 32) != 0)

    # -- pubkey derivation: seckey 1 must map to the generator G --
    kat.check("pubkey(1) == G (compressed)",
              pubkey(lib, sk_bytes(1), True).hex() == G_COMPRESSED)
    g65 = pubkey(lib, sk_bytes(1), False)
    kat.check("pubkey(1) uncompressed prefix/coords",
              g65[0] == 4 and g65[1:33] == bytes.fromhex(G_COMPRESSED[2:]))

    # -- decompress round trip + fail-closed on a corrupt prefix --
    dec = ctypes.create_string_buffer(65)
    rc = lib.cnx_pubkey_decompress(pubkey(lib, sk_bytes(1), True), 33, dec)
    kat.check("decompress(compressed G) == G65", rc == 0 and dec.raw == g65)
    bad = bytearray(pubkey(lib, sk_bytes(1), True))
    bad[0] = 0x05
    kat.check("decompress rejects prefix 0x05",
              lib.cnx_pubkey_decompress(bytes(bad), 33, dec) != 0)

    # -- RFC 6979 deterministic signatures: the classic public vector set --
    for sk_int, msg, exp_r, exp_s in RFC6979:
        sk = sk_bytes(sk_int)
        h = hashlib.sha256(msg).digest()
        sig = ctypes.create_string_buffer(64)
        rc = lib.cnx_ecdsa_sign(sk, h, sig)
        r = int.from_bytes(sig.raw[:32], "big")
        s = int.from_bytes(sig.raw[32:], "big")
        label = msg[:16].decode("ascii", "replace")
        kat.check(f"rfc6979 r ({label}...)", rc == 0 and r == exp_r,
                  f"r = {r:064x}")
        kat.check(f"rfc6979 s ({label}...)", rc == 0 and s == exp_s,
                  f"s = {s:064x}")
        kat.check(f"rfc6979 low-s ({label}...)", s <= SECP256K1_N // 2)
        # determinism: signing again yields the identical signature
        sig2 = ctypes.create_string_buffer(64)
        lib.cnx_ecdsa_sign(sk, h, sig2)
        kat.check(f"rfc6979 deterministic ({label}...)", sig.raw == sig2.raw)
        # and it verifies in CoinXT with both pubkey forms
        p33 = pubkey(lib, sk, True)
        p65 = pubkey(lib, sk, False)
        kat.check(f"verify own sig, pub33 ({label}...)",
                  lib.cnx_ecdsa_verify(p33, 33, h, sig) == 0)
        kat.check(f"verify own sig, pub65 ({label}...)",
                  lib.cnx_ecdsa_verify(p65, 65, h, sig) == 0)
        # a corrupt signature must fail closed
        corrupt = bytearray(sig.raw)
        corrupt[10] ^= 0x40
        kat.check(f"corrupt sig rejected ({label}...)",
                  lib.cnx_ecdsa_verify(p33, 33, h, bytes(corrupt)) != 0)

    # -- signing with an invalid key fails closed --
    sig = ctypes.create_string_buffer(64)
    kat.check("sign with seckey 0 rejected",
              lib.cnx_ecdsa_sign(sk_bytes(0), b"\x11" * 32, sig) != 0)

    # -- recoverable signature + ecrecover round trip --
    sk = sk_bytes(0xC0FFEE)
    h = hashlib.sha256(b"CoinXT ecrecover round trip").digest()
    sig65 = ctypes.create_string_buffer(65)
    rc = lib.cnx_ecdsa_sign_recoverable(sk, h, sig65)
    kat.check("sign_recoverable rc", rc == 0)
    kat.check("recid in 0..3", sig65.raw[64] <= 3)
    rec = ctypes.create_string_buffer(65)
    rc = lib.cnx_ecdsa_recover(sig65.raw, h, rec)
    kat.check("ecrecover returns the signing pubkey",
              rc == 0 and rec.raw == pubkey(lib, sk, False))
    # the 64-byte r||s part must equal the plain deterministic signature
    plain = ctypes.create_string_buffer(64)
    lib.cnx_ecdsa_sign(sk, h, plain)
    kat.check("recoverable r||s == plain r||s", sig65.raw[:64] == plain.raw)
    # the WRONG recid must not recover the signer (fail closed or wrong key)
    wrong = bytearray(sig65.raw)
    wrong[64] ^= 1
    rc = lib.cnx_ecdsa_recover(bytes(wrong), h, rec)
    kat.check("wrong recid does not yield the signer",
              rc != 0 or rec.raw != pubkey(lib, sk, False))
    bad = bytearray(sig65.raw)
    bad[64] = 9
    kat.check("recid 9 rejected",
              lib.cnx_ecdsa_recover(bytes(bad), h, rec) != 0)

    # -- ECDH: symmetric, and the SEC1 x-coordinate convention --
    ska, skb = sk_bytes(0xA11CE), sk_bytes(0xB0B)
    sha = ctypes.create_string_buffer(32)
    shb = ctypes.create_string_buffer(32)
    rc1 = lib.cnx_ecdh(ska, pubkey(lib, skb, True), 33, sha)
    rc2 = lib.cnx_ecdh(skb, pubkey(lib, ska, False), 65, shb)
    kat.check("ecdh symmetric (33 vs 65 pub forms)",
              rc1 == 0 and rc2 == 0 and sha.raw == shb.raw)

    # -- cnx_wipe: the LCB layer's pre-deallocate secret scrub --
    buf = ctypes.create_string_buffer(b"\xaa" * 32, 32)
    kat.check("cnx_wipe zeroes the buffer",
              lib.cnx_wipe(buf, 32) == 0 and buf.raw == b"\x00" * 32)


def run_external_crosschecks(lib, kat):
    """The gold standard: CoinXT output must interoperate with a mainstream
    independent library (python-ecdsa), not just verify in CoinXT."""
    if ext_ecdsa is None:
        kat.skip("external cross-checks", "python-ecdsa not installed")
        return
    from ecdsa.util import sigdecode_string, sigencode_string

    for sk_int, msg, _r, _s in RFC6979:
        sk = sk_bytes(sk_int)
        h = hashlib.sha256(msg).digest()
        label = msg[:16].decode("ascii", "replace")
        sig = ctypes.create_string_buffer(64)
        lib.cnx_ecdsa_sign(sk, h, sig)
        # 1) a CoinXT signature VERIFIES in python-ecdsa
        vk = ext_ecdsa.SigningKey.from_secret_exponent(
            sk_int, curve=SECP256k1).get_verifying_key()
        try:
            ok = vk.verify_digest(sig.raw, h, sigdecode=sigdecode_string)
        except ext_ecdsa.BadSignatureError:
            ok = False
        kat.check(f"EXT verify CoinXT sig ({label}...)", ok)
        # 2) python-ecdsa's own RFC 6979 signature matches CoinXT's after
        #    low-s normalization (python-ecdsa does not canonicalize s)
        esig = ext_ecdsa.SigningKey.from_secret_exponent(
            sk_int, curve=SECP256k1).sign_digest_deterministic(
                h, hashfunc=hashlib.sha256, sigencode=sigencode_string)
        er = int.from_bytes(esig[:32], "big")
        es = int.from_bytes(esig[32:], "big")
        es = min(es, SECP256K1_N - es)
        kat.check(f"EXT rfc6979 agreement ({label}...)",
                  sig.raw == er.to_bytes(32, "big") + es.to_bytes(32, "big"))
        # 3) pubkey derivation agrees byte for byte
        kat.check(f"EXT pubkey agreement ({label}...)",
                  pubkey(lib, sk, False)[1:] == vk.to_string())
        # 4) and a python-ecdsa signature verifies in CoinXT (both directions)
        kat.check(f"CoinXT verifies EXT sig ({label}...)",
                  lib.cnx_ecdsa_verify(
                      pubkey(lib, sk, True), 33, h,
                      er.to_bytes(32, "big") + es.to_bytes(32, "big")) == 0)

    # 5) ECDH x-coordinate against python-ecdsa point arithmetic
    ska_int, skb_int = 0xA11CE, 0xB0B
    out = ctypes.create_string_buffer(32)
    rc = lib.cnx_ecdh(sk_bytes(ska_int), pubkey(lib, sk_bytes(skb_int), True),
                      33, out)
    shared = (SECP256k1.generator * skb_int) * ska_int
    kat.check("EXT ecdh x-coordinate agreement",
              rc == 0 and out.raw == int(shared.x()).to_bytes(32, "big"))


# ---------------------------------------------------------------------------
# Phase 3 address vectors (script-side encoders). coin-kat.py drives the NATIVE
# shim, so it cannot run the .livecodescript Base58Check / Bech32 / EIP-55
# encoders directly - those are checked ON-ENGINE by
# examples/coinxt-tests.livecodescript. What this file CAN do, and does below,
# is LOCK the expected address strings: it derives the pubkey from the real
# shim, reference-encodes it in Python, and asserts the result equals the
# famous PUBLIC vectors (BIP-173's bc1qw508..., the pk=1 Ethereum address). If
# those pinned strings are ever mistyped in the on-engine harness, this fails.
# The reference encoders are the same algorithm the livecodescript implements.

# pubkey(1) = the secp256k1 generator; its canonical addresses are published.
ADDRESS_VECTORS = {
    # seckey int: (P2PKH mainnet, P2WPKH mainnet, ETH EIP-55)
    1: ("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
    0xC0FFEE: ("1PkjVT2eq7sLQaad4sa3bsawdHdop5EPWj",
               "bc1qlxvp7agw998t68qm76ek6t20gh320yrs8lhw7j",
               "0xF5A5E415061470A8b9137959180901aEa72450a4"),
}
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


def _h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def _dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _b58check(version, payload):
    body = bytes([version]) + payload + _dsha(bytes([version]) + payload)[:4]
    n_zero = len(body) - len(body.lstrip(b"\x00"))
    num = int.from_bytes(body, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * n_zero + out


def _bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= _BECH32_GEN[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_p2wpkh(hrp, h20):
    data = [0]
    acc = bits = 0
    for b in h20:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(expand + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32[d] for d in data + checksum)


def _keccak256(msg):
    rc = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
          0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
          0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
          0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
          0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
          0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
          0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
          0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    rot = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
           [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    mask = (1 << 64) - 1

    def rol(x, n):
        return ((x << n) | (x >> (64 - n))) & mask

    a = [[0] * 5 for _ in range(5)]
    rate = 136
    m = bytearray(msg)
    m.append(0x01)
    while len(m) % rate:
        m.append(0)
    m[-1] ^= 0x80
    for off in range(0, len(m), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(m[off + i * 8:off + i * 8 + 8], "little")
        for rnd in range(24):
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    a[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = rol(a[x][y], rot[x][y])
            for x in range(5):
                for y in range(5):
                    a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
            a[0][0] ^= rc[rnd]
    out = bytearray()
    for i in range(4):
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out[:32])


def _eth_address(pub65):
    body = _keccak256(pub65[1:])[12:].hex()
    kh = _keccak256(body.encode("ascii")).hex()
    out = "0x"
    for i, ch in enumerate(body):
        if ch in "0123456789":
            out += ch
        else:
            out += ch.upper() if int(kh[i], 16) >= 8 else ch
    return out


def run_address_vectors(lib, kat):
    # keccak256("") sanity: proves the reference keccak here matches the shim's
    kat.check("reference keccak256(empty) matches the shim",
              _keccak256(b"").hex() == digest(lib, "cnx_keccak256", b"").hex())
    for sk_int, (exp_p2pkh, exp_p2wpkh, exp_eth) in ADDRESS_VECTORS.items():
        sk = sk_bytes(sk_int)
        pub33 = pubkey(lib, sk, True)   # from the real shim
        pub65 = pubkey(lib, sk, False)
        h20 = _h160(pub33)
        kat.check(f"P2PKH vector locked (sk={sk_int:#x})",
                  _b58check(0x00, h20) == exp_p2pkh)
        kat.check(f"P2WPKH vector locked (sk={sk_int:#x})",
                  _bech32_p2wpkh("bc", h20) == exp_p2wpkh)
        kat.check(f"ETH/EIP-55 vector locked (sk={sk_int:#x})",
                  _eth_address(pub65) == exp_eth)


def main(argv):
    check = "--check" in argv[1:]
    cc = find_cc()
    if cc is None:
        print("coin-kat: skipped (no C compiler found)")
        return 0

    kat = Kat(verbose=not check)
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "libcoinxt_kat.so")
        try:
            build_lib(cc, out_path)
        except subprocess.CalledProcessError as exc:
            print(f"coin-kat: BUILD FAILED ({exc})")
            return 1
        lib = load(out_path)

        abi = lib.cnx_abi_version()
        kat.check(f"abi_version == {ABI_EXPECTED}", abi == ABI_EXPECTED,
                  f"got {abi}")
        run_hash_kats(lib, kat)
        run_mac_kdf_kats(lib, kat)
        run_curve_kats(lib, kat)
        run_external_crosschecks(lib, kat)
        run_address_vectors(lib, kat)

    if kat.problems:
        for p in kat.problems:
            print("coin-kat: FAIL:", p)
        return 1
    skipnote = f" ({len(kat.skips)} skipped)" if kat.skips else ""
    print(f"coin-kat: self-check OK{skipnote}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
