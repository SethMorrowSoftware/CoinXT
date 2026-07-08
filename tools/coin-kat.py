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

ABI_EXPECTED = 3

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
        # HD (BIP-32) nodes
        "cnx_hdnode_from_seed": [buf, size, buf],
        "cnx_hdnode_derive": [buf, cint, cint, buf],
        "cnx_hdnode_private_key": [buf, buf],
        "cnx_hdnode_public_key": [buf, buf],
        "cnx_hdnode_chaincode": [buf, buf],
        # Schnorr / BIP-340 (aux is an optional pointer; NULL -> zero bytes)
        "cnx_xonly_from_seckey": [buf, buf],
        "cnx_schnorr_sign": [buf, buf, buf, buf],
        "cnx_schnorr_verify": [buf, buf, buf],
        "cnx_taproot_tweak_pubkey": [buf, buf],
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


# ---------------------------------------------------------------------------
# BIP-39 (phase 4a, script). Like the address encoders, the mnemonic logic is
# livecodescript and cannot be driven here; the on-engine harness checks it.
# This file (a) verifies the shipped wordlist is the canonical BIP-39 English
# list, (b) parses the wordlist EMBEDDED in src/coinxt.livecodescript and
# asserts it is byte-identical to that file (so the embed cannot drift), and
# (c) locks the published Trezor mnemonic/seed vectors the harness checks.
BIP39_WORDLIST = os.path.join(HERE, "..", "data", "bip39-english.txt")
BIP39_WORDLIST_SHA256 = \
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
COINXT_LCS = os.path.join(HERE, "..", "src", "coinxt.livecodescript")
# Trezor BIP-39 vectors (entropy hex -> mnemonic, seed with passphrase "TREZOR")
BIP39_VECTORS = [
    ("00000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon about",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
     "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd309717"
     "0af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
]


def _read_embedded_wordlist():
    """Extract the wordlist embedded in src/coinxt.livecodescript's
    cxBip39Ensure block (the `put "..." into/after tWords` lines)."""
    import re
    text = open(COINXT_LCS, encoding="utf-8").read()
    # only within the cxBip39Ensure command body
    start = text.find("private command cxBip39Ensure")
    end = text.find("end cxBip39Ensure", start)
    body = text[start:end]
    parts = re.findall(r'put "([^"]*)" (?:into|after) tWords', body)
    return " ".join(parts).split()


def run_bip39_checks(lib, kat):
    if not os.path.isfile(BIP39_WORDLIST):
        kat.check("BIP-39 wordlist present", False, "data/bip39-english.txt missing")
        return
    words = open(BIP39_WORDLIST, encoding="utf-8").read().split()
    digest_hex = hashlib.sha256(
        open(BIP39_WORDLIST, "rb").read()).hexdigest()
    kat.check("BIP-39 wordlist is the canonical list",
              len(words) == 2048 and digest_hex == BIP39_WORDLIST_SHA256)
    embedded = _read_embedded_wordlist()
    kat.check("embedded wordlist matches data/bip39-english.txt (no drift)",
              embedded == words)

    # Reference BIP-39 (the exact bounded algorithm the livecodescript uses),
    # asserted against the published Trezor vectors so the harness's expected
    # strings are locked.
    def from_entropy(ent):
        n = len(ent)
        cs = (n * 8) // 32
        numw = ((n * 8) + cs) // 11
        full = ent + hashlib.sha256(ent).digest()[:1]
        acc = bits = bidx = 0
        out = []
        for _ in range(numw):
            while bits < 11:
                acc = acc * 256 + full[bidx]
                bidx += 1
                bits += 8
            bits -= 11
            out.append(words[(acc >> bits) & 0x7FF])
            acc &= (1 << bits) - 1
        return " ".join(out)

    def to_seed(mnem, passphrase=""):
        return hashlib.pbkdf2_hmac(
            "sha512", mnem.encode(), ("mnemonic" + passphrase).encode(),
            2048, 64).hex()

    for hexent, exp_mnem, exp_seed in BIP39_VECTORS:
        ent = bytes.fromhex(hexent)
        kat.check(f"BIP-39 mnemonic vector locked ({len(ent) * 8}-bit)",
                  from_entropy(ent) == exp_mnem)
        kat.check(f"BIP-39 seed vector locked ({len(ent) * 8}-bit)",
                  to_seed(exp_mnem, "TREZOR") == exp_seed)


# ---------------------------------------------------------------------------
# BIP-32 HD nodes (phase 4b, native). The shim's cnx_hdnode_* transcribe
# trezor's secp256k1 CKD; this pins them to the OFFICIAL BIP-32 test vectors by
# reconstructing each node's xprv (Base58Check of the node blob + version) and
# comparing to the published string - depth, parent fingerprint, child number,
# chain code, and private key all at once.
BIP32_VECTOR1_SEED = "000102030405060708090a0b0c0d0e0f"
# mainnet extended-key version bytes (BIP-32), the same two cxXprv/cxXpub emit.
XPRV_VERSION = bytes.fromhex("0488ade4")
XPUB_VERSION = bytes.fromhex("0488b21e")
# (path, official xprv, official xpub). The path is applied step by step; each
# level pins BOTH extended keys, so the reconstruction below locks the exact
# strings cxXprv / cxXpub must emit on-engine.
BIP32_VECTOR1 = [
    ([],
     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
     "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
    ([(0, True)],
     "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
     "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
    ([(0, True), (1, False)],
     "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
     "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
    ([(0, True), (1, False), (2, True)],
     "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
     "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"),
    ([(0, True), (1, False), (2, True), (2, False)],
     "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
     "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"),
    ([(0, True), (1, False), (2, True), (2, False), (1000000000, False)],
     "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
     "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"),
]


def _b58decode(s):
    num = 0
    for ch in s:
        num = num * 58 + _B58.index(ch)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def _b58check_body(body):
    # Base58Check over a body whose version prefix is ALREADY prepended (xprv/
    # xpub use a 4-byte version, not the 1-byte _b58check takes). This is the
    # exact framing cxXprv / cxXpub perform: append the 4-byte double-SHA-256
    # tail, then Base58 the whole thing.
    data = body + _dsha(body)[:4]
    n_zero = len(data) - len(data.lstrip(b"\x00"))
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * n_zero + out


def run_hd_checks(lib, kat):
    seed = bytes.fromhex(BIP32_VECTOR1_SEED)
    for path, xprv, xpub in BIP32_VECTOR1:
        node = ctypes.create_string_buffer(73)
        rc = lib.cnx_hdnode_from_seed(seed, len(seed), node)
        if rc != 0:
            kat.check("BIP-32 from_seed", False, f"rc={rc}")
            return
        for index, hardened in path:
            child = ctypes.create_string_buffer(73)
            rc = lib.cnx_hdnode_derive(node.raw, index, 1 if hardened else 0, child)
            if rc != 0:
                kat.check(f"BIP-32 derive index {index}", False, f"rc={rc}")
                return
            node = child
        # official xprv body = version(4)|depth(1)|fp(4)|child(4)|cc(32)|00|priv(32)|checksum(4)
        body = _b58decode(xprv)[4:-4]   # depth..priv, 74 bytes
        blob = node.raw                  # depth|fp|child|cc|priv, 73 bytes
        label = "m" + "".join(f"/{i}{'H' if h else ''}" for i, h in path)
        ok = (blob[0:41] == body[0:41] and body[41] == 0
              and blob[41:73] == body[42:74])
        kat.check(f"BIP-32 vector 1 {label} (blob fields)", ok)
        # Reconstruct the full xprv/xpub the way cxXprv/cxXpub do, from ONLY the
        # blob fields + the shim's own pubkey derivation, and lock to the
        # published strings. blob[0:41] = depth|fp|child|cc; blob[41:73] = priv.
        pub = pubkey(lib, blob[41:73], True)
        built_xprv = _b58check_body(XPRV_VERSION + blob[0:41] + b"\x00" + blob[41:73])
        built_xpub = _b58check_body(XPUB_VERSION + blob[0:41] + pub)
        kat.check(f"BIP-32 vector 1 {label} xprv string", built_xprv == xprv)
        kat.check(f"BIP-32 vector 1 {label} xpub string", built_xpub == xpub)
    # a public-key accessor round trip against the shim's own pubkey derivation
    node = ctypes.create_string_buffer(73)
    lib.cnx_hdnode_from_seed(seed, len(seed), node)
    priv = ctypes.create_string_buffer(32)
    pub = ctypes.create_string_buffer(33)
    lib.cnx_hdnode_private_key(node.raw, priv)
    lib.cnx_hdnode_public_key(node.raw, pub)
    kat.check("hdnode pubkey == pubkey(hdnode privkey)",
              pub.raw == pubkey(lib, priv.raw, True))


# ---------------------------------------------------------------------------
# Schnorr / BIP-340 (Taproot, native). The shim's cnx_schnorr_* transcribe the
# BIP-340 SCHEME over trezor's secp256k1 primitives. This section pins them to
# the OFFICIAL BIP-340 test vectors, and - the family gold standard for a
# signing path - cross-checks every CoinXT signature against an INDEPENDENT
# reference implementation (the BIP-340 reference pseudocode, below). CoinXT
# signs a fixed 32-byte message (like its ECDSA: sign only the exact digest;
# Taproot always signs a 32-byte sighash), so only the 32-byte-message vectors
# (0-14) are in scope; the variable-length vectors (15-18) are out of scope by
# design and intentionally not driven here.

# secp256k1 domain parameters (for the independent reference only).
_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _sn_taghash(tag, msg):
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def _sn_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] == P2[0] and (P1[1] != P2[1]):
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], _SECP_P - 2, _SECP_P)) % _SECP_P
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], _SECP_P - 2, _SECP_P)) % _SECP_P
    x3 = (lam * lam - P1[0] - P2[0]) % _SECP_P
    return (x3, (lam * (P1[0] - x3) - P1[1]) % _SECP_P)


def _sn_mul(P, k):
    R = None
    for i in range(256):
        if (k >> i) & 1:
            R = _sn_add(R, P)
        P = _sn_add(P, P)
    return R


def _sn_lift_x(x):
    if x >= _SECP_P:
        return None
    c = (pow(x, 3, _SECP_P) + 7) % _SECP_P
    y = pow(c, (_SECP_P + 1) // 4, _SECP_P)
    if pow(y, 2, _SECP_P) != c:
        return None
    return (x, y if y % 2 == 0 else _SECP_P - y)


def _sn_ref_sign(msg, seckey, aux):
    d0 = int.from_bytes(seckey, "big")
    assert 1 <= d0 <= _SECP_N - 1
    P = _sn_mul(_SECP_G, d0)
    d = d0 if P[1] % 2 == 0 else _SECP_N - d0
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), _sn_taghash("BIP0340/aux", aux)))
    k0 = int.from_bytes(_sn_taghash("BIP0340/nonce", t + P[0].to_bytes(32, "big") + msg), "big") % _SECP_N
    assert k0 != 0
    R = _sn_mul(_SECP_G, k0)
    k = k0 if R[1] % 2 == 0 else _SECP_N - k0
    e = int.from_bytes(_sn_taghash("BIP0340/challenge",
                                   R[0].to_bytes(32, "big") + P[0].to_bytes(32, "big") + msg), "big") % _SECP_N
    return R[0].to_bytes(32, "big") + ((k + e * d) % _SECP_N).to_bytes(32, "big")


def _sn_ref_verify(msg, pk, sig):
    P = _sn_lift_x(int.from_bytes(pk, "big"))
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    if P is None or r >= _SECP_P or s >= _SECP_N:
        return False
    e = int.from_bytes(_sn_taghash("BIP0340/challenge", sig[0:32] + pk + msg), "big") % _SECP_N
    R = _sn_add(_sn_mul(_SECP_G, s), _sn_mul(P, _SECP_N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


# Official BIP-340 test vectors, rows 0-14 (32-byte messages only), copied
# verbatim from bitcoin/bips bip-0340/test-vectors.csv. Each tuple is
# (index, seckey|None, x-only pubkey, aux_rand|None, message, signature, valid).
SCHNORR_VECTORS = [
    (0, "0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", True),
    (1, "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "0000000000000000000000000000000000000000000000000000000000000001",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", True),
    (2, "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
     "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
     "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", True),
    (3, "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", True),  # test fails if msg is reduced modulo p or n
    (4, None, "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", None,
     "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
     "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", True),
    (5, None, "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),  # public key not on the curve
    (6, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", False),  # has_even_y(R) is false
    (7, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", False),  # negated message
    (8, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", False),  # negated s value
    (9, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", False),  # sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
    (10, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", False),  # sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
    (11, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),  # sig[0:32] is not an X coordinate on the curve
    (12, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),  # sig[0:32] is equal to field size
    (13, None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", False),  # sig[32:64] is equal to curve order
    (14, None, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),  # public key is not a valid X coordinate because it exceeds the field size
]


def run_schnorr_checks(lib, kat):
    # The independent reference must itself reproduce every published vector,
    # BEFORE we trust it to cross-check the shim (defends against a mistyped
    # vector, the same discipline as the BIP-32 xprv/xpub reconstruction).
    for idx, sk, pk, aux, msg, sig, valid in SCHNORR_VECTORS:
        pkb, msgb, sigb = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
        kat.check(f"BIP-340 ref verify vector {idx}", _sn_ref_verify(msgb, pkb, sigb) == valid)
        if sk is not None:
            ref = _sn_ref_sign(msgb, bytes.fromhex(sk), bytes.fromhex(aux))
            kat.check(f"BIP-340 ref sign vector {idx}", ref == sigb)

    # Now the shim, against both the published vector AND the reference.
    for idx, sk, pk, aux, msg, sig, valid in SCHNORR_VECTORS:
        pkb, msgb, sigb = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
        # verify: shim result must match the published TRUE/FALSE
        rc = lib.cnx_schnorr_verify(pkb, msgb, sigb)
        kat.check(f"BIP-340 shim verify vector {idx}", (rc == 0) == valid, f"rc={rc}")
        if sk is None:
            continue
        skb, auxb = bytes.fromhex(sk), bytes.fromhex(aux)
        # x-only pubkey from the shim equals the published pubkey
        xonly = ctypes.create_string_buffer(32)
        rc = lib.cnx_xonly_from_seckey(skb, xonly)
        kat.check(f"BIP-340 shim xonly vector {idx}", rc == 0 and xonly.raw == pkb, f"rc={rc}")
        # deterministic sign: shim signature == published == reference
        out = ctypes.create_string_buffer(64)
        rc = lib.cnx_schnorr_sign(skb, msgb, auxb, out)
        kat.check(f"BIP-340 shim sign vector {idx}", rc == 0 and out.raw == sigb, f"rc={rc}")
        # and the shim verifies its own signature
        rc = lib.cnx_schnorr_verify(pkb, msgb, out.raw)
        kat.check(f"BIP-340 shim self-verify vector {idx}", rc == 0, f"rc={rc}")

    # aux_rand = NULL must behave as 32 zero bytes: vector 0 uses all-zero aux,
    # so signing it with a NULL aux pointer must reproduce the same signature.
    idx, sk, pk, aux, msg, sig, valid = SCHNORR_VECTORS[0]
    out = ctypes.create_string_buffer(64)
    rc = lib.cnx_schnorr_sign(bytes.fromhex(sk), bytes.fromhex(msg), None, out)
    kat.check("BIP-340 NULL aux == zero aux", rc == 0 and out.raw == bytes.fromhex(sig), f"rc={rc}")


# ---------------------------------------------------------------------------
# Taproot (BIP-341 key-path tweak + BIP-86 address). The shim's
# cnx_taproot_tweak_pubkey computes the witness-v1 output key
# Q = P + int(hash_TapTweak(P))*G; this section pins it (and the Bech32m bc1p
# address the script layer builds) to the OFFICIAL BIP-86 test vectors, cross-
# checked against an independent tweak using the BIP-340 reference point ops.
# (internal x-only key, expected output key, expected bc1p address).
TAPROOT_VECTORS = [
    ("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
     "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
     "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
    ("83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
     "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
     "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
    ("399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
     "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
     "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"),
]


def _tr_ref_tweak(internal):
    # BIP-341 key-path-only output key, via the BIP-340 reference point ops.
    t = int.from_bytes(_sn_taghash("TapTweak", internal), "big")
    P = _sn_lift_x(int.from_bytes(internal, "big"))
    Q = _sn_add(P, _sn_mul(_SECP_G, t))
    return Q[0].to_bytes(32, "big")


def _bech32m_p2tr(hrp, prog):
    # witness v1 + 32-byte program, Bech32m (const 0x2bc830a3), the exact
    # encoding cxBtcAddressP2TR must produce.
    data = [1]
    acc = bits = 0
    for b in prog:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(expand + data + [0] * 6) ^ 0x2BC830A3
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32[d] for d in data + checksum)


def run_taproot_checks(lib, kat):
    for internal, output, address in TAPROOT_VECTORS:
        ib, ob = bytes.fromhex(internal), bytes.fromhex(output)
        # independent reference reproduces the published output key + address
        kat.check(f"BIP-86 ref tweak {address[:12]}", _tr_ref_tweak(ib) == ob)
        kat.check(f"BIP-86 ref bech32m {address[:12]}", _bech32m_p2tr("bc", ob) == address)
        # the shim's tweak matches the published output key
        out = ctypes.create_string_buffer(32)
        rc = lib.cnx_taproot_tweak_pubkey(ib, out)
        kat.check(f"BIP-86 shim tweak {address[:12]}", rc == 0 and out.raw == ob, f"rc={rc}")


# ---------------------------------------------------------------------------
# Phase 5 script encoders: WIF, nested SegWit (P2SH-P2WPKH), the EIP-191
# personal-message digest, and the Bech32/Bech32m SEGWIT-ADDRESS DECODER.
# Like the phase-3 encoders these are livecodescript and cannot be driven
# here; each reference below is the SAME algorithm the script implements
# (transcribed 1:1 BEFORE pinning, the phase-3 discipline), locked to public
# vectors, so the strings the on-engine harness pins cannot silently drift.

# The famous published WIF pair of secret key 1, plus the testnet form
# (recomputed by the reference encoder on every run, not trusted from memory).
WIF_VECTORS = [
    # (seckey int, compressed, mainnet, expected WIF)
    (1, True, True, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
    (1, False, True, "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"),
    (1, True, False, "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"),
]
# P2SH-P2WPKH (BIP-49 nested SegWit) of pubkey(1), mainnet and testnet.
P2SH_P2WPKH_VECTORS = {
    True: "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
    False: "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN",
}
# EIP-191 personal-message digests: keccak256( 0x19 || "Ethereum Signed
# Message:" || 0x0A || decimal byte length || message ). Pinned from the
# reference keccak here (itself locked to the published Ethereum vectors)
# and re-derived through the SHIM's keccak over the same preimage below, so
# two independent implementations agree before the string is trusted.
EIP191_VECTORS = {
    b"hello":
        "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750",
    b"Pay Bob 1 ETH, nonce 7":
        "c9b88db977ceecb8767c21e678b67a5580fc6a358fb05dd626631772a37e3de1",
}
# Bech32/Bech32m segwit-address decode vectors (BIP-173 + BIP-350 examples):
# (address, expected hrp, expected witness version, expected program hex).
BECH32_DECODE_VALID = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc", 0,
     "751e76e8199196d454941c45d1b3a323f1433bd6"),
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "tb", 0,
     "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
     "bc", 1,
     "751e76e8199196d454941c45d1b3a323f1433bd6"
     "751e76e8199196d454941c45d1b3a323f1433bd6"),
    ("BC1SW50QGDZ25J", "bc", 16, "751e"),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "bc", 2,
     "751e76e8199196d454941c45d1b3a323"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc", 1,
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    # the BIP-86 first receiving address this repo already pins elsewhere;
    # its program is the published BIP-86 output key
    ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "bc", 1,
     "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"),
]
# Malformed inputs the decoder must REJECT (each is genuinely invalid; the
# reason in the comment was confirmed by the reference decoder, and several
# are straight from the BIP-173/350 invalid lists).
BECH32_DECODE_INVALID = [
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",   # one flipped char
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3T4",   # mixed case
    "BC1QW508d6QEJxTDG4y5R3ZArVARY0C5XW7KV8F3t4",   # mixed case (BIP-173)
    "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",   # v1 with a bech32 checksum
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",  # padding
    "bc1gmk9yu",                                    # data part too short
    "bc1q9zpgru",                                   # empty witness program
    "qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",      # no separator / no hrp
]

_BECH32M_CONST = 0x2BC830A3


def _wif(sk, compressed, mainnet):
    version = 0x80 if mainnet else 0xEF
    return _b58check(version, sk + (b"\x01" if compressed else b""))


def _p2sh_p2wpkh(pub33, mainnet):
    # redeem script = OP_0 PUSH20 hash160(pubkey), the P2WPKH witness program
    redeem = b"\x00\x14" + _h160(pub33)
    return _b58check(0x05 if mainnet else 0xC4, _h160(redeem))


def _personal_hash(msg):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode("ascii")
    return _keccak256(prefix + msg)


def _bech32_segwit_encode(hrp, witver, prog):
    # general witness-program encode (v0 bech32, v1+ bech32m); used for the
    # encode->decode round trips below.
    const = 1 if witver == 0 else _BECH32M_CONST
    data = [witver]
    acc = bits = 0
    for b in prog:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(expand + data + [0] * 6) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32[d] for d in data + checksum)


def _bech32_decode(s):
    """1:1 mirror of cxBech32Decode (src/coinxt.livecodescript). Returns
    (hrp, witver, program) or an error string, exactly the script's
    fail-closed branches in the same order."""
    if len(s) > 90:
        return "too long"
    if s != s.lower() and s != s.upper():
        return "mixed case"
    s = s.lower()
    sep = s.rfind("1")
    if sep < 1:
        return "no separator / empty hrp"
    if len(s) - (sep + 1) < 7:
        return "data part too short"
    hrp = s[:sep]
    for ch in hrp:
        if ord(ch) < 33 or ord(ch) > 126:
            return "bad hrp char"
    values = []
    for ch in s[sep + 1:]:
        pos = _BECH32.find(ch)
        if pos < 0:
            return "bad data char"
        values.append(pos)
    witver = values[0]
    if witver > 16:
        return "bad witness version"
    const = 1 if witver == 0 else _BECH32M_CONST
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _bech32_polymod(expand + values) != const:
        return "bad checksum"
    acc = bits = 0
    prog = bytearray()
    for v in values[1:-6]:
        acc = (acc * 32) + v
        bits += 5
        if bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 255)
            acc = acc & ((1 << bits) - 1)
    if bits >= 5 or acc != 0:
        return "bad padding"
    if len(prog) < 2 or len(prog) > 40:
        return "bad program length"
    if witver == 0 and len(prog) not in (20, 32):
        return "bad v0 program length"
    return (hrp, witver, bytes(prog))


def run_phase5_encoder_checks(lib, kat):
    sk1 = sk_bytes(1)
    for sk_int, compressed, mainnet, expected in WIF_VECTORS:
        got = _wif(sk_bytes(sk_int), compressed, mainnet)
        kat.check(f"WIF vector locked (sk={sk_int}, c={compressed}, m={mainnet})",
                  got == expected, got)
    pub33 = pubkey(lib, sk1, True)
    for mainnet, expected in P2SH_P2WPKH_VECTORS.items():
        got = _p2sh_p2wpkh(pub33, mainnet)
        kat.check(f"P2SH-P2WPKH vector locked (mainnet={mainnet})",
                  got == expected, got)
    # EIP-191: the pinned digest, the shim's keccak over the same preimage,
    # and the full personal_sign -> ecrecover -> address round trip
    for msg, expected in EIP191_VECTORS.items():
        pre = (b"\x19Ethereum Signed Message:\n"
               + str(len(msg)).encode("ascii") + msg)
        kat.check(f"EIP-191 reference digest ({msg[:10]}...)",
                  _personal_hash(msg).hex() == expected)
        kat.check(f"EIP-191 shim keccak agrees ({msg[:10]}...)",
                  digest(lib, "cnx_keccak256", pre).hex() == expected)
    d = _personal_hash(b"hello")
    sig = ctypes.create_string_buffer(65)
    rec = ctypes.create_string_buffer(65)
    ok = (lib.cnx_ecdsa_sign_recoverable(sk1, d, sig) == 0
          and lib.cnx_ecdsa_recover(sig.raw, d, rec) == 0)
    kat.check("EIP-191 sign -> ecrecover -> signer address",
              ok and _eth_address(rec.raw) == _eth_address(pubkey(lib, sk1, False)))
    # bech32/bech32m decode: every valid vector yields exactly its program...
    for s, hrp, wv, prog_hex in BECH32_DECODE_VALID:
        got = _bech32_decode(s)
        ok = (not isinstance(got, str) and got[0] == hrp and got[1] == wv
              and got[2].hex() == prog_hex)
        kat.check(f"bech32 decode valid: {s[:28]}...", ok,
                  got if isinstance(got, str) else got[2].hex())
    # ...every malformed input is rejected...
    for s in BECH32_DECODE_INVALID:
        got = _bech32_decode(s)
        kat.check(f"bech32 decode rejects: {s[:28]}...",
                  isinstance(got, str), f"ACCEPTED {got}")
    # ...and encode->decode round trips over the shapes CoinXT emits
    for wv, prog in [(0, _h160(pub33)), (0, bytes(32)),
                     (1, bytes.fromhex(BECH32_DECODE_VALID[6][3])),
                     (16, b"\x75\x1e")]:
        enc = _bech32_segwit_encode("bc", wv, prog)
        kat.check(f"bech32 encode->decode round trip (v{wv}, {len(prog)}B)",
                  _bech32_decode(enc) == ("bc", wv, prog))


# ---------------------------------------------------------------------------
# RLP (the Ethereum serialization) and the EIP-155 offline transaction. The
# script layer's composable encoders (cxRlpBytes / cxRlpList / cxRlpUIntBytes
# / cxRlpUIntDec) are mirrored 1:1 below and locked to the yellow-paper
# vectors; then the OFFICIAL EIP-155 example transaction (the one printed in
# the EIP: key 0x46..46, nonce 9, 20 gwei, 21000 gas, to 0x3535..35, 1 ETH,
# chain 1) is rebuilt with these mirrors + the SHIM's keccak and recoverable
# signer, and must reproduce the published signing hash, r, s, v = 37, and
# the full raw tx byte for byte. That anchors the whole offline-signing
# chain: RLP -> keccak -> RFC 6979 sign -> EIP-155 v -> RLP again.
EIP155_KEY = bytes.fromhex("46" * 32)
EIP155_SIGHASH = \
    "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
EIP155_R = "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
EIP155_S = "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
EIP155_RAW = (
    "f86c098504a817c800825208943535353535353535353535353535353535353535"
    "880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c"
    "71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc"
    "64214b297fb1966a3b6d83")


def _rlp_header(base, n):
    if n <= 55:
        return bytes([base + n])
    lenbytes = b""
    while n:
        lenbytes = bytes([n % 256]) + lenbytes
        n //= 256
    return bytes([base + 55 + len(lenbytes)]) + lenbytes


def _rlp_bytes(b):
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _rlp_header(0x80, len(b)) + b


def _rlp_list(payload):
    return _rlp_header(0xC0, len(payload)) + payload


def _rlp_uint_bytes(b):
    return _rlp_bytes(b.lstrip(b"\x00"))


def _rlp_uint_dec(dec):
    # the script's byte-array multiply-accumulate, digit for digit
    buf = []
    for ch in dec:
        carry = ord(ch) - 48
        for j in range(len(buf)):
            v = buf[j] * 10 + carry
            buf[j] = v % 256
            carry = v // 256
        while carry:
            buf.append(carry % 256)
            carry //= 256
    return _rlp_uint_bytes(bytes(reversed(buf)))


def run_rlp_eip155_checks(lib, kat):
    lorem = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"
    vectors = [
        (_rlp_bytes(b"dog"), "83646f67"),
        (_rlp_list(_rlp_bytes(b"cat") + _rlp_bytes(b"dog")),
         "c88363617483646f67"),
        (_rlp_bytes(b""), "80"),
        (_rlp_list(b""), "c0"),
        (_rlp_uint_dec("0"), "80"),
        (_rlp_bytes(b"\x0f"), "0f"),
        (_rlp_uint_dec("1024"), "820400"),
        (_rlp_uint_bytes(b"\x00\x00\x04\x00"), "820400"),
        (_rlp_uint_dec("1000000000000000000"), "880de0b6b3a7640000"),
        (_rlp_bytes(lorem),
         "b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e"
         "7365637465747572206164697069736963696e6720656c6974"),
        # the set-theoretical representation of three: [ [], [[]], [ [], [[]] ] ]
        (_rlp_list(_rlp_list(b"") + _rlp_list(_rlp_list(b""))
                   + _rlp_list(_rlp_list(b"") + _rlp_list(_rlp_list(b"")))),
         "c7c0c1c0c3c0c1c0"),
    ]
    for got, want in vectors:
        kat.check(f"RLP vector {want[:16]}", got.hex() == want, got.hex())
    # the official EIP-155 example, end to end through the shim
    items = (_rlp_uint_dec("9") + _rlp_uint_dec("20000000000")
             + _rlp_uint_dec("21000")
             + _rlp_bytes(bytes.fromhex("35" * 20))
             + _rlp_uint_dec("1000000000000000000") + _rlp_bytes(b""))
    preimage = _rlp_list(items + _rlp_uint_dec("1")
                         + _rlp_uint_dec("0") + _rlp_uint_dec("0"))
    sighash = digest(lib, "cnx_keccak256", preimage)
    kat.check("EIP-155 signing hash", sighash.hex() == EIP155_SIGHASH,
              sighash.hex())
    sig = ctypes.create_string_buffer(65)
    rc = lib.cnx_ecdsa_sign_recoverable(EIP155_KEY, sighash, sig)
    kat.check("EIP-155 r matches the published example",
              rc == 0 and sig.raw[:32].hex() == EIP155_R)
    kat.check("EIP-155 s matches the published example",
              rc == 0 and sig.raw[32:64].hex() == EIP155_S)
    v = 35 + 2 * 1 + sig.raw[64]
    kat.check("EIP-155 v = 37", v == 37, str(v))
    raw = _rlp_list(items + _rlp_uint_dec(str(v))
                    + _rlp_uint_bytes(sig.raw[:32])
                    + _rlp_uint_bytes(sig.raw[32:64]))
    kat.check("EIP-155 raw signed tx byte-identical to the EIP's example",
              raw.hex() == EIP155_RAW, raw.hex())


# ---------------------------------------------------------------------------
# Bitcoin transaction signing (BIP-143 P2WPKH / P2SH-P2WPKH) plus its two
# building blocks, strict-DER signatures and address->scriptPubKey. The
# mirrors below are 1:1 with cxSigToDer / cxAddressToScript /
# cxBtcTxSignP2WPKH, and the anchor is the OFFICIAL BIP-143 P2SH-P2WPKH
# example: one input, two outputs, every intermediate value published in the
# BIP (hashPrevouts, hashSequence, hashOutputs, the preimage, the sighash,
# the DER signature, the final tx). The shim's deterministic RFC 6979
# signature IS the published one, so the whole chain pins byte for byte.
BIP143_KEY = bytes.fromhex(
    "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
BIP143_PUB = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
# the funding txid as displayed (big-endian; the outpoint serializes reversed)
BIP143_TXID = "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb"
BIP143_VOUT = 1
BIP143_AMOUNT = 1000000000
# the two published outputs, as the demo/API takes them: "amount address"
# (the addresses are the P2PKH form of the published output h160s)
BIP143_OUT1 = (199996600, "1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7")
BIP143_OUT2 = (800000000, "1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8")
BIP143_VERSION, BIP143_SEQUENCE, BIP143_LOCKTIME = 1, 0xFFFFFFFE, 1170
BIP143_SIGHASH = \
    "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
BIP143_DER = ("3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d7"
              "94d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad401072"
              "6870540656fe9dcb")
BIP143_RAW = (
    "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb"
    "1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02"
    "b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008"
    "af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044"
    "022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220"
    "217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad"
    "1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000")
# the signed tx's txid (derived from the published final tx: double-SHA-256
# of the witness-stripped serialization, displayed byte-reversed)
BIP143_NEW_TXID = \
    "ef48d9d0f595052e0f8cdcf825f7a5e50b6a388a81f206f3f4846e5ecd7a0c23"
# address -> scriptPubKey pairs (BIP-350 published pairs + the Base58 forms)
ADDR_SCRIPT_PAIRS = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
     "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    ("BC1SW50QGDZ25J", "6002751e"),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
     "5210751e76e8199196d454941c45d1b3a323"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
     "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    ("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
     "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
    ("3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
     "a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487"),
]


def _sig_to_der(sig64):
    def trim_pad(b):
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] >= 0x80:
            b = b"\x00" + b
        return b
    r, s = trim_pad(sig64[:32]), trim_pad(sig64[32:64])
    body = bytes([0x02, len(r)]) + r + bytes([0x02, len(s)]) + s
    return bytes([0x30, len(body)]) + body


def _address_to_script(addr):
    if addr.lower()[:3] in ("bc1", "tb1"):
        got = _bech32_decode(addr)
        if isinstance(got, str):
            return None
        _, witver, prog = got
        op = 0 if witver == 0 else 0x50 + witver
        return bytes([op, len(prog)]) + prog
    try:
        raw = _b58decode(addr)
    except ValueError:
        return None
    body, chk = raw[:-4], raw[-4:]
    if _dsha(body)[:4] != chk or len(body) != 21:
        return None
    version, h20 = body[0], body[1:]
    if version in (0x00, 0x6F):
        return b"\x76\xa9\x14" + h20 + b"\x88\xac"
    if version in (0x05, 0xC4):
        return b"\xa9\x14" + h20 + b"\x87"
    return None


def _btc_sign_p2wpkh(lib, sk, txid_be_hex, vout, amount, outputs, nested,
                     version, sequence, locktime):
    """1:1 mirror of cxBtcTxSignP2WPKH; outputs is [(sats, address), ...].
    Returns (new_txid_hex, sighash_hex, raw_bytes)."""
    def u32(n):
        return n.to_bytes(4, "little")

    def u64(n):
        return n.to_bytes(8, "little")

    pub = pubkey(lib, sk, True)
    h160 = _h160(pub)
    outpoint = bytes.fromhex(txid_be_hex)[::-1] + u32(vout)
    outs = b""
    for amt, addr in outputs:
        script = _address_to_script(addr)
        outs += u64(amt) + bytes([len(script)]) + script
    script_code = b"\x19\x76\xa9\x14" + h160 + b"\x88\xac"
    preimage = (u32(version) + _dsha(outpoint) + _dsha(u32(sequence))
                + outpoint + script_code + u64(amount) + u32(sequence)
                + _dsha(outs) + u32(locktime) + u32(1))
    sighash = _dsha(preimage)
    sig = ctypes.create_string_buffer(64)
    rc = lib.cnx_ecdsa_sign(sk, sighash, sig)
    assert rc == 0
    der = _sig_to_der(sig.raw) + b"\x01"
    if nested:
        redeem = b"\x00\x14" + h160
        script_sig = bytes([len(redeem) + 1, len(redeem)]) + redeem
    else:
        script_sig = b"\x00"
    body_in = outpoint + script_sig + u32(sequence)
    outs_counted = bytes([len(outputs)]) + outs
    witness = b"\x02" + bytes([len(der)]) + der + b"\x21" + pub
    raw = (u32(version) + b"\x00\x01\x01" + body_in + outs_counted
           + witness + u32(locktime))
    stripped = u32(version) + b"\x01" + body_in + outs_counted + u32(locktime)
    return _dsha(stripped)[::-1].hex(), sighash.hex(), raw


def run_btc_tx_checks(lib, kat):
    kat.check("BIP-143 example pubkey",
              pubkey(lib, BIP143_KEY, True).hex() == BIP143_PUB)
    txid, sighash, raw = _btc_sign_p2wpkh(
        lib, BIP143_KEY, BIP143_TXID, BIP143_VOUT, BIP143_AMOUNT,
        [BIP143_OUT1, BIP143_OUT2], True,
        BIP143_VERSION, BIP143_SEQUENCE, BIP143_LOCKTIME)
    kat.check("BIP-143 sighash matches the published value",
              sighash == BIP143_SIGHASH, sighash)
    kat.check("BIP-143 raw signed tx byte-identical to the BIP's example",
              raw.hex() == BIP143_RAW, raw.hex())
    kat.check("BIP-143 new txid", txid == BIP143_NEW_TXID, txid)
    # the DER signature inside it is the published one; also pin the encoder
    sig = ctypes.create_string_buffer(64)
    lib.cnx_ecdsa_sign(BIP143_KEY, bytes.fromhex(BIP143_SIGHASH), sig)
    kat.check("DER of the example signature matches the BIP",
              _sig_to_der(sig.raw).hex() == BIP143_DER)
    # constructed DER edges: high-bit pad, leading-zero trim, zero integer
    edge = _sig_to_der(bytes([0x80] + [0x11] * 31 + [0x00, 0x00]
                             + [0x7F] + [0x22] * 29))
    kat.check("DER pads a set high bit and trims leading zeros",
              edge.hex() == "30430221" + "0080" + "11" * 31
              + "021e" + "7f" + "22" * 29)
    kat.check("DER encodes zero as a single 00 byte",
              _sig_to_der(bytes(64)).hex() == "3006020100020100")
    # python-ecdsa cross-check of the DER framing, when available
    try:
        from ecdsa.util import sigdecode_der
        from ecdsa import SECP256k1
        r, s = sigdecode_der(bytes.fromhex(BIP143_DER), SECP256k1.order)
        kat.check("python-ecdsa parses our DER to the same r/s",
                  r == int.from_bytes(sig.raw[:32], "big")
                  and s == int.from_bytes(sig.raw[32:], "big"))
    except ImportError:
        kat.skip("python-ecdsa DER cross-check", "ecdsa not installed")
    # address -> scriptPubKey pairs, and fail-closed on a corrupt address
    for addr, want in ADDR_SCRIPT_PAIRS:
        got = _address_to_script(addr)
        kat.check(f"addr->script {addr[:20]}...",
                  got is not None and got.hex() == want)
    kat.check("addr->script rejects a corrupt checksum",
              _address_to_script("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMx") is None)


# ---------------------------------------------------------------------------
# PSBT (BIP-174), the cold-signer surface. Mirrors of cxPsbtDecode/Sign/
# Finalize's algorithms, anchored three ways: (a) the OFFICIAL BIP-174
# creator vector parses and re-encodes BYTE-EXACT; (b) a PSBT built for the
# official BIP-143 example signs to the BIP's published DER and extracts the
# BIP's published raw tx; (c) an HD-signing PSBT (BIP32_DERIVATION walk from
# the canonical mnemonic's master, fingerprint 73c5da0a) signs and extracts
# a deterministic raw tx. The base64 constants here are the SAME strings the
# on-engine harness pins, so the two cannot drift.
PSBT_CREATOR_B64 = (
    "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////"
    "g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTY"
    "XCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAA"
    "AAAAAAA=")
PSBT143_IN_B64 = (
    "cHNidP8BAHcBAAAAAdtrGyCqD9eyOIC+LsvUqYEwl0z0dI+2YJKsTTzrGlR3AQAAAAD+////"
    "Ari06wsAAAAAGXapFKRXtoTX8NU5pGpFu8BD81tZ0NljiKwACK8vAAAAABl2qRT9Jwse5qvK"
    "6pf+p60EAui9itbXfIiskgQAAAABASAAypo7AAAAABepFEcz83z024b7wu/tJQC09OSfMSAj"
    "hwEDBAEAAAABBBYAFHkJGXIYbESesd7SK3jkDQCb3wCJAAAA")
PSBT143_SIGNED_B64 = (
    "cHNidP8BAHcBAAAAAdtrGyCqD9eyOIC+LsvUqYEwl0z0dI+2YJKsTTzrGlR3AQAAAAD+////"
    "Ari06wsAAAAAGXapFKRXtoTX8NU5pGpFu8BD81tZ0NljiKwACK8vAAAAABl2qRT9Jwse5qvK"
    "6pf+p60EAui9itbXfIiskgQAAAABASAAypo7AAAAABepFEcz83z024b7wu/tJQC09OSfMSAj"
    "hyICA60djokhLwuSx00ju3EMAGYq0UcBmKxIxD99b5OiomhzRzBEAiBHrI6Hg1LT673hyUzj"
    "oQ0FfCQXV0cRb4KI5deU0S1ILwIgIX82pIXK6QPHEzMdh3wfZGd+NiKtQBByaHBUBlb+ncsB"
    "AQMEAQAAAAEEFgAUeQkZchhsRJ6x3tIreOQNAJvfAIkAAAA=")
PSBT_HD_B64 = (
    "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////"
    "AZBfAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH6CGAQAAAAAAFgAUwM68"
    "1sPTyox13F7GLr5VMw75EOIiBgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPBhz"
    "xdoKVAAAgAAAAIAAAACAAAAAAAAAAAAAAA==")
PSBT_HD_TXID = \
    "28257a9a303b3eb63c4366754ac0905a9b73548e6a3158c86e408bdf018cff85"
PSBT_HD_RAW = (
    "02000000000101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaa0000000000fdffffff01905f010000000000160014751e76e8199196d45494"
    "1c45d1b3a323f1433bd602483045022100cae928967fc76aa2e058328d58d824f58472"
    "fe659066dc6aa9c5ba2449b4359c02201f202c8eb5dfe810a28e465c68d260ec6c263b"
    "e7acb42e528fb4bda055a7dc1001210330d54fd0dd420a6e5f8d3624f5f3482cae350f"
    "79d5f0753bf5beef9c2d91af3c00000000")
PSBT_MASTER_FP = "73c5da0a"


def _p_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def _p_rd_varint(f):
    import io as _io
    n = f.read(1)[0]
    if n < 0xFD:
        return n
    if n == 0xFD:
        return int.from_bytes(f.read(2), "little")
    return int.from_bytes(f.read(4), "little")


def _p_parse_tx(raw):
    import io
    f = io.BytesIO(raw)
    version = int.from_bytes(f.read(4), "little")
    nin = _p_rd_varint(f)
    witness = False
    if nin == 0:
        assert f.read(1) == b"\x01"
        witness = True
        nin = _p_rd_varint(f)
    ins = []
    for _ in range(nin):
        t = f.read(32)
        vout = int.from_bytes(f.read(4), "little")
        ssig = f.read(_p_rd_varint(f))
        seq = int.from_bytes(f.read(4), "little")
        ins.append((t, vout, ssig, seq))
    outs = []
    for _ in range(_p_rd_varint(f)):
        v = int.from_bytes(f.read(8), "little")
        outs.append((v, f.read(_p_rd_varint(f))))
    if witness:
        for _ in range(nin):
            for _ in range(_p_rd_varint(f)):
                f.read(_p_rd_varint(f))
    locktime = int.from_bytes(f.read(4), "little")
    return version, ins, outs, locktime


def _p_parse(raw):
    import io
    assert raw[:5] == b"psbt\xff"
    f = io.BytesIO(raw[5:])

    def rd_map():
        entries = []
        while True:
            klen = _p_rd_varint(f)
            if klen == 0:
                return entries
            k = f.read(klen)
            entries.append((k, f.read(_p_rd_varint(f))))
    g = rd_map()
    unsigned = dict((k[0], v) for k, v in g)[0x00]
    _, ins, outs, _ = _p_parse_tx(unsigned)
    imaps = [rd_map() for _ in range(len(ins))]
    omaps = [rd_map() for _ in range(len(outs))]
    assert f.read() == b""
    return g, imaps, omaps, unsigned


def _p_serialize(g, imaps, omaps):
    out = b"psbt\xff"
    for m in [g] + imaps + omaps:
        for k, v in m:
            out += _p_varint(len(k)) + k + _p_varint(len(v)) + v
        out += b"\x00"
    return out


def _p_entry(m, t):
    for k, v in m:
        if len(k) == 1 and k[0] == t:
            return v
    return None


def _p_digest(unsigned, idx, prog, amount):
    version, ins, outs, locktime = _p_parse_tx(unsigned)
    prevouts = b"".join(t + v.to_bytes(4, "little") for t, v, _, _ in ins)
    seqs = b"".join(s.to_bytes(4, "little") for _, _, _, s in ins)
    outputs = b"".join(v.to_bytes(8, "little") + _p_varint(len(s)) + s
                       for v, s in outs)
    t, v, _, seq = ins[idx]
    pre = (version.to_bytes(4, "little") + _dsha(prevouts) + _dsha(seqs)
           + t + v.to_bytes(4, "little")
           + b"\x19\x76\xa9\x14" + prog + b"\x88\xac"
           + amount.to_bytes(8, "little") + seq.to_bytes(4, "little")
           + _dsha(outputs) + locktime.to_bytes(4, "little")
           + (1).to_bytes(4, "little"))
    return _dsha(pre)


def _p_input_prog(m):
    """(prog_h160, nested, spk, amount) for a single-key segwit input."""
    wu = _p_entry(m, 0x01)
    if wu is None:
        return None, False, None, None
    amount = int.from_bytes(wu[:8], "little")
    spk = wu[9:]
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return spk[2:], False, spk, amount
    if len(spk) == 23 and spk[0] == 0xA9 and spk[-1] == 0x87:
        r = _p_entry(m, 0x04)
        if r is not None and len(r) == 22 and r[:2] == b"\x00\x14" \
                and _h160(r) == spk[2:22]:
            return r[2:], True, spk, amount
    return None, False, spk, amount


def _p_sign(lib, raw, key):
    """Mirror of cxPsbtSign: key = 32-byte seckey or 73-byte HD blob."""
    g, imaps, omaps, unsigned = _p_parse(raw)
    for i, m in enumerate(imaps):
        st = _p_entry(m, 0x03)
        if st is not None and int.from_bytes(st, "little") != 1:
            continue
        prog, nested, spk, amount = _p_input_prog(m)
        if prog is None:
            continue
        sk = None
        if len(key) == 32:
            if _h160(pubkey(lib, key, True)) == prog:
                sk = key
        else:
            fp = _h160(pubkey(lib, key[41:73], True))[:4]
            for k, v in m:
                if len(k) != 34 or k[0] != 0x06 or v[:4] != fp:
                    continue
                node = key
                for j in range(4, len(v), 4):
                    n = int.from_bytes(v[j:j + 4], "little")
                    child = ctypes.create_string_buffer(73)
                    lib.cnx_hdnode_derive(node, n & 0x7FFFFFFF,
                                          1 if n >= 0x80000000 else 0, child)
                    node = child.raw
                if pubkey(lib, node[41:73], True) == k[1:] \
                        and _h160(k[1:]) == prog:
                    sk = node[41:73]
                    break
        if sk is None:
            continue
        pub = pubkey(lib, sk, True)
        if any(len(k) == 34 and k[0] == 0x02 and k[1:] == pub for k, _ in m):
            continue
        digest = _p_digest(unsigned, i, prog, amount)
        sig = ctypes.create_string_buffer(64)
        assert lib.cnx_ecdsa_sign(sk, digest, sig) == 0
        pos = 0
        for j, (k, _) in enumerate(m):
            if k[0] <= 0x02:
                pos = j + 1
        m.insert(pos, (b"\x02" + pub, _sig_to_der(sig.raw) + b"\x01"))
    return _p_serialize(g, imaps, omaps)


def _p_finalize(raw):
    """Mirror of cxPsbtFinalize: returns (txid_hex, raw_tx_bytes)."""
    g, imaps, _, unsigned = _p_parse(raw)
    version, ins, outs, locktime = _p_parse_tx(unsigned)
    body_ins, wits = b"", b""
    for i, m in enumerate(imaps):
        prog, nested, _, _ = _p_input_prog(m)
        assert prog is not None, f"input {i} not single-key segwit"
        der = None
        for k, v in m:
            if len(k) == 34 and k[0] == 0x02 and _h160(k[1:]) == prog:
                pub, der = k[1:], v
                break
        assert der is not None, f"input {i} missing signature"
        ssig = (_p_varint(22) + b"\x00\x14" + prog) if nested else b""
        t, v, _, seq = ins[i]
        body_ins += (t + v.to_bytes(4, "little") + _p_varint(len(ssig))
                     + ssig + seq.to_bytes(4, "little"))
        wits += b"\x02" + _p_varint(len(der)) + der + b"\x21" + pub
    body_ins = _p_varint(len(ins)) + body_ins
    body_outs = _p_varint(len(outs)) + b"".join(
        v.to_bytes(8, "little") + _p_varint(len(s)) + s for v, s in outs)
    raw_tx = (version.to_bytes(4, "little") + b"\x00\x01" + body_ins
              + body_outs + wits + locktime.to_bytes(4, "little"))
    stripped = (version.to_bytes(4, "little") + body_ins + body_outs
                + locktime.to_bytes(4, "little"))
    return _dsha(stripped)[::-1].hex(), raw_tx


def run_psbt_checks(lib, kat):
    import base64
    # (a) the official creator vector re-encodes byte-exact
    raw = base64.b64decode(PSBT_CREATOR_B64)
    g, im, om, _ = _p_parse(raw)
    kat.check("PSBT official creator vector re-encodes byte-exact",
              _p_serialize(g, im, om) == raw)
    # (b) the BIP-143 example as a PSBT: construct, pin, sign, finalize
    pub = pubkey(lib, BIP143_KEY, True)
    redeem = b"\x00\x14" + _h160(pub)
    spk = b"\xa9\x14" + _h160(redeem) + b"\x87"
    wu = ((1000000000).to_bytes(8, "little") + _p_varint(len(spk)) + spk)
    unsigned = bytes.fromhex(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb"
        "1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a4"
        "6a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97"
        "fea7ad0402e8bd8ad6d77c88ac92040000")
    built = _p_serialize([(b"\x00", unsigned)],
                         [[(b"\x01", wu), (b"\x03", (1).to_bytes(4, "little")),
                           (b"\x04", redeem)]], [[], []])
    kat.check("PSBT of the BIP-143 example matches the pinned base64",
              base64.b64encode(built).decode() == PSBT143_IN_B64)
    signed = _p_sign(lib, built, BIP143_KEY)
    kat.check("signing it matches the pinned signed base64",
              base64.b64encode(signed).decode() == PSBT143_SIGNED_B64)
    psig = [v for k, v in _p_parse(signed)[1][0] if k[0] == 0x02][0]
    kat.check("the partial sig is the BIP's published DER",
              psig.hex() == BIP143_DER + "01")
    txid, raw_tx = _p_finalize(signed)
    kat.check("finalize extracts the BIP's published raw tx",
              raw_tx.hex() == BIP143_RAW)
    kat.check("finalized txid", txid == BIP143_NEW_TXID, txid)
    kat.check("an unrelated key leaves the PSBT byte-identical",
              _p_sign(lib, built, sk_bytes(1)) == built)
    # (c) HD signing from the canonical mnemonic via BIP32_DERIVATION
    seed = hashlib.pbkdf2_hmac("sha512", RESTORE_MNEMONIC.encode("ascii"),
                               b"mnemonic", 2048, 64)
    master = ctypes.create_string_buffer(73)
    lib.cnx_hdnode_from_seed(seed, len(seed), master)
    master = master.raw
    kat.check("master fingerprint of the canonical mnemonic",
              _h160(pubkey(lib, master[41:73], True))[:4].hex() == PSBT_MASTER_FP)
    hd_raw = base64.b64decode(PSBT_HD_B64)
    signed_hd = _p_sign(lib, hd_raw, master)
    txid_hd, raw_hd = _p_finalize(signed_hd)
    kat.check("HD-signed PSBT extracts the pinned raw tx",
              raw_hd.hex() == PSBT_HD_RAW, raw_hd.hex())
    kat.check("HD txid", txid_hd == PSBT_HD_TXID, txid_hd)


# ---------------------------------------------------------------------------
# EIP-712 typed structured data: the composable word/hashStruct/digest chain,
# locked to the OFFICIAL example in the EIP itself (the Mail struct, domain
# "Ether Mail", signed by the key keccak256("cow")): published digest, r, s,
# v = 28, and the famous signer address.
EIP712_DIGEST = \
    "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
EIP712_R = "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d"
EIP712_S = "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562"
EIP712_SIGNER = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"


def run_eip712_checks(lib, kat):
    K = lambda b: digest(lib, "cnx_keccak256", b)
    w_addr = lambda h: bytes(12) + bytes.fromhex(h)
    w_str = lambda t: K(t.encode())
    w_u = lambda n: n.to_bytes(32, "big")
    dom = K(K(b"EIP712Domain(string name,string version,uint256 chainId,"
              b"address verifyingContract)")
            + w_str("Ether Mail") + w_str("1") + w_u(1)
            + w_addr("cccccccccccccccccccccccccccccccccccccccc"))
    person = b"Person(string name,address wallet)"
    mail = b"Mail(Person from,Person to,string contents)" + person
    cow = K(K(person) + w_str("Cow")
            + w_addr("cd2a3d9f938e13cd947ec05abc7fe734df8dd826"))
    bob = K(K(person) + w_str("Bob")
            + w_addr("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
    msg = K(K(mail) + cow + bob + w_str("Hello, Bob!"))
    dg = K(b"\x19\x01" + dom + msg)
    kat.check("EIP-712 digest matches the EIP example", dg.hex() == EIP712_DIGEST)
    sk = K(b"cow")
    sig = ctypes.create_string_buffer(65)
    rc = lib.cnx_ecdsa_sign_recoverable(sk, dg, sig)
    kat.check("EIP-712 r matches", rc == 0 and sig.raw[:32].hex() == EIP712_R)
    kat.check("EIP-712 s matches", sig.raw[32:64].hex() == EIP712_S)
    kat.check("EIP-712 v = 28", sig.raw[64] + 27 == 28)
    kat.check("EIP-712 signer address",
              _eth_address(pubkey(lib, sk, False)) == EIP712_SIGNER)


# ---------------------------------------------------------------------------
# BIP-322 generic signed messages ("simple", P2WPKH). Anchors: the BIP's
# published message hashes and test address reproduce, our deterministic
# signature round-trips through the verify mirror, and - the interop that
# matters - the BIP's PUBLISHED signatures (made by Bitcoin Core, whose
# low-R nonce grinding makes different but equally valid bytes) VERIFY here.
BIP322_HASH_EMPTY = \
    "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
BIP322_HASH_HELLO = \
    "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
BIP322_WIF = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"
BIP322_ADDR = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
BIP322_SIG_HELLO = (
    "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFlu"
    "MGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XC"
    "sMvViHI=")
BIP322_SIG_EMPTY = (
    "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEyl"
    "yxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XC"
    "sMvViHI=")


def _b322_hash(msg):
    t = hashlib.sha256(b"BIP0322-signed-message").digest()
    return hashlib.sha256(t + t + msg).digest()


def _b322_sighash(h160, msg):
    def u32(n):
        return n.to_bytes(4, "little")

    def u64(n):
        return n.to_bytes(8, "little")
    ssig = b"\x00\x20" + _b322_hash(msg)
    spk = b"\x00\x14" + h160
    to_spend = (u32(0) + b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff"
                + bytes([len(ssig)]) + ssig + u32(0)
                + b"\x01" + u64(0) + bytes([len(spk)]) + spk + u32(0))
    outpoint = _dsha(to_spend) + u32(0)
    outs = u64(0) + b"\x01\x6a"
    sc = b"\x19\x76\xa9\x14" + h160 + b"\x88\xac"
    pre = (u32(0) + _dsha(outpoint) + _dsha(u32(0)) + outpoint + sc
           + u64(0) + u32(0) + _dsha(outs) + u32(0) + u32(1))
    return _dsha(pre)


def _b322_verify(lib, addr, msg, sig_b64):
    import base64
    got = _bech32_decode(addr)
    if isinstance(got, str) or got[1] != 0 or len(got[2]) != 20:
        return False
    w = base64.b64decode(sig_b64)
    if w[0] != 2:
        return False
    dlen = w[1]
    der = w[2:2 + dlen]
    if w[2 + dlen] != 33 or len(w) != 36 + dlen:
        return False
    pub = w[3 + dlen:36 + dlen]
    if _h160(pub) != got[2] or der[-1] != 1:
        return False
    rl = der[3]
    r = der[4:4 + rl].lstrip(b"\x00").rjust(32, b"\x00")
    sl = der[4 + rl + 1]
    sv = der[6 + rl:6 + rl + sl].lstrip(b"\x00").rjust(32, b"\x00")
    return lib.cnx_ecdsa_verify(pub, len(pub), _b322_sighash(got[2], msg),
                                r + sv) == 0


def run_bip322_checks(lib, kat):
    import base64
    kat.check("BIP-322 tagged hash of empty",
              _b322_hash(b"").hex() == BIP322_HASH_EMPTY)
    kat.check("BIP-322 tagged hash of Hello World",
              _b322_hash(b"Hello World").hex() == BIP322_HASH_HELLO)
    sk = _b58decode(BIP322_WIF)[1:33]
    pub = pubkey(lib, sk, True)
    kat.check("BIP-322 test key yields the published address",
              _bech32_p2wpkh("bc", _h160(pub)) == BIP322_ADDR)
    # the BIP's published Core signatures verify here (the interop anchor)
    kat.check("published Hello World signature verifies",
              _b322_verify(lib, BIP322_ADDR, b"Hello World", BIP322_SIG_HELLO))
    kat.check("published empty-message signature verifies",
              _b322_verify(lib, BIP322_ADDR, b"", BIP322_SIG_EMPTY))
    kat.check("a signature does not verify for a different message",
              not _b322_verify(lib, BIP322_ADDR, b"hello world",
                               BIP322_SIG_HELLO))
    # our own deterministic signature round-trips
    sig = ctypes.create_string_buffer(64)
    assert lib.cnx_ecdsa_sign(sk, _b322_sighash(_h160(pub), b"Hello World"),
                              sig) == 0
    der = _sig_to_der(sig.raw) + b"\x01"
    ours = base64.b64encode(b"\x02" + bytes([len(der)]) + der
                            + b"\x21" + pub).decode()
    kat.check("our deterministic signature verifies too",
              _b322_verify(lib, BIP322_ADDR, b"Hello World", ours))


# ---------------------------------------------------------------------------
# The wallet-restore path (the demo's headline feature): the canonical BIP-39
# test mnemonic restores, through the SHIM's real HD-node derivation, to the
# OFFICIAL BIP-84 and BIP-86 first addresses (those two strings are printed
# in the BIPs themselves, so they anchor the whole chain: mnemonic -> seed ->
# path -> key -> address), plus the widely published BIP-44 / BIP-49 /
# Ethereum m/44'/60' firsts, the BIP-84 account xpub, and the first key's
# WIF. These are exactly the strings the demo's Restore button must show.
RESTORE_MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon about")
RESTORE_VECTORS = {
    "m/44'/0'/0'/0/0": ("p2pkh", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
    "m/49'/0'/0'/0/0": ("p2sh-p2wpkh", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
    "m/84'/0'/0'/0/0": ("p2wpkh",
                        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
    "m/86'/0'/0'/0/0": ("p2tr",
                        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
    "m/44'/60'/0'/0/0": ("eth", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
    # the demo's fidelity listing shows receive #0..#9 and change #0; the
    # second receive and the first change address are ALSO printed in BIP-84
    # itself, and eth #1 is the widely published second account, so the
    # listing's continuation is anchored too, not just its first row
    "m/84'/0'/0'/0/1": ("p2wpkh",
                        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
    "m/84'/0'/0'/1/0": ("p2wpkh",
                        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
    "m/44'/60'/0'/0/1": ("eth", "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
}
RESTORE_ACCOUNT_XPUB = (
    "m/84'/0'/0'",
    "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAP"
    "shWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V")
RESTORE_FIRST_WIF = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"


def _hd_derive_path(lib, seed, path):
    node = ctypes.create_string_buffer(73)
    rc = lib.cnx_hdnode_from_seed(seed, len(seed), node)
    if rc != 0:
        return None
    for part in path.split("/")[1:]:
        hardened = part.endswith("'")
        index = int(part.rstrip("'"))
        child = ctypes.create_string_buffer(73)
        rc = lib.cnx_hdnode_derive(node.raw, index, 1 if hardened else 0, child)
        if rc != 0:
            return None
        node = child
    return node.raw


def run_restore_checks(lib, kat):
    seed = hashlib.pbkdf2_hmac("sha512", RESTORE_MNEMONIC.encode("ascii"),
                               b"mnemonic", 2048, 64)
    for path, (kind, expected) in RESTORE_VECTORS.items():
        blob = _hd_derive_path(lib, seed, path)
        if blob is None:
            kat.check(f"restore {path}", False, "derivation failed")
            continue
        pub33 = pubkey(lib, blob[41:73], True)
        if kind == "p2pkh":
            got = _b58check(0x00, _h160(pub33))
        elif kind == "p2sh-p2wpkh":
            got = _p2sh_p2wpkh(pub33, True)
        elif kind == "p2wpkh":
            got = _bech32_p2wpkh("bc", _h160(pub33))
        elif kind == "p2tr":
            out = ctypes.create_string_buffer(32)
            rc = lib.cnx_taproot_tweak_pubkey(pub33[1:], out)
            got = _bech32m_p2tr("bc", out.raw) if rc == 0 else "tweak failed"
        else:
            got = _eth_address(pubkey(lib, blob[41:73], False))
        kat.check(f"restore {path} -> {kind}", got == expected, got)
    # the watch-only account xpub the demo prints (BIP-84 account level)
    path, expected = RESTORE_ACCOUNT_XPUB
    blob = _hd_derive_path(lib, seed, path)
    got = _b58check_body(XPUB_VERSION + blob[0:41]
                         + pubkey(lib, blob[41:73], True))
    kat.check(f"restore {path} account xpub", got == expected, got)
    # the first BIP-84 key's WIF (the demo's export-a-single-key line)
    blob = _hd_derive_path(lib, seed, "m/84'/0'/0'/0/0")
    got = _wif(blob[41:73], True, True)
    kat.check("restore first-key WIF", got == RESTORE_FIRST_WIF, got)


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
        run_bip39_checks(lib, kat)
        run_hd_checks(lib, kat)
        run_schnorr_checks(lib, kat)
        run_taproot_checks(lib, kat)
        run_phase5_encoder_checks(lib, kat)
        run_rlp_eip155_checks(lib, kat)
        run_btc_tx_checks(lib, kat)
        run_psbt_checks(lib, kat)
        run_eip712_checks(lib, kat)
        run_bip322_checks(lib, kat)
        run_restore_checks(lib, kat)

    if kat.problems:
        for p in kat.problems:
            print("coin-kat: FAIL:", p)
        return 1
    skipnote = f" ({len(kat.skips)} skipped)" if kat.skips else ""
    print(f"coin-kat: self-check OK{skipnote}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
