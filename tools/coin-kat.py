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
