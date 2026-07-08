/* coinxt.c - the CoinXT C shim (cnx_ ABI) over vendored trezor-crypto.
 *
 * CoinXT wraps trezor-crypto (MIT) behind a thin, stable C ABI so an OXT / xTalk
 * app can reach Bitcoin/Ethereum crypto through one LCB foreign module. This file
 * is the ENTIRE native surface (SPEC.md section 5.1): every export is buffer-in /
 * buffer-out, returns an int status, and is deterministic. No I/O, no global
 * state (SPEC.md section 4).
 *
 * Phase 1: the full hash/KDF surface + the ABI guard + the length functions.
 * Phase 2: the secp256k1 curve surface (pubkey, ECDSA/RFC 6979, recoverable,
 * recover, ECDH). Phase 4b (ABI 3): BIP-32 HD child-key derivation and BIP-340
 * Schnorr, both transcribing a standard PUBLIC scheme over the audited
 * primitives already vendored rather than pulling in trezor's multi-curve
 * bip32.c or the whole secp256k1-zkp (see the section banners and VENDOR.md).
 * BIP-39 mnemonics live in the script layer (they need no curve math).
 *
 * ABI rules (CLAUDE.md, carried family FFI law):
 *  - byte buffers cross as Pointer + length; sizes are size_t;
 *  - every function returns int (0 ok, negative error);
 *  - never return a bridged/owned C string;
 *  - every length is a function, never a hardcoded LCB constant;
 *  - cnx_abi_version() gates a stale binary via the .lcb cxCheckABI();
 *  - fixed-size buffers (a 32-byte seckey, a 32-byte digest, a 64/65-byte
 *    signature) cross WITHOUT a redundant length argument; the LCB layer
 *    validates lengths against the cnx_*_len() functions before the call.
 *    Genuinely variable-length buffers (hash input, HMAC key/message, a
 *    33-or-65-byte pubkey) always cross with their length.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> /* memcpy for the HD node blob field moves */

#include "ecdsa.h"     /* vendored trezor-crypto: sign/verify/recover/ECDH   */
#include "bignum.h"    /* scalar range check for cnx_seckey_verify           */
#include "hmac.h"      /* HMAC-SHA256 / HMAC-SHA512                          */
#include "memzero.h"   /* best-effort wiping of secret temporaries           */
#include "pbkdf2.h"    /* PBKDF2-HMAC-SHA512 (BIP-39 seed derivation)        */
#include "rand.h"      /* declares the integrator hook we implement below    */
#include "ripemd160.h" /* RIPEMD-160 (Bitcoin hash160)                       */
#include "secp256k1.h" /* the one curve CoinXT exposes                       */
#include "sha2.h"      /* SHA-256 / SHA-512                                  */
#include "sha3.h"      /* keccak_256 / sha3_256 (one-shot)                   */

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h> /* BCryptGenRandom; link with -lbcrypt */
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
    defined(__NetBSD__)
#include <stdlib.h> /* arc4random_buf */
#else
#include <errno.h>
#include <stdio.h>
#include <sys/random.h> /* getrandom(2), glibc >= 2.25 and musl */
#endif

/* ---- ABI version + status codes (stable; never renumber a shipped code) ---- */

#define CNX_ABI_VERSION 3 /* 3: BIP-32 HD nodes + Schnorr/BIP-340 (2026-07-08) */

#define CNX_OK 0
#define CNX_ERR_NULL (-1)     /* a required buffer pointer was NULL */
#define CNX_ERR_BADLEN (-2)   /* a length argument was out of range */
#define CNX_ERR_BADKEY (-3)   /* seckey out of range, or pubkey not on the curve */
#define CNX_ERR_BADSIG (-4)   /* signature malformed, or does not verify */
#define CNX_ERR_RANGE (-5)    /* a numeric argument was out of range */
#define CNX_ERR_INTERNAL (-6) /* upstream failed on validated input (a bug) */

int cnx_abi_version(void) { return CNX_ABI_VERSION; }

/* ---- length constants exposed as functions (never hardcode a size in LCB) --- */

size_t cnx_keccak256_len(void) { return 32; }
size_t cnx_sha3_256_len(void) { return 32; }
size_t cnx_sha256_len(void) { return 32; }
size_t cnx_sha512_len(void) { return 64; }
size_t cnx_ripemd160_len(void) { return 20; }
size_t cnx_hmac_sha256_len(void) { return 32; }
size_t cnx_hmac_sha512_len(void) { return 64; }
size_t cnx_seckey_len(void) { return 32; }
size_t cnx_pubkey_len_compressed(void) { return 33; }
size_t cnx_pubkey_len_uncompressed(void) { return 65; }
size_t cnx_ecdsa_sig_len(void) { return 64; }
size_t cnx_recoverable_sig_len(void) { return 65; }
size_t cnx_digest_len(void) { return 32; }
size_t cnx_ecdh_secret_len(void) { return 32; }
size_t cnx_hdnode_len(void) { return 73; }
size_t cnx_chaincode_len(void) { return 32; }
size_t cnx_xonly_len(void) { return 32; }        /* BIP-340 x-only pubkey */
size_t cnx_schnorr_sig_len(void) { return 64; }  /* BIP-340 signature     */

/* ---- the trezor-crypto integrator RNG hook --------------------------------
 * The phase-0 assumption was that nothing calls this once signing is RFC 6979
 * and key material comes from the caller. That is FALSE at the vendored
 * commit: ecdsa.c calls random32() on EVERY curve operation for side-channel
 * blinding (curve_to_jacobian randomizes the Jacobian z coordinate; the
 * signing path additionally splits the nonce with a random scalar). That
 * randomness never reaches an output: every cnx_ result is still a pure
 * function of its inputs and stays KAT-pinned. So instead of aborting (which
 * would break every call) or a weak stub (which would silently defeat
 * upstream's hardening), we feed it the OS CSPRNG and fail LOUDLY (abort) if
 * the OS cannot supply entropy, because continuing would quietly downgrade
 * the side-channel protection around live private keys.
 * Fresh KEY material still never comes from here; it is the caller's
 * (SPEC.md section 4). */

void random_buffer(uint8_t *buf, size_t len) {
#if defined(_WIN32)
  if (BCryptGenRandom(NULL, buf, (ULONG)len,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    abort();
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
    defined(__NetBSD__)
  arc4random_buf(buf, len);
#else
  size_t off = 0;
  while (off < len) {
    ssize_t got = getrandom(buf + off, len - off, 0);
    if (got < 0) {
      if (errno == EINTR) continue;
      abort();
    }
    off += (size_t)got;
  }
#endif
}

/* ---- secret hygiene helper --------------------------------------------------
 * The LCB layer marshals out-buffers through engine MCMemoryAllocate blocks.
 * When such a block carried a secret (an ECDH shared secret; HD seckeys in a
 * later phase) it must be zeroed BEFORE MCMemoryDeallocate, with the same
 * best-effort memzero the vendored code uses, so the secret does not linger in
 * freed heap. Exposed as a cnx_ call because the LCB layer has no wipe of its
 * own. */

int cnx_wipe(unsigned char *buf, size_t len) {
  if (buf == NULL) return len == 0 ? CNX_OK : CNX_ERR_NULL;
  memzero(buf, len);
  return CNX_OK;
}

/* ---- hashes -----------------------------------------------------------------
 * Ethereum's "SHA3" is Keccak-256 (original 0x01 padding); NIST SHA3-256 uses
 * 0x06. They are DIFFERENT functions and must never be aliased (the classic
 * Ethereum footgun). trezor-crypto exposes both one-shot; we surface both.
 * Every out buffer is caller-allocated at the matching cnx_*_len() size. An
 * empty input is valid (in may be NULL only when inlen == 0; we substitute a
 * valid pointer so no hash internal ever dereferences NULL). */

static const unsigned char cnx_empty[1] = {0};

static int cnx_fix_null(const unsigned char **in, size_t inlen) {
  if (*in == NULL) {
    if (inlen != 0) return CNX_ERR_NULL;
    *in = cnx_empty;
  }
  return CNX_OK;
}

int cnx_keccak256(const unsigned char *in, size_t inlen, unsigned char *out32) {
  if (out32 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&in, inlen) != CNX_OK) return CNX_ERR_NULL;
  keccak_256(in, inlen, out32);
  return CNX_OK;
}

int cnx_sha3_256(const unsigned char *in, size_t inlen, unsigned char *out32) {
  if (out32 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&in, inlen) != CNX_OK) return CNX_ERR_NULL;
  sha3_256(in, inlen, out32);
  return CNX_OK;
}

int cnx_sha256(const unsigned char *in, size_t inlen, unsigned char *out32) {
  if (out32 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&in, inlen) != CNX_OK) return CNX_ERR_NULL;
  sha256_Raw(in, inlen, out32);
  return CNX_OK;
}

int cnx_sha512(const unsigned char *in, size_t inlen, unsigned char *out64) {
  if (out64 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&in, inlen) != CNX_OK) return CNX_ERR_NULL;
  sha512_Raw(in, inlen, out64);
  return CNX_OK;
}

int cnx_ripemd160(const unsigned char *in, size_t inlen, unsigned char *out20) {
  if (out20 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&in, inlen) != CNX_OK) return CNX_ERR_NULL;
  ripemd160(in, inlen, out20);
  return CNX_OK;
}

/* HMAC: upstream takes uint32_t lengths, so a size_t crossing 4 GiB would
 * silently truncate; refuse it instead (no sane MAC input is that large). An
 * empty KEY is legal HMAC (padded), so it gets the same NULL-with-zero fix. */

int cnx_hmac_sha256(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *out32) {
  if (out32 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&key, keylen) != CNX_OK) return CNX_ERR_NULL;
  if (cnx_fix_null(&msg, msglen) != CNX_OK) return CNX_ERR_NULL;
  if (keylen > UINT32_MAX || msglen > UINT32_MAX) return CNX_ERR_BADLEN;
  hmac_sha256(key, (uint32_t)keylen, msg, (uint32_t)msglen, out32);
  return CNX_OK;
}

int cnx_hmac_sha512(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *out64) {
  if (out64 == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&key, keylen) != CNX_OK) return CNX_ERR_NULL;
  if (cnx_fix_null(&msg, msglen) != CNX_OK) return CNX_ERR_NULL;
  if (keylen > UINT32_MAX || msglen > UINT32_MAX) return CNX_ERR_BADLEN;
  hmac_sha512(key, (uint32_t)keylen, msg, (uint32_t)msglen, out64);
  return CNX_OK;
}

/* PBKDF2-HMAC-SHA512. iters crosses as a plain int (a BIP-39 seed uses 2048;
 * nothing legitimate needs > 2^31). outlen is the caller's requested key
 * length; upstream takes int lengths, so both are range-checked. A password or
 * salt may legally be empty. */

int cnx_pbkdf2_hmac_sha512(const unsigned char *pw, size_t pwlen,
                           const unsigned char *salt, size_t saltlen,
                           int iters, unsigned char *out, size_t outlen) {
  if (out == NULL) return CNX_ERR_NULL;
  if (cnx_fix_null(&pw, pwlen) != CNX_OK) return CNX_ERR_NULL;
  if (cnx_fix_null(&salt, saltlen) != CNX_OK) return CNX_ERR_NULL;
  if (pwlen > INT_MAX || saltlen > INT_MAX) return CNX_ERR_BADLEN;
  if (outlen == 0 || outlen > INT_MAX) return CNX_ERR_BADLEN;
  if (iters < 1) return CNX_ERR_RANGE;
  pbkdf2_hmac_sha512(pw, (int)pwlen, salt, (int)saltlen, (uint32_t)iters, out,
                     (int)outlen);
  return CNX_OK;
}

/* ---- secp256k1 (phase 2) ----------------------------------------------------
 * The curve is fixed: CoinXT exposes secp256k1 only (both chains use it), so
 * no curve parameter crosses the ABI. Upstream's return conventions are
 * inconsistent (sign/verify/recover/ecdh return 0 on success; read/uncompress
 * return 1 on success); everything is normalized here to the cnx_ codes so the
 * LCB layer sees exactly one convention.
 *
 * Signatures are 64 bytes r||s, big-endian, and are ALWAYS low-s: upstream
 * canonicalizes s > n/2 to n - s inside ecdsa_sign_digest (BIP-62; what
 * EIP-2 requires). Verification keeps upstream semantics: any mathematically
 * valid signature verifies, including a high-s one from another producer;
 * malformed r/s (zero or >= n) fail closed as CNX_ERR_BADSIG.
 *
 * A recoverable signature is 65 bytes r||s||recid with recid the RAW 0..3
 * recovery id (bit 0: R.y parity, bit 1: R.x overflowed the order). Mapping
 * to Ethereum's v (27/28, or EIP-155) is presentation and stays in script. */

/* A valid seckey is a scalar in [1, n-1] (upstream's own validity rule, the
 * same check tc_ecdsa_get_public_key33 performs before using a key). */
int cnx_seckey_verify(const unsigned char *sk32) {
  bignum256 k;
  int valid = 0;
  if (sk32 == NULL) return CNX_ERR_NULL;
  bn_read_be(sk32, &k);
  valid = !bn_is_zero(&k) && bn_is_less(&k, &secp256k1.order);
  memzero(&k, sizeof(k));
  return valid ? CNX_OK : CNX_ERR_BADKEY;
}

/* compressed != 0 writes 33 bytes (02/03||x) into out; 0 writes 65 bytes
 * (04||x||y). The LCB layer sizes out via cnx_pubkey_len_*(). */
int cnx_pubkey_from_seckey(const unsigned char *sk32, int compressed,
                           unsigned char *out) {
  int rc = 0;
  if (sk32 == NULL || out == NULL) return CNX_ERR_NULL;
  if (compressed)
    rc = ecdsa_get_public_key33(&secp256k1, sk32, out);
  else
    rc = ecdsa_get_public_key65(&secp256k1, sk32, out);
  return rc == 0 ? CNX_OK : CNX_ERR_BADKEY;
}

/* Accepts a 33-byte compressed (02/03) or 65-byte uncompressed (04) pubkey;
 * writes the 65-byte uncompressed form. The prefix byte must match publen so
 * a truncated buffer can never be over-read. */
int cnx_pubkey_decompress(const unsigned char *pub, size_t publen,
                          unsigned char *out65) {
  if (pub == NULL || out65 == NULL) return CNX_ERR_NULL;
  if (publen == 33) {
    if (pub[0] != 0x02 && pub[0] != 0x03) return CNX_ERR_BADKEY;
  } else if (publen == 65) {
    if (pub[0] != 0x04) return CNX_ERR_BADKEY;
  } else {
    return CNX_ERR_BADLEN;
  }
  if (ecdsa_uncompress_pubkey(&secp256k1, pub, out65) != 1)
    return CNX_ERR_BADKEY;
  return CNX_OK;
}

/* Deterministic ECDSA (RFC 6979) over the caller's 32-byte digest. CoinXT
 * never builds the digest: sign exactly what the app constructed (SPEC.md
 * section 8 rule 5). out_sig64 = r||s, always low-s. */
int cnx_ecdsa_sign(const unsigned char *sk32, const unsigned char *hash32,
                   unsigned char *out_sig64) {
  int rc = 0;
  if (sk32 == NULL || hash32 == NULL || out_sig64 == NULL) return CNX_ERR_NULL;
  if (cnx_seckey_verify(sk32) != CNX_OK) return CNX_ERR_BADKEY;
  rc = ecdsa_sign_digest(&secp256k1, sk32, hash32, out_sig64, NULL, NULL);
  /* the key was pre-validated, so a failure here is upstream's retry loop
   * exhausting (probability ~2^-256 per RFC 6979) or a real bug: loud code */
  return rc == 0 ? CNX_OK : CNX_ERR_INTERNAL;
}

int cnx_ecdsa_verify(const unsigned char *pub, size_t publen,
                     const unsigned char *hash32,
                     const unsigned char *sig64) {
  int rc = 0;
  if (pub == NULL || hash32 == NULL || sig64 == NULL) return CNX_ERR_NULL;
  if (publen == 33) {
    if (pub[0] != 0x02 && pub[0] != 0x03) return CNX_ERR_BADKEY;
  } else if (publen == 65) {
    if (pub[0] != 0x04) return CNX_ERR_BADKEY;
  } else {
    return CNX_ERR_BADLEN;
  }
  rc = ecdsa_verify_digest(&secp256k1, pub, sig64, hash32);
  if (rc == 0) return CNX_OK;
  /* upstream: 1 = pubkey rejected; 2..5 = r/s out of range or no match */
  return rc == 1 ? CNX_ERR_BADKEY : CNX_ERR_BADSIG;
}

/* Recoverable variant for Ethereum: out_sig65 = r||s||recid (raw 0..3). */
int cnx_ecdsa_sign_recoverable(const unsigned char *sk32,
                               const unsigned char *hash32,
                               unsigned char *out_sig65) {
  int rc = 0;
  uint8_t recid = 0;
  if (sk32 == NULL || hash32 == NULL || out_sig65 == NULL) return CNX_ERR_NULL;
  if (cnx_seckey_verify(sk32) != CNX_OK) return CNX_ERR_BADKEY;
  rc = ecdsa_sign_digest(&secp256k1, sk32, hash32, out_sig65, &recid, NULL);
  if (rc != 0) return CNX_ERR_INTERNAL;
  out_sig65[64] = recid;
  return CNX_OK;
}

/* ecrecover: sig65 = r||s||recid (raw 0..3; the script layer strips any
 * 27/EIP-155 offset first). Writes the 65-byte uncompressed signer pubkey. */
int cnx_ecdsa_recover(const unsigned char *sig65, const unsigned char *hash32,
                      unsigned char *out_pub65) {
  if (sig65 == NULL || hash32 == NULL || out_pub65 == NULL) return CNX_ERR_NULL;
  if (sig65[64] > 3) return CNX_ERR_BADSIG;
  if (ecdsa_recover_pub_from_sig(&secp256k1, out_pub65, sig65, hash32,
                                 (int)sig65[64]) != 0)
    return CNX_ERR_BADSIG;
  return CNX_OK;
}

/* ECDH: out32 is the raw SEC1 shared secret, the big-endian X coordinate of
 * sk * P (no hash, no KDF), so it cross-checks 1:1 against any standard
 * library; a protocol that wants a derived key hashes it in script. The full
 * 65-byte shared point is a secret intermediate and is wiped here. */
int cnx_ecdh(const unsigned char *sk32, const unsigned char *pub,
             size_t publen, unsigned char *out32) {
  uint8_t session[65];
  int rc = 0;
  size_t i = 0;
  if (sk32 == NULL || pub == NULL || out32 == NULL) return CNX_ERR_NULL;
  if (cnx_seckey_verify(sk32) != CNX_OK) return CNX_ERR_BADKEY;
  if (publen == 33) {
    if (pub[0] != 0x02 && pub[0] != 0x03) return CNX_ERR_BADKEY;
  } else if (publen == 65) {
    if (pub[0] != 0x04) return CNX_ERR_BADKEY;
  } else {
    return CNX_ERR_BADLEN;
  }
  rc = ecdh_multiply(&secp256k1, sk32, pub, session);
  if (rc != 0) {
    memzero(session, sizeof(session));
    return CNX_ERR_BADKEY;
  }
  for (i = 0; i < 32; i++) out32[i] = session[1 + i];
  memzero(session, sizeof(session));
  return CNX_OK;
}

/* ---- HD (BIP-32) nodes, secp256k1 only --------------------------------------
 * The node crosses the ABI as a fixed 73-byte opaque blob (SPEC.md 5.1):
 *   [depth:1][parent_fingerprint:4][child_num:4 BE][chain_code:32][priv:32]
 * These are exactly the fields BIP-32's xprv/xpub serialization needs; the
 * script layer adds the version bytes and Base58Check framing.
 *
 * We deliberately do NOT vendor trezor's bip32.c: it is multi-curve and drags
 * in the whole tree (aes, cardano, nem, nist256p1, the ed25519-donna subtree).
 * cnx_hdnode_derive instead transcribes trezor's OWN secp256k1 child-key
 * derivation (hdnode_private_ckd_bip32) over the same audited primitives we
 * already vendor (hmac_sha512, bn_add/bn_mod, ecdsa_get_public_key33). Every
 * result is pinned to the official BIP-32 test vectors headless
 * (tools/coin-kat.py). This is a standard, public KEY-DERIVATION SCHEME
 * composing audited ops - like hash160 or the address encoders - not a new
 * curve op or hash. */

#define CNX_HDNODE_LEN 73
#define CNX_HD_DEPTH 0
#define CNX_HD_FP 1
#define CNX_HD_CHILD 5
#define CNX_HD_CC 9
#define CNX_HD_KEY 41

/* cnx_hdnode_len() is defined with the other length functions above. */

/* fingerprint = first 4 bytes of hash160(pubkey33) */
static void cnx_hd_fingerprint(const unsigned char *pub33, unsigned char *out4) {
  unsigned char sha[32], rip[20];
  sha256_Raw(pub33, 33, sha);
  ripemd160(sha, 32, rip);
  out4[0] = rip[0];
  out4[1] = rip[1];
  out4[2] = rip[2];
  out4[3] = rip[3];
}

static void cnx_put_be32(unsigned char *p, uint32_t v) {
  p[0] = (unsigned char)((v >> 24) & 0xff);
  p[1] = (unsigned char)((v >> 16) & 0xff);
  p[2] = (unsigned char)((v >> 8) & 0xff);
  p[3] = (unsigned char)(v & 0xff);
}

/* master node from a seed: I = HMAC-SHA512("Bitcoin seed", seed); IL is the
 * master private key (must be in [1, n-1]; a seed producing an out-of-range IL
 * is rejected, ~2^-128), IR the chain code. depth 0, fingerprint 0, child 0. */
int cnx_hdnode_from_seed(const unsigned char *seed, size_t slen,
                         unsigned char *out_node) {
  unsigned char I[64];
  bignum256 a;
  int ok;
  if (seed == NULL || out_node == NULL) return CNX_ERR_NULL;
  if (slen == 0 || slen > UINT32_MAX) return CNX_ERR_BADLEN;
  hmac_sha512((const uint8_t *)"Bitcoin seed", 12, seed, (uint32_t)slen, I);
  bn_read_be(I, &a);
  ok = !bn_is_zero(&a) && bn_is_less(&a, &secp256k1.order);
  memzero(&a, sizeof(a));
  if (!ok) {
    memzero(I, sizeof(I));
    return CNX_ERR_BADKEY;
  }
  memzero(out_node, CNX_HDNODE_LEN);
  out_node[CNX_HD_DEPTH] = 0;
  /* fingerprint (4) and child (4) already zero from memzero */
  memcpy(out_node + CNX_HD_CC, I + 32, 32);
  memcpy(out_node + CNX_HD_KEY, I, 32);
  memzero(I, sizeof(I));
  return CNX_OK;
}

/* one BIP-32 step. index is 0..2^31-1; hardened != 0 sets the high bit. The
 * out node's parent_fingerprint is hash160(parent pubkey)[:4], so the child
 * blob is fully serializable to xprv/xpub in script. Returns CNX_ERR_BADKEY on
 * the ~2^-127 case where IL >= n or the child key is zero (BIP-32 says use the
 * next index); the caller retries with index+1. */
int cnx_hdnode_derive(const unsigned char *node, int index, int hardened,
                      unsigned char *out_node) {
  unsigned char data[1 + 32 + 4];
  unsigned char I[64];
  unsigned char parent_pub[33];
  bignum256 a, b;
  uint32_t i;
  if (node == NULL || out_node == NULL) return CNX_ERR_NULL;
  if (index < 0) return CNX_ERR_RANGE;
  i = (uint32_t)index;
  if (hardened) i |= 0x80000000u;

  /* the parent pubkey is needed for a non-hardened step's data AND for the
   * child's parent fingerprint, so derive it up front */
  if (ecdsa_get_public_key33(&secp256k1, node + CNX_HD_KEY, parent_pub) != 0)
    return CNX_ERR_BADKEY;

  if (i & 0x80000000u) {
    data[0] = 0;
    memcpy(data + 1, node + CNX_HD_KEY, 32); /* 0x00 || parent priv */
  } else {
    memcpy(data, parent_pub, 33);
  }
  cnx_put_be32(data + 33, i);

  bn_read_be(node + CNX_HD_KEY, &a);
  hmac_sha512(node + CNX_HD_CC, 32, data, sizeof(data), I);

  bn_read_be(I, &b);
  if (!bn_is_less(&b, &secp256k1.order)) {
    memzero(&a, sizeof(a));
    memzero(&b, sizeof(b));
    memzero(I, sizeof(I));
    return CNX_ERR_BADKEY;
  }
  bn_add(&b, &a);              /* b = IL + kpar */
  bn_mod(&b, &secp256k1.order); /* mod n */
  if (bn_is_zero(&b)) {
    memzero(&a, sizeof(a));
    memzero(&b, sizeof(b));
    memzero(I, sizeof(I));
    return CNX_ERR_BADKEY;
  }

  out_node[CNX_HD_DEPTH] = (unsigned char)(node[CNX_HD_DEPTH] + 1);
  cnx_hd_fingerprint(parent_pub, out_node + CNX_HD_FP);
  cnx_put_be32(out_node + CNX_HD_CHILD, i);
  memcpy(out_node + CNX_HD_CC, I + 32, 32);
  bn_write_be(&b, out_node + CNX_HD_KEY);

  memzero(&a, sizeof(a));
  memzero(&b, sizeof(b));
  memzero(I, sizeof(I));
  memzero(data, sizeof(data));
  return CNX_OK;
}

int cnx_hdnode_private_key(const unsigned char *node, unsigned char *out32) {
  if (node == NULL || out32 == NULL) return CNX_ERR_NULL;
  memcpy(out32, node + CNX_HD_KEY, 32);
  return CNX_OK;
}

int cnx_hdnode_public_key(const unsigned char *node, unsigned char *out33) {
  if (node == NULL || out33 == NULL) return CNX_ERR_NULL;
  if (ecdsa_get_public_key33(&secp256k1, node + CNX_HD_KEY, out33) != 0)
    return CNX_ERR_BADKEY;
  return CNX_OK;
}

int cnx_hdnode_chaincode(const unsigned char *node, unsigned char *out32) {
  if (node == NULL || out32 == NULL) return CNX_ERR_NULL;
  memcpy(out32, node + CNX_HD_CC, 32);
  return CNX_OK;
}

/* ---- Schnorr / BIP-340 (Taproot), secp256k1 only ----------------------------
 * BIP-340 Schnorr signatures over the caller's 32-byte message. As with ECDSA,
 * CoinXT signs exactly the bytes the app hands it and never builds the sighash
 * (SPEC.md section 8 rule 5). Like BIP-32 above, this is NOT a new curve op: it
 * transcribes the BIP-340 SCHEME - a standard, published construction - over
 * the same audited trezor-crypto primitives already vendored (scalar_multiply
 * = k*G, point_multiply = k*P, point_add, uncompress_coords = lift_x, the bn_*
 * modular arithmetic, sha256). We deliberately do NOT vendor secp256k1-zkp: its
 * zkp_bip340.c pulls the entire secp256k1-zkp library (precomputed tables and
 * all), a far larger and riskier surface than composing the ops we already
 * audit. Every path is pinned to the OFFICIAL BIP-340 test vectors headless
 * (tools/coin-kat.py), including the INVALID-signature cases, and a CoinXT
 * signature must also verify in an independent library before VERIFY -> fact.
 *
 * Determinism: BIP-340 signing is a pure function of (seckey, msg, aux_rand).
 * aux_rand is a CALLER-supplied OPTIONAL 32-byte buffer (NULL -> 32 zero bytes,
 * BIP-340's fully-defined default), so no shim RNG feeds the output and every
 * signature stays KAT-pinned. (trezor's scalar/point multiply still call
 * random32() for internal Jacobian blinding only; that never changes the
 * result, exactly as for ECDSA.) */

/* tagged hash = SHA256(SHA256(tag) || SHA256(tag) || msg), BIP-340 section 3.
 * The doubled 32-byte tag hash domain-separates each of the three hashes. */
static void cnx_tagged_hash(const char *tag, size_t taglen,
                            const unsigned char *msg, size_t msglen,
                            unsigned char *out32) {
  unsigned char th[32];
  SHA256_CTX ctx;
  sha256_Raw((const uint8_t *)tag, taglen, th);
  sha256_Init(&ctx);
  sha256_Update(&ctx, th, 32);
  sha256_Update(&ctx, th, 32);
  sha256_Update(&ctx, msg, msglen);
  sha256_Final(&ctx, out32);
}

/* The BIP-340 x-only public key is x(d*G): the 32-byte big-endian x-coordinate,
 * independent of the point's y parity (negating the point leaves x unchanged).
 * We reuse the compressed pubkey and drop its 02/03 prefix. */
int cnx_xonly_from_seckey(const unsigned char *sk32, unsigned char *out32) {
  unsigned char pub33[33];
  if (sk32 == NULL || out32 == NULL) return CNX_ERR_NULL;
  if (cnx_seckey_verify(sk32) != CNX_OK) return CNX_ERR_BADKEY;
  if (ecdsa_get_public_key33(&secp256k1, sk32, pub33) != 0)
    return CNX_ERR_BADKEY;
  memcpy(out32, pub33 + 1, 32);
  memzero(pub33, sizeof(pub33));
  return CNX_OK;
}

/* BIP-340 Sign(sk, m, a). sk32 is the 32-byte secret (in [1, n-1]); msg32 the
 * 32-byte message; aux32 the optional 32-byte auxiliary randomness (NULL -> 32
 * zero bytes). out_sig64 = bytes(R) || bytes((k + e*d) mod n). Follows the
 * BIP-340 reference pseudocode step for step; the bn_* discipline mirrors
 * trezor's own tc_ecdsa_sign_digest. */
int cnx_schnorr_sign(const unsigned char *sk32, const unsigned char *msg32,
                     const unsigned char *aux32, unsigned char *out_sig64) {
  unsigned char aux_default[32] = {0};
  unsigned char d_bytes[32], p_x[32], t[32], rnd[32], r_x[32], e_bytes[32];
  unsigned char aux_hash[32], buf[96];
  bignum256 d, k, e, ed;
  curve_point P, R;
  const bignum256 *order = &secp256k1.order;
  int i, rc = CNX_ERR_INTERNAL;
  if (sk32 == NULL || msg32 == NULL || out_sig64 == NULL) return CNX_ERR_NULL;
  if (aux32 == NULL) aux32 = aux_default;
  if (cnx_seckey_verify(sk32) != CNX_OK) return CNX_ERR_BADKEY;

  /* d' = int(sk) in [1, n-1] (verified). P = d'*G; bytes(P) = x(P). */
  bn_read_be(sk32, &d);
  if (scalar_multiply(&secp256k1, &d, &P) != 0) goto done;
  bn_write_be(&P.x, p_x);
  /* d = d' if P has even y, else n - d' */
  if (bn_is_odd(&P.y)) bn_subtract(order, &d, &d);
  bn_write_be(&d, d_bytes);

  /* t = bytes(d) XOR hash_BIP0340/aux(a) */
  cnx_tagged_hash("BIP0340/aux", 11, aux32, 32, aux_hash);
  for (i = 0; i < 32; i++) t[i] = (unsigned char)(d_bytes[i] ^ aux_hash[i]);

  /* rand = hash_BIP0340/nonce(t || bytes(P) || m); k' = int(rand) mod n != 0 */
  memcpy(buf, t, 32);
  memcpy(buf + 32, p_x, 32);
  memcpy(buf + 64, msg32, 32);
  cnx_tagged_hash("BIP0340/nonce", 13, buf, 96, rnd);
  bn_read_be(rnd, &k);
  bn_mod(&k, order);
  if (bn_is_zero(&k)) goto done;

  /* R = k'*G; k = k' if R has even y, else n - k'. bytes(R) = x(R). */
  if (scalar_multiply(&secp256k1, &k, &R) != 0) goto done;
  bn_write_be(&R.x, r_x);
  if (bn_is_odd(&R.y)) bn_subtract(order, &k, &k);

  /* e = int(hash_BIP0340/challenge(bytes(R) || bytes(P) || m)) mod n */
  memcpy(buf, r_x, 32);
  memcpy(buf + 32, p_x, 32);
  memcpy(buf + 64, msg32, 32);
  cnx_tagged_hash("BIP0340/challenge", 17, buf, 96, e_bytes);
  bn_read_be(e_bytes, &e);
  bn_mod(&e, order);

  /* s = (k + e*d) mod n; sig = bytes(R) || bytes(s) */
  ed = d;
  bn_multiply(&e, &ed, order);  /* ed = e*d mod n */
  bn_add(&k, &ed);              /* k = k + e*d */
  bn_mod(&k, order);            /* mod n */
  memcpy(out_sig64, r_x, 32);
  bn_write_be(&k, out_sig64 + 32);
  rc = CNX_OK;

done:
  memzero(&d, sizeof(d));
  memzero(&k, sizeof(k));
  memzero(&ed, sizeof(ed));
  memzero(&P, sizeof(P));
  memzero(&R, sizeof(R));
  memzero(d_bytes, sizeof(d_bytes));
  memzero(t, sizeof(t));
  memzero(rnd, sizeof(rnd));
  memzero(aux_hash, sizeof(aux_hash));
  memzero(buf, sizeof(buf));
  if (rc != CNX_OK) memzero(out_sig64, 64);
  return rc;
}

/* BIP-340 Verify(pk, m, sig). pk32 is the 32-byte x-only pubkey; msg32 the
 * 32-byte message; sig64 = r(32) || s(32). Returns CNX_OK iff the signature is
 * valid, CNX_ERR_BADSIG otherwise (fail closed on any malformed field). */
int cnx_schnorr_verify(const unsigned char *pk32, const unsigned char *msg32,
                       const unsigned char *sig64) {
  unsigned char buf[96], e_bytes[32];
  bignum256 r, s, e;
  curve_point P, sG, eP;
  const bignum256 *order = &secp256k1.order;
  const bignum256 *prime = &secp256k1.prime;
  int ok = 0;
  if (pk32 == NULL || msg32 == NULL || sig64 == NULL) return CNX_ERR_NULL;

  /* P = lift_x(int(pk)): x < p, and (x, even y) must be on the curve. */
  bn_read_be(pk32, &P.x);
  if (!bn_is_less(&P.x, prime)) return CNX_ERR_BADSIG;
  uncompress_coords(&secp256k1, 0x02 /* want even y */, &P.x, &P.y);
  if (!ecdsa_validate_pubkey(&secp256k1, &P)) return CNX_ERR_BADSIG;

  /* r = int(sig[0:32]) < p; s = int(sig[32:64]) < n */
  bn_read_be(sig64, &r);
  bn_read_be(sig64 + 32, &s);
  if (!bn_is_less(&r, prime) || !bn_is_less(&s, order)) return CNX_ERR_BADSIG;

  /* e = int(hash_BIP0340/challenge(bytes(r) || bytes(P) || m)) mod n */
  memcpy(buf, sig64, 32);        /* bytes(r) is sig[0:32] verbatim */
  memcpy(buf + 32, pk32, 32);    /* bytes(P) is the x-only pubkey  */
  memcpy(buf + 64, msg32, 32);
  cnx_tagged_hash("BIP0340/challenge", 17, buf, 96, e_bytes);
  bn_read_be(e_bytes, &e);
  bn_mod(&e, order);

  /* R = s*G - e*P (negate e*P by flipping its y, then add). */
  if (scalar_multiply(&secp256k1, &s, &sG) != 0) return CNX_ERR_INTERNAL;
  if (point_multiply(&secp256k1, &e, &P, &eP) != 0) return CNX_ERR_INTERNAL;
  bn_subtract(prime, &eP.y, &eP.y);  /* -eP */
  point_add(&secp256k1, &eP, &sG);   /* sG = -eP + sG = s*G - e*P = R */

  /* accept iff R is finite, has even y, and x(R) == r */
  ok = !point_is_infinity(&sG) && !bn_is_odd(&sG.y) && bn_is_equal(&sG.x, &r);
  return ok ? CNX_OK : CNX_ERR_BADSIG;
}
