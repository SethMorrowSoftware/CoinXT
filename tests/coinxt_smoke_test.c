/* coinxt_smoke_test.c - walk every phase-1/2 cnx_ export at least once.
 *
 * Two jobs, one file (the SodiumXT model, tests/sodium_smoke_test.c):
 *  - ctest runs it on every CI platform lane, so a lane whose compile
 *    succeeded but whose code misbehaves (a wrong-endian build, a broken
 *    RNG hook) fails loudly before its binary is shipped;
 *  - native/build.sh compiles this same file under ASan + UBSan (the `asan`
 *    mode), proving the walked paths memory- and UB-clean.
 * Correctness in depth is tools/coin-kat.py's job (public vectors, external
 * cross-check against python-ecdsa); this is the cheap always-run gate.
 */
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
extern int cnx_hdnode_from_seed(const unsigned char *, size_t, unsigned char *);
extern int cnx_hdnode_derive(const unsigned char *, int, int, unsigned char *);
extern int cnx_hdnode_private_key(const unsigned char *, unsigned char *);
extern int cnx_hdnode_public_key(const unsigned char *, unsigned char *);
extern int cnx_hdnode_chaincode(const unsigned char *, unsigned char *);
extern int cnx_xonly_from_seckey(const unsigned char *, unsigned char *);
extern int cnx_schnorr_sign(const unsigned char *, const unsigned char *, const unsigned char *, unsigned char *);
extern int cnx_schnorr_verify(const unsigned char *, const unsigned char *, const unsigned char *);
extern int cnx_taproot_tweak_pubkey(const unsigned char *, unsigned char *);
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
  unsigned char node[73], child[73], hdpriv[32], hdpub[33], hdcc[32];
  unsigned char xonly[32], schsig[64], aux[32];
  NEED(cnx_abi_version() == 3, "ABI");
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
  /* BIP-32: master node from a seed, one hardened + one normal derive step,
   * and the field accessors (correctness is pinned in tools/coin-kat.py) */
  memset(sh1, 0x2b, 16);
  NEED(cnx_hdnode_from_seed(sh1, 16, node) == 0, "hdnode from_seed");
  NEED(cnx_hdnode_derive(node, 44, 1, child) == 0, "hdnode derive hardened");
  NEED(cnx_hdnode_derive(child, 0, 0, node) == 0, "hdnode derive normal");
  NEED(cnx_hdnode_private_key(node, hdpriv) == 0, "hdnode privkey");
  NEED(cnx_hdnode_public_key(node, hdpub) == 0, "hdnode pubkey");
  NEED(cnx_hdnode_chaincode(node, hdcc) == 0, "hdnode chaincode");
  NEED(cnx_seckey_verify(hdpriv) == 0, "derived key is a valid seckey");
  /* Schnorr / BIP-340: x-only pubkey, sign (NULL aux + explicit aux), verify,
   * and corrupt-signature rejection (correctness pinned in tools/coin-kat.py) */
  NEED(cnx_xonly_from_seckey(sk1, xonly) == 0, "schnorr xonly");
  NEED(cnx_schnorr_sign(sk1, hash, NULL, schsig) == 0, "schnorr sign null aux");
  NEED(cnx_schnorr_verify(xonly, hash, schsig) == 0, "schnorr verify");
  memset(aux, 0x5a, 32);
  NEED(cnx_schnorr_sign(sk1, hash, aux, schsig) == 0, "schnorr sign aux");
  NEED(cnx_schnorr_verify(xonly, hash, schsig) == 0, "schnorr verify aux");
  schsig[10] ^= 1;
  NEED(cnx_schnorr_verify(xonly, hash, schsig) != 0, "schnorr corrupt rejected");
  /* Taproot: tweak the x-only key to a witness-v1 output key (BIP-341/86;
   * the vectors are pinned in tools/coin-kat.py) */
  NEED(cnx_taproot_tweak_pubkey(xonly, o) == 0, "taproot tweak");
  NEED(cnx_wipe(sh1, 32) == 0 && sh1[0] == 0 && sh1[31] == 0, "wipe");
  printf("cnx_selftest: OK\n");
  return 0;
}
