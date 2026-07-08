-- coinxt-tests.livecodescript - CoinXT's on-engine self-test harness.
--
-- Exercises the public cx* API (src/coinxt.livecodescript over the coinxt LCB
-- extension) with the SAME public known-answer vectors tools/coin-kat.py pins
-- headless, plus the negative paths (corrupt signatures, malformed keys, the
-- fail-closed error contract). Where coin-kat.py proves the NATIVE shim, this
-- harness proves the two script layers above it on a real engine: the FFI
-- marshalling, the length checks, the throw-to-error-string mapping, and the
-- boolean fail-closed predicates.
--
-- How to run, once the CoinXT extension is installed (so org.openxtalk.library
-- .coinxt is loaded) and src/coinxt.livecodescript is in scope (e.g. `start
-- using` it as a script-only stack), from the message box:
--     put cxSelfTest()
-- It returns a per-check report and a PASSED/FAILED summary. If the extension
-- or the native library is missing the harness reports that ONE failure and
-- skips the rest (nothing else could pass, so the noise would hide the cause).
--
-- Every pinned constant below is a PUBLIC vector, cross-checked against an
-- independent implementation (hashlib / hmac / python-ecdsa) before pinning
-- (the CLAUDE.md testing rule); the RFC 6979 signature is the classic public
-- secp256k1 vector (seckey 1, "Satoshi Nakamoto", low-s form).
--
-- Verified statically (tools/check-livecodescript.py); needs an on-engine run.

local sLog
local sPass
local sFail

-- seckey scalars as 32-byte big-endian hex (public test values; never fund)
constant kSk1 = "0000000000000000000000000000000000000000000000000000000000000001"
constant kSkA = "00000000000000000000000000000000000000000000000000000000000a11ce"
constant kSkB = "0000000000000000000000000000000000000000000000000000000000000b0b"
-- the generator G = pubkey(1), compressed and uncompressed (curve constants)
constant kG33 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
constant kG65 = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
-- sha256("Satoshi Nakamoto") and the classic RFC 6979 signature of it by sk=1
constant kHashSatoshi = "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"
constant kSigSatoshi = "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
-- pubkey(0xB0B) compressed, and x(0xA11CE * 0xB0B * G), the raw SEC1 ECDH secret
constant kPubB33 = "035d45cb81aa765d69ca52e3869491ecf0e8fdf6a63d64e65b5213647ee4973ae5"
constant kEcdhX = "74f43c053591097e99e0886e03499baec02c6702a12db92347151afadf03cd8d"
-- canonical mainnet addresses of pubkey(1): the legacy Base58Check address,
-- the BIP-173 SegWit example, and the pk=1 Ethereum EIP-55 address (all public)
constant kAddrP2PKH = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
constant kAddrP2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
constant kAddrEth = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
-- the classic BIP-39 vector: all-zero 128-bit entropy, its mnemonic, and the
-- seed with passphrase "TREZOR" (the Trezor python-mnemonic test vectors)
constant kEnt128 = "00000000000000000000000000000000"
constant kMnem128 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
constant kSeed128 = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
-- BIP-32 test vector 1: seed, master xprv/xpub, and the m/0' xprv/xpub
constant kBip32Seed = "000102030405060708090a0b0c0d0e0f"
constant kXprvM = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
constant kXpubM = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
constant kXprvM0H = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
constant kXpubM0H = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
-- BIP-340 test vector 0: seckey, x-only pubkey, message, aux_rand, signature
constant kSchnorrSk = "0000000000000000000000000000000000000000000000000000000000000003"
constant kSchnorrPk = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
constant kSchnorrMsg = "0000000000000000000000000000000000000000000000000000000000000000"
constant kSchnorrAux = "0000000000000000000000000000000000000000000000000000000000000000"
constant kSchnorrSig = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
-- BIP-86 Taproot: the first receiving key's x-only internal key and bc1p address
constant kTapInternal = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
constant kTapAddr = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
-- the witness program inside kTapAddr (the published BIP-86 output key)
constant kTapOutput = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
-- WIF of seckey 1: the famous published pair, plus the testnet compressed form
constant kWif1C = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
constant kWif1U = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
constant kWif1TC = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
-- P2SH-P2WPKH (BIP-49 nested SegWit) of pubkey(1), mainnet
constant kAddrP2SH = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
-- EIP-191 personal-message digest of "hello" (locked in tools/coin-kat.py
-- from two independent keccak implementations)
constant kPersonalHello = "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
-- wallet restore: the canonical mnemonic kMnem128 with an EMPTY passphrase
-- restores to these (the 84/86 strings are the OFFICIAL BIP test vectors;
-- all seven are locked through the real shim in tools/coin-kat.py)
constant kRestA44 = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
constant kRestA49 = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
constant kRestA84 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
constant kRestA86 = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
constant kRestAEth = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
constant kRestXpub84 = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
constant kRestWif84 = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"

function cxSelfTest
   local tAbi
   put "CoinXT self-test" & return into sLog
   put 0 into sPass
   put 0 into sFail

   -- Gate everything on BOTH layers being reachable. The cx* functions live
   -- in src/coinxt.livecodescript, a SEPARATE script library from this stack:
   -- if it is not loaded, a bare cxCheckABI() call raises the engine error
   -- "Function: error in function handler, Hint: cxCheckABI" (paid for
   -- on-engine, 2026-07-08), so probe it inside try/catch and report the
   -- cause cleanly instead of erroring out.
   try
      put cxCheckABI() into tAbi
   catch tErr
      put "  FAIL calling cxCheckABI raised:" && tErr & return after sLog
      put return & "SKIPPED: the cx* API is not reachable at all. This harness needs BOTH layers:" & return after sLog
      put "  1. the packaged CoinXT extension installed (org.openxtalk.library.coinxt" & return after sLog
      put "     with its code/<arch>-<platform>/coinxt library), and" & return after sLog
      put "  2. src/coinxt.livecodescript loaded as a library (start using it)." & return after sLog
      put "Load whichever is missing and rerun." & return after sLog
      return sLog
   end try
   -- Both script layers are reachable; now the ABI gate proper: if the check
   -- cannot pass (stale or missing native binary), every later section would
   -- fail for the same reason, so report the one cause and stop (the OnionXT
   -- skip discipline).
   if tAbi is not true then
      put "  FAIL cxCheckABI:" && tAbi & return after sLog
      put return & "SKIPPED: the CoinXT extension (org.openxtalk.library.coinxt) or its" & return after sLog
      put "native library is not loaded; install the packaged extension and rerun." & return after sLog
      return sLog
   end if
   put "  ok   cxCheckABI (extension + native library + ABI match)" & return after sLog
   add 1 to sPass

   testErrorContract
   testHashes
   testHmac
   testPbkdf2
   testKeys
   testSign
   testRecover
   testEcdh
   testEncodings
   testAddresses
   testWif
   testBech32Decode
   testEthPersonal
   testMnemonics
   testHd
   testSchnorr
   testTaproot
   testRestore

   put return & "----" & return after sLog
   put "PASSED:" && sPass & "   FAILED:" && sFail after sLog
   return sLog
end cxSelfTest

-- record one assertion
on cxtCheck pCondition, pLabel
   if pCondition then
      add 1 to sPass
      put "  ok   " & pLabel & return after sLog
   else
      add 1 to sFail
      put "  FAIL " & pLabel & return after sLog
   end if
end cxtCheck

private command cxtSection pTitle
   put pTitle & ":" & return after sLog
end cxtSection

-- hex of a Data value (binaryDecode FILLS the out var and returns a count)
private function cxtHex pData
   local tHex
   get binaryDecode("H*", pData, tHex)
   return tHex
end cxtHex

-- Data from a hex string
private function cxtBin pHex
   return binaryEncode("H*", pHex)
end cxtBin

private function cxtAscii pText
   return textEncode(pText, "ascii")
end cxtAscii

on testErrorContract
   local tBad
   cxtSection "error contract"
   -- a malformed call returns a "CoinXT: ..." STRING, and cxIsError spots it
   put cxSign(cxtAscii("short"), cxtBin(kHashSatoshi)) into tBad
   cxtCheck cxIsError(tBad), "cxSign with a short seckey returns a CoinXT: error"
   cxtCheck (cxIsError(cxSha256(cxtAscii("x"))) is false), "a good result is not an error"
end testErrorContract

on testHashes
   cxtSection "hashes"
   -- the Ethereum-vs-NIST footgun, pinned from both sides
   cxtCheck (cxtHex(cxKeccak256(empty)) is \
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), \
      "keccak256(empty) matches the published Ethereum vector"
   cxtCheck (cxtHex(cxKeccak256(cxtAscii("abc"))) is \
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"), \
      "keccak256(abc) matches the published vector"
   cxtCheck (cxtHex(cxSha3_256(cxtAscii("abc"))) is \
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), \
      "sha3_256(abc) matches FIPS-202"
   cxtCheck (cxKeccak256(cxtAscii("abc")) is not cxSha3_256(cxtAscii("abc"))), \
      "keccak256 and sha3_256 are distinct (no aliasing)"
   cxtCheck (cxtHex(cxSha256(cxtAscii("abc"))) is \
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), \
      "sha256(abc) matches FIPS-180"
   cxtCheck (cxtHex(cxSha512(cxtAscii("abc"))) is \
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"), \
      "sha512(abc) matches FIPS-180"
   cxtCheck (cxtHex(cxRipemd160(cxtAscii("abc"))) is \
      "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"), \
      "ripemd160(abc) matches the published vector"
   cxtCheck (cxtHex(cxHash160(cxtAscii("abc"))) is \
      "bb1be98c142444d7a56aa3981c3942a978e4dc33"), \
      "hash160 = ripemd160(sha256(x))"
   cxtCheck (cxtHex(cxHash256(cxtAscii("abc"))) is \
      "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"), \
      "hash256 = sha256(sha256(x))"
end testHashes

on testHmac
   cxtSection "hmac (RFC 4231 case 2)"
   cxtCheck (cxtHex(cxHmacSha256(cxtAscii("Jefe"), cxtAscii("what do ya want for nothing?"))) is \
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), \
      "hmac-sha256 matches RFC 4231"
   cxtCheck (cxtHex(cxHmacSha512(cxtAscii("Jefe"), cxtAscii("what do ya want for nothing?"))) is \
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"), \
      "hmac-sha512 matches RFC 4231"
end testHmac

on testPbkdf2
   local tOut
   cxtSection "pbkdf2-hmac-sha512"
   -- the BIP-39 shape: 2048 iterations, 64-byte key, "mnemonic"-prefixed salt
   put cxPbkdf2HmacSha512(cxtAscii("abandon abandon ability"), cxtAscii("mnemonicTREZOR"), 2048, 64) into tOut
   cxtCheck (cxtHex(tOut) is \
      "75e55693825bd86300f16b1f156e596bb5a7dbd26922dfe3f5c0f238cb4d10534e63e99feed1bb80016f3136168af98c5abd55166e9ee069c1d2b0ee596871e6"), \
      "pbkdf2 (BIP-39 shape) matches hashlib"
   cxtCheck cxIsError(cxPbkdf2HmacSha512(cxtAscii("p"), cxtAscii("s"), 0, 64)), \
      "0 iterations is rejected with a clean error"
end testPbkdf2

on testKeys
   local tPub
   cxtSection "keys (secp256k1)"
   cxtCheck (cxSeckeyValidate(cxtBin(kSk1)) is true), "seckey 1 is valid"
   cxtCheck (cxSeckeyValidate(cxtBin("0000000000000000000000000000000000000000000000000000000000000000")) is false), \
      "the zero seckey is rejected"
   cxtCheck (cxSeckeyValidate(cxtBin("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) is false), \
      "a scalar above the order is rejected"
   cxtCheck (cxSeckeyValidate(cxtAscii("too short")) is false), "a wrong-length seckey is rejected"
   cxtCheck (cxNewSeckey(cxtBin(kSk1)) is cxtBin(kSk1)), \
      "cxNewSeckey passes valid entropy through unchanged"
   cxtCheck (cxtHex(cxPublicKey(cxtBin(kSk1), true)) is kG33), \
      "pubkey(1) compressed is the generator G"
   cxtCheck (cxtHex(cxPublicKey(cxtBin(kSk1), false)) is kG65), \
      "pubkey(1) uncompressed is 04 || Gx || Gy"
   cxtCheck (cxtHex(cxPubkeyDecompress(cxtBin(kG33))) is kG65), \
      "decompress(G33) reproduces G65"
   put cxtBin(kG33) into tPub
   put numToByte(5) into byte 1 of tPub
   cxtCheck cxIsError(cxPubkeyDecompress(tPub)), \
      "a corrupt pubkey prefix fails closed with a clean error"
end testKeys

on testSign
   local tSig
   local tSig2
   local tBad
   local tByte
   cxtSection "deterministic ECDSA (RFC 6979)"
   put cxSign(cxtBin(kSk1), cxtBin(kHashSatoshi)) into tSig
   cxtCheck (cxtHex(tSig) is kSigSatoshi), \
      "sign(sk=1, sha256(Satoshi Nakamoto)) matches the classic public vector (low-s)"
   put cxSign(cxtBin(kSk1), cxtBin(kHashSatoshi)) into tSig2
   cxtCheck (tSig is tSig2), "signing is deterministic (identical second signature)"
   cxtCheck (cxVerify(cxtBin(kG33), cxtBin(kHashSatoshi), tSig) is true), \
      "the signature verifies under the compressed pubkey"
   cxtCheck (cxVerify(cxtBin(kG65), cxtBin(kHashSatoshi), tSig) is true), \
      "the signature verifies under the uncompressed pubkey"
   -- flip one bit; keep the bitXor on its own line (operators inside a larger
   -- compound expression can choke an OXT parser, the family gotcha)
   put tSig into tBad
   put byteToNum(byte 11 of tBad) into tByte
   put tByte bitXor 64 into tByte
   put numToByte(tByte) into byte 11 of tBad
   cxtCheck (cxVerify(cxtBin(kG33), cxtBin(kHashSatoshi), tBad) is false), \
      "a corrupt signature is rejected (false, not an error)"
   cxtCheck (cxVerify(cxtBin(kG33), cxHash256(cxtAscii("other digest")), tSig) is false), \
      "the signature does not verify for a different digest"
   cxtCheck (cxVerify(cxtAscii("junk"), cxtBin(kHashSatoshi), tSig) is false), \
      "a malformed pubkey fails closed as false"
end testSign

on testRecover
   local tSig65
   local tRecid
   local tRec
   local tWrong
   cxtSection "recoverable signatures + ecrecover"
   put cxSignRecoverable(cxtBin(kSk1), cxtBin(kHashSatoshi)) into tSig65
   cxtCheck (the number of bytes in tSig65 is 65), "recoverable signature is 65 bytes"
   put byteToNum(byte 65 of tSig65) into tRecid
   cxtCheck (tRecid >= 0 and tRecid <= 3), "recid is the RAW 0..3 form"
   cxtCheck (byte 1 to 64 of tSig65 is cxSign(cxtBin(kSk1), cxtBin(kHashSatoshi))), \
      "the r||s part equals the plain deterministic signature"
   put cxRecover(tSig65, cxtBin(kHashSatoshi)) into tRec
   cxtCheck (cxtHex(tRec) is kG65), "ecrecover returns the signing pubkey"
   put tSig65 into tWrong
   put tRecid bitXor 1 into tRecid
   put numToByte(tRecid) into byte 65 of tWrong
   put cxRecover(tWrong, cxtBin(kHashSatoshi)) into tRec
   if cxIsError(tRec) then
      cxtCheck true, "the wrong recid does not yield the signer"
   else
      cxtCheck (cxtHex(tRec) is not kG65), "the wrong recid does not yield the signer"
   end if
   put tSig65 into tWrong
   put numToByte(9) into byte 65 of tWrong
   cxtCheck cxIsError(cxRecover(tWrong, cxtBin(kHashSatoshi))), \
      "recid 9 fails closed with a clean error"
end testRecover

on testEcdh
   local tShared
   cxtSection "ecdh (raw SEC1 x-coordinate)"
   put cxEcdh(cxtBin(kSkA), cxtBin(kPubB33)) into tShared
   cxtCheck (cxtHex(tShared) is kEcdhX), "ecdh(a, B) matches the pinned x-coordinate"
   cxtCheck (cxEcdh(cxtBin(kSkB), cxPublicKey(cxtBin(kSkA), false)) is tShared), \
      "ecdh is symmetric across compressed / uncompressed forms"
   cxtCheck cxIsError(cxEcdh(cxtBin(kSkA), cxtAscii("not a pubkey"))), \
      "a malformed pubkey fails closed with a clean error"
end testEcdh

on testEncodings
   local tRoundHex
   local tDecoded
   cxtSection "encodings (hex, Base58Check)"
   -- hex round trip
   put cxHexEncode(cxtBin("deadbeef")) into tRoundHex
   cxtCheck (tRoundHex is "deadbeef"), "hex encode round trip"
   cxtCheck cxIsError(cxHexDecode("xyz")), "hex decode rejects non-hex (fail closed)"
   cxtCheck cxIsError(cxHexDecode("abc")), "hex decode rejects an odd length (fail closed)"
   -- Base58Check round trip: version 0x00 + a 20-byte payload, then decode back
   put cxBase58CheckDecode(kAddrP2PKH) into tDecoded
   cxtCheck (line 1 of tDecoded is "0"), "Base58Check decode recovers version 0x00"
   cxtCheck (cxHexEncode(line 2 to -1 of tDecoded) is "751e76e8199196d454941c45d1b3a323f1433bd6"), \
      "Base58Check decode recovers the hash160 payload"
   -- a corrupt checksum must be rejected (flip the last character)
   cxtCheck cxIsError(cxBase58CheckDecode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMx")), \
      "Base58Check rejects a corrupt checksum (fail closed)"
end testEncodings

on testAddresses
   cxtSection "addresses (BTC legacy / SegWit, ETH EIP-55)"
   -- all three derived from pubkey(1); pinned to public BIP-173 / EIP-55 vectors
   cxtCheck (cxBtcAddressP2PKH(cxtBin(kG33), true) is kAddrP2PKH), \
      "P2PKH(pubkey 1) is the canonical legacy address"
   cxtCheck (cxBtcAddressP2WPKH(cxtBin(kG33), true) is kAddrP2WPKH), \
      "P2WPKH(pubkey 1) is the BIP-173 SegWit example address"
   cxtCheck (cxBtcAddressP2SH_P2WPKH(cxtBin(kG33), true) is kAddrP2SH), \
      "P2SH-P2WPKH(pubkey 1) is the locked BIP-49-style address"
   cxtCheck cxIsError(cxBtcAddressP2SH_P2WPKH(cxtBin(kG65), true)), \
      "P2SH-P2WPKH rejects an uncompressed pubkey (fail closed)"
   cxtCheck (cxEthAddress(cxtBin(kG65)) is kAddrEth), \
      "ethAddress(pubkey 1) is the pk=1 EIP-55 address"
   -- the compressed pubkey feeds the same Ethereum address (decompressed inside)
   cxtCheck (cxEthAddress(cxtBin(kG33)) is kAddrEth), \
      "ethAddress accepts a compressed pubkey too"
   -- EIP-55 validation: the checksummed form is stable, a bad-length input fails
   cxtCheck (cxEthAddressChecksum(kAddrEth) is kAddrEth), \
      "EIP-55 re-checksum is idempotent on a valid address"
   cxtCheck (cxEthAddressChecksum(toLower(kAddrEth)) is kAddrEth), \
      "EIP-55 restores mixed case from an all-lowercase address"
   cxtCheck cxIsError(cxEthAddressChecksum("0x1234")), \
      "EIP-55 rejects a wrong-length address (fail closed)"
end testAddresses

on testWif
   local tDecoded
   local tKey
   cxtSection "WIF (wallet import format)"
   cxtCheck (cxWifEncode(cxtBin(kSk1), true, true) is kWif1C), \
      "WIF(sk=1, compressed, mainnet) is the published string"
   cxtCheck (cxWifEncode(cxtBin(kSk1), false, true) is kWif1U), \
      "WIF(sk=1, uncompressed, mainnet) is the published string"
   cxtCheck (cxWifEncode(cxtBin(kSk1), true, false) is kWif1TC), \
      "WIF(sk=1, compressed, testnet) matches the locked vector"
   put cxWifDecode(kWif1C) into tDecoded
   cxtCheck (line 1 of tDecoded is "mainnet" and line 2 of tDecoded is "true"), \
      "WIF decode reports mainnet + compressed"
   put line 3 to -1 of tDecoded into tKey
   cxtCheck (tKey is cxtBin(kSk1)), "WIF decode round-trips the key bytes"
   put empty into tKey
   put empty into tDecoded
   -- fail closed: a corrupt checksum, a non-WIF version byte, a bad seckey
   cxtCheck cxIsError(cxWifDecode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm")), \
      "a corrupt WIF checksum is rejected"
   cxtCheck cxIsError(cxWifDecode(kAddrP2PKH)), \
      "a valid Base58Check with a non-WIF version byte is rejected"
   cxtCheck cxIsError(cxWifEncode(cxtAscii("short"), true, true)), \
      "a bad seckey is rejected on encode"
end testWif

on testBech32Decode
   local tDec
   cxtSection "Bech32/Bech32m decode"
   put cxBech32Decode(kAddrP2WPKH) into tDec
   cxtCheck (line 1 of tDec is "bc" and line 2 of tDec is "0" and \
      cxHexEncode(line 3 to -1 of tDec) is "751e76e8199196d454941c45d1b3a323f1433bd6"), \
      "the BIP-173 example decodes to hrp bc, v0, the hash160 program"
   put cxBech32Decode(toUpper(kAddrP2WPKH)) into tDec
   cxtCheck (line 2 of tDec is "0"), "the all-uppercase form is accepted"
   put cxBech32Decode(kTapAddr) into tDec
   cxtCheck (line 2 of tDec is "1" and cxHexEncode(line 3 to -1 of tDec) is kTapOutput), \
      "the BIP-86 bc1p decodes to v1 + the published output key"
   -- fail closed (each is a BIP-173/350 invalid class)
   cxtCheck cxIsError(cxBech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")), \
      "a flipped character is rejected (bad checksum)"
   cxtCheck cxIsError(cxBech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3T4")), \
      "a mixed-case string is rejected"
   cxtCheck cxIsError(cxBech32Decode("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")), \
      "a v1 program with a bech32 (not bech32m) checksum is rejected"
end testBech32Decode

on testEthPersonal
   local tHash
   local tSig
   local tRec
   cxtSection "EIP-191 personal messages"
   put cxEthPersonalHash(cxtAscii("hello")) into tHash
   cxtCheck (cxtHex(tHash) is kPersonalHello), \
      "personalHash(hello) matches the locked digest"
   put cxSignRecoverable(cxtBin(kSk1), tHash) into tSig
   put cxRecover(tSig, tHash) into tRec
   cxtCheck (cxEthAddress(tRec) is kAddrEth), \
      "personal_sign -> ecrecover recovers the signer's ADDRESS"
end testEthPersonal

-- the demo's headline flow, end to end on-engine: the canonical mnemonic
-- restores to the published first addresses of every standard path (the
-- BIP-84/86 strings are the official BIP test vectors)
on testRestore
   local tSeed
   local tMaster
   local tNode
   local tKey
   cxtSection "wallet restore (canonical mnemonic -> published addresses)"
   put cxMnemonicToSeed(kMnem128, empty) into tSeed
   put cxHdFromSeed(tSeed) into tMaster
   put empty into tSeed
   if cxIsError(tMaster) then
      cxtCheck false, "master node derives from the canonical mnemonic"
      exit testRestore
   end if
   put cxHdDerivePath(tMaster, "m/44'/0'/0'/0/0") into tNode
   cxtCheck (cxBtcAddressP2PKH(cxHdPubkey(tNode), true) is kRestA44), \
      "m/44'/0'/0'/0/0 is the published legacy address"
   put cxHdDerivePath(tMaster, "m/49'/0'/0'/0/0") into tNode
   cxtCheck (cxBtcAddressP2SH_P2WPKH(cxHdPubkey(tNode), true) is kRestA49), \
      "m/49'/0'/0'/0/0 is the published nested-SegWit address"
   put cxHdDerivePath(tMaster, "m/84'/0'/0'/0/0") into tNode
   cxtCheck (cxBtcAddressP2WPKH(cxHdPubkey(tNode), true) is kRestA84), \
      "m/84'/0'/0'/0/0 is the OFFICIAL BIP-84 first address"
   put cxHdSeckey(tNode) into tKey
   cxtCheck (cxWifEncode(tKey, true, true) is kRestWif84), \
      "the first BIP-84 key exports to the locked WIF"
   put empty into tKey
   put cxHdDerivePath(tMaster, "m/86'/0'/0'/0/0") into tNode
   cxtCheck (cxBtcAddressP2TR(cxHdPubkey(tNode), true) is kRestA86), \
      "m/86'/0'/0'/0/0 is the OFFICIAL BIP-86 first address"
   put cxHdDerivePath(tMaster, "m/44'/60'/0'/0/0") into tNode
   cxtCheck (cxEthAddress(cxHdPubkey(tNode)) is kRestAEth), \
      "m/44'/60'/0'/0/0 is the published Ethereum first address"
   put cxHdDerivePath(tMaster, "m/84'/0'/0'") into tNode
   cxtCheck (cxXpub(tNode, true) is kRestXpub84), \
      "the BIP-84 account xpub matches the locked vector"
   put empty into tNode
   put empty into tMaster
end testRestore

on testMnemonics
   local tMnem
   local tSeed
   local tTampered
   cxtSection "BIP-39 mnemonics"
   -- entropy -> mnemonic (the classic all-zero 128-bit vector)
   put cxMnemonicFromEntropy(cxtBin(kEnt128)) into tMnem
   cxtCheck (tMnem is kMnem128), "128-bit zero entropy makes the canonical 12-word mnemonic"
   -- validate: the good mnemonic passes, a tampered checksum word fails closed
   cxtCheck (cxMnemonicValidate(kMnem128) is true), "the mnemonic validates (checksum ok)"
   put "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo" into tTampered
   cxtCheck (cxMnemonicValidate(tTampered) is false), "a wrong checksum word is rejected"
   cxtCheck (cxMnemonicValidate("notaword " & kMnem128) is false), "an unknown word / wrong length is rejected"
   -- mnemonic -> seed (PBKDF2-HMAC-SHA512, passphrase TREZOR)
   put cxMnemonicToSeed(kMnem128, "TREZOR") into tSeed
   cxtCheck (cxtHex(tSeed) is kSeed128), "mnemonic + TREZOR passphrase makes the pinned 64-byte seed"
   -- wrong-length entropy fails closed with a clean error
   cxtCheck cxIsError(cxMnemonicFromEntropy(cxtBin("00112233"))), \
      "entropy that is not 16-32 bytes is rejected"
end testMnemonics

on testHd
   local tNode
   local tChild
   local tPathNode
   cxtSection "BIP-32 HD wallets (xprv / xpub, path derivation)"
   put cxHdFromSeed(cxtBin(kBip32Seed)) into tNode
   cxtCheck (cxXprv(tNode, true) is kXprvM), "master xprv matches BIP-32 vector 1"
   cxtCheck (cxXpub(tNode, true) is kXpubM), "master xpub matches BIP-32 vector 1"
   -- one hardened step: m/0'
   put cxHdDerive(tNode, 0, true) into tChild
   cxtCheck (cxXprv(tChild, true) is kXprvM0H), "m/0' xprv matches BIP-32 vector 1"
   cxtCheck (cxXpub(tChild, true) is kXpubM0H), "m/0' xpub matches BIP-32 vector 1"
   -- the path parser reaches the same node (the apostrophe marks hardened)
   put cxHdDerivePath(tNode, "m/0'") into tPathNode
   cxtCheck (cxXprv(tPathNode, true) is kXprvM0H), "cxHdDerivePath('m/0'') reaches the same node"
   -- a malformed path element fails closed
   cxtCheck cxIsError(cxHdDerivePath(tNode, "m/notanumber")), "a non-numeric path element is rejected"
   -- nodes carry a private key: clear them
   put empty into tNode
   put empty into tChild
   put empty into tPathNode
end testHd

on testSchnorr
   local tXonly
   local tSig
   cxtSection "Schnorr / BIP-340"
   put cxXonlyFromSeckey(cxtBin(kSchnorrSk)) into tXonly
   cxtCheck (cxtHex(tXonly) is kSchnorrPk), "x-only pubkey matches BIP-340 vector 0"
   -- deterministic sign with the vector's aux_rand
   put cxSchnorrSign(cxtBin(kSchnorrSk), cxtBin(kSchnorrMsg), cxtBin(kSchnorrAux)) into tSig
   cxtCheck (cxtHex(tSig) is kSchnorrSig), "signature matches BIP-340 vector 0"
   -- verify accepts the good signature, rejects a wrong message
   cxtCheck (cxSchnorrVerify(tXonly, cxtBin(kSchnorrMsg), tSig) is true), "verify accepts the valid signature"
   cxtCheck (cxSchnorrVerify(tXonly, cxtBin(kSchnorrSk), tSig) is false), "verify rejects a wrong message (fail closed)"
   -- empty aux (a NULL pointer) behaves as the all-zero aux the vector uses
   put cxSchnorrSign(cxtBin(kSchnorrSk), cxtBin(kSchnorrMsg), "") into tSig
   cxtCheck (cxtHex(tSig) is kSchnorrSig), "empty aux behaves as the zero-aux default"
end testSchnorr

on testTaproot
   cxtSection "Taproot (BIP-341 tweak, BIP-86 address)"
   cxtCheck (cxBtcAddressP2TR(cxtBin(kTapInternal), true) is kTapAddr), \
      "P2TR(internal key) is the BIP-86 bc1p address"
   -- a full SEC1 pubkey also yields a well-formed witness-v1 address
   cxtCheck (char 1 to 4 of cxBtcAddressP2TR(cxtBin(kG33), true) is "bc1p"), \
      "P2TR accepts a compressed pubkey and yields a bc1p address"
   cxtCheck cxIsError(cxBtcAddressP2TR(cxtBin("00112233"), true)), \
      "P2TR rejects a wrong-length key (fail closed)"
end testTaproot
