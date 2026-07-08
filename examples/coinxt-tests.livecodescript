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
constant kSk1 is "0000000000000000000000000000000000000000000000000000000000000001"
constant kSkA is "00000000000000000000000000000000000000000000000000000000000a11ce"
constant kSkB is "0000000000000000000000000000000000000000000000000000000000000b0b"
-- the generator G = pubkey(1), compressed and uncompressed (curve constants)
constant kG33 is "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
constant kG65 is "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
-- sha256("Satoshi Nakamoto") and the classic RFC 6979 signature of it by sk=1
constant kHashSatoshi is "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"
constant kSigSatoshi is "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
-- pubkey(0xB0B) compressed, and x(0xA11CE * 0xB0B * G), the raw SEC1 ECDH secret
constant kPubB33 is "035d45cb81aa765d69ca52e3869491ecf0e8fdf6a63d64e65b5213647ee4973ae5"
constant kEcdhX is "74f43c053591097e99e0886e03499baec02c6702a12db92347151afadf03cd8d"

function cxSelfTest
   local tAbi
   put "CoinXT self-test" & return into sLog
   put 0 into sPass
   put 0 into sFail

   -- Gate everything on the extension + native library being loadable: if the
   -- ABI check cannot pass, every later section would fail for the same
   -- reason, so report the one cause and stop (the OnionXT skip discipline).
   put cxCheckABI() into tAbi
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
