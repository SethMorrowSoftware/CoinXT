/* coinxt.livecodescript - the CoinXT public API (cx*).

   CoinXT gives an xTalk app Bitcoin/Ethereum crypto primitives by wrapping
   trezor-crypto behind a small C shim and the LCB module (src/coinxt.lcb).
   This layer is the ONLY one apps call. Its contract (SPEC.md section 6):

   - functions RETURN a value; a value that can fail returns a
     "CoinXT: ..." STRING on failure, so callers test with cxIsError().
     Predicates (cxVerify, cxSeckeyValidate) return a boolean and fail
     CLOSED: any malformed input is false, never an error a caller could
     mistake for success.
   - bytes are Data (binary strings); text conversion is the caller's.
   - the app owns key custody. CoinXT holds a key only for the microseconds
     of one call, and this layer clears its own key variables the moment it
     is done (put empty into ...). HONEST LIMIT: OXT script variables are
     not locked memory, so a seed or seckey held in a script variable can be
     paged to disk; the trust boundary is the machine, not this library.
   - CoinXT signs only the exact 32-byte digest the app hands it. It does
     not build sighashes or transaction preimages here (that is a later
     phase, and even then the app confirms the decoded intent first).
   - fresh key material comes from the CALLER (SodiumXT sxRandomBytes, or
     OS entropy the app obtained itself); CoinXT has no ambient RNG.

   Load order: the app loads the coinxt LCB extension (which loads the
   native shim), then this script library. Call cxCheckABI() once at
   startup: it fails cleanly if the native binary is stale or missing.

   Status: designed and statically reasoned; NEEDS AN ON-ENGINE PASS
   (there is no headless OXT compiler; see CLAUDE.md).
*/

----------------------------------------------------------------------
-- setup / guards
----------------------------------------------------------------------

-- true when everything is loaded and version-matched; a string that says
-- what to fix otherwise. Call once at startup, before any other cx* call:
-- the LCB side refuses to run against a stale native binary, so a skewed
-- install fails HERE, loudly, instead of corrupting memory later.
function cxCheckABI
   try
      cxbCheckABI
   catch tErr
      return cxMakeError(tErr, "(cxCheckABI)")
   end try
   return true
end cxCheckABI

-- the one test every fallible cx* result should pass through
function cxIsError pValue
   return pValue begins with "CoinXT:"
end cxIsError

-- Normalize a caught error to the "CoinXT: ..." contract. CONFIRMED
-- ON-ENGINE (2026-07-08): an error thrown inside an LCB extension handler
-- reaches a livecodescript catch variable as the engine's STRUCTURED
-- execution-error list (comma-separated code,line,column,hint lines), with
-- our thrown "CoinXT: ..." text embedded as a hint field, NOT as the
-- verbatim thrown string (a script-level throw DOES arrive verbatim). So:
-- pass a verbatim message through, dig our message out of a structured
-- list, and wrap anything else so the caller still sees a CoinXT: error.
private function cxMakeError pErr, pWhere
   local tPos
   local tMsg
   if pErr begins with "CoinXT:" then
      return pErr && pWhere
   end if
   put offset("CoinXT:", pErr) into tPos
   if tPos > 0 then
      put char tPos to -1 of pErr into tMsg
      -- keep only OUR message line; the engine stacks more error lines below
      return line 1 of tMsg && pWhere
   end if
   return "CoinXT: unexpected engine error:" && line 1 of pErr && pWhere
end cxMakeError

----------------------------------------------------------------------
-- hashes (Data in, Data out)
----------------------------------------------------------------------

-- Keccak-256: Ethereum's hash (ORIGINAL 0x01 padding). NOT SHA3-256.
function cxKeccak256 pData
   local tOut
   try
      put cxbKeccak256(pData) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxKeccak256)")
   end try
   return tOut
end cxKeccak256

-- SHA3-256: NIST FIPS-202 (0x06 padding). NOT Ethereum's Keccak-256.
function cxSha3_256 pData
   local tOut
   try
      put cxbSha3_256(pData) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxSha3_256)")
   end try
   return tOut
end cxSha3_256

function cxSha256 pData
   local tOut
   try
      put cxbSha256(pData) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxSha256)")
   end try
   return tOut
end cxSha256

function cxSha512 pData
   local tOut
   try
      put cxbSha512(pData) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxSha512)")
   end try
   return tOut
end cxSha512

function cxRipemd160 pData
   local tOut
   try
      put cxbRipemd160(pData) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxRipemd160)")
   end try
   return tOut
end cxRipemd160

-- Bitcoin's hash160: RIPEMD160(SHA256(x)), the pubkey-to-address hash
function cxHash160 pData
   local tOut
   try
      put cxbRipemd160(cxbSha256(pData)) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHash160)")
   end try
   return tOut
end cxHash160

-- Bitcoin's hash256: SHA256(SHA256(x)), txids and Base58Check checksums
function cxHash256 pData
   local tOut
   try
      put cxbSha256(cxbSha256(pData)) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHash256)")
   end try
   return tOut
end cxHash256

function cxHmacSha256 pKey, pMsg
   local tOut
   try
      put cxbHmacSha256(pKey, pMsg) into tOut
   catch tErr
      put empty into pKey
      return cxMakeError(tErr, "(cxHmacSha256)")
   end try
   put empty into pKey
   return tOut
end cxHmacSha256

function cxHmacSha512 pKey, pMsg
   local tOut
   try
      put cxbHmacSha512(pKey, pMsg) into tOut
   catch tErr
      put empty into pKey
      return cxMakeError(tErr, "(cxHmacSha512)")
   end try
   put empty into pKey
   return tOut
end cxHmacSha512

-- PBKDF2-HMAC-SHA512; a BIP-39 seed is pIterations = 2048, pOutLen = 64.
-- The derived key is treated as secret all the way down (wiped in native
-- memory before the block is freed).
function cxPbkdf2HmacSha512 pPassword, pSalt, pIterations, pOutLen
   local tOut
   try
      put cxbPbkdf2HmacSha512(pPassword, pSalt, pIterations, pOutLen) into tOut
   catch tErr
      put empty into pPassword
      return cxMakeError(tErr, "(cxPbkdf2HmacSha512)")
   end try
   put empty into pPassword
   return tOut
end cxPbkdf2HmacSha512

----------------------------------------------------------------------
-- keys and signatures (secp256k1)
----------------------------------------------------------------------

-- Validate 32 caller-supplied entropy bytes as a secp256k1 seckey and
-- return them as the key. CoinXT does NOT generate entropy: bring it from
-- SodiumXT sxRandomBytes or OS entropy you trust. The chance that honest
-- entropy falls outside [1, n-1] is about 2^-128: if it ever happens, draw
-- fresh entropy and call again (never "fix up" the bytes).
function cxNewSeckey pEntropy
   local tOk
   try
      put cxbSeckeyVerify(pEntropy) into tOk
   catch tErr
      put empty into pEntropy
      return cxMakeError(tErr, "(cxNewSeckey)")
   end try
   if tOk then
      return pEntropy
   end if
   put empty into pEntropy
   return "CoinXT: entropy is not a valid seckey (needs 32 bytes in [1, n-1]); draw fresh entropy and retry (cxNewSeckey)"
end cxNewSeckey

-- true for a well-formed seckey (32 bytes, scalar in [1, n-1]); fail closed
function cxSeckeyValidate pSeckey
   local tOk
   try
      put cxbSeckeyVerify(pSeckey) into tOk
   catch tErr
      put empty into pSeckey
      return false
   end try
   put empty into pSeckey
   return tOk
end cxSeckeyValidate

-- 33-byte compressed (default, what Bitcoin wants) or 65-byte uncompressed
-- (pass false; what a raw Ethereum address derivation wants)
function cxPublicKey pSeckey, pCompressed
   local tOut
   if pCompressed is empty then
      put true into pCompressed
   end if
   try
      put cxbPubkeyFromSeckey(pSeckey, pCompressed) into tOut
   catch tErr
      put empty into pSeckey
      return cxMakeError(tErr, "(cxPublicKey)")
   end try
   put empty into pSeckey
   return tOut
end cxPublicKey

-- expand a 33-byte compressed pubkey to the 65-byte 04||x||y form (a
-- 65-byte input passes through validated); fails closed on a bad point
function cxPubkeyDecompress pPubkey
   local tOut
   try
      put cxbPubkeyDecompress(pPubkey) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxPubkeyDecompress)")
   end try
   return tOut
end cxPubkeyDecompress

-- Deterministic ECDSA (RFC 6979) over EXACTLY the 32-byte digest you built:
-- CoinXT never constructs the sighash for you. Returns 64 bytes r||s,
-- always canonical low-s (BIP-62, and what EIP-2 requires). Signing the
-- same digest with the same key always returns the identical signature.
function cxSign pSeckey, pHash32
   local tOut
   try
      put cxbEcdsaSign(pSeckey, pHash32) into tOut
   catch tErr
      put empty into pSeckey
      return cxMakeError(tErr, "(cxSign)")
   end try
   put empty into pSeckey
   return tOut
end cxSign

-- true only if pSig64 verifies for pHash32 under pPubkey (33 or 65 bytes);
-- every malformed input is false, never a string (fail closed)
function cxVerify pPubkey, pHash32, pSig64
   local tOk
   try
      put cxbEcdsaVerify(pPubkey, pHash32, pSig64) into tOk
   catch tErr
      return false
   end try
   return tOk
end cxVerify

-- Ethereum's shape: 65 bytes r||s||v where v is the RAW recovery id 0..3.
-- Adding 27 (personal_sign) or the EIP-155 chain offset is presentation,
-- done where the transaction is assembled, never here.
function cxSignRecoverable pSeckey, pHash32
   local tOut
   try
      put cxbEcdsaSignRecoverable(pSeckey, pHash32) into tOut
   catch tErr
      put empty into pSeckey
      return cxMakeError(tErr, "(cxSignRecoverable)")
   end try
   put empty into pSeckey
   return tOut
end cxSignRecoverable

-- ecrecover: the 65-byte signature (raw recid 0..3 in the last byte; strip
-- any 27 / EIP-155 offset first) plus the digest yields the signer's
-- 65-byte uncompressed pubkey, or a clean error if nothing recovers
function cxRecover pSig65, pHash32
   local tOut
   try
      put cxbEcdsaRecover(pSig65, pHash32) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxRecover)")
   end try
   return tOut
end cxRecover

-- Raw SEC1 ECDH: the 32-byte X coordinate of pSeckey * pPubkey, no KDF.
-- Hash the result (per your protocol) before using it as a symmetric key;
-- the raw coordinate is deliberately returned so it cross-checks against
-- any standard library.
function cxEcdh pSeckey, pPubkey
   local tOut
   try
      put cxbEcdh(pSeckey, pPubkey) into tOut
   catch tErr
      put empty into pSeckey
      return cxMakeError(tErr, "(cxEcdh)")
   end try
   put empty into pSeckey
   return tOut
end cxEcdh

----------------------------------------------------------------------
-- encodings and addresses (PURE SCRIPT, no shim; phase 3)
--
-- The OnionXT base32 discipline (CLAUDE.md): build/parse with byte ops
-- (byteToNum / numToByte / byte x of), keep every bit-buffer small and
-- MASKED each step so a long payload never builds an integer past 2^53,
-- route div/mod through their own lines (a compound div/mod can choke an
-- OXT parser), and never use `^`. Every checksum is verified on decode and
-- fails closed. These are pinned to public vectors (BIP-173, EIP-55) in
-- examples/coinxt-tests.livecodescript.
----------------------------------------------------------------------

-- lowercase hex of a Data value
function cxHexEncode pData
   local tHex
   get binaryDecode("H*", pData, tHex)
   return tHex
end cxHexEncode

-- Data from a hex string; fail closed on an odd length or a non-hex char
function cxHexDecode pHex
   if (the number of chars in pHex) mod 2 is not 0 then
      return "CoinXT: hex has an odd number of characters (cxHexDecode)"
   end if
   if pHex is not empty and matchText(pHex, "^[0-9a-fA-F]+$") is false then
      return "CoinXT: hex contains a non-hex character (cxHexDecode)"
   end if
   return binaryEncode("H*", pHex)
end cxHexDecode

-- 2^pN as an integer (a helper, so `^` never appears in a compound expression)
private function cxPow2 pN
   local tResult
   local tI
   put 1 into tResult
   repeat pN times
      put tResult * 2 into tResult
   end repeat
   return tResult
end cxPow2

-- ---- Base58 / Base58Check ----

-- raw Base58 of a Data value (Bitcoin alphabet). The standard byte-array long
-- division: no big integer is ever formed (the carry stays under 58*256+255).
private function cxB58Encode pData
   local tAlpha
   local tDigits
   local tZeros
   local tIdx
   local tCarry
   local tJ
   local tCount
   local tOut
   put "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" into tAlpha
   put the number of bytes in pData into tCount
   -- leading zero bytes map to leading "1"s
   put 0 into tZeros
   repeat with tIdx = 1 to tCount
      if byteToNum(byte tIdx of pData) is 0 then
         add 1 to tZeros
      else
         exit repeat
      end if
   end repeat
   -- tDigits holds base58 digit values, one per byte, least-significant first
   put empty into tDigits
   repeat with tIdx = 1 to tCount
      put byteToNum(byte tIdx of pData) into tCarry
      repeat with tJ = 1 to the number of bytes in tDigits
         put (byteToNum(byte tJ of tDigits) * 256) + tCarry into tCarry
         put numToByte(tCarry mod 58) into byte tJ of tDigits
         put tCarry div 58 into tCarry
      end repeat
      repeat while tCarry > 0
         put numToByte(tCarry mod 58) after tDigits
         put tCarry div 58 into tCarry
      end repeat
   end repeat
   put empty into tOut
   repeat tZeros times
      put "1" after tOut
   end repeat
   repeat with tIdx = (the number of bytes in tDigits) down to 1
      put char (byteToNum(byte tIdx of tDigits) + 1) of tAlpha after tOut
   end repeat
   return tOut
end cxB58Encode

-- raw Base58 decode to a Data value, or a CoinXT: error on a bad character
private function cxB58Decode pString
   local tAlpha
   local tBytes
   local tOnes
   local tIdx
   local tCarry
   local tJ
   local tPos
   local tOut
   -- MONEY-CRITICAL: the Base58 alphabet is case-DISTINCT (an uppercase and a
   -- lowercase letter are different digits), but `offset` and `is` default to
   -- caseSensitive FALSE, which would collide them (a lowercase "g" would match
   -- the uppercase "G" that comes first in the alphabet) and decode the wrong
   -- bytes. caseSensitive is local to this handler and reverts on exit.
   set the caseSensitive to true
   put "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" into tAlpha
   put 0 into tOnes
   repeat with tIdx = 1 to the number of chars in pString
      if char tIdx of pString is "1" then
         add 1 to tOnes
      else
         exit repeat
      end if
   end repeat
   put empty into tBytes
   repeat with tIdx = 1 to the number of chars in pString
      put offset(char tIdx of pString, tAlpha) into tPos
      if tPos is 0 then
         return "CoinXT: not a Base58 character (cxB58Decode)"
      end if
      put tPos - 1 into tCarry
      repeat with tJ = 1 to the number of bytes in tBytes
         put (byteToNum(byte tJ of tBytes) * 58) + tCarry into tCarry
         put numToByte(tCarry mod 256) into byte tJ of tBytes
         put tCarry div 256 into tCarry
      end repeat
      repeat while tCarry > 0
         put numToByte(tCarry mod 256) after tBytes
         put tCarry div 256 into tCarry
      end repeat
   end repeat
   put empty into tOut
   repeat tOnes times
      put numToByte(0) after tOut
   end repeat
   repeat with tIdx = (the number of bytes in tBytes) down to 1
      put byte tIdx of tBytes after tOut
   end repeat
   return tOut
end cxB58Decode

-- Base58Check encode: base58( version || payload || first4(sha256d) ).
-- pVersion is a byte value (0..255).
function cxBase58CheckEncode pVersion, pPayload
   local tBody
   local tCheck
   put numToByte(pVersion) & pPayload into tBody
   put cxHash256(tBody) into tCheck
   if cxIsError(tCheck) then
      return tCheck && "(cxBase58CheckEncode)"
   end if
   return cxB58Encode(tBody & (byte 1 to 4 of tCheck))
end cxBase58CheckEncode

-- Base58Check decode: returns version (a number) & LF & payload (Data) after
-- recomputing and comparing the 4-byte checksum. Fails closed on any mismatch.
function cxBase58CheckDecode pString
   local tRaw
   local tBody
   local tWant
   local tGot
   -- the checksum compare below must be byte-exact; caseSensitive defaults to
   -- FALSE, which would fold ASCII-case-equivalent checksum bytes together and
   -- could accept a bad checksum. Local to this handler, reverts on exit.
   set the caseSensitive to true
   put cxB58Decode(pString) into tRaw
   if cxIsError(tRaw) then
      return tRaw && "(cxBase58CheckDecode)"
   end if
   if the number of bytes in tRaw < 5 then
      return "CoinXT: Base58Check payload too short (cxBase58CheckDecode)"
   end if
   put byte 1 to (the number of bytes in tRaw - 4) of tRaw into tBody
   put byte (the number of bytes in tRaw - 3) to (the number of bytes in tRaw) of tRaw into tGot
   put cxHash256(tBody) into tWant
   if cxIsError(tWant) then
      return tWant && "(cxBase58CheckDecode)"
   end if
   if (byte 1 to 4 of tWant) is not tGot then
      return "CoinXT: bad Base58Check checksum (cxBase58CheckDecode)"
   end if
   return byteToNum(byte 1 of tBody) & return & (byte 2 to (the number of bytes in tBody) of tBody)
end cxBase58CheckDecode

-- ---- Bech32 / Bech32m ----

-- convert a Data value (8-bit bytes) to 5-bit groups (with padding), as a
-- Data of one 5-bit value per byte. The accumulator is MASKED to the low
-- pending bits each step, so it never grows past ~2^13.
private function cxBits8to5 pData
   local tAcc
   local tBits
   local tIdx
   local tOut
   put 0 into tAcc
   put 0 into tBits
   put empty into tOut
   repeat with tIdx = 1 to the number of bytes in pData
      put (tAcc * 256) + byteToNum(byte tIdx of pData) into tAcc
      add 8 to tBits
      repeat while tBits >= 5
         subtract 5 from tBits
         put numToByte((tAcc div cxPow2(tBits)) mod 32) after tOut
      end repeat
      put tAcc mod cxPow2(tBits) into tAcc
   end repeat
   if tBits > 0 then
      put numToByte((tAcc * cxPow2(5 - tBits)) mod 32) after tOut
   end if
   return tOut
end cxBits8to5

-- the Bech32 polymod over a Data of 5-bit values; returns the 30-bit checksum
private function cxBechPolymod pValues
   local tChk
   local tIdx
   local tValue
   local tTop
   put 1 into tChk
   repeat with tIdx = 1 to the number of bytes in pValues
      put byteToNum(byte tIdx of pValues) into tValue
      put tChk div 33554432 into tTop
      put (tChk mod 33554432) * 32 into tChk
      put tChk bitXor tValue into tChk
      if (tTop bitAnd 1) is 1 then
         put tChk bitXor 996825010 into tChk
      end if
      put tTop div 2 into tTop
      if (tTop bitAnd 1) is 1 then
         put tChk bitXor 642813549 into tChk
      end if
      put tTop div 2 into tTop
      if (tTop bitAnd 1) is 1 then
         put tChk bitXor 513874426 into tChk
      end if
      put tTop div 2 into tTop
      if (tTop bitAnd 1) is 1 then
         put tChk bitXor 1027748829 into tChk
      end if
      put tTop div 2 into tTop
      if (tTop bitAnd 1) is 1 then
         put tChk bitXor 705979059 into tChk
      end if
   end repeat
   return tChk
end cxBechPolymod

-- the HRP expansion (high bits, a 0 separator, low bits) as a Data of 5-bit values
private function cxBechHrpExpand pHrp
   local tOut
   local tIdx
   local tCode
   put empty into tOut
   repeat with tIdx = 1 to the number of chars in pHrp
      put charToNum(char tIdx of pHrp) into tCode
      put numToByte(tCode div 32) after tOut
   end repeat
   put numToByte(0) after tOut
   repeat with tIdx = 1 to the number of chars in pHrp
      put charToNum(char tIdx of pHrp) into tCode
      put numToByte(tCode mod 32) after tOut
   end repeat
   return tOut
end cxBechHrpExpand

-- Bech32 (witness v0) / Bech32m (v1+) encode of a witness program.
-- pWitVer is the witness version (0..16); pProgram is the raw program Data.
function cxBech32Encode pHrp, pWitVer, pProgram
   local tCharset
   local tValues
   local tPoly
   local tConst
   local tInput
   local tIdx
   local tOut
   put "qpzry9x8gf2tvdw0s3jn54khce6mua7l" into tCharset
   if pWitVer is 0 then
      put 1 into tConst
   else
      -- Bech32m constant 0x2bc830a3 (BIP-350), used for witness v1+ (Taproot).
      -- This path is now exercised by cxBtcAddressP2TR and locked to the
      -- BIP-86 bc1p vectors in tools/coin-kat.py.
      put 734539939 into tConst
   end if
   -- data = witver (one 5-bit value) then the 8->5 conversion of the program
   put numToByte(pWitVer) & cxBits8to5(pProgram) into tValues
   -- checksum = polymod( hrpExpand || data || six zeros ) XOR const, split to 6 groups
   put cxBechHrpExpand(pHrp) & tValues into tInput
   repeat 6 times
      put numToByte(0) after tInput
   end repeat
   put cxBechPolymod(tInput) bitXor tConst into tPoly
   put pHrp & "1" into tOut
   repeat with tIdx = 1 to the number of bytes in tValues
      put char (byteToNum(byte tIdx of tValues) + 1) of tCharset after tOut
   end repeat
   -- append the 6 checksum characters (most-significant group first)
   repeat with tIdx = 0 to 5
      put char (((tPoly div cxPow2(5 * (5 - tIdx))) mod 32) + 1) of tCharset after tOut
   end repeat
   return tOut
end cxBech32Encode

-- Bech32 (witness v0) / Bech32m (v1+) DECODE of a SegWit address: the exact
-- inverse of cxBech32Encode, failing closed on everything BIP-173/350 reject:
-- mixed case, a bad character, a bad checksum, the wrong checksum constant
-- for the witness version (a v0 address must be bech32, v1+ bech32m), bad
-- 5->8 padding, and a bad program length (2..40 bytes; v0 exactly 20 or 32).
-- Returns hrp & LF & witness version & LF & program (Data, LAST, so callers
-- take `line 3 to -1`), or a CoinXT: error. The algorithm was transcribed 1:1
-- to Python and locked to the BIP-173/350 valid AND invalid vectors in
-- tools/coin-kat.py; the on-engine harness re-runs the same vectors.
function cxBech32Decode pString
   local tCharset
   local tLower
   local tSep
   local tIdx
   local tHrp
   local tCode
   local tValues
   local tPos
   local tWitVer
   local tConst
   local tAcc
   local tBits
   local tProgram
   local tLen
   -- the charset lookup and the case checks below must be case-EXACT, but
   -- `is` and `offset` default to caseSensitive FALSE (the Base58 lesson,
   -- item 5.10). Local to this handler, reverts on exit.
   set the caseSensitive to true
   put "qpzry9x8gf2tvdw0s3jn54khce6mua7l" into tCharset
   if the number of chars in pString > 90 then
      return "CoinXT: Bech32 string longer than 90 characters (cxBech32Decode)"
   end if
   -- BIP-173: a mixed-case string is invalid (all-lower or all-upper only)
   if pString is not toLower(pString) and pString is not toUpper(pString) then
      return "CoinXT: mixed-case Bech32 string (cxBech32Decode)"
   end if
   put toLower(pString) into tLower
   -- the separator is the LAST "1" (the HRP itself may contain "1"s)
   put 0 into tSep
   repeat with tIdx = 1 to the number of chars in tLower
      if char tIdx of tLower is "1" then
         put tIdx into tSep
      end if
   end repeat
   if tSep < 2 then
      return "CoinXT: no Bech32 separator / empty prefix (cxBech32Decode)"
   end if
   -- the witness version plus 6 checksum chars is the minimum data part
   if (the number of chars in tLower) - tSep < 7 then
      return "CoinXT: Bech32 data part too short (cxBech32Decode)"
   end if
   put char 1 to (tSep - 1) of tLower into tHrp
   repeat with tIdx = 1 to the number of chars in tHrp
      put charToNum(char tIdx of tHrp) into tCode
      if tCode < 33 or tCode > 126 then
         return "CoinXT: bad character in Bech32 prefix (cxBech32Decode)"
      end if
   end repeat
   -- map every data char to its 5-bit value
   put empty into tValues
   repeat with tIdx = (tSep + 1) to the number of chars in tLower
      put offset(char tIdx of tLower, tCharset) into tPos
      if tPos is 0 then
         return "CoinXT: bad Bech32 data character (cxBech32Decode)"
      end if
      put numToByte(tPos - 1) after tValues
   end repeat
   -- BIP-350: the expected checksum constant DEPENDS on the witness version
   put byteToNum(byte 1 of tValues) into tWitVer
   if tWitVer > 16 then
      return "CoinXT: witness version above 16 (cxBech32Decode)"
   end if
   if tWitVer is 0 then
      put 1 into tConst
   else
      put 734539939 into tConst
   end if
   if cxBechPolymod(cxBechHrpExpand(tHrp) & tValues) is not tConst then
      return "CoinXT: bad Bech32 checksum (cxBech32Decode)"
   end if
   -- 5->8 bit repack of the program (drop the witver value and the final 6
   -- checksum values); the accumulator is MASKED each step so it never grows
   -- past 2^13 (the OnionXT base32 discipline)
   put 0 into tAcc
   put 0 into tBits
   put empty into tProgram
   repeat with tIdx = 2 to (the number of bytes in tValues - 6)
      put (tAcc * 32) + byteToNum(byte tIdx of tValues) into tAcc
      add 5 to tBits
      if tBits >= 8 then
         subtract 8 from tBits
         put numToByte((tAcc div cxPow2(tBits)) mod 256) after tProgram
         put tAcc mod cxPow2(tBits) into tAcc
      end if
   end repeat
   -- strict padding (BIP-173): under 5 leftover bits, and all of them zero
   if tBits >= 5 or tAcc is not 0 then
      return "CoinXT: bad Bech32 padding (cxBech32Decode)"
   end if
   put the number of bytes in tProgram into tLen
   if tLen < 2 or tLen > 40 then
      return "CoinXT: witness program must be 2..40 bytes (cxBech32Decode)"
   end if
   if tWitVer is 0 and tLen is not 20 and tLen is not 32 then
      return "CoinXT: a v0 witness program must be 20 or 32 bytes (cxBech32Decode)"
   end if
   return tHrp & return & tWitVer & return & tProgram
end cxBech32Decode

-- ---- Ethereum address (EIP-55) ----

-- uppercase a hex string's letters where the matching nibble of
-- keccak256(lowercase-address) is >= 8 (the EIP-55 mixed-case checksum)
private function cxEip55 pLowerHex
   local tKeccakHex
   local tOut
   local tIdx
   local tChar
   local tNibble
   put cxHexEncode(cxKeccak256(textEncode(pLowerHex, "ascii"))) into tKeccakHex
   put empty into tOut
   repeat with tIdx = 1 to the number of chars in pLowerHex
      put char tIdx of pLowerHex into tChar
      if tChar is in "0123456789" then
         put tChar after tOut
      else
         put (offset(char tIdx of tKeccakHex, "0123456789abcdef") - 1) into tNibble
         if tNibble >= 8 then
            put toUpper(tChar) after tOut
         else
            put tChar after tOut
         end if
      end if
   end repeat
   return tOut
end cxEip55

-- Ethereum address from a pubkey (33 or 65 bytes): "0x" + EIP-55 of the last
-- 20 bytes of keccak256(uncompressed pubkey without its 0x04 prefix).
function cxEthAddress pPubkey
   local tPub65
   local tHash
   put pPubkey into tPub65
   if the number of bytes in tPub65 is 33 then
      put cxPubkeyDecompress(tPub65) into tPub65
      if cxIsError(tPub65) then
         return tPub65 && "(cxEthAddress)"
      end if
   end if
   if the number of bytes in tPub65 is not 65 then
      return "CoinXT: pubkey must be 33 or 65 bytes (cxEthAddress)"
   end if
   put cxKeccak256(byte 2 to 65 of tPub65) into tHash
   if cxIsError(tHash) then
      return tHash && "(cxEthAddress)"
   end if
   return "0x" & cxEip55(cxHexEncode(byte 13 to 32 of tHash))
end cxEthAddress

-- Validate and re-checksum an "0x..." Ethereum address. Returns the EIP-55
-- form; on a malformed input returns a CoinXT: error (fail closed).
function cxEthAddressChecksum pAddress
   local tHex
   put pAddress into tHex
   if char 1 to 2 of tHex is "0x" or char 1 to 2 of tHex is "0X" then
      delete char 1 to 2 of tHex
   end if
   if the number of chars in tHex is not 40 then
      return "CoinXT: an Ethereum address is 20 bytes / 40 hex chars (cxEthAddressChecksum)"
   end if
   if matchText(tHex, "^[0-9a-fA-F]+$") is false then
      return "CoinXT: address contains a non-hex character (cxEthAddressChecksum)"
   end if
   return "0x" & cxEip55(toLower(tHex))
end cxEthAddressChecksum

-- EIP-191 "personal message" digest: keccak256 of 0x19 || "Ethereum Signed
-- Message:" || 0x0A || the message's DECIMAL byte length || the message.
-- This is the digest wallets' personal_sign / eth_sign flows hash (the
-- prefix makes a signed message unusable as a transaction). Sign it with
-- cxSignRecoverable; cxRecover + cxEthAddress then recover the signing
-- ADDRESS from the signature alone, the Ethereum sign-in flow. pMessage is
-- Data (textEncode at the boundary, as everywhere in this API).
function cxEthPersonalHash pMessage
   local tLen
   local tPreimage
   put the number of bytes in pMessage into tLen
   put numToByte(25) & textEncode("Ethereum Signed Message:", "ascii") \
      & numToByte(10) & textEncode(tLen, "ascii") & pMessage into tPreimage
   return cxKeccak256(tPreimage)
end cxEthPersonalHash

-- ---- Bitcoin addresses ----

-- legacy P2PKH: Base58Check( version || hash160(pubkey) ). pMainnet defaults true.
function cxBtcAddressP2PKH pPubkey, pMainnet
   local tH160
   local tVersion
   put cxHash160(pPubkey) into tH160
   if cxIsError(tH160) then
      return tH160 && "(cxBtcAddressP2PKH)"
   end if
   if pMainnet is false then
      put 111 into tVersion
   else
      put 0 into tVersion
   end if
   return cxBase58CheckEncode(tVersion, tH160)
end cxBtcAddressP2PKH

-- native SegWit P2WPKH: Bech32( hrp, 0, hash160(pubkey) ). pMainnet defaults true.
function cxBtcAddressP2WPKH pPubkey, pMainnet
   local tH160
   local tHrp
   put cxHash160(pPubkey) into tH160
   if cxIsError(tH160) then
      return tH160 && "(cxBtcAddressP2WPKH)"
   end if
   if pMainnet is false then
      put "tb" into tHrp
   else
      put "bc" into tHrp
   end if
   return cxBech32Encode(tHrp, 0, tH160)
end cxBtcAddressP2WPKH

-- nested SegWit P2SH-P2WPKH (BIP-49, the "3..." form every pre-SegWit wallet
-- can pay): Base58Check( 0x05 | 0xC4, hash160( 0x0014 || hash160(pubkey) ) ).
-- BIP-49 requires the COMPRESSED pubkey; a 65-byte key would make a
-- different script whose coins standard wallets cannot spend, so any other
-- length fails closed. pMainnet defaults true.
function cxBtcAddressP2SH_P2WPKH pPubkey, pMainnet
   local tH160
   local tRedeem
   local tScriptHash
   local tVersion
   if the number of bytes in pPubkey is not 33 then
      return "CoinXT: P2SH-P2WPKH needs the 33-byte compressed pubkey (cxBtcAddressP2SH_P2WPKH)"
   end if
   put cxHash160(pPubkey) into tH160
   if cxIsError(tH160) then
      return tH160 && "(cxBtcAddressP2SH_P2WPKH)"
   end if
   -- the redeem script is the P2WPKH witness program: OP_0 PUSH20 <hash160>
   put numToByte(0) & numToByte(20) & tH160 into tRedeem
   put cxHash160(tRedeem) into tScriptHash
   if cxIsError(tScriptHash) then
      return tScriptHash && "(cxBtcAddressP2SH_P2WPKH)"
   end if
   if pMainnet is false then
      put 196 into tVersion
   else
      put 5 into tVersion
   end if
   return cxBase58CheckEncode(tVersion, tScriptHash)
end cxBtcAddressP2SH_P2WPKH

-- ---- WIF (wallet import format) private-key serialization ----

-- WIF-encode a 32-byte secret key: Base58Check( 0x80 mainnet / 0xEF testnet,
-- seckey || 0x01 when the corresponding pubkey is compressed ). This is the
-- form every mainstream wallet imports and exports single keys in. THE
-- RESULT IS THE PRIVATE KEY: treat the string as a secret and clear your
-- copy when done. pCompressed and pMainnet default true.
function cxWifEncode pSeckey, pCompressed, pMainnet
   local tVersion
   local tPayload
   local tOut
   if cxSeckeyValidate(pSeckey) is false then
      return "CoinXT: not a valid 32-byte secret key (cxWifEncode)"
   end if
   if pMainnet is false then
      put 239 into tVersion
   else
      put 128 into tVersion
   end if
   put pSeckey into tPayload
   if pCompressed is not false then
      put numToByte(1) after tPayload
   end if
   put cxBase58CheckEncode(tVersion, tPayload) into tOut
   put empty into tPayload
   return tOut
end cxWifEncode

-- WIF-decode. Verifies the Base58Check checksum, the WIF version byte, the
-- payload shape (32 bytes, or 33 with the 0x01 compressed marker), and the
-- key range, failing closed on all of them. Returns network ("mainnet" or
-- "testnet") & LF & compressed (true/false) & LF & the 32-byte secret key
-- (LAST, so take `line 3 to -1`). The key is a SECRET: clear your copy the
-- moment you are done with it.
function cxWifDecode pWif
   local tDecoded
   local tVersion
   local tPayload
   local tNetwork
   local tCompressed
   local tKey
   local tOut
   put cxBase58CheckDecode(pWif) into tDecoded
   if cxIsError(tDecoded) then
      return tDecoded && "(cxWifDecode)"
   end if
   put line 1 of tDecoded into tVersion
   put line 2 to -1 of tDecoded into tPayload
   put empty into tDecoded
   if tVersion is 128 then
      put "mainnet" into tNetwork
   else if tVersion is 239 then
      put "testnet" into tNetwork
   else
      put empty into tPayload
      return "CoinXT: not a WIF version byte (cxWifDecode)"
   end if
   if the number of bytes in tPayload is 33 and byteToNum(byte 33 of tPayload) is 1 then
      put true into tCompressed
      put byte 1 to 32 of tPayload into tKey
   else if the number of bytes in tPayload is 32 then
      put false into tCompressed
      put tPayload into tKey
   else
      put empty into tPayload
      return "CoinXT: not a WIF payload (32 or 33 bytes) (cxWifDecode)"
   end if
   put empty into tPayload
   if cxSeckeyValidate(tKey) is false then
      put empty into tKey
      return "CoinXT: WIF decodes to an out-of-range key (cxWifDecode)"
   end if
   put tNetwork & return & tCompressed & return & tKey into tOut
   put empty into tKey
   return tOut
end cxWifDecode

-- ---- RLP (recursive length prefix; the Ethereum serialization) ----
--
-- COMPOSABLE encoders, so no nested list structure ever crosses an API:
-- encode each item with cxRlpBytes / cxRlpUIntBytes / cxRlpUIntDec,
-- concatenate the encoded items, then wrap the concatenation with
-- cxRlpList (nest by wrapping again). RLP integers are MINIMAL big-endian
-- (zero is the empty string); a single byte below 0x80 is its own
-- encoding. Pinned to the yellow-paper vectors AND the official EIP-155
-- example transaction in tools/coin-kat.py; the on-engine harness
-- (testRlp / testEthTx) re-runs both through this exact layer.

-- the shared length header: pBase is 128 (0x80) for a byte string,
-- 192 (0xC0) for a list; over 55 bytes the length itself is length-prefixed
private function cxRlpHeader pBase, pLen
   local tLenBytes
   local tN
   if pLen <= 55 then
      return numToByte(pBase + pLen)
   end if
   put empty into tLenBytes
   put pLen into tN
   repeat while tN > 0
      put numToByte(tN mod 256) before tLenBytes
      put tN div 256 into tN
   end repeat
   return numToByte(pBase + 55 + the number of bytes in tLenBytes) & tLenBytes
end cxRlpHeader

-- RLP of a byte string (Data). A single byte below 0x80 IS its encoding.
function cxRlpBytes pData
   if the number of bytes in pData is 1 and byteToNum(byte 1 of pData) < 128 then
      return pData
   end if
   return cxRlpHeader(128, the number of bytes in pData) & pData
end cxRlpBytes

-- RLP list wrap: pPayload is the CONCATENATION of already-encoded items
-- (pass empty for the empty list, 0xC0).
function cxRlpList pPayload
   return cxRlpHeader(192, the number of bytes in pPayload) & pPayload
end cxRlpList

-- RLP of an unsigned integer given as big-endian BYTES: leading zero bytes
-- are stripped (RLP integers are minimal; zero is the empty string). Use
-- for a quantity that is already binary, like a signature's r or s.
function cxRlpUIntBytes pData
   local tIdx
   local tStart
   put 0 into tStart
   repeat with tIdx = 1 to the number of bytes in pData
      if byteToNum(byte tIdx of pData) is not 0 then
         put tIdx into tStart
         exit repeat
      end if
   end repeat
   if tStart is 0 then
      return cxRlpBytes(empty)
   end if
   return cxRlpBytes(byte tStart to -1 of pData)
end cxRlpUIntBytes

-- RLP of an unsigned integer given as a DECIMAL string of ANY size (a wei
-- amount is far past 2^53, so no script integer is ever formed): the same
-- byte-array multiply-accumulate cxB58Encode uses, every intermediate
-- bounded. Fails closed on a non-digit; empty and "0" both encode as 0x80.
function cxRlpUIntDec pDecimal
   local tBuf
   local tIdx
   local tJ
   local tDigit
   local tCarry
   local tOut
   put empty into tBuf
   repeat with tIdx = 1 to the number of chars in pDecimal
      put charToNum(char tIdx of pDecimal) - 48 into tDigit
      if tDigit < 0 or tDigit > 9 then
         return "CoinXT: not a decimal digit (cxRlpUIntDec)"
      end if
      put tDigit into tCarry
      repeat with tJ = 1 to the number of bytes in tBuf
         put (byteToNum(byte tJ of tBuf) * 10) + tCarry into tCarry
         put numToByte(tCarry mod 256) into byte tJ of tBuf
         put tCarry div 256 into tCarry
      end repeat
      repeat while tCarry > 0
         put numToByte(tCarry mod 256) after tBuf
         put tCarry div 256 into tCarry
      end repeat
   end repeat
   -- tBuf is little-endian; emit big-endian
   put empty into tOut
   repeat with tIdx = (the number of bytes in tBuf) down to 1
      put byte tIdx of tBuf after tOut
   end repeat
   return cxRlpUIntBytes(tOut)
end cxRlpUIntDec

--
-- entropy <-> words + the checksum word are pure bytes over cxSha256; the
-- mnemonic -> seed step is PBKDF2-HMAC-SHA512 (cxPbkdf2HmacSha512), 2048
-- iterations, salt "mnemonic" + passphrase, 64-byte seed. The 2048-word
-- English wordlist is EMBEDDED below so the library is self-contained; it is
-- byte-identical to data/bip39-english.txt (the canonical BIP-39 list, sha256
-- 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda), and
-- tools/coin-kat.py parses this block and asserts it matches that file so the
-- two cannot drift. NFKD note: the English wordlist and ASCII passphrases are
-- already NFKD, so the seed is byte-exact; a non-ASCII passphrase would need
-- NFKD normalization the engine does not apply here (documented limit).
----------------------------------------------------------------------

-- the wordlist, cached return-delimited on first use for whole-word lookup
local sBip39List

private command cxBip39Ensure
   local tWords
   if sBip39List is not empty then
      exit cxBip39Ensure
   end if
   put "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid" into tWords
   put " acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance" after tWords
   put " advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album" after tWords
   put " alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among" after tWords
   put " amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique" after tWords
   put " anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor" after tWords
   put " army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume" after tWords
   put " asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado" after tWords
   put " avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball" after tWords
   put " bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become" after tWords
   put " beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle" after tWords
   put " bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood" after tWords
   put " blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring" after tWords
   put " borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief" after tWords
   put " bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb" after tWords
   put " bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable" after tWords
   put " cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable" after tWords
   put " capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog" after tWords
   put " catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk" after tWords
   put " champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child" after tWords
   put " chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify" after tWords
   put " claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud" after tWords
   put " clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine" after tWords
   put " come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper" after tWords
   put " copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle" after tWords
   put " craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop" after tWords
   put " cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious" after tWords
   put " current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn" after tWords
   put " day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay" after tWords
   put " deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk" after tWords
   put " despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital" after tWords
   put " dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide" after tWords
   put " divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft" after tWords
   put " dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb" after tWords
   put " dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo" after tWords
   put " ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator" after tWords
   put " elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy" after tWords
   put " energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode" after tWords
   put " equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil" after tWords
   put " evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit" after tWords
   put " exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint" after tWords
   put " faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault" after tWords
   put " favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field" after tWords
   put " figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness" after tWords
   put " fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly" after tWords
   put " foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil" after tWords
   put " foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel" after tWords
   put " fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment" after tWords
   put " gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle" after tWords
   put " ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue" after tWords
   put " goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass" after tWords
   put " gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun" after tWords
   put " gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard" after tWords
   put " head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip" after tWords
   put " hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital" after tWords
   put " host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband" after tWords
   put " hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose" after tWords
   put " improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial" after tWords
   put " inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest" after tWords
   put " invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel" after tWords
   put " job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup" after tWords
   put " key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know" after tWords
   put " lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law" after tWords
   put " lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend" after tWords
   put " length lens leopard lesson letter level liar liberty library license life lift light like limb limit" after tWords
   put " link lion liquid list little live lizard load loan lobster local lock logic lonely long loop" after tWords
   put " lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet" after tWords
   put " maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin" after tWords
   put " marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure" after tWords
   put " meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message" after tWords
   put " metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake" after tWords
   put " mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning" after tWords
   put " mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music" after tWords
   put " must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative" after tWords
   put " neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee" after tWords
   put " noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey" after tWords
   put " object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay" after tWords
   put " old olive olympic omit once one onion online only open opera opinion oppose option orange orbit" after tWords
   put " orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over" after tWords
   put " own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper" after tWords
   put " parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut" after tWords
   put " pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical" after tWords
   put " piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet" after tWords
   put " plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony" after tWords
   put " pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare" after tWords
   put " present pretty prevent price pride primary print priority prison private prize problem process produce profit program" after tWords
   put " project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil" after tWords
   put " puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz" after tWords
   put " quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid" after tWords
   put " rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle" after tWords
   put " reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove" after tWords
   put " render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire" after tWords
   put " retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid" after tWords
   put " ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room" after tWords
   put " rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness" after tWords
   put " safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say" after tWords
   put " scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea" after tWords
   put " search season seat second secret section security seed seek segment select sell seminar senior sense sentence" after tWords
   put " series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine" after tWords
   put " ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side" after tWords
   put " siege sight sign silent silk silly silver similar simple since sing siren sister situate six size" after tWords
   put " skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan" after tWords
   put " slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social" after tWords
   put " sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup" after tWords
   put " source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin" after tWords
   put " spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium" after tWords
   put " staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting" after tWords
   put " stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject" after tWords
   put " submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme" after tWords
   put " sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim" after tWords
   put " swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target" after tWords
   put " task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that" after tWords
   put " theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger" after tWords
   put " tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token" after tWords
   put " tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist" after tWords
   put " toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree" after tWords
   put " trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try" after tWords
   put " tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical" after tWords
   put " ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown" after tWords
   put " unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful" after tWords
   put " useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle" after tWords
   put " velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view" after tWords
   put " village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote" after tWords
   put " voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave" after tWords
   put " way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat" after tWords
   put " wheel when where whip whisper wide width wife wild will win window wine wing wink winner" after tWords
   put " winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth" after tWords
   put " wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo" after tWords
   replace space with return in tWords
   put tWords into sBip39List
end cxBip39Ensure

-- entropy (16, 20, 24, 28, or 32 bytes) -> a space-joined BIP-39 mnemonic.
-- The checksum is the top ENT/32 bits of sha256(entropy); the entropy+checksum
-- bit stream is split into 11-bit word indices (a MASKED accumulator, never
-- past 2^19).
function cxMnemonicFromEntropy pEntropy
   local tEntLen
   local tCsBits
   local tNumWords
   local tHash
   local tFull
   local tAcc
   local tBits
   local tByteIdx
   local tIdx
   local tOut
   put the number of bytes in pEntropy into tEntLen
   if tEntLen < 16 or tEntLen > 32 or (tEntLen mod 4) is not 0 then
      return "CoinXT: BIP-39 entropy must be 16, 20, 24, 28, or 32 bytes (cxMnemonicFromEntropy)"
   end if
   put (tEntLen * 8) div 32 into tCsBits
   put ((tEntLen * 8) + tCsBits) div 11 into tNumWords
   put cxSha256(pEntropy) into tHash
   if cxIsError(tHash) then
      return tHash && "(cxMnemonicFromEntropy)"
   end if
   put pEntropy & (byte 1 of tHash) into tFull
   cxBip39Ensure
   put 0 into tAcc
   put 0 into tBits
   put 1 into tByteIdx
   put empty into tOut
   repeat tNumWords times
      repeat while tBits < 11
         put (tAcc * 256) + byteToNum(byte tByteIdx of tFull) into tAcc
         add 1 to tByteIdx
         add 8 to tBits
      end repeat
      subtract 11 from tBits
      put tAcc div cxPow2(tBits) into tIdx
      put tIdx mod 2048 into tIdx
      put tAcc mod cxPow2(tBits) into tAcc
      if tOut is empty then
         put line (tIdx + 1) of sBip39List into tOut
      else
         put space & (line (tIdx + 1) of sBip39List) after tOut
      end if
   end repeat
   return tOut
end cxMnemonicFromEntropy

-- true only if pWords is a valid BIP-39 mnemonic (known words AND the checksum
-- verifies); every malformed input is false (fail closed)
function cxMnemonicValidate pWords
   local tNumWords
   local tSaved
   local tPos
   local tAcc
   local tBits
   local tBitBytes
   local tByteVal
   local tEntBytes
   local tEntropy
   local tChecksumVal
   local tCsBits
   local tHash
   local tWant
   local tIdx
   put the number of words in pWords into tNumWords
   if tNumWords is not 12 and tNumWords is not 15 and tNumWords is not 18 and tNumWords is not 21 and tNumWords is not 24 then
      return false
   end if
   cxBip39Ensure
   put the wholeMatches into tSaved
   set the wholeMatches to true
   put 0 into tAcc
   put 0 into tBits
   put empty into tBitBytes
   repeat with tIdx = 1 to tNumWords
      put lineOffset(word tIdx of pWords, sBip39List) into tPos
      if tPos is 0 then
         set the wholeMatches to tSaved
         return false
      end if
      put (tAcc * 2048) + (tPos - 1) into tAcc
      add 11 to tBits
      repeat while tBits >= 8
         subtract 8 from tBits
         put tAcc div cxPow2(tBits) into tByteVal
         put tByteVal mod 256 into tByteVal
         put numToByte(tByteVal) after tBitBytes
         put tAcc mod cxPow2(tBits) into tAcc
      end repeat
   end repeat
   set the wholeMatches to tSaved
   put (tNumWords * 4) div 3 into tEntBytes
   put byte 1 to tEntBytes of tBitBytes into tEntropy
   if tBits > 0 then
      put tAcc into tChecksumVal
      put tBits into tCsBits
   else
      put byteToNum(byte (tEntBytes + 1) of tBitBytes) into tChecksumVal
      put 8 into tCsBits
   end if
   put cxSha256(tEntropy) into tHash
   if cxIsError(tHash) then
      return false
   end if
   put byteToNum(byte 1 of tHash) div cxPow2(8 - tCsBits) into tWant
   if tChecksumVal is tWant then
      return true
   end if
   return false
end cxMnemonicValidate

-- mnemonic + optional passphrase -> the 64-byte BIP-39 seed (the BIP-32 master
-- seed). PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic" + passphrase.
function cxMnemonicToSeed pWords, pPassphrase
   return cxPbkdf2HmacSha512(textEncode(pWords, "utf-8"), textEncode("mnemonic" & pPassphrase, "utf-8"), 2048, 64)
end cxMnemonicToSeed

----------------------------------------------------------------------
-- HD wallets (BIP-32; phase 4b)
--
-- The node is the 73-byte opaque blob the shim returns
-- (depth||parent_fingerprint||child||chaincode||privkey). It CARRIES A
-- PRIVATE KEY, so this layer clears its node variables the moment it is done,
-- exactly as it does for a seckey. xprv/xpub are framed HERE in script (the
-- version bytes + Base58Check over the blob fields), so no extra native call
-- is needed for serialization.
----------------------------------------------------------------------

-- master node from a BIP-39/other seed (I = HMAC-SHA512("Bitcoin seed", seed))
function cxHdFromSeed pSeed
   local tOut
   try
      put cxbHdFromSeed(pSeed) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHdFromSeed)")
   end try
   return tOut
end cxHdFromSeed

-- one derivation step (index 0..2^31-1; pHardened sets the high bit)
function cxHdDerive pNode, pIndex, pHardened
   local tOut
   try
      put cxbHdDerive(pNode, pIndex, pHardened) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHdDerive)")
   end try
   return tOut
end cxHdDerive

-- derive a whole path like "m/44'/0'/0'/0/0" (the apostrophe, or a trailing h
-- or H, marks a hardened level). Returns the final node, or a CoinXT: error on
-- a malformed path or a failed step. Intermediate parent nodes (each carrying
-- a private key) are cleared as we go.
function cxHdDerivePath pNode, pPath
   local tSavedDelim
   local tCount
   local tI
   local tPart
   local tHardened
   local tSteps
   local tNode
   local tNext
   local tStepLine
   -- PASS 1: parse + validate the path into steps ("index hardened" per line)
   put empty into tSteps
   put the itemDelimiter into tSavedDelim
   set the itemDelimiter to "/"
   put the number of items of pPath into tCount
   repeat with tI = 1 to tCount
      put item tI of pPath into tPart
      if tI is 1 and (tPart is "m" or tPart is "M") then
         next repeat
      end if
      if tPart is empty then
         next repeat
      end if
      put false into tHardened
      if last char of tPart is "'" or last char of tPart is "h" or last char of tPart is "H" then
         put true into tHardened
         delete last char of tPart
      end if
      if tPart is not an integer then
         set the itemDelimiter to tSavedDelim
         return "CoinXT: bad element in derivation path " & pPath & " (cxHdDerivePath)"
      end if
      if tPart < 0 or tPart > 2147483647 then
         set the itemDelimiter to tSavedDelim
         return "CoinXT: derivation index out of range (cxHdDerivePath)"
      end if
      put tPart & space & tHardened & return after tSteps
   end repeat
   set the itemDelimiter to tSavedDelim
   -- PASS 2: derive step by step, clearing each parent node
   put pNode into tNode
   repeat for each line tStepLine in tSteps
      put cxHdDerive(tNode, word 1 of tStepLine, (word 2 of tStepLine is "true")) into tNext
      put empty into tNode
      if cxIsError(tNext) then
         return tNext
      end if
      put tNext into tNode
   end repeat
   return tNode
end cxHdDerivePath

-- the node's fields (the private key is secret; clear your copy when done)
function cxHdSeckey pNode
   local tOut
   try
      put cxbHdPrivateKey(pNode) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHdSeckey)")
   end try
   return tOut
end cxHdSeckey

function cxHdPubkey pNode
   local tOut
   try
      put cxbHdPublicKey(pNode) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHdPubkey)")
   end try
   return tOut
end cxHdPubkey

function cxHdChainCode pNode
   local tOut
   try
      put cxbHdChainCode(pNode) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxHdChainCode)")
   end try
   return tOut
end cxHdChainCode

-- xprv (extended PRIVATE key), Base58Check. pMainnet defaults true. The result
-- carries the private key: treat it as secret. version||depth||fp||child||cc||
-- 0x00||priv, then Base58Check.
function cxXprv pNode, pMainnet
   local tVersion
   local tPriv
   local tBody
   local tCheck
   if pMainnet is false then
      put binaryEncode("H*", "04358394") into tVersion
   else
      put binaryEncode("H*", "0488ade4") into tVersion
   end if
   put cxHdSeckey(pNode) into tPriv
   if cxIsError(tPriv) then
      return tPriv && "(cxXprv)"
   end if
   put tVersion & (byte 1 to 41 of pNode) & numToByte(0) & tPriv into tBody
   put empty into tPriv
   put cxHash256(tBody) into tCheck
   if cxIsError(tCheck) then
      return tCheck && "(cxXprv)"
   end if
   return cxB58Encode(tBody & (byte 1 to 4 of tCheck))
end cxXprv

-- xpub (extended PUBLIC key), Base58Check. version||depth||fp||child||cc||
-- pubkey33, then Base58Check.
function cxXpub pNode, pMainnet
   local tVersion
   local tPub
   local tBody
   local tCheck
   if pMainnet is false then
      put binaryEncode("H*", "043587cf") into tVersion
   else
      put binaryEncode("H*", "0488b21e") into tVersion
   end if
   put cxHdPubkey(pNode) into tPub
   if cxIsError(tPub) then
      return tPub && "(cxXpub)"
   end if
   put tVersion & (byte 1 to 41 of pNode) & tPub into tBody
   put cxHash256(tBody) into tCheck
   if cxIsError(tCheck) then
      return tCheck && "(cxXpub)"
   end if
   return cxB58Encode(tBody & (byte 1 to 4 of tCheck))
end cxXpub

----------------------------------------------------------------------
-- Schnorr / BIP-340 + Taproot (phase 4b)
--
-- BIP-340 Schnorr signing/verification over a 32-byte message (as with
-- cxSign, the app hands CoinXT the exact digest; Taproot always signs a
-- 32-byte sighash). The x-only public key is 32 bytes. cxBtcAddressP2TR
-- performs the BIP-341 key-path tweak in the shim, then Bech32m-frames the
-- witness-v1 output key into a bc1p address. All native ops are transcribed
-- from the published BIP-340/341 schemes and pinned to the official vectors
-- (BIP-340 test vectors, BIP-86 addresses) in tools/coin-kat.py.
----------------------------------------------------------------------

-- the 32-byte BIP-340 x-only public key of a 32-byte secret key
function cxXonlyFromSeckey pSeckey
   local tOut
   try
      put cxbXonlyFromSeckey(pSeckey) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxXonlyFromSeckey)")
   end try
   return tOut
end cxXonlyFromSeckey

-- BIP-340 sign: 32-byte seckey, 32-byte message, OPTIONAL 32-byte aux_rand
-- (pass empty to omit; the shim then uses 32 zero bytes, the BIP-340 default).
-- Returns the 64-byte signature, or a CoinXT: error.
function cxSchnorrSign pSeckey, pMessage, pAuxRand
   local tOut
   try
      put cxbSchnorrSign(pSeckey, pMessage, pAuxRand) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxSchnorrSign)")
   end try
   return tOut
end cxSchnorrSign

-- BIP-340 verify: 32-byte x-only pubkey, 32-byte message, 64-byte signature.
-- Returns true only for a valid signature; every malformed input is false.
function cxSchnorrVerify pXonly, pMessage, pSig
   try
      return cxbSchnorrVerify(pXonly, pMessage, pSig)
   catch tErr
      return false
   end try
end cxSchnorrVerify

-- BIP-341 key-path Taproot output key: tweak a 32-byte x-only INTERNAL key to
-- the 32-byte witness-v1 OUTPUT key. Public helper for callers that want the
-- raw output key; cxBtcAddressP2TR wraps it into a bc1p address.
function cxTaprootOutputKey pXonlyInternal
   local tOut
   try
      put cxbTaprootTweak(pXonlyInternal) into tOut
   catch tErr
      return cxMakeError(tErr, "(cxTaprootOutputKey)")
   end try
   return tOut
end cxTaprootOutputKey

-- Taproot P2TR address (BIP-86 single-key). Takes a pubkey (33/65-byte SEC1,
-- or a 32-byte x-only internal key), tweaks it to the output key, and Bech32m-
-- frames it as a witness-v1 bc1p (mainnet, default) / tb1p (testnet) address.
function cxBtcAddressP2TR pPubkey, pMainnet
   local tXonly
   local tOutputKey
   local tHrp
   -- accept a full SEC1 pubkey (drop the prefix to the 32-byte x) or an
   -- already-x-only 32-byte key
   if the number of bytes in pPubkey is 33 or the number of bytes in pPubkey is 65 then
      put byte 2 to 33 of pPubkey into tXonly
   else if the number of bytes in pPubkey is 32 then
      put pPubkey into tXonly
   else
      return "CoinXT: P2TR needs a 33/65-byte pubkey or a 32-byte x-only key (cxBtcAddressP2TR)"
   end if
   put cxTaprootOutputKey(tXonly) into tOutputKey
   if cxIsError(tOutputKey) then
      return tOutputKey && "(cxBtcAddressP2TR)"
   end if
   if pMainnet is false then
      put "tb" into tHrp
   else
      put "bc" into tHrp
   end if
   return cxBech32Encode(tHrp, 1, tOutputKey)
end cxBtcAddressP2TR
