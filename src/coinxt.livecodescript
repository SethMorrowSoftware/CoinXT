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
      put 719259665 into tConst
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
