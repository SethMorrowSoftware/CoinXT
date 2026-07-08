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
