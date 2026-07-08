-- coinxt-demo.livecodescript - the CoinXT showcase stack.
--
-- A self-building demo (no IDE design step, the family pattern): on open it
-- creates a tabbed UI and walks the phase-1/2 story: make a key, derive its
-- public key, sign a digest deterministically, verify it, watch tampering get
-- REJECTED, recover the signer Ethereum-style, agree on an ECDH secret, and
-- hash with both Keccak-256 and SHA3-256 (the footgun, shown side by side).
--
-- To use (requires the CoinXT extension installed so org.openxtalk.library
-- .coinxt is loaded, and src/coinxt.livecodescript in scope, e.g. `start
-- using`): open this as a script-only stack, OR paste it as a stack's script
-- and `send "preOpenStack" to <that stack>`.
--
-- KEYS IN THIS DEMO ARE PUBLIC TEST KEYS. The "demo key" is derived from the
-- famously compromised phrase "correct horse battery staple"; every key made
-- here is for show. NEVER fund a key a demo made. Real entropy comes from
-- SodiumXT sxRandomBytes (the optional button, capability-gated) or OS
-- entropy the app obtained itself; custody is always the app's (SPEC.md).
--
-- Conventions: bytes cross as Data (textEncode/textDecode at the boundary);
-- cx* functions return a value or a "CoinXT: ..." error string (test with
-- cxIsError); predicates return booleans and fail closed. Controls are named
-- "prefix:role" so one mouseUp router dispatches every click and showTab
-- toggles a panel by prefix (the sodium-demo pattern).
--
-- Verified statically (tools/check-livecodescript.py); run in OXT to confirm.

local sTab          -- active tab key: keys | sign | eth | ecdh | hash | about
local sSeckey       -- the demo seckey (PUBLIC test key material only)
local sPub33        -- its compressed pubkey
local sPub65        -- its uncompressed pubkey
local sSig          -- last plain signature (64 bytes)
local sSigMsg       -- the message that was signed
local sEthSig       -- last recoverable signature (65 bytes)

on preOpenStack
   buildUI
   showTab "keys"
end preOpenStack

-- ==========================================================================
-- Palette. Single RGB source of truth (single-line ifs are checker-safe).
-- ==========================================================================

private function clr pName
   if pName is "headerBg" then return "24,26,32"
   if pName is "headerText" then return "240,240,244"
   if pName is "headerSub" then return "160,163,175"
   if pName is "appBg" then return "240,241,245"
   if pName is "panelBg" then return "255,255,255"
   if pName is "accent" then return "247,147,26"
   if pName is "accentText" then return "24,26,32"
   if pName is "muted" then return "120,126,140"
   if pName is "ink" then return "32,35,44"
   if pName is "ok" then return "26,137,71"
   if pName is "bad" then return "201,52,62"
   if pName is "tabIdle" then return "214,218,228"
   if pName is "mono" then return "245,246,250"
   return "0,0,0"
end clr

-- ==========================================================================
-- Styled control factory (the family idioms: opaque fields so backgroundColor
-- shows, ONE font name because a comma reads as fontname,language, names carry
-- a "prefix:role" tag for routing and tab visibility).
-- ==========================================================================

private command makeRect pName, pRect, pColorName, pRound
   create graphic pName
   set the rectangle of graphic pName to pRect
   set the style of graphic pName to "rectangle"
   if pRound > 0 then
      set the style of graphic pName to "roundrect"
      set the roundRadius of graphic pName to pRound
   end if
   set the opaque of graphic pName to true
   set the lineSize of graphic pName to 0
   set the backgroundColor of graphic pName to clr(pColorName)
end makeRect

private command makeLabel pName, pRect, pText, pColorName, pSize, pStyle
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to false
   set the opaque of field pName to false
   set the margins of field pName to 4
   set the textFont of field pName to "Helvetica"
   set the textSize of field pName to pSize
   set the textStyle of field pName to pStyle
   set the foregroundColor of field pName to clr(pColorName)
   put pText into field pName
end makeLabel

private command makeInput pName, pRect, pText
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to false
   set the showBorder of field pName to true
   set the borderWidth of field pName to 1
   set the threeD of field pName to false
   set the opaque of field pName to true
   set the backgroundColor of field pName to clr("panelBg")
   set the textFont of field pName to "Helvetica"
   set the textSize of field pName to 13
   set the foregroundColor of field pName to clr("ink")
   put pText into field pName
end makeInput

private command makeMono pName, pRect
   create field pName
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to true
   set the borderWidth of field pName to 1
   set the threeD of field pName to false
   set the opaque of field pName to true
   set the backgroundColor of field pName to clr("mono")
   set the textFont of field pName to "Courier"
   set the textSize of field pName to 11
   set the foregroundColor of field pName to clr("ink")
   set the vScrollbar of field pName to true
end makeMono

private command makeButton pName, pRect, pLabel, pPrimary
   create button pName
   set the rectangle of button pName to pRect
   set the showName of button pName to true
   set the label of button pName to pLabel
   set the textFont of button pName to "Helvetica"
   set the textSize of button pName to 13
   set the textStyle of button pName to "bold"
   set the threeD of button pName to false
   set the borderWidth of button pName to 0
   set the opaque of button pName to true
   set the autoHilite of button pName to true
   if pPrimary then
      set the backgroundColor of button pName to clr("accent")
      set the foregroundColor of button pName to clr("accentText")
   else
      set the backgroundColor of button pName to clr("tabIdle")
      set the foregroundColor of button pName to clr("ink")
   end if
end makeButton

private command setStatus pName, pText, pState
   put pText into field pName
   if pState is "ok" then
      set the foregroundColor of field pName to clr("ok")
   else if pState is "bad" then
      set the foregroundColor of field pName to clr("bad")
   else
      set the foregroundColor of field pName to clr("muted")
   end if
end setStatus

-- hex of a Data value (binaryDecode FILLS the out var and returns a count)
private function hexOf pData
   local tHex
   get binaryDecode("H*", pData, tHex)
   return tHex
end hexOf

-- short hex preview, so keys and digests do not become a wall of text
private function shortHex pData, pMax
   local tHex
   put hexOf(pData) into tHex
   if the number of chars in tHex > pMax then
      return char 1 to pMax of tHex & "..."
   end if
   return tHex
end shortHex

-- ==========================================================================
-- UI construction.
-- ==========================================================================

on buildUI
   if there is a field "ui:title" then
      exit buildUI
   end if
   set the width of this stack to 820
   set the height of this stack to 648
   set the name of this stack to "CoinXT Demo"
   set the backgroundColor of this stack to clr("appBg")

   -- Header bar.
   makeRect "ui:header", "0,0,820,64", "headerBg", 0
   makeLabel "ui:title", "24,9,520,40", "CoinXT", "headerText", 23, "bold"
   makeLabel "ui:subtitle", "26,40,600,60", "Bitcoin and Ethereum crypto primitives for xTalk", "headerSub", 12, "plain"
   makeLabel "ui:ver", "560,16,800,40", "", "headerSub", 12, "plain"
   set the textAlign of field "ui:ver" to "right"
   if cxCheckABI() is true then
      put "native library loaded (ABI ok)" into field "ui:ver"
   else
      put "library NOT loaded" into field "ui:ver"
   end if

   -- Tab bar.
   makeButton "ui:tabKeys", "24,76,128,104", "Keys", false
   makeButton "ui:tabSign", "134,76,258,104", "Sign and Verify", false
   makeButton "ui:tabEth", "264,76,388,104", "Recover (ETH)", false
   makeButton "ui:tabEcdh", "394,76,508,104", "Shared Secret", false
   makeButton "ui:tabHash", "514,76,618,104", "Hashes", false
   makeButton "ui:tabAbout", "624,76,728,104", "About", false

   -- Content panel + footer.
   makeRect "ui:panel", "24,112,796,604", "panelBg", 10
   makeLabel "ui:footer", "24,612,796,644", "Backed by trezor-crypto through the CoinXT C shim. Signing is deterministic (RFC 6979, always low-s); every malformed input fails closed. Demo keys are PUBLIC: never fund them.", "muted", 11, "plain"

   buildKeysTab
   buildSignTab
   buildEthTab
   buildEcdhTab
   buildHashTab
   buildAboutTab
end buildUI

on buildKeysTab
   makeLabel "keys:h", "48,126,748,154", "A key is 32 bytes; CoinXT validates it and derives the public key", "ink", 16, "bold"
   makeLabel "keys:p", "48,154,748,196", "CoinXT never invents entropy. The demo key is derived from a famously PUBLIC phrase (correct horse battery staple), so it is safe to show and fatal to fund. The SodiumXT button draws real entropy if that library is loaded.", "muted", 12, "plain"
   makeButton "keys:demoKey", "48,204,220,232", "Use the demo key", true
   makeButton "keys:sodiumKey", "232,204,436,232", "Draw entropy from SodiumXT", false
   makeLabel "keys:outLabel", "48,244,748,264", "seckey / compressed pubkey / uncompressed pubkey:", "muted", 11, "plain"
   makeMono "keys:out", "48,266,748,430"
   makeLabel "keys:status", "48,440,748,470", "no key yet", "muted", 12, "plain"
   setStatus "keys:status", "no key yet - click a button above", ""
end buildKeysTab

on buildSignTab
   makeLabel "sign:h", "48,126,748,154", "Deterministic ECDSA over the digest YOU built", "ink", 16, "bold"
   makeLabel "sign:p", "48,154,748,196", "CoinXT signs exactly a 32-byte digest (here sha256 of your message) and nothing else; the same key and digest always give the SAME signature (RFC 6979), so there is no nonce to get wrong. Tampering is rejected, not partially accepted.", "muted", 12, "plain"
   makeInput "sign:msg", "48,204,748,232", "Pay Bob 1 coin, invoice 42"
   makeButton "sign:go", "48,242,160,270", "Sign", true
   makeButton "sign:verify", "172,242,284,270", "Verify", false
   makeButton "sign:tamper", "296,242,436,270", "Tamper and verify", false
   makeLabel "sign:outLabel", "48,282,748,302", "digest / signature (r||s, low-s):", "muted", 11, "plain"
   makeMono "sign:out", "48,304,748,430"
   makeLabel "sign:status", "48,440,748,470", "", "muted", 12, "plain"
   setStatus "sign:status", "make a key on the Keys tab, then sign", ""
end buildSignTab

on buildEthTab
   makeLabel "eth:h", "48,126,748,154", "Recoverable signatures: what Ethereum's ecrecover does", "ink", 16, "bold"
   makeLabel "eth:p", "48,154,748,196", "A recoverable signature carries a recovery id (raw 0..3 here; the 27 / EIP-155 offset is a transaction-format detail). From the signature plus the digest alone, anyone can recover the signer's public key - that is how Ethereum knows who sent a transaction.", "muted", 12, "plain"
   makeButton "eth:sign", "48,204,220,232", "Sign recoverably", true
   makeButton "eth:recover", "232,204,404,232", "Recover the signer", false
   makeLabel "eth:outLabel", "48,244,748,264", "signature (r||s||recid) / recovered pubkey:", "muted", 11, "plain"
   makeMono "eth:out", "48,266,748,430"
   makeLabel "eth:status", "48,440,748,470", "", "muted", 12, "plain"
   setStatus "eth:status", "make a key on the Keys tab first", ""
end buildEthTab

on buildEcdhTab
   makeLabel "ecdh:h", "48,126,748,154", "Two parties, one shared secret (ECDH)", "ink", 16, "bold"
   makeLabel "ecdh:p", "48,154,748,196", "Alice combines HER secret key with BOB's public key; Bob does the reverse. Both land on the same 32 bytes (the raw SEC1 x-coordinate) without the secret keys ever moving. A real protocol hashes this secret before using it as a key.", "muted", 12, "plain"
   makeButton "ecdh:go", "48,204,260,232", "Run the exchange (test keys)", true
   makeLabel "ecdh:outLabel", "48,244,748,264", "Alice's view / Bob's view:", "muted", 11, "plain"
   makeMono "ecdh:out", "48,266,748,430"
   makeLabel "ecdh:status", "48,440,748,470", "", "muted", 12, "plain"
   setStatus "ecdh:status", "", ""
end buildEcdhTab

on buildHashTab
   makeLabel "hash:h", "48,126,748,154", "The coin hashes, including the classic Ethereum footgun", "ink", 16, "bold"
   makeLabel "hash:p", "48,154,748,196", "Ethereum's Keccak-256 and NIST's SHA3-256 differ ONLY in one padding byte, and mixing them up is the classic wallet bug. CoinXT exposes them as two functions that can never be aliased; compare them below.", "muted", 12, "plain"
   makeInput "hash:msg", "48,204,748,232", "abc"
   makeButton "hash:go", "48,242,160,270", "Hash it", true
   makeMono "hash:out", "48,282,748,440"
   makeLabel "hash:status", "48,450,748,480", "", "muted", 12, "plain"
   setStatus "hash:status", "", ""
end buildHashTab

on buildAboutTab
   makeLabel "about:h", "48,126,748,154", "What CoinXT is (and is not)", "ink", 16, "bold"
   makeMono "about:out", "48,164,748,560"
   put aboutText() into field "about:out"
end buildAboutTab

private function aboutText
   local tOut
   put "CoinXT wraps trezor-crypto (the MIT-licensed C crypto core of the" & return into tOut
   put "Trezor hardware wallet) behind a small C shim and this xTalk API." & return after tOut
   put return after tOut
   put "It gives an xTalk app the primitives a wallet is built from:" & return after tOut
   put "  - secp256k1 keypairs, deterministic ECDSA (RFC 6979, low-s)" & return after tOut
   put "  - recoverable signatures + ecrecover (Ethereum's v)" & return after tOut
   put "  - ECDH, SHA-2, SHA-3, Keccak-256, RIPEMD-160, HMAC, PBKDF2" & return after tOut
   put "  - coming next: addresses/encodings, HD wallets, mnemonics" & return after tOut
   put return after tOut
   put "It is NOT a wallet, a node, or a broadcaster, and it holds no" & return after tOut
   put "custody: the app owns key storage, backup, and confirm-before-sign." & return after tOut
   put "CoinXT signs only the exact 32-byte digest it is handed." & return after tOut
   put return after tOut
   put "Honesty notes (SPEC.md section 8):" & return after tOut
   put "  - script variables are not locked memory; the trust boundary is" & return after tOut
   put "    the machine, not this library (not hardware-wallet isolation)" & return after tOut
   put "  - fresh entropy comes from the CALLER (SodiumXT sxRandomBytes)" & return after tOut
   put "  - every deterministic path is pinned by public test vectors;" & return after tOut
   put "    run the full harness: put cxSelfTest() (coinxt-tests stack)" & return after tOut
   return tOut
end aboutText

-- ==========================================================================
-- Tab switching. Controls are named "prefix:role"; a tab shows its prefix.
-- ==========================================================================

on showTab pKey
   local tIdx
   local tName
   local tPrefix
   local tOldDelim
   put pKey into sTab
   put the itemDelimiter into tOldDelim
   set the itemDelimiter to ":"
   repeat with tIdx = 1 to the number of controls
      put the short name of control tIdx into tName
      put item 1 of tName into tPrefix
      if tPrefix is "ui" then
         next repeat
      end if
      set the visible of control tIdx to (tPrefix is pKey)
   end repeat
   set the itemDelimiter to tOldDelim
   restyleTabs
end showTab

on restyleTabs
   styleTab "ui:tabKeys", (sTab is "keys")
   styleTab "ui:tabSign", (sTab is "sign")
   styleTab "ui:tabEth", (sTab is "eth")
   styleTab "ui:tabEcdh", (sTab is "ecdh")
   styleTab "ui:tabHash", (sTab is "hash")
   styleTab "ui:tabAbout", (sTab is "about")
end restyleTabs

on styleTab pName, pActive
   if pActive then
      set the backgroundColor of button pName to clr("accent")
      set the foregroundColor of button pName to clr("accentText")
   else
      set the backgroundColor of button pName to clr("tabIdle")
      set the foregroundColor of button pName to clr("ink")
   end if
end styleTab

-- ==========================================================================
-- One router for every click ("prefix:role"). Disabled controls never arrive.
-- ==========================================================================

on mouseUp
   local tName
   local tPrefix
   local tRole
   local tOldDelim
   put the short name of the target into tName
   put the itemDelimiter into tOldDelim
   set the itemDelimiter to ":"
   put item 1 of tName into tPrefix
   put item 2 of tName into tRole
   set the itemDelimiter to tOldDelim
   if tPrefix is "ui" then
      handleChrome tRole
   else if tPrefix is "keys" then
      handleKeys tRole
   else if tPrefix is "sign" then
      handleSign tRole
   else if tPrefix is "eth" then
      handleEth tRole
   else if tPrefix is "ecdh" then
      handleEcdh tRole
   else if tPrefix is "hash" then
      handleHash tRole
   end if
end mouseUp

on handleChrome pRole
   if pRole is "tabKeys" then
      showTab "keys"
   else if pRole is "tabSign" then
      showTab "sign"
   else if pRole is "tabEth" then
      showTab "eth"
   else if pRole is "tabEcdh" then
      showTab "ecdh"
   else if pRole is "tabHash" then
      showTab "hash"
   else if pRole is "tabAbout" then
      showTab "about"
   end if
end handleChrome

-- ==========================================================================
-- Keys tab.
-- ==========================================================================

on handleKeys pRole
   if pRole is "demoKey" then
      doDemoKey
   else if pRole is "sodiumKey" then
      doSodiumKey
   end if
end handleKeys

on doDemoKey
   -- the famously PUBLIC brainwallet phrase: perfect for a demo, fatal to fund
   adoptSeckey cxSha256(textEncode("correct horse battery staple", "utf-8")), \
         "demo key adopted; it is PUBLIC (correct horse battery staple) - never fund it"
end doDemoKey

on doSodiumKey
   local tEntropy
   -- compose the sibling library directly, wrapped in try/catch: if SodiumXT
   -- is not loaded the call raises a catchable error and we degrade VISIBLY
   try
      put sxRandomBytes(32) into tEntropy
   catch tErr
      setStatus "keys:status", "SodiumXT is not loaded (optional); use the demo key instead", "bad"
      exit doSodiumKey
   end try
   adoptSeckey tEntropy, "fresh key from SodiumXT entropy (still a DEMO key: this stack shows it on screen)"
end doSodiumKey

private command adoptSeckey pEntropy, pStatusText
   local tKey
   local tOut
   put cxNewSeckey(pEntropy) into tKey
   if cxIsError(tKey) then
      setStatus "keys:status", tKey, "bad"
      exit adoptSeckey
   end if
   put tKey into sSeckey
   put cxPublicKey(sSeckey, true) into sPub33
   put cxPublicKey(sSeckey, false) into sPub65
   if cxIsError(sPub33) or cxIsError(sPub65) then
      setStatus "keys:status", "pubkey derivation failed; is the extension loaded?", "bad"
      exit adoptSeckey
   end if
   put "seckey  " & hexOf(sSeckey) & return into tOut
   put "pub33   " & hexOf(sPub33) & return after tOut
   put "pub65   " & hexOf(sPub65) & return after tOut
   put tOut into field "keys:out"
   setStatus "keys:status", pStatusText, "ok"
end adoptSeckey

-- ==========================================================================
-- Sign and Verify tab.
-- ==========================================================================

on handleSign pRole
   if pRole is "go" then
      doSign
   else if pRole is "verify" then
      doVerify
   else if pRole is "tamper" then
      doTamper
   end if
end handleSign

private function needKey pStatusField
   if sSeckey is empty then
      setStatus pStatusField, "no key yet: make one on the Keys tab first", "bad"
      return false
   end if
   return true
end needKey

on doSign
   local tHash
   local tOut
   if needKey("sign:status") is false then
      exit doSign
   end if
   put field "sign:msg" into sSigMsg
   put cxSha256(textEncode(sSigMsg, "utf-8")) into tHash
   put cxSign(sSeckey, tHash) into sSig
   if cxIsError(sSig) then
      setStatus "sign:status", sSig, "bad"
      exit doSign
   end if
   put "digest  " & hexOf(tHash) & return into tOut
   put "sig     " & hexOf(sSig) & return after tOut
   put tOut into field "sign:out"
   setStatus "sign:status", "signed deterministically: sign again and the signature will be IDENTICAL", "ok"
end doSign

on doVerify
   local tHash
   if sSig is empty then
      setStatus "sign:status", "sign something first", "bad"
      exit doVerify
   end if
   put cxSha256(textEncode(sSigMsg, "utf-8")) into tHash
   if cxVerify(sPub33, tHash, sSig) is true then
      setStatus "sign:status", "signature verifies under the public key", "ok"
   else
      setStatus "sign:status", "signature did NOT verify (did the message change after signing?)", "bad"
   end if
end doVerify

on doTamper
   local tHash
   local tBad
   local tByte
   if sSig is empty then
      setStatus "sign:status", "sign something first", "bad"
      exit doTamper
   end if
   put cxSha256(textEncode(sSigMsg, "utf-8")) into tHash
   put sSig into tBad
   put byteToNum(byte 11 of tBad) into tByte
   put tByte bitXor 64 into tByte
   put numToByte(tByte) into byte 11 of tBad
   if cxVerify(sPub33, tHash, tBad) is false then
      setStatus "sign:status", "one flipped bit and verification REJECTS it: that is the fail-closed headline", "ok"
   else
      setStatus "sign:status", "tampered signature verified - this must never happen", "bad"
   end if
end doTamper

-- ==========================================================================
-- Recover (ETH) tab.
-- ==========================================================================

on handleEth pRole
   if pRole is "sign" then
      doEthSign
   else if pRole is "recover" then
      doRecover
   end if
end handleEth

on doEthSign
   local tHash
   local tOut
   if needKey("eth:status") is false then
      exit doEthSign
   end if
   put cxKeccak256(textEncode("Pay Bob 1 ETH, nonce 7", "utf-8")) into tHash
   put cxSignRecoverable(sSeckey, tHash) into sEthSig
   if cxIsError(sEthSig) then
      setStatus "eth:status", sEthSig, "bad"
      exit doEthSign
   end if
   put "digest  " & hexOf(tHash) & return into tOut
   put "r||s    " & hexOf(byte 1 to 64 of sEthSig) & return after tOut
   put "recid   " & byteToNum(byte 65 of sEthSig) && "(raw 0..3; Ethereum shows it as 27/28 or EIP-155)" & return after tOut
   put tOut into field "eth:out"
   setStatus "eth:status", "recoverable signature made (Keccak-256 digest, as Ethereum hashes)", "ok"
end doEthSign

on doRecover
   local tHash
   local tRec
   if sEthSig is empty then
      setStatus "eth:status", "sign recoverably first", "bad"
      exit doRecover
   end if
   put cxKeccak256(textEncode("Pay Bob 1 ETH, nonce 7", "utf-8")) into tHash
   put cxRecover(sEthSig, tHash) into tRec
   if cxIsError(tRec) then
      setStatus "eth:status", tRec, "bad"
      exit doRecover
   end if
   put field "eth:out" & "recovered " & hexOf(tRec) & return into field "eth:out"
   if tRec is sPub65 then
      setStatus "eth:status", "recovered pubkey MATCHES the signer: that is ecrecover", "ok"
   else
      setStatus "eth:status", "recovered pubkey does not match - this must never happen", "bad"
   end if
end doRecover

-- ==========================================================================
-- Shared Secret (ECDH) tab.
-- ==========================================================================

on handleEcdh pRole
   if pRole is "go" then
      doEcdh
   end if
end handleEcdh

on doEcdh
   local tAliceSk
   local tBobSk
   local tAliceView
   local tBobView
   local tOut
   -- two PUBLIC demo keys, derived from fixed phrases so the run reproduces
   put cxNewSeckey(cxSha256(textEncode("alice demo key (public)", "utf-8"))) into tAliceSk
   put cxNewSeckey(cxSha256(textEncode("bob demo key (public)", "utf-8"))) into tBobSk
   if cxIsError(tAliceSk) or cxIsError(tBobSk) then
      setStatus "ecdh:status", "demo key derivation failed; is the extension loaded?", "bad"
      exit doEcdh
   end if
   put cxEcdh(tAliceSk, cxPublicKey(tBobSk, true)) into tAliceView
   put cxEcdh(tBobSk, cxPublicKey(tAliceSk, false)) into tBobView
   if cxIsError(tAliceView) or cxIsError(tBobView) then
      setStatus "ecdh:status", "ecdh failed; is the extension loaded?", "bad"
      exit doEcdh
   end if
   put "alice   " & hexOf(tAliceView) & return into tOut
   put "bob     " & hexOf(tBobView) & return after tOut
   put tOut into field "ecdh:out"
   -- model the hygiene even with demo keys: clear key variables when done
   put empty into tAliceSk
   put empty into tBobSk
   if tAliceView is tBobView then
      setStatus "ecdh:status", "both parties computed the SAME secret; no secret key crossed the wire", "ok"
   else
      setStatus "ecdh:status", "the two views differ - this must never happen", "bad"
   end if
end doEcdh

-- ==========================================================================
-- Hashes tab.
-- ==========================================================================

on handleHash pRole
   if pRole is "go" then
      doHashAll
   end if
end handleHash

on doHashAll
   local tIn
   local tOut
   put textEncode(field "hash:msg", "utf-8") into tIn
   put "keccak256  " & hexOf(cxKeccak256(tIn)) & return into tOut
   put "sha3-256   " & hexOf(cxSha3_256(tIn)) & return after tOut
   put "           (same input, ONE padding byte apart: never alias these two)" & return after tOut
   put "sha256     " & hexOf(cxSha256(tIn)) & return after tOut
   put "ripemd160  " & hexOf(cxRipemd160(tIn)) & return after tOut
   put "hash160    " & hexOf(cxHash160(tIn)) && "(what a Bitcoin address hashes)" & return after tOut
   put "hash256    " & hexOf(cxHash256(tIn)) && "(txids, Base58Check checksums)" & return after tOut
   put tOut into field "hash:out"
   setStatus "hash:status", "note how keccak256 and sha3-256 differ completely", "ok"
end doHashAll
