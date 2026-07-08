-- coinxt-demo.livecodescript - the CoinXT showcase stack.
--
-- A self-building, professionally laid-out demo (the family pattern: nocloud,
-- SodiumXT, TorrentXT) that makes one point clearly: xTalk now has real
-- Bitcoin and Ethereum cryptography, deterministic and fail-closed, through
-- one library. On open it builds a branded, tabbed UI with no IDE design step
-- (softly-shadowed cards, numbered step badges, platform-native monospace),
-- one panel per capability. Every panel tells the same story: your INPUT, a
-- plain sentence about WHAT the crypto does, the OUTPUT, and a colored STATUS
-- line - green for success, red when a check correctly REJECTS tampering, a
-- wrong key, or a malformed input. That rejection is the headline: unlike a
-- hand-rolled signer, these primitives fail closed.
--
-- Tabs: Keys (make + validate a secp256k1 key, derive its public key),
-- Sign & Verify (deterministic RFC 6979 ECDSA + tamper rejection), Ethereum
-- (recoverable signatures + ecrecover), Shared Secret (ECDH), Hashes (the
-- Keccak-256 vs SHA3-256 footgun, side by side, plus SHA-2, RIPEMD-160,
-- hash160/hash256), Key Derivation (HMAC + PBKDF2, the BIP-39 seed shape),
-- About (the pitch + a one-click self-test over every primitive).
--
-- KEYS IN THIS DEMO ARE PUBLIC TEST KEYS. The demo key derives from the
-- famously compromised phrase "correct horse battery staple", so it is safe
-- to show and fatal to fund. NEVER fund a key a demo made. Real entropy comes
-- from SodiumXT sxRandomBytes (the optional button, capability-gated) or OS
-- entropy the app obtained itself; custody is always the app's (SPEC.md).
--
-- To use (requires the CoinXT extension installed so org.openxtalk.library
-- .coinxt is loaded, and src/coinxt.livecodescript in scope, e.g. `start
-- using` it): open this as a script-only stack, OR paste it as a stack's
-- script and `send "preOpenStack" to <that stack>`.
--
-- Conventions (CLAUDE.md): bytes cross as Data (textEncode/textDecode at the
-- boundary); cx* functions return a value or a "CoinXT: ..." error string
-- (test with cxIsError); predicates return booleans and fail closed. Controls
-- are named "prefix:role" so one mouseUp router dispatches every click and
-- showTab toggles a panel by prefix. Verified statically
-- (tools/check-livecodescript.py); run in OXT to confirm.

-- ------------------------------------------------------------------ palette
-- Single RGB source of truth. Crypto-neutral dark slate chrome with a
-- Bitcoin-orange accent and an Ethereum-violet accent on the ETH tab.
constant kClrPage = "236,238,242"        -- window background
constant kClrCard = "255,255,255"        -- card fill (and input fill)
constant kClrCardLine = "224,228,235"    -- hairline card border / dividers
constant kClrBand = "23,27,38"           -- header band (dark slate)
constant kClrBandText = "244,246,250"    -- title on the band / badge digits
constant kClrBandSub = "150,157,175"     -- tagline on the band
constant kClrInk = "28,32,42"            -- primary text
constant kClrInkSoft = "92,100,116"      -- secondary text / status lines
constant kClrInkMute = "140,147,160"     -- captions, hints, empty states
constant kClrAccent = "242,150,42"       -- Bitcoin-orange accent (badges, primary buttons)
constant kClrAccentText = "28,32,42"     -- ink on the orange accent
constant kClrEth = "104,128,232"         -- Ethereum-violet accent (ETH tab)
constant kClrEthText = "255,255,255"
constant kClrOk = "26,137,71"            -- success status
constant kClrBad = "201,52,62"           -- rejection / failure status
constant kClrTabIdle = "220,224,232"     -- inactive tab fill
constant kClrCodeBg = "245,247,250"      -- mono output fill
constant kClrCodeLine = "213,219,229"    -- mono output border
constant kClrFieldLine = "203,210,222"   -- entry-field border
constant kClrPillOk = "205,240,214"      -- ABI pill: loaded
constant kClrPillOkText = "22,101,52"
constant kClrPillBad = "247,216,216"     -- ABI pill: not loaded
constant kClrPillBadText = "150,42,42"

-- ------------------------------------------------------------------ state
local sTab            -- active tab key: keys | sign | eth | ecdh | hash | kdf | about
local sSeckey         -- the demo seckey (PUBLIC test key material only)
local sPub33          -- its compressed pubkey
local sPub65          -- its uncompressed pubkey
local sSig            -- last plain signature (64 bytes)
local sSigMsg         -- the message that was signed
local sEthSig         -- last recoverable signature (65 bytes)
local sEthMsg         -- the message signed on the Ethereum tab
local sTPass          -- embedded self-test: passing checks
local sTFail          -- embedded self-test: failing checks
local sTLog           -- embedded self-test: running transcript

-- ------------------------------------------------------------------ lifecycle
on preOpenStack
   buildUI
   showTab "keys"
end preOpenStack

-- On a stack-script recompile (paste-into-script flow) openStack fires but
-- preOpenStack does not, so build here too; buildUI no-ops once built.
on openStack
   buildUI
   if sTab is empty then
      showTab "keys"
   end if
end openStack

-- ------------------------------------------------------------------ styled control factory
-- The family idioms: opaque fields so backgroundColor shows, ONE font name
-- (a comma reads as fontname,language), auto-fit a label to its MEASURED text
-- height (never guess metrics; that clipped text on the sibling projects),
-- names carry a "prefix:role" tag for routing and tab visibility.

-- platform-native monospace: the mono surfaces look native, not typewriter.
-- A missing face substitutes the engine default (a soft, safe failure).
private function cxdMonoFont
   if the platform is "MacOS" then
      return "Menlo"
   else if the platform is "Win32" then
      return "Consolas"
   end if
   return "DejaVu Sans Mono"
end cxdMonoFont

private command cxdRect pName, pRect, pColorName, pRound
   if there is no graphic pName then
      create graphic pName
   end if
   set the rectangle of graphic pName to pRect
   set the style of graphic pName to "rectangle"
   set the antialiased of graphic pName to true
   if pRound > 0 then
      set the style of graphic pName to "roundrect"
      set the roundRadius of graphic pName to pRound
   end if
   set the opaque of graphic pName to true
   set the filled of graphic pName to true
   set the lineSize of graphic pName to 0
   set the backgroundColor of graphic pName to pColorName
end cxdRect

-- A dashboard card: rounded, hairline-bordered, softly shadowed, placed
-- BEHIND its group of controls. Clicks fall through to the mouseUp router.
private command cxdPanel pName, pRect
   if there is no graphic pName then
      create graphic pName
   end if
   set the rectangle of graphic pName to pRect
   set the style of graphic pName to "roundrect"
   set the roundRadius of graphic pName to 12
   set the antialiased of graphic pName to true
   set the filled of graphic pName to true
   set the backgroundColor of graphic pName to kClrCard
   set the lineSize of graphic pName to 1
   set the foregroundColor of graphic pName to kClrCardLine
   set the borderColor of graphic pName to kClrCardLine
   cxdSoftShadow pName
end cxdPanel

-- A soft drop shadow. Graphic effects are an LC-9-era feature, so this is a
-- PURE enhancement: an engine without them just skips it (the try) and the
-- hairline border still separates the card from the page.
private command cxdSoftShadow pName
   local tShadow
   local tErr
   try
      put "60,66,82" into tShadow["color"]
      put 28 into tShadow["opacity"]
      put 12 into tShadow["size"]
      put 0 into tShadow["spread"]
      put 3 into tShadow["distance"]
      put 90 into tShadow["angle"]
      set the dropShadow of graphic pName to tShadow
   catch tErr
   end try
end cxdSoftShadow

-- create-or-reuse a label, then FIT it to its measured text height (top
-- pinned) so nothing clips and centering math has a true text height.
private command cxdLabel pName, pRect, pText, pColorName, pSize, pStyle
   local tSavedDelim
   local tRectTop
   local tMeasured
   if there is no field pName then
      create field pName
   end if
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the showBorder of field pName to false
   set the opaque of field pName to false
   set the margins of field pName to "4,2,4,2"
   set the textFont of field pName to "Helvetica"
   set the textSize of field pName to pSize
   set the textStyle of field pName to pStyle
   set the foregroundColor of field pName to pColorName
   put pText into field pName
   if pText is not empty then
      set the itemDelimiter to comma
      put item 2 of pRect into tRectTop
      put the formattedHeight of field pName into tMeasured
      if tMeasured > 0 then
         set the height of field pName to tMeasured
         set the top of field pName to tRectTop
      end if
   end if
end cxdLabel

private command cxdHdr pName, pRect, pText
   cxdLabel pName, pRect, pText, kClrInk, 15, "bold"
end cxdHdr

private command cxdCap pName, pRect, pText, pColorName
   cxdLabel pName, pRect, pText, pColorName, 12, "plain"
end cxdCap

private command cxdInput pName, pRect, pText
   if there is no field pName then
      create field pName
   end if
   set the rectangle of field pName to pRect
   set the lockText of field pName to false
   set the threeD of field pName to false
   set the borderWidth of field pName to 1
   set the borderColor of field pName to kClrFieldLine
   set the opaque of field pName to true
   set the backgroundColor of field pName to kClrCard
   set the margins of field pName to "6,6,6,6"
   set the textFont of field pName to "Helvetica"
   set the textSize of field pName to 13
   set the foregroundColor of field pName to kClrInk
   put pText into field pName
end cxdInput

private command cxdMono pName, pRect
   if there is no field pName then
      create field pName
   end if
   set the rectangle of field pName to pRect
   set the lockText of field pName to true
   set the threeD of field pName to false
   set the borderWidth of field pName to 1
   set the borderColor of field pName to kClrCodeLine
   set the opaque of field pName to true
   set the backgroundColor of field pName to kClrCodeBg
   set the margins of field pName to "8,6,8,6"
   set the textFont of field pName to cxdMonoFont()
   set the textSize of field pName to 11
   set the foregroundColor of field pName to kClrInk
   set the vScrollbar of field pName to true
   put empty into field pName
end cxdMono

private command cxdButton pName, pRect, pLabel, pKind
   if there is no button pName then
      create button pName
   end if
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
   if pKind is "primary" then
      set the backgroundColor of button pName to kClrAccent
      set the foregroundColor of button pName to kClrAccentText
   else if pKind is "eth" then
      set the backgroundColor of button pName to kClrEth
      set the foregroundColor of button pName to kClrEthText
   else
      set the backgroundColor of button pName to kClrTabIdle
      set the foregroundColor of button pName to kClrInk
   end if
end cxdButton

-- a small filled disc holding a step number, so a multi-step flow reads at a
-- glance: accent disc + centered ink digit, sized to its measured height.
private command cxdBadge pName, pRect, pDigit
   local tSavedDelim
   local tTopY
   local tBottomY
   if there is no graphic (pName & "Bg") then
      create graphic (pName & "Bg")
   end if
   set the itemDelimiter to comma
   put item 2 of pRect into tTopY
   put item 4 of pRect into tBottomY
   set the rectangle of graphic (pName & "Bg") to pRect
   set the style of graphic (pName & "Bg") to "roundrect"
   set the roundRadius of graphic (pName & "Bg") to (tBottomY - tTopY)
   set the antialiased of graphic (pName & "Bg") to true
   set the filled of graphic (pName & "Bg") to true
   set the backgroundColor of graphic (pName & "Bg") to kClrAccent
   set the lineSize of graphic (pName & "Bg") to 0
   cxdLabel pName, pRect, pDigit, kClrAccentText, 12, "bold"
   set the textAlign of field pName to "center"
   set the top of field pName to (tTopY + (((tBottomY - tTopY) - the height of field pName) div 2))
end cxdBadge

-- colored one-line status: ok (green), bad (red), or neutral (muted)
private command cxdStatus pName, pText, pState
   put pText into field pName
   if pState is "ok" then
      set the foregroundColor of field pName to kClrOk
   else if pState is "bad" then
      set the foregroundColor of field pName to kClrBad
   else
      set the foregroundColor of field pName to kClrInkSoft
   end if
end cxdStatus

-- flash a button's label to "Copied!" and copy text to the clipboard, so the
-- feedback lands AT the pointer. The original label rides a custom property.
private command cxdCopyFlash pBtn, pText
   set the clipboardData["text"] to pText
   if the uRealLabel of button pBtn is empty then
      set the uRealLabel of button pBtn to the label of button pBtn
   end if
   set the label of button pBtn to "Copied!"
   send ("cxdCopyReset" && quote & pBtn & quote) to me in 1100 milliseconds
end cxdCopyFlash

command cxdCopyReset pBtn
   if there is no button pBtn then
      exit cxdCopyReset
   end if
   if the uRealLabel of button pBtn is not empty then
      set the label of button pBtn to the uRealLabel of button pBtn
   end if
end cxdCopyReset

-- ------------------------------------------------------------------ small utilities
-- hex of a Data value (binaryDecode FILLS the out var and returns a count)
private function cxdHex pData
   local tHex
   get binaryDecode("H*", pData, tHex)
   return tHex
end cxdHex

-- Data from a hex string
private function cxdBin pHex
   return binaryEncode("H*", pHex)
end cxdBin

private function cxdAscii pText
   return textEncode(pText, "utf-8")
end cxdAscii

-- short hex preview so keys and digests do not become a wall of text
private function cxdShort pData, pMax
   local tHex
   put cxdHex(pData) into tHex
   if the number of chars in tHex > pMax then
      return char 1 to pMax of tHex & "..."
   end if
   return tHex
end cxdShort

-- ------------------------------------------------------------------ UI construction
on buildUI
   if there is a field "ui:title" then
      exit buildUI
   end if
   set the width of this stack to 900
   set the height of this stack to 700
   set the name of this stack to "CoinXT Demo"
   set the backgroundColor of this stack to kClrPage

   -- header band
   cxdRect "ui:band", "0,0,900,72", kClrBand, 0
   cxdLabel "ui:title", "28,13,520,52", "CoinXT", kClrBandText, 24, "bold"
   cxdLabel "ui:subtitle", "30,44,640,68", "Bitcoin and Ethereum cryptography for xTalk, from one library", kClrBandSub, 12, "plain"

   -- ABI status pill (top-right); set by refreshAbiPill
   cxdRect "ui:pill", "700,20,872,50", kClrPillBad, 15
   cxdLabel "ui:pillText", "700,20,872,50", "", kClrPillBadText, 11, "bold"
   set the textAlign of field "ui:pillText" to "center"
   refreshAbiPill

   -- tab bar
   cxdButton "ui:tabKeys", "24,84,141,114", "Keys", "idle"
   cxdButton "ui:tabSign", "146,84,263,114", "Sign & Verify", "idle"
   cxdButton "ui:tabEth", "268,84,385,114", "Ethereum", "idle"
   cxdButton "ui:tabEcdh", "390,84,507,114", "Shared Secret", "idle"
   cxdButton "ui:tabHash", "512,84,629,114", "Hashes", "idle"
   cxdButton "ui:tabKdf", "634,84,751,114", "Key Derivation", "idle"
   cxdButton "ui:tabAbout", "756,84,873,114", "About", "idle"

   -- content panel + footer
   cxdPanel "ui:panel", "24,124,876,652"
   cxdLabel "ui:footer", "24,662,876,694", "Backed by trezor-crypto through the CoinXT C shim. Signing is deterministic (RFC 6979, always low-s); every malformed input fails closed. Demo keys are PUBLIC - never fund them.", kClrInkMute, 11, "plain"

   buildKeysTab
   buildSignTab
   buildEthTab
   buildEcdhTab
   buildHashTab
   buildKdfTab
   buildAboutTab
end buildUI

command refreshAbiPill
   local tState
   put cxdProbe() into tState
   if tState is true then
      set the backgroundColor of graphic "ui:pill" to kClrPillOk
      cxdStatusPill "native library loaded", kClrPillOkText
   else
      set the backgroundColor of graphic "ui:pill" to kClrPillBad
      cxdStatusPill "library not loaded", kClrPillBadText
   end if
end refreshAbiPill

private command cxdStatusPill pText, pColor
   put pText into field "ui:pillText"
   set the foregroundColor of field "ui:pillText" to pColor
end cxdStatusPill

-- probe both layers: cxCheckABI lives in a separate script library, so a
-- bare call raises an engine error when that library is not in scope; the
-- try/catch turns that into a clean false (the on-engine lesson).
function cxdProbe
   local tErr
   try
      return cxCheckABI() is true
   catch tErr
      return false
   end try
end cxdProbe

-- ---- Keys tab
on buildKeysTab
   cxdHdr "keys:h", "48,138,852,166", "A key is 32 bytes; CoinXT validates it and derives the public key"
   cxdCap "keys:p", "48,168,852,214", "CoinXT never invents entropy. The demo key derives from a famously PUBLIC phrase (correct horse battery staple), so it is safe to show and fatal to fund. The SodiumXT button draws real entropy if that library is loaded.", kClrInkSoft
   cxdButton "keys:demo", "48,222,236,252", "Use the demo key", "primary"
   cxdButton "keys:sodium", "248,222,468,252", "Draw entropy (SodiumXT)", "idle"
   cxdButton "keys:copy", "480,222,600,252", "Copy pubkey", "idle"
   cxdCap "keys:outLabel", "48,266,852,286", "seckey (PUBLIC) / compressed pubkey (02|03) / uncompressed pubkey (04):", kClrInkMute
   cxdMono "keys:out", "48,288,852,452"
   cxdCap "keys:note", "48,462,852,502", "The compressed pubkey feeds a Bitcoin address; the uncompressed one (minus its 04 byte) feeds an Ethereum address. Those encoders arrive in the next phase.", kClrInkMute
   cxdLabel "keys:status", "48,566,852,600", "No key yet - click a button above.", kClrInkSoft, 12, "plain"
end buildKeysTab

-- ---- Sign & Verify tab
on buildSignTab
   cxdHdr "sign:h", "48,138,852,166", "Deterministic ECDSA over the digest YOU built"
   cxdCap "sign:p", "48,168,852,214", "CoinXT signs exactly a 32-byte digest (here SHA-256 of your message). The same key and digest always give the SAME signature (RFC 6979), so there is no nonce to leak. Then flip one bit and watch verification reject it.", kClrInkSoft
   cxdBadge "sign:b1", "48,224,74,250", "1"
   cxdButton "sign:go", "82,222,210,252", "Sign", "primary"
   cxdBadge "sign:b2", "224,224,250,250", "2"
   cxdButton "sign:verify", "258,222,386,252", "Verify", "idle"
   cxdBadge "sign:b3", "400,224,426,250", "3"
   cxdButton "sign:tamper", "434,222,606,252", "Flip a bit & verify", "idle"
   cxdCap "sign:msgLabel", "48,266,852,286", "Message to sign:", kClrInkMute
   cxdInput "sign:msg", "48,288,852,320", "Pay Bob 1 coin, invoice 42"
   cxdCap "sign:outLabel", "48,330,852,350", "digest (SHA-256) / signature (r||s, low-s):", kClrInkMute
   cxdMono "sign:out", "48,352,852,452"
   cxdLabel "sign:status", "48,566,852,600", "Make a key on the Keys tab, then Sign here.", kClrInkSoft, 12, "plain"
end buildSignTab

-- ---- Ethereum tab
on buildEthTab
   cxdHdr "eth:h", "48,138,852,166", "Recoverable signatures: what Ethereum's ecrecover does"
   cxdCap "eth:p", "48,168,852,222", "A recoverable signature carries a recovery id (raw 0..3 here; the 27 / EIP-155 offset is a transaction-format detail). From the signature and the digest ALONE, anyone can recover the signer's public key - that is how Ethereum knows who sent a transaction, without the key ever being sent.", kClrInkSoft
   cxdButton "eth:sign", "48,230,236,260", "Sign recoverably", "eth"
   cxdButton "eth:recover", "248,230,436,260", "Recover the signer", "idle"
   cxdCap "eth:outLabel", "48,274,852,294", "digest (Keccak-256) / signature r||s||recid / recovered pubkey:", kClrInkMute
   cxdMono "eth:out", "48,296,852,452"
   cxdLabel "eth:status", "48,566,852,600", "Make a key on the Keys tab first.", kClrInkSoft, 12, "plain"
end buildEthTab

-- ---- Shared Secret (ECDH) tab
on buildEcdhTab
   cxdHdr "ecdh:h", "48,138,852,166", "Two parties, one shared secret (ECDH)"
   cxdCap "ecdh:p", "48,168,852,222", "Alice combines HER secret key with BOB's public key; Bob does the reverse. Both land on the same 32 bytes (the raw SEC1 x-coordinate) without either secret key ever moving. A real protocol hashes this secret before using it as a symmetric key.", kClrInkSoft
   cxdButton "ecdh:go", "48,230,300,260", "Run the exchange (test keys)", "primary"
   cxdCap "ecdh:outLabel", "48,274,852,294", "Alice's view (sk_A, pub_B) / Bob's view (sk_B, pub_A):", kClrInkMute
   cxdMono "ecdh:out", "48,296,852,452"
   cxdLabel "ecdh:status", "48,566,852,600", "Click above to run a Diffie-Hellman exchange between two demo keys.", kClrInkSoft, 12, "plain"
end buildEcdhTab

-- ---- Hashes tab
on buildHashTab
   cxdHdr "hash:h", "48,138,852,166", "The coin hashes, including the classic Ethereum footgun"
   cxdCap "hash:p", "48,168,852,214", "Ethereum's Keccak-256 and NIST's SHA3-256 differ by ONE padding byte, and confusing them is the classic wallet bug. CoinXT exposes them as two functions that can never be aliased. Hash any text and compare.", kClrInkSoft
   cxdCap "hash:msgLabel", "48,224,852,244", "Text to hash:", kClrInkMute
   cxdInput "hash:msg", "48,246,700,278", "abc"
   cxdButton "hash:go", "712,246,852,278", "Hash it", "primary"
   cxdMono "hash:out", "48,290,852,452"
   cxdLabel "hash:status", "48,566,852,600", "Keccak-256 and SHA3-256 will look completely different - that is the point.", kClrInkSoft, 12, "plain"
end buildHashTab

-- ---- Key Derivation tab
on buildKdfTab
   cxdHdr "kdf:h", "48,138,852,166", "HMAC and PBKDF2: the building blocks of HD wallets"
   cxdCap "kdf:p", "48,168,852,214", "HMAC-SHA512 is the core of BIP-32 key derivation; PBKDF2-HMAC-SHA512 with 2048 iterations turns a BIP-39 mnemonic into a 64-byte seed. Both are pinned to public test vectors and shown here end to end.", kClrInkSoft
   cxdCap "kdf:msgLabel", "48,224,852,244", "Passphrase (used as the HMAC message and the PBKDF2 password):", kClrInkMute
   cxdInput "kdf:msg", "48,246,700,278", "abandon abandon ability"
   cxdButton "kdf:go", "712,246,852,278", "Derive", "primary"
   cxdMono "kdf:out", "48,290,852,452"
   cxdLabel "kdf:status", "48,566,852,600", "Enter a passphrase and click Derive.", kClrInkSoft, 12, "plain"
end buildKdfTab

-- ---- About tab (pitch + embedded self-test)
on buildAboutTab
   cxdHdr "about:h", "48,138,852,166", "CoinXT: Bitcoin and Ethereum primitives for xTalk"
   cxdCap "about:exp", "48,168,852,300", "CoinXT wraps trezor-crypto (the MIT-licensed C crypto core of the Trezor hardware wallet) behind a small C shim and a livecodescript API, so any xTalk app can make secp256k1 keys, sign deterministically (RFC 6979, low-s), verify, recover a signer the Ethereum way, agree on an ECDH secret, and hash with SHA-2, SHA-3, Keccak-256 and RIPEMD-160 - without shipping a wallet, a node, or a browser plugin. It adds no cryptography of its own; every curve op and hash is trezor-crypto's. The app owns key custody and confirm-before-sign; CoinXT signs only the exact digest it is handed.", kClrInkSoft
   cxdButton "about:selftest", "48,306,300,338", "Run the full self-test", "primary"
   cxdMono "about:out", "48,350,852,452"
   cxdLabel "about:status", "48,566,852,600", "Click Run the full self-test to check every primitive against a public vector.", kClrInkSoft, 12, "plain"
end buildAboutTab

-- ------------------------------------------------------------------ tab switching
on showTab pKey
   local tSavedDelim
   local tIdx
   local tName
   local tPrefix
   put pKey into sTab
   set the itemDelimiter to ":"
   repeat with tIdx = 1 to the number of controls
      put the short name of control tIdx into tName
      put item 1 of tName into tPrefix
      if tPrefix is "ui" then
         next repeat
      end if
      set the visible of control tIdx to (tPrefix is pKey)
   end repeat
   restyleTabs
end showTab

on restyleTabs
   styleTab "ui:tabKeys", (sTab is "keys")
   styleTab "ui:tabSign", (sTab is "sign")
   styleTab "ui:tabEth", (sTab is "eth")
   styleTab "ui:tabEcdh", (sTab is "ecdh")
   styleTab "ui:tabHash", (sTab is "hash")
   styleTab "ui:tabKdf", (sTab is "kdf")
   styleTab "ui:tabAbout", (sTab is "about")
end restyleTabs

on styleTab pName, pActive
   if pActive then
      set the backgroundColor of button pName to kClrBand
      set the foregroundColor of button pName to kClrBandText
   else
      set the backgroundColor of button pName to kClrTabIdle
      set the foregroundColor of button pName to kClrInk
   end if
end styleTab

-- ------------------------------------------------------------------ one mouseUp router
on mouseUp
   local tSavedDelim
   local tName
   local tPrefix
   local tRole
   put the short name of the target into tName
   set the itemDelimiter to ":"
   put item 1 of tName into tPrefix
   put item 2 of tName into tRole
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
   else if tPrefix is "kdf" then
      handleKdf tRole
   else if tPrefix is "about" then
      handleAbout tRole
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
   else if pRole is "tabKdf" then
      showTab "kdf"
   else if pRole is "tabAbout" then
      showTab "about"
   end if
end handleChrome

-- ------------------------------------------------------------------ Keys tab actions
on handleKeys pRole
   if pRole is "demo" then
      doDemoKey
   else if pRole is "sodium" then
      doSodiumKey
   else if pRole is "copy" then
      doCopyPubkey
   end if
end handleKeys

on doDemoKey
   adoptSeckey cxSha256(cxdAscii("correct horse battery staple")), \
      "Demo key adopted. It is PUBLIC (correct horse battery staple) - never fund it."
end doDemoKey

on doSodiumKey
   local tEntropy
   local tErr
   -- compose the sibling library directly, wrapped in try/catch: if SodiumXT
   -- is not loaded the call raises a catchable error and we degrade VISIBLY.
   try
      put sxRandomBytes(32) into tEntropy
   catch tErr
      cxdStatus "keys:status", "SodiumXT is not loaded (optional); use the demo key instead.", "bad"
      exit doSodiumKey
   end try
   adoptSeckey tEntropy, "Fresh key from SodiumXT entropy (still a DEMO key: this stack shows it on screen)."
end doSodiumKey

command adoptSeckey pEntropy, pStatusText
   local tKey
   local tOut
   put cxNewSeckey(pEntropy) into tKey
   if cxIsError(tKey) then
      cxdStatus "keys:status", tKey, "bad"
      exit adoptSeckey
   end if
   put tKey into sSeckey
   put cxPublicKey(sSeckey, true) into sPub33
   put cxPublicKey(sSeckey, false) into sPub65
   if cxIsError(sPub33) or cxIsError(sPub65) then
      cxdStatus "keys:status", "Public key derivation failed; is the extension loaded?", "bad"
      exit adoptSeckey
   end if
   put "seckey  " & cxdHex(sSeckey) & return into tOut
   put "pub33   " & cxdHex(sPub33) & return after tOut
   put "pub65   " & cxdHex(sPub65) after tOut
   put tOut into field "keys:out"
   cxdStatus "keys:status", pStatusText, "ok"
end adoptSeckey

on doCopyPubkey
   if sPub33 is empty then
      cxdStatus "keys:status", "Make a key first.", "bad"
      exit doCopyPubkey
   end if
   cxdCopyFlash "keys:copy", cxdHex(sPub33)
   cxdStatus "keys:status", "Compressed public key copied to the clipboard.", "ok"
end doCopyPubkey

-- ------------------------------------------------------------------ Sign tab actions
on handleSign pRole
   if pRole is "go" then
      doSign
   else if pRole is "verify" then
      doVerify
   else if pRole is "tamper" then
      doTamper
   end if
end handleSign

function haveKey pStatusField
   if sSeckey is empty then
      cxdStatus pStatusField, "No key yet: make one on the Keys tab first.", "bad"
      return false
   end if
   return true
end haveKey

on doSign
   local tHash
   local tOut
   if haveKey("sign:status") is false then
      exit doSign
   end if
   put field "sign:msg" into sSigMsg
   put cxSha256(cxdAscii(sSigMsg)) into tHash
   put cxSign(sSeckey, tHash) into sSig
   if cxIsError(sSig) then
      cxdStatus "sign:status", sSig, "bad"
      exit doSign
   end if
   put "digest  " & cxdHex(tHash) & return into tOut
   put "sig     " & cxdHex(sSig) after tOut
   put tOut into field "sign:out"
   cxdStatus "sign:status", "Signed. Sign again and the signature is IDENTICAL (RFC 6979 determinism).", "ok"
end doSign

on doVerify
   local tHash
   if sSig is empty then
      cxdStatus "sign:status", "Sign something first.", "bad"
      exit doVerify
   end if
   put cxSha256(cxdAscii(sSigMsg)) into tHash
   if cxVerify(sPub33, tHash, sSig) is true then
      cxdStatus "sign:status", "Signature verifies under the public key.", "ok"
   else
      cxdStatus "sign:status", "Signature did NOT verify (did the message change after signing?).", "bad"
   end if
end doVerify

on doTamper
   local tHash
   local tBad
   local tByte
   if sSig is empty then
      cxdStatus "sign:status", "Sign something first.", "bad"
      exit doTamper
   end if
   put cxSha256(cxdAscii(sSigMsg)) into tHash
   -- flip one bit of the signature; keep the bitXor on its own line (operators
   -- inside a larger compound expression can choke an OXT parser)
   put sSig into tBad
   put byteToNum(byte 11 of tBad) into tByte
   put tByte bitXor 64 into tByte
   put numToByte(tByte) into byte 11 of tBad
   put "digest  " & cxdHex(tHash) & return into field "sign:out"
   put "tampered " & cxdHex(tBad) after field "sign:out"
   if cxVerify(sPub33, tHash, tBad) is false then
      cxdStatus "sign:status", "One flipped bit and verification REJECTS it - that is the fail-closed headline.", "ok"
   else
      cxdStatus "sign:status", "A tampered signature verified - this must never happen.", "bad"
   end if
end doTamper

-- ------------------------------------------------------------------ Ethereum tab actions
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
   if haveKey("eth:status") is false then
      exit doEthSign
   end if
   put "Pay Bob 1 ETH, nonce 7" into sEthMsg
   put cxKeccak256(cxdAscii(sEthMsg)) into tHash
   put cxSignRecoverable(sSeckey, tHash) into sEthSig
   if cxIsError(sEthSig) then
      cxdStatus "eth:status", sEthSig, "bad"
      exit doEthSign
   end if
   put "digest  " & cxdHex(tHash) & return into tOut
   put "r||s    " & cxdHex(byte 1 to 64 of sEthSig) & return after tOut
   put "recid   " & byteToNum(byte 65 of sEthSig) && "(raw 0..3; Ethereum shows it as 27/28 or EIP-155)" after tOut
   put tOut into field "eth:out"
   cxdStatus "eth:status", "Recoverable signature made over a Keccak-256 digest (as Ethereum hashes).", "ok"
end doEthSign

on doRecover
   local tHash
   local tRec
   if sEthSig is empty then
      cxdStatus "eth:status", "Sign recoverably first.", "bad"
      exit doRecover
   end if
   put cxKeccak256(cxdAscii(sEthMsg)) into tHash
   put cxRecover(sEthSig, tHash) into tRec
   if cxIsError(tRec) then
      cxdStatus "eth:status", tRec, "bad"
      exit doRecover
   end if
   put field "eth:out" & return & "recovered " & cxdHex(tRec) into field "eth:out"
   if tRec is sPub65 then
      cxdStatus "eth:status", "Recovered pubkey MATCHES the signer - that is ecrecover.", "ok"
   else
      cxdStatus "eth:status", "Recovered pubkey does not match - this must never happen.", "bad"
   end if
end doRecover

-- ------------------------------------------------------------------ ECDH tab actions
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
   -- two PUBLIC demo keys from fixed phrases, so the run reproduces
   put cxNewSeckey(cxSha256(cxdAscii("alice demo key (public)"))) into tAliceSk
   put cxNewSeckey(cxSha256(cxdAscii("bob demo key (public)"))) into tBobSk
   if cxIsError(tAliceSk) or cxIsError(tBobSk) then
      cxdStatus "ecdh:status", "Demo key derivation failed; is the extension loaded?", "bad"
      exit doEcdh
   end if
   put cxEcdh(tAliceSk, cxPublicKey(tBobSk, true)) into tAliceView
   put cxEcdh(tBobSk, cxPublicKey(tAliceSk, false)) into tBobView
   if cxIsError(tAliceView) or cxIsError(tBobView) then
      cxdStatus "ecdh:status", "ECDH failed; is the extension loaded?", "bad"
      exit doEcdh
   end if
   put "alice   " & cxdHex(tAliceView) & return into tOut
   put "bob     " & cxdHex(tBobView) after tOut
   put tOut into field "ecdh:out"
   -- model the hygiene even with demo keys: clear key variables when done
   put empty into tAliceSk
   put empty into tBobSk
   if tAliceView is tBobView then
      cxdStatus "ecdh:status", "Both parties computed the SAME secret; no secret key crossed the wire.", "ok"
   else
      cxdStatus "ecdh:status", "The two views differ - this must never happen.", "bad"
   end if
end doEcdh

-- ------------------------------------------------------------------ Hashes tab actions
on handleHash pRole
   if pRole is "go" then
      doHashAll
   end if
end handleHash

on doHashAll
   local tIn
   local tOut
   put cxdAscii(field "hash:msg") into tIn
   put "keccak256  " & cxdHex(cxKeccak256(tIn)) & return into tOut
   put "sha3-256   " & cxdHex(cxSha3_256(tIn)) & return after tOut
   put "           ^ same input, ONE padding byte apart: never alias these two" & return after tOut
   put "sha256     " & cxdHex(cxSha256(tIn)) & return after tOut
   put "sha512     " & cxdShort(cxSha512(tIn), 96) & return after tOut
   put "ripemd160  " & cxdHex(cxRipemd160(tIn)) & return after tOut
   put "hash160    " & cxdHex(cxHash160(tIn)) && "(a Bitcoin address hashes this)" & return after tOut
   put "hash256    " & cxdHex(cxHash256(tIn)) && "(txids, Base58Check checksums)" after tOut
   put tOut into field "hash:out"
   cxdStatus "hash:status", "Notice how keccak256 and sha3-256 differ completely.", "ok"
end doHashAll

-- ------------------------------------------------------------------ Key Derivation tab actions
on handleKdf pRole
   if pRole is "go" then
      doDerive
   end if
end handleKdf

on doDerive
   local tPass
   local tOut
   local tSeed
   put cxdAscii(field "kdf:msg") into tPass
   put "hmac-sha256  " & cxdHex(cxHmacSha256(cxdAscii("Bitcoin seed"), tPass)) & return into tOut
   put "hmac-sha512  " & cxdShort(cxHmacSha512(cxdAscii("Bitcoin seed"), tPass), 96) & return after tOut
   put "             ^ HMAC-SHA512(key=Bitcoin seed) is the BIP-32 master step" & return & return after tOut
   put cxPbkdf2HmacSha512(tPass, cxdAscii("mnemonicTREZOR"), 2048, 64) into tSeed
   if cxIsError(tSeed) then
      cxdStatus "kdf:status", tSeed, "bad"
      exit doDerive
   end if
   put "bip39 seed   " & cxdHex(tSeed) after tOut
   put "             ^ PBKDF2-HMAC-SHA512, 2048 iters, salt mnemonic+passphrase" & return after tOut
   put tOut into field "kdf:out"
   put empty into tPass
   cxdStatus "kdf:status", "This is exactly how a BIP-39 mnemonic becomes a 64-byte wallet seed.", "ok"
end doDerive

-- ------------------------------------------------------------------ About tab: embedded self-test
on handleAbout pRole
   if pRole is "selftest" then
      doSelfTest
   end if
end handleAbout

on doSelfTest
   local tSk
   local tHash
   local tSig
   put 0 into sTPass
   put 0 into sTFail
   put "CoinXT self-test" & return & return into sTLog

   if cxdProbe() is false then
      put "The CoinXT extension or its native library is not loaded." & return after sTLog
      put "Install the packaged extension and load src/coinxt.livecodescript, then retry." after sTLog
      put sTLog into field "about:out"
      cxdStatus "about:status", "Cannot run: the cx* API is not reachable.", "bad"
      exit doSelfTest
   end if

   -- hashes (published vectors)
   checkInto (cxdHex(cxKeccak256(empty)) is \
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), \
      "keccak256(empty) matches the Ethereum vector"
   checkInto (cxKeccak256(cxdAscii("abc")) is not cxSha3_256(cxdAscii("abc"))), \
      "keccak256 and sha3-256 are distinct (no aliasing)"
   checkInto (cxdHex(cxSha256(cxdAscii("abc"))) is \
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), \
      "sha256(abc) matches FIPS-180"
   checkInto (cxdHex(cxRipemd160(cxdAscii("abc"))) is \
      "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"), \
      "ripemd160(abc) matches the published vector"

   -- keys and deterministic signing (the classic public RFC 6979 vector)
   put cxdBin("0000000000000000000000000000000000000000000000000000000000000001") into tSk
   checkInto (cxSeckeyValidate(tSk) is true), "seckey 1 is valid"
   checkInto (cxdHex(cxPublicKey(tSk, true)) is \
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), \
      "pubkey(1) compressed is the generator G"
   put cxdBin("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e") into tHash
   put cxSign(tSk, tHash) into tSig
   checkInto (cxdHex(tSig) is \
      "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"), \
      "sign(sk=1, sha256(Satoshi Nakamoto)) matches the public vector (low-s)"
   checkInto (cxVerify(cxPublicKey(tSk, true), tHash, tSig) is true), \
      "the signature verifies under its public key"

   -- negative paths (fail closed)
   checkInto cxIsError(cxSign(cxdAscii("short"), tHash)), \
      "a short seckey returns a clean CoinXT: error"
   checkInto (cxVerify(cxPublicKey(tSk, true), cxSha256(cxdAscii("other")), tSig) is false), \
      "the signature does not verify for a different digest"

   -- ecrecover round trip
   put cxSignRecoverable(tSk, tHash) into tSig
   checkInto (cxRecover(tSig, tHash) is cxPublicKey(tSk, false)), \
      "ecrecover returns the signing pubkey"

   put sTLog into field "about:out"
   if sTFail is 0 then
      cxdStatus "about:status", ("All checks passed: " & sTPass & " / " & sTPass & " green."), "ok"
   else
      cxdStatus "about:status", ("FAILED: " & sTFail & " of " & (sTPass + sTFail) & " checks did not pass."), "bad"
   end if
end doSelfTest

-- record one check into the running transcript (a script-local, so nothing
-- couples to a control's visibility)
command checkInto pCondition, pLabel
   if pCondition then
      add 1 to sTPass
      put "  ok   " & pLabel & return after sTLog
   else
      add 1 to sTFail
      put "  FAIL " & pLabel & return after sTLog
   end if
end checkInto
