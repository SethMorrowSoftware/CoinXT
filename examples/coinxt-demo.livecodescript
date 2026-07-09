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
-- Tabs: Keys (make + validate a secp256k1 key, derive its public key + WIF),
-- Addresses (Bitcoin legacy + nested SegWit + SegWit + Taproot, Ethereum with
-- EIP-55, mainnet/testnet toggle), Sign & Verify (deterministic RFC 6979
-- ECDSA + tamper rejection + verify-a-pasted-signature), Schnorr (BIP-340
-- sign/verify/tamper + the BIP-341 Taproot tweak), Ethereum (EIP-191
-- personal_sign + ecrecover to the signer's ADDRESS, plus a COMPLETE offline
-- EIP-155 transaction: RLP -> keccak -> sign -> raw broadcast bytes), BTC Tx
-- (a COMPLETE offline BIP-143 SegWit spend - native or nested - that
-- reproduces the official BIP-143 example byte for byte, fee always shown),
-- PSBT (BIP-174 cold signing: decode a pasted PSBT's intent, sign only what
-- your key or the Wallet phrase's derivation paths control, finalize and
-- extract - the Sparrow / Electrum / Core interchange flow),
-- Shared Secret (ECDH, including your-key x pasted-pubkey), Hashes (the
-- Keccak-256 vs SHA3-256 footgun, plus SHA-2, RIPEMD-160, hash160/hash256,
-- HMAC), Wallet (type/paste ANY BIP-39 phrase to RESTORE it, or generate
-- 12/24 fresh words: the first BIP-44/49/84/86 + Ethereum addresses, the
-- account xpub AND xprv, the first key's WIF, and a TEN-address fidelity
-- listing per chain to compare against any mainstream wallet), Decode
-- (paste any address / WIF / xprv / xpub and see it verified and taken
-- apart, or REJECTED on a bad checksum), About (pitch + one-click self-test).
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
local sTab            -- active tab: keys | addr | sign | schn | eth | btx | psbt | ecdh | hash | seed | dec | about
local sSeckey         -- the demo seckey (PUBLIC test key material only)
local sPub33          -- its compressed pubkey
local sPub65          -- its uncompressed pubkey
local sSig            -- last plain signature (64 bytes)
local sSigMsg         -- the message that was signed
local sSchnSig        -- last Schnorr signature (64 bytes)
local sSchnMsg        -- the message signed on the Schnorr tab
local sEthSig         -- last recoverable signature (65 bytes)
local sEthMsg         -- the message signed on the Ethereum tab
local sTestnet        -- true when the Addresses tab shows testnet forms
local sBtxNested      -- true when the BTC Tx input is nested P2SH-P2WPKH
local sAddrP2WPKH     -- last derived SegWit address (for the copy button)
local sAddrEth        -- last derived Ethereum address (for the copy button)
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

-- ------------------------------------------------------------------ UI construction
on buildUI
   if there is a field "ui:title" then
      exit buildUI
   end if
   -- a 720p footprint (fits a 1280x720 display with window chrome to spare):
   -- wide enough that a full pubkey, signature, or raw tx line never wraps
   set the width of this stack to 1200
   set the height of this stack to 680
   set the name of this stack to "CoinXT Demo"
   set the backgroundColor of this stack to kClrPage

   -- header band
   cxdRect "ui:band", "0,0,1200,64", kClrBand, 0
   cxdLabel "ui:title", "28,8,520,44", "CoinXT", kClrBandText, 24, "bold"
   cxdLabel "ui:subtitle", "30,40,760,62", "Bitcoin and Ethereum cryptography for xTalk, from one library", kClrBandSub, 12, "plain"

   -- ABI status pill (top-right); set by refreshAbiPill
   cxdRect "ui:pill", "976,17,1172,47", kClrPillBad, 15
   cxdLabel "ui:pillText", "976,17,1172,47", "", kClrPillBadText, 11, "bold"
   set the textAlign of field "ui:pillText" to "center"
   refreshAbiPill

   -- tab bar: twelve equal tabs on one 96px rhythm, full labels, flush
   -- with the panel edges
   cxdButton "ui:tabKeys", "24,74,101,104", "Keys", "idle"
   cxdButton "ui:tabAddr", "106,74,183,104", "Addresses", "idle"
   cxdButton "ui:tabSign", "188,74,265,104", "Sign", "idle"
   cxdButton "ui:tabSchn", "270,74,347,104", "Schnorr", "idle"
   cxdButton "ui:tabEth", "352,74,429,104", "Ethereum", "idle"
   cxdButton "ui:tabBtx", "434,74,511,104", "BTC Tx", "idle"
   cxdButton "ui:tabPsbt", "516,74,593,104", "PSBT", "idle"
   cxdButton "ui:tabEcdh", "598,74,675,104", "ECDH", "idle"
   cxdButton "ui:tabHash", "680,74,757,104", "Hashes", "idle"
   cxdButton "ui:tabSeed", "762,74,839,104", "Wallet", "idle"
   cxdButton "ui:tabTool", "844,74,921,104", "Tools", "idle"
   cxdButton "ui:tabOnline", "926,74,1003,104", "Online", "idle"
   cxdButton "ui:tabDec", "1008,74,1085,104", "Decode", "idle"
   cxdButton "ui:tabAbout", "1090,74,1173,104", "About", "idle"

   -- content panel + footer
   cxdPanel "ui:panel", "24,114,1176,632"
   cxdLabel "ui:footer", "24,642,1176,672", "Backed by trezor-crypto through the CoinXT C shim. Signing is deterministic (RFC 6979 / BIP-340, always canonical); every malformed input fails closed. Demo keys are PUBLIC - never fund them.", kClrInkMute, 11, "plain"

   buildKeysTab
   buildAddrTab
   buildSignTab
   buildSchnorrTab
   buildEthTab
   buildBtxTab
   buildPsbtTab
   buildEcdhTab
   buildHashTab
   buildSeedTab
   buildToolTab
   buildOnlineTab
   buildDecodeTab
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
   cxdHdr "keys:h", "48,128,1152,156", "A key is 32 bytes; CoinXT validates it and derives the public key"
   cxdCap "keys:p", "48,158,1152,202", "CoinXT never invents entropy. The demo key derives from a famously PUBLIC phrase (correct horse battery staple), so it is safe to show and fatal to fund. The SodiumXT button draws real entropy if that library is loaded, and you can import your own test key below.", kClrInkSoft
   cxdButton "keys:demo", "48,210,236,240", "Use the demo key", "primary"
   cxdButton "keys:sodium", "248,210,468,240", "Draw entropy (SodiumXT)", "idle"
   cxdButton "keys:copy", "480,210,630,240", "Copy pubkey", "idle"
   cxdCap "keys:outLabel", "48,250,1152,268", "seckey (PUBLIC) / compressed + uncompressed pubkey / x-only (BIP-340) / WIF export:", kClrInkMute
   cxdMono "keys:out", "48,270,1152,420"
   cxdCap "keys:note", "48,428,1152,470", "The compressed pubkey feeds the Bitcoin addresses; the uncompressed one (minus its 04 byte) feeds an Ethereum address. The WIF line is the same secret key in the form every wallet imports. Open the Addresses tab to see all five address forms.", kClrInkMute
   cxdCap "keys:importLabel", "48,478,1152,496", "Or import YOUR OWN test key - paste a WIF string or 64 hex characters (test keys only!):", kClrInkMute
   cxdInput "keys:import", "48,498,940,528", ""
   cxdButton "keys:load", "952,498,1152,528", "Import key", "primary"
   cxdLabel "keys:status", "48,596,1152,628", "No key yet - click a button above.", kClrInkSoft, 12, "plain"
end buildKeysTab

-- ---- Addresses tab
on buildAddrTab
   cxdHdr "addr:h", "48,128,1152,156", "Real Bitcoin and Ethereum addresses from your key"
   cxdCap "addr:p", "48,158,1152,206", "The one public key becomes five addresses: Bitcoin legacy (Base58Check, 1...), nested SegWit (P2SH-P2WPKH, 3..., the form every pre-SegWit wallet can pay), native SegWit (Bech32, bc1q), Taproot (Bech32m, bc1p, BIP-341 tweaked), plus an Ethereum address (Keccak-256 with the EIP-55 mixed-case checksum). All framed in script, pinned to the BIP-173/350, BIP-49/86 and EIP-55 test vectors.", kClrInkSoft
   cxdButton "addr:go", "48,214,236,244", "Derive addresses", "primary"
   cxdButton "addr:copyBtc", "248,214,438,244", "Copy SegWit (bc1)", "idle"
   cxdButton "addr:copyEth", "450,214,640,244", "Copy Ethereum", "eth"
   cxdButton "addr:net", "652,214,852,244", "Network: mainnet", "idle"
   cxdCap "addr:outLabel", "48,254,1152,272", "P2PKH (1...) / P2SH-P2WPKH (3...) / P2WPKH (bc1q...) / P2TR (bc1p...) / Ethereum (0x...):", kClrInkMute
   cxdMono "addr:out", "48,274,1152,424"
   cxdCap "addr:note", "48,432,1152,478", "The Bitcoin forms come from the COMPRESSED key; the Ethereum form comes from the UNCOMPRESSED key (its last 20 keccak bytes). Taproot tweaks the key (Q = P + hash(P)*G) before encoding. Toggle the network to see the testnet framing of the SAME key (Ethereum uses one address on every chain).", kClrInkMute
   cxdLabel "addr:status", "48,596,1152,628", "Make a key on the Keys tab, then derive its addresses here.", kClrInkSoft, 12, "plain"
end buildAddrTab

-- ---- Sign & Verify tab
on buildSignTab
   cxdHdr "sign:h", "48,128,1152,156", "Deterministic ECDSA over the digest YOU built"
   cxdCap "sign:p", "48,158,1152,202", "CoinXT signs exactly a 32-byte digest (here SHA-256 of your message). The same key and digest always give the SAME signature (RFC 6979), so there is no nonce to leak. Then flip one bit and watch verification reject it - and verify signatures from ANY other library below.", kClrInkSoft
   cxdBadge "sign:b1", "48,212,74,238", "1"
   cxdButton "sign:go", "82,210,230,240", "Sign", "primary"
   cxdBadge "sign:b2", "244,212,270,238", "2"
   cxdButton "sign:verify", "278,210,426,240", "Verify", "idle"
   cxdBadge "sign:b3", "440,212,466,238", "3"
   cxdButton "sign:tamper", "474,210,666,240", "Flip a bit & verify", "idle"
   cxdCap "sign:msgLabel", "48,250,1152,268", "Message to sign:", kClrInkMute
   cxdInput "sign:msg", "48,270,1152,300", "Pay Bob 1 coin, invoice 42"
   cxdCap "sign:outLabel", "48,308,1152,326", "digest (SHA-256) / signature (r||s, low-s):", kClrInkMute
   cxdMono "sign:out", "48,328,1152,448"
   cxdCap "sign:vLabel", "48,458,1152,476", "Or verify a PASTED signature against the message above - pubkey hex / signature hex (r||s):", kClrInkMute
   cxdInput "sign:vpub", "48,478,560,508", ""
   cxdInput "sign:vsig", "572,478,1010,508", ""
   cxdButton "sign:vgo", "1022,478,1152,508", "Check", "idle"
   cxdCap "sign:b322Label", "48,518,1152,536", "BIP-322 (proof you control a bc1q address): Sign makes a portable base64 proof of the message above; Check verifies one (address in the LEFT box, base64 signature in the RIGHT box). Signatures from Bitcoin Core / Sparrow verify here and vice versa.", kClrInkMute
   cxdButton "sign:b322sign", "48,544,268,574", "BIP-322 sign (my key)", "idle"
   cxdButton "sign:b322check", "280,544,480,574", "Check BIP-322", "idle"
   cxdLabel "sign:status", "48,596,1152,628", "Make a key on the Keys tab, then Sign here.", kClrInkSoft, 12, "plain"
end buildSignTab

-- ---- Schnorr (BIP-340) tab
on buildSchnorrTab
   cxdHdr "schn:h", "48,128,1152,156", "Schnorr signatures (BIP-340): what a Taproot spend signs with"
   cxdCap "schn:p", "48,158,1152,206", "Bitcoin Taproot replaced ECDSA with Schnorr: 32-byte x-only public keys and 64-byte signatures that verify with one clean equation. CoinXT signs the 32-byte digest deterministically (the BIP-340 zero-aux default), and the SAME key, tweaked per BIP-341 (Q = P + hash(P)*G), becomes the bc1p address a Taproot spend unlocks.", kClrInkSoft
   cxdBadge "schn:b1", "48,216,74,242", "1"
   cxdButton "schn:go", "82,214,230,244", "Sign (BIP-340)", "primary"
   cxdBadge "schn:b2", "244,216,270,242", "2"
   cxdButton "schn:verify", "278,214,426,244", "Verify", "idle"
   cxdBadge "schn:b3", "440,216,466,242", "3"
   cxdButton "schn:tamper", "474,214,666,244", "Flip a bit & verify", "idle"
   cxdCap "schn:msgLabel", "48,254,1152,272", "Message to sign (SHA-256 makes the 32-byte digest BIP-340 signs):", kClrInkMute
   cxdInput "schn:msg", "48,274,1152,304", "Taproot pays whoever proves this"
   cxdCap "schn:outLabel", "48,312,1152,330", "x-only pubkey / digest / signature (r||s) / Taproot output key + bc1p address:", kClrInkMute
   cxdMono "schn:out", "48,332,1152,502"
   cxdLabel "schn:status", "48,596,1152,628", "Make a key on the Keys tab, then Sign here.", kClrInkSoft, 12, "plain"
end buildSchnorrTab

-- ---- Ethereum tab
on buildEthTab
   cxdHdr "eth:h", "48,128,1152,156", "Ethereum: personal_sign, ecrecover, and a fully signed transaction"
   cxdCap "eth:p", "48,158,1152,206", "Two complete Ethereum flows, entirely offline. personal_sign: the message is prefixed the EIP-191 way (so it can never double as a transaction), Keccak-256 hashed, and signed RECOVERABLY - from the signature alone, ecrecover yields the signer's ADDRESS; that is every 'Sign in with Ethereum' login. Transaction: the fields below are RLP-encoded, hashed, signed, and reassembled into the exact raw bytes a node would broadcast (EIP-155 replay protection, chain 1).", kClrInkSoft
   cxdCap "eth:msgLabel", "48,214,1152,232", "Message (personal_sign):", kClrInkMute
   cxdInput "eth:msg", "48,234,700,264", "I control this address, nonce 7"
   cxdButton "eth:sign", "712,234,920,264", "Sign (EIP-191)", "eth"
   cxdButton "eth:recover", "932,234,1152,264", "Recover signer", "idle"
   cxdCap "eth:txLabel", "48,272,1152,290", "Transaction: to-address / value in wei (fixed demo fields: nonce 9, 20 gwei, 21000 gas, chain 1):", kClrInkMute
   cxdInput "eth:to", "48,292,560,322", "0x3535353535353535353535353535353535353535"
   cxdInput "eth:value", "572,292,800,322", "1000000000000000000"
   cxdButton "eth:tx", "812,292,1012,322", "Sign transaction", "eth"
   cxdButton "eth:typed", "1024,292,1152,322", "EIP-712", "idle"
   cxdCap "eth:outLabel", "48,330,1152,348", "digest / signature / recovered address / raw signed transaction:", kClrInkMute
   cxdMono "eth:out", "48,350,1152,540"
   cxdLabel "eth:status", "48,596,1152,628", "Make a key on the Keys tab first.", kClrInkSoft, 12, "plain"
end buildEthTab

-- ---- BTC Tx tab (offline BIP-143 signing)
on buildBtxTab
   cxdHdr "btx:h", "48,128,1152,156", "Sign a real Bitcoin transaction, offline (BIP-143)"
   cxdCap "btx:p", "48,158,1152,206", "One SegWit input owned by YOUR current key (Keys tab), any standard outputs: the fields are BIP-143 hashed, signed deterministically, DER-framed, and assembled into broadcast-ready raw bytes - all offline. Whatever the outputs do not spend becomes the fee, shown before you sign. The prefill is the OFFICIAL BIP-143 example: click Load, then Sign, and the raw bytes must equal the transaction printed in the BIP itself.", kClrInkSoft
   cxdButton "btx:go", "48,214,248,244", "Sign transaction", "primary"
   cxdButton "btx:example", "260,214,500,244", "Load the BIP-143 example", "idle"
   cxdButton "btx:nested", "512,214,732,244", "Input: nested (BIP-49)", "idle"
   cxdCap "btx:inLabel", "48,252,1152,270", "Funding outpoint - txid / vout / amount in satoshis (the coin your key controls):", kClrInkMute
   cxdInput "btx:txid", "48,272,700,302", "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb"
   cxdInput "btx:vout", "712,272,780,302", "1"
   cxdInput "btx:amt", "792,272,1012,302", "1000000000"
   cxdCap "btx:outLabel", "48,310,1152,328", "Outputs, one per line: amountSats address (any address type; the unspent rest is the fee):", kClrInkMute
   cxdInput "btx:outs", "48,330,1152,388", "199996600 1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7" & return & "800000000 1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8"
   cxdCap "btx:advLabel", "48,396,1152,414", "version / sequence / locktime:", kClrInkMute
   cxdInput "btx:ver", "48,416,140,446", "1"
   cxdInput "btx:seq", "152,416,320,446", "4294967294"
   cxdInput "btx:lock", "332,416,480,446", "1170"
   cxdMono "btx:out", "48,454,1152,586"
   cxdLabel "btx:status", "48,596,1152,628", "Load the example (it also adopts the example's PUBLIC key), or fill in your own test coin. Nothing is broadcast; the output is raw bytes you can inspect in any tx decoder.", kClrInkSoft, 12, "plain"
end buildBtxTab

-- ---- PSBT tab (BIP-174 cold signing)
on buildPsbtTab
   cxdHdr "psbt:h", "48,128,1152,156", "PSBT: the cold-signing flow every Bitcoin wallet speaks (BIP-174)"
   cxdCap "psbt:p", "48,158,1152,206", "Paste a Partially Signed Bitcoin Transaction from Sparrow, Electrum, or Core: Decode shows exactly what it pays before anything is signed; Sign adds signatures ONLY for the single-key SegWit inputs your key controls (by direct key, or by walking the PSBT's own BIP32 derivation paths from the Wallet tab's phrase - the air-gapped hardware-wallet flow); Finalize extracts the broadcast-ready transaction. The prefill wraps the official BIP-143 example, so Sign + Finalize must end at the BIP's published bytes.", kClrInkSoft
   cxdButton "psbt:dec", "48,214,236,244", "Decode intent", "primary"
   cxdButton "psbt:signhd", "248,214,478,244", "Sign (Wallet tab phrase)", "idle"
   cxdButton "psbt:signkey", "490,214,690,244", "Sign (Keys tab key)", "idle"
   cxdButton "psbt:final", "702,214,902,244", "Finalize + extract", "idle"
   cxdCap "psbt:inLabel", "48,252,1152,270", "PSBT (base64 or hex). The signed form replaces this field, so the flow chains: decode -> sign -> finalize.", kClrInkMute
   cxdInput "psbt:in", "48,272,1152,330", "cHNidP8BAHcBAAAAAdtrGyCqD9eyOIC+LsvUqYEwl0z0dI+2YJKsTTzrGlR3AQAAAAD+////Ari06wsAAAAAGXapFKRXtoTX8NU5pGpFu8BD81tZ0NljiKwACK8vAAAAABl2qRT9Jwse5qvK6pf+p60EAui9itbXfIiskgQAAAABASAAypo7AAAAABepFEcz83z024b7wu/tJQC09OSfMSAjhwEDBAEAAAABBBYAFHkJGXIYbESesd7SK3jkDQCb3wCJAAAA"
   cxdMono "psbt:out", "48,338,1152,586"
   cxdLabel "psbt:status", "48,596,1152,628", "Decode first - a cold signer NEVER signs what it has not shown you. (The prefilled example's key loads via the BTC Tx tab's Load button.)", kClrInkSoft, 12, "plain"
end buildPsbtTab

-- ---- Shared Secret (ECDH) tab
on buildEcdhTab
   cxdHdr "ecdh:h", "48,128,1152,156", "Two parties, one shared secret (ECDH)"
   cxdCap "ecdh:p", "48,158,1152,206", "Alice combines HER secret key with BOB's public key; Bob does the reverse. Both land on the same 32 bytes (the raw SEC1 x-coordinate) without either secret key ever moving. A real protocol hashes this secret before using it as a symmetric key.", kClrInkSoft
   cxdButton "ecdh:go", "48,214,320,244", "Run the exchange (test keys)", "primary"
   cxdCap "ecdh:outLabel", "48,254,1152,272", "Alice's view (sk_A, pub_B) / Bob's view (sk_B, pub_A):", kClrInkMute
   cxdMono "ecdh:out", "48,274,1152,424"
   cxdCap "ecdh:peerLabel", "48,434,1152,452", "Or combine YOUR key (Keys tab) with a pasted peer public key (33/65-byte hex):", kClrInkMute
   cxdInput "ecdh:peer", "48,454,940,484", ""
   cxdButton "ecdh:mine", "952,454,1152,484", "Secret with MY key", "primary"
   cxdLabel "ecdh:status", "48,596,1152,628", "Click above to run a Diffie-Hellman exchange between two demo keys.", kClrInkSoft, 12, "plain"
end buildEcdhTab

-- ---- Hashes tab
on buildHashTab
   cxdHdr "hash:h", "48,128,1152,156", "The coin hashes, including the classic Ethereum footgun"
   cxdCap "hash:p", "48,158,1152,202", "Ethereum's Keccak-256 and NIST's SHA3-256 differ by ONE padding byte, and confusing them is the classic wallet bug. CoinXT exposes them as two functions that can never be aliased. Hash any text and compare.", kClrInkSoft
   cxdCap "hash:msgLabel", "48,210,1152,228", "Text to hash (or 0x... to hash raw hex bytes, so you can check vectors from any tool):", kClrInkMute
   cxdInput "hash:msg", "48,230,940,260", "abc"
   cxdButton "hash:go", "952,230,1152,260", "Hash it", "primary"
   cxdMono "hash:out", "48,270,1152,500"
   cxdLabel "hash:status", "48,596,1152,628", "Keccak-256 and SHA3-256 will look completely different - that is the point.", kClrInkSoft, 12, "plain"
end buildHashTab

-- ---- HD Wallet tab (restore ANY BIP-39 phrase, or generate 12/24 words)
on buildSeedTab
   cxdHdr "seed:h", "48,128,1152,156", "Restore a whole wallet from its seed phrase (BIP-32/39/44/49/84/86)"
   cxdCap "seed:p", "48,158,1152,210", "Type or paste ANY BIP-39 phrase and Restore rebuilds the whole wallet: the checksum is verified (a typo in any word is caught), PBKDF2-HMAC-SHA512 makes the 64-byte master seed, and CoinXT walks the BIP-32 tree to the first receiving address of EVERY standard account type plus the watch-only account xpub, the first key's WIF, and a ten-address fidelity listing per chain. The field starts with the canonical TEST phrase, so you can check every line against any mainstream wallet.", kClrInkSoft
   cxdButton "seed:restore", "48,218,236,248", "Restore wallet", "primary"
   cxdButton "seed:gen12", "248,218,428,248", "Generate 12 words", "idle"
   cxdButton "seed:gen24", "440,218,620,248", "Generate 24 words", "idle"
   cxdCap "seed:ppLabel", "640,224,738,244", "Passphrase:", kClrInkMute
   cxdInput "seed:pp", "742,218,1012,248", ""
   cxdCap "seed:mnemLabel", "48,256,1152,274", "Seed phrase (12/15/18/21/24 words; PUBLIC demo phrases only - never type a funded one here):", kClrInkMute
   cxdInput "seed:mnem", "48,276,1152,320", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
   cxdCap "seed:pathLabel", "48,334,178,352", "Explore a path:", kClrInkMute
   cxdInput "seed:path", "182,328,620,358", "m/84'/0'/0'/0/0"
   cxdButton "seed:derive", "632,328,812,358", "Derive this path", "idle"
   cxdMono "seed:out", "48,366,1152,586"
   cxdLabel "seed:status", "48,596,1152,628", "Click Restore to rebuild the canonical test wallet, or Generate for a fresh phrase (SodiumXT entropy if loaded, else a fixed DEMO value).", kClrInkSoft, 12, "plain"
end buildSeedTab

-- ---- Tools tab (the workflow layer: files, profiles, gap-scan)
on buildToolTab
   cxdHdr "tool:h", "48,128,1152,156", "Wallet tools: watch-only export, files, and the is-this-address-mine check"
   cxdCap "tool:p", "48,158,1152,206", "The workflow around the crypto, all app-layer (CoinXT stays a calculator; storage is the app's). Build profile writes a WATCH-ONLY export of the Wallet tab's phrase - fingerprint, every account xpub, first addresses - safe to keep on a hot machine. Save/Load round-trip the text box to a file (profiles, PSBTs, raw transactions). Scan answers the question that prevents the classic address-swap loss: is this address REALLY one of mine?", kClrInkSoft
   cxdButton "tool:profile", "48,214,296,244", "Build watch-only profile", "primary"
   cxdButton "tool:save", "308,214,478,244", "Save to file...", "idle"
   cxdButton "tool:load", "490,214,660,244", "Load from file...", "idle"
   cxdButton "tool:qrgo", "672,214,860,244", "QR the file box", "idle"
   cxdCap "tool:scanLabel", "48,252,1152,270", "Scan the Wallet tab's phrase for an address (receive + change, first 20 of every standard chain):", kClrInkMute
   cxdInput "tool:addr", "48,272,700,302", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
   cxdButton "tool:scan", "712,272,912,302", "Scan: is it mine?", "primary"
   cxdCap "tool:ioLabel", "48,310,700,328", "File box (profiles land here; Save writes, Load fills, QR renders):", kClrInkMute
   cxdInput "tool:io", "48,330,700,440", ""
   cxdMono "tool:out", "48,448,700,586"
   -- the air-gap surface: the file box as a QR, rendered by the ENGINE's
   -- qrCreate library (compose, never hand-roll - the same rule as the
   -- crypto). Created hidden-safe: showTab toggles it by prefix like any
   -- other control.
   if there is no image "tool:qr" then
      create image "tool:qr"
   end if
   set the rectangle of image "tool:qr" to "760,310,1036,586"
   cxdLabel "tool:status", "48,596,1152,628", "Build a profile from the Wallet tab's phrase, or paste an address and Scan.", kClrInkSoft, 12, "plain"
end buildToolTab

-- ---- Online tab (the OPTIONAL network layer; opt-in, testnet-first)
on buildOnlineTab
   cxdHdr "online:h", "48,128,1152,156", "Online: look up balances and broadcast - the OPT-IN network layer"
   cxdCap "online:p", "48,158,1152,214", "This is the SEPARATE coinxt-online module (SPEC 1.1), not the offline core. It reads chain state and broadcasts already-signed bytes over the engine's HTTP; it NEVER touches a key. Two honest costs: querying an explorer LEAKS your address to that server (point Endpoint at your own node or a Tor hidden service to avoid it), and Broadcast puts a real transaction on a real network. Defaults to a public TESTNET explorer, so a first run cannot spend mainnet coins.", kClrInkSoft
   cxdButton "online:balance", "48,220,236,250", "Look up balance", "primary"
   cxdButton "online:utxos", "248,220,436,250", "List UTXOs", "idle"
   cxdButton "online:net", "448,220,648,250", "Network: testnet", "idle"
   cxdCap "online:addrLabel", "48,258,1152,276", "Address to query (a TESTNET address by default; paste your own):", kClrInkMute
   cxdInput "online:addr", "48,278,1152,308", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
   cxdCap "online:txLabel", "48,316,1152,334", "Raw signed transaction hex to broadcast (from the BTC Tx or PSBT tab):", kClrInkMute
   cxdInput "online:tx", "48,336,972,366", ""
   cxdButton "online:broadcast", "984,336,1152,366", "Broadcast", "eth"
   cxdMono "online:out", "48,376,1152,586"
   cxdLabel "online:status", "48,596,1152,628", "Reads go to a public testnet explorer by default. Nothing is broadcast until you click Broadcast on a real signed tx.", kClrInkSoft, 12, "plain"
end buildOnlineTab

-- ---- Decode / inspect tab
on buildDecodeTab
   cxdHdr "dec:h", "48,128,1152,156", "Paste anything: verify its checksum and take it apart"
   cxdCap "dec:p", "48,158,1152,210", "Every format CoinXT emits, it also verifies and decodes, fail closed: Base58Check (legacy and P2SH addresses, WIF keys, xprv/xpub), Bech32/Bech32m (bc1q/bc1p SegWit addresses, BIP-350 rules including the v1 constant), and EIP-55 (the Ethereum mixed-case checksum). Change ONE character of a valid string and watch it be rejected instead of coerced - on a payment rail, that rejection is the feature.", kClrInkSoft
   cxdButton "dec:go", "48,218,248,248", "Decode + verify", "primary"
   cxdCap "dec:inLabel", "48,258,1152,276", "Address / WIF / xprv / xpub / 0x... to inspect:", kClrInkMute
   cxdInput "dec:in", "48,278,1152,308", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
   cxdMono "dec:out", "48,318,1152,500"
   cxdCap "dec:note", "48,508,1152,552", "Try: a 1... or 3... address, a bc1q/bc1p address (flip a character to see the checksum catch it), a WIF key (KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn is the famous PUBLIC key-1), an xpub, or an Ethereum 0x address in any casing.", kClrInkMute
   cxdLabel "dec:status", "48,596,1152,628", "Paste a string above and click Decode.", kClrInkSoft, 12, "plain"
end buildDecodeTab

-- ---- About tab (pitch + embedded self-test)
on buildAboutTab
   cxdHdr "about:h", "48,128,1152,156", "CoinXT: Bitcoin and Ethereum primitives for xTalk"
   cxdCap "about:exp", "48,158,1152,290", "CoinXT wraps trezor-crypto (the MIT-licensed C crypto core of the Trezor hardware wallet) behind a small C shim and a livecodescript API, so any xTalk app can make secp256k1 keys, sign deterministically (ECDSA RFC 6979 low-s, and BIP-340 Schnorr), verify, recover a signer the Ethereum way (raw and EIP-191 personal_sign), sign COMPLETE offline transactions on BOTH chains (EIP-155 legacy Ethereum, and BIP-143 SegWit Bitcoin with strict-DER framing - each reproducing its official published example byte for byte), act as a PSBT cold signer (decode, sign, finalize BIP-174 files from Sparrow / Electrum / Core, including HD signing via the PSBT's own derivation paths), sign EIP-712 typed data (the chain behind every signTypedData prompt, pinned to the EIP's own example), prove address ownership with BIP-322 signed messages (the BIP's own Core-made signatures verify here), OPTIONALLY read balances and broadcast over the engine's HTTP (a separate opt-in module that never touches a key), agree on an ECDH secret, restore or create a BIP-32/39 HD wallet on every standard path (BIP-44/49/84/86 and Ethereum), build and DECODE legacy / nested-SegWit / SegWit / Taproot / Ethereum addresses plus WIF and xprv/xpub, and hash with SHA-2, SHA-3, Keccak-256, RIPEMD-160 and HMAC - without shipping a wallet, a node, or a browser plugin. It adds no cryptography of its own; every curve op and hash is trezor-crypto's. Every checksum is verified on decode and every malformed input fails closed. The app owns key custody and confirm-before-sign; CoinXT signs only the exact digest it is handed.", kClrInkSoft
   cxdButton "about:selftest", "48,298,300,328", "Run the full self-test", "primary"
   cxdMono "about:out", "48,338,1152,586"
   cxdLabel "about:status", "48,596,1152,628", "Click Run the full self-test to check every primitive against a public vector.", kClrInkSoft, 12, "plain"
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
   styleTab "ui:tabAddr", (sTab is "addr")
   styleTab "ui:tabSign", (sTab is "sign")
   styleTab "ui:tabSchn", (sTab is "schn")
   styleTab "ui:tabEth", (sTab is "eth")
   styleTab "ui:tabBtx", (sTab is "btx")
   styleTab "ui:tabPsbt", (sTab is "psbt")
   styleTab "ui:tabEcdh", (sTab is "ecdh")
   styleTab "ui:tabHash", (sTab is "hash")
   styleTab "ui:tabSeed", (sTab is "seed")
   styleTab "ui:tabTool", (sTab is "tool")
   styleTab "ui:tabOnline", (sTab is "online")
   styleTab "ui:tabDec", (sTab is "dec")
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
   else if tPrefix is "addr" then
      handleAddr tRole
   else if tPrefix is "sign" then
      handleSign tRole
   else if tPrefix is "schn" then
      handleSchnorr tRole
   else if tPrefix is "eth" then
      handleEth tRole
   else if tPrefix is "btx" then
      handleBtx tRole
   else if tPrefix is "psbt" then
      handlePsbt tRole
   else if tPrefix is "ecdh" then
      handleEcdh tRole
   else if tPrefix is "hash" then
      handleHash tRole
   else if tPrefix is "seed" then
      handleSeed tRole
   else if tPrefix is "tool" then
      handleTool tRole
   else if tPrefix is "online" then
      handleOnline tRole
   else if tPrefix is "dec" then
      handleDecode tRole
   else if tPrefix is "about" then
      handleAbout tRole
   end if
end mouseUp

on handleChrome pRole
   if pRole is "tabKeys" then
      showTab "keys"
   else if pRole is "tabAddr" then
      showTab "addr"
   else if pRole is "tabSign" then
      showTab "sign"
   else if pRole is "tabSchn" then
      showTab "schn"
   else if pRole is "tabEth" then
      showTab "eth"
   else if pRole is "tabBtx" then
      showTab "btx"
   else if pRole is "tabPsbt" then
      showTab "psbt"
   else if pRole is "tabEcdh" then
      showTab "ecdh"
   else if pRole is "tabHash" then
      showTab "hash"
   else if pRole is "tabSeed" then
      showTab "seed"
   else if pRole is "tabTool" then
      showTab "tool"
   else if pRole is "tabOnline" then
      showTab "online"
   else if pRole is "tabDec" then
      showTab "dec"
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
   else if pRole is "load" then
      doImportKey
   else if pRole is "copy" then
      doCopyPubkey
   end if
end handleKeys

-- paste-your-own: accept a 64-hex-char raw seckey or any WIF string; both
-- paths validate range/checksum and fail closed before anything is adopted
on doImportKey
   local tIn
   local tKey
   local tDecoded
   put word 1 to -1 of field "keys:import" into tIn
   if tIn is empty then
      cxdStatus "keys:status", "Paste a WIF string or 64 hex characters first.", "bad"
      exit doImportKey
   end if
   if the number of chars in tIn is 64 then
      put cxHexDecode(tIn) into tKey
      if cxIsError(tKey) then
         cxdStatus "keys:status", tKey, "bad"
         exit doImportKey
      end if
      adoptSeckey tKey, "Imported from raw hex. Treat every key typed into a demo as compromised."
      put empty into tKey
      exit doImportKey
   end if
   put cxWifDecode(tIn) into tDecoded
   if cxIsError(tDecoded) then
      cxdStatus "keys:status", tDecoded, "bad"
      exit doImportKey
   end if
   put line 3 to -1 of tDecoded into tKey
   adoptSeckey tKey, "Imported from WIF (" & line 1 of tDecoded & "," && \
      "compressed=" & line 2 of tDecoded & "). Treat every key typed into a demo as compromised."
   put empty into tKey
   put empty into tDecoded
end doImportKey

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
   put "pub65   " & cxdHex(sPub65) & return after tOut
   put "xonly   " & cxdHex(cxXonlyFromSeckey(sSeckey)) && "(BIP-340 form: Schnorr + Taproot)" & return after tOut
   put "wif     " & cxWifEncode(sSeckey, true, true) && "(mainnet, compressed - a SECRET in real life)" after tOut
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

-- ------------------------------------------------------------------ Addresses tab actions
on handleAddr pRole
   if pRole is "go" then
      doAddresses
   else if pRole is "net" then
      doToggleNetwork
   else if pRole is "copyBtc" then
      if sAddrP2WPKH is empty then
         cxdStatus "addr:status", "Derive addresses first.", "bad"
      else
         cxdCopyFlash "addr:copyBtc", sAddrP2WPKH
         cxdStatus "addr:status", "SegWit address copied to the clipboard.", "ok"
      end if
   else if pRole is "copyEth" then
      if sAddrEth is empty then
         cxdStatus "addr:status", "Derive addresses first.", "bad"
      else
         cxdCopyFlash "addr:copyEth", sAddrEth
         cxdStatus "addr:status", "Ethereum address copied to the clipboard.", "ok"
      end if
   end if
end handleAddr

on doToggleNetwork
   put (sTestnet is not true) into sTestnet
   if sTestnet then
      set the label of button "addr:net" to "Network: testnet"
   else
      set the label of button "addr:net" to "Network: mainnet"
   end if
   -- re-derive in place so the toggle reads as one action
   if sSeckey is not empty then
      doAddresses
   end if
end doToggleNetwork

on doAddresses
   local tMainnet
   local tP2pkh
   local tP2sh
   local tP2wpkh
   local tP2tr
   local tEth
   local tOut
   if haveKey("addr:status") is false then
      exit doAddresses
   end if
   put (sTestnet is not true) into tMainnet
   -- the Bitcoin forms come from the compressed key; Ethereum from uncompressed
   put cxBtcAddressP2PKH(sPub33, tMainnet) into tP2pkh
   put cxBtcAddressP2SH_P2WPKH(sPub33, tMainnet) into tP2sh
   put cxBtcAddressP2WPKH(sPub33, tMainnet) into tP2wpkh
   put cxBtcAddressP2TR(sPub33, tMainnet) into tP2tr
   put cxEthAddress(sPub65) into tEth
   if cxIsError(tP2pkh) or cxIsError(tP2sh) or cxIsError(tP2wpkh) or cxIsError(tP2tr) or cxIsError(tEth) then
      cxdStatus "addr:status", "Address derivation failed; is the extension loaded?", "bad"
      exit doAddresses
   end if
   put tP2wpkh into sAddrP2WPKH
   put tEth into sAddrEth
   put "BTC legacy   (P2PKH)        " & tP2pkh & return into tOut
   put "BTC nested   (P2SH-P2WPKH)  " & tP2sh & return after tOut
   put "BTC SegWit   (P2WPKH)       " & tP2wpkh & return after tOut
   put "BTC Taproot  (P2TR)         " & tP2tr & return after tOut
   put "Ethereum     (EIP-55)       " & tEth && "(chain-independent)" after tOut
   put tOut into field "addr:out"
   if tMainnet then
      cxdStatus "addr:status", "Five addresses from one key - fund none of them (demo keys are public).", "ok"
   else
      cxdStatus "addr:status", "The SAME key in testnet framing (m/n..., 2..., tb1q..., tb1p...).", "ok"
   end if
end doAddresses

-- ------------------------------------------------------------------ Sign tab actions
on handleSign pRole
   if pRole is "go" then
      doSign
   else if pRole is "verify" then
      doVerify
   else if pRole is "tamper" then
      doTamper
   else if pRole is "vgo" then
      doVerifyPasted
   else if pRole is "b322sign" then
      doBip322Sign
   else if pRole is "b322check" then
      doBip322Check
   end if
end handleSign

-- BIP-322: a portable, wallet-interoperable proof that the current key
-- controls its bc1q address and endorses the message field
on doBip322Sign
   local tAddr
   local tSig
   local tOut
   if haveKey("sign:status") is false then
      exit doBip322Sign
   end if
   put cxBtcAddressP2WPKH(sPub33, true) into tAddr
   put cxBip322Sign(sSeckey, cxdAscii(field "sign:msg")) into tSig
   if cxIsError(tSig) then
      cxdStatus "sign:status", tSig, "bad"
      exit doBip322Sign
   end if
   put "address    " & tAddr & return & "message    " & field "sign:msg" \
      & return & "bip322     " & tSig into tOut
   put tOut into field "sign:out"
   cxdStatus "sign:status", "A portable proof: paste the address + signature into Sparrow or Core (verifymessage) and it checks out there too.", "ok"
end doBip322Sign

on doBip322Check
   local tOk
   put cxBip322Verify(word 1 to -1 of field "sign:vpub", cxdAscii(field "sign:msg"), word 1 to -1 of field "sign:vsig") into tOk
   if tOk is true then
      cxdStatus "sign:status", "VALID: whoever made this signature controls that address and endorsed this exact message.", "ok"
   else
      cxdStatus "sign:status", "Does NOT verify: wrong address, wrong message, or a corrupt signature (fail closed).", "bad"
   end if
end doBip322Check

-- third-party verification: paste any pubkey + raw signature and check them
-- against SHA-256 of the message field. Sign here and verify in another
-- library, or the reverse - that is what makes the demo a test bench.
on doVerifyPasted
   local tPub
   local tSig
   local tHash
   put cxHexDecode(word 1 to -1 of field "sign:vpub") into tPub
   put cxHexDecode(word 1 to -1 of field "sign:vsig") into tSig
   if cxIsError(tPub) or (the number of bytes in tPub is not 33 and the number of bytes in tPub is not 65) then
      cxdStatus "sign:status", "The pubkey must be 33 or 65 bytes of hex (66 or 130 characters).", "bad"
      exit doVerifyPasted
   end if
   if cxIsError(tSig) or the number of bytes in tSig is not 64 then
      cxdStatus "sign:status", "The signature must be the raw 64-byte r||s form (128 hex characters).", "bad"
      exit doVerifyPasted
   end if
   put cxSha256(cxdAscii(field "sign:msg")) into tHash
   if cxVerify(tPub, tHash, tSig) is true then
      cxdStatus "sign:status", "The pasted signature VERIFIES for this message under that pubkey.", "ok"
   else
      cxdStatus "sign:status", "Does NOT verify: wrong key, wrong message, or a corrupt signature (fail closed).", "bad"
   end if
end doVerifyPasted

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

-- ------------------------------------------------------------------ Schnorr tab actions
on handleSchnorr pRole
   if pRole is "go" then
      doSchnorrSign
   else if pRole is "verify" then
      doSchnorrVerify
   else if pRole is "tamper" then
      doSchnorrTamper
   end if
end handleSchnorr

on doSchnorrSign
   local tXonly
   local tHash
   local tOutKey
   local tAddr
   local tOut
   if haveKey("schn:status") is false then
      exit doSchnorrSign
   end if
   put field "schn:msg" into sSchnMsg
   put cxXonlyFromSeckey(sSeckey) into tXonly
   put cxSha256(cxdAscii(sSchnMsg)) into tHash
   -- empty aux_rand = the BIP-340 zero-aux default, so signing is deterministic
   put cxSchnorrSign(sSeckey, tHash, empty) into sSchnSig
   if cxIsError(tXonly) or cxIsError(sSchnSig) then
      cxdStatus "schn:status", "Schnorr signing failed; is the extension loaded?", "bad"
      exit doSchnorrSign
   end if
   -- the same key's Taproot life: tweak to the output key, frame as bc1p
   put cxTaprootOutputKey(tXonly) into tOutKey
   put cxBtcAddressP2TR(sPub33, true) into tAddr
   put "xonly    " & cxdHex(tXonly) & return into tOut
   put "digest   " & cxdHex(tHash) & return after tOut
   put "sig      " & cxdHex(sSchnSig) & return after tOut
   if cxIsError(tOutKey) is false and cxIsError(tAddr) is false then
      put "tweaked  " & cxdHex(tOutKey) && "(Q = P + hash(P)*G)" & return after tOut
      put "taproot  " & tAddr after tOut
   end if
   put tOut into field "schn:out"
   cxdStatus "schn:status", "Signed (BIP-340, deterministic). Sign again: the signature is IDENTICAL.", "ok"
end doSchnorrSign

on doSchnorrVerify
   local tHash
   if sSchnSig is empty then
      cxdStatus "schn:status", "Sign something first.", "bad"
      exit doSchnorrVerify
   end if
   put cxSha256(cxdAscii(sSchnMsg)) into tHash
   if cxSchnorrVerify(cxXonlyFromSeckey(sSeckey), tHash, sSchnSig) is true then
      cxdStatus "schn:status", "The Schnorr signature verifies under the x-only public key.", "ok"
   else
      cxdStatus "schn:status", "Signature did NOT verify (did the message change after signing?).", "bad"
   end if
end doSchnorrVerify

on doSchnorrTamper
   local tHash
   local tBad
   local tByte
   if sSchnSig is empty then
      cxdStatus "schn:status", "Sign something first.", "bad"
      exit doSchnorrTamper
   end if
   put cxSha256(cxdAscii(sSchnMsg)) into tHash
   -- flip one bit of the signature (the bitXor stays on its own line)
   put sSchnSig into tBad
   put byteToNum(byte 23 of tBad) into tByte
   put tByte bitXor 8 into tByte
   put numToByte(tByte) into byte 23 of tBad
   if cxSchnorrVerify(cxXonlyFromSeckey(sSeckey), tHash, tBad) is false then
      cxdStatus "schn:status", "One flipped bit and BIP-340 verification REJECTS it - fail closed, as with ECDSA.", "ok"
   else
      cxdStatus "schn:status", "A tampered signature verified - this must never happen.", "bad"
   end if
end doSchnorrTamper

-- ------------------------------------------------------------------ Ethereum tab actions
on handleEth pRole
   if pRole is "sign" then
      doEthSign
   else if pRole is "recover" then
      doRecover
   else if pRole is "tx" then
      doTxSign
   else if pRole is "typed" then
      doEip712
   end if
end handleEth

-- sign the EIP's own Mail example as typed data (EIP-712) with the CURRENT
-- key: domain separator, struct hashes, digest, recoverable signature - the
-- exact chain behind every wallet's signTypedData prompt. The self-test
-- pins the whole example against the EIP's published digest and signature.
on doEip712
   local tPerson
   local tMail
   local tDom
   local tCow
   local tBob
   local tMsg
   local tDigest
   local tSig
   local tOut
   if haveKey("eth:status") is false then
      exit doEip712
   end if
   put "Person(string name,address wallet)" into tPerson
   put "Mail(Person from,Person to,string contents)" & tPerson into tMail
   put cxEip712HashStruct("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)", \
      cxEip712WordHash(cxdAscii("Ether Mail")) & cxEip712WordHash(cxdAscii("1")) \
      & cxEip712WordUInt("1") & cxEip712WordAddress("0xCcCcccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")) into tDom
   put cxEip712HashStruct(tPerson, cxEip712WordHash(cxdAscii("Cow")) \
      & cxEip712WordAddress("0xCd2a3d9F938E13CD947Ec05AbC7fe734Df8DD826")) into tCow
   put cxEip712HashStruct(tPerson, cxEip712WordHash(cxdAscii("Bob")) \
      & cxEip712WordAddress("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")) into tBob
   put cxEip712HashStruct(tMail, tCow & tBob & cxEip712WordHash(cxdAscii("Hello, Bob!"))) into tMsg
   put cxEip712Digest(tDom, tMsg) into tDigest
   put cxSignRecoverable(sSeckey, tDigest) into tSig
   if cxIsError(tDigest) or cxIsError(tSig) then
      cxdStatus "eth:status", "Typed-data signing failed; is the extension loaded?", "bad"
      exit doEip712
   end if
   put "typed      Mail(from Cow, to Bob, contents Hello, Bob!) under domain Ether Mail" & return into tOut
   put "domainSep  " & cxdHex(tDom) & return after tOut
   put "structHash " & cxdHex(tMsg) & return after tOut
   put "digest     " & cxdHex(tDigest) && "(keccak of 0x19 0x01 || both)" & return after tOut
   put "r||s       " & cxdHex(byte 1 to 64 of tSig) & return after tOut
   put "v          " & (byteToNum(byte 65 of tSig) + 27) & return after tOut
   put "signer     " & cxEthAddress(sPub65) after tOut
   put tOut into field "eth:out"
   cxdStatus "eth:status", "The EIP-712 chain behind every signTypedData prompt (Permits, orders, votes). The self-test pins this exact example to the EIP's published signature.", "ok"
end doEip712

on doEthSign
   local tHash
   local tRecid
   local tOut
   if haveKey("eth:status") is false then
      exit doEthSign
   end if
   put field "eth:msg" into sEthMsg
   -- EIP-191: prefix + length + message, keccak-256 - exactly what a
   -- wallet's personal_sign hashes before signing recoverably
   put cxEthPersonalHash(cxdAscii(sEthMsg)) into tHash
   put cxSignRecoverable(sSeckey, tHash) into sEthSig
   if cxIsError(tHash) or cxIsError(sEthSig) then
      cxdStatus "eth:status", "Signing failed; is the extension loaded?", "bad"
      exit doEthSign
   end if
   put byteToNum(byte 65 of sEthSig) into tRecid
   put "digest   " & cxdHex(tHash) && "(EIP-191 prefixed)" & return into tOut
   put "r||s     " & cxdHex(byte 1 to 64 of sEthSig) & return after tOut
   put "v        " & tRecid && "raw =" && (tRecid + 27) && "in the classic 27/28 form" & return after tOut
   put "signer   " & cxEthAddress(sPub65) after tOut
   put tOut into field "eth:out"
   cxdStatus "eth:status", "personal_sign done. Now click Recover: the ADDRESS comes back from the signature alone.", "ok"
end doEthSign

on doRecover
   local tHash
   local tRec
   local tAddr
   if sEthSig is empty then
      cxdStatus "eth:status", "Sign a message first.", "bad"
      exit doRecover
   end if
   put cxEthPersonalHash(cxdAscii(sEthMsg)) into tHash
   put cxRecover(sEthSig, tHash) into tRec
   if cxIsError(tRec) then
      cxdStatus "eth:status", tRec, "bad"
      exit doRecover
   end if
   put cxEthAddress(tRec) into tAddr
   put field "eth:out" & return & "recovered" && tAddr into field "eth:out"
   if tAddr is cxEthAddress(sPub65) then
      cxdStatus "eth:status", "Recovered address MATCHES the signer: message + signature = proven identity.", "ok"
   else
      cxdStatus "eth:status", "Recovered address does not match - this must never happen.", "bad"
   end if
end doRecover

-- build and sign a complete EIP-155 legacy transaction, offline. The demo
-- fixes nonce 9, 20 gwei, 21000 gas, chain 1 (the shape of the official
-- EIP-155 example, which the self-test reproduces byte for byte) and takes
-- the to-address and wei value from the fields. This is the app-layer
-- composition CoinXT's rules require: the human-readable fields are ON
-- SCREEN (confirm-before-sign); the library only encodes, hashes, signs.
on doTxSign
   local tTo
   local tChecked
   local tToBytes
   local tValueRlp
   local tItems
   local tPreimage
   local tHash
   local tSig
   local tV
   local tRaw
   local tOut
   if haveKey("eth:status") is false then
      exit doTxSign
   end if
   put word 1 to -1 of field "eth:to" into tTo
   put cxEthAddressChecksum(tTo) into tChecked
   if cxIsError(tChecked) then
      cxdStatus "eth:status", tChecked, "bad"
      exit doTxSign
   end if
   -- fail closed on a WRONG mixed-case checksum (single-case carries none);
   -- the case comparison must be exact, so caseSensitive goes on (local)
   set the caseSensitive to true
   if tTo is not tChecked and tTo is not toLower(tTo) and tTo is not toUpper(tTo) then
      cxdStatus "eth:status", "The to-address fails its EIP-55 checksum - not signing.", "bad"
      exit doTxSign
   end if
   put cxHexDecode(char 3 to -1 of toLower(tTo)) into tToBytes
   put cxRlpUIntDec(word 1 to -1 of field "eth:value") into tValueRlp
   if cxIsError(tToBytes) or cxIsError(tValueRlp) then
      cxdStatus "eth:status", "The value must be a plain decimal wei amount.", "bad"
      exit doTxSign
   end if
   -- the six body fields, each RLP-encoded, concatenated in tx order
   put cxRlpUIntDec("9") & cxRlpUIntDec("20000000000") & cxRlpUIntDec("21000") \
      & cxRlpBytes(tToBytes) & tValueRlp & cxRlpBytes(empty) into tItems
   -- EIP-155 preimage: body + (chainId, 0, 0); its keccak is what gets signed
   put cxRlpList(tItems & cxRlpUIntDec("1") & cxRlpUIntDec("0") & cxRlpUIntDec("0")) into tPreimage
   put cxKeccak256(tPreimage) into tHash
   put cxSignRecoverable(sSeckey, tHash) into tSig
   if cxIsError(tSig) then
      cxdStatus "eth:status", tSig, "bad"
      exit doTxSign
   end if
   put 35 + 2 + byteToNum(byte 65 of tSig) into tV
   put cxRlpList(tItems & cxRlpUIntDec(tV) & cxRlpUIntBytes(byte 1 to 32 of tSig) \
      & cxRlpUIntBytes(byte 33 to 64 of tSig)) into tRaw
   put "sighash  " & cxdHex(tHash) && "(keccak of the RLP preimage)" & return into tOut
   put "v        " & tV && "(35 + 2*chainId + recid: EIP-155 replay protection)" & return after tOut
   put "r||s     " & cxdHex(byte 1 to 64 of tSig) & return after tOut
   put "raw tx   0x" & cxdHex(tRaw) after tOut
   put tOut into field "eth:out"
   cxdStatus "eth:status", "A broadcast-shaped signed transaction, built entirely offline. NEVER broadcast a demo key's transaction.", "ok"
end doTxSign

-- ------------------------------------------------------------------ BTC Tx tab actions
on handleBtx pRole
   if pRole is "go" then
      doBtxSign
   else if pRole is "example" then
      doBtxExample
   else if pRole is "nested" then
      doBtxToggle
   end if
end handleBtx

on doBtxToggle
   put (sBtxNested is not true) into sBtxNested
   if sBtxNested then
      set the label of button "btx:nested" to "Input: nested (BIP-49)"
   else
      set the label of button "btx:nested" to "Input: native (bc1q)"
   end if
end doBtxToggle

-- load every field of the OFFICIAL BIP-143 P2SH-P2WPKH example, including
-- its (published, PUBLIC) key, so Sign reproduces the BIP's raw tx exactly
on doBtxExample
   put true into sBtxNested
   set the label of button "btx:nested" to "Input: nested (BIP-49)"
   put "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb" into field "btx:txid"
   put 1 into field "btx:vout"
   put 1000000000 into field "btx:amt"
   put "199996600 1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7" & return & \
      "800000000 1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8" into field "btx:outs"
   put 1 into field "btx:ver"
   put 4294967294 into field "btx:seq"
   put 1170 into field "btx:lock"
   adoptSeckey cxdBin("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"), \
      "BIP-143 example key adopted (PUBLIC - printed in the BIP; never fund it)."
   cxdStatus "btx:status", "Official example loaded (key included). Sign now: the raw bytes must equal the transaction printed in BIP-143.", "ok"
end doBtxExample

-- the confirm-before-sign flow: parse the on-screen fields, show the fee,
-- and let the library fail closed on anything malformed
on doBtxSign
   local tOuts
   local tLine
   local tTotal
   local tFee
   local tRes
   local tOut
   if haveKey("btx:status") is false then
      exit doBtxSign
   end if
   -- total the outputs here so the FEE is on screen next to the result
   put 0 into tTotal
   repeat for each line tLine in field "btx:outs"
      if tLine is empty then
         next repeat
      end if
      if word 1 of tLine is not an integer then
         cxdStatus "btx:status", "Each output line is: amountSats address", "bad"
         exit doBtxSign
      end if
      add word 1 of tLine to tTotal
   end repeat
   put cxBtcTxSignP2WPKH(sSeckey, word 1 to -1 of field "btx:txid", \
      word 1 to -1 of field "btx:vout", word 1 to -1 of field "btx:amt", \
      field "btx:outs", sBtxNested is true, word 1 to -1 of field "btx:ver", \
      word 1 to -1 of field "btx:seq", word 1 to -1 of field "btx:lock") into tRes
   if cxIsError(tRes) then
      put tRes into field "btx:out"
      cxdStatus "btx:status", "Refused to sign (fail closed) - fix the field the error names.", "bad"
      exit doBtxSign
   end if
   put (word 1 to -1 of field "btx:amt") - tTotal into tFee
   put "txid     " & line 1 of tRes & return into tOut
   put "sighash  " & line 2 of tRes && "(BIP-143, SIGHASH_ALL)" & return after tOut
   put "fee      " & tFee && "sats (input minus outputs - always review this)" & return after tOut
   put "raw tx   " & cxHexEncode(line 3 to -1 of tRes) after tOut
   put tOut into field "btx:out"
   cxdStatus "btx:status", "Signed offline: paste the raw tx into any decoder to inspect it. NEVER broadcast a demo transaction.", "ok"
end doBtxSign

-- ------------------------------------------------------------------ PSBT tab actions
on handlePsbt pRole
   if pRole is "dec" then
      doPsbtDecode
   else if pRole is "signhd" then
      doPsbtSign "hd"
   else if pRole is "signkey" then
      doPsbtSign "key"
   else if pRole is "final" then
      doPsbtFinal
   end if
end handlePsbt

on doPsbtDecode
   local tRes
   put cxPsbtDecode(field "psbt:in") into tRes
   put tRes into field "psbt:out"
   if cxIsError(tRes) then
      cxdStatus "psbt:status", "Rejected (fail closed): not a decodable PSBT.", "bad"
   else
      cxdStatus "psbt:status", "This is what the transaction PAYS. Only sign it if every line is what you intend.", "ok"
   end if
end doPsbtDecode

-- sign with the Keys-tab key ("key") or by walking the PSBT's BIP32 paths
-- from the Wallet tab's phrase ("hd", the air-gapped hardware-wallet flow)
on doPsbtSign pMode
   local tMnem
   local tMaster
   local tNew
   if pMode is "key" then
      if haveKey("psbt:status") is false then
         exit doPsbtSign
      end if
      put cxPsbtSign(field "psbt:in", sSeckey) into tNew
   else
      put word 1 to -1 of field "seed:mnem" into tMnem
      if cxMnemonicValidate(tMnem) is false then
         cxdStatus "psbt:status", "The Wallet tab's seed phrase does not validate - fix it there first.", "bad"
         exit doPsbtSign
      end if
      put cxHdFromSeed(cxMnemonicToSeed(tMnem, field "seed:pp")) into tMaster
      put cxPsbtSign(field "psbt:in", tMaster) into tNew
      put empty into tMaster
   end if
   if cxIsError(tNew) then
      put tNew into field "psbt:out"
      cxdStatus "psbt:status", "Refused to sign (fail closed).", "bad"
      exit doPsbtSign
   end if
   -- chain the flow: the signed PSBT replaces the input, the report shows it
   put tNew into field "psbt:in"
   put cxPsbtDecode(tNew) into field "psbt:out"
   cxdStatus "psbt:status", "Signed every input this key controls (the sig counts above show which). Pass the PSBT back to the wallet, or Finalize here.", "ok"
end doPsbtSign

on doPsbtFinal
   local tRes
   local tOut
   put cxPsbtFinalize(field "psbt:in") into tRes
   if cxIsError(tRes) then
      put tRes into field "psbt:out"
      cxdStatus "psbt:status", "Not finalizable yet - the error names the input and why.", "bad"
      exit doPsbtFinal
   end if
   put "txid     " & line 1 of tRes & return into tOut
   put "raw tx   " & cxHexEncode(line 2 to -1 of tRes) after tOut
   put tOut into field "psbt:out"
   cxdStatus "psbt:status", "Broadcast-ready bytes, built entirely offline. NEVER broadcast a demo transaction.", "ok"
end doPsbtFinal

-- ------------------------------------------------------------------ ECDH tab actions
on handleEcdh pRole
   if pRole is "go" then
      doEcdh
   else if pRole is "mine" then
      doEcdhMine
   end if
end handleEcdh

-- the paste-your-own flow: YOUR key (Keys tab) x a pasted peer pubkey
on doEcdhMine
   local tPeerHex
   local tPeer
   local tShared
   if haveKey("ecdh:status") is false then
      exit doEcdhMine
   end if
   put word 1 to -1 of field "ecdh:peer" into tPeerHex
   put cxHexDecode(tPeerHex) into tPeer
   if cxIsError(tPeer) or (the number of bytes in tPeer is not 33 and the number of bytes in tPeer is not 65) then
      cxdStatus "ecdh:status", "Paste a 33- or 65-byte public key as hex (66 or 130 characters).", "bad"
      exit doEcdhMine
   end if
   put cxEcdh(sSeckey, tPeer) into tShared
   if cxIsError(tShared) then
      cxdStatus "ecdh:status", tShared, "bad"
      exit doEcdhMine
   end if
   put "my key x pasted pubkey:" & return & "shared  " & cxdHex(tShared) into field "ecdh:out"
   cxdStatus "ecdh:status", "The peer computes the SAME 32 bytes from THEIR key and YOUR pubkey (Keys tab, Copy pubkey).", "ok"
end doEcdhMine

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
   -- a 0x prefix means "hash these raw BYTES", so vectors from other tools
   -- can be checked exactly; anything else is hashed as UTF-8 text
   if char 1 to 2 of field "hash:msg" is "0x" then
      put cxHexDecode(char 3 to -1 of word 1 to -1 of field "hash:msg") into tIn
      if cxIsError(tIn) then
         cxdStatus "hash:status", "Not valid hex after the 0x prefix.", "bad"
         exit doHashAll
      end if
   else
      put cxdAscii(field "hash:msg") into tIn
   end if
   put "keccak256  " & cxdHex(cxKeccak256(tIn)) & return into tOut
   put "sha3-256   " & cxdHex(cxSha3_256(tIn)) & return after tOut
   put "           ^ same input, ONE padding byte apart: never alias these two" & return after tOut
   put "sha256     " & cxdHex(cxSha256(tIn)) & return after tOut
   put "sha512     " & cxdHex(cxSha512(tIn)) & return after tOut
   put "ripemd160  " & cxdHex(cxRipemd160(tIn)) & return after tOut
   put "hash160    " & cxdHex(cxHash160(tIn)) && "(a Bitcoin address hashes this)" & return after tOut
   put "hash256    " & cxdHex(cxHash256(tIn)) && "(txids, Base58Check checksums)" & return after tOut
   put "hmac256    " & cxdHex(cxHmacSha256(cxdAscii("demo-key"), tIn)) && "(keyed MAC, key = demo-key)" & return after tOut
   put "hmac512    " & cxdHex(cxHmacSha512(cxdAscii("demo-key"), tIn)) && "(BIP-32 derives with this)" after tOut
   put tOut into field "hash:out"
   cxdStatus "hash:status", "Notice how keccak256 and sha3-256 differ completely.", "ok"
end doHashAll

-- ------------------------------------------------------------------ Wallet (restore / generate) tab actions
on handleSeed pRole
   if pRole is "restore" then
      doRestore
   else if pRole is "gen12" then
      doGenerate 16
   else if pRole is "gen24" then
      doGenerate 32
   else if pRole is "derive" then
      doDerivePath
   end if
end handleSeed

-- the path explorer: derive ANY typed path from the phrase above and show
-- everything that node is - every address form, the pubkey, WIF, xprv/xpub.
-- Rederives from the phrase each click, so no master node lingers in state.
on doDerivePath
   local tMnem
   local tPath
   local tSeed
   local tMaster
   local tNode
   local tKey
   local tPub
   local tOut
   put word 1 to -1 of field "seed:mnem" into tMnem
   if cxMnemonicValidate(tMnem) is false then
      cxdStatus "seed:status", "Fix the seed phrase first (its checksum does not validate).", "bad"
      exit doDerivePath
   end if
   put word 1 to -1 of field "seed:path" into tPath
   put cxMnemonicToSeed(tMnem, field "seed:pp") into tSeed
   put cxHdFromSeed(tSeed) into tMaster
   put empty into tSeed
   if cxIsError(tMaster) then
      cxdStatus "seed:status", tMaster, "bad"
      exit doDerivePath
   end if
   put cxHdDerivePath(tMaster, tPath) into tNode
   put empty into tMaster
   if cxIsError(tNode) then
      put tNode into field "seed:out"
      cxdStatus "seed:status", "Bad path: use m/44'/0'/0'/0/0 shapes (' or h marks a hardened step).", "bad"
      exit doDerivePath
   end if
   put cxHdPubkey(tNode) into tPub
   put "path       " & tPath & return & return into tOut
   put "legacy     " & cxBtcAddressP2PKH(tPub, true) & return after tOut
   put "nested     " & cxBtcAddressP2SH_P2WPKH(tPub, true) & return after tOut
   put "segwit     " & cxBtcAddressP2WPKH(tPub, true) & return after tOut
   put "taproot    " & cxBtcAddressP2TR(tPub, true) & return after tOut
   put "ethereum   " & cxEthAddress(tPub) & return & return after tOut
   put "pubkey     " & cxdHex(tPub) & return after tOut
   put cxHdSeckey(tNode) into tKey
   put "wif        " & cxWifEncode(tKey, true, true) && "(SECRET in real life)" & return after tOut
   put empty into tKey
   put "xprv       " & cxXprv(tNode, true) & return after tOut
   put "xpub       " & cxXpub(tNode, true) after tOut
   put empty into tNode
   put tOut into field "seed:out"
   cxdStatus "seed:status", "One node, every identity it has. Compare any line against another wallet's export.", "ok"
end doDerivePath

-- make a fresh phrase (12 words from 16 entropy bytes, 24 from 32), put it
-- in the phrase field, and run the SAME restore path a typed phrase takes
on doGenerate pEntropyBytes
   local tEntropy
   local tErr
   local tMnem
   -- entropy: SodiumXT if present, else a fixed DEMO value (so a machine
   -- without SodiumXT still runs, loudly non-random)
   try
      put sxRandomBytes(pEntropyBytes) into tEntropy
   catch tErr
      put byte 1 to pEntropyBytes of \
         cxSha512(cxdAscii("coinxt demo seed entropy")) into tEntropy
   end try
   put cxMnemonicFromEntropy(tEntropy) into tMnem
   put empty into tEntropy
   if cxIsError(tMnem) then
      cxdStatus "seed:status", tMnem, "bad"
      exit doGenerate
   end if
   put tMnem into field "seed:mnem"
   doRestore
end doGenerate

-- the headline flow: whatever phrase is in the field - typed, pasted, or
-- generated - is validated (fail closed on a bad checksum) and expanded into
-- the whole wallet: seed, the first address of EVERY standard account type,
-- the watch-only account xpub, and the first key's WIF
on doRestore
   local tMnem
   local tPass
   local tSeed
   local tMaster
   local tNode
   local tChain
   local tI
   local tKey
   local tOut
   put word 1 to -1 of field "seed:mnem" into tMnem
   if tMnem is empty then
      cxdStatus "seed:status", "Type, paste, or generate a seed phrase first.", "bad"
      exit doRestore
   end if
   -- the checksum gate: the last word ties the whole phrase together, so a
   -- typo (or a made-up phrase) is REJECTED here, not turned into a wallet
   if cxMnemonicValidate(tMnem) is false then
      put "checksum   INVALID - phrase rejected (fail closed)" into field "seed:out"
      cxdStatus "seed:status", "Not a valid BIP-39 phrase: a word is wrong, missing, or the checksum fails.", "bad"
      exit doRestore
   end if
   put field "seed:pp" into tPass
   put cxMnemonicToSeed(tMnem, tPass) into tSeed
   if cxIsError(tSeed) then
      cxdStatus "seed:status", tSeed, "bad"
      exit doRestore
   end if
   put cxHdFromSeed(tSeed) into tMaster
   if cxIsError(tMaster) then
      cxdStatus "seed:status", tMaster, "bad"
      exit doRestore
   end if
   put "checksum   valid (" & the number of words of tMnem & " words)" & return into tOut
   put "seed       " & cxdHex(tSeed) & return & return after tOut
   -- the first receiving address of every standard account type; against the
   -- canonical test phrase these match the published BIP-84/86 vectors and
   -- what any mainstream wallet derives
   put cxHdDerivePath(tMaster, "m/44'/0'/0'/0/0") into tNode
   if not cxIsError(tNode) then
      put "legacy  #0 " & cxBtcAddressP2PKH(cxHdPubkey(tNode), true) & \
         "  (m/44'/0'/0'/0/0)" & return after tOut
   end if
   put cxHdDerivePath(tMaster, "m/49'/0'/0'/0/0") into tNode
   if not cxIsError(tNode) then
      put "nested  #0 " & cxBtcAddressP2SH_P2WPKH(cxHdPubkey(tNode), true) & \
         "  (m/49'/0'/0'/0/0)" & return after tOut
   end if
   put cxHdDerivePath(tMaster, "m/84'/0'/0'/0/0") into tNode
   if not cxIsError(tNode) then
      put "segwit  #0 " & cxBtcAddressP2WPKH(cxHdPubkey(tNode), true) & \
         "  (m/84'/0'/0'/0/0)" & return after tOut
      -- the single-key escape hatch: this one key, importable anywhere
      put cxHdSeckey(tNode) into tKey
      put "  its WIF  " & cxWifEncode(tKey, true, true) & \
         "  (import just this key into any wallet)" & return after tOut
      put empty into tKey
   end if
   put cxHdDerivePath(tMaster, "m/86'/0'/0'/0/0") into tNode
   if not cxIsError(tNode) then
      put "taproot #0 " & cxBtcAddressP2TR(cxHdPubkey(tNode), true) & \
         "  (m/86'/0'/0'/0/0)" & return after tOut
   end if
   put cxHdDerivePath(tMaster, "m/44'/60'/0'/0/0") into tNode
   if not cxIsError(tNode) then
      put "eth     #0 " & cxEthAddress(cxHdPubkey(tNode)) & \
         "  (m/44'/60'/0'/0/0)" & return & return after tOut
   end if
   -- the account-level serializations (BIP-84 account): the watch-only xpub
   -- and, because demo phrases are public anyway, the xprv with its warning
   put cxHdDerivePath(tMaster, "m/84'/0'/0'") into tNode
   if not cxIsError(tNode) then
      put "acct xpub  " & cxXpub(tNode, true) & return & \
         "           (m/84'/0'/0' - watch-only: derives addresses, signs nothing)" & return after tOut
      put "acct xprv  " & cxXprv(tNode, true) & return & \
         "           (SECRET in real life: spends everything below the account)" & return after tOut
   end if
   -- the fidelity check: ten receiving addresses and the first change
   -- address, each from ONE cached chain node (a single cxHdDerive step per
   -- index). Restore the same phrase in any mainstream wallet and the whole
   -- list must match, address for address.
   put cxHdDerivePath(tMaster, "m/84'/0'/0'/0") into tChain
   if not cxIsError(tChain) then
      put return & "segwit receive #0..#9 (m/84'/0'/0'/0/i) - compare in any wallet:" & return after tOut
      repeat with tI = 0 to 9
         put cxHdDerive(tChain, tI, false) into tNode
         if cxIsError(tNode) then
            exit repeat
         end if
         put "  #" & tI & "  " & cxBtcAddressP2WPKH(cxHdPubkey(tNode), true) & return after tOut
      end repeat
   end if
   put cxHdDerivePath(tMaster, "m/84'/0'/0'/1/0") into tNode
   if not cxIsError(tNode) then
      put "  change #0  " & cxBtcAddressP2WPKH(cxHdPubkey(tNode), true) & \
         "  (m/84'/0'/0'/1/0)" & return after tOut
   end if
   put cxHdDerivePath(tMaster, "m/44'/60'/0'/0") into tChain
   if not cxIsError(tChain) then
      put return & "eth accounts #0..#9 (m/44'/60'/0'/0/i) - compare in any wallet:" & return after tOut
      repeat with tI = 0 to 9
         put cxHdDerive(tChain, tI, false) into tNode
         if cxIsError(tNode) then
            exit repeat
         end if
         put "  #" & tI & "  " & cxEthAddress(cxHdPubkey(tNode)) & return after tOut
      end repeat
   end if
   put tOut into field "seed:out"
   -- clear every secret we touched (seed and nodes carry private keys)
   put empty into tSeed
   put empty into tMaster
   put empty into tNode
   put empty into tChain
   cxdStatus "seed:status", "Wallet restored: every standard account, plus ten addresses per chain to verify fidelity against any wallet. Demo phrases are PUBLIC - never fund them.", "ok"
end doRestore

-- ------------------------------------------------------------------ Tools tab actions
on handleTool pRole
   if pRole is "profile" then
      doToolProfile
   else if pRole is "save" then
      doToolSave
   else if pRole is "load" then
      doToolLoad
   else if pRole is "scan" then
      doToolScan
   else if pRole is "qrgo" then
      doToolQr
   end if
end handleTool

-- render the file box as a QR code for air-gap transfer (a PSBT or profile
-- crosses to a phone / another machine without a wire). The ENGINE's
-- qrCreate library does the encoding - CoinXT rolls no QR of its own, the
-- compose-audited-code rule - and a build without the library degrades to a
-- clean message inside the try/catch (the SodiumXT capability-gate pattern).
on doToolQr
   local tErr
   local tText
   put field "tool:io" into tText
   if tText is empty then
      cxdStatus "tool:status", "Nothing to encode: build a profile or load a file into the file box first.", "bad"
      exit doToolQr
   end if
   try
      qrCreate the long id of image "tool:qr", tText, "M", 3
      cxdStatus "tool:status", "Scan it with any wallet or phone. QR is how a PSBT crosses an air gap without a cable.", "ok"
   catch tErr
      cxdStatus "tool:status", "This engine build has no qrCreate library - showing nothing rather than a wrong code.", "bad"
   end try
end doToolQr

-- a master node from the Wallet tab's phrase, or empty (status already set)
private function cxdToolMaster
   local tMnem
   local tMaster
   put word 1 to -1 of field "seed:mnem" into tMnem
   if cxMnemonicValidate(tMnem) is false then
      cxdStatus "tool:status", "The Wallet tab's seed phrase does not validate - fix it there first.", "bad"
      return empty
   end if
   put cxHdFromSeed(cxMnemonicToSeed(tMnem, field "seed:pp")) into tMaster
   if cxIsError(tMaster) then
      cxdStatus "tool:status", tMaster, "bad"
      return empty
   end if
   return tMaster
end cxdToolMaster

-- the WATCH-ONLY profile: fingerprint + every account xpub + first
-- addresses. No private material: safe to store and share with a
-- coordinator; it can derive receiving addresses but sign nothing.
on doToolProfile
   local tMaster
   local tAcct
   local tLeaf
   local tOut
   put cxdToolMaster() into tMaster
   if tMaster is empty then
      exit doToolProfile
   end if
   put "CoinXT watch-only profile v1" & return into tOut
   put "fingerprint " & cxHexEncode(byte 1 to 4 of cxHash160(cxHdPubkey(tMaster))) & return after tOut
   put cxHdDerivePath(tMaster, "m/44'/0'/0'") into tAcct
   put "xpub44  " & cxXpub(tAcct, true) & return after tOut
   put cxHdDerivePath(tMaster, "m/49'/0'/0'") into tAcct
   put "xpub49  " & cxXpub(tAcct, true) & return after tOut
   put cxHdDerivePath(tMaster, "m/84'/0'/0'") into tAcct
   put "xpub84  " & cxXpub(tAcct, true) & return after tOut
   put cxHdDerivePath(tMaster, "m/86'/0'/0'") into tAcct
   put "xpub86  " & cxXpub(tAcct, true) & return after tOut
   put cxHdDerivePath(tMaster, "m/44'/60'/0'") into tAcct
   put "xpubEth " & cxXpub(tAcct, true) & return after tOut
   put cxHdDerivePath(tMaster, "m/84'/0'/0'/0/0") into tLeaf
   put "addr84-0 " & cxBtcAddressP2WPKH(cxHdPubkey(tLeaf), true) & return after tOut
   put cxHdDerivePath(tMaster, "m/44'/60'/0'/0/0") into tLeaf
   put "addrEth-0 " & cxEthAddress(cxHdPubkey(tLeaf)) after tOut
   put empty into tMaster
   put empty into tAcct
   put empty into tLeaf
   put tOut into field "tool:io"
   cxdStatus "tool:status", "Watch-only profile built (NO private material). Save it to a file, or hand it to a coordinator.", "ok"
end doToolProfile

on doToolSave
   ask file "Save the file box as" with "coinxt-export.txt"
   if it is empty then
      cxdStatus "tool:status", "Save cancelled.", "bad"
      exit doToolSave
   end if
   put field "tool:io" into URL ("file:" & it)
   cxdStatus "tool:status", "Saved. Files are the app's job (SPEC rule 2); CoinXT itself stores nothing.", "ok"
end doToolSave

on doToolLoad
   answer file "Choose a file to load into the file box"
   if it is empty then
      cxdStatus "tool:status", "Load cancelled.", "bad"
      exit doToolLoad
   end if
   put URL ("file:" & it) into field "tool:io"
   cxdStatus "tool:status", "Loaded. Copy a PSBT to the PSBT tab, a raw tx to Decode, or read a profile here.", "ok"
end doToolLoad

-- the address-swap defence: derive the first 20 receive + change addresses
-- of EVERY standard chain from the phrase and look for the pasted address.
-- Fund an address only when this says MINE with the path you expect.
on doToolScan
   local tTarget
   local tMaster
   local tPaths
   local tPathLine
   local tChainIdx
   local tChain
   local tI
   local tNode
   local tAddr
   local tFound
   put word 1 to -1 of field "tool:addr" into tTarget
   if tTarget is empty then
      cxdStatus "tool:status", "Paste an address to look for first.", "bad"
      exit doToolScan
   end if
   put cxdToolMaster() into tMaster
   if tMaster is empty then
      exit doToolScan
   end if
   put "m/44'/0'/0',legacy" & return & "m/49'/0'/0',nested" & return \
      & "m/84'/0'/0',segwit" & return & "m/86'/0'/0',taproot" & return \
      & "m/44'/60'/0',eth" into tPaths
   put empty into tFound
   repeat for each line tPathLine in tPaths
      repeat with tChainIdx = 0 to 1
         put cxHdDerivePath(tMaster, item 1 of tPathLine & "/" & tChainIdx) into tChain
         if cxIsError(tChain) then
            next repeat
         end if
         repeat with tI = 0 to 19
            put cxHdDerive(tChain, tI, false) into tNode
            if item 2 of tPathLine is "legacy" then
               put cxBtcAddressP2PKH(cxHdPubkey(tNode), true) into tAddr
            else if item 2 of tPathLine is "nested" then
               put cxBtcAddressP2SH_P2WPKH(cxHdPubkey(tNode), true) into tAddr
            else if item 2 of tPathLine is "segwit" then
               put cxBtcAddressP2WPKH(cxHdPubkey(tNode), true) into tAddr
            else if item 2 of tPathLine is "taproot" then
               put cxBtcAddressP2TR(cxHdPubkey(tNode), true) into tAddr
            else
               put cxEthAddress(cxHdPubkey(tNode)) into tAddr
            end if
            -- ETH compares case-folded (EIP-55 is presentation); BTC exact
            if tAddr is tTarget or (item 2 of tPathLine is "eth" and toLower(tAddr) is toLower(tTarget)) then
               put item 1 of tPathLine & "/" & tChainIdx & "/" & tI into tFound
               exit repeat
            end if
         end repeat
         if tFound is not empty then
            exit repeat
         end if
      end repeat
      if tFound is not empty then
         exit repeat
      end if
   end repeat
   put empty into tMaster
   put empty into tChain
   put empty into tNode
   if tFound is empty then
      put "NOT MINE (searched receive+change 0..19 of m/44'/49'/84'/86' and eth)" & return & "address: " & tTarget into field "tool:out"
      cxdStatus "tool:status", "NOT found in this wallet's standard chains. Do NOT fund it assuming it is yours - this is how address-swap malware wins.", "bad"
   else
      put "MINE at " & tFound & return & "address: " & tTarget into field "tool:out"
      cxdStatus "tool:status", "Verified: this wallet derives that address at " & tFound & " (chain 0 = receive, 1 = change).", "ok"
   end if
end doToolScan

-- ------------------------------------------------------------------ Online tab actions
on handleOnline pRole
   if pRole is "balance" then
      doOnlineBalance
   else if pRole is "utxos" then
      doOnlineUtxos
   else if pRole is "net" then
      doOnlineNet
   else if pRole is "broadcast" then
      doOnlineBroadcast
   end if
end handleOnline

-- the online module is optional and separate: wrap every cxo* call in
-- try/catch so a build without it degrades to a clear message (the SodiumXT
-- capability-gate pattern), never an uncaught engine error.
private function cxdOnlineReady
   local tErr
   try
      get cxoEndpoint()
      return true
   catch tErr
      cxdStatus "online:status", "The coinxt-online module is not loaded (it is optional; start using it to enable this tab).", "bad"
      return false
   end try
end cxdOnlineReady

on doOnlineNet
   local tErr
   if cxdOnlineReady() is false then
      exit doOnlineNet
   end if
   try
      if the label of button "online:net" contains "testnet" then
         cxoSetEndpoint "https://blockstream.info/api"
         set the label of button "online:net" to "Network: mainnet"
         put "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" into field "online:addr"
         cxdStatus "online:status", "MAINNET endpoint. Queries now touch real balances - and leak the address to the explorer.", "bad"
      else
         cxoSetEndpoint "https://blockstream.info/testnet/api"
         set the label of button "online:net" to "Network: testnet"
         put "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" into field "online:addr"
         cxdStatus "online:status", "Back to the testnet explorer.", "ok"
      end if
   catch tErr
      cxdStatus "online:status", "Could not set the endpoint.", "bad"
   end try
end doOnlineNet

on doOnlineBalance
   local tErr
   local tBal
   if cxdOnlineReady() is false then
      exit doOnlineBalance
   end if
   try
      put cxoBalance(word 1 to -1 of field "online:addr") into tBal
   catch tErr
      cxdStatus "online:status", "The online module raised an error.", "bad"
      exit doOnlineBalance
   end try
   if cxoIsError(tBal) then
      put tBal into field "online:out"
      cxdStatus "online:status", "Lookup failed (network, or the explorer returned something unparseable - fail closed).", "bad"
      exit doOnlineBalance
   end if
   put "address   " & (word 1 to -1 of field "online:addr") & return \
      & "balance   " & tBal & " sats  (" & (tBal / 100000000) & " BTC), confirmed" into field "online:out"
   cxdStatus "online:status", "Confirmed balance read live. This told the explorer the address is one you care about.", "ok"
end doOnlineBalance

on doOnlineUtxos
   local tErr
   local tUtxos
   local tLine
   local tOut
   if cxdOnlineReady() is false then
      exit doOnlineUtxos
   end if
   try
      put cxoUtxos(word 1 to -1 of field "online:addr") into tUtxos
   catch tErr
      cxdStatus "online:status", "The online module raised an error.", "bad"
      exit doOnlineUtxos
   end try
   if cxoIsError(tUtxos) then
      put tUtxos into field "online:out"
      cxdStatus "online:status", "Lookup failed (fail closed on a bad response).", "bad"
      exit doOnlineUtxos
   end if
   if tUtxos is empty then
      put "No UTXOs at this address (nothing to spend)." into field "online:out"
      cxdStatus "online:status", "No unspent outputs found.", "ok"
      exit doOnlineUtxos
   end if
   put "txid                                                              vout  sats        confirmed" & return into tOut
   repeat for each line tLine in tUtxos
      put word 1 of tLine && word 2 of tLine && word 3 of tLine && word 4 of tLine & return after tOut
   end repeat
   put tOut into field "online:out"
   cxdStatus "online:status", "These are the exact outpoints the BTC Tx tab needs to build a spend (txid + vout + amount).", "ok"
end doOnlineUtxos

on doOnlineBroadcast
   local tErr
   local tRes
   if cxdOnlineReady() is false then
      exit doOnlineBroadcast
   end if
   if word 1 to -1 of field "online:tx" is empty then
      cxdStatus "online:status", "Paste a signed raw transaction (from BTC Tx or PSBT) to broadcast.", "bad"
      exit doOnlineBroadcast
   end if
   try
      put cxoBroadcast(word 1 to -1 of field "online:tx") into tRes
   catch tErr
      cxdStatus "online:status", "The online module raised an error.", "bad"
      exit doOnlineBroadcast
   end try
   if cxoIsError(tRes) then
      put tRes into field "online:out"
      cxdStatus "online:status", "Broadcast rejected (the node's reason is shown) - fail closed.", "bad"
      exit doOnlineBroadcast
   end if
   put "BROADCAST OK" & return & "txid  " & tRes into field "online:out"
   cxdStatus "online:status", "Accepted by the network. On mainnet this is irreversible - only ever broadcast a tx you built and reviewed.", "ok"
end doOnlineBroadcast

-- ------------------------------------------------------------------ Decode tab actions
on handleDecode pRole
   if pRole is "go" then
      doDecode
   end if
end handleDecode

-- dispatch on shape: 0x... is Ethereum, bc1/tb1 is Bech32, anything else is
-- tried as Base58Check. Every branch VERIFIES a checksum before showing a
-- single decoded byte, and a failure paints the rejection, not a guess.
on doDecode
   local tIn
   local tPfx
   put word 1 to -1 of field "dec:in" into tIn
   if tIn is empty then
      cxdStatus "dec:status", "Paste something to decode first.", "bad"
      exit doDecode
   end if
   put toLower(char 1 to 3 of tIn) into tPfx
   if char 1 to 2 of tIn is "0x" then
      doDecodeEth tIn
   else if tPfx is "bc1" or tPfx is "tb1" then
      doDecodeBech32 tIn
   else
      doDecodeBase58 tIn
   end if
end doDecode

private command doDecodeEth pIn
   local tChecksummed
   local tBody
   local tOut
   put cxEthAddressChecksum(pIn) into tChecksummed
   if cxIsError(tChecksummed) then
      put tChecksummed into field "dec:out"
      cxdStatus "dec:status", "Rejected: not an Ethereum address (fail closed).", "bad"
      exit doDecodeEth
   end if
   put "type       Ethereum address (20 bytes)" & return into tOut
   put "EIP-55     " & tChecksummed & return after tOut
   -- the case comparison below IS the checksum check, so it must be
   -- case-exact; caseSensitive defaults to false (local, reverts on exit)
   set the caseSensitive to true
   put char 3 to -1 of pIn into tBody
   if pIn is tChecksummed then
      put "checksum   the mixed case matches EIP-55 exactly" after tOut
      put tOut into field "dec:out"
      cxdStatus "dec:status", "Valid: the EIP-55 mixed-case checksum protects every hex digit.", "ok"
   else if tBody is toLower(tBody) or tBody is toUpper(tBody) then
      put "checksum   single-case input: legal, but carries NO checksum" after tOut
      put tOut into field "dec:out"
      cxdStatus "dec:status", "Valid hex, but unprotected: use the EIP-55 form above when sharing.", "ok"
   else
      put "checksum   MIXED CASE DOES NOT MATCH EIP-55 - rejected" after tOut
      put tOut into field "dec:out"
      cxdStatus "dec:status", "EIP-55 checksum MISMATCH: at least one character is wrong. Rejected.", "bad"
   end if
end doDecodeEth

private command doDecodeBech32 pIn
   local tDec
   local tHrp
   local tVer
   local tProg
   local tKind
   local tNet
   local tOut
   put cxBech32Decode(pIn) into tDec
   if cxIsError(tDec) then
      put tDec into field "dec:out"
      cxdStatus "dec:status", "Rejected (fail closed) - a corrupt address never decodes to plausible bytes.", "bad"
      exit doDecodeBech32
   end if
   put line 1 of tDec into tHrp
   put line 2 of tDec into tVer
   put line 3 to -1 of tDec into tProg
   if tHrp is "bc" then
      put "Bitcoin mainnet" into tNet
   else if tHrp is "tb" then
      put "Bitcoin testnet" into tNet
   else
      put "prefix" && quote & tHrp & quote into tNet
   end if
   if tVer is 0 and the number of bytes in tProg is 20 then
      put "SegWit P2WPKH (pays a pubkey hash, Bech32)" into tKind
   else if tVer is 0 and the number of bytes in tProg is 32 then
      put "SegWit P2WSH (pays a script hash, Bech32)" into tKind
   else if tVer is 1 and the number of bytes in tProg is 32 then
      put "Taproot P2TR (pays a tweaked x-only key, Bech32m)" into tKind
   else
      put "witness v" & tVer && "program (Bech32m)" into tKind
   end if
   put "type       " & tKind & return into tOut
   put "network    " & tNet & return after tOut
   put "witness    v" & tVer & return after tOut
   put "program    " & cxdHex(tProg) && "(" & the number of bytes in tProg & " bytes)" after tOut
   put tOut into field "dec:out"
   cxdStatus "dec:status", "Checksum valid (BIP-173/350, including the v0-vs-v1 constant rule).", "ok"
end doDecodeBech32

private command doDecodeBase58 pIn
   local tDec
   local tVersion
   local tPayload
   local tOut
   put cxBase58CheckDecode(pIn) into tDec
   if cxIsError(tDec) then
      put tDec into field "dec:out"
      cxdStatus "dec:status", "Rejected (fail closed) - the 4-byte double-SHA-256 checksum does not match.", "bad"
      exit doDecodeBase58
   end if
   put line 1 of tDec into tVersion
   put line 2 to -1 of tDec into tPayload
   put empty into tDec
   if tVersion is 0 and the number of bytes in tPayload is 20 then
      put "type       Bitcoin legacy P2PKH address (mainnet)" & return & \
         "hash160    " & cxdHex(tPayload) into tOut
   else if tVersion is 5 and the number of bytes in tPayload is 20 then
      put "type       Bitcoin P2SH address (mainnet; nested SegWit lives here)" & return & \
         "hash160    " & cxdHex(tPayload) into tOut
   else if tVersion is 111 and the number of bytes in tPayload is 20 then
      put "type       Bitcoin legacy P2PKH address (TESTNET)" & return & \
         "hash160    " & cxdHex(tPayload) into tOut
   else if tVersion is 196 and the number of bytes in tPayload is 20 then
      put "type       Bitcoin P2SH address (TESTNET)" & return & \
         "hash160    " & cxdHex(tPayload) into tOut
   else if tVersion is 128 or tVersion is 239 then
      put empty into tPayload
      doDecodeWif pIn
      exit doDecodeBase58
   else if tVersion is 4 and the number of bytes in tPayload is 77 then
      put empty into tPayload
      doDecodeXKey pIn
      exit doDecodeBase58
   else
      put "type       Base58Check, version" && tVersion && \
         "(" & the number of bytes in tPayload & " payload bytes)" & return & \
         "payload    " & cxdHex(tPayload) into tOut
   end if
   put empty into tPayload
   put tOut into field "dec:out"
   cxdStatus "dec:status", "Base58Check checksum valid.", "ok"
end doDecodeBase58

-- a WIF string is a PRIVATE KEY; decode it, say so loudly, and show which
-- addresses it controls (that is what an attacker could do with it too)
private command doDecodeWif pIn
   local tWif
   local tNet
   local tCompressed
   local tKey
   local tPub
   local tMainnet
   local tOut
   put cxWifDecode(pIn) into tWif
   if cxIsError(tWif) then
      put tWif into field "dec:out"
      cxdStatus "dec:status", "Rejected: WIF-shaped but invalid (fail closed).", "bad"
      exit doDecodeWif
   end if
   put line 1 of tWif into tNet
   put line 2 of tWif into tCompressed
   put line 3 to -1 of tWif into tKey
   put empty into tWif
   put (tNet is "mainnet") into tMainnet
   put cxPublicKey(tKey, (tCompressed is "true")) into tPub
   put "type       WIF - A PRIVATE KEY, not an address" & return into tOut
   put "network    " & tNet & "   compressed pubkey: " & tCompressed & return after tOut
   put "seckey     " & cxdHex(tKey) & return after tOut
   if cxIsError(tPub) is false then
      put "controls   " & cxBtcAddressP2PKH(tPub, tMainnet) after tOut
      if tCompressed is "true" then
         put return & "           " & cxBtcAddressP2WPKH(tPub, tMainnet) after tOut
      end if
   end if
   put empty into tKey
   put tOut into field "dec:out"
   cxdStatus "dec:status", "Anyone holding this string holds the coins on those addresses. Treat WIF as a secret.", "bad"
end doDecodeWif

-- an extended key: version(3 more bytes)|depth|fingerprint|child|chaincode|key
private command doDecodeXKey pIn
   local tDec
   local tPayload
   local tSub
   local tKind
   local tSecret
   local tChild
   local tChildText
   local tOut
   put cxBase58CheckDecode(pIn) into tDec
   put line 2 to -1 of tDec into tPayload
   put empty into tDec
   put cxHexEncode(byte 1 to 3 of tPayload) into tSub
   put false into tSecret
   if tSub is "88ade4" then
      put "xprv - an extended PRIVATE key (mainnet)" into tKind
      put true into tSecret
   else if tSub is "88b21e" then
      put "xpub - an extended PUBLIC key (mainnet, watch-only)" into tKind
   else if tSub is "358394" then
      put "tprv - an extended PRIVATE key (testnet)" into tKind
      put true into tSecret
   else if tSub is "3587cf" then
      put "tpub - an extended PUBLIC key (testnet, watch-only)" into tKind
   else
      put "unknown extended-key version 04" & tSub into tKind
   end if
   -- big-endian child index (payload bytes 9..12; 5..8 are the parent
   -- fingerprint); an index >= 2^31 marks a hardened step
   put ((byteToNum(byte 9 of tPayload) * 256 + byteToNum(byte 10 of tPayload)) \
      * 256 + byteToNum(byte 11 of tPayload)) * 256 + byteToNum(byte 12 of tPayload) into tChild
   if tChild >= 2147483648 then
      put (tChild - 2147483648) & "' (hardened)" into tChildText
   else
      put tChild into tChildText
   end if
   put "type       " & tKind & return into tOut
   put "depth      " & byteToNum(byte 4 of tPayload) && "(steps below the master)" & return after tOut
   put "parent     " & cxHexEncode(byte 5 to 8 of tPayload) && "(fingerprint)" & return after tOut
   put "child      " & tChildText & return after tOut
   put "chaincode  " & cxHexEncode(byte 13 to 44 of tPayload) & return after tOut
   if tSecret then
      put "key        (a 32-byte PRIVATE key follows the 00 pad - not shown)" after tOut
   else
      put "pubkey     " & cxHexEncode(byte 45 to 77 of tPayload) after tOut
   end if
   put empty into tPayload
   put tOut into field "dec:out"
   if tSecret then
      cxdStatus "dec:status", "This string can spend EVERYTHING below this node. Treat xprv/tprv as a secret.", "bad"
   else
      cxdStatus "dec:status", "Watch-only: this key derives addresses below this node but signs nothing.", "ok"
   end if
end doDecodeXKey

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
   local tMnem
   local tNode
   local tDecoded
   local tItems
   local tV
   local tRaw
   put 0 into sTPass
   put 0 into sTFail
   put "CoinXT self-test" & return & return into sTLog

   if cxdProbe() is false then
      put "The CoinXT extension or its native library is not loaded." & return after sTLog
      put "Install the packaged extension and load src/coinxt.livecodescript, then retry." after sTLog
      -- EIP-712: the EIP's own example digest, byte for byte
   put cxEip712Digest(cxEip712HashStruct("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)", \
      cxEip712WordHash(cxdAscii("Ether Mail")) & cxEip712WordHash(cxdAscii("1")) & cxEip712WordUInt("1") \
      & cxEip712WordAddress("0xCcCcccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")), \
      cxEip712HashStruct("Mail(Person from,Person to,string contents)Person(string name,address wallet)", \
      cxEip712HashStruct("Person(string name,address wallet)", cxEip712WordHash(cxdAscii("Cow")) & cxEip712WordAddress("0xCd2a3d9F938E13CD947Ec05AbC7fe734Df8DD826")) \
      & cxEip712HashStruct("Person(string name,address wallet)", cxEip712WordHash(cxdAscii("Bob")) & cxEip712WordAddress("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")) \
      & cxEip712WordHash(cxdAscii("Hello, Bob!")))) into tDecoded
   checkInto (cxHexEncode(tDecoded) is \
      "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"), \
      "the EIP-712 Mail example digest matches the EIP's published value"

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

   -- addresses (the BIP-173 SegWit example, the pk=1 Ethereum address)
   checkInto (cxBtcAddressP2WPKH(cxPublicKey(tSk, true), true) is \
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), \
      "P2WPKH(pubkey 1) is the BIP-173 example address"
   checkInto (cxEthAddress(cxPublicKey(tSk, false)) is \
      "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"), \
      "ethAddress(pubkey 1) is the pk=1 EIP-55 address"

   -- BIP-39 (the classic all-zero 128-bit vector)
   put "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" into tMnem
   checkInto (cxMnemonicFromEntropy(cxdBin("00000000000000000000000000000000")) is tMnem), \
      "128-bit zero entropy makes the canonical 12-word mnemonic"
   checkInto (cxMnemonicValidate(tMnem) is true), "the mnemonic validates (checksum ok)"
   checkInto (cxdHex(cxMnemonicToSeed(tMnem, "TREZOR")) is \
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"), \
      "mnemonic + TREZOR makes the pinned 64-byte seed"

   -- BIP-32 HD (test vector 1 master xprv/xpub)
   put cxHdFromSeed(cxdBin("000102030405060708090a0b0c0d0e0f")) into tNode
   checkInto (cxXprv(tNode, true) is \
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"), \
      "BIP-32 master xprv matches test vector 1"
   checkInto (cxXpub(tNode, true) is \
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"), \
      "BIP-32 master xpub matches test vector 1"
   put empty into tNode

   -- BIP-340 Schnorr (test vector 0) + Taproot address (BIP-86)
   put cxdBin("0000000000000000000000000000000000000000000000000000000000000003") into tSk
   checkInto (cxdHex(cxXonlyFromSeckey(tSk)) is \
      "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"), \
      "BIP-340 x-only pubkey matches test vector 0"
   put cxSchnorrSign(tSk, cxdBin("0000000000000000000000000000000000000000000000000000000000000000"), \
      cxdBin("0000000000000000000000000000000000000000000000000000000000000000")) into tSig
   checkInto (cxdHex(tSig) is \
      "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"), \
      "BIP-340 signature matches test vector 0"
   checkInto (cxBtcAddressP2TR(cxdBin("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"), true) is \
      "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"), \
      "P2TR(internal key) is the BIP-86 bc1p address"

   -- WIF, nested SegWit, decode, EIP-191 (the phase-5 surface)
   put cxdBin("0000000000000000000000000000000000000000000000000000000000000001") into tSk
   checkInto (cxWifEncode(tSk, true, true) is \
      "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"), \
      "WIF(sk=1) is the famous published string"
   put cxWifDecode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn") into tDecoded
   checkInto ((line 3 to -1 of tDecoded) is tSk), \
      "WIF decode round-trips the key bytes"
   checkInto (cxBtcAddressP2SH_P2WPKH(cxPublicKey(tSk, true), true) is \
      "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"), \
      "P2SH-P2WPKH(pubkey 1) matches the locked vector"
   put cxBech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") into tDecoded
   checkInto (cxHexEncode(line 3 to -1 of tDecoded) is \
      "751e76e8199196d454941c45d1b3a323f1433bd6"), \
      "Bech32 decode recovers the BIP-173 witness program"
   checkInto cxIsError(cxBech32Decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")), \
      "a corrupt Bech32 address is rejected (fail closed)"
   put cxEthPersonalHash(cxdAscii("hello")) into tHash
   checkInto (cxEthAddress(cxRecover(cxSignRecoverable(tSk, tHash), tHash)) is \
      "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"), \
      "EIP-191 personal_sign recovers the signer's address"

   -- wallet restore: the canonical phrase reproduces the OFFICIAL BIP-84 vector
   put cxHdFromSeed(cxMnemonicToSeed(tMnem, empty)) into tNode
   put cxHdDerivePath(tNode, "m/84'/0'/0'/0/0") into tNode
   checkInto (cxBtcAddressP2WPKH(cxHdPubkey(tNode), true) is \
      "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), \
      "restoring the canonical phrase gives the official BIP-84 first address"
   put empty into tNode

   -- RLP + the official EIP-155 example transaction, byte for byte
   checkInto (cxHexEncode(cxRlpList(cxRlpBytes(cxdAscii("cat")) & cxRlpBytes(cxdAscii("dog")))) is \
      "c88363617483646f67"), "RLP of [cat, dog] matches the yellow paper"
   put cxdBin("4646464646464646464646464646464646464646464646464646464646464646") into tSk
   put cxRlpUIntDec("9") & cxRlpUIntDec("20000000000") & cxRlpUIntDec("21000") \
      & cxRlpBytes(cxdBin("3535353535353535353535353535353535353535")) \
      & cxRlpUIntDec("1000000000000000000") & cxRlpBytes(empty) into tItems
   put cxKeccak256(cxRlpList(tItems & cxRlpUIntDec("1") & cxRlpUIntDec("0") & cxRlpUIntDec("0"))) into tHash
   put cxSignRecoverable(tSk, tHash) into tSig
   put 35 + 2 + byteToNum(byte 65 of tSig) into tV
   put cxRlpList(tItems & cxRlpUIntDec(tV) & cxRlpUIntBytes(byte 1 to 32 of tSig) \
      & cxRlpUIntBytes(byte 33 to 64 of tSig)) into tRaw
   checkInto (cxHexEncode(tRaw) is \
      "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"), \
      "the official EIP-155 example transaction is reproduced byte for byte"

   -- the official BIP-143 P2SH-P2WPKH example transaction, byte for byte
   put cxBtcTxSignP2WPKH(cxdBin("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"), \
      "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb", 1, 1000000000, \
      "199996600 1Fyxts6r24DpEieygQiNnWxUdb18ANa5p7" & return & "800000000 1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8", \
      true, 1, 4294967294, 1170) into tDecoded
   if cxIsError(tDecoded) then
      checkInto false, "the official BIP-143 example transaction is reproduced byte for byte"
   else
      checkInto (cxHexEncode(line 3 to -1 of tDecoded) is \
         "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"), \
         "the official BIP-143 example transaction is reproduced byte for byte"
   end if

   -- PSBT: sign + finalize the wrapped BIP-143 example to the same bytes
   put cxPsbtSign("cHNidP8BAHcBAAAAAdtrGyCqD9eyOIC+LsvUqYEwl0z0dI+2YJKsTTzrGlR3AQAAAAD+////Ari06wsAAAAAGXapFKRXtoTX8NU5pGpFu8BD81tZ0NljiKwACK8vAAAAABl2qRT9Jwse5qvK6pf+p60EAui9itbXfIiskgQAAAABASAAypo7AAAAABepFEcz83z024b7wu/tJQC09OSfMSAjhwEDBAEAAAABBBYAFHkJGXIYbESesd7SK3jkDQCb3wCJAAAA", \
      cxdBin("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")) into tDecoded
   if cxIsError(tDecoded) then
      checkInto false, "a PSBT of the BIP-143 example signs + finalizes to the published tx"
   else
      put cxPsbtFinalize(tDecoded) into tDecoded
      checkInto (not cxIsError(tDecoded) and cxHexEncode(line 2 to -1 of tDecoded) is \
         "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"), \
         "a PSBT of the BIP-143 example signs + finalizes to the published tx"
   end if

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
