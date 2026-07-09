/* coinxt-online.livecodescript - CoinXT's OPTIONAL online composition layer.

   This is NOT part of the trusted offline core (src/coinxt.livecodescript +
   the shim). It is a SEPARATE module an app loads deliberately (start using
   it, exactly as it opts into SodiumXT), so the core stays auditably
   network-free and key-free. See SPEC.md section 1.1.

   What it does: compose the ENGINE's HTTP (optionally over Tor, if the app
   routes through OnionXT) to READ chain state an offline signer cannot know
   (an address's UTXOs, its confirmed balance, a fee rate) and to WRITE an
   already-signed transaction to the network. The read/broadcast talks to an
   Esplora-compatible REST endpoint (Blockstream / mempool.space / your OWN
   node or Tor hidden service).

   The rules that keep this honest (SPEC 1.1), enforced here:
   - It NEVER touches a private key. It fetches read-only data and broadcasts
     bytes the offline core already signed. Signing stays in the core.
   - An explorer's answer is UNTRUSTED. A queried server can lie about
     balances / UTXOs / fees, so every response is parsed FAIL-CLOSED (a
     malformed body is a clean "CoinXT: ..." error, never a guessed value),
     and the app still shows the human every amount + destination before the
     core signs. A parser bug can feed a wrong amount to the tx builder,
     never forge a signature; the on-screen fee is the backstop.
   - Querying LEAKS your addresses to the endpoint, and broadcasting reveals
     your IP. Point cxoSetEndpoint at your OWN node or a Tor hidden service
     (the OnionXT composition) for the private path. Default is a public
     TESTNET explorer, so a first run cannot touch real coins.

   The response PARSERS are pure functions, transcribed 1:1 to Python and
   vector-locked in tools/coin-kat.py against representative Esplora-shape
   fixtures (documented as schema fixtures, not a captured live response);
   only the thin HTTP verbs (cxoGet / cxoPost) need an on-engine pass.

   Status: designed, parser-verified against fixtures; the network verbs and
   the JSON scanning NEED AN ON-ENGINE PASS (see CLAUDE.md, phase 8).
*/

local sBase   -- the REST base URL (no trailing slash); default set on first use

----------------------------------------------------------------------
-- endpoint configuration
----------------------------------------------------------------------

-- the base URL, defaulting to Blockstream's public TESTNET Esplora (so a
-- first run cannot touch mainnet coins). Point this at your own node or a
-- Tor hidden service (via OnionXT) for privacy.
function cxoEndpoint
   if sBase is empty then
      put "https://blockstream.info/testnet/api" into sBase
   end if
   return sBase
end cxoEndpoint

-- set the base URL (strip a trailing slash so path joins are clean)
command cxoSetEndpoint pBase
   local tBase
   put pBase into tBase
   if the last char of tBase is "/" then
      delete the last char of tBase
   end if
   put tBase into sBase
end cxoSetEndpoint

----------------------------------------------------------------------
-- targeted JSON extraction (fail closed; not a general parser)
--
-- These scan the response TEXT for exactly the fields the Esplora schema
-- exposes, depth-aware so a nested key never matches at the wrong level.
-- Verified 1:1 in tools/coin-kat.py (run_online_parse_checks) including a
-- 3000-blob fuzz that must never raise and agreement with a real JSON
-- parser on flat numeric keys.
----------------------------------------------------------------------

-- the value token of "pKey": at brace-depth 0 within pObj (a JSON object
-- text). Returns the unquoted string, a bare number/bool token, or a raw
-- sub-object/array substring; empty if not present at this level. The
-- caller distinguishes "absent" (empty) by context.
private function cxoField pObj, pKey
   local tS
   local tBody
   local tNeedle
   local tDepth
   local tI
   local tN
   local tCh
   local tInStr
   local tJ
   put pObj into tS
   if the first char of tS is not "{" or the last char of tS is not "}" then
      return empty
   end if
   put char 2 to -2 of tS into tBody
   put quote & pKey & quote into tNeedle
   put 0 into tDepth
   put 1 into tI
   put the number of chars in tBody into tN
   put false into tInStr
   repeat while tI <= tN
      put char tI of tBody into tCh
      if tInStr then
         if tCh is "\" then
            add 2 to tI
            next repeat
         end if
         if tCh is quote then
            put false into tInStr
         end if
         add 1 to tI
         next repeat
      end if
      if tCh is quote then
         -- a string starts here; is it our key at depth 0?
         if tDepth is 0 and char tI to (tI + the number of chars in tNeedle - 1) of tBody is tNeedle then
            put tI + the number of chars in tNeedle into tJ
            repeat while tJ <= tN and (char tJ of tBody is space or char tJ of tBody is tab)
               add 1 to tJ
            end repeat
            if tJ <= tN and char tJ of tBody is ":" then
               add 1 to tJ
               repeat while tJ <= tN and (char tJ of tBody is space or char tJ of tBody is tab)
                  add 1 to tJ
               end repeat
               return cxoValueToken(tBody, tJ)
            end if
         end if
         -- skip to the end of this string
         add 1 to tI
         repeat while tI <= tN
            if char tI of tBody is "\" then
               add 2 to tI
               next repeat
            end if
            if char tI of tBody is quote then
               add 1 to tI
               exit repeat
            end if
            add 1 to tI
         end repeat
         next repeat
      end if
      if tCh is "{" or tCh is "[" then
         add 1 to tDepth
      else if tCh is "}" or tCh is "]" then
         subtract 1 from tDepth
      end if
      add 1 to tI
   end repeat
   return empty
end cxoField

-- the JSON value token beginning at 1-based char pJ of pBody
private function cxoValueToken pBody, pJ
   local tN
   local tCh
   local tK
   local tOpen
   local tClose
   local tDepth
   local tInStr
   put the number of chars in pBody into tN
   put char pJ of pBody into tCh
   if tCh is quote then
      put pJ + 1 into tK
      repeat while tK <= tN
         if char tK of pBody is "\" then
            add 2 to tK
            next repeat
         end if
         if char tK of pBody is quote then
            return char (pJ + 1) to (tK - 1) of pBody
         end if
         add 1 to tK
      end repeat
      return empty
   end if
   if tCh is "{" or tCh is "[" then
      if tCh is "{" then
         put "}" into tClose
      else
         put "]" into tClose
      end if
      put tCh into tOpen
      put 0 into tDepth
      put pJ into tK
      put false into tInStr
      repeat while tK <= tN
         put char tK of pBody into tCh
         if tInStr then
            if tCh is "\" then
               add 2 to tK
               next repeat
            end if
            if tCh is quote then
               put false into tInStr
            end if
         else if tCh is quote then
            put true into tInStr
         else if tCh is tOpen then
            add 1 to tDepth
         else if tCh is tClose then
            subtract 1 from tDepth
            if tDepth is 0 then
               return char pJ to tK of pBody
            end if
         end if
         add 1 to tK
      end repeat
      return empty
   end if
   -- a bare token (number / true / false / null) up to the next comma
   put pJ into tK
   repeat while tK <= tN and char tK of pBody is not ","
      add 1 to tK
   end repeat
   return cxoTrim(char pJ to (tK - 1) of pBody)
end cxoValueToken

-- split a JSON array text into its top-level element substrings (brace /
-- bracket depth aware, strings ignored). Returns them return-delimited, or
-- a "CoinXT: ..." error on unbalanced input. An empty array is empty.
private function cxoArrayElements pArr
   local tS
   local tBody
   local tOut
   local tStart
   local tDepth
   local tI
   local tN
   local tCh
   local tInStr
   local tEsc
   put cxoTrim(pArr) into tS
   if the first char of tS is not "[" or the last char of tS is not "]" then
      return "CoinXT: not a JSON array (cxoArrayElements)"
   end if
   put char 2 to -2 of tS into tBody
   put empty into tOut
   put 1 into tStart
   put 0 into tDepth
   put false into tInStr
   put false into tEsc
   put the number of chars in tBody into tN
   put 1 into tI
   repeat while tI <= tN
      put char tI of tBody into tCh
      if tInStr then
         if tEsc then
            put false into tEsc
         else if tCh is "\" then
            put true into tEsc
         else if tCh is quote then
            put false into tInStr
         end if
         add 1 to tI
         next repeat
      end if
      if tCh is quote then
         put true into tInStr
      else if tCh is "{" or tCh is "[" then
         add 1 to tDepth
      else if tCh is "}" or tCh is "]" then
         subtract 1 from tDepth
         if tDepth < 0 then
            return "CoinXT: unbalanced JSON array (cxoArrayElements)"
         end if
      else if tCh is "," and tDepth is 0 then
         put cxoTrim(char tStart to (tI - 1) of tBody) & return after tOut
         put tI + 1 into tStart
      end if
      add 1 to tI
   end repeat
   if tDepth is not 0 or tInStr then
      return "CoinXT: unbalanced JSON array (cxoArrayElements)"
   end if
   if cxoTrim(char tStart to -1 of tBody) is not empty then
      put cxoTrim(char tStart to -1 of tBody) after tOut
   end if
   return tOut
end cxoArrayElements

-- trim ASCII whitespace from both ends
private function cxoTrim pStr
   local tS
   put pStr into tS
   repeat while tS is not empty and (the first char of tS is space or the first char of tS is tab or the first char of tS is return or the first char of tS is numToChar(10))
      delete the first char of tS
   end repeat
   repeat while tS is not empty and (the last char of tS is space or the last char of tS is tab or the last char of tS is return or the last char of tS is numToChar(10))
      delete the last char of tS
   end repeat
   return tS
end cxoTrim

-- a token to a non-negative integer, or empty (fail closed)
private function cxoUInt pTok
   if matchText(pTok, "^[0-9]+$") then
      return pTok
   end if
   return empty
end cxoUInt

----------------------------------------------------------------------
-- HTTP verbs (the ONLY network-touching handlers; on-engine pass needed)
--
-- These use the engine's own URL access. If the app has routed the socket
-- layer through OnionXT / Tor, these inherit it; otherwise they go direct
-- (and reveal the client IP - the documented privacy cost). Any transport
-- failure surfaces as a clean "CoinXT: ..." error via `the result`.
----------------------------------------------------------------------

private function cxoGet pUrl
   local tData
   local tErr
   put empty into tData
   put URL pUrl into tData
   put the result into tErr
   if tErr is not empty then
      return "CoinXT: network error:" && tErr && "(cxoGet)"
   end if
   return tData
end cxoGet

private function cxoPost pUrl, pBody
   local tReply
   local tErr
   post pBody to URL pUrl
   put it into tReply
   put the result into tErr
   if tErr is not empty then
      return "CoinXT: network error:" && tErr && "(cxoPost)"
   end if
   return tReply
end cxoPost

----------------------------------------------------------------------
-- the public cxo* API
----------------------------------------------------------------------

-- PARSE an Esplora /utxo array body to one line per output, "txid vout
-- valueSats confirmed". Pure (no network), so coin-kat and the on-engine
-- harness both drive it against fixtures. A malformed body fails closed; an
-- empty array returns empty. These are the exact fields cxBtcTxSignP2WPKH
-- needs - but the app still shows the human the amount before signing.
function cxoParseUtxos pBody
   local tElems
   local tElem
   local tTxid
   local tVout
   local tValue
   local tStatus
   local tConfirmed
   local tOut
   put cxoArrayElements(pBody) into tElems
   if cxoIsError(tElems) then
      return tElems && "(cxoParseUtxos)"
   end if
   put empty into tOut
   repeat for each line tElem in tElems
      put cxoField(tElem, "txid") into tTxid
      put cxoUInt(cxoField(tElem, "vout")) into tVout
      put cxoUInt(cxoField(tElem, "value")) into tValue
      put cxoField(tElem, "status") into tStatus
      put (cxoField(tStatus, "confirmed") is "true") into tConfirmed
      if the number of chars in tTxid is not 64 or tVout is empty or tValue is empty then
         return "CoinXT: malformed UTXO in explorer response (cxoParseUtxos)"
      end if
      put tTxid && tVout && tValue && tConfirmed & return after tOut
   end repeat
   if the last char of tOut is return then
      delete the last char of tOut
   end if
   return tOut
end cxoParseUtxos

-- PARSE an Esplora /address body to the CONFIRMED balance in satoshis
-- (chain_stats funded minus spent). Pure; fails closed.
function cxoParseBalance pBody
   local tChain
   local tFunded
   local tSpent
   put cxoField(pBody, "chain_stats") into tChain
   put cxoUInt(cxoField(tChain, "funded_txo_sum")) into tFunded
   put cxoUInt(cxoField(tChain, "spent_txo_sum")) into tSpent
   if tFunded is empty or tSpent is empty then
      return "CoinXT: could not read the balance (cxoParseBalance)"
   end if
   return tFunded - tSpent
end cxoParseBalance

-- PARSE an Esplora /fee-estimates body to a sat/vB rate for the pBlocks
-- target (empty -> 6), rounded UP so an estimate never rounds a fee below
-- the target. Pure; fails closed.
function cxoParseFeeRate pBody, pBlocks
   local tTarget
   local tTok
   local tInt
   if pBlocks is empty then
      put "6" into tTarget
   else
      put pBlocks into tTarget
   end if
   put cxoField(pBody, tTarget) into tTok
   if tTok is empty or matchText(tTok, "^[0-9]+(\\.[0-9]+)?$") is false then
      return "CoinXT: could not read the fee rate (cxoParseFeeRate)"
   end if
   put trunc(tTok) into tInt
   if tTok > tInt then
      add 1 to tInt
   end if
   return tInt
end cxoParseFeeRate

-- an address's unspent outputs (fetch + parse). See cxoParseUtxos.
function cxoUtxos pAddress
   local tBody
   put cxoGet(cxoEndpoint() & "/address/" & pAddress & "/utxo") into tBody
   if cxoIsError(tBody) then
      return tBody
   end if
   return cxoParseUtxos(tBody)
end cxoUtxos

-- an address's confirmed balance in satoshis (fetch + parse).
function cxoBalance pAddress
   local tBody
   put cxoGet(cxoEndpoint() & "/address/" & pAddress) into tBody
   if cxoIsError(tBody) then
      return tBody
   end if
   return cxoParseBalance(tBody)
end cxoBalance

-- a recommended fee rate in sat/vB for pBlocks-block confirmation
-- (fetch + parse; pass empty for 6).
function cxoFeeRate pBlocks
   local tBody
   put cxoGet(cxoEndpoint() & "/fee-estimates") into tBody
   if cxoIsError(tBody) then
      return tBody
   end if
   return cxoParseFeeRate(tBody, pBlocks)
end cxoFeeRate

-- broadcast an already-signed raw transaction (hex, from cxBtcTxSignP2WPKH
-- or cxPsbtFinalize). Returns the network txid on success, or a clean
-- "CoinXT: ..." error carrying the node's rejection message. THIS PUTS A
-- TRANSACTION ON A REAL NETWORK: the app must confirm the decoded intent
-- with the human first (SPEC rule 3). Never broadcast a demo key's tx.
function cxoBroadcast pRawHex
   local tHex
   local tReply
   put cxoTrim(pRawHex) into tHex
   if matchText(tHex, "^[0-9a-fA-F]+$") is false or (the number of chars in tHex) mod 2 is not 0 then
      return "CoinXT: not a hex transaction (cxoBroadcast)"
   end if
   put cxoPost(cxoEndpoint() & "/tx", tHex) into tReply
   if cxoIsError(tReply) then
      return tReply
   end if
   put cxoTrim(tReply) into tReply
   -- Esplora replies with the bare txid on success, an error string otherwise
   if the number of chars in tReply is 64 and matchText(tReply, "^[0-9a-fA-F]+$") then
      return toLower(tReply)
   end if
   return "CoinXT: broadcast rejected:" && tReply && "(cxoBroadcast)"
end cxoBroadcast

-- the same error contract as the core: a cxo* result that begins "CoinXT:"
function cxoIsError pValue
   return pValue begins with "CoinXT:"
end cxoIsError
