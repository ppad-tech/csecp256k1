{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import Crypto.Curve.Secp256k1
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain units

units :: TestTree
units = testGroup "unit tests" [
    parse_pub_test
  , serialize_pub_test
  , serialize_pub_u_test
  , derive_pub_test
  , tweak_pub_add_test
  , tweak_pub_mul_test
  , tweak_sec_add_test
  , tweak_sec_mul_test
  , parse_der_test
  , serialize_der_test
  , compact_test
  , parse_xonly_test
  , serialize_xonly_test
  , keypair_test
  , sign_ecdsa_test
  , verify_ecdsa_test
  , sign_schnorr_test
  , verify_schnorr_test
  ]

parse_pub_test :: TestTree
parse_pub_test = testCase "parse_pub (success)" $
  wcontext $ \tex -> do
    -- throws on failure, so any return implies success
    _ <- parse_pub tex _PUB_COMPRESSED
    assertBool "success" True

serialize_pub_test :: TestTree
serialize_pub_test = testCase "serialize_pub (success)" $
  wcontext $ \tex -> do
    par <- parse_pub tex _PUB_COMPRESSED
    pub <- serialize_pub tex par
    assertEqual "success" pub _PUB_COMPRESSED

serialize_pub_u_test :: TestTree
serialize_pub_u_test = testCase "serialize_pub_u (success)" $
  wcontext $ \tex -> do
    par <- parse_pub tex _PUB_UNCOMPRESSED
    pub <- serialize_pub_u tex par
    assertEqual "success" pub _PUB_UNCOMPRESSED

derive_pub_test :: TestTree
derive_pub_test = testCase "derive_pub (success)" $
  wcontext $ \tex -> do
    -- throws on failure, so any return implies success
    _ <- derive_pub tex _SEC
    assertBool "success" True

tweak_pub_add_test :: TestTree
tweak_pub_add_test =
  testCase "tweak_pub_add (success)" $
    wcontext $ \tex -> do
      pub <- parse_pub tex _PUB_COMPRESSED
      add <- tweak_pub_add tex pub _TWEAK
      eek <- serialize_pub_u tex add
      assertEqual "success" eek _PUB_ADD_TWEAKED

tweak_pub_mul_test :: TestTree
tweak_pub_mul_test =
  testCase "tweak_pub_mul (success)" $
    wcontext $ \tex -> do
      pub <- parse_pub tex _PUB_COMPRESSED
      add <- tweak_pub_mul tex pub _TWEAK
      eek <- serialize_pub_u tex add
      assertEqual "success" eek _PUB_MUL_TWEAKED

tweak_sec_add_test :: TestTree
tweak_sec_add_test =
  testCase "tweak_sec_add (success)" $
    wcontext $ \tex -> do
      eek <- tweak_sec_add tex _SEC _TWEAK
      assertEqual "success" eek _SEC_ADD_TWEAKED

tweak_sec_mul_test :: TestTree
tweak_sec_mul_test =
  testCase "tweak_sec_mul (success)" $
    wcontext $ \tex -> do
      eek <- tweak_sec_mul tex _SEC _TWEAK
      assertEqual "success" eek _SEC_MUL_TWEAKED

parse_der_test :: TestTree
parse_der_test =
  testCase "parse_der (success)" $
    wcontext $ \tex -> do
      -- throws on failure, so any return implies success
      _ <- parse_der tex _DER
      assertBool "success" True

serialize_der_test :: TestTree
serialize_der_test =
  testCase "serialize_der (success)" $
    wcontext $ \tex -> do
      par <- parse_der tex _DER
      der <- serialize_der tex par
      assertEqual "success" der _DER

-- joint parse, serialize test
compact_test :: TestTree
compact_test =
  testCase "{parse, serialize}_compact (success)" $
    wcontext $ \tex -> do
      sig <- parse_der tex _DER
      com <- serialize_compact tex sig
      par <- parse_compact tex com
      der <- serialize_der tex par
      assertEqual "success" der _DER

parse_xonly_test :: TestTree
parse_xonly_test =
  testCase "parse_xonly (success)" $ do
    wcontext $ \tex -> do
      pux <- parse_xonly tex _PUB_XONLY
      pub <- serialize_xonly tex pux
      assertEqual "success" pub _PUB_XONLY

serialize_xonly_test :: TestTree
serialize_xonly_test =
  testCase "serialize_xonly (success)" $
    wcontext $ \tex -> do
      pub <- parse_pub tex _PUB_COMPRESSED
      key <- xonly tex pub
      pux <- serialize_xonly tex key
      assertEqual "success" pux _PUB_XONLY

keypair_test :: TestTree
keypair_test =
  testCase "keypair (success)" $ do
    wcontext $ \tex -> do
      per <- keypair tex _SEC
      sec <- keypair_sec tex per
      pub <- keypair_pub tex per
      ser <- serialize_pub tex pub
      assertEqual "success" sec _SEC
      assertEqual "success" ser _PUB_COMPRESSED

sign_ecdsa_test :: TestTree
sign_ecdsa_test = testCase "sign_ecdsa (success)" $
  wcontext $ \tex -> do
    sig <- sign_ecdsa tex _SEC _HAS
    der <- serialize_der tex sig
    assertEqual "success" _DER der

verify_ecdsa_test :: TestTree
verify_ecdsa_test = testCase "verify_ecdsa (success)" $
  wcontext $ \tex -> do
    pub <- parse_pub tex _PUB_UNCOMPRESSED
    sig <- parse_der tex _DER
    suc <- verify_ecdsa tex pub _HAS sig
    assertBool "success" suc

sign_schnorr_test :: TestTree
sign_schnorr_test = testCase "sign_schnorr (success)" $
  wcontext $ \tex -> do
    let enn = BS.replicate 32 0
    sig <- sign_schnorr tex _HAS _SEC enn
    assertEqual "success" sig _SIG_SCHNORR

verify_schnorr_test :: TestTree
verify_schnorr_test = testCase "verify_schnorr (success)" $
  wcontext $ \tex -> do
    pub <- parse_pub tex _PUB_UNCOMPRESSED
    suc <- verify_schnorr tex pub _HAS _SIG_SCHNORR
    assertBool "success" suc

ecdh_test :: TestTree
ecdh_test = testCase "ecdh (success)" $
  wcontext $ \tex -> do
    pub <- parse_pub tex _PUB_COMPRESSED
    -- throws on failure, so any return implies success
    _ <- ecdh tex pub _SEC
    assertBool "success" True

-- test inputs

-- mostly grabbed from haskoin/secp256k1-haskell

-- DER-encoded signature
_DER :: BS.ByteString
_DER = mconcat [
    "0E\STX!\NUL\245\STX\191\160z\244>~\242ea\139\r\146\154v\EM\238\SOH\214"
  , "\NAK\SO7\235n\170\242\200\189\&7\251\"\STX o\EOT\NAK\171\SO\154\151z"
  , "\253x\178\194n\243\155\&9R\tm1\159\212\177\SOH\199h\173l\DC3.0E"
  ]

-- a 32-byte message hash
_HAS :: BS.ByteString
_HAS = mconcat [
    "\245\203\231\216\129\130\164\184\228\NUL\249k\ACK\DC2\137!\134J"
  , "\CAN\CAN}\DC1L\138\232T\ESCVl\138\206\NUL"
  ]

-- a 32-byte secret key
_SEC :: BS.ByteString
_SEC = mconcat [
    "\246RU\tMws\237\141\212\ETB\186\220\159\192E\193\248\SI\220[-%\ETB"
  , "+\ETX\FS\230\147>\ETX\154"
  ]

-- 32 bytes
_TWEAK :: BS.ByteString
_TWEAK = mconcat [
    "\245\203\231\216\129\130\164\184\228\NUL\249k\ACK\DC2\137!\134J"
  , "\CAN\CAN}\DC1L\138\232T\ESCVl\138\206\NUL"
  ]

-- _PUB add-tweaked with _TWEAK
_PUB_ADD_TWEAKED :: BS.ByteString
_PUB_ADD_TWEAKED = mconcat [
    "\EOTD\FS9\130\185uvdn\r\240\201g6\ACK=\246\180/.\229f\209;\159d$0-"
  , "\DC3y\229\CAN\253\200z\DC4\197C[\255z]\180U B\203A \198\184jK\189="
  , "\ACKC\243\193J\208\DC3h"
  ]

-- _PUB mul-tweaked with _TWEAK
_PUB_MUL_TWEAKED :: BS.ByteString
_PUB_MUL_TWEAKED = mconcat [
    "\EOT\243y\220\153\205\245\200>C=\239\162g\251\179\&7}a\214\183y"
  , "\192j\SOL\226\154\227\255SS\177*\228\156\157\a\231\&6\143+\165"
  , "\164F\194\ETX%\\\233\DC22)\145\162\214\169\213\213v\FSa\237\CANE"
  ]

-- _SEC add-tweaked with _TWEAK
_SEC_ADD_TWEAKED :: BS.ByteString
_SEC_ADD_TWEAKED = mconcat [
    "\236\RS<\225\206\250\CAN\166q\213\DC1%\226\178Ih\141\147K\SO(\245"
  , "\209fS\132\217\176/\146\144Y"
  ]

-- _SEC mul-tweaked with _TWEAK
_SEC_MUL_TWEAKED :: BS.ByteString
_SEC_MUL_TWEAKED = mconcat [
    "\169oYbI:\203\ETB\159`\168j\151\133\252z0\224\195\155d\192\157$\254"
  , "\ACKM\154\239\NAK\228\192"
  ]

-- 33-byte (compressed) public key
_PUB_COMPRESSED :: BS.ByteString
_PUB_COMPRESSED = mconcat [
    "\ETX\221\237B\ETX\218\201j~\133\242\195t\163|\227\233\201\161U"
  , "\167+d\180U\ESC\v\254w\157\212G\ENQ"
  ]

-- 65-byte (uncompressed) public key
_PUB_UNCOMPRESSED :: BS.ByteString
_PUB_UNCOMPRESSED = mconcat [
    "\EOT\221\237B\ETX\218\201j~\133\242\195t\163|\227\233\201\161U\167"
  , "+d\180U\ESC\v\254w\157\212G\ENQ\DC2!=^\215\144R,\EOT-\238\142\133"
  , "\196\192\236_\150\128\vr\188Y@\200\188\FS^\DC1\228\252\191"
  ]

-- 32-byte x-only pubkey
_PUB_XONLY :: BS.ByteString
_PUB_XONLY = mconcat [
    "\221\237B\ETX\218\201j~\133\242\195t\163|\227\233\201\161U\167+d"
  , "\180U\ESC\v\254w\157\212G\ENQ"
  ]

-- 64-byte schnorr signature
_SIG_SCHNORR :: BS.ByteString
_SIG_SCHNORR  = mconcat [
    "\214\185AtJ\189\250Gp\NAK2\221\DC2[\182\209\192j{\140^\222R\NUL~"
  , "\139d@<\138\163rh\247\152\r\228\175\236\219\156\151\214~\135\&7"
  , "\225\&6\234\220;\164R\191\170\186\243\NAK\147\f\144\156ez"
  ]

