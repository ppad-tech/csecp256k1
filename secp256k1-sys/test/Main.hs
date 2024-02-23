{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE ViewPatterns  #-}

module Main where

import Control.Monad (when)
import Control.Exception (Exception, bracket, throwIO)
import Crypto.Secp256k1.Internal
import qualified Data.ByteString as BS
import Foreign.C.Types (CUInt)
import Foreign.Ptr (Ptr)
import qualified Foreign.Ptr as F (nullPtr, castPtr)
import qualified Foreign.Marshal.Alloc as A (alloca, allocaBytes)
import qualified Foreign.Storable as S (poke, peek)
import qualified System.Entropy as E
import Test.Tasty
import Test.Tasty.HUnit

data Secp256k1Error = Secp256k1Error
  deriving Show

instance Exception Secp256k1Error

_DER_BYTES :: Int
_DER_BYTES = 72

_PUB_BYTES_COMPRESSED :: Int
_PUB_BYTES_COMPRESSED = 33

_PUB_BYTES_UNCOMPRESSED :: Int
_PUB_BYTES_UNCOMPRESSED = 65

_PUB_BYTES_INTERNAL :: Int
_PUB_BYTES_INTERNAL = 64

_SEC_BYTES :: Int
_SEC_BYTES = 32

_SIG_BYTES :: Int
_SIG_BYTES = 64

_COMPRESSED_FLAG :: CUInt
_COMPRESSED_FLAG = 0x0102

_UNCOMPRESSED_FLAG :: CUInt
_UNCOMPRESSED_FLAG = 0x0002

main :: IO ()
main = defaultMain units

units :: TestTree
units = testGroup "unit tests" [
    context_create
  , context_randomize
  , ec_pubkey_parse
  , ec_pubkey_serialize_compressed
  , ec_pubkey_serialize_uncompressed
  , ec_pubkey_create
  , ecdsa_signature_parse_der
  , ecdsa_signature_serialize_der
  , ecdsa_sign
  , ecdsa_verify_compressed
  , ecdsa_verify_uncompressed
  -- , ecdh_test
  ]

wcontext :: (Ptr Context -> IO a) -> IO a
wcontext =
  bracket
    (secp256k1_context_create _SECP256K1_CONTEXT_NONE)
    secp256k1_context_destroy

wentropy :: (Ptr Seed32 -> IO a) -> IO a
wentropy c = do
  bs <- E.getEntropy 32
  BS.useAsCString bs $ \(F.castPtr -> b) -> c b

-- context

context_create :: TestTree
context_create = testCase "secp256k1_context_create (non-null)" $
  wcontext $ \tex -> assertBool "non-null" $ tex /= F.nullPtr

context_randomize :: TestTree
context_randomize = testCase "secp256k1_context_randomize (success)" $
  wcontext $ \tex -> do
    suc <- wentropy (secp256k1_context_randomize tex)
    assertBool "success" (suc == 1)

-- ec

ec_pubkey_parse :: TestTree
ec_pubkey_parse = testCase "secp256k1_ec_pubkey_parse (success)" $
  wcontext $ \tex -> do
    -- throws on failure, so any return implies success
    _ <- parse_pubkey tex _PUB_COMPRESSED
    assertBool "success" True

ec_pubkey_serialize_compressed :: TestTree
ec_pubkey_serialize_compressed =
  testCase "secp256k1_ec_pubkey_serialize (compressed, success)" $
    wcontext $ \tex -> do
      par <- parse_pubkey tex _PUB_COMPRESSED
      pub <- serialize_pubkey_compressed tex par
      assertEqual "success" pub _PUB_COMPRESSED

ec_pubkey_serialize_uncompressed :: TestTree
ec_pubkey_serialize_uncompressed =
  testCase "secp256k1_ec_pubkey_serialize (uncompressed, success)" $
    wcontext $ \tex -> do
      par <- parse_pubkey tex _PUB_UNCOMPRESSED
      pub <- serialize_pubkey_uncompressed tex par
      assertEqual "success" pub _PUB_UNCOMPRESSED

ec_pubkey_create :: TestTree
ec_pubkey_create =
  testCase "secp256k1_ec_pubkey_create (success)" $
    wcontext $ \tex -> do
      _ <- create_pubkey tex _SEC
      assertBool "success" True

-- ecdsa

ecdsa_signature_parse_der :: TestTree
ecdsa_signature_parse_der =
  testCase "secp256k1_ecdsa_signature_parse_der (success)" $
    wcontext $ \tex -> do
      -- throws on failure, so any return implies success
      _ <- parse_der tex _DER
      assertBool "success" True

ecdsa_signature_serialize_der :: TestTree
ecdsa_signature_serialize_der =
  testCase "secp256k1_ecdsa_signature_serialize_der (success)" $
    wcontext $ \tex -> do
      par <- parse_der tex _DER
      der <- serialize_der tex par
      assertEqual "success" der _DER

ecdsa_sign :: TestTree
ecdsa_sign = testCase "secp256k1_ecdsa_sign (success)" $
  wcontext $ \tex -> do
    par <- parse_der tex _DER
    sig <- sign_ecdsa tex _SEC _HAS
    assertEqual "success" sig par

ecdsa_verify_compressed :: TestTree
ecdsa_verify_compressed =
  testCase "secp256k1_ecdsa_verify (compressed, success)" $
    wcontext $ \tex -> do
      suc <- verify_ecdsa tex _PUB_COMPRESSED _HAS _DER
      assertBool "success" suc

ecdsa_verify_uncompressed :: TestTree
ecdsa_verify_uncompressed =
  testCase "secp256k1_ecdsa_verify (uncompressed, success)" $
    wcontext $ \tex -> do
      suc <- verify_ecdsa tex _PUB_UNCOMPRESSED _HAS _DER
      assertBool "success" suc

-- ecdh

-- XX getting dyld error when trying to run
--
-- ecdh_test :: TestTree
-- ecdh_test = testCase "secp256k1_ecdh (success)" $
--   wcontext $ \tex -> do
--     -- throws on failure, so any return implies success
--     _ <- ecdh tex _PUB_COMPRESSED _SEC
--     assertBool "success" True

-- wrappers

parse_der :: Ptr Context -> BS.ByteString -> IO BS.ByteString
parse_der tex bs =
  BS.useAsCStringLen bs $ \(F.castPtr -> der, fromIntegral -> len) ->
    A.allocaBytes _SIG_BYTES $ \out -> do
      suc <- secp256k1_ecdsa_signature_parse_der tex out der len
      when (suc /= 1) $ throwIO Secp256k1Error
      let par = F.castPtr out
      BS.packCStringLen (par, _SIG_BYTES)

serialize_der :: Ptr Context -> BS.ByteString -> IO BS.ByteString
serialize_der tex bs = A.alloca $ \len ->
  A.allocaBytes _DER_BYTES $ \out ->
    BS.useAsCString bs $ \(F.castPtr -> sig) -> do
      let siz = fromIntegral _DER_BYTES
      S.poke len siz
      suc <- secp256k1_ecdsa_signature_serialize_der tex out len sig
      when (suc /= 1) $ throwIO Secp256k1Error
      pek <- S.peek len
      let enc = F.castPtr out
          nel = fromIntegral pek
      BS.packCStringLen (enc, nel)

parse_pubkey :: Ptr Context -> BS.ByteString -> IO BS.ByteString
parse_pubkey tex bs =
  BS.useAsCStringLen bs $ \(F.castPtr -> pub, fromIntegral -> len) ->
    A.allocaBytes _PUB_BYTES_INTERNAL $ \out -> do
      suc <- secp256k1_ec_pubkey_parse tex out pub len
      when (suc /= 1) $ throwIO Secp256k1Error
      let par = F.castPtr out
      BS.packCStringLen (par, _PUB_BYTES_INTERNAL)

create_pubkey :: Ptr Context -> BS.ByteString -> IO BS.ByteString
create_pubkey tex bs =
  BS.useAsCString bs $ \(F.castPtr -> sec) ->
    A.allocaBytes _PUB_BYTES_INTERNAL $ \out -> do
      suc <- secp256k1_ec_pubkey_create tex out sec
      when (suc /= 1) $ throwIO Secp256k1Error
      let pub = F.castPtr out
      BS.packCStringLen (pub, _PUB_BYTES_INTERNAL)

serialize_pubkey_compressed :: Ptr Context -> BS.ByteString -> IO BS.ByteString
serialize_pubkey_compressed tex bs =
  BS.useAsCString bs $ \(F.castPtr -> pub) ->
    A.alloca $ \len ->
      A.allocaBytes _PUB_BYTES_COMPRESSED $ \out -> do
        let siz = fromIntegral _PUB_BYTES_COMPRESSED
        S.poke len siz
        suc <- secp256k1_ec_pubkey_serialize tex out len pub _COMPRESSED_FLAG
        when (suc /= 1) $ throwIO Secp256k1Error
        pec <- S.peek len
        let enc = F.castPtr out
            nel = fromIntegral pec
        BS.packCStringLen (enc, nel)

serialize_pubkey_uncompressed
  :: Ptr Context
  -> BS.ByteString
  -> IO BS.ByteString
serialize_pubkey_uncompressed tex bs =
  BS.useAsCString bs $ \(F.castPtr -> pub) ->
    A.alloca $ \len ->
      A.allocaBytes _PUB_BYTES_UNCOMPRESSED $ \out -> do
        let siz = fromIntegral _PUB_BYTES_UNCOMPRESSED
        S.poke len siz
        suc <- secp256k1_ec_pubkey_serialize tex out len pub _UNCOMPRESSED_FLAG
        when (suc /= 1) $ throwIO Secp256k1Error
        pec <- S.peek len
        let enc = F.castPtr out
            nel = fromIntegral pec
        BS.packCStringLen (enc, nel)

sign_ecdsa :: Ptr Context -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
sign_ecdsa tex key msg =
  A.allocaBytes _SIG_BYTES $ \out ->
    BS.useAsCString msg $ \(F.castPtr -> has) ->
      BS.useAsCString key $ \(F.castPtr -> sec) -> do
        suc <- secp256k1_ecdsa_sign tex out has sec F.nullPtr F.nullPtr
        when (suc /= 1) $ throwIO Secp256k1Error
        let sig = F.castPtr out
        BS.packCStringLen (sig, _SIG_BYTES)

verify_ecdsa
  :: Ptr Context
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> IO Bool
verify_ecdsa tex key msg der = do
  sig <- parse_der tex der
  pub <- parse_pubkey tex key
  suc <- BS.useAsCString msg $ \(F.castPtr -> has) ->
    BS.useAsCString pub $ \(F.castPtr -> kep) ->
      BS.useAsCString sig $ \(F.castPtr -> sip) ->
        secp256k1_ecdsa_verify tex sip has kep
  pure (suc == 1)

-- XX resurrect when ecdh problems solved
--
-- ecdh :: Ptr Context -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
-- ecdh tex pub sec =
--   A.allocaBytes _SEC_BYTES $ \out -> do
--     par <- parse_pubkey tex pub
--     BS.useAsCString par $ \(F.castPtr -> pab) ->
--       BS.useAsCString sec $ \(F.castPtr -> sep) -> do
--         suc <- secp256k1_ecdh tex out pab sep F.nullPtr F.nullPtr
--         when (suc /= 1) $ throwIO Secp256k1Error
--         let key = F.castPtr out
--         BS.packCStringLen (key, _SEC_BYTES)

-- test inputs

-- a DER-encoded signature
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

