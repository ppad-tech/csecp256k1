{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Curve.Secp256k1 as S
import qualified Crypto.Curve.Secp256k1.Internal as SI
import qualified Data.ByteString as BS

instance NFData S.Context
instance NFData S.KeyPair
instance NFData S.Pub
instance NFData S.Sig
instance NFData S.XOnlyPub

main :: IO ()
main = defaultMain [
    suite
  ]

suite :: Benchmark
suite = envWithCleanup setup destroy $ \ ~(tex, fen, pub, sig) ->
    bgroup "csecp256k1" [
        bgroup "ecdsa" [
          bench "sign" . nfIO $ S.sign_ecdsa tex _SEC _HAS
        , bench "verify" . nfIO $ S.verify_ecdsa tex pub _HAS sig
        ]
      , bgroup "schnorr" [
          bench "sign" . nfIO $ S.sign_schnorr tex _HAS _SEC fen
        , bench "verify" . nfIO $ S.verify_schnorr tex pub _HAS _SIG_SCHNORR
        ]
      , bgroup "ecdh" [
          bench "ecdh" . nfIO $ S.ecdh tex pub _SEC
        ]
      ]
  where
    setup = do
      ptr <- SI.secp256k1_context_create SI._SECP256K1_CONTEXT_NONE
      pub <- SI.wcontext $ \tex -> S.parse_pub (S.Context tex) _PUB_COMPRESSED
      sig <- SI.wcontext $ \tex -> S.parse_der (S.Context tex) _DER
      pure (S.Context ptr, BS.replicate 32 0, pub, sig)

    destroy (S.Context tex, _, _, _) = SI.secp256k1_context_destroy tex

-- inputs

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

-- DER-encoded signature
_DER :: BS.ByteString
_DER = mconcat [
    "0E\STX!\NUL\245\STX\191\160z\244>~\242ea\139\r\146\154v\EM\238\SOH\214"
  , "\NAK\SO7\235n\170\242\200\189\&7\251\"\STX o\EOT\NAK\171\SO\154\151z"
  , "\253x\178\194n\243\155\&9R\tm1\159\212\177\SOH\199h\173l\DC3.0E"
  ]

-- 64-byte schnorr signature
_SIG_SCHNORR :: BS.ByteString
_SIG_SCHNORR  = mconcat [
    "\214\185AtJ\189\250Gp\NAK2\221\DC2[\182\209\192j{\140^\222R\NUL~"
  , "\139d@<\138\163rh\247\152\r\228\175\236\219\156\151\214~\135\&7"
  , "\225\&6\234\220;\164R\191\170\186\243\NAK\147\f\144\156ez"
  ]

