{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Secp256k1 as S
import qualified Data.ByteString as BS

instance NFData S.KeyPair
instance NFData S.Pub
instance NFData S.Sig
instance NFData S.XOnlyPub

main :: IO ()
main = defaultMain [
    sign
  ]

sign :: Benchmark
sign = bgroup "sign" [
      bench "sign" . nfIO $ sign_bench _HAS _SEC
    , bench "sign_schnorr" . nfIO $
        sign_schnorr_bench _HAS _SEC (BS.replicate 32 0)
    ]
  where
    sign_bench has sec = S.wcontext $ \tex ->
      S.sign tex sec has

    sign_schnorr_bench has sec enn = S.wcontext $ \tex ->
      S.sign_schnorr tex has sec enn

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

