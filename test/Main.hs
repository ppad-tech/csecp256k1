{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import Crypto.Secp256k1
import qualified System.Entropy as E
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain units

units :: TestTree
units = testGroup "unit tests" [
  ]

-- XX check rust-secp256k1 for examples
--    more generally, any secret key can provide a pubkey; the issue is in
--    knowing the implementation is performing correctly.
--
--    i can likely use secp256k1-haskell to confirm same behaviour, though.


