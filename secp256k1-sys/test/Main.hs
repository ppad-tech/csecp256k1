module Main where

import Control.Exception (bracket)
import Crypto.Secp256k1.Internal
import qualified Data.ByteString as BS
import Foreign.Ptr (Ptr)
import qualified Foreign.Ptr as F (nullPtr, castPtr)
import qualified System.Entropy as E
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain units

units :: TestTree
units = testGroup "unit tests" [
    context_create
  , context_randomize
  ]

wcontext :: (Ptr Context -> IO a) -> IO a
wcontext =
  bracket
    (secp256k1_context_create _SECP256K1_CONTEXT_NONE)
    secp256k1_context_destroy

wentropy :: (Ptr Seed32 -> IO a) -> IO a
wentropy c = do
  bs <- E.getEntropy 32
  BS.useAsCStringLen bs $ \(b, _) ->
    c (F.castPtr b)

-- context

context_create :: TestTree
context_create = testCase "secp256k1_context_create (non-null)" $
  wcontext $ \tex -> assertBool "non-null" $ tex /= F.nullPtr

context_randomize :: TestTree
context_randomize = testCase "secp256k1_context_randomize (success)" $
  wcontext $ \tex -> do
    suc <- wentropy (secp256k1_context_randomize tex)
    assertBool "success" (suc == 1)

