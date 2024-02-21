{-# LANGUAGE CApiFFI #-}

module Crypto.Secp256k1.Internal (
  -- context
    _SECP256K1_CONTEXT_NONE
  , Context
  , Seed32
  , secp256k1_context_create
  , secp256k1_context_destroy
  , secp256k1_context_randomize
  ) where

import Foreign.Ptr (Ptr)
import Foreign.C.Types (CInt(..), CUInt(..))

data Context

-- 32-byte random seed
data Seed32

-- context

-- per secp256k1.h:
--
--  > The only valid non-deprecated flag in recent library versions is
--  > SECP256K1_CONTEXT_NONE, which will create a context sufficient for
--  > all functionality
--
-- where SECP256K1_CONTEXT_NONE = 1, via:
--
-- #define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
-- #define SECP256K1_CONTEXT_NONE (SECP256K1_FLAGS_TYPE_CONTEXT)
_SECP256K1_CONTEXT_NONE :: Integral a => a
_SECP256K1_CONTEXT_NONE = 1

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_context_create"
  secp256k1_context_create
    :: CUInt
    -> IO (Ptr Context)

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_context_destroy"
  secp256k1_context_destroy
    :: Ptr Context
    -> IO ()

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_context_randomize"
  secp256k1_context_randomize
    :: Ptr Context
    -> Ptr Seed32
    -> IO CInt

