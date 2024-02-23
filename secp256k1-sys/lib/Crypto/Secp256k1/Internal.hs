{-# LANGUAGE CApiFFI #-}

module Crypto.Secp256k1.Internal (
  -- context
    _SECP256K1_CONTEXT_NONE
  , Context
  , Seed32
  , secp256k1_context_create
  , secp256k1_context_destroy
  , secp256k1_context_randomize

  -- ec
  , secp256k1_ec_pubkey_parse
  , secp256k1_ec_pubkey_serialize
  , secp256k1_ec_pubkey_create

  -- ecdsa
  , MsgHash32
  , PubKey64
  , SecKey32
  , Sig64
  , secp256k1_ecdsa_sign
  , secp256k1_ecdsa_verify
  , secp256k1_ecdsa_signature_parse_der
  , secp256k1_ecdsa_signature_serialize_der

  -- ecdh
  -- , secp256k1_ecdh
  ) where

import Foreign.Ptr (Ptr)
import Foreign.C.Types (CUChar(..), CInt(..), CUInt(..), CSize(..))

-- context

-- secp256k1 context
data Context

-- 32-byte random seed
data Seed32

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

-- ec

-- 64-byte public key
data PubKey64

-- 32-byte secret key
data SecKey32

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_parse"
  secp256k1_ec_pubkey_parse
    :: Ptr Context
    -> Ptr PubKey64
    -> Ptr CUChar
    -> CSize
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_serialize"
  secp256k1_ec_pubkey_serialize
    :: Ptr Context
    -> Ptr CUChar
    -> Ptr CSize
    -> Ptr PubKey64
    -> CUInt
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_create"
  secp256k1_ec_pubkey_create
    :: Ptr Context
    -> Ptr PubKey64
    -> Ptr SecKey32
    -> IO CInt

-- ecdsa

-- 32-byte message hash
data MsgHash32

-- 64-byte signature
data Sig64

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_sign"
  secp256k1_ecdsa_sign
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr MsgHash32
    -> Ptr SecKey32
    -> Ptr a
    -> Ptr b
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_verify"
  secp256k1_ecdsa_verify
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr MsgHash32
    -> Ptr PubKey64
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_parse_der"
  secp256k1_ecdsa_signature_parse_der
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr CUChar
    -> CSize
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_serialize_der"
  secp256k1_ecdsa_signature_serialize_der
    :: Ptr Context
    -> Ptr CUChar
    -> Ptr CSize
    -> Ptr Sig64
    -> IO CInt


-- ecdh

-- XX seems fine, but GHC bails on call
--
-- foreign import capi
--   "secp256k1_ecdh.h haskellsecp256k1_v0_1_0_ecdh"
--   secp256k1_ecdh
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr PubKey64
--     -> Ptr SecKey32
--     -> Ptr a
--     -> Ptr b
--     -> IO CInt

-- schnorr

-- foreign import capi
--   "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_schnorrsig_sign32"
--   secp256k1_schnorrsig_sign32
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> Ptr KeyPair
--     -> Ptr CUChar
--     -> IO CInt

-- foreign import capi
--   "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_schnorrsig_verify"
--   secp256k1_schnorrsig_verify
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> CSize
--     -> Ptr XOnlyPublicKey
--     -> IO CInt
--
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_create"
-- --   secp256k1_keypair_create
-- --     :: Ptr Context
-- --     -> Ptr KeyPair
-- --     -> Ptr CUChar
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_parse"
-- --   secp256k1_xonly_pubkey_parse
-- --     :: Ptr Context
-- --     -> Ptr XOnlyPublicKey
-- --     -> Ptr CUChar
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_serialize"
-- --   secp256k1_xonly_pubkey_serialize
-- --     :: Ptr Context
-- --     -> Ptr CUChar
-- --     -> Ptr XOnlyPublicKey
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_from_pubkey"
-- --   secp256k1_xonly_pubkey_from_pubkey
-- --     :: Ptr Context
-- --     -> Ptr XOnlyPublicKey
-- --     -> Ptr CInt
-- --     -> Ptr PublicKey
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_cmp"
-- --   secp256k1_xonly_pubkey_cmp
-- --     :: Ptr Context
-- --     -> Ptr XOnlyPublicKey
-- --     -> Ptr XOnlyPublicKey
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_tweak_add"
-- --   secp256k1_xonly_pubkey_tweak_add
-- --     :: Ptr Context
-- --     -> Ptr PublicKey
-- --     -> Ptr XOnlyPublicKey
-- --     -> Ptr CUChar
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_xonly_pub"
-- --   secp256k1_keypair_xonly_pub
-- --     :: Ptr Context
-- --     -> Ptr XOnlyPublicKey
-- --     -> Ptr CInt
-- --     -> Ptr KeyPair
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_xonly_tweak_add"
-- --   secp256k1_keypair_xonly_tweak_add
-- --     :: Ptr Context
-- --     -> Ptr KeyPair
-- --     -> Ptr CUChar
-- --     -> IO CInt
-- --
-- -- foreign import capi
-- --   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_tweak_add_check"
-- --   secp256k1_xonly_pubkey_tweak_add_check
-- --     :: Ptr Context
-- --     -> Ptr CUChar
-- --     -> CInt
-- --     -> Ptr XOnlyPublicKey
-- --     -> Ptr CUChar
-- --     -> IO CInt
-- --
-- --
