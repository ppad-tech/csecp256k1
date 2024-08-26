{-# LANGUAGE CApiFFI #-}

module Crypto.Secp256k1.Internal (
  -- constants
    _DER_BYTES
  , _PUB_BYTES_INTERNAL
  , _PUB_BYTES_COMPRESSED
  , _PUB_BYTES_UNCOMPRESSED
  , _PUB_BYTES_XONLY
  , _SEC_BYTES
  , _SIG_BYTES
  , _KEYPAIR_BYTES
  , _COMPRESSED_FLAG
  , _UNCOMPRESSED_FLAG

  -- context
  , _SECP256K1_CONTEXT_NONE
  , Context
  , Seed32
  , secp256k1_context_create
  , secp256k1_context_destroy
  , secp256k1_context_randomize
  , wcontext

  -- ec
  , PubKey64
  , SecKey32
  , Tweak32
  , secp256k1_ec_pubkey_parse
  , secp256k1_ec_pubkey_serialize
  , secp256k1_ec_pubkey_create
  , secp256k1_ec_pubkey_tweak_add
  , secp256k1_ec_pubkey_tweak_mul
  , secp256k1_ec_seckey_tweak_add
  , secp256k1_ec_seckey_tweak_mul

  -- ecdsa
  , MsgHash32
  , Sig64
  , secp256k1_ecdsa_sign
  , secp256k1_ecdsa_verify
  , secp256k1_ecdsa_signature_parse_der
  , secp256k1_ecdsa_signature_serialize_der
  , secp256k1_ecdsa_signature_parse_compact
  , secp256k1_ecdsa_signature_serialize_compact

  -- ecdh
  , secp256k1_ecdh

  -- extrakeys
  , KeyPair96
  , XOnlyPublicKey64
  , secp256k1_keypair_create
  , secp256k1_keypair_sec
  , secp256k1_keypair_pub
  , secp256k1_xonly_pubkey_parse
  , secp256k1_xonly_pubkey_serialize
  , secp256k1_xonly_pubkey_from_pubkey

  -- schnorr
  , secp256k1_schnorrsig_sign32
  , secp256k1_schnorrsig_verify
  ) where

import Control.Exception (bracket)
import Foreign.Ptr (Ptr)
import Foreign.C.Types (CUChar(..), CInt(..), CUInt(..), CSize(..))

-- size constants

-- bytesize of a DER-encoded signature
_DER_BYTES :: Int
_DER_BYTES = 72

-- bytesize of an x-only pubkey
_PUB_BYTES_XONLY :: Int
_PUB_BYTES_XONLY = 32

-- bytesize of a compressed pubkey
_PUB_BYTES_COMPRESSED :: Int
_PUB_BYTES_COMPRESSED = 33

-- bytesize of an uncompressed pubkey
_PUB_BYTES_UNCOMPRESSED :: Int
_PUB_BYTES_UNCOMPRESSED = 65

-- bytesize of a secp256k1-internal pubkey
_PUB_BYTES_INTERNAL :: Int
_PUB_BYTES_INTERNAL = 64

-- bytesize of a secret key
_SEC_BYTES :: Int
_SEC_BYTES = 32

-- bytesize of a secp256k1-internal signature
_SIG_BYTES :: Int
_SIG_BYTES = 64

-- bytesize of a secp256k1-internal keypair
_KEYPAIR_BYTES :: Int
_KEYPAIR_BYTES = 96

-- flag to indicate a compressed pubkey when parsing
_COMPRESSED_FLAG :: CUInt
_COMPRESSED_FLAG = 0x0102

-- flag to indicate an uncompressed pubkey when parsing
_UNCOMPRESSED_FLAG :: CUInt
_UNCOMPRESSED_FLAG = 0x0002

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

-- returning the context itself and attempting to use it outside of a
-- 'wcontext' block will produce segfaults
wcontext :: (Ptr Context -> IO a) -> IO a
wcontext =
  bracket
    (secp256k1_context_create _SECP256K1_CONTEXT_NONE)
    secp256k1_context_destroy

-- ec

-- 64-byte public key
data PubKey64

-- 32-byte secret key
data SecKey32

-- 32-byte tweak
data Tweak32

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

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_seckey_tweak_add"
  secp256k1_ec_seckey_tweak_add
    :: Ptr Context
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_tweak_add"
  secp256k1_ec_pubkey_tweak_add
    :: Ptr Context
    -> Ptr PubKey64
    -> Ptr Tweak32
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_seckey_tweak_mul"
  secp256k1_ec_seckey_tweak_mul
    :: Ptr Context
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_tweak_mul"
  secp256k1_ec_pubkey_tweak_mul
    :: Ptr Context
    -> Ptr PubKey64
    -> Ptr Tweak32
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

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_parse_compact"
  secp256k1_ecdsa_signature_parse_compact
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr CUChar
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_serialize_compact"
  secp256k1_ecdsa_signature_serialize_compact
    :: Ptr Context
    -> Ptr CUChar
    -> Ptr Sig64
    -> IO CInt

-- ecdh

foreign import capi
  "secp256k1_ecdh.h haskellsecp256k1_v0_1_0_ecdh"
  secp256k1_ecdh
    :: Ptr Context
    -> Ptr CUChar
    -> Ptr PubKey64
    -> Ptr SecKey32
    -> Ptr a
    -> Ptr b
    -> IO CInt

-- extrakeys

data KeyPair96

data XOnlyPublicKey64

foreign import capi
  "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_create"
  secp256k1_keypair_create
    :: Ptr Context
    -> Ptr KeyPair96
    -> Ptr SecKey32
    -> IO CInt

foreign import capi
  "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_pub"
  secp256k1_keypair_pub
    :: Ptr Context
    -> Ptr PubKey64
    -> Ptr KeyPair96
    -> IO CInt

foreign import capi
  "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_sec"
  secp256k1_keypair_sec
    :: Ptr Context
    -> Ptr SecKey32
    -> Ptr KeyPair96
    -> IO CInt

foreign import capi
  "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_parse"
  secp256k1_xonly_pubkey_parse
    :: Ptr Context
    -> Ptr XOnlyPublicKey64
    -> Ptr CUChar
    -> IO CInt

foreign import capi
  "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_serialize"
  secp256k1_xonly_pubkey_serialize
    :: Ptr Context
    -> Ptr CUChar
    -> Ptr XOnlyPublicKey64
    -> IO CInt

foreign import capi
  "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_from_pubkey"
  secp256k1_xonly_pubkey_from_pubkey
    :: Ptr Context
    -> Ptr XOnlyPublicKey64
    -> Ptr CInt
    -> Ptr PubKey64
    -> IO CInt

-- schnorr

foreign import capi
  "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_schnorrsig_sign32"
  secp256k1_schnorrsig_sign32
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr MsgHash32
    -> Ptr KeyPair96
    -> Ptr CUChar
    -> IO CInt

foreign import capi
  "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_schnorrsig_verify"
  secp256k1_schnorrsig_verify
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr CUChar
    -> CSize
    -> Ptr XOnlyPublicKey64
    -> IO CInt

