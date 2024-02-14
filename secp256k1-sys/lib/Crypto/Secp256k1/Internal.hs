{-# LANGUAGE CApiFFI #-}

module Crypto.Secp256k1.Internal (
  -- context
    Context
  , Seed32
  , secp256k1_context_create
  , secp256k1_context_destroy
  , secp256k1_context_randomize

  -- ecdsa
  , NonceFn
  , Nonce32
  , MsgHash32
  , PubKey64
  , SecKey32
  , Sig64
  , Algo16
  , secp256k1_nonce_function_rfc6979
  , secp256k1_nonce_function_default
  , secp256k1_ecdsa_verify
  , secp256k1_ecdsa_sign
  , secp256k1_ecdsa_signature_normalize
  , secp256k1_ecdsa_signature_parse_der
  , secp256k1_ecdsa_signature_serialize_der
  , secp256k1_ecdsa_signature_serialize_compact
  ) where

import Foreign.Ptr (Ptr)
import Foreign.C.Types (CUChar(..), CInt(..), CUInt(..), CSize(..))

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

-- ecdsa

-- 32-byte array
data Nonce32

-- 32-byle message hash
data MsgHash32

-- 16-byte signature algorithm description
data Algo16

-- 64-byte signature
data Sig64

-- 64-byte public key
data PubKey64

-- 32-byte secret key
data SecKey32

-- 32-byte secret key
data Bytes64

-- deterministic nonce function
newtype NonceFn a = NonceFn (
     Ptr Nonce32
  -> Ptr MsgHash32
  -> Ptr SecKey32
  -> Ptr Algo16
  -> Ptr a
  -> CUInt
  -> IO CInt
  )

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_nonce_function_rfc6979"
  secp256k1_nonce_function_rfc6979
    :: NonceFn a

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_nonce_function_default"
  secp256k1_nonce_function_default
    :: NonceFn a

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_verify"
  secp256k1_ecdsa_verify
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr MsgHash32
    -> Ptr PubKey64
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_sign"
  secp256k1_ecdsa_sign
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr MsgHash32
    -> Ptr SecKey32
    -> Ptr (NonceFn a) -- XX check
    -> Ptr b
    -> IO CInt

foreign import capi
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_normalize"
  secp256k1_ecdsa_signature_normalize
    :: Ptr Context
    -> Ptr Sig64
    -> Ptr Sig64
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
  "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_serialize_compact"
  secp256k1_ecdsa_signature_serialize_compact
    :: Ptr Context
    -> Ptr Bytes64
    -> Ptr Sig64
    -> IO CInt









-- XX ideally the context should be represented using a storable instance,
--    which would enable 'mallocForeignPtr', which apparently has a heavily
--    optimised implementation in GHC
-- newtype ForeignContext = ForeignContext (ForeignPtr Context)

-- create = bracket acquire release



-- createContext :: IO Ctx
-- createContext = do
--   ctx <- mask_ $ do
--     pctx <- contextCreate signVerify
--     Ctx <$> newForeignPtr contextDestroyFunPtr pctx
--   randomizeContext ctx
--   return ctx
--
-- cloneContext :: Ctx -> IO Ctx
-- cloneContext (Ctx fctx) =
--   withForeignPtr fctx $ \ctx -> mask_ $ do
--     ctx' <- contextClone ctx
--     Ctx <$> newForeignPtr contextDestroyFunPtr ctx'
--
-- destroyContext :: Ctx -> IO ()
-- destroyContext (Ctx fctx)= finalizeForeignPtr fctx

-- randomizeContext :: Ctx -> IO ()
-- randomizeContext (Ctx fctx) = withForeignPtr fctx $ \ctx -> do
--   ret <- withRandomSeed $ contextRandomize ctx
--   unless (isSuccess ret) $ error "Could not randomize context"










-- -- Hash function to use to post-process an ECDH point to get
-- -- a shared secret.
-- newtype EcdhHashFn a = EcdhHashFn (
--      Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr a
--   -> IO CInt
--   )
--
-- -- Same as secp256k1_nonce function with the exception of accepting an
-- -- additional pubkey argument and not requiring an attempt argument.
-- -- The pubkey argument can protect signature schemes with key-prefixed
-- -- challenge hash inputs against reusing the nonce when signing with the
-- -- wrong precomputed pubkey.
-- newtype SchnorrNonceFn a = SchnorrNonceFn (
--      Ptr CUChar
--   -> Ptr CUChar
--   -> CSize
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> CSize
--   -> Ptr a
--   -> IO CInt
--   )
--
--
-- -- A hash function used by `ellswift_ecdh` to hash the final ECDH shared
-- -- secret.
-- newtype EllswiftEcdhHashFn a = EllswiftEcdhHashFn (
--      Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr a
--   -> IO CInt
--   )
--
-- newtype EllswiftXdhHashFn a = EllswiftXdhHashFn (
--      Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr CUChar
--   -> Ptr a
--   -> IO CInt
--   )
--
-- -- Data structure that contains additional arguments for
-- -- schnorrsig_sign_custom.
-- data SchnorrSigExtraParams a =
--   SchnorrSigExtraParams
--     !BS.ByteString       -- magic
--     (SchnorrNonceFn a)  -- nonce_fp
--     (forall b. Ptr b)   -- ndata
--
-- -- Create a new SchnorrSigExtraParams properly initialized.
-- --
-- -- `nonce_fp`: pointer to a nonce generation function. If NULL
-- -- haskellsecp256k1_v0_5_0_nonce_function_bip340 is used
-- --
-- -- `ndata`: pointer to arbitrary data used by the nonce
-- -- generation function (can be NULL). If it is non-NULL and
-- -- haskellsecp256k1_v0_5_0_nonce_function_bip340 is used, then ndata
-- -- must be a pointer to 32-byte auxiliary randomness as per BIP-340.
-- new_SchnorrSigExtraParams
--   :: SchnorrNonceFn a
--   -> (forall b. Ptr b)
--   -> SchnorrSigExtraParams a
-- new_SchnorrSigExtraParams nonce_fp ndata =
--   let magic = BS.pack [0xda, 0x6f, 0xb3, 0x8c]
--   in  SchnorrSigExtraParams magic nonce_fp ndata
--
-- -- A Secp256k1 context, containing various precomputed values and
-- -- such needed to do elliptic curve computations.
-- newtype Context = Context CInt
--
-- -- Library-internal representation of a Secp256k1 public key
-- newtype PublicKey = PublicKey BS.ByteString
--
-- -- Library-internal representation of a Secp256k1 secret key (32-byte)
-- newtype SecretKey = SecretKey BS.ByteString
--
-- -- Library-internal representation of a Secp256k1 signature
-- newtype Signature = Signature BS.ByteString
--
-- newtype XOnlyPublicKey = XOnlyPublicKey BS.ByteString
--
-- newtype KeyPair = KeyPair BS.ByteString
--
-- -- Library-internal representation of a ElligatorSwift encoded group element.
-- newtype ElligatorSwift = ElligatorSwift BS.ByteString


-- -- Default ECDH hash function
-- foreign import capi
--   "secp256k1_ecdh.h haskellsecp256k1_v0_1_0_ecdh_hash_function_default"
--   secp256k1_ecdh_hash_function_default :: EcdhHashFn a
--
-- -- Default ECDH hash function for BIP324 key establishment
-- foreign import capi
--   "secp256k1_ellswift.h haskellsecp256k1_v0_1_0_ellswift_xdh_hash_function_bip324"
--   secp256k1_ellswift_xdh_hash_function_bip324 :: EllswiftEcdhHashFn a
--
-- foreign import capi
--   "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_nonce_function_bip340"
--   secp256k1_nonce_function_bip340 :: SchnorrNonceFn a
--
-- -- XX suspected won't compile
-- --
-- --     #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_9_2_context_no_precomp")]
-- --     pub static secp256k1_context_no_precomp: *const Context;
-- --
-- --     // Contexts
-- --     #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_9_2_context_preallocated_destroy")]
-- --     pub fn secp256k1_context_preallocated_destroy(cx: NonNull<Context>);
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_parse_der"
--   secp256k1_ecdsa_signature_parse_der
--     :: Ptr Context
--     -> Ptr Signature
--     -> Ptr CUChar
--     -> CSize
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ecdsa_signature_parse_compact"
--   secp256k1_ecdsa_signature_parse_compact
--     :: Ptr Context
--     -> Ptr Signature
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_seckey_verify"
--   secp256k1_ec_seckey_verify
--     :: Ptr Context
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_seckey_negate"
--   secp256k1_ec_seckey_negate
--     :: Ptr Context
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_seckey_tweak_add"
--   secp256k1_ec_seckey_tweak_add
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_seckey_tweak_mul"
--   secp256k1_ec_seckey_tweak_mul
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_sec"
--   secp256k1_keypair_sec
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr KeyPair
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_pub"
--   secp256k1_keypair_pub
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr KeyPair
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_ellswift.h haskellsecp256k1_v0_1_0_ellswift_encode"
--   secp256k1_ellswift_encode
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr PublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_ellswift.h haskellsecp256k1_v0_1_0_ellswift_decode"
--   secp256k1_ellswift_decode
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_ellswift.h haskellsecp256k1_v0_1_0_ellswift_create"
--   secp256k1_ellswift_create
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr SecretKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- -- XX check pointer to hash function
-- --
-- foreign import capi
--   "secp256k1_ellswift.h haskellsecp256k1_v0_1_0_ellswift_xdh"
--   secp256k1_ellswift_xdh
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> CInt
--     -> Ptr (EllswiftXdhHashFn a) -- <- problem
--     -> Ptr b
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_preallocated.h haskellsecp256k1_v0_1_0_context_preallocated_size"
--   secp256k1_context_preallocated_size
--     :: CUInt
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_preallocated.h haskellsecp256k1_v0_1_0_context_preallocated_create"
--   secp256k1_context_preallocated_create
--     :: Ptr CUChar         -- XX maybe be precise that this is *void; non null
--     -> CUInt
--     -> IO (Ptr Context)   -- non null
--
-- foreign import capi
--   "secp256k1_preallocated.h haskellsecp256k1_v0_1_0_context_preallocated_clone_size"
--   secp256k1_context_preallocated_clone_size
--     :: Ptr Context
--     -> IO CSize -- pure?
--
-- foreign import capi
--   "secp256k1_preallocated.h haskellsecp256k1_v0_1_0_context_preallocated_clone"
--   secp256k1_context_preallocated_clone
--     :: Ptr Context
--     -> Ptr a               -- non null
--     -> IO (Ptr Context)
--
-- foreign import capi
--   "secp256k1_preallocated.h haskellsecp256k1_v0_1_0_context_randomize"
--   secp256k1_context_randomize
--     :: Ptr Context         -- non null
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_parse"
--   secp256k1_ec_pubkey_parse
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr CUChar
--     -> CSize
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_serialize"
--   secp256k1_ec_pubkey_serialize
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CSize
--     -> Ptr PublicKey
--     -> CUInt
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_create"
--   secp256k1_ec_pubkey_create
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_negate"
--   secp256k1_ec_pubkey_negate
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_cmp"
--   secp256k1_ec_pubkey_cmp
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr PublicKey
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_tweak_add"
--   secp256k1_ec_pubkey_tweak_add
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_tweak_mul"
--   secp256k1_ec_pubkey_tweak_mul
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- -- XX requires ccall?
-- --
-- -- foreign import capi
-- --   "secp256k1.h haskellsecp256k1_v0_1_0_ec_pubkey_combine"
-- --   secp256k1_ec_pubkey_combine
-- --     :: Ptr Context
-- --     -> Ptr PublicKey
-- --     -> Ptr (Ptr PublicKey) -- array of pubkeys
-- --     -> CSize
-- --     -> IO CInt
--
-- -- XX problem including hash function
-- --
-- -- foreign import capi
-- --   "secp256k1.h haskellsecp256k1_v0_1_0_ecdh"
-- --   secp256k1_ecdh
-- --     :: Ptr Context
-- --     -> Ptr CUChar
-- --     -> Ptr PublicKey
-- --     -> Ptr CUChar
-- --     -> EcdhHashFn a
-- --     -> Ptr b
-- --     -> IO CInt

-- -- XX s/sign/sign32 following compiler warning
-- --
-- foreign import capi
--   "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_schnorrsig_sign32"
--   secp256k1_schnorrsig_sign32
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> Ptr KeyPair
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_schnorrsig.h haskellsecp256k1_v0_1_0_schnorrsig_sign_custom"
--   secp256k1_schnorrsig_sign_custom
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr CUChar
--     -> CSize
--     -> Ptr KeyPair
--     -> Ptr (SchnorrSigExtraParams a)
--     -> IO CInt
--
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
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_create"
--   secp256k1_keypair_create
--     :: Ptr Context
--     -> Ptr KeyPair
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_parse"
--   secp256k1_xonly_pubkey_parse
--     :: Ptr Context
--     -> Ptr XOnlyPublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_serialize"
--   secp256k1_xonly_pubkey_serialize
--     :: Ptr Context
--     -> Ptr CUChar
--     -> Ptr XOnlyPublicKey
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_from_pubkey"
--   secp256k1_xonly_pubkey_from_pubkey
--     :: Ptr Context
--     -> Ptr XOnlyPublicKey
--     -> Ptr CInt
--     -> Ptr PublicKey
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_cmp"
--   secp256k1_xonly_pubkey_cmp
--     :: Ptr Context
--     -> Ptr XOnlyPublicKey
--     -> Ptr XOnlyPublicKey
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_tweak_add"
--   secp256k1_xonly_pubkey_tweak_add
--     :: Ptr Context
--     -> Ptr PublicKey
--     -> Ptr XOnlyPublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_xonly_pub"
--   secp256k1_keypair_xonly_pub
--     :: Ptr Context
--     -> Ptr XOnlyPublicKey
--     -> Ptr CInt
--     -> Ptr KeyPair
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_keypair_xonly_tweak_add"
--   secp256k1_keypair_xonly_tweak_add
--     :: Ptr Context
--     -> Ptr KeyPair
--     -> Ptr CUChar
--     -> IO CInt
--
-- foreign import capi
--   "secp256k1_extrakeys.h haskellsecp256k1_v0_1_0_xonly_pubkey_tweak_add_check"
--   secp256k1_xonly_pubkey_tweak_add_check
--     :: Ptr Context
--     -> Ptr CUChar
--     -> CInt
--     -> Ptr XOnlyPublicKey
--     -> Ptr CUChar
--     -> IO CInt
--
--
