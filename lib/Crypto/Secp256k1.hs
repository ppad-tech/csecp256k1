{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.Secp256k1
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
--
-- Maintainer: Jared Tobin <jared@ppad.tech>
-- Stability: stable
-- Portability: portable
--
-- Bindings to bitcoin-core/secp256k1, which "provides digital
-- signatures and other cryptographic primitives on the secp256k1
-- elliptic curve."
--
-- This library exposes a minimal subset of functionality, primarily
-- supporting ECDSA/Schnorr signatures and ECDH secret computation.

module Crypto.Secp256k1 (
    -- exceptions
    Secp256k1Exception(..)

    -- context
  , Context
  , wcontext
  , wrcontext

    -- ec
  , Pub
  , derive_pub
  , parse_pub
  , serialize_pub
  , serialize_pub_u

    -- ecdsa
  , Sig
  , sign
  , verify
  , parse_der
  , serialize_der

    -- ecdh
  , ecdh

    -- extrakeys
  , XOnlyPub
  , xonly
  , parse_xonly
  , serialize_xonly

  , KeyPair
  , create_keypair
  , keypair_pub
  , keypair_sec

    -- schnorr
  , sign_schnorr
  , verify_schnorr
  ) where

import Control.Exception (Exception, bracket, throwIO)
import Control.Monad (when)
import Crypto.Secp256k1.Internal hiding (Context)
import qualified Crypto.Secp256k1.Internal as I (Context)
import qualified Data.ByteString as BS
import qualified Foreign.Marshal.Alloc as A (alloca, allocaBytes)
import Foreign.Ptr (Ptr)
import qualified Foreign.Ptr as F (castPtr, nullPtr)
import qualified Foreign.Storable as S (poke, peek)

-- | A bitcoin-core/secp256k1 context.
--
--   bitcoin-core/secp256k1 computations typically require a context,
--   the primary purpose of which is to store randomization data as
--   increased protection against side-channel attacks (and the second
--   of which is boring pointer storage to various library callbacks).
--
--   You should create and use values of this type via 'wrcontext' or
--   'wcontext'.
newtype Context = Context (Ptr I.Context)

instance Show Context where
  show (Context tex) = "<bitcoin-core/secp256k1 context " <> show tex <> ">"

-- | A bitcoin-core/secp256k1-internal public key.
--
--   Create a value of this type by parsing a compressed or uncompressed
--   public key via 'parse_pub', deriving one from a secret key via
--   'create_pub', or extracting one from a keypair via 'keypair_pub'.
newtype Pub = Pub BS.ByteString

instance Show Pub where
  show _ = "<bitcoin-core/secp256k1 public key>"

-- | A bitcoin-core/secp256k1-internal x-only public key.
--
--   An "x-only" public key corresponds to a public key with even
--   y-coordinate.
--
--   Create a value of this type from a 'Pub' via 'xonly', or parse one
--   directly via 'parse_xonly'.
newtype XOnlyPub = XOnlyPub BS.ByteString

instance Show XOnlyPub where
  show _ = "<bitcoin-core/secp256k1 x-only public key>"

-- | A bitcoin-core/secp256k1-internal public/secret keypair.
--
--   Create a value of this type by passing a secret key to
--   'create_keypair'.
newtype KeyPair = KeyPair BS.ByteString

instance Show KeyPair where
  show _ = "<bitcoin-core/secp256k1 keypair>"

-- | A bitcoin-core/secp256k1-internal ECDSA signature.
--
--   Create a value of this type via 'sign', or parse a DER-encoded
--   signature via 'parse_der'.
newtype Sig = Sig BS.ByteString

instance Show Sig where
  show _ = "<bitcoin-core/secp256k1 signature>"

-- exceptions

-- | A catch-all exception type.
--
--   Internal library errors (i.e., non-unit return values in the
--   underlying C functions) will typically throw a Secp256k1Error
--   exception.
data Secp256k1Exception =
    Secp256k1Error
  | InsufficientEntropy
  deriving Show

instance Exception Secp256k1Exception

-- context

-- | Execute the supplied continuation within a fresh
--   bitcoin-core/secp256k1 context. The context will be destroyed
--   afterwards.
--
--   This function executes the supplied continuation in a context
--   that has /not/ been randomized, and so /doesn't/ offer additional
--   side-channel attack protection. For that, use 'wrcontext'.
--
--   >>> wcontext $ \tex -> parse_pub tex bytestring
--   "<bitcoin-core/secp256k1 public key>"
wcontext :: (Context -> IO a) -> IO a
wcontext = bracket create destroy where
  create = do
    tex <- secp256k1_context_create _SECP256K1_CONTEXT_NONE
    pure (Context tex)

  destroy (Context tex) =
    secp256k1_context_destroy tex

-- | Same as 'wcontext', but randomize the bitcoin-core/secp256k1
--   context with the provided entropy before executing the supplied
--   continuation.
--
--   You must supply at least 32 bytes of entropy; any less will result
--   in an InsufficientEntropy exception.
--
--   >>> wrcontext entropy $ \tex -> sign tex sec msg
--   "<bitcoin-core/secp256k1 signature>"
wrcontext :: BS.ByteString -> (Context -> IO a) -> IO a
wrcontext enn con
    | BS.length enn < 32 = throwIO InsufficientEntropy
    | otherwise = bracket create destroy con
  where
    create = do
      tex <- secp256k1_context_create _SECP256K1_CONTEXT_NONE
      BS.useAsCString enn $ \(F.castPtr -> sed) -> do
        suc <- secp256k1_context_randomize tex sed
        when (suc /= 1) $ throwIO Secp256k1Error
        pure (Context tex)

    destroy (Context tex) =
      secp256k1_context_destroy tex

-- ec

-- | Derive a public key from a 32-byte secret key.
--
--   The size of the input is not checked.
--
--   >>> wrcontext entropy $ \tex -> derive_pub tex sec
--   "<bitcoin-core/secp256k1 public key>"
derive_pub :: Context -> BS.ByteString -> IO Pub
derive_pub (Context tex) bs =
  BS.useAsCString bs $ \(F.castPtr -> sec) ->
    A.allocaBytes _PUB_BYTES_INTERNAL $ \out -> do
      suc <- secp256k1_ec_pubkey_create tex out sec
      when (suc /= 1) $ throwIO Secp256k1Error
      let pub = F.castPtr out
      key <- BS.packCStringLen (pub, _PUB_BYTES_INTERNAL)
      pure (Pub key)

-- | Parse a compressed (33-byte) or uncompressed (65-byte) public key.
--
--   The size of the input is not checked.
--
--   >>> wcontext $ \tex -> parse_pub tex bs
--   "<bitcoin-core/secp256k1 public key>"
parse_pub :: Context -> BS.ByteString -> IO Pub
parse_pub (Context tex) bs =
  BS.useAsCStringLen bs $ \(F.castPtr -> pub, fromIntegral -> len) ->
    A.allocaBytes _PUB_BYTES_INTERNAL $ \out -> do
      suc <- secp256k1_ec_pubkey_parse tex out pub len
      when (suc /= 1) $ throwIO Secp256k1Error
      let par = F.castPtr out
      key <- BS.packCStringLen (par, _PUB_BYTES_INTERNAL)
      pure (Pub key)

data PubFormat =
    Compressed
  | Uncompressed

-- | Serialize a public key into a compressed (33-byte) bytestring
--   representation.
--
--   >>> wcontext $ \tex -> serialize_pub tex pub
serialize_pub :: Context -> Pub -> IO BS.ByteString
serialize_pub = serialize_pub_in Compressed

-- | Serialize a public key into an uncompressed (65-byte) bytestring
--   represention.
--
--   >>> wcontext $ \tex -> serialize_pub_u tex pub
serialize_pub_u :: Context -> Pub -> IO BS.ByteString
serialize_pub_u = serialize_pub_in Uncompressed

serialize_pub_in :: PubFormat -> Context -> Pub -> IO BS.ByteString
serialize_pub_in for (Context tex) (Pub pub) =
    BS.useAsCString pub $ \(F.castPtr -> key) ->
      A.alloca $ \len ->
        A.allocaBytes bys $ \out -> do
          let siz = fromIntegral bys
          S.poke len siz
          suc <- secp256k1_ec_pubkey_serialize tex out len key fal
          when (suc /= 1) $ throwIO Secp256k1Error
          pec <- S.peek len
          let enc = F.castPtr out
              nel = fromIntegral pec
          BS.packCStringLen (enc, nel)
  where
    bys = case for of
      Compressed -> _PUB_BYTES_COMPRESSED
      Uncompressed -> _PUB_BYTES_UNCOMPRESSED

    fal = case for of
      Compressed -> _COMPRESSED_FLAG
      Uncompressed -> _UNCOMPRESSED_FLAG

-- ecdsa

-- | Sign a 32-byte message hash with the provided secret key.
--
--   The sizes of the inputs are not checked.
--
--   >>> wrcontext entropy $ \tex -> sign tex sec msg
--   "<bitcoin-core/secp256k1 signature>"
sign :: Context -> BS.ByteString -> BS.ByteString -> IO Sig
sign (Context tex) key msg =
  A.allocaBytes _SIG_BYTES $ \out ->
    BS.useAsCString msg $ \(F.castPtr -> has) ->
      BS.useAsCString key $ \(F.castPtr -> sec) -> do
        suc <- secp256k1_ecdsa_sign tex out has sec F.nullPtr F.nullPtr
        when (suc /= 1) $ throwIO Secp256k1Error
        let sig = F.castPtr out
        enc <- BS.packCStringLen (sig, _SIG_BYTES)
        pure (Sig enc)

-- | Verify an ECDSA signature for the provided message hash with the
--   supplied public key.
--
--   Returns 'True' for a verifying signature, 'False' otherwise.
--
--   The size of the input is not checked.
--
--   >>> wcontext $ \tex -> verify tex pub msg good_sig
--   True
--   >>> wcontext $ \tex -> verify tex pub msg bad_sig
--   False
verify :: Context -> Pub -> BS.ByteString -> Sig -> IO Bool
verify (Context tex) (Pub pub) msg (Sig sig) =
  BS.useAsCString pub $ \(F.castPtr -> key) ->
    BS.useAsCString sig $ \(F.castPtr -> sip) ->
      BS.useAsCString msg $ \(F.castPtr -> has) -> do
        suc <- secp256k1_ecdsa_verify tex sip has key
        pure (suc == 1)

-- | Parse a DER-encoded bytestring into a signature.
--
--   >>> wcontext $ \tex -> parse_der tex bytestring
--   "<bitcoin-core/secp256k1 signature>"
--   >>> wcontext $ \tex -> parse_der tex bad_bytestring
--   *** Exception: Secp256k1Error
parse_der :: Context -> BS.ByteString -> IO Sig
parse_der (Context tex) bs =
  BS.useAsCStringLen bs $ \(F.castPtr -> der, fromIntegral -> len) ->
    A.allocaBytes _SIG_BYTES $ \out -> do
      suc <- secp256k1_ecdsa_signature_parse_der tex out der len
      when (suc /= 1) $ throwIO Secp256k1Error
      let par = F.castPtr out
      sig <- BS.packCStringLen (par, _SIG_BYTES)
      pure (Sig sig)

-- | Serialize a signature into a DER-encoded bytestring.
--
--   >>> wcontext $ \tex -> serialize_der tex sig
serialize_der :: Context -> Sig  -> IO BS.ByteString
serialize_der (Context tex) (Sig sig) =
  A.alloca $ \len ->
    A.allocaBytes _DER_BYTES $ \out ->
      BS.useAsCString sig $ \(F.castPtr -> sip) -> do
        let siz = fromIntegral _DER_BYTES
        S.poke len siz
        suc <- secp256k1_ecdsa_signature_serialize_der tex out len sip
        when (suc /= 1) $ throwIO Secp256k1Error
        pek <- S.peek len
        let der = F.castPtr out
            nel = fromIntegral pek
        BS.packCStringLen (der, nel)

-- extrakeys

-- | Convert a public key into an x-only public key (i.e. one with even
--   y coordinate).
--
--   >>> wcontext $ \tex -> xonly tex pub
--   "<bitcoin-core/secp256k1 x-only public key>"
xonly :: Context -> Pub -> IO XOnlyPub
xonly (Context tex) (Pub pub) =
  A.allocaBytes _PUB_BYTES_INTERNAL $ \out ->
    BS.useAsCString pub $ \(F.castPtr -> pup) -> do
      -- returns 1 always
      _ <- secp256k1_xonly_pubkey_from_pubkey tex out F.nullPtr pup
      let key = F.castPtr out
      pux <- BS.packCStringLen (key, _PUB_BYTES_INTERNAL)
      pure (XOnlyPub pux)

-- | Parse a compressed (33-byte) or uncompressed (65-byte) public key into
--   an x-only public key.
--
--   The size of the input is not checked.
--
--   >>> wcontext $ \tex -> parse_xonly tex bytestring
--   "<bitcoin-core/secp256k1 x-only public key>"
parse_xonly :: Context -> BS.ByteString -> IO XOnlyPub
parse_xonly (Context tex) bs =
  A.allocaBytes _PUB_BYTES_INTERNAL $ \out ->
    BS.useAsCString bs $ \(F.castPtr -> pub) -> do
      suc <- secp256k1_xonly_pubkey_parse tex out pub
      when (suc /= 1) $ throwIO Secp256k1Error
      let key = F.castPtr out
      pux <- BS.packCStringLen (key, _PUB_BYTES_INTERNAL)
      pure (XOnlyPub pux)

-- | Serialize an x-only public key into a 32-byte bytestring
--   representation.
--
--   >>> wcontext $ \tex -> serialize_xonly tex xonly
serialize_xonly :: Context -> XOnlyPub -> IO BS.ByteString
serialize_xonly (Context tex) (XOnlyPub pux) =
  A.allocaBytes _PUB_BYTES_XONLY $ \out -> do
    BS.useAsCString pux $ \(F.castPtr -> pub) -> do
      -- returns 1 always
      _ <- secp256k1_xonly_pubkey_serialize tex out pub
      let enc = F.castPtr out
      BS.packCStringLen (enc, _PUB_BYTES_XONLY)

-- | Derive a keypair from the provided 32-byte secret key.
--
--   The size of the input is not checked.
--
--   >>> wrcontext entropy $ \tex -> create_keypair tex sec
--   "<bitcoin-core/secp256k1 keypair>"
create_keypair :: Context -> BS.ByteString -> IO KeyPair
create_keypair (Context tex) sec =
  A.allocaBytes _KEYPAIR_BYTES $ \out ->
    BS.useAsCString sec $ \(F.castPtr -> key) -> do
      suc <- secp256k1_keypair_create tex out key
      when (suc /= 1) $ throwIO Secp256k1Error
      let enc = F.castPtr out
      per <- BS.packCStringLen (enc, _KEYPAIR_BYTES)
      pure (KeyPair per)

-- | Extract a public key from a keypair.
--
--   >>> wrcontext entropy $ \tex -> keypair_pub tex keypair
--   "<bitcoin-core/secp256k1 public key>"
keypair_pub :: Context -> KeyPair -> IO Pub
keypair_pub (Context tex) (KeyPair per) =
  A.allocaBytes _PUB_BYTES_INTERNAL $ \out ->
    BS.useAsCString per $ \(F.castPtr -> par) -> do
      -- returns 1 always
      _ <- secp256k1_keypair_pub tex out par
      let enc = F.castPtr out
      pub <- BS.packCStringLen (enc, _PUB_BYTES_INTERNAL)
      pure (Pub pub)

-- | Extract a secret key from a keypair.
--
--   >>> wrcontext entropy $ \tex -> keypair_sec tex keypair
keypair_sec :: Context -> KeyPair -> IO BS.ByteString
keypair_sec (Context tex) (KeyPair per) =
  A.allocaBytes _SEC_BYTES $ \out ->
    BS.useAsCString per $ \(F.castPtr -> par) -> do
      _ <- secp256k1_keypair_sec tex out par
      let enc = F.castPtr out
      BS.packCStringLen (enc, _SEC_BYTES)

-- ecdh

-- | Compute an ECDH secret from the provided public and (32-byte)
--   secret key.
--
--   The size of the input is not checked.
--
--   >>> wrcontext entropy $ \tex -> ecdh tex pub sec
ecdh :: Context -> Pub -> BS.ByteString -> IO BS.ByteString
ecdh (Context tex) (Pub pub) sec =
  A.allocaBytes _SEC_BYTES $ \out ->
    BS.useAsCString pub $ \(F.castPtr -> pup) ->
      BS.useAsCString sec $ \(F.castPtr -> sep) -> do
        suc <- secp256k1_ecdh tex out pup sep F.nullPtr F.nullPtr
        when (suc /= 1) $ throwIO Secp256k1Error
        let key = F.castPtr out
        BS.packCStringLen (key, _SEC_BYTES)

-- schnorr

-- | Sign a 32-byte message hash with the provided secret key.
--
--   BIP340 recommends that 32 bytes of auxiliary entropy be added when
--   signing, and bitcoin-core/secp256k1 allows this, but the added
--   entropy is only supplemental to security, and is not required. We
--   omit the feature here, for API simplicity.
--
--   The resulting 64-byte signature is safe to serialize, and so is not
--   wrapped in a newtype.
--
--   The sizes of the inputs are not checked.
--
--   >>> wrcontext entropy $ \tex -> sign_schnorr tex msg sec
sign_schnorr :: Context -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
sign_schnorr c@(Context tex) msg sec =
  A.allocaBytes _SIG_BYTES $ \out ->
    BS.useAsCString msg $ \(F.castPtr -> has) -> do
      KeyPair per <- create_keypair c sec
      BS.useAsCString per $ \(F.castPtr -> pur) -> do
        suc <- secp256k1_schnorrsig_sign32 tex out has pur F.nullPtr
        when (suc /= 1) $ throwIO Secp256k1Error
        let enc = F.castPtr out
        BS.packCStringLen (enc, _SIG_BYTES)

-- | Verify a 64-byte Schnorr signature for the provided 32-byte message
--   hash with the supplied public key.
--
--   The sizes of the inputs are not checked.
--
--   >>> wrcontext entropy $ \tex -> verify_schnorr tex pub msg sig
verify_schnorr :: Context -> Pub -> BS.ByteString -> BS.ByteString -> IO Bool
verify_schnorr c@(Context tex) pub msg sig =
  BS.useAsCString sig $ \(F.castPtr -> sip) ->
    BS.useAsCStringLen msg $ \(F.castPtr -> has, fromIntegral -> len) -> do
      XOnlyPub pux <- xonly c pub
      BS.useAsCString pux $ \(F.castPtr -> pax) -> do
        suc <- secp256k1_schnorrsig_verify tex sip has len pax
        pure (suc == 1)

