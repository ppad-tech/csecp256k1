{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

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

-- | A secp256k1 context.
newtype Context = Context (Ptr I.Context)

-- | A secp256k1-internal public key.
newtype Pub = Pub BS.ByteString

-- | A secp256k1-internal x-only public key.
newtype XOnlyPub = XOnlyPub BS.ByteString

-- | A secp256k1-internal public/secret keypair.
newtype KeyPair = KeyPair BS.ByteString

-- | A secp256k1-internal ECDSA signature.
newtype Sig = Sig BS.ByteString

-- exceptions

data Secp256k1Exception =
    Secp256k1Error
  | InsufficientEntropy
  | Bip340Error
  deriving Show

instance Exception Secp256k1Exception

-- context

-- | Execute the supplied continuation within a fresh secp256k1 context.
--   The context will be destroyed afterwards.
wcontext :: (Context -> IO a) -> IO a
wcontext = bracket create destroy where
  create = do
    tex <- secp256k1_context_create _SECP256K1_CONTEXT_NONE
    pure (Context tex)

  destroy (Context tex) =
    secp256k1_context_destroy tex

-- | Same as 'wcontext', but randomize the secp256k1 context via the
--   provided entropy before executing the supplied continuation.
--
--   You must supply at least 32 bytes of entropy; any less will result
--   in an InsufficientEntropy exception.
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
serialize_pub :: Context -> Pub -> IO BS.ByteString
serialize_pub = serialize_pub_in Compressed

-- | Serialize a public key into an uncompressed (65-byte) bytestring
--   represention.
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
verify :: Context -> Pub -> BS.ByteString -> Sig -> IO Bool
verify (Context tex) (Pub pub) msg (Sig sig) =
  BS.useAsCString pub $ \(F.castPtr -> key) ->
    BS.useAsCString sig $ \(F.castPtr -> sip) ->
      BS.useAsCString msg $ \(F.castPtr -> has) -> do
        suc <- secp256k1_ecdsa_verify tex sip has key
        pure (suc == 1)

-- | Parse a DER-encoded bytestring into a signature.
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
--   The sizes of the inputs are not checked.
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
verify_schnorr :: Context -> BS.ByteString -> BS.ByteString -> Pub -> IO Bool
verify_schnorr c@(Context tex) sig msg pub =
  BS.useAsCString sig $ \(F.castPtr -> sip) ->
    BS.useAsCStringLen msg $ \(F.castPtr -> has, fromIntegral -> len) -> do
      XOnlyPub pux <- xonly c pub
      BS.useAsCString pux $ \(F.castPtr -> pax) -> do
        suc <- secp256k1_schnorrsig_verify tex sip has len pax
        pure (suc == 1)

