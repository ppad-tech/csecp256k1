{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.Secp256k1
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Bindings to bitcoin-core/secp256k1, a C library supporting digital
-- signatures and other cryptographic primitives on the secp256k1
-- elliptic curve.
--
-- This library exposes a minimal subset of functionality, primarily
-- supporting ECDSA/Schnorr signatures and ECDH secret computation.

module Crypto.Secp256k1 (
    Context(..)
  , wcontext
  , wrcontext

  , Sig
  , sign
  , sign_schnorr
  , verify
  , verify_schnorr
  , ecdh

  , parse_der
  , serialize_der
  , parse_compact
  , serialize_compact

  , Pub
  , derive_pub
  , parse_pub
  , tweak_pub_add
  , tweak_pub_mul
  , tweak_sec_add
  , tweak_sec_mul
  , serialize_pub
  , serialize_pub_u
  , XOnlyPub
  , xonly
  , parse_xonly
  , serialize_xonly
  , KeyPair
  , keypair
  , keypair_pub
  , keypair_sec

  , Secp256k1Exception(..)
  ) where

import Control.Exception (Exception, bracket, throwIO)
import Control.Monad (when)
import Crypto.Secp256k1.Internal hiding (Context)
import qualified Crypto.Secp256k1.Internal as I (Context)
import GHC.Generics
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
--
--   The data constructor is exported only to make the implementation
--   easier to benchmark. You should /not/ pattern match on or
--   manipulate context values.
newtype Context = Context (Ptr I.Context)
  deriving stock Generic

instance Show Context where
  show (Context tex) = "<bitcoin-core/secp256k1 context " <> show tex <> ">"

-- | A bitcoin-core/secp256k1-internal public key.
--
--   Create a value of this type by parsing a compressed or uncompressed
--   public key via 'parse_pub', deriving one from a secret key via
--   'create_pub', or extracting one from a keypair via 'keypair_pub'.
newtype Pub = Pub BS.ByteString
  deriving stock Generic

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
  deriving stock Generic

instance Show XOnlyPub where
  show _ = "<bitcoin-core/secp256k1 x-only public key>"

-- | A bitcoin-core/secp256k1-internal keypair.
--
--   Create a value of this type by passing a secret key to
--   'keypair'.
newtype KeyPair = KeyPair BS.ByteString
  deriving stock Generic

instance Show KeyPair where
  show _ = "<bitcoin-core/secp256k1 keypair>"

-- | A bitcoin-core/secp256k1-internal ECDSA signature.
--
--   Create a value of this type via 'sign', or parse a DER-encoded
--   signature via 'parse_der'.
newtype Sig = Sig BS.ByteString
  deriving stock Generic

instance Show Sig where
  show _ = "<bitcoin-core/secp256k1 signature>"

-- exceptions

-- | A catch-all exception type.
--
--   Internal library errors (i.e., non-unit return values in the
--   underlying C functions) will typically throw a 'Secp256k1Error'
--   exception.
data Secp256k1Exception =
    -- | Thrown when a bitcoin-core/secp256k1 function returns a value
    --   indicating failure.
    Secp256k1Error
    -- | Thrown when a csecp256k1 function has been passed a bad (i.e.,
    --   incorrectly-sized) input.
  | CSecp256k1Error
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
--   Do /not/ attempt to use the created 'Context' value outside
--   of a 'wcontext' or 'wrcontext' block, as the internal
--   bitcoin-core/secp256k1 context will have been destroyed by then.
--   For example, don't be cheeky and do something like:
--
--   > do
--   >   context <- wcontext pure
--   >   derive_pub context seckey
--
--   unless you like segfaults.
--
--   >>> wcontext $ \tex -> parse_pub tex bytestring
--   "<bitcoin-core/secp256k1 public key>"
wcontext
  :: (Context -> IO a) -- ^ continuation to run in the context
  -> IO a
wcontext = bracket create destroy where
  create = do
    tex <- secp256k1_context_create _SECP256K1_CONTEXT_NONE
    pure (Context tex)

  destroy (Context tex) =
    secp256k1_context_destroy tex

-- | Same as 'wcontext', but randomize the bitcoin-core/secp256k1
--   context with the provided 32 bytes of entropy before executing the
--   supplied continuation.
--
--   Use this function to execute computations that may benefit from
--   additional side-channel attack protection.
--
--   As with 'wcontext', do /not/ attempt to use a created 'Context'
--   value outside of the 'wrcontext' block.
--
--   >>> wrcontext entropy $ \tex -> sign tex sec msg
--   "<bitcoin-core/secp256k1 signature>"
wrcontext
  :: BS.ByteString     -- ^ 32 bytes of fresh entropy
  -> (Context -> IO a) -- ^ continuation to run in the context
  -> IO a
wrcontext enn con
    | BS.length enn /= 32 = throwIO CSecp256k1Error
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
--   >>> wrcontext entropy $ \tex -> derive_pub tex sec
--   "<bitcoin-core/secp256k1 public key>"
derive_pub
  :: Context
  -> BS.ByteString -- ^ 32-byte secret key
  -> IO Pub
derive_pub (Context tex) bs
  | BS.length bs /= 32 = throwIO CSecp256k1Error
  | otherwise = BS.useAsCString bs $ \(F.castPtr -> sec) ->
      A.allocaBytes _PUB_BYTES_INTERNAL $ \out -> do
        suc <- secp256k1_ec_pubkey_create tex out sec
        when (suc /= 1) $ throwIO Secp256k1Error
        let pub = F.castPtr out
        key <- BS.packCStringLen (pub, _PUB_BYTES_INTERNAL)
        pure (Pub key)

-- | Parse a compressed (33-byte) or uncompressed (65-byte) public key.
--
--   >>> wcontext $ \tex -> parse_pub tex bs
--   "<bitcoin-core/secp256k1 public key>"
parse_pub
  :: Context
  -> BS.ByteString -- ^ compressed or uncompressed public key
  -> IO Pub
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
serialize_pub
  :: Context
  -> Pub
  -> IO BS.ByteString -- ^ serialized compressed public key
serialize_pub = serialize_pub_in Compressed

-- | Serialize a public key into an uncompressed (65-byte) bytestring
--   represention.
--
--   >>> wcontext $ \tex -> serialize_pub_u tex pub
serialize_pub_u
  :: Context
  -> Pub
  -> IO BS.ByteString -- ^ serialized uncompressed public key
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

-- | Additively tweak a public key with the supplied 32-byte tweak.
--
--   >>> wrcontext $ \tex -> tweak_pub_add pub tweak
tweak_pub_add
  :: Context
  -> Pub
  -> BS.ByteString -- ^ 32-byte tweak value
  -> IO Pub
tweak_pub_add (Context tex) (Pub pub) wee
  | BS.length wee /= 32 = throwIO CSecp256k1Error
  | otherwise = do
      let cop = BS.copy pub
      BS.useAsCString cop $ \(F.castPtr -> out) ->
        BS.useAsCString wee $ \(F.castPtr -> eek) -> do
          suc <- secp256k1_ec_pubkey_tweak_add tex out eek
          when (suc /= 1) $ throwIO Secp256k1Error
          let enc = F.castPtr out
          key <- BS.packCStringLen (enc, _PUB_BYTES_INTERNAL)
          pure (Pub key)

-- | Multiplicatively tweak a public key with the supplied 32-byte
--   tweak.
--
--   >>> wrcontext $ \tex -> tweak_pub_mul pub tweak
tweak_pub_mul
  :: Context
  -> Pub
  -> BS.ByteString -- ^ 32-byte tweak value
  -> IO Pub
tweak_pub_mul (Context tex) (Pub pub) wee
  | BS.length wee /= 32 = throwIO CSecp256k1Error
  | otherwise = do
      let cop = BS.copy pub
      BS.useAsCString cop $ \(F.castPtr -> out) ->
        BS.useAsCString wee $ \(F.castPtr -> eek) -> do
          suc <- secp256k1_ec_pubkey_tweak_mul tex out eek
          when (suc /= 1) $ throwIO Secp256k1Error
          let enc = F.castPtr out
          key <- BS.packCStringLen (enc, _PUB_BYTES_INTERNAL)
          pure (Pub key)

-- | Additively tweak a secret key with the supplied 32-byte tweak.
--
--   >>> wrcontext $ \tex -> tweak_sec_add sec tweak
tweak_sec_add
  :: Context
  -> BS.ByteString    -- ^ 32-byte secret key
  -> BS.ByteString    -- ^ 32-byte tweak value
  -> IO BS.ByteString -- ^ 32-byte secret key
tweak_sec_add (Context tex) key wee
  | BS.length key /= 32 || BS.length wee /= 32 = throwIO CSecp256k1Error
  | otherwise = do
      let sec = BS.copy key
      BS.useAsCString sec $ \(F.castPtr -> out) ->
        BS.useAsCString wee $ \(F.castPtr -> eek) -> do
          suc <- secp256k1_ec_seckey_tweak_add tex out eek
          when (suc /= 1) $ throwIO Secp256k1Error
          let enc = F.castPtr out
          BS.packCStringLen (enc, _SEC_BYTES)

-- | Multiplicatively tweak a secret key with the supplied 32-byte
--   tweak.
--
--   >>> wrcontext $ \tex -> tweak_sec_mul sec tweak
tweak_sec_mul
  :: Context
  -> BS.ByteString    -- ^ 32-byte secret key
  -> BS.ByteString    -- ^ 32-byte tweak value
  -> IO BS.ByteString -- ^ 32-byte secret key
tweak_sec_mul (Context tex) key wee
  | BS.length key /= 32 || BS.length wee /= 32 = throwIO CSecp256k1Error
  | otherwise = do
      let sec = BS.copy key
      BS.useAsCString sec $ \(F.castPtr -> out) ->
        BS.useAsCString wee $ \(F.castPtr -> eek) -> do
          suc <- secp256k1_ec_seckey_tweak_mul tex out eek
          when (suc /= 1) $ throwIO Secp256k1Error
          let enc = F.castPtr out
          BS.packCStringLen (enc, _SEC_BYTES)

-- ecdsa

-- | Sign a 32-byte message hash with the provided secret key.
--
--   >>> wrcontext entropy $ \tex -> sign tex sec msg
--   "<bitcoin-core/secp256k1 signature>"
sign
  :: Context
  -> BS.ByteString -- ^ 32-byte secret key
  -> BS.ByteString -- ^ 32-byte message hash
  -> IO Sig
sign (Context tex) key msg
  | BS.length key /= 32 || BS.length msg /= 32 = throwIO CSecp256k1Error
  | otherwise = A.allocaBytes _SIG_BYTES $ \out ->
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
--   >>> wcontext $ \tex -> verify tex pub msg good_sig
--   True
--   >>> wcontext $ \tex -> verify tex pub msg bad_sig
--   False
verify
  :: Context
  -> Pub
  -> BS.ByteString -- ^ 32-byte message hash
  -> Sig
  -> IO Bool
verify (Context tex) (Pub pub) msg (Sig sig)
  | BS.length msg /= 32 = throwIO CSecp256k1Error
  | otherwise = BS.useAsCString pub $ \(F.castPtr -> key) ->
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
parse_der
  :: Context
  -> BS.ByteString -- ^ DER-encoded signature
  -> IO Sig
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
serialize_der
  :: Context
  -> Sig
  -> IO BS.ByteString -- ^ DER-encoded signature
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

-- | Parse a bytestring encoding a compact (64-byte) signature.
--
--   >>> wcontext $ \tex -> parse_compact tex bytestring
parse_compact
  :: Context
  -> BS.ByteString -- ^ bytestring encoding a 64-byte compact signature
  -> IO Sig
parse_compact (Context tex) bs =
  BS.useAsCString bs $ \(F.castPtr -> com) ->
    A.allocaBytes _SIG_BYTES $ \out -> do
      suc <- secp256k1_ecdsa_signature_parse_compact tex out com
      when (suc /= 1) $ throwIO Secp256k1Error
      let par = F.castPtr out
      enc <- BS.packCStringLen (par, _SIG_BYTES)
      pure (Sig enc)

-- | Serialize a signature into a compact (64-byte) bytestring.
--
--   >>> wcontext $ \tex -> serialize_compact tex sig
serialize_compact
  :: Context
  -> Sig
  -> IO BS.ByteString
serialize_compact (Context tex) (Sig sig) =
  BS.useAsCString sig $ \(F.castPtr -> sip) ->
    A.allocaBytes _SIG_BYTES $ \out -> do
      -- always returns 1
      _ <- secp256k1_ecdsa_signature_serialize_compact tex out sip
      let enc = F.castPtr out
      BS.packCStringLen (enc, _SIG_BYTES)

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
--   >>> wcontext $ \tex -> parse_xonly tex bytestring
--   "<bitcoin-core/secp256k1 x-only public key>"
parse_xonly
  :: Context
  -> BS.ByteString -- ^ compressed or uncompressed public key
  -> IO XOnlyPub
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
serialize_xonly
  :: Context
  -> XOnlyPub
  -> IO BS.ByteString -- ^ serialized x-only public key
serialize_xonly (Context tex) (XOnlyPub pux) =
  A.allocaBytes _PUB_BYTES_XONLY $ \out -> do
    BS.useAsCString pux $ \(F.castPtr -> pub) -> do
      -- returns 1 always
      _ <- secp256k1_xonly_pubkey_serialize tex out pub
      let enc = F.castPtr out
      BS.packCStringLen (enc, _PUB_BYTES_XONLY)

-- | Derive a keypair from the provided 32-byte secret key.
--
--   >>> wrcontext entropy $ \tex -> keypair tex sec
--   "<bitcoin-core/secp256k1 keypair>"
keypair
  :: Context
  -> BS.ByteString -- ^ 32-byte secret key
  -> IO KeyPair
keypair (Context tex) sec
  | BS.length sec /= 32 = throwIO CSecp256k1Error
  | otherwise = A.allocaBytes _KEYPAIR_BYTES $ \out ->
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
keypair_sec
  :: Context
  -> KeyPair
  -> IO BS.ByteString -- ^ 32-byte secret key
keypair_sec (Context tex) (KeyPair per) =
  A.allocaBytes _SEC_BYTES $ \out ->
    BS.useAsCString per $ \(F.castPtr -> par) -> do
      _ <- secp256k1_keypair_sec tex out par
      let enc = F.castPtr out
      BS.packCStringLen (enc, _SEC_BYTES)

-- ecdh

-- | Compute an ECDH secret key from the provided public key and
--   (32-byte) secret key.
--
--   >>> wrcontext entropy $ \tex -> ecdh tex pub sec
ecdh
  :: Context
  -> Pub
  -> BS.ByteString    -- ^ 32-byte secret key
  -> IO BS.ByteString -- ^ 32-byte secret key
ecdh (Context tex) (Pub pub) sec
  | BS.length sec /= 32 = throwIO CSecp256k1Error
  | otherwise =
      A.allocaBytes _SEC_BYTES $ \out ->
        BS.useAsCString pub $ \(F.castPtr -> pup) ->
          BS.useAsCString sec $ \(F.castPtr -> sep) -> do
            suc <- secp256k1_ecdh tex out pup sep F.nullPtr F.nullPtr
            when (suc /= 1) $ throwIO Secp256k1Error
            let key = F.castPtr out
            BS.packCStringLen (key, _SEC_BYTES)

-- schnorr

-- | Sign a 32-byte message hash with the provided secret key, using the
--   provided 32 bytes of fresh auxiliary entropy.
--
--   BIP340 recommends that 32 bytes of fresh auxiliary entropy be
--   generated and added at signing time as additional protection
--   against side-channel attacks (namely, to thwart so-called "fault
--   injection" attacks). This entropy is /supplemental/ to security,
--   and the cryptographic security of the signature scheme itself does
--   not rely on it, so it is not strictly required; 32 zero bytes can
--   be used in its stead.
--
--   The resulting 64-byte Schnorr signature is portable, and so is not
--   wrapped in a newtype.
--
--   >>> import qualified System.Entropy as E  -- example entropy source
--   >>> enn <- E.getEntropy 32
--   >>> aux <- E.getEntropy 32
--   >>> wrcontext enn $ \tex -> sign_schnorr tex msg sec aux
sign_schnorr
  :: Context
  -> BS.ByteString    -- ^ 32-byte message hash
  -> BS.ByteString    -- ^ 32-byte secret key
  -> BS.ByteString    -- ^ 32 bytes of fresh entropy
  -> IO BS.ByteString -- ^ 64-byte signature
sign_schnorr c@(Context tex) msg sec aux
  | BS.length msg /= 32 || BS.length sec /= 32 || BS.length aux /= 32 =
      throwIO CSecp256k1Error
  | otherwise = A.allocaBytes _SIG_BYTES $ \out ->
      BS.useAsCString msg $ \(F.castPtr -> has) ->
        BS.useAsCString aux $ \(F.castPtr -> enn) -> do
          KeyPair per <- keypair c sec
          BS.useAsCString per $ \(F.castPtr -> pur) -> do
            suc <- secp256k1_schnorrsig_sign32 tex out has pur enn
            when (suc /= 1) $ throwIO Secp256k1Error
            let enc = F.castPtr out
            BS.packCStringLen (enc, _SIG_BYTES)

-- | Verify a 64-byte Schnorr signature for the provided 32-byte message
--   hash with the supplied public key.
--
--   >>> wrcontext entropy $ \tex -> verify_schnorr tex pub msg sig
verify_schnorr
  :: Context
  -> Pub
  -> BS.ByteString -- ^ 32-byte message hash
  -> BS.ByteString -- ^ 64-byte signature
  -> IO Bool
verify_schnorr c@(Context tex) pub msg sig
  | BS.length msg /= 32 || BS.length sig /= 64 = throwIO CSecp256k1Error
  | otherwise =
    BS.useAsCString sig $ \(F.castPtr -> sip) ->
      BS.useAsCStringLen msg $ \(F.castPtr -> has, fromIntegral -> len) -> do
        XOnlyPub pux <- xonly c pub
        BS.useAsCString pux $ \(F.castPtr -> pax) -> do
          suc <- secp256k1_schnorrsig_verify tex sip has len pax
          pure (suc == 1)

