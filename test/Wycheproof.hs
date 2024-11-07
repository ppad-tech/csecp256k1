{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Wycheproof (
    Wycheproof(..)
  , execute_group
  )  where

import Control.Exception
import Crypto.Curve.Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson ((.:))
import qualified Data.Aeson as A
import qualified Data.Attoparsec.ByteString as AT
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified GHC.Num.Integer as I
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase)

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' unstep 0 where
  unstep a (fi -> b) = (a `I.integerShiftL` 8) `I.integerOr` b

execute_group :: Context -> EcdsaTestGroup -> IO TestTree
execute_group tex EcdsaTestGroup {..} = do
    let raw = B16.decodeLenient (TE.encodeUtf8 pk_uncompressed)
    pub <- parse_pub tex raw
    let tests = fmap (execute tex pub) etg_tests
    pure (testGroup msg tests)
  where
    msg = "wycheproof (" <> T.unpack etg_type <> ", " <> T.unpack etg_sha <> ")"
    PublicKey {..} = etg_publicKey

execute :: Context -> Pub -> EcdsaVerifyTest -> TestTree
execute tex pub EcdsaVerifyTest {..} = testCase report $ do
    let msg = B16.decodeLenient (TE.encodeUtf8 t_msg)
        sig = B16.decodeLenient (TE.encodeUtf8 t_sig)
    syg <- try (parse_der tex sig) :: IO (Either Secp256k1Exception Sig)
    case syg of
      Left _  -> assertBool mempty (t_result == "invalid")
      Right s -> do
        ver <- verify_ecdsa tex pub msg s
        if   t_result == "invalid"
        then assertBool mempty (not ver)
        else assertBool mempty ver
  where
    report = "wycheproof " <> show t_tcId

data Wycheproof = Wycheproof {
    wp_algorithm        :: !T.Text
  , wp_generatorVersion :: !T.Text
  , wp_numberOfTests    :: !Int
  , wp_testGroups       :: ![EcdsaTestGroup]
  } deriving Show

instance A.FromJSON Wycheproof where
  parseJSON = A.withObject "Wycheproof" $ \m -> Wycheproof
    <$> m .: "algorithm"
    <*> m .: "generatorVersion"
    <*> m .: "numberOfTests"
    <*> m .: "testGroups"

data EcdsaTestGroup = EcdsaTestGroup {
    etg_type      :: !T.Text
  , etg_publicKey :: !PublicKey
  , etg_sha       :: !T.Text
  , etg_tests     :: ![EcdsaVerifyTest]
  } deriving Show

instance A.FromJSON EcdsaTestGroup where
  parseJSON = A.withObject "EcdsaTestGroup" $ \m -> EcdsaTestGroup
    <$> m .: "type"
    <*> m .: "publicKey"
    <*> m .: "sha"
    <*> m .: "tests"

data PublicKey = PublicKey {
    pk_type         :: !T.Text
  , pk_curve        :: !T.Text
  , pk_keySize      :: !Int
  , pk_uncompressed :: !T.Text
  } deriving Show

instance A.FromJSON PublicKey where
  parseJSON = A.withObject "PublicKey" $ \m -> PublicKey
    <$> m .: "type"
    <*> m .: "curve"
    <*> m .: "keySize"
    <*> m .: "uncompressed"

data EcdsaVerifyTest = EcdsaVerifyTest {
    t_tcId    :: !Int
  , t_comment :: !T.Text
  , t_msg     :: !T.Text
  , t_sig     :: !T.Text
  , t_result  :: !T.Text
  } deriving Show

instance A.FromJSON EcdsaVerifyTest where
  parseJSON = A.withObject "EcdsaVerifyTest" $ \m -> EcdsaVerifyTest
    <$> m .: "tcId"
    <*> m .: "comment"
    <*> m .: "msg"
    <*> m .: "sig"
    <*> m .: "result"

