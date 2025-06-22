{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module BIP340 (
    cases
  , execute
  ) where

import Control.Applicative
import Control.Exception
import Crypto.Curve.Secp256k1
import qualified Data.Attoparsec.ByteString.Char8 as AT
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Test.Tasty
import Test.Tasty.HUnit

decodeLenient :: BS.ByteString -> BS.ByteString
decodeLenient bs = case B16.decode bs of
  Nothing -> error "bang"
  Just b -> b

data Case = Case {
    c_index   :: !Int
  , c_sk      :: !BS.ByteString
  , c_pk      :: !BS.ByteString
  , c_aux     :: !BS.ByteString
  , c_msg     :: !BS.ByteString
  , c_sig     :: !BS.ByteString
  , c_res     :: !Bool
  , c_comment :: !BS.ByteString
  } deriving Show

execute :: Context -> Case -> TestTree
execute tex Case {..} = testCase ("bip0340 " <> show c_index) $ do
  par <- try (parse_xonly tex (decodeLenient c_pk))
          :: IO (Either Secp256k1Exception XOnlyPub)
  case par of
    Left _ -> assertBool mempty (not c_res)
    Right (XOnlyPub pub) -> do
      let pk = Pub pub
      if   c_sk == mempty
      then do -- no signature; test verification
        ver <- verify_schnorr tex pk c_msg c_sig
        if   c_res
        then assertBool mempty ver
        else assertBool mempty (not ver)
      -- XX test pubkey derivation from sk
      else do -- signature present; test sig too
        sig <- sign_schnorr tex c_msg c_sk c_aux
        ver <- verify_schnorr tex pk c_msg sig
        assertEqual mempty c_sig sig
        if   c_res
        then assertBool mempty ver
        else assertBool mempty (not ver)

header :: AT.Parser ()
header = do
  _ <- AT.string "index,secret key,public key,aux_rand,message,signature,verification result,comment"
  AT.endOfLine

test_case :: AT.Parser Case
test_case = do
  c_index <- AT.decimal AT.<?> "index"
  _ <- AT.char ','
  c_sk <- fmap decodeLenient (AT.takeWhile (/= ',') AT.<?> "sk")
  _ <- AT.char ','
  c_pk <- AT.takeWhile1 (/= ',') AT.<?> "pk"
  _ <- AT.char ','
  c_aux <- fmap decodeLenient (AT.takeWhile (/= ',') AT.<?> "aux")
  _ <- AT.char ','
  c_msg <- fmap decodeLenient (AT.takeWhile (/= ',') AT.<?> "msg")
  _ <- AT.char ','
  c_sig <- fmap decodeLenient (AT.takeWhile1 (/= ',') AT.<?> "sig")
  _ <- AT.char ','
  c_res <- (AT.string "TRUE" *> pure True) <|> (AT.string "FALSE" *> pure False)
            AT.<?> "res"
  _ <- AT.char ','
  c_comment <- AT.takeWhile (/= '\n') AT.<?> "comment"
  AT.endOfLine
  pure Case {..}

cases :: AT.Parser [Case]
cases = header *> AT.many1 test_case

