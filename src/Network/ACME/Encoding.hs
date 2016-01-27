{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.ACME.Encoding (
    thumbprint,
    JWK(..),
    toStrict,
    csr,
    challenge,
    registration,
    authz,
    signPayload',
    ) where

import           Crypto.Number.Serialize    (i2osp)
import           Data.Aeson                 (ToJSON (..), encode, object, (.=))
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.Digest.Pure.SHA       (bytestringDigest, sha256)
import           Data.Maybe
import           Data.Text.Encoding         (decodeUtf8)
import           OpenSSL
import           OpenSSL.RSA
import           Text.Email.Validate
import qualified Data.Text                  as T

--------------------------------------------------------------------------------
-- | Sign return a payload with a nonce-protected header.

signPayload' :: (ByteString -> IO ByteString) -> RSAPubKey -> String -> ByteString -> IO LC.ByteString
signPayload' sign pub nonce_ payload = withOpenSSL $ do
  let protected = b64 (header pub nonce_)
  sig <- b64 <$> sign (B.concat [protected, ".", payload])
  return $ encode (Request (header' pub) protected payload sig)

--------------------------------------------------------------------------------
-- | Base64URL encoding of Integer with padding '=' removed.
b64i :: Integer -> ByteString
b64i = b64 . i2osp

b64 :: ByteString -> ByteString
b64 = B.takeWhile (/= 61) . Base64.encode

toStrict :: LB.ByteString -> ByteString
toStrict = B.concat . LB.toChunks

header' :: RSAKey k => k -> Header
header' key = Header "RS256" (JWK (rsaE key) "RSA" (rsaN key)) Nothing

header :: RSAKey k => k -> String -> ByteString
header key nonce = (toStrict . encode)
                     (Header "RS256" (JWK (rsaE key) "RSA" (rsaN key)) (Just nonce))

-- | Registration payload to sign with user key.
registration :: EmailAddress -> String -> ByteString
registration emailAddr terms = (b64 . toStrict . encode) (Reg emailAddr terms)

-- | Challenge request payload to sign with user key.
authz :: String -> ByteString
authz = b64. toStrict . encode . Authz

-- | Challenge response payload to sign with user key.
challenge :: ByteString -> ByteString
challenge = b64 . toStrict . encode . Challenge . BC.unpack

-- | CSR request payload to sign with user key.
csr :: ByteString -> ByteString
csr = b64 . toStrict . encode . CSR . b64

thumbprint :: JWK -> ByteString
thumbprint = b64 . toStrict . bytestringDigest . sha256 . encodeOrdered

-- | There is an `encodePretty'` in `aeson-pretty`, but do it by hand here.
encodeOrdered :: JWK -> LB.ByteString
encodeOrdered JWK{..} = LC.pack $
  "{\"e\":\"" ++ hE' ++ "\",\"kty\":\"" ++ hKty ++ "\",\"n\":\"" ++ hN' ++ "\"}"
  where
  hE' = BC.unpack (b64i hE)
  hN' = BC.unpack (b64i hN)


--------------------------------------------------------------------------------
data Header = Header
  { hAlg   :: String
  , hJwk   :: JWK
  , hNonce :: Maybe String
  }
  deriving Show

data JWK = JWK
  { hE   :: Integer
  , hKty :: String
  , hN   :: Integer
  }
  deriving Show

instance ToJSON Header where
  toJSON Header{..} = object $
    [ "alg" .= hAlg
    , "jwk" .= toJSON hJwk
    ] ++ maybeToList (("nonce" .=) <$> hNonce)

instance ToJSON JWK where
  toJSON JWK{..} = object
    [ "e" .= decodeUtf8 (b64i hE)
    , "kty" .= hKty
    , "n" .= decodeUtf8 (b64i hN)
    ]

data Reg = Reg
  { rMail      :: EmailAddress
  , rAgreement :: String
  }
  deriving Show

instance ToJSON Reg where
  toJSON Reg{..} = object
    [ "resource" .= ("new-reg" :: String)
    , "contact" .= ["mailto:" ++ (T.unpack . decodeUtf8 . toByteString $ rMail)]
    , "agreement" .= rAgreement
    ]

data Request = Request
  { rHeader    :: Header
  , rProtected :: ByteString
  , rPayload   :: ByteString
  , rSignature :: ByteString
  }
  deriving Show

instance ToJSON Request where
  toJSON Request{..} = object
    [ "header" .= toJSON rHeader
    , "protected" .= decodeUtf8 rProtected
    , "payload" .= decodeUtf8 rPayload
    , "signature" .= decodeUtf8 rSignature
    ]

data Authz = Authz
  { aDomain :: String
  }

instance ToJSON Authz where
  toJSON Authz{..} = object
    [ "resource" .= ("new-authz" :: String)
    , "identifier" .= object
      [ "type" .= ("dns" :: String)
      , "value" .= aDomain
      ]
    ]

data Challenge = Challenge
  { cKeyAuth :: String
  }

instance ToJSON Challenge where
  toJSON Challenge{..} = object
    [ "resource" .= ("challenge" :: String)
    , "keyAuthorization" .= cKeyAuth
    ]

data CSR = CSR ByteString
  deriving Show

instance ToJSON CSR where
  toJSON (CSR s) = object
    [ "resource" .= ("new-cert" :: String)
    , "csr" .= decodeUtf8 s
    ]
