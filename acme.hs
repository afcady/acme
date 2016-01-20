{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.

module Main where

import           Control.Lens               hiding ((.=))
import           Control.Monad
import           Crypto.Number.Serialize    (i2osp)
import           Data.Aeson                 (ToJSON (..), encode, object, (.=))
import           Data.Aeson.Lens            hiding (key)
import qualified Data.Aeson.Lens            as JSON
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.Digest.Pure.SHA       (bytestringDigest, sha256)
import           Data.Maybe
import qualified Data.Text                  as T
import           Data.Text.Encoding         (decodeUtf8)
import           Network.Wreq               hiding (header)
import           OpenSSL
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.EVP.Sign
import           OpenSSL.PEM
import           OpenSSL.RSA
import           Options.Applicative        hiding (header)
import qualified Options.Applicative        as Opt
import           System.Directory
import           System.Process             (readProcess)

directoryUrl :: String
directoryUrl =  "https://acme-v01.api.letsencrypt.org/directory"

main :: IO ()
main = execParser opts >>= go
  where
    opts = info (helper <*> cmdopts) (fullDesc <> progDesc detailedDescription <> Opt.header "Let's Encrypt! ACME client")
    detailedDescription = "This is a work in progress."

data CmdOpts = CmdOpts {
      optKeyFile :: String,
      optDomain  :: String,
      optEmail   :: Maybe String,
      optTerms   :: Maybe String
}

defaultTerms :: String
defaultTerms = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

cmdopts :: Parser CmdOpts
cmdopts = CmdOpts <$> strOption (long "key" <> metavar "FILE" <> help "filename of your private RSA key")
                  <*> strOption (long "domain" <> metavar "DOMAIN" <> help "the domain name to certify")
                  <*> optional (strOption (long "email" <> metavar "ADDRESS" <> help "an email address with which to register an account"))
                  <*> optional (strOption (long "terms" <> metavar "URL" <> help "the terms param of the registration request"))

genKey :: String -> IO ()
genKey privKeyFile = readProcess "openssl" (words "genrsa 4096 -out" ++ [privKeyFile]) "" >>= writeFile privKeyFile

go :: CmdOpts -> IO ()
go (CmdOpts privKeyFile domain email termOverride) = do

  doesFileExist privKeyFile >>= flip unless (genKey privKeyFile)

  priv <- readFile privKeyFile >>= flip readPrivateKey PwTTY
  mbPub <- maybe (return Nothing) (rsaCopyPublic >=> return . Just)
             (toKeyPair priv :: Maybe RSAKeyPair)

  let terms = fromMaybe defaultTerms termOverride
      pub :: RSAPubKey
      pub = fromMaybe (error "Error: failed to parse RSA key.") mbPub

  Just nonce_ <- getNonce

  -- Create user account
  forM_ email $ \m ->
    LB.writeFile "registration.body" =<< signPayload priv pub nonce_ (registration m terms)

  -- Obtain a challenge
  LB.writeFile "challenge-request.body" =<< signPayload priv pub nonce_ (authz domain)

  -- Answser the challenge
  let thumb = thumbprint (JWK (rsaE pub) "RSA" (rsaN pub))
      -- Extracted from POST response above.
      token = "DjyJpI3HVWAmsAwMT5ZFpW8dj19cel6ml6qaBUeGpCg"
      thumbtoken = toStrict (LB.fromChunks [token, ".", thumb])

  putStrLn ("Serve http://" ++ domain ++ "/.well-known/acme-challenge/" ++ BC.unpack token)
  putStrLn ("With content:\n" ++ BC.unpack thumbtoken)

  -- Notify Let's Encrypt we answsered the challenge
  LB.writeFile "challenge-response.body" =<< signPayload priv pub nonce_ (challenge thumbtoken)

  -- Wait for challenge validation Send a CSR and get a certificate
  csr_ <- B.readFile (domain ++ ".csr.der")
  LB.writeFile "csr-request.body" =<< signPayload priv pub nonce_ (csr csr_)

  return ()

data Directory = Directory {
  _newCert    :: String,
  _newAuthz   :: String,
  _revokeCert :: String,
  _newReg     :: String,
  _nonce      :: String
}

getDirectory :: String -> IO (Maybe Directory)
getDirectory url = do
  r <- get url
  let nonce = r ^? responseHeader "Replay-Nonce" . to (T.unpack . decodeUtf8)
      k x   = r ^? responseBody . JSON.key x . _String . to T.unpack
  return $ Directory <$> k "new-cert" <*> k "new-authz" <*> k "revoke-cert" <*> k "new-reg" <*> nonce

getNonce :: IO (Maybe String)
getNonce = fmap _nonce <$> getDirectory directoryUrl

--------------------------------------------------------------------------------
-- | Sign and write a payload to a file with a nonce-protected header.
signPayload :: (RSAKey k, KeyPair kp) => kp -> k -> String -> ByteString -> IO LC.ByteString
signPayload priv pub nonce_ payload = withOpenSSL $ do
  let protected = b64 (header pub nonce_)
  Just dig <- getDigestByName "SHA256"
  sig <- b64 <$> signBS dig priv (B.concat [protected, ".", payload])
  return $ buildBody pub protected payload sig

buildBody :: RSAKey k => k -> ByteString -> ByteString -> ByteString -> LC.ByteString
buildBody key protected payload sig = encode (Request (header' key) protected payload sig)

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
registration :: String -> String -> ByteString
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
thumbprint = b64 . toStrict .bytestringDigest . sha256 . encodeOrdered

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
    ] ++ maybe [] ((:[]) . ("nonce" .=)) hNonce

instance ToJSON JWK where
  toJSON JWK{..} = object
    [ "e" .= decodeUtf8 (b64i hE)
    , "kty" .= hKty
    , "n" .= decodeUtf8 (b64i hN)
    ]

data Reg = Reg
  { rMail      :: String
  , rAgreement :: String
  }
  deriving Show

instance ToJSON Reg where
  toJSON Reg{..} = object
    [ "resource" .= ("new-reg" :: String)
    , "contact" .= ["mailto:" ++ rMail]
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
