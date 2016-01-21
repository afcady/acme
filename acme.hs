{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Main where

import           Control.Lens               hiding ((.=))
import           Control.Monad
import           Crypto.Number.Serialize    (i2osp)
import           Data.Aeson                 (ToJSON (..), encode, object, (.=), Value)
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
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)
import           Network.Wreq               (Response, responseHeader, responseBody, responseStatus, statusCode, statusMessage, defaults, checkStatus)
import qualified Network.Wreq.Session       as WS
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
import Control.Monad.RWS.Strict
import Data.Coerce
import Control.Concurrent (threadDelay)
import System.Exit

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
      optChallengeDir :: String,
      optEmail   :: Maybe String,
      optTerms   :: Maybe String
}

defaultTerms :: String
defaultTerms = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

cmdopts :: Parser CmdOpts
cmdopts = CmdOpts <$> strOption (long "key" <> metavar "FILE" <> help "filename of your private RSA key")
                  <*> strOption (long "domain" <> metavar "DOMAIN" <> help "the domain name to certify")
                  <*> strOption (long "dir" <> metavar "DIR" <> help "output directory for ACME challenges")
                  <*> optional (strOption (long "email" <> metavar "ADDRESS" <> help "an email address with which to register an account"))
                  <*> optional (strOption (long "terms" <> metavar "URL" <> help "the terms param of the registration request"))

genKey :: String -> IO ()
genKey privKeyFile = void $ readProcess "openssl" (words "genrsa -out" ++ [privKeyFile, "4096"]) ""

genReq :: String -> String -> String -> IO ()
genReq privKeyFile domain out = void $ readProcess "openssl" (args privKeyFile domain out) ""
  where
    args k d o = words "req -new -sha256 -outform DER -key" ++ [k, "-subj", "/CN=" ++ d, "-out", o]

data Keys = Keys SomeKeyPair RSAPubKey
readKeys :: String -> IO Keys
readKeys privKeyFile = do
  priv <- readFile privKeyFile >>= flip readPrivateKey PwTTY
  pub <- rsaCopyPublic $ fromMaybe (error "Error: failed to parse RSA key.") (toKeyPair priv :: Maybe RSAKeyPair)
  return $ Keys priv pub

go :: CmdOpts -> IO ()
go (CmdOpts privKeyFile domain challengeDir email termOverride) = do

  doesFileExist privKeyFile >>= flip unless (genKey privKeyFile)

  let domainKeyFile = domain </> "rsa.key"
      domainCSRFile = domain </> "csr.der"
      domainCertFile = domain </> "cert.der"

  doesDirectoryExist domain >>= flip unless (createDirectory domain)
  doesFileExist domainKeyFile >>= flip unless (genKey domainKeyFile)
  doesFileExist domainCSRFile >>= flip unless (genReq domainKeyFile domain domainCSRFile)

  csrData <- B.readFile domainCSRFile

  keys@(Keys _ pub) <- readKeys privKeyFile
  let terms = fromMaybe defaultTerms termOverride

  -- Create user account
  runACME directoryUrl keys $ do
    forM_ email $ register terms >=> statusReport

    r <- challengeRequest domain >>= statusReport
    let

        httpChallenge  :: (Value -> Const (Endo s) Value) -> Response LC.ByteString -> Const (Endo s) (Response LC.ByteString)
        httpChallenge  = responseBody . JSON.key "challenges" . to universe . traverse . (filtered . has $ ix "type" . only "http-01")

        token = r ^?! httpChallenge . JSON.key "token" . _String . to encodeUtf8
        crUri = r ^?! httpChallenge . JSON.key "uri" . _String . to T.unpack

        thumb = thumbprint (JWK (rsaE pub) "RSA" (rsaN pub))
        thumbtoken = toStrict (LB.fromChunks [token, ".", thumb])

    liftIO $ do
      mapM_ print $ r ^@.. httpChallenge . members
      print $ encodeOrdered (JWK (rsaE pub) "RSA" (rsaN pub))

    -- liftIO $ LC.writeFile (challengeDir </> BC.unpack token) p
    liftIO $ BC.writeFile (challengeDir </> BC.unpack token) thumbtoken

    -- Wait for challenge validation
    -- TODO: first hit the local server to test whether this is valid
    r <- pollChallenge crUri thumbtoken >>= statusReport

    if r ^. responseStatus . statusCode . to isSuccess then do

      liftIO $ void exitSuccess
      -- Send a CSR and get a certificate
      void $ saveCert csrData domainCertFile >>= statusReport

    else liftIO $ putStrLn "Error"

  where
    a </> b = a ++ "/" ++ b
    isSuccess n = n >= 200 && n <= 300

saveCert :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => ByteString -> FilePath -> m (Response LC.ByteString)
saveCert input output = do
  r <- sendPayload _newCert (csr input)
  liftIO $ LC.writeFile output $ r ^. responseBody
  return r

pollChallenge :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => String -> ByteString -> m (Response LC.ByteString)
pollChallenge crUri thumbtoken = loop
  where
    loop = do
      liftIO . threadDelay $ 2000 * 1000
      liftIO $ putStrLn "polling..."
      r <- sendPayload (const crUri) (challenge thumbtoken) >>= statusReport
      let status = r ^? responseBody . JSON.key "status" . _String
      if status == Just "pending"
        then do
          liftIO . print $ r ^. responseBody
          liftIO . print $ r ^? responseBody . JSON.key "keyAuthorization" . _String
          liftIO . threadDelay $ 2000 * 1000
          loop
        else do
          liftIO $ putStrLn "done polling."
          liftIO $ print r
          return r

data Env = Env { getDir :: Directory, getKeys :: Keys, getSession :: WS.Session }

type ACME a = RWST Env () Nonce IO a
runACME :: String -> Keys -> ACME a -> IO a
runACME url keys f = WS.withSession $ \sess -> do
  Just (dir, nonce) <- getDirectory sess url
  fst <$> evalRWST f (Env dir keys sess) nonce

data Directory = Directory {
  _newCert    :: String,
  _newAuthz   :: String,
  _revokeCert :: String,
  _newReg     :: String
}
newtype Nonce = Nonce String
testRegister :: String -> IO (Response LC.ByteString)
testRegister email = runTest (register defaultTerms email) >>= statusReport

runTest :: ACME b -> IO b
runTest t = readKeys "rsa.key" >>= flip (runACME directoryUrl) t

testCR :: IO (Response LC.ByteString)
testCR = runTest $ challengeRequest "fifty.childrenofmay.org"

getDirectory :: WS.Session -> String -> IO (Maybe (Directory, Nonce))
getDirectory sess url = do
  r <- WS.get sess url
  let nonce = r ^? responseHeader "Replay-Nonce" . to (Nonce . T.unpack . decodeUtf8)
      k x   = r ^? responseBody . JSON.key x . _String . to T.unpack
  return $ (,) <$> (Directory <$> k "new-cert" <*> k "new-authz" <*> k "revoke-cert" <*> k "new-reg") <*> nonce

register :: String -> String -> ACME (Response LC.ByteString)
register terms email = sendPayload _newReg (registration email terms)

challengeRequest :: (MonadIO m, MonadState Nonce m, MonadReader Env m) => String -> m (Response LC.ByteString)
challengeRequest domain = sendPayload _newAuthz (authz domain)

statusLine :: Response body -> String
statusLine r =  (r ^. responseStatus . statusCode . to show) ++ " " ++ r ^. responseStatus . statusMessage . to (T.unpack . decodeUtf8)

statusReport :: MonadIO m => Response body -> m (Response body)
statusReport r = do
  liftIO $ putStrLn $ statusLine r
  return r

sendPayload :: (MonadIO m, MonadState Nonce m, MonadReader Env m) => (Directory -> String) -> ByteString -> m (Response LC.ByteString)
sendPayload reqType payload = do
  keys <- asks getKeys
  dir <- asks getDir
  nonce <- gets coerce
  signed <- liftIO $ signPayload keys nonce payload
  post (reqType dir) signed

-- post :: (MonadReader Env m, MonadState Nonce m, MonadIO m, Postable a) => String -> a -> m (Response LC.ByteString)
post url payload = do
  sess <- asks getSession
  r <- liftIO $ WS.postWith noStatusCheck sess url payload
  put $ r ^?! responseHeader "Replay-Nonce" . to (Nonce . T.unpack . decodeUtf8)
  return r
  where
    noStatusCheck = defaults & checkStatus .~ Just nullChecker
    nullChecker _ _ _ = Nothing

--------------------------------------------------------------------------------
-- | Sign return a payload with a nonce-protected header.
signPayload :: Keys -> String -> ByteString -> IO LC.ByteString
signPayload (Keys priv pub) nonce_ payload = withOpenSSL $ do
  let protected = b64 (header pub nonce_)
  Just dig <- getDigestByName "SHA256"
  sig <- b64 <$> signBS dig priv (B.concat [protected, ".", payload])
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
