{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Main where

import           Control.Lens               hiding ((.=))
import           Control.Monad
import           Control.Monad.RWS.Strict
import           Crypto.Number.Serialize    (i2osp)
import           Data.Aeson                 (ToJSON (..), Value, encode, object,
                                             (.=))
import           Data.Aeson.Lens            hiding (key)
import qualified Data.Aeson.Lens            as JSON
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.Coerce
import           Data.Digest.Pure.SHA       (bytestringDigest, sha256)
import           Data.Maybe
import qualified Data.Text                  as T
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)
import           Network.Wreq               (Response, checkStatus, defaults,
                                             responseBody, responseHeader,
                                             responseStatus, statusCode,
                                             statusMessage)
import qualified Network.Wreq.Session       as WS
import           OpenSSL
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.EVP.Sign
import           OpenSSL.PEM
import           OpenSSL.RSA
import           OpenSSL.X509.Request
import           Options.Applicative        hiding (header)
import qualified Options.Applicative        as Opt
import           System.Directory
import           System.Process.ByteString

stagingDirectoryUrl, liveDirectoryUrl :: String
liveDirectoryUrl = "https://acme-v01.api.letsencrypt.org/directory"
stagingDirectoryUrl = "https://acme-staging.api.letsencrypt.org/directory"

main :: IO ()
main = execParser opts >>= go
  where
    opts = info (helper <*> cmdopts) (fullDesc <> progDesc detailedDescription <> Opt.header "Let's Encrypt! ACME client")
    detailedDescription = "This is a work in progress."

data CmdOpts = CmdOpts {
      optKeyFile      :: String,
      optDomain       :: String,
      optChallengeDir :: String,
      optDomainDir    :: Maybe String,
      optEmail        :: Maybe String,
      optTerms        :: Maybe String,
      optStaging      :: Bool
}

defaultTerms :: String
defaultTerms = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

cmdopts :: Parser CmdOpts
cmdopts = CmdOpts <$> strOption
                        (long "key" <> metavar "FILE" <> help "filename of your private RSA key")
                  <*> strOption
                        (long "domain" <> metavar "DOMAIN" <> help "the domain name to certify")
                  <*> strOption
                        (long "challenge-dir" <>
                         metavar "DIR" <>
                         help "output directory for ACME challenges")
                  <*> optional
                        (strOption
                           (long "domain-dir" <>
                            metavar "DIR" <>
                            help
                              "directory in which to domain certificates and keys are stored; the default is to use the domain name as a directory name"))
                  <*> optional
                        (strOption
                           (long "email" <>
                            metavar "ADDRESS" <>
                            help "an email address with which to register an account"))
                  <*> optional
                        (strOption
                           (long "terms" <>
                            metavar "URL" <>
                            help "the terms param of the registration request"))
                  <*> switch
                        (long "staging" <> help
                                             "use staging servers instead of live servers (certificates will not be real!)")

genKey :: String -> IO ()
genKey privKeyFile = withOpenSSL $ do
    kp <- generateRSAKey' 4096 65537
    pem <- writePKCS8PrivateKey kp Nothing
    writeFile privKeyFile pem

genReq :: FilePath -> String -> IO ByteString
genReq domainKeyFile domain = withOpenSSL $ do
  (Keys priv pub) <- readKeys domainKeyFile
  Just dig <- getDigestByName "SHA256"
  req <- newX509Req
  setSubjectName req [("CN", domain)]
  setVersion req 0
  setPublicKey req pub
  signX509Req req priv (Just dig)
  pem <- writeX509Req req ReqNewFormat
  -- Sigh.  No DER support for X509 reqs in HsOpenSSL.
  (_, o, _) <- readProcessWithExitCode "openssl" (words "req -outform der") (encodeUtf8 $ T.pack pem)
  return o

data Keys = Keys SomeKeyPair RSAPubKey
readKeys :: String -> IO Keys
readKeys privKeyFile = do
  priv <- readFile privKeyFile >>= flip readPrivateKey PwTTY
  pub <- rsaCopyPublic $ fromMaybe (error "Error: failed to parse RSA key.") (toKeyPair priv :: Maybe RSAKeyPair)
  return $ Keys priv pub

data ChallengeRequest = ChallengeRequest { crUri :: String, crToken :: ByteString, crThumbToken :: ByteString }

go :: CmdOpts -> IO ()
go (CmdOpts privKeyFile domain challengeDir altDomainDir email termOverride staging) = do
  let terms           = fromMaybe defaultTerms termOverride
      directoryUrl    = if staging then stagingDirectoryUrl else liveDirectoryUrl
      domainKeyFile   = domainDir </> "rsa.key"
      domainCSRFile   = domainDir </> "csr.der"
      domainCertFile  = domainDir </> "cert.der"
      domainDir       = fromMaybe domain altDomainDir

  doesFileExist privKeyFile >>= flip unless (genKey privKeyFile)

  doesDirectoryExist domain >>= flip unless (createDirectory domainDir)
  doesFileExist domainKeyFile >>= flip unless (genKey domainKeyFile)

  keys <- readKeys privKeyFile

  doesFileExist domainCSRFile >>= flip unless (genReq domainKeyFile domain >>= B.writeFile domainCSRFile)

  csrData <- B.readFile domainCSRFile

  -- TODO: verify that challengeDir is writable before continuing.

  runACME directoryUrl keys $ do
    forM_ email $ register terms >=> statusReport

    (ChallengeRequest nextUri token thumbtoken) <- challengeRequest domain >>= statusReport >>= extractCR

    liftIO $ BC.writeFile (challengeDir </> BC.unpack token) thumbtoken

    -- TODO: first hit the local server to test whether this is valid

    notifyChallenge nextUri thumbtoken >>= statusReport >>= ncErrorReport

    retrieveCert csrData >>= statusReport >>= saveCert domainCertFile

  where
    a </> b = a ++ "/" ++ b

extractCR :: MonadReader Env m => Response LC.ByteString -> m ChallengeRequest
extractCR r = do
  Keys _ pub <- asks getKeys
  let httpChallenge :: (Value -> Const (Endo s) Value) -> Response LC.ByteString -> Const (Endo s) (Response LC.ByteString)
      httpChallenge = responseBody .
                      JSON.key "challenges" .
                      to universe .
                      traverse .
                      (filtered . has $ ix "type" . only "http-01")

      token = r ^?! httpChallenge . JSON.key "token" . _String . to encodeUtf8
      crUri = r ^?! httpChallenge . JSON.key "uri" . _String . to T.unpack

      thumb = thumbprint (JWK (rsaE pub) "RSA" (rsaN pub))
      thumbtoken = toStrict (LB.fromChunks [token, ".", thumb])

  return $ ChallengeRequest crUri token thumbtoken

ncErrorReport :: (Show body, AsValue body, MonadIO m) => Response body -> m ()
ncErrorReport r =
  when (Just "pending" /= r ^? responseBody . JSON.key "status" . _String) $ liftIO $ do
    putStrLn "Unexpected response to challenge-response request:"
    print r

saveCert :: MonadIO m => FilePath -> Response LC.ByteString -> m ()
saveCert domainCertFile r =
  if isSuccess $ r ^. responseStatus . statusCode
    then liftIO $ LC.writeFile domainCertFile $ r ^. responseBody
    else liftIO $ do
      let (summary, details) = (k "type", k "detail")
          k x = r ^?! responseBody . JSON.key x . _String . to T.unpack
      liftIO $ putStrLn $ summary ++ "  ----  " ++ details
  where
    isSuccess n = n >= 200 && n <= 300

retrieveCert :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => ByteString -> m (Response LC.ByteString)
retrieveCert input = sendPayload _newCert (csr input)

notifyChallenge :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => String -> ByteString -> m (Response LC.ByteString)
notifyChallenge crUri thumbtoken = sendPayload (const crUri) (challenge thumbtoken)

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

runTest :: ACME b -> IO b
runTest t = readKeys "rsa.key" >>= flip (runACME stagingDirectoryUrl) t

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

post :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => String -> LC.ByteString -> m (Response LC.ByteString)
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
