{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Main where

import           Control.Lens               hiding (each, (.=))
import           Control.Monad
import           Control.Monad.RWS.Strict
import           Data.Aeson                 (Value)
import           Data.Aeson.Lens            hiding (key)
import qualified Data.Aeson.Lens            as JSON
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.Coerce
import           Data.List
import           Data.Maybe
import           Data.String                (fromString)
import qualified Data.Text                  as T
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)
import           Data.Time.Clock.POSIX      (getPOSIXTime)
import           Network.ACME
import           Network.Wreq               (Response, checkStatus, defaults,
                                             responseBody, responseHeader,
                                             responseStatus, statusCode,
                                             statusMessage)
import qualified Network.Wreq               as W
import qualified Network.Wreq.Session       as WS
import           OpenSSL
import           OpenSSL.EVP.Digest
import           OpenSSL.PEM
import           OpenSSL.RSA
import           OpenSSL.X509.Request
import           Options.Applicative        hiding (header)
import qualified Options.Applicative        as Opt
import           Pipes
import           System.Directory
import           Text.Email.Validate
import           Text.Domain.Validate hiding (validate)
import           Network.URI

stagingDirectoryUrl, liveDirectoryUrl :: URI
Just liveDirectoryUrl = parseAbsoluteURI "https://acme-v01.api.letsencrypt.org/directory"
Just stagingDirectoryUrl = parseAbsoluteURI "https://acme-staging.api.letsencrypt.org/directory"

main :: IO ()
main = execParser opts >>= go
  where
    opts = info (helper <*> cmdopts) (fullDesc <> progDesc detailedDescription <> Opt.header "Let's Encrypt! ACME client")
    detailedDescription = unwords
                            [ "This program will generate a signed TLS certificate"
                            , "using the ACME protocol and the free Let's Encrypt! CA."
                            ]

data CmdOpts = CmdOpts {
      optKeyFile      :: String,
      optDomains      :: [String],
      optChallengeDir :: String,
      optDomainDir    :: Maybe String,
      optEmail        :: Maybe String,
      optTerms        :: Maybe String,
      optStaging      :: Bool
}

defaultTerms :: URI
Just defaultTerms = parseAbsoluteURI "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

cmdopts :: Parser CmdOpts
cmdopts = CmdOpts <$> strOption (long "key" <> metavar "FILE" <>
                                 help "filename of your private RSA key")
                  <*> some
                        (strOption
                           (long "domain" <>
                            metavar "DOMAIN" <>
                            help
                              (unwords
                                 [ "the domain name(s) to certify;"
                                 , "specify more than once for a multi-domain certificate"
                                 ])))
                  <*> strOption (long "challenge-dir" <> metavar "DIR" <>
                                 help "output directory for ACME challenges")
                  <*> optional
                        (strOption
                           (long "domain-dir" <>
                            metavar "DIR" <>
                            help
                              (unwords
                                 [ "directory in which to domain certificates and keys are stored;"
                                 , "the default is to use the (first) domain name as a directory name"
                                 ])))
                  <*> optional
                        (strOption (long "email" <> metavar "ADDRESS" <>
                                    help "an email address with which to register an account"))
                  <*> optional (strOption (long "terms" <> metavar "URL" <>
                                           help "the terms param of the registration request"))
                  <*> switch
                        (long "staging" <> help
                                             (unwords
                                                [ "use staging servers instead of live servers"
                                                , "(generated certificates will not be trusted!)"
                                                ]))

genKey :: String -> IO ()
genKey privKeyFile = withOpenSSL $ do
    kp <- generateRSAKey' 4096 65537
    pem <- writePKCS8PrivateKey kp Nothing
    writeFile privKeyFile pem

genReq :: FilePath -> [DomainName] -> IO LC.ByteString
genReq _ [] = error "genReq called with zero domains"
genReq domainKeyFile domains@(domain:_) = withOpenSSL $ do
  Just (Keys priv pub) <- readKeyFile domainKeyFile
  Just dig <- getDigestByName "SHA256"
  req <- newX509Req
  setSubjectName req [("CN", show domain)]
  setVersion req 0
  setPublicKey req pub
  void $ addExtensions req [(nidSubjectAltName, intercalate ", " (map (("DNS:" ++) . show) domains))]
  signX509Req req priv (Just dig)
  writeX509ReqDER req
  where
    nidSubjectAltName = 85

readKeyFile :: FilePath -> IO (Maybe Keys)
readKeyFile = readFile >=> readKeys

data ChallengeRequest = ChallengeRequest { crUri :: String, crToken :: ByteString, crThumbToken :: ByteString }

otherwiseM :: Monad m => m Bool -> m () -> m ()
a `otherwiseM` b = a >>= flip unless b
infixl 0 `otherwiseM`

go :: CmdOpts -> IO ()
go CmdOpts { .. } = do
  let terms           = fromMaybe defaultTerms (join $ parseAbsoluteURI <$> optTerms)
      directoryUrl    = if optStaging then stagingDirectoryUrl else liveDirectoryUrl
      domainKeyFile   = domainDir </> "rsa.key"
      domainCSRFile   = domainDir </> "csr.der"
      domainCertFile  = domainDir </> "cert.der"
      domainDir       = fromMaybe (head optDomains) optDomainDir
      privKeyFile     = optKeyFile
      requestDomains  = fromMaybe (error "invalid domain name") $ sequence $ domainName . fromString <$> optDomains

  doesFileExist privKeyFile `otherwiseM` genKey privKeyFile

  doesDirectoryExist domainDir `otherwiseM` createDirectory domainDir
  doesFileExist domainKeyFile `otherwiseM` genKey domainKeyFile

  Just keys <- readKeyFile privKeyFile

  challengeDir <- ensureWritableDir optChallengeDir "challenge directory"
  void $ ensureWritableDir domainDir "domain directory"

  forM_ requestDomains $ canProvision challengeDir >=> (`unless` error "Error: cannot provision files to web server via challenge directory")

  csrData <- CSR . toStrict <$> genReq domainKeyFile requestDomains
  B.writeFile domainCSRFile (coerce csrData)

  let email = either (error . ("Error: invalid email address: " ++)) id . validate . fromString <$> optEmail

  certify directoryUrl keys email terms requestDomains challengeDir csrData domainCertFile

certify :: URI -> Keys -> Maybe EmailAddress -> URI -> [DomainName] -> WritableDir -> CSR -> FilePath -> IO ()
certify directoryUrl keys optEmail terms requestDomains optChallengeDir csrData domainCertFile =

  runACME directoryUrl keys $ do
    forM_ optEmail $ register terms >=> statusReport

    let producer :: Producer ChallengeRequest ACME ()
        producer = for (each requestDomains) $ challengeRequest >=> statusReport >=> extractCR >=> yield
        consumer :: Consumer ChallengeRequest ACME ()
        consumer = forever $ await >>= consume1
        consume1 (ChallengeRequest nextUri token thumbtoken) = do
          lift $ liftIO $ BC.writeFile (coerce optChallengeDir </> BC.unpack token) thumbtoken
          notifyChallenge nextUri thumbtoken >>= statusReport >>= ncErrorReport

    runEffect $ producer >-> consumer

    retrieveCert csrData >>= statusReport >>= saveCert domainCertFile

newtype CSR = CSR ByteString

(</>) :: String -> String -> String
a </> b = a ++ "/" ++ b
infixr 5 </>

canProvision :: WritableDir -> DomainName -> IO Bool
canProvision challengeDir domain = do
  randomish <- fromString . show <$> getPOSIXTime

  let absFile = coerce challengeDir </> relFile
      relFile = ".test." ++ show randomish

  LC.writeFile absFile randomish
  r <- W.get $ "http://" ++ show domain </> ".well-known/acme-challenge" </> relFile
  removeFile absFile
  return $ r ^. responseBody == randomish


newtype WritableDir = WritableDir String
ensureWritableDir :: FilePath -> String -> IO WritableDir
ensureWritableDir file name = do
  (writable <$> getPermissions file) >>= flip unless (err name)
  return $ WritableDir file
  where err n = error $ "Error: " ++ n ++ " is not writable"

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

retrieveCert :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => CSR -> m (Response LC.ByteString)
retrieveCert input = sendPayload _newCert (csr $ coerce input)

notifyChallenge :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => String -> ByteString -> m (Response LC.ByteString)
notifyChallenge crUri thumbtoken = sendPayload (const crUri) (challenge thumbtoken)

data Env = Env { getDir :: Directory, getKeys :: Keys, getSession :: WS.Session }

type ACME = RWST Env () Nonce IO
runACME :: URI -> Keys -> ACME a -> IO a
runACME url keys f = WS.withSession $ \sess -> do
  Just (dir, nonce) <- getDirectory sess (show url)
  fst <$> evalRWST f (Env dir keys sess) nonce

data Directory = Directory {
  _newCert    :: String,
  _newAuthz   :: String,
  _revokeCert :: String,
  _newReg     :: String
}
newtype Nonce = Nonce String

getDirectory :: WS.Session -> String -> IO (Maybe (Directory, Nonce))
getDirectory sess url = do
  r <- WS.get sess url
  let nonce = r ^? responseHeader "Replay-Nonce" . to (Nonce . T.unpack . decodeUtf8)
      k x   = r ^? responseBody . JSON.key x . _String . to T.unpack
  return $ (,) <$> (Directory <$> k "new-cert" <*> k "new-authz" <*> k "revoke-cert" <*> k "new-reg") <*> nonce

register :: URI -> EmailAddress -> ACME (Response LC.ByteString)
register terms email = sendPayload _newReg (registration email (show terms))

challengeRequest :: (MonadIO m, MonadState Nonce m, MonadReader Env m) => DomainName -> m (Response LC.ByteString)
challengeRequest = sendPayload _newAuthz . authz . show

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

