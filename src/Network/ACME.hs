{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE ViewPatterns          #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Network.ACME where

import           Control.Arrow
import           Control.Error
import           Control.Lens                 hiding (each, (.=))
import           Control.Monad
import           Control.Monad.RWS.Strict
import           Control.Monad.Trans.Resource hiding (register)
import           Data.Aeson                   (Value)
import           Data.Aeson.Lens              hiding (key)
import qualified Data.Aeson.Lens              as JSON
import           Data.ByteString              (ByteString)
import qualified Data.ByteString.Char8        as BC
import qualified Data.ByteString.Lazy         as LB
import qualified Data.ByteString.Lazy.Char8   as LC
import           Data.Coerce
import           Data.List
import           Data.String                  (fromString)
import qualified Data.Text                    as T
import           Data.Text.Encoding           (decodeUtf8, encodeUtf8)
import           Data.Time.Clock.POSIX        (getPOSIXTime)
import           Network.ACME.Encoding
import           Network.URI
import           Network.Wreq                 (Response, checkStatus, defaults,
                                               responseBody, responseHeader,
                                               responseStatus, statusCode,
                                               statusMessage)
import qualified Network.Wreq                 as W
import qualified Network.Wreq.Session         as WS
import           OpenSSL
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.EVP.Sign             hiding (sign)
import           OpenSSL.PEM
import           OpenSSL.RSA
import           OpenSSL.X509                 (X509, readDerX509)
import           OpenSSL.X509.Request
import           System.Directory
import           Text.Domain.Validate         hiding (validate)
import           Text.Email.Validate

-- The `certify` function

certify :: URI -> Keys -> Maybe (URI, EmailAddress) -> DispatchHttpProvisioner -> CSR -> IO (Either String X509)
certify directoryUrl keys reg provision certReq =
  (mapM readDerX509 =<<) $ runACME directoryUrl keys $ do
    forM_ reg $ uncurry register >=> statusReport

    let performChallenge domain (ChallengeRequest nextUri token thumbtoken) = do
          liftResourceT $ provision domain token thumbtoken
          notifyChallenge nextUri thumbtoken >>= statusReport >>= ncErrorReport

        cr dom = challengeRequest dom >>= statusReport >>= extractCR >>= performChallenge dom

    runResourceT $ do
      challengeResultLinks <- forM (csrDomains certReq) cr
      lift . runExceptT $ do
        ExceptT $ pollResults challengeResultLinks <&> left ("certificate receipt was not attempted because a challenge failed: " ++)
        ExceptT $ retrieveCert certReq >>= statusReport <&> checkCertResponse

pollResults :: [Response LC.ByteString] -> ACME (Either String ())
pollResults [] = return $ Right ()
pollResults (link:links) = do
  -- TODO: use "Retry-After" header if present
  let Just uri = link ^? responseBody . JSON.key "uri" . _String
  r <- liftIO $ W.get (T.unpack uri) >>= statusReport
  let status = r ^. responseBody . JSON.key "status" . _String
  case status of
    "pending" -> pollResults $ links ++ [r]
    "valid"   -> pollResults links
    "invalid" -> return . Left $ r ^. responseBody . JSON.key "error" . to extractAcmeError
    _         -> return . Left $ "unexpected response from ACME server: " ++ show r

-- Provisioner callback

type DispatchHttpProvisioner = DomainName -> ByteString -> ByteString -> ResIO ()
fileProvisioner :: WritableDir -> DispatchHttpProvisioner
fileProvisioner challengeDir _ = provisionViaFile challengeDir

type HttpProvisioner = ByteString -> ByteString -> ResIO ()

dispatchProvisioner :: [(DomainName, HttpProvisioner)] -> DispatchHttpProvisioner
dispatchProvisioner xs = dispatch (`lookup` xs)
  where
    dispatch :: (DomainName -> Maybe HttpProvisioner) -> DispatchHttpProvisioner
    dispatch dispatchFunc (dispatchFunc -> Just provision) = provision
    dispatch _ dom = const . const . liftIO $ fail errmsg
      where errmsg = "No means specified to provision files over HTTP for domain: " ++ show dom

provisionViaFile :: WritableDir -> HttpProvisioner
provisionViaFile dir tok thumbtoken = do
  void $ allocate (return f) removeFile
  liftIO $ BC.writeFile f thumbtoken

  where
    f = (coerce dir </>) (T.unpack $ decodeUtf8 tok)

newtype WritableDir = WritableDir String
ensureWritableDir :: FilePath -> String -> IO WritableDir
ensureWritableDir file name = do
  (writable <$> getPermissions file) >>= flip unless (e name)
  return $ WritableDir file
  where e n = error $ "Error: " ++ n ++ " is not writable"

canProvision :: DomainName -> HttpProvisioner -> IO Bool
canProvision domain provision = do
  token <- (".test." ++) . show <$> getPOSIXTime
  r <- runResourceT $ do
         provision (fromString token) (fromString token)
         liftIO $ W.get $ show $ acmeChallengeURI domain (fromString token)
  return $ r ^. responseBody == fromString token

canProvisionDir :: WritableDir -> DomainName -> IO Bool
canProvisionDir challengeDir domain = canProvision domain (provisionViaFile challengeDir)

-- The ACME monad

data Directory = Directory {
  _newCert    :: String,
  _newAuthz   :: String,
  _revokeCert :: String,
  _newReg     :: String
}
newtype Nonce = Nonce String
data Env = Env { getDir :: Directory, getKeys :: Keys, getSession :: WS.Session }
type ACME = RWST Env () Nonce IO

runACME :: URI -> Keys -> ACME a -> IO a
runACME url keys f = WS.withSession $ \sess -> do
  Just (dir, nonce) <- getDirectory sess (show url)
  fst <$> evalRWST f (Env dir keys sess) nonce

post :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => String -> LC.ByteString -> m (Response LC.ByteString)
post url payload = do
  sess <- asks getSession
  r <- liftIO $ WS.postWith noStatusCheck sess url payload
  put $ r ^?! responseHeader "Replay-Nonce" . to (Nonce . T.unpack . decodeUtf8)
  return r
  where
    noStatusCheck = defaults & checkStatus .~ Just nullChecker
    nullChecker _ _ _ = Nothing

sendPayload :: (MonadIO m, MonadState Nonce m, MonadReader Env m) => (Directory -> String) -> ByteString -> m (Response LC.ByteString)
sendPayload reqType payload = do
  keys <- asks getKeys
  dir <- asks getDir
  nonce <- gets coerce
  signed <- liftIO $ signPayload keys nonce payload
  post (reqType dir) signed

signPayload :: Keys -> String -> ByteString -> IO LC.ByteString
signPayload (Keys priv pub) = signPayload' sign pub
  where
    sign x = do
      Just dig <- getDigestByName "SHA256"
      signBS dig priv x

-- Generating ACME requests

getDirectory :: WS.Session -> String -> IO (Maybe (Directory, Nonce))
getDirectory sess url = do
  r <- WS.get sess url
  let nonce = r ^? responseHeader "Replay-Nonce" . to (Nonce . T.unpack . decodeUtf8)
      k x   = r ^? responseBody . JSON.key x . _String . to T.unpack
  return $ (,) <$> (Directory <$> k "new-cert" <*> k "new-authz" <*> k "revoke-cert" <*> k "new-reg") <*> nonce

retrieveCert :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => CSR -> m (Response LC.ByteString)
retrieveCert input = sendPayload _newCert (csr $ csrData input)

notifyChallenge :: (MonadReader Env m, MonadState Nonce m, MonadIO m) => String -> ByteString -> m (Response LC.ByteString)
notifyChallenge uri thumbtoken = sendPayload (const uri) (challenge thumbtoken)

register :: URI -> EmailAddress -> ACME (Response LC.ByteString)
register terms email = sendPayload _newReg (registration email (show terms))

challengeRequest :: (MonadIO m, MonadState Nonce m, MonadReader Env m) => DomainName -> m (Response LC.ByteString)
challengeRequest = sendPayload _newAuthz . authz . domainToString

-- Handling ACME responses

data ChallengeRequest = ChallengeRequest { crUri :: String, crToken :: ByteString, crThumbToken :: ByteString }
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
      nextU = r ^?! httpChallenge . JSON.key "uri" . _String . to T.unpack

      thumb = thumbprint (JWK (rsaE pub) "RSA" (rsaN pub))
      thumbtoken = toStrict (LB.fromChunks [token, ".", thumb])

  return $ ChallengeRequest nextU token thumbtoken

ncErrorReport :: (Show body, AsValue body, MonadIO m) => Response body -> m (Response body)
ncErrorReport r = do
  when (Just "pending" /= r ^? responseBody . JSON.key "status" . _String) $ liftIO $ do
    putStrLn "Unexpected response to challenge-response request:"
    print r
  return r

extractAcmeError :: forall s. AsValue s => s -> String
extractAcmeError r = summary ++ "  ----  " ++ details
  where
    (Just summary, Just details) = (k "type", k "detail")
    k x = r ^? JSON.key x . _String . to T.unpack

checkCertResponse :: Response LC.ByteString -> Either String LC.ByteString
checkCertResponse r =
  if isSuccess $ r ^. responseStatus . statusCode
    then Right $ r ^. responseBody
    else Left $ r ^. responseBody . to extractAcmeError
  where
    isSuccess n = n >= 200 && n < 300

statusLine :: Response body -> String
statusLine r = x ++ " " ++ y
  where
    x = r ^. responseStatus . statusCode . to show
    y = r ^. responseStatus . statusMessage . to (T.unpack . decodeUtf8)

statusReport :: MonadIO m => Response body -> m (Response body)
statusReport r = do
  liftIO $ putStrLn $ statusLine r
  return r

-- OpenSSL operations

data CSR = CSR { csrDomains :: [DomainName], csrData :: ByteString }
genReq :: Keys -> [DomainName] -> IO CSR
genReq _ [] = error "genReq called with zero domains"
genReq (Keys priv pub) domains@(domain:_) = withOpenSSL $ do
  Just dig <- getDigestByName "SHA256"
  req <- newX509Req
  setSubjectName req [("CN", domainToString domain)]
  setVersion req 0
  setPublicKey req pub
  void $ addExtensions req [(nidSubjectAltName, intercalate ", " (map (("DNS:" ++) . domainToString) domains))]
  signX509Req req priv (Just dig)
  CSR domains . toStrict <$> writeX509ReqDER req
  where
    nidSubjectAltName = 85

data Keys = Keys RSAKeyPair RSAPubKey
readKeys :: String -> IO (Maybe Keys)
readKeys privKeyData = do
  priv <- toKeyPair <$> readPrivateKey privKeyData PwTTY
  pub <- mapM rsaCopyPublic priv
  return $ Keys <$> priv <*> pub

-- General utility

(</>) :: String -> String -> String
a </> b = a ++ "/" ++ b
infixr 5 </>

domainToString :: DomainName -> String
domainToString = T.unpack . decodeUtf8 . Text.Domain.Validate.toByteString

acmeChallengeURI :: DomainName -> BC.ByteString -> URI
acmeChallengeURI dom tok = URI "http:" dom' tok' "" ""
  where
    dom' = Just $ URIAuth "" (domainToString dom) ""
    tok' = "/.well-known/acme-challenge" </> BC.unpack tok
