{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Network.ACME where

import           Control.Lens               hiding (each, (.=))
import           Control.Monad
import           Control.Monad.RWS.Strict
import           Data.Aeson                 (Value)
import           Data.Aeson.Lens            hiding (key)
import qualified Data.Aeson.Lens            as JSON
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.Coerce
import           Data.String                (fromString)
import qualified Data.Text                  as T
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)
import           Data.Time.Clock.POSIX      (getPOSIXTime)
import           Network.ACME.Encoding
import           Network.Wreq               (Response, checkStatus, defaults,
                                             responseBody, responseHeader,
                                             responseStatus, statusCode,
                                             statusMessage)
import qualified Network.Wreq               as W
import qualified Network.Wreq.Session       as WS
import           OpenSSL.RSA
import           Pipes
import           System.Directory
import           Text.Email.Validate
import           Text.Domain.Validate hiding (validate)
import           Network.URI

certify :: URI -> Keys -> Maybe EmailAddress -> URI -> [DomainName] -> WritableDir -> CSR -> IO (Either String LC.ByteString)
certify directoryUrl keys optEmail terms requestDomains optChallengeDir csrData =

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

    retrieveCert csrData >>= statusReport <&> checkCertResponse

data ChallengeRequest = ChallengeRequest { crUri :: String, crToken :: ByteString, crThumbToken :: ByteString }

newtype CSR = CSR ByteString

newtype WritableDir = WritableDir String
ensureWritableDir :: FilePath -> String -> IO WritableDir
ensureWritableDir file name = do
  (writable <$> getPermissions file) >>= flip unless (err name)
  return $ WritableDir file
  where err n = error $ "Error: " ++ n ++ " is not writable"

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

checkCertResponse :: Response LC.ByteString -> Either String LC.ByteString
checkCertResponse r =
  if isSuccess $ r ^. responseStatus . statusCode
    then Right $ r ^. responseBody
    else
      let (summary, details) = (k "type", k "detail")
          k x = r ^?! responseBody . JSON.key x . _String . to T.unpack
      in Left $ summary ++ "  ----  " ++ details
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
