{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE MultiWayIf           #-}
{-# LANGUAGE NamedFieldPuns       #-}
{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE ViewPatterns         #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Main where

import           BasePrelude
import           Control.Lens                 hiding (argument, (&))
import           Control.Monad.Except
import           Control.Monad.Trans.Resource
import           Data.Aeson.Lens
import qualified Data.HashMap.Strict          as HashMap
import           Data.Text                    (Text, pack, unpack)
import           Data.Text.Encoding           (decodeUtf8, encodeUtf8)
import           Data.Time.Clock
import           Data.Yaml                    (Object)
import qualified Data.Yaml.Config             as Config
import           Data.Yaml.Config.Internal    (Config (..))
import           Network.ACME                 (HttpProvisioner, Keys (..),
                                               canProvision, certify,
                                               ensureWritableDir,
                                               provisionViaFile, readKeys,
                                               (</>))
import           Network.ACME.Issuer          (letsEncryptX3CrossSigned)
import           Network.URI
import           OpenSSL
import           OpenSSL.DH
import           OpenSSL.PEM
import           OpenSSL.RSA
import           OpenSSL.X509                 (X509, getNotAfter)
import           Options.Applicative          hiding (header)
import qualified Options.Applicative          as Opt
import           System.Directory
import           System.IO
import           System.Posix.Escape
import           System.Process
import           Text.Domain.Validate         hiding (validate)
import           Text.Email.Validate

import qualified Data.ASN1.Types              (ASN1Object)
import qualified Data.ByteString              as B
import           Data.PEM                     (pemContent, pemParseBS)
import qualified Data.X509                    as X509

defaultUpdateConfigFile :: FilePath
defaultUpdateConfigFile = "config.yaml"

stagingDirectoryUrl, liveDirectoryUrl, defaultTerms :: URI
Just liveDirectoryUrl    = parseAbsoluteURI "https://acme-v01.api.letsencrypt.org/directory"
Just stagingDirectoryUrl = parseAbsoluteURI "https://acme-staging.api.letsencrypt.org/directory"
Just defaultTerms        = parseAbsoluteURI "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

main :: IO ()
main = execParser (info opts idm) >>= run
  where
    opts :: Parser Options
    opts = Options <$> parseCommand
    parseCommand :: Parser Command
    parseCommand = subparser $
      command "certify" (info (helper <*> certifyOpts) desc) <>
      command "update"  (info (helper <*> updateOpts)  desc)
    desc = fullDesc <> progDesc detailedDescription <> Opt.header "Let's Encrypt! ACME client"
    detailedDescription = unwords
                            [ "This program will generate a signed TLS certificate"
                            , "using the ACME protocol and the free Let's Encrypt! CA."
                            ]
run :: Options -> IO ()
run (Options (Certify opts)) = runCertify opts >>= either (error . ("Error: " ++)) return
run (Options (Update opts)) = runUpdate opts

data Command = Certify CertifyOpts | Update UpdateOpts

data Options = Options {
      optCommand :: Command
}

data CertifyOpts = CertifyOpts {
      optKeyFile            :: String,
      optDomains            :: [String],
      optChallengeDir       :: String,
      optDomainDir          :: Maybe String,
      optEmail              :: Maybe String,
      optTerms              :: Maybe String,
      optSkipDH             :: Bool,
      optStaging            :: Bool,
      optSkipProvisionCheck :: Bool
}

data UpdateOpts = UpdateOpts {
      updateConfigFile       :: Maybe FilePath,
      updateHosts            :: [String],
      updateStaging          :: Bool,
      updateDryRun           :: Bool,
      updateDoPrivisionCheck :: Bool,
      updateTryVHosts        :: [String]
}

updateOpts :: Parser Command
updateOpts = fmap Update $
  UpdateOpts <$> optional
                   (strOption
                      (long "config" <>
                       metavar "FILENAME" <>
                       help "location of YAML configuration file"))
             <*> many (argument str (metavar "HOSTS"))
             <*> stagingSwitch
             <*> switch
                   (long "dry-run" <> help
                                        (unwords
                                           [ "Do not fetch any certificates; only tests"
                                           , "configuration file and http provisioning"
                                           ]))
             <*> pure True
             <*> many
                   (strOption
                      (long "try" <>
                       metavar "DOMAIN" <>
                       help
                         (unwords
                            [ "When specified, only specified domains will be checked"
                            , "for the ability to provision HTTP files; when not"
                            , "specified, all domains will be checked"
                            ])))

-- TODO: global options
stagingSwitch :: Parser Bool
stagingSwitch =
  switch
    (long "staging" <> help
                         (unwords
                            [ "Use staging servers instead of live servers"
                            , "(generated certificates will not be trusted!)"
                            ]))

certifyOpts :: Parser Command
certifyOpts = fmap Certify $
  CertifyOpts <$> strOption (long "key" <> metavar "FILE" <>
                             help "Filename of your private RSA key")
              <*> some
                    (strOption
                       (long "domain" <>
                        metavar "DOMAIN" <>
                        help
                          (unwords
                             [ "The domain name(s) to certify;"
                             , "specify more than once for a multi-domain certificate"
                             ])))
              <*> strOption (long "challenge-dir" <> metavar "DIR" <>
                             help "Output directory for ACME challenges")
              <*> optional
                    (strOption
                       (long "domain-dir" <>
                        metavar "DIR" <>
                        help
                          (unwords
                             [ "Directory in which to domain certificates and keys are stored;"
                             , "the default is to use the (first) domain name as a directory name"
                             ])))
              <*> optional (strOption (long "email" <> metavar "ADDRESS" <>
                                       help "An email address with which to register an account"))
              <*> optional (strOption (long "terms" <> metavar "URL" <>
                                       help "The terms param of the registration request"))
              <*> switch (long "skip-dhparams" <> help "Don't generate DH params for combined cert")
              <*> stagingSwitch
              <*> switch
                    (long "skip-provision-check" <> help
                                                      (unwords
                                                         [ "Don't test whether HTTP provisioning works before"
                                                         , "making ACME requests"
                                                         ]))

instance Show HttpProvisioner where
    show _ = "<code>"
instance Show Keys where
    show _ = "<keys>"

data CertSpec = CertSpec {
      csDomains        :: [(DomainName, HttpProvisioner)],
      csSkipDH         :: Bool,
      csCertificateDir :: FilePath,
      csUserKeys       :: Keys
} deriving Show

certAltNames :: X509.SignedExact X509.Certificate -> [String]
certAltNames sc = toListOf (_Just . _Right . to strip1 . folded) altNames & mapMaybe strip2
  where
    altNames :: Maybe (Either String X509.ExtSubjectAltName)
    altNames = X509.extensionGetE $ X509.certExtensions $ X509.signedObject $ X509.getSigned sc
    strip1 (X509.ExtSubjectAltName x) = x
    strip2 (X509.AltNameDNS x) = Just x
    strip2 _ = Nothing

data NeedCertReason = Expired | NearExpiration | SubDomainsAdded | NoExistingCert | InvalidExistingCert deriving Show
needToFetch :: CertSpec -> IO (Either NeedCertReason ())
needToFetch cs@CertSpec{..} = runExceptT $ do
  exists <- liftIO $ doesFileExist certFile
  unless exists $ throwError NoExistingCert

  -- TODO: parse with cryptonite
  cert <- liftIO $ readFile certFile >>= readX509
  expiration <- liftIO $ getNotAfter cert
  now <- liftIO getCurrentTime

  signedCert <- (liftIO (readSignedObject certFile) >>=) $
                maybe (throwError InvalidExistingCert) return . preview (folded . _Right)
  let wantedDomains = domainToString . fst <$> csDomains
      haveDomains = certAltNames signedCert
  unless (null $ wantedDomains \\ haveDomains) $ throwError SubDomainsAdded

  if | expiration < now                      -> throwError Expired
     | expiration < addUTCTime graceTime now -> throwError NearExpiration
     | otherwise                             -> return ()
  where
    graceTime = days 20
    days = (*) (24 * 60 * 60)
    certFile = domainCertFile cs

readSignedObject :: (Eq a, Show a, Data.ASN1.Types.ASN1Object a) => FilePath -> IO [Either String (X509.SignedExact a)]
readSignedObject =
  B.readFile >=> return .
                 either error (map (X509.decodeSignedObject . pemContent)) . pemParseBS

configGetCertReqs :: Config -> IO [(String, DomainName, [VHostSpec])]
configGetCertReqs hostsConfig = do
  fmap concat $ forM (Config.keys hostsConfig) $ \host ->
    do
      hostParts <- (Config.subconfig host hostsConfig >>= Config.subconfig "domains") <&> extractObject
      return $ flip map (HashMap.keys hostParts) $ \domain ->
        (unpack host, domainName' $ unpack domain, combineSubdomains domain hostParts)

combineSubdomains :: AsPrimitive v => Text -> HashMap.HashMap Text v -> [VHostSpec]
combineSubdomains domain subs =
  map (makeVHostSpec (domainName' $ unpack domain)) $
    sort -- '.' sorts first
      $ concat $ HashMap.lookup domain subs & toListOf (_Just . _String . to (words . unpack))

extractObject :: Config -> Object
extractObject (Config _ o) = o

runUpdate :: UpdateOpts -> IO ()
runUpdate UpdateOpts { .. } = do
  issuerCert <- readX509 letsEncryptX3CrossSigned

  config <- Config.load $ fromMaybe defaultUpdateConfigFile updateConfigFile
  certReqDomains <- configGetCertReqs =<< Config.subconfig "hosts" config

  globalCertificateDir <- getHomeDirectory <&> (</> if updateStaging then ".acme/fake-certs" else ".acme/certs")
  createDirectoryIfMissing True globalCertificateDir

  Just keys <- getOrCreateKeys $ globalCertificateDir </> "rsa.key"

  let mbCertSpecs :: [(String, DomainName, Maybe CertSpec)]
      mbCertSpecs = flip map certReqDomains $ \(host, domain, domains) -> (,,) host domain $
                    dereference (map (chooseProvisioner host) domains) <&> certSpec globalCertificateDir keys host domain

  validCertSpecs <- forM mbCertSpecs $ \(host, domain, mbSpec) ->
                      maybe (error $ "Invalid configuration.  Host = " ++ host ++ ", domain = " ++ show domain)
                            (return . (,,) host domain)
                            mbSpec

  let wantedCertSpecs = filter (wantUpdate . view _1) validCertSpecs

  when updateDoPrivisionCheck $
    forM_ (view _3 <$> wantedCertSpecs) $ \spec ->
      forM_ (filter (wantProvisionCheck . fst) $ csDomains spec) $ \csd -> do
        putStrLn $ "Provision check: " ++ (domainToString . fst $ csd)
        can <- uncurry canProvision csd
        unless can $ error "Error: cannot provision files to web server"

  when (null updateTryVHosts) $ forM_ wantedCertSpecs $ \(_, domain, spec) -> do

    let terms              = defaultTerms
        directoryUrl       = if updateStaging then stagingDirectoryUrl else liveDirectoryUrl
        email              = emailAddress $ encodeUtf8 . pack $ "root@" ++ (domainToString . fst . head) (csDomains spec)

    (needToFetch spec >>=) $ leftMapM_ $ \reason -> do
      putStrLn $ concat ["New certificate needed (for domain ", domainToString domain, "): ", show reason]
      if updateDryRun
      then putStrLn "Dry run: nothing fetched, nothing saved."
      else print =<< fetchCertificate directoryUrl terms email issuerCert spec

  where

    elemOrNull :: Eq a => [a] -> a -> Bool
    elemOrNull xs x = null xs || x `elem` xs

    wantProvisionCheck :: DomainName -> Bool
    wantProvisionCheck = elemOrNull updateTryVHosts . domainToString

    wantUpdate :: String -> Bool
    wantUpdate = elemOrNull updateHosts

    dereference :: [(DomainName, Either DomainName HttpProvisioner)] -> Maybe [(DomainName, HttpProvisioner)]
    dereference xs = plumb $ xs <&> fmap (either deref Just)
      where
        deref :: DomainName -> Maybe HttpProvisioner
        deref s = lookup s xs & preview (_Just . _Right)
        plumb = traverse (\(a, b) -> fmap ((,) a) b)

    chooseProvisioner :: String -> VHostSpec -> (DomainName, Either DomainName HttpProvisioner)
    chooseProvisioner host (VHostSpec domain pathInfo) =
      (domain, provisionViaRemoteFile host <$> pathInfo)

    certSpec :: FilePath -> Keys -> String -> DomainName -> [(DomainName, HttpProvisioner)] -> CertSpec
    certSpec baseDir keys host domain requestDomains = CertSpec { .. }
      where
        csDomains = requestDomains
        csSkipDH = True -- TODO: implement
        csUserKeys = keys
        csCertificateDir = baseDir </> host </> domainToString domain

domainToString :: DomainName -> String
domainToString = unpack . decodeUtf8 . Text.Domain.Validate.toByteString

data VHostSpec = VHostSpec DomainName (Either DomainName FilePath) deriving Show
makeVHostSpec :: DomainName -> String -> VHostSpec
makeVHostSpec parentDomain vhostSpecStr = VHostSpec (domainName' vhostName) (left domainName' spec)
  where
    vhostName = appendParent sub
    (sub, spec) = splitSpec vhostSpecStr

    splitSpec :: String -> (String, Either String FilePath)
    splitSpec (break (== '{') -> (a, b)) = (,) a $
      case b of
        ('{':c@('/':_)) -> Right $ takeWhile (/= '}') c
        ('{':c)         -> Left  $ takeWhile (/= '}') c & appendParent
        _               -> Right $ "/srv" </> vhostName </> "public_html"

    appendParent = (<..> domainToString parentDomain)

data TempRemover = TempRemover { removeTemp :: IO () }
remoteTemp :: String -> FilePath -> String -> IO TempRemover
remoteTemp host fileName content = do
  (inp,out,err,_pid) <- ssh $ unlines
    [ "mkdir -p " ++ escape (dirname fileName)
    , "printf '%s' " ++ escape content ++ " > " ++ escape fileName
    , "echo provisioned."
    , "trap " ++ (escape . unwords) ["rm -f", escape fileName] ++ " EXIT"
    , "read line"
    ]
  void $ hGetLine out
  return $ TempRemover $ mapM_ hClose [inp, out, err]
  where
    ssh cmd = runInteractiveProcess "ssh" (host : words "-- sh -c" ++ [escape cmd]) Nothing Nothing

dirname :: String -> String
dirname = dropWhileEnd (/= '/')

provisionViaRemoteFile :: String -> FilePath -> HttpProvisioner
provisionViaRemoteFile = provision
  where
    provision host dir (bsToS -> tok) (bsToS -> thumbtoken) =
      void $ allocate (liftIO $ remoteTemp host (dir </> wk </> tok) thumbtoken) removeTemp
    wk = ".well-known/acme-challenge"
    bsToS = unpack . decodeUtf8

runCertify :: CertifyOpts -> IO (Either String ())
runCertify CertifyOpts{..} = do
  let terms              = fromMaybe defaultTerms (join $ parseAbsoluteURI <$> optTerms)
      directoryUrl       = if optStaging then stagingDirectoryUrl else liveDirectoryUrl
      domainDir          = fromMaybe (head optDomains) optDomainDir
      privKeyFile        = optKeyFile
      requestDomains     = map domainName' optDomains
      email              = either (error . ("Error: invalid email address: " ++)) id . validate . fromString <$> optEmail

  issuerCert <- readX509 letsEncryptX3CrossSigned -- TODO: Don't use fixed issuer certificate.  It changed before; it will again.

  seq email (return ())
  createDirectoryIfMissing False domainDir
  challengeDir <- ensureWritableDir optChallengeDir "challenge directory"
  void $ ensureWritableDir domainDir "domain directory"

  Just keys <- getOrCreateKeys privKeyFile

  let spec = CertSpec {..}
      csDomains        = map (flip (,) (provisionViaFile challengeDir)) requestDomains
      csSkipDH         = optSkipDH
      csUserKeys       = keys
      csCertificateDir = domainDir

  unless optSkipProvisionCheck $
    forM_ csDomains $ uncurry canProvision >=>
      (`unless` error "Error: cannot provision files to web server")

  fetchCertificate directoryUrl terms email issuerCert spec

fetchCertificate :: URI -> URI -> Maybe EmailAddress -> X509 -> CertSpec -> IO (Either String ())
fetchCertificate directoryUrl terms email issuerCert cs@CertSpec{..} = do
  Just domainKeys <- getOrCreateKeys $ csCertificateDir </> "rsa.key"
  dh <- saveDhParams cs

  certificate <- certify directoryUrl csUserKeys ((,) terms <$> email) domainKeys csDomains
  for certificate $ saveCertificate issuerCert dh domainKeys cs

saveDhParams :: CertSpec -> IO (Maybe DHP)
saveDhParams cs@CertSpec{csSkipDH} =
  if csSkipDH then return Nothing else Just <$> getOrCreateDH (domainDhFile cs)

saveCertificate :: X509 -> Maybe DHP -> Keys -> CertSpec -> X509 -> IO ()
saveCertificate issuerCert dh domainKeys cs = saveBoth
  where
    saveBoth x509      = savePEM x509 >> saveCombined x509
    saveCombined       = combinedCert issuerCert dh domainKeys >=> writePrivateFile (domainCombinedFile cs)
    savePEM            = writeX509                             >=> writePrivateFile (domainCertFile cs)

writePrivateFile :: FilePath -> String -> IO ()
writePrivateFile fn content = do
  touchFile fn
  setPermissions fn privatePerms
  writeFile fn content
  where
    privatePerms = emptyPermissions & setOwnerReadable True & setOwnerWritable True

touchFile :: FilePath -> IO ()
touchFile fn = writeFile fn ""

domainDhFile :: CertSpec -> FilePath
domainDhFile CertSpec{..} = csCertificateDir </> "dhparams.pem"

domainCombinedFile :: CertSpec -> FilePath
domainCombinedFile CertSpec{..} = csCertificateDir </> "cert.combined.pem"

domainCertFile :: CertSpec -> FilePath
domainCertFile CertSpec{..} = csCertificateDir </> "cert.pem"

genKey :: IO String
genKey = withOpenSSL $ do
  kp <- generateRSAKey' 4096 65537
  writePKCS8PrivateKey kp Nothing

getOrCreate :: IO String -> (String -> IO a) -> FilePath -> IO a
getOrCreate gen parse file = do
  exists <- doesFileExist file
  createDirectoryIfMissing True (dirname file)
  parse =<< if exists then readFile file else gen >>= save file
  where
    save f x = writeFile f x >> return x

getOrCreateKeys :: FilePath -> IO (Maybe Keys)
getOrCreateKeys = getOrCreate genKey readKeys

getOrCreateDH :: FilePath -> IO DHP
getOrCreateDH = getOrCreate (genDHParams' >>= writeDHParams) readDHParams

domainName' :: String -> DomainName
domainName' dom = fromMaybe (error $ "Error: invalid domain name: " ++ dom) (domainName $ fromString dom)

genDHParams' :: IO DHP
genDHParams' = do
  hSetBuffering stdout NoBuffering
  putStr "Generating DH Params..."
  dh <- genDHParams DHGen2 2048
  putStrLn "  Done."
  return dh

combinedCert :: X509 -> Maybe DHP -> Keys -> X509 -> IO String
combinedCert issuerCert dh (Keys privKey _) cert = do
  dhStr <- mapM writeDHParams dh
  certStr <- writeX509 cert
  privKeyStr <- writePKCS8PrivateKey privKey Nothing
  issuerCertStr <- writeX509 issuerCert
  return $ concat [certStr, issuerCertStr, privKeyStr, fromMaybe "" dhStr]

otherwiseM :: Monad m => m Bool -> m () -> m ()
a `otherwiseM` b = a >>= flip unless b
infixl 0 `otherwiseM`

(<..>) :: String -> String -> String
"." <..> dom = dom
sub <..> dom = sub ++ "." ++ dom

leftMapM_ :: Monad m => (a -> m ()) -> Either a b -> m ()
leftMapM_ f = mapM_ f . either Right Left
