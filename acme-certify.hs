{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE NamedFieldPuns      #-}
{-# LANGUAGE NoImplicitPrelude   #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.
--
-- https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

module Main where

import           BasePrelude
import           Network.ACME         (HttpProvisioner, Keys (..),
                                       canProvision, certify,
                                       ensureWritableDir, provisionViaFile,
                                       readKeys, (</>))
import           Network.ACME.Issuer  (letsEncryptX1CrossSigned)
import           Network.URI
import           OpenSSL
import           OpenSSL.DH
import           OpenSSL.PEM
import           OpenSSL.RSA
import           OpenSSL.X509         (X509)
import           Options.Applicative  hiding (header)
import qualified Options.Applicative  as Opt
import           System.Directory
import           System.IO
import           Text.Domain.Validate hiding (validate)
import           Text.Email.Validate

import qualified Data.Yaml.Config     as Yaml

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
      updateConfigFile :: Maybe FilePath
}

data AcmeCertRequest = AcmeCertRequest {
      acrDomains        :: [(DomainName, HttpProvisioner)],
      acrSkipDH         :: Bool,
      acrCertificateDir :: FilePath,
      acrUserKeys       :: Keys
}

updateOpts :: Parser Command
updateOpts = fmap Update $
  UpdateOpts <$> optional
                   (strOption
                      (long "config" <>
                       metavar "FILENAME" <>
                       help "location of YAML configuration file"))

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
              <*> switch
                    (long "staging" <> help
                                         (unwords
                                            [ "Use staging servers instead of live servers"
                                            , "(generated certificates will not be trusted!)"
                                            ]))
              <*> switch
                    (long "skip-provision-check" <> help
                                                      (unwords
                                                         [ "Don't test whether HTTP provisioning works before"
                                                         , "making ACME requests"
                                                         ]))

runUpdate :: UpdateOpts -> IO ()
runUpdate UpdateOpts{..} = do
  error "test"

runCertify :: CertifyOpts -> IO (Either String ())
runCertify CertifyOpts{..} = do
  let terms              = fromMaybe defaultTerms (join $ parseAbsoluteURI <$> optTerms)
      directoryUrl       = if optStaging then stagingDirectoryUrl else liveDirectoryUrl
      domainDir          = fromMaybe (head optDomains) optDomainDir
      privKeyFile        = optKeyFile
      requestDomains     = map domainName' optDomains
      email              = either (error . ("Error: invalid email address: " ++)) id . validate . fromString <$> optEmail

  issuerCert <- readX509 letsEncryptX1CrossSigned

  seq email (return ())
  doesDirectoryExist domainDir `otherwiseM` createDirectory domainDir
  challengeDir <- ensureWritableDir optChallengeDir "challenge directory"
  void $ ensureWritableDir domainDir "domain directory"

  Just keys <- getOrCreateKeys privKeyFile

  let req = AcmeCertRequest {..}
      acrDomains        = map (flip (,) (provisionViaFile challengeDir)) requestDomains
      acrSkipDH         = optSkipDH
      acrUserKeys       = keys
      acrCertificateDir = domainDir

  unless optSkipProvisionCheck $
    forM_ acrDomains $ uncurry canProvision >=>
      (`unless` error "Error: cannot provision files to web server")

  go' directoryUrl terms email issuerCert req

go' :: URI -> URI -> Maybe EmailAddress -> X509 -> AcmeCertRequest -> IO (Either String ())
go' directoryUrl terms email issuerCert acr@AcmeCertRequest{..} = do
  Just domainKeys <- getOrCreateKeys $ acrCertificateDir </> "rsa.key"
  dh <- saveDhParams acr

  certificate <- certify directoryUrl acrUserKeys ((,) terms <$> email) domainKeys acrDomains
  for certificate $ saveCertificate issuerCert dh domainKeys acr

saveDhParams :: AcmeCertRequest -> IO (Maybe DHP)
saveDhParams AcmeCertRequest{acrSkipDH, acrCertificateDir} = do
  let domainDhFile = acrCertificateDir </> "dhparams.pem"
  if acrSkipDH then return Nothing else Just <$> getOrCreateDH domainDhFile

saveCertificate :: X509 -> Maybe DHP -> Keys -> AcmeCertRequest -> X509 -> IO ()
saveCertificate issuerCert dh domainKeys AcmeCertRequest{acrCertificateDir} = saveBoth
  where
    saveBoth x509      = savePEM x509 >> saveCombined x509
    saveCombined       = combinedCert issuerCert dh domainKeys >=> writeFile domainCombinedFile
    savePEM            = writeX509                             >=> writeFile domainCertFile
    domainCombinedFile = acrCertificateDir </> "cert.combined.pem"
    domainCertFile     = acrCertificateDir </> "cert.pem"

genKey :: IO String
genKey = withOpenSSL $ do
  kp <- generateRSAKey' 4096 65537
  writePKCS8PrivateKey kp Nothing

getOrCreate :: IO String -> (String -> IO a) -> FilePath -> IO a
getOrCreate gen parse file = do
  exists <- doesFileExist file
  parse =<< if exists then readFile file else gen >>= save file
  where
    save f x = writeFile f x >> return x

getOrCreateKeys :: FilePath -> IO (Maybe Keys)
getOrCreateKeys = getOrCreate genKey readKeys

getOrCreateDH :: FilePath -> IO DHP
getOrCreateDH = getOrCreate (genDHParams' >>= writeDHParams) readDHParams

domainName' :: String -> DomainName
domainName' dom = fromMaybe (error $ "Error: invalid domain name: " ++ show dom) (domainName $ fromString dom)

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

