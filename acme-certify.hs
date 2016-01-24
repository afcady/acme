{-# LANGUAGE FlexibleContexts    #-}
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
import qualified Data.ByteString.Lazy.Char8 as LC
import           Network.ACME               (CSR (..), canProvision, certify,
                                             ensureWritableDir, (</>))
import           Network.ACME.Encoding      (Keys (..), readKeys, toStrict)
import           Network.URI
import           OpenSSL
import           OpenSSL.EVP.Digest
import           OpenSSL.PEM
import           OpenSSL.RSA
import           OpenSSL.X509.Request
import           Options.Applicative        hiding (header)
import qualified Options.Applicative        as Opt
import           System.Directory
import           Text.Domain.Validate       hiding (validate)
import           Text.Email.Validate

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

genKey :: FilePath -> IO String
genKey privKeyFile = withOpenSSL $ do
    kp <- generateRSAKey' 4096 65537
    pem <- writePKCS8PrivateKey kp Nothing
    writeFile privKeyFile pem
    return pem

genReq :: Keys -> [DomainName] -> IO CSR
genReq _ [] = error "genReq called with zero domains"
genReq (Keys priv pub) domains@(domain:_) = withOpenSSL $ do
  Just dig <- getDigestByName "SHA256"
  req <- newX509Req
  setSubjectName req [("CN", show domain)]
  setVersion req 0
  setPublicKey req pub
  void $ addExtensions req [(nidSubjectAltName, intercalate ", " (map (("DNS:" ++) . show) domains))]
  signX509Req req priv (Just dig)
  CSR . toStrict <$> writeX509ReqDER req
  where
    nidSubjectAltName = 85

getOrCreateKeys :: FilePath -> IO (Maybe Keys)
getOrCreateKeys file = do
  exists <- doesFileExist file
  readKeys =<< if exists then readFile file else genKey file

go :: CmdOpts -> IO ()
go CmdOpts { .. } = do
  let terms           = fromMaybe defaultTerms (join $ parseAbsoluteURI <$> optTerms)
      directoryUrl    = if optStaging then stagingDirectoryUrl else liveDirectoryUrl
      domainKeyFile   = domainDir </> "rsa.key"
      domainCertFile  = domainDir </> "cert.der"
      domainDir       = fromMaybe (head optDomains) optDomainDir
      privKeyFile     = optKeyFile
      requestDomains  = fromMaybe (error "invalid domain name") $ sequence $ domainName . fromString <$> optDomains

  doesDirectoryExist domainDir `otherwiseM` createDirectory domainDir

  Just domainKeys <- getOrCreateKeys domainKeyFile
  Just keys <- getOrCreateKeys privKeyFile

  challengeDir <- ensureWritableDir optChallengeDir "challenge directory"
  void $ ensureWritableDir domainDir "domain directory"

  forM_ requestDomains $ canProvision challengeDir >=>
            (`unless` error "Error: cannot provision files to web server via challenge directory")

  csrData <- genReq domainKeys requestDomains

  let email = either (error . ("Error: invalid email address: " ++)) id . validate . fromString <$> optEmail

  certificate <- certify directoryUrl keys email terms requestDomains challengeDir csrData

  either (error . ("Error: " ++)) (LC.writeFile domainCertFile) certificate

otherwiseM :: Monad m => m Bool -> m () -> m ()
a `otherwiseM` b = a >>= flip unless b
infixl 0 `otherwiseM`
