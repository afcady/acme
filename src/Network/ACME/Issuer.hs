{-# LANGUAGE TemplateHaskell #-}

module Network.ACME.Issuer where

import Data.ByteString.Char8
import Data.FileEmbed

letsEncryptX1CrossSigned :: String
letsEncryptX1CrossSigned = unpack $(embedFile "lets-encrypt-x1-cross-signed.pem")
