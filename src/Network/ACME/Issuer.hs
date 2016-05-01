{-# LANGUAGE TemplateHaskell #-}

module Network.ACME.Issuer where

import Data.ByteString.Char8
import Data.FileEmbed

letsEncryptX1CrossSigned :: String
letsEncryptX1CrossSigned = unpack $(embedFile "lets-encrypt-x1-cross-signed.pem")

letsEncryptX2CrossSigned :: String
letsEncryptX2CrossSigned = unpack $(embedFile "lets-encrypt-x2-cross-signed.pem")

letsEncryptX3CrossSigned :: String
letsEncryptX3CrossSigned = unpack $(embedFile "lets-encrypt-x3-cross-signed.pem")

letsEncryptX4CrossSigned :: String
letsEncryptX4CrossSigned = unpack $(embedFile "lets-encrypt-x4-cross-signed.pem")
