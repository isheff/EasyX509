{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

module EasyX509 (
   bytestring_to_rsa_privkey
  ,bytestring_to_x509
  ,x509_verify
  ,x509_sign
  ) where

import Control.Monad  (liftM, liftM2)
import Crypto.PubKey.RSA.Types (Error(MessageSizeIncorrect, MessageTooLong, MessageNotRecognized, SignatureTooLong, InvalidParameters))
import Crypto.PubKey.RSA.PKCS15 (verify, HashAlgorithmASN1, signSafer)
import Crypto.Random (DRG, withDRG)
import Data.ASN1.Object (ASN1Object)
import Data.ByteString.Lazy (ByteString, toStrict, fromStrict, fromChunks)
import Crypto.PubKey.OpenSsh (decodePrivate, OpenSshPrivateKey(OpenSshPrivateKeyRsa))
import qualified Crypto.PubKey.RSA.Types as Cryptonite (PrivateKey(PrivateKey), PublicKey(PublicKey))
import qualified Crypto.Types.PubKey.RSA as OpenSSL (PrivateKey(PrivateKey), PublicKey(PublicKey))
import Data.Either (rights, lefts)
import Data.List (intercalate)
import Data.PEM (pemParseLBS, pemContent, PEM(pemName, pemContent))
import Data.Text.Lazy    (pack)
import Data.Types.Injective (Injective, to)
import Data.Types.Isomorphic (Iso)
import Data.X509 (Certificate, certPubKey
                 ,PubKey(PubKeyRSA, PubKeyDSA, PubKeyDH, PubKeyEC, PubKeyUnknown)
                 ,PrivKey(PrivKeyRSA)
                 ,decodeSignedObject
                 ,signedObject
                 ,getSigned)


instance Injective OpenSSL.PublicKey Cryptonite.PublicKey where
  to (OpenSSL.PublicKey s n e) = Cryptonite.PublicKey s n e

instance Injective Cryptonite.PublicKey OpenSSL.PublicKey where
  to (Cryptonite.PublicKey s n e) = OpenSSL.PublicKey s n e

instance Iso Cryptonite.PublicKey OpenSSL.PublicKey
instance Iso OpenSSL.PublicKey Cryptonite.PublicKey

instance Injective OpenSSL.PrivateKey Cryptonite.PrivateKey where
  to (OpenSSL.PrivateKey pub d p q dP dQ qinv) = Cryptonite.PrivateKey (to pub) d p q dP dQ qinv

instance Injective Cryptonite.PrivateKey OpenSSL.PrivateKey where
  to (Cryptonite.PrivateKey pub d p q dP dQ qinv) = OpenSSL.PrivateKey (to pub) d p q dP dQ qinv

instance Iso OpenSSL.PrivateKey Cryptonite.PrivateKey
instance Iso Cryptonite.PrivateKey OpenSSL.PrivateKey


bytestring_to_x509 :: (Show a, Eq a, ASN1Object a) => ByteString -> Either String a
bytestring_to_x509 b = case pemParseLBS b of
                         Left s        -> Left s
                         (Right [])    -> Left  $ "No valid PEM objects could be read from " ++ (show b)
                         (Right (pem:_)) -> case decodeSignedObject $ pemContent pem of
                                            Left s -> Left s
                                            Right signed_certificate -> Right $ signedObject $ getSigned signed_certificate

bytestring_to_rsa_privkey :: ByteString -> Either String PrivKey
bytestring_to_rsa_privkey b = case decodePrivate (toStrict b) of
                                Right (OpenSshPrivateKeyRsa private) -> Right $ PrivKeyRSA $ to private
                                Right _ -> Left $ "wrong kind of private key. I can only deal with RSA: " ++ (show b)
                                Left  s -> Left s

-- ISHEFF: TODO (amongst other things): figure out HashAlgorithm s and which ones go where.
x509_verify :: (HashAlgorithmASN1 h) => (Maybe h) -> Certificate -> ByteString -> ByteString -> Maybe String
x509_verify hash_alg certificate message signature =
  case certPubKey certificate of
    PubKeyRSA public_key -> if verify hash_alg public_key (toStrict message) (toStrict signature)
                               then Nothing
                               else Just "key appears to be correctly formatted, but the message simply did not verify"
    PubKeyDSA _ -> Just "This DSA key should in theory be doable. It's a Crypto.PubKey.DSA.PublicKey, but I have to figure out how to parse signatures for this kind of thing."
    PubKeyDH _ -> Just "This is a DH format public key. I have no idea what to do."
    PubKeyEC _ -> Just "This is a Data.X509.PubKeyEC. I have no idea what to do."
    PubKeyUnknown _ _ -> Just "This public key type isn't recognized by my libraries."

x509_sign :: (HashAlgorithmASN1 h, DRG gen) => (Maybe h) -> gen -> PrivKey -> ByteString -> (Either String ByteString)
x509_sign m_hash g (PrivKeyRSA private_key) message = case fst $ withDRG g $ signSafer m_hash private_key $ toStrict message of
  (Left MessageSizeIncorrect) -> Left "the message to decrypt is not of the correct size (need to be == private_size)"
  (Left MessageTooLong      ) -> Left "the message to encrypt is too long"
  (Left MessageNotRecognized) -> Left "the message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)"
  (Left SignatureTooLong    ) -> Left "the message's digest is too long"
  (Left InvalidParameters   ) -> Left "some parameters lead to breaking assumptions."
  (Right b) -> Right $ fromStrict b
x509_sign _ _ _ _ = Left "I do not know how to deal with non-RSA private keys at this time."

