{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}


import EasyX509 (bytestring_to_x509, x509_verify, x509_sign, bytestring_to_rsa_privkey)
import Crypto.Hash.Algorithms (MD2(MD2)
                              ,MD5(MD5)
                              ,SHA1(SHA1)
                              ,SHA224(SHA224)
                              ,SHA256(SHA256)
                              ,SHA384(SHA384)
                              ,SHA512(SHA512)
                              ,SHA512t_224(SHA512t_224)
                              ,SHA512t_256(SHA512t_256)
                              ,RIPEMD160(RIPEMD160))
import Control.Monad     (liftM, liftM2)
import Crypto.Random (getSystemDRG)
import Data.Either (isRight)
import Data.Maybe (isJust)
import Data.ByteString.Lazy.Char8 (pack)
import qualified Data.ByteString.Lazy as ByteString (readFile, concat, take, drop, singleton)
import Test.HUnit        (Test(TestList,TestLabel,TestCase)
                         ,assertEqual
                         ,assertBool
                         ,runTestTT)


main :: IO ()
main = do { runTestTT $ TestList [
   TestLabel "verify signed stuff works" (
     TestCase (
       do { gen <- getSystemDRG
          ; m_cert <- ByteString.readFile "test/cert.pem"
          ; m_private <- ByteString.readFile "test/key.pem"
          ; cert <- return $  bytestring_to_x509 m_cert
          ; private <- return $ bytestring_to_rsa_privkey m_private
          ; case cert of
              Left s -> putStrLn $ "\n"++ s
              Right _ -> return ()
          ; assertBool "did the certificate parse correctly?" $ isRight cert
          ; case private of
              Left s -> putStrLn s
              Right _ -> return ()
          ; assertBool "did the private key parse correctly?" $ isRight private
          ; case (cert, private) of
              (Right c, Right p) ->
                 let message = pack "message text here"
                     test_hash h = let e_signature =  x509_sign h gen p message
                                    in do { assertBool "did the signing procedure work?" $ isRight e_signature
                                          ; case e_signature of
                                              Left s -> putStrLn s
                                              Right signature ->
                                                do { assertEqual "does the signature verify?" Nothing $
                                                       x509_verify h c message signature
                                                   ; assertBool "does the verification fail on a bogus signature?" (not (Nothing == (
                                                       x509_verify h c message (
                                                         ByteString.concat [ByteString.take 21 signature,
                                                                            ByteString.singleton 134, -- insert a byte that's just plain wrong.
                                                                            ByteString.drop 22 signature]))))}}
                 in do {test_hash (Nothing :: (Maybe MD2))
                       ;test_hash (Just MD2)
                       ;test_hash (Just MD5)
                       ;test_hash (Just SHA1)
                       ;test_hash (Just SHA224)
                       ;test_hash (Just SHA256)
                       ;test_hash (Just SHA384)
                       ;test_hash (Just SHA512)
                       ;test_hash (Just SHA512t_224)
                       ;test_hash (Just SHA512t_256)
                       ;test_hash (Just RIPEMD160)
                       }
              _ -> return ()}))
  ]
 ; return ()
}
