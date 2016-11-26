{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}


import EasyX509 (bytestring_to_x509, x509_verify, x509_sign, bytestring_to_rsa_privkey)
import Crypto.Hash.Algorithms (MD2)
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
                     e_signature = x509_sign (Nothing :: (Maybe MD2)) gen p message
                  in do { assertBool "did the signing procedure work?" $ isRight e_signature
                        ; case e_signature of
                            Left s -> putStrLn s
                            Right signature ->
                              do { assertEqual "does the signature verify?" Nothing $
                                     x509_verify (Nothing :: (Maybe MD2)) c message signature
                                 ; assertBool "does the verification fail on a bogus signature?" (not (Nothing == (
                                     x509_verify (Nothing :: (Maybe MD2)) c message (
                                       ByteString.concat [ByteString.take 21 signature,
                                                          ByteString.singleton 133, -- insert a byte that's just plain wrong.
                                                          ByteString.drop 22 signature]))))}}
              _ -> return ()}))
  ]
 ; return ()
}
