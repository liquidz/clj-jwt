(ns clj-jwt.key-test
  (:require
    [clj-jwt.key :refer :all]
    [midje.sweet :refer :all]))

(facts "private key"
  (fact "rsa non encrypt key"
    (type (private-key "test/files/rsa/no_pass.key"))
    => org.bouncycastle.jce.provider.JCERSAPrivateCrtKey)

  (fact "rsa crypted key"
    (type (private-key "test/files/rsa/3des.key" "pass phrase"))
    => org.bouncycastle.jce.provider.JCERSAPrivateCrtKey)

  (fact "rsa crypted key wrong pass-phrase"
    (private-key "test/files/rsa/3des.key" "wrong pass phrase")
    => (throws org.bouncycastle.openssl.EncryptionException))

  (fact "ecdsa key"
    (type (private-key "test/files/ec/private.key"))
    => org.bouncycastle.jce.provider.JCEECPrivateKey))

(facts "public key"
  (fact "rsa non encrypted key"
    (type (public-key "test/files/rsa/no_pass.key"))
    => org.bouncycastle.jce.provider.JCERSAPublicKey)

  (fact "rsa encrypted key"
    (type (public-key "test/files/rsa/3des.key" "pass phrase"))
    => org.bouncycastle.jce.provider.JCERSAPublicKey
    )
  (fact "rsa encrypted key with wrong pass phrase"
    (type (public-key "test/files/rsa/3des.key" "wrong pass phrase"))
    => (throws org.bouncycastle.openssl.EncryptionException))

  (fact "ecdsa public key"
    (type (public-key "test/files/ec/public.key"))
    => org.bouncycastle.jce.provider.JCEECPublicKey))

