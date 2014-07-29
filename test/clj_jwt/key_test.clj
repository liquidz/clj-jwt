(ns clj-jwt.key-test
  (:require
    [clj-jwt.key :refer :all]
    [midje.sweet :refer :all]
    [clj-jwt.core-test :refer [with-bc-provider-fn]]))

(with-state-changes [(around :facts (with-bc-provider-fn (fn [] ?form)))]
  (facts "rsa private key"
    (fact "non encrypt key"
      (type (private-key "test/files/rsa/no_pass.key"))
      => org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey)

    (fact "crypted key"
      (type (private-key "test/files/rsa/3des.key" "pass phrase"))
      => org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey)

    (fact "crypted key wrong pass-phrase"
      (private-key "test/files/rsa/3des.key" "wrong pass phrase")
      => (throws org.bouncycastle.openssl.EncryptionException)))

  (facts "ecdsa private key"
    (fact "ecdsa key"
      (type (private-key "test/files/ec/private.key"))
      => org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey))

  (facts "rsa public key"
    (fact "rsa non encrypted key"
      (type (public-key "test/files/rsa/no_pass.key"))
      => org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey)

    (fact "rsa encrypted key"
      (type (public-key "test/files/rsa/3des.key" "pass phrase"))
      => org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey)

    (fact "rsa encrypted key with wrong pass phrase"
      (type (public-key "test/files/rsa/3des.key" "wrong pass phrase"))
      => (throws org.bouncycastle.openssl.EncryptionException))

    (fact "rsa non encrypted key from string"
      (-> "test/files/rsa/no_pass.key" slurp public-key-from-string type)
      => org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey)

    (fact "rsa encrypted key from string"
      (-> "test/files/rsa/3des.key" slurp (public-key-from-string "pass phrase") type)
      => org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey)

    (fact "rsa encrypted key with wrong pass phrase from string"
      (-> "test/files/rsa/3des.key" slurp (public-key-from-string "wrong pass phrase") type)
      => (throws org.bouncycastle.openssl.EncryptionException))

    (fact "invalid key string"
      (public-key-from-string "foobar") => nil))

  (facts "ecdsa public key"
    (fact "ecdsa public key"
      (type (public-key "test/files/ec/public.key"))
      => org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey)

    (fact "ecdsa public key from string"
      (-> "test/files/ec/public.key" slurp public-key-from-string type)
      => org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey)))
