(ns jwt.rsa.key-test
  (:require
    [jwt.rsa.key :refer :all]
    [midje.sweet :refer :all]))

(facts "rsa private key"
  (fact "non encrypt key"
    (type (rsa-private-key "test/files/rsa/no_pass.key"))
    => org.bouncycastle.jce.provider.JCERSAPrivateCrtKey)

  (fact "crypted key"
    (type (rsa-private-key "test/files/rsa/3des.key" "pass phrase"))
    => org.bouncycastle.jce.provider.JCERSAPrivateCrtKey)

  (fact "crypted key wrong pass-phrase"
    (rsa-private-key "test/files/rsa/3des.key" "wrong pass phrase")
    => (throws org.bouncycastle.openssl.EncryptionException)))

(facts "rsa public key"
  (fact "non encrypted key"
    (type (rsa-public-key "test/files/rsa/no_pass.key"))
    => org.bouncycastle.jce.provider.JCERSAPublicKey)

  (fact "encrypted key"
    (type (rsa-public-key "test/files/rsa/3des.key" "pass phrase"))
    => org.bouncycastle.jce.provider.JCERSAPublicKey
    )
  (fact "encrypted key with wrong pass phrase"
    (type (rsa-public-key "test/files/rsa/3des.key" "wrong pass phrase"))
    => (throws org.bouncycastle.openssl.EncryptionException)
    )
  )




