(ns jwt.sign-test
  (:require
    [jwt.sign    :refer :all]
    [jwt.base64  :refer [url-safe-encode]]
    [jwt.rsa.key :refer [rsa-private-key]]
    [midje.sweet :refer :all]))

(facts "HMAC"
  (let [[hs256 hs384 hs512] (map #(comp url-safe-encode (get-signature-fn %))
                                 [:HS256 :HS384 :HS512])
        key "foo", body "foo"]
    (fact "HS256"
      (hs256 key body) => "CLo1fidPUoBldmx3CmOav2gJs5zP03wqMVfH9RlU2go")

    (fact "HS384"
      (hs384 key body) => (str "piXjQSLhU8VQMR__GcK-j0-B52Y3YhDbUAqkjRZ5skHGnO8bfaqF9smvE8n-6"
                               "AOR"))
    (fact "HS512"
      (hs512 key body) => (str "zpfRr559UfVU-WtKizOGdX7fF46Z0Tburo2T_0CzrEVsGD_JZX0eky96QYdkr"
                               "TNH67E1N7Rh_6z9XnIJBCPj2g"))))

(facts "RSA"
  (let [[rs256 rs384 rs512] (map #(comp url-safe-encode (get-signature-fn %))
                                 [:RS256 :RS384 :RS512])
        key (rsa-private-key "test/files/rsa/no_pass.key")
        body "foo"]
    (fact "RS256"
      (rs256 key body) => (str "VUbrxVb4ud4Iqh8h3rBHijagwFbXyml6FkqgYl9JhauWMZReM4brJh__KlBeF"
                               "R30ZruV2_VUpFYEuSnsoO1KrscnZklUow_Z8AKWCrCSxWO1I8qyskbWyN3MBq"
                               "fQxVNEc62xrzMMpdnLq6OpIk--Sh5ZdUYl-tT3wy4HV_sxQUU"))

    (fact "RS384"
      (rs384 key body) => (str "F1HhYSk8cFdnr1ODDv-Q6YvTpMq3p8STD3lh6gingp1U5gpYmnbMqgOr_YM5z"
                               "jeUsFI1d1FolwfaeKeBRxVo9tjawb-TxFAFIdVLfZpwb3kR7nHq9NsQHfkDf_"
                               "DnfSPOi8d7wX8Eunb-padnM9sn1L4g1GYH9ReuoYhV8JUsJZE"))

    (fact "RS512"
      (rs512 key body) => (str "VVfaoXP5WUGNSggUE1FVYV-JKZRGnFkm2ATFm2MQ7bZbyan4EBzVPUN1B5Be3"
                               "A-Z1j3LeLKFWhryRRAjzW--Ut5rs5t0MjJ4OgUUhXAEXXAeJfbeEVxzBv4C-F"
                               "e9avjnNjUgcPlJgQAMQbrLirSo8Z8hb1Iqz9f7pUuNLTkAQJA"))))





