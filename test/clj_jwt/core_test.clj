(ns clj-jwt.core-test
  (:require
    [clj-jwt.core  :refer :all]
    [clj-jwt.key   :refer [private-key public-key]]
    [clj-time.core :refer [date-time plus days now]]
    [midje.sweet   :refer :all]))

(def claim {:iss "foo"})
(def rsa-prv-key     (private-key "test/files/rsa/no_pass.key"))
(def rsa-pub-key     (public-key  "test/files/rsa/no_pass.pub.key"))
(def rsa-enc-prv-key (private-key "test/files/rsa/3des.key" "pass phrase"))
(def rsa-enc-pub-key (public-key  "test/files/rsa/3des.pub.key"))
(def rsa-dmy-key     (public-key  "test/files/rsa/dummy.key"))

(def ec-prv-key      (private-key "test/files/ec/private.key"))
(def ec-pub-key      (public-key  "test/files/ec/public.key"))
(def ec-dmy-key      (public-key  "test/files/ec/dummy.key"))

(facts "JWT tokenize"
  (fact "Plain JWT should be generated."
    (-> claim jwt to-str)
    => "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJmb28ifQ.")

  (fact "If unknown algorithm is specified, exception is throwed."
    (-> claim jwt (sign :DUMMY "foo")) => (throws Exception))

  (fact "HS256 signed JWT should be generated."
    (-> claim jwt (sign "foo") to-str)
    => (str "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.8yUIo-xkh537lD_CZycqS1zB"
            "NhBNkIrcfzaFgwt8zdg")

    (-> claim jwt (sign :HS256 "foo") to-str)
    => (str "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.8yUIo-xkh537lD_CZycqS1zB"
            "NhBNkIrcfzaFgwt8zdg"))

  (fact "HS384 signed JWT should be generated."
    (-> claim jwt (sign :HS384 "foo") to-str)
    => (str "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.34ZaTLCZGBAfcCryhYaFYy8Z"
            "-47do1cftq365YmvIcubonhGdRnvpgV8s_iG_lvd"))

  (fact "HS512 signed JWT should be generated."
    (-> claim jwt (sign :HS512 "foo") to-str)
    => (str "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.58Q4HxaxKAZIffEyDI2eRM_2"
            "L7mK7NlNwOq8v96gbfZLMM7r2hxXKuwvMLez2XivUUCEyoaVB1Yz3vGtwAvSZQ"))

  (fact "RS256 signed JWT should be generated."
    (-> claim jwt (sign :RS256 rsa-prv-key) to-str)
    => (str "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.ZIjAlGryslu1APkgY1eCmaK7"
            "GDINiGX-htlD1-33F4VXK8lUXbdm1n9F1fpHcOFksScniWMvC5f9520jdxyb5c-9CmXz21iDtFdFKWGG"
            "zlT_hPjZ0Ta_M8goReBO0L-nDM5hJHxzEqgSZQ7tkcJ18PCdxeMia5NMRV0shGMMUzU")

    (-> claim jwt (sign :RS256 rsa-enc-prv-key) to-str)
    => (str "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.E20DLUOR5VeoTKtH5FjR71rm"
            "_rZV2AdXYDQCxqHpMWyZSO6wO4g67phTD727izDxd_NjuNXd2m7Atth7tGABaMhqHLh9EUwba_0nTbw6"
            "mc_4mWaK4KBq8LG4WErQnFAVhzGbo1aEK_J7iasuUCfnxN9fZeBBUGH_h5JgPogCPdA"))

  (fact "RS384 signed JWT should be generated."
    (-> claim jwt (sign :RS384 rsa-prv-key) to-str)
    => (str "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.sWyMCwJhztfOcSoxRRiCAioB"
            "H5F8WFJs5t8DxPV0D7JvB9JwaN8reIQ7kFKJiQWFbhrC7tnlT5UDX9z3fyLjdmNvLTSOII3J9UPpidE1"
            "4WvqnXk5DV8k4QxTdWHRufssDFZe7Bsq5yBRAGZos2e8U9hOuqxCib7EjGCe09PdDhg")

    (-> claim jwt (sign :RS384 rsa-enc-prv-key) to-str)
    => (str "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.Uz3ZGXNuuKYsmoslBrNJnVKC"
            "GW-dptW-eOWPrTGVN1P54bgjS6QbhwE-PPL2HHGUIYlebVmHb2RKLLvmQ8y63NZ1QSXEk8QBz5-bwy6Y"
            "m_QCYh4tfvZYheH97zHcLF3GDLlfrodukO9gGc1xpiXJiZMtIso6sGACHmXNn4LA1bk"))

  (fact "RS512 signed JWT should be generated."
    (-> claim jwt (sign :RS512 rsa-prv-key) to-str)
    => (str "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.QKK5oOrVU5e0eG0nt7a_3Hzw"
            "v1YJIp1F3iSKVgbdjWyp6rhyS4O4HEql6UxUOVDvf_aTrO4NG81dIo_wzjI1LBNCVtwKhR-8KUFs4Yg3"
            "1NLwBMazIzxX_IfkpIkUPuyDGrca7pksJ9dppte33mMK3MDv0RQQqgXiJpbLRGWSNrs")

    (-> claim jwt (sign :RS512 rsa-enc-prv-key) to-str)
    => (str "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.P6ER78xL8AlV4BXrtTtBIcsc"
            "JOktKH03Uj12mqjiS6o1h4Cf7QHKXjWxe33hrEgkzcYBHDqw7wH915f6ZnB5mkvDtBkLinA9gK0M2rfB"
            "7NqAbxXYMDXti2PhV9PgRzOp97zPCSD98bML0Cy89E8sPcnM7-07wWOK4yhuoTWyV_8"))

  (fact "'exp', 'nbf', 'iat' claims should be converted as IntDate."
    (let [d     (date-time 2000 1 2 3 4 5)
          claim (merge claim {:exp (plus d (days 1)) :nbf d :iat d :dmy d})
          token (jwt claim)]
      (-> token :claims :exp) => 946868645
      (-> token :claims :nbf) => 946782245
      (-> token :claims :iat) => 946782245
      (-> token :claims :dmy) => d)))

(facts "JWT verify"
  (fact "Unknown signature algorithm should be thrown exception."
    (verify (->JWT {:typ "JWT" :alg "DUMMY"} claim ""))    => (throws Exception)
    (verify (->JWT {:typ "JWT" :alg "DUMMY"} claim "") "") => (throws Exception))

  (fact "Plain JWT should be verified."
    (-> claim jwt verify)                             => true
    (-> claim jwt (verify ""))                        => true
    (-> claim jwt (verify :none ""))                  => true
    (-> claim jwt to-str str->jwt verify)             => true
    (-> claim jwt to-str str->jwt (verify "foo"))     => false
    (-> claim jwt to-str str->jwt (verify :HS256 "")) => false
    (-> claim jwt (assoc :signature "foo") verify)    => false)

  (fact "HS256 signed JWT should be verified."
    (-> claim jwt (sign "foo") (verify "foo"))                 => true
    (-> claim jwt (sign "foo") (verify :HS256 "foo"))          => true
    (-> claim jwt (sign "foo") (verify :HS384 "foo"))          => false
    (-> claim jwt (sign "foo") to-str str->jwt (verify "foo")) => true
    (-> claim jwt (sign "foo") (verify "bar"))                 => false)

  (fact "HS384 signed JWT should be verified."
    (-> claim jwt (sign :HS384 "foo") (verify "foo"))                 => true
    (-> claim jwt (sign :HS384 "foo") (verify :HS384 "foo"))          => true
    (-> claim jwt (sign :HS384 "foo") (verify :HS256 "foo"))          => false
    (-> claim jwt (sign :HS384 "foo") to-str str->jwt (verify "foo")) => true
    (-> claim jwt (sign :HS384 "foo") (verify "bar"))                 => false)

  (fact "HS512 signed JWT should be verified."
    (-> claim jwt (sign :HS512 "foo") (verify "foo"))                 => true
    (-> claim jwt (sign :HS512 "foo") (verify :HS512 "foo"))          => true
    (-> claim jwt (sign :HS512 "foo") (verify :HS256 "foo"))          => false
    (-> claim jwt (sign :HS512 "foo") to-str str->jwt (verify "foo")) => true
    (-> claim jwt (sign :HS512 "foo") (verify "bar"))                 => false)

  (fact "RS256 signed JWT should be verified."
    (-> claim jwt (sign :RS256 rsa-prv-key) (verify rsa-pub-key))                 => true
    (-> claim jwt (sign :RS256 rsa-prv-key) (verify :RS256 rsa-pub-key))          => true
    (-> claim jwt (sign :RS256 rsa-prv-key) (verify :RS384 rsa-pub-key))          => false
    (-> claim jwt (sign :RS256 rsa-prv-key) to-str str->jwt (verify rsa-pub-key)) => true
    (-> claim jwt (sign :RS256 rsa-prv-key) (verify rsa-dmy-key))                 => false

    (-> claim jwt (sign :RS256 rsa-enc-prv-key) (verify rsa-enc-pub-key))                 => true
    (-> claim jwt (sign :RS256 rsa-enc-prv-key) (verify :RS256 rsa-enc-pub-key))          => true
    (-> claim jwt (sign :RS256 rsa-enc-prv-key) (verify :RS384 rsa-enc-pub-key))          => false
    (-> claim jwt (sign :RS256 rsa-enc-prv-key) to-str str->jwt (verify rsa-enc-pub-key)) => true
    (-> claim jwt (sign :RS256 rsa-enc-prv-key) (verify rsa-dmy-key))                     => false)

  (fact "RS384 signed JWT should be verified."
    (-> claim jwt (sign :RS384 rsa-prv-key) (verify rsa-pub-key))                 => true
    (-> claim jwt (sign :RS384 rsa-prv-key) (verify :RS384 rsa-pub-key))          => true
    (-> claim jwt (sign :RS384 rsa-prv-key) (verify :RS256 rsa-pub-key))          => false
    (-> claim jwt (sign :RS384 rsa-prv-key) to-str str->jwt (verify rsa-pub-key)) => true
    (-> claim jwt (sign :RS384 rsa-prv-key) (verify rsa-dmy-key))                 => false

    (-> claim jwt (sign :RS384 rsa-enc-prv-key) (verify rsa-enc-pub-key))                 => true
    (-> claim jwt (sign :RS384 rsa-enc-prv-key) to-str str->jwt (verify rsa-enc-pub-key)) => true
    (-> claim jwt (sign :RS384 rsa-enc-prv-key) (verify rsa-dmy-key))                     => false)

  (fact "RS512 signed JWT should be verified."
    (-> claim jwt (sign :RS512 rsa-prv-key) (verify rsa-pub-key))                 => true
    (-> claim jwt (sign :RS512 rsa-prv-key) (verify :RS512 rsa-pub-key))          => true
    (-> claim jwt (sign :RS512 rsa-prv-key) (verify :RS256 rsa-pub-key))          => false
    (-> claim jwt (sign :RS512 rsa-prv-key) to-str str->jwt (verify rsa-pub-key)) => true
    (-> claim jwt (sign :RS512 rsa-prv-key) (verify rsa-dmy-key))                 => false

    (-> claim jwt (sign :RS512 rsa-enc-prv-key) (verify rsa-enc-pub-key))                 => true
    (-> claim jwt (sign :RS512 rsa-enc-prv-key) (verify :RS512 rsa-enc-pub-key))          => true
    (-> claim jwt (sign :RS512 rsa-enc-prv-key) (verify :RS256 rsa-enc-pub-key))          => false
    (-> claim jwt (sign :RS512 rsa-enc-prv-key) to-str str->jwt (verify rsa-enc-pub-key)) => true
    (-> claim jwt (sign :RS512 rsa-enc-prv-key) (verify rsa-dmy-key))                     => false)

  (fact "ES256 signed JWT shoud be verified."
    (-> claim jwt (sign :ES256 ec-prv-key) (verify ec-pub-key))                 => true
    (-> claim jwt (sign :ES256 ec-prv-key) (verify :ES256 ec-pub-key))          => true
    (-> claim jwt (sign :ES256 ec-prv-key) (verify :ES384 ec-pub-key))          => false
    (-> claim jwt (sign :ES256 ec-prv-key) to-str str->jwt (verify ec-pub-key)) => true)

  (fact "ES384 signed JWT shoud be verified."
    (-> claim jwt (sign :ES384 ec-prv-key) (verify ec-pub-key))                 => true
    (-> claim jwt (sign :ES384 ec-prv-key) (verify :ES384 ec-pub-key))          => true
    (-> claim jwt (sign :ES384 ec-prv-key) (verify :ES256 ec-pub-key))          => false
    (-> claim jwt (sign :ES384 ec-prv-key) to-str str->jwt (verify ec-pub-key)) => true)

  (fact "ES512 signed JWT shoud be verified."
    (-> claim jwt (sign :ES512 ec-prv-key) (verify ec-pub-key))                 => true
    (-> claim jwt (sign :ES512 ec-prv-key) (verify :ES512 ec-pub-key))          => true
    (-> claim jwt (sign :ES512 ec-prv-key) (verify :ES256 ec-pub-key))          => false
    (-> claim jwt (sign :ES512 ec-prv-key) to-str str->jwt (verify ec-pub-key)) => true)

  (fact "Claims containing string key should be verified"
    (let [sclaim {"a/b" "c"}
          token  (-> sclaim jwt (sign "foo"))]
      (verify token "foo")                                 => true
      (-> token to-str str->jwt (verify "foo"))            => true
      (verify token "bar")                                 => false)))

(facts "str->jwt function should work."
  (let [before (jwt claim)
        after  (-> before to-str str->jwt)]
    (fact "plain jwt"
      (:header before)    => (:header after)
      (:claims before)    => (:claims after)
      (:signature before) => (:signature after)))

  (let [claim {:iss "foo"}
        before (-> claim jwt (sign "foo"))
        after  (-> before to-str str->jwt)]
    (fact "signed jwt"
      (:header before)    => (:header after)
      (:claims before)    => (:claims after)
      (:signature before) => (:signature after)))

  (let [claim {"a/b" "c"}
        before (jwt claim)
        after  (-> before to-str str->jwt)]
    (fact "Claim containing string key"
      (:header before)    => (:header after)
      (:claims before)    => (:claims after)
      (:signature before) => (:signature after))))
