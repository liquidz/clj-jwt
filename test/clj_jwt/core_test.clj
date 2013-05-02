(ns clj-jwt.core-test
  (:require
    [clj-jwt.core    :refer :all]
    [clj-jwt.rsa.key :refer [rsa-private-key rsa-public-key]]
    [clj-time.core   :refer [date-time plus days now]]
    [midje.sweet     :refer :all]))

(def claim {:iss "foo"})
(def prv-key (rsa-private-key     "test/files/rsa/no_pass.key"))
(def pub-key (rsa-public-key      "test/files/rsa/no_pass.pub.key"))
(def enc-prv-key (rsa-private-key "test/files/rsa/3des.key" "pass phrase"))
;(def enc-pub-key (rsa-public-key  "test/files/rsa/3des.pub.key" "pass phrase"))
(def enc-pub-key (rsa-public-key  "test/files/rsa/3des.pub.key"))
(def dmy-key (rsa-public-key      "test/files/rsa/dummy.key"))

(facts "JWT tokenize"
  (fact "Plain JWT should be generated."
    (-> claim jwt to-str)
    => "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJmb28ifQ.")

  (fact "If unknown algorithm is specified, exception is throwed."
    (-> claim jwt (sign :DUMMY "foo")) => (throws Exception))

  (fact "HS256 signed JWT should be generated."
    (-> claim jwt (sign "foo") to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmb28ifQ.mScNySwrJjjVjGiIaSW0blyb"
            "g2knXpuokTzYio5XUFg")

    (-> claim jwt (sign :HS256 "foo") to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmb28ifQ.mScNySwrJjjVjGiIaSW0blyb"
            "g2knXpuokTzYio5XUFg"))

  (fact "HS384 signed JWT should be generated."
    (-> claim jwt (sign :HS384 "foo") to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJmb28ifQ.DamQl6Dv8-Ya92kJx6zKlF4n"
            "xX12NO0V0vhFsOGbwTUIdtkc08Rt4pNQZukIJyNc"))

  (fact "HS512 signed JWT should be generated."
    (-> claim jwt (sign :HS512 "foo") to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJmb28ifQ.RoOaMBk4uzRmCAOCLg5h9QkL"
            "FAugLwYeGGhXSjlJ57n4EHoapm6nvheJzIF8OlLYtjwdPcdFbsuaTgPSIa1tCQ"))

  (fact "RS256 signed JWT should be generated."
    (-> claim jwt (sign :RS256 prv-key) to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJmb28ifQ.CqIxuQMw8-sJR0X7v7DqvJua"
            "ND2Oy_LpG_kc-SaAM_sfyuC2TMTnqKJiQLmr-VUbM5-EXiCF853xQIr6xnoNmrHFPgbLeynhPyfvsx1u"
            "1RIw25z8r0ZJiNtNbSelueYRAjYlrnYUPxqreervGqkLRdEz5uBn3Vy250ggvHb3S_I")

    (-> claim jwt (sign :RS256 enc-prv-key) to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJmb28ifQ.0oDxxzP3AoZGosxJSCKE9J9G"
            "r_z1TYog8XbQvVaBPAscXPlGpesLP9Nu4PZDwkPa6qMuVYomcea4P61zIeFUNNPq_KhGtOLTEmw7fWX8"
            "sjX-YAWxfz1lJFOkCeYrG3rRXzRJStZa-phsfI_f_XyiSbIM6FQrt_pn8z0KJvI-_Oo"))

  (fact "RS384 signed JWT should be generated."
    (-> claim jwt (sign :RS384 prv-key) to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJmb28ifQ.RIe33rDJ8qKN49qis9DnvEHt"
            "cw2af5bndLWaEChSYFRd5MN5e0c936HkyV_40z2DCOLrKt-6HPz1zVePKYOiM0wKr_hEiPEBUtxo4EOS"
            "l_XRHgGC2ol3NM57Z0NzUONW4L9GZoojaDopBxfT5zYxt403dgbsp6BzYlnnODHCbfs")

    (-> claim jwt (sign :RS384 enc-prv-key) to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJmb28ifQ.Goh6VyLf3RmVzfh708QKLrVb"
            "x4nLa8SOnXb3mV_UqGRqU6KGO712rMNXbRVddkktC1d1xgxv13XKgZX2RVTMb0utI_yii0hCSHijnvSb"
            "x7CgQOJLdXPryQ_K1pUcZWPZbQ965O07XxHApGEjMPVZYFF6GhiGe0xBjR4TCNNOipA"))

  (fact "RS512 signed JWT should be generated."
    (-> claim jwt (sign :RS512 prv-key) to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJmb28ifQ.stQhJDu0Hv1ZMTBBYyGNPjap"
            "HyDrWRDJSJARhHXmC0T2LkOEtNGBFeQ4mojvxcwd1u2FUu9N5KEmCsmqMpaIubVvdd4GkmGQ4REhR7Cm"
            "YFBvB4dFPCpG_B8jn5QkYpXm_zr4wXhW6mdSR4oq_wsULT5O4Z8haoSCl3ysT9SbI0g")

    (-> claim jwt (sign :RS512 enc-prv-key) to-str)
    => (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJmb28ifQ.LsOapoyhzPzsFy1dkP7o-Se9"
            "4VKnwuyigZW5i0r0nTymBHa9auctCW9saJIk7Lt9GVLQkRM92exgEX3rqntZPQXm960FPr5-csgCuHnV"
            "qACM0zaoAL3x97lOgK_f93aw2g7Tv3AtXfN9LZ8P7YMfmnwGdeqZRREXWJcpc-7Dioo"))

  (fact "'exp', 'nbf', 'iot' claims should be converted as IntDate."
    (let [d     (date-time 2000 1 2 3 4 5)
          claim (merge claim {:exp (plus d (days 1)) :nbf d :iot d :dmy d})
          token (jwt claim)]
      (-> token :claims :exp) => 946868645
      (-> token :claims :nbf) => 946782245
      (-> token :claims :iot) => 946782245
      (-> token :claims :dmy) => d)))

(facts "JWT verify"
  (fact "Unknown signature algorithm should be thrown exception."
    (verify (->JWT {:typ "JWT" :alg "DUMMY"} claim ""))    => (throws Exception)
    (verify (->JWT {:typ "JWT" :alg "DUMMY"} claim "") "") => (throws Exception))

  (fact "Plain JWT should be verified."
    (-> claim jwt verify) => true
    (-> claim jwt to-str str->jwt verify) => true
    (-> claim jwt (assoc :signature "foo") verify) => false)

  (fact "HS256 signed JWT should be verified."
    (-> claim jwt (sign "foo") (verify "foo"))                 => true
    (-> claim jwt (sign "foo") to-str str->jwt (verify "foo")) => true
    (-> claim jwt (sign "foo") (verify "bar"))                 => false)

  (fact "HS384 signed JWT should be verified."
    (-> claim jwt (sign :HS384 "foo") (verify "foo"))                 => true
    (-> claim jwt (sign :HS384 "foo") to-str str->jwt (verify "foo")) => true
    (-> claim jwt (sign :HS384 "foo") (verify "bar"))                 => false)

  (fact "HS512 signed JWT should be verified."
    (-> claim jwt (sign :HS512 "foo") (verify "foo"))                 => true
    (-> claim jwt (sign :HS512 "foo") to-str str->jwt (verify "foo")) => true
    (-> claim jwt (sign :HS512 "foo") (verify "bar"))                 => false)

  (fact "RS256 signed JWT should be verified."
    (-> claim jwt (sign :RS256 prv-key) (verify pub-key))                 => true
    (-> claim jwt (sign :RS256 prv-key) to-str str->jwt (verify pub-key)) => true
    (-> claim jwt (sign :RS256 prv-key) (verify dmy-key))                 => false

    (-> claim jwt (sign :RS256 enc-prv-key) (verify enc-pub-key))                 => true
    (-> claim jwt (sign :RS256 enc-prv-key) to-str str->jwt (verify enc-pub-key)) => true
    (-> claim jwt (sign :RS256 enc-prv-key) (verify dmy-key))                     => false)

  (fact "RS384 signed JWT should be verified."
    (-> claim jwt (sign :RS384 prv-key) (verify pub-key))                 => true
    (-> claim jwt (sign :RS384 prv-key) to-str str->jwt (verify pub-key)) => true
    (-> claim jwt (sign :RS384 prv-key) (verify dmy-key))                 => false

    (-> claim jwt (sign :RS384 enc-prv-key) (verify enc-pub-key))                 => true
    (-> claim jwt (sign :RS384 enc-prv-key) to-str str->jwt (verify enc-pub-key)) => true
    (-> claim jwt (sign :RS384 enc-prv-key) (verify dmy-key))                     => false)

  (fact "RS512 signed JWT should be verified."
    (-> claim jwt (sign :RS512 prv-key) (verify pub-key))                 => true
    (-> claim jwt (sign :RS512 prv-key) to-str str->jwt (verify pub-key)) => true
    (-> claim jwt (sign :RS512 prv-key) (verify dmy-key))                 => false

    (-> claim jwt (sign :RS512 enc-prv-key) (verify enc-pub-key))                 => true
    (-> claim jwt (sign :RS512 enc-prv-key) to-str str->jwt (verify enc-pub-key)) => true
    (-> claim jwt (sign :RS512 enc-prv-key) (verify dmy-key))                     => false))


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
      (:signature before) => (:signature after))))
