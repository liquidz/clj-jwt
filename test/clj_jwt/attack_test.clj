(ns clj-jwt.attack-test
  (:require
    [clj-jwt.core   :refer :all]
    [clj-jwt.sign   :refer :all]
    [clj-jwt.key    :refer [private-key public-key]]
    [clojure.string :as str]
    [clojure.test   :refer :all]))

(def pub-key-path "test/files/rsa/no_pass.pub.key")
(def rsa-prv-key  (private-key "test/files/rsa/no_pass.key"))
(def rsa-pub-key  (public-key  pub-key-path))

(deftest test-algorithm->none-attack
  (let [key "secret"
        original (-> {:foo "bar"} jwt (sign :HS256 key))
        attacked (update-in original [:header :alg] (constantly "none"))]
    (testing "attack"
      (is (verify original key))
      (is (not (verify attacked key))))

    (testing "defense"
      (is (verify original :HS256 key))
      (is (not (verify original :RS256 key)))
      (is (not (verify attacked :HS256 key))))))

(deftest test-rsa->hmac-attack
  (let [base      (jwt {:foo "bar"})
        original  (sign base :RS256 rsa-prv-key)
        hmac-sign (-> base (sign :HS256 (str/trim (slurp pub-key-path))) :signature)
        attacked  (-> original
                      (update-in [:header :alg] (constantly "HS256"))
                      (update-in [:signature] (constantly hmac-sign)))]
    (testing "attack"
      (is (verify original rsa-pub-key))
      (is (thrown? Exception (verify attacked rsa-pub-key))))

    (testing "defense"
      (is (verify original :RS256 rsa-pub-key))
      (is (not (verify original :HS256 rsa-pub-key)))
      (is (not (verify attacked :RS256 rsa-pub-key))))))
