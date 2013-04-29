(ns jwt.base64-test
  (:require
    [jwt.base64  :as base64]
    [midje.sweet :refer :all]))


(facts "base64/encode"
  (fact "encode from string"
    (base64/encode "foo") => "Zm9v"
    (base64/encode "bar") => "YmFy"
    (base64/encode "foo.bar") => "Zm9vLmJhcg==")

  (fact "encode from byte array"
    (base64/encode (.getBytes "foo" "UTF-8")) => "Zm9v"
    (base64/encode (.getBytes "bar" "UTF-8")) => "YmFy"
    (base64/encode (.getBytes "foo.bar" "UTF-8")) => "Zm9vLmJhcg=="))

(facts "base64/url-safe-encode"
  (fact "encode from string"
    (base64/url-safe-encode "foo") => "Zm9v"
    (base64/url-safe-encode "bar") => "YmFy"
    (base64/url-safe-encode "foo.bar") => "Zm9vLmJhcg")

  (fact "encode from byte array"
    (base64/url-safe-encode (.getBytes "foo" "UTF-8")) => "Zm9v"
    (base64/url-safe-encode (.getBytes "bar" "UTF-8")) => "YmFy"
    (base64/url-safe-encode (.getBytes "foo.bar" "UTF-8")) => "Zm9vLmJhcg"))


(fact "base64/decode"
  (base64/decode "Zm9v") => "foo"
  (base64/decode "YmFy") => "bar"
  (base64/decode "Zm9vLmJhcg==") => "foo.bar")

(fact "base64/url-safe-decode"
  (base64/url-safe-decode "Zm9v") => "foo"
  (base64/url-safe-decode "YmFy") => "bar"
  (base64/url-safe-decode "Zm9vLmJhcg") => "foo.bar")
