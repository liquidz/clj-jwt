(ns jwt.base64-test
  (:require
    [jwt.base64  :refer :all]
    [midje.sweet :refer :all]))


(facts "base64/encode"
  (fact "string -> byte array encode"
    (class   (encode "foo"))     => (Class/forName "[B")
    (String. (encode "foo"))     => "Zm9v"
    (String. (encode "bar"))     => "YmFy"
    (String. (encode "foo.bar")) => "Zm9vLmJhcg==")

  (fact "string -> string encode"
    (encode-str "foo")     => "Zm9v"
    (encode-str "bar")     => "YmFy"
    (encode-str "foo.bar") => "Zm9vLmJhcg==")

  (fact "byte array -> string encode"
    (encode-str (.getBytes "foo" "UTF-8"))     => "Zm9v"
    (encode-str (.getBytes "bar" "UTF-8"))     => "YmFy"
    (encode-str (.getBytes "foo.bar" "UTF-8")) => "Zm9vLmJhcg==")

  (fact "byte array -> byte array encode"
    (class   (encode (.getBytes "foo" "UTF-8")))     => (Class/forName "[B")
    (String. (encode (.getBytes "foo" "UTF-8")))     => "Zm9v"
    (String. (encode (.getBytes "bar" "UTF-8")))     => "YmFy"
    (String. (encode (.getBytes "foo.bar" "UTF-8"))) => "Zm9vLmJhcg=="))

(facts "base64/decode"
  (fact "string -> byte array decode"
    (class (decode "Zm9v"))           => (Class/forName "[B")
    (String. (decode "Zm9v"))         => "foo"
    (String. (decode "YmFy"))         => "bar"
    (String. (decode "Zm9vLmJhcg==")) => "foo.bar")

  (fact "string -> string decode"
    (decode-str "Zm9v")         => "foo"
    (decode-str "YmFy")         => "bar"
    (decode-str "Zm9vLmJhcg==") => "foo.bar"
    )

  (fact "byte array -> string decode"
    (decode-str (.getBytes "Zm9v" "UTF-8"))         => "foo"
    (decode-str (.getBytes "YmFy" "UTF-8"))         => "bar"
    (decode-str (.getBytes "Zm9vLmJhcg==" "UTF-8")) => "foo.bar")

  (fact "byte array -> byte array decode"
    (class   (decode (.getBytes "Zm9v" "UTF-8")))         => (Class/forName "[B")
    (String. (decode (.getBytes "Zm9v" "UTF-8")))         => "foo"
    (String. (decode (.getBytes "YmFy" "UTF-8")))         => "bar"
    (String. (decode (.getBytes "Zm9vLmJhcg==" "UTF-8"))) => "foo.bar"))

(facts "base64/url-safe-encode-str"
  (fact "string -> string encode"
    (url-safe-encode-str "foo")     => "Zm9v"
    (url-safe-encode-str "bar")     => "YmFy"
    (url-safe-encode-str "foo.bar") => "Zm9vLmJhcg")

  (fact "byte array -> string encode"
    (url-safe-encode-str (.getBytes "foo" "UTF-8"))     => "Zm9v"
    (url-safe-encode-str (.getBytes "bar" "UTF-8"))     => "YmFy"
    (url-safe-encode-str (.getBytes "foo.bar" "UTF-8")) => "Zm9vLmJhcg"))

(facts "base64/url-safe-decode"
  (fact "string -> string url-safe decode"
    (url-safe-decode-str "Zm9v")       => "foo"
    (url-safe-decode-str "YmFy")       => "bar"
    (url-safe-decode-str "Zm9vLmJhcg") => "foo.bar")

  (fact "string -> byte array url-safe decode"
    (class   (url-safe-decode "Zm9v"))       => (Class/forName "[B")
    (String. (url-safe-decode "Zm9v"))       => "foo"
    (String. (url-safe-decode "YmFy"))       => "bar"
    (String. (url-safe-decode "Zm9vLmJhcg")) => "foo.bar")
  )
