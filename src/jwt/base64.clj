(ns jwt.base64
  (:require [clojure.data.codec.base64 :as base64]
            [clojure.string :as str]
            )
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           ))

(defprotocol ByteArrayInput
  (input-stream [this]))

(extend-type String
  ByteArrayInput
  (input-stream [src] (ByteArrayInputStream. (.getBytes src "UTF-8"))))

(extend-type (Class/forName "[B")
  ByteArrayInput
  (input-stream [src] (ByteArrayInputStream. src)))


(defn encode [x]
  (with-open [in  (input-stream x)
              out (ByteArrayOutputStream.)]
    (base64/encoding-transfer in out)
    (.toString out)))

(defn url-safe-encode [s]
  (-> (encode s)
      (str/replace #"\s" "")
      (str/replace "=" "")
      (str/replace "+" "-")
      (str/replace "/" "_")))

(defn decode [x]
  (with-open [in  (input-stream x)
              out (ByteArrayOutputStream.)]
    (base64/decoding-transfer in out)
    (.toString out)))

(defn url-safe-decode [^String s]
  (-> (case (mod (count s) 4)
        2 (str s "==")
        3 (str s "=")
        s)
      (str/replace "-" "+")
      (str/replace "_" "/")
      decode))

