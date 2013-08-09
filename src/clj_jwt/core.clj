(ns clj-jwt.core
  (:require
    [clj-jwt.base64    :refer [url-safe-encode-str url-safe-decode-str]]
    [clj-jwt.sign      :refer [get-signature-fn get-verify-fn supported-algorithm?]]
    [clj-time.coerce   :refer [to-long]]
    [clojure.data.json :as json]
    [clojure.string    :as str]))

(def ^:private DEFAULT_SIGNATURE_ALGORITHM :HS256)
(def ^:private map->encoded-json (comp url-safe-encode-str json/write-str))
(def ^:private encoded-json->map (comp #(json/read-str % :key-fn keyword) url-safe-decode-str))
(defn- update-map [m k f] (if (contains? m k) (update-in m [k] f) m))
(defn- joda-time? [x] (= org.joda.time.DateTime (type x)))
(defn- to-intdate [d] {:pre [(joda-time? d)]} (int (/ (to-long d) 1000)))

(defrecord JWT [header claims signature])

; ----------------------------------
; JsonWebToken
; ----------------------------------
(defprotocol JsonWebToken
  "Protocol for JsonWebToken"
  (init           [this claims] "Initialize token")
  (encoded-header [this] "Get url-safe base64 encoded header json")
  (encoded-claims [this] "Get url-safe base64 encoded claims json")
  (to-str         [this] "Generate JsonWebToken as string"))

(extend-protocol JsonWebToken
  JWT
  (init [this claims]
    (let [claims (reduce #(update-map % %2 to-intdate) claims [:exp :nbf :iat])]
      (assoc this :header {:alg "none" :typ "JWT"} :claims claims :signature "")))

  (encoded-header [this]
    (-> this :header map->encoded-json))

  (encoded-claims [this]
    (-> this :claims map->encoded-json))

  (to-str [this]
    (str (encoded-header this) "." (encoded-claims this) "." (get this :signature ""))))


; ----------------------------------
; JsonWebSignature
; ----------------------------------
(defprotocol JsonWebSignature
  "Protocol for JonWebSignature"
  (set-alg [this alg] "Set algorithm name to JWS Header Parameter")
  (sign    [this key] [this alg key] "Set signature to this token")
  (verify  [this] [this key] "Verify this token"))

(extend-protocol JsonWebSignature
  JWT
  (set-alg [this alg]
    (assoc-in this [:header :alg] (name alg)))

  (sign
    ([this key] (sign this DEFAULT_SIGNATURE_ALGORITHM key))
    ([this alg key]
     (let [this*   (set-alg this alg)
           sign-fn (get-signature-fn alg)
           data    (str (encoded-header this*) "." (encoded-claims this*))]
       (assoc this* :signature (sign-fn key data)))))

  (verify
    ([this] (verify this ""))
    ([this key]
     (let [alg (-> this :header :alg keyword)]
       (cond
         (= :none alg) (= "" (:signature this))

         (supported-algorithm? alg)
         (let [verify-fn (get-verify-fn alg)
               data    (str (encoded-header this) "." (encoded-claims this))]
           (verify-fn key data (:signature this)))

         :else (throw (Exception. "Unkown signature")))))))

; =jwt
(defn jwt [claim] (init (->JWT "" "" "") claim))

; =str->jwt
(defn str->jwt
  [jwt-string]
  (let [[header claims signature] (str/split jwt-string #"\.")]
    (->JWT (encoded-json->map header)
           (encoded-json->map claims)
           (or signature ""))))

