(ns clj-jwt.sign
  (:require
    [clj-jwt.base64  :refer [url-safe-encode-str url-safe-decode]]
    [crypto.equality :refer [eq?]]))

; Initialize SecureRandom only once, since it requests a fresh
; seed on every initialization and this can take a very long
; time depending on which platform you use.
(def random-source (delay (java.security.SecureRandom.)))

; HMAC
(defn- hmac-sign
  "Function to sign data with HMAC algorithm."
  [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [hmac-key (javax.crypto.spec.SecretKeySpec. (.getBytes key charset) alg)
        hmac     (doto (javax.crypto.Mac/getInstance alg)
                       (.init hmac-key))]
    (url-safe-encode-str (.doFinal hmac (.getBytes body charset)))))

(defn- hmac-verify
  "Function to verify data and signature with HMAC algorithm."
  [alg key body signature & {:keys [charset] :or {charset "UTF-8"}}]
  (eq? signature (hmac-sign alg key body :charset charset)))

; RSA
(defn- rsa-sign
  "Function to sign data with RSA algorithm."
  [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg)
                  (.initSign key @random-source)
                  (.update (.getBytes body charset)))]
    (url-safe-encode-str (.sign sig))))

(defn- rsa-verify
  "Function to verify data and signature with RSA algorithm."
  [alg key body signature & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg)
                  (.initVerify key)
                  (.update (.getBytes body charset)))]
    (.verify sig (url-safe-decode signature))))


; ECDSA
(defn- ec-sign
  [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg)
                  (.initSign key)
                  (.update (.getBytes body charset)))]
    (url-safe-encode-str (.sign sig))))

(defn ec-verify
  [alg key body signature & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg)
                  (.initSign key)
                  (.update (.getBytes body charset)))]
    (.verify sig (url-safe-decode signature))))

(def ^:private signature-fns
  {:HS256 (partial hmac-sign "HmacSHA256")
   :HS384 (partial hmac-sign "HmacSHA384")
   :HS512 (partial hmac-sign "HmacSHA512")
   :RS256 (partial rsa-sign  "SHA256withRSA")
   :RS384 (partial rsa-sign  "SHA384withRSA")
   :RS512 (partial rsa-sign  "SHA512withRSA")
   :ES256 (partial ec-sign   "SHA256withECDSA")
   :ES384 (partial ec-sign   "SHA384withECDSA")
   :ES512 (partial ec-sign   "SHA512withECDSA")})

(def ^:private verify-fns
  {:HS256 (partial hmac-verify "HmacSHA256")
   :HS384 (partial hmac-verify "HmacSHA384")
   :HS512 (partial hmac-verify "HmacSHA512")
   :RS256 (partial rsa-verify  "SHA256withRSA")
   :RS384 (partial rsa-verify  "SHA384withRSA")
   :RS512 (partial rsa-verify  "SHA512withRSA")
   :ES256 (partial rsa-verify  "SHA256withECDSA")
   :ES384 (partial rsa-verify  "SHA384withECDSA")
   :ES512 (partial rsa-verify  "SHA512withECDSA")})

(defn- get-fns [m alg]
  (if-let [f (get m alg)]
    f
    (throw (Exception. "Unkown signature"))))

(def get-signature-fn (partial get-fns signature-fns))
(def get-verify-fn    (partial get-fns verify-fns))
(def supported-algorithm? (set (keys verify-fns)))
