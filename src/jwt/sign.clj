(ns jwt.sign
  (:require
    [jwt.base64 :refer [url-safe-encode-str url-safe-decode]]))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

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
  (= signature (hmac-sign alg key body :charset charset)))

; RSA
(defn- rsa-sign
  "Function to sign data with RSA algorithm."
  [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg "BC")
                  (.initSign key (java.security.SecureRandom.))
                  (.update (.getBytes body charset)))]
    (url-safe-encode-str (.sign sig))))

(defn- rsa-verify
  "Function to verify data and signature with RSA algorithm."
  [alg key body signature & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg "BC")
                  (.initVerify key)
                  (.update (.getBytes body charset)))]
    (.verify sig (url-safe-decode signature))))

(def ^:private signature-fns
  {:HS256 (partial hmac-sign "HmacSHA256")
   :HS384 (partial hmac-sign "HmacSHA384")
   :HS512 (partial hmac-sign "HmacSHA512")
   :RS256 (partial rsa-sign  "SHA256withRSA")
   :RS384 (partial rsa-sign  "SHA384withRSA")
   :RS512 (partial rsa-sign  "SHA512withRSA")})

(def ^:private verify-fns
  {:HS256 (partial hmac-verify "HmacSHA256")
   :HS384 (partial hmac-verify "HmacSHA384")
   :HS512 (partial hmac-verify "HmacSHA512")
   :RS256 (partial rsa-verify "SHA256withRSA")
   :RS384 (partial rsa-verify "SHA384withRSA")
   :RS512 (partial rsa-verify "SHA512withRSA")})

(defn- get-fns [m alg]
  (if-let [f (get m alg)]
    f
    (throw (Exception. "Unkown signature"))))

(def get-signature-fn (partial get-fns signature-fns))
(def get-verify-fn    (partial get-fns verify-fns))
(def supported-algorithm? (set (keys verify-fns)))
