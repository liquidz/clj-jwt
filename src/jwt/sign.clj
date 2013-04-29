(ns jwt.sign)

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

; HMAC
(defn hmac-sha
  [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [hmac-key (javax.crypto.spec.SecretKeySpec. (.getBytes key charset) alg)
        hmac     (doto (javax.crypto.Mac/getInstance alg)
                       (.init hmac-key))]
    (.doFinal hmac (.getBytes body charset))))

; RSA
(defn rsa-sha [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg "BC")
                  (.initSign key (java.security.SecureRandom.))
                  (.update (.getBytes body charset)))]
    (.sign sig)))

(def signature-fns
  {:HS256 (partial hmac-sha "HmacSHA256")
   :HS384 (partial hmac-sha "HmacSHA384")
   :HS512 (partial hmac-sha "HmacSHA512")
   :RS256 (partial rsa-sha  "SHA256withRSA")
   :RS384 (partial rsa-sha  "SHA384withRSA")
   :RS512 (partial rsa-sha  "SHA512withRSA")})

(defn get-signature-fn [alg]
  (if-let [f (get signature-fns alg)]
    f
    (throw (Exception. "Unkown signature"))))

