(ns jwt.sign)

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

; HMAC
(defn hmac-sign
  [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [hmac-key (javax.crypto.spec.SecretKeySpec. (.getBytes key charset) alg)
        hmac     (doto (javax.crypto.Mac/getInstance alg)
                       (.init hmac-key))]
    (.doFinal hmac (.getBytes body charset))))

; RSA
(defn rsa-sign [alg key body & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg "BC")
                  (.initSign key (java.security.SecureRandom.))
                  (.update (.getBytes body charset)))]
    (.sign sig)))

(defn rsa-verify [alg key body signature & {:keys [charset] :or {charset "UTF-8"}}]
  (let [sig (doto (java.security.Signature/getInstance alg "BC")
                  (.initVerify key)
                  (.update (.getBytes body charset)))]
    ;(.verify sig (.getBytes signature charset))
    (.verify sig signature)
    ))

(def signature-fns
  {:HS256 (partial hmac-sign "HmacSHA256")
   :HS384 (partial hmac-sign "HmacSHA384")
   :HS512 (partial hmac-sign "HmacSHA512")
   :RS256 (partial rsa-sign  "SHA256withRSA")
   :RS384 (partial rsa-sign  "SHA384withRSA")
   :RS512 (partial rsa-sign  "SHA512withRSA")})

(def verify-fns
  {:RS256 (partial rsa-verify "SHA256withRSA")
   :RS384 (partial rsa-verify "SHA384withRSA")
   :RS512 (partial rsa-verify "SHA512withRSA")})

(defn- get-fns [m alg]
  (if-let [f (get m alg)]
    f
    (throw (Exception. "Unkown signature"))))

(def get-signature-fn (partial get-fns signature-fns))
(def get-verify-fn    (partial get-fns verify-fns))

