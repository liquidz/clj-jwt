(ns clj-jwt.key
  (:require [clojure.java.io :as io])
  (:import  [org.bouncycastle.openssl PasswordFinder PEMReader]))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defn- password-finder [s]
  (reify PasswordFinder
    (getPassword [this] (.toCharArray s))))

(defn- pem->key
  [filename & [pass-phrase]]
  (with-open [r (io/reader filename)]
    (let [pr (if pass-phrase
               (PEMReader. r (password-finder pass-phrase))
               (PEMReader. r))]
      (.readObject pr))))

(defn private-key
  [& args]
  (.getPrivate (apply pem->key args)))

(defn- public-key? [k]
  (let [typ (type k)]
    (or (= org.bouncycastle.jce.provider.JCERSAPublicKey typ)
        (= org.bouncycastle.jce.provider.JCEECPublicKey typ))))

(defn public-key
  [& args]
  (let [res (apply pem->key args)]
    (if (public-key? res)
      res
      (.getPublic res))))
