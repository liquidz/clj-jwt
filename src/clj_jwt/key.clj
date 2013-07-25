(ns clj-jwt.key
  (:require [clojure.java.io :as io])
  (:import  [org.bouncycastle.openssl PasswordFinder PEMReader]
            [java.io StringReader]))

(java.security.Security/addProvider
(org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defn- password-finder [s]
  (reify PasswordFinder
    (getPassword [this] (.toCharArray s))))

(defn- pem->key
  [reader pass-phrase]
  (if pass-phrase
    (.readObject (PEMReader. reader (password-finder pass-phrase)))
    (.readObject (PEMReader. reader))))

(defn private-key
  [filename & [pass-phrase]]
  (with-open [r (io/reader filename)]
    (.getPrivate
      (pem->key r pass-phrase))))

(defn- public-key? [k]
  (let [typ (type k)]
    (or (= org.bouncycastle.jce.provider.JCERSAPublicKey typ)
        (= org.bouncycastle.jce.provider.JCEECPublicKey  typ))))

(defn public-key
  [filename & [pass-phrase]]
  (with-open [r (io/reader filename)]
    (let [res (pem->key r pass-phrase)]
      (if (public-key? res)
        res
        (.getPublic res)))))

(defn public-key-from-string
  [key-str & [pass-phrase]]
  (with-open [r (StringReader. key-str)]
    (let [res (pem->key r pass-phrase)]
      (if (public-key? res)
        res
        (.getPublic res)))))
