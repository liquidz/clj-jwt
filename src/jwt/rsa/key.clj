(ns jwt.rsa.key
  (:require [clojure.java.io :as io])
  (:import  [org.bouncycastle.openssl PasswordFinder PEMReader]))

(defn- password-finder [s]
  (reify PasswordFinder
    (getPassword [this] (.toCharArray s))))

(defn- rsa-key
  [filename & [pass-phrase]]
  (with-open [r (io/reader filename)]
    (let [pr (if pass-phrase
               (PEMReader. r (password-finder pass-phrase))
               (PEMReader. r))]
      (.readObject pr))))

(defn rsa-private-key
  [& args]
  (.getPrivate (apply rsa-key args)))

(defn rsa-public-key
  [& args]
  (let [res (apply rsa-key args)]
    (if (= org.bouncycastle.jce.provider.JCERSAPublicKey (type res))
      res
      (.getPublic res))))
