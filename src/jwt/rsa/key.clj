(ns jwt.rsa.key
  (:require [clojure.java.io :as io])
  )

(defn- password-finder [s]
  (reify org.bouncycastle.openssl.PasswordFinder
    (getPassword [this] (.toCharArray s))))

(defn- rsa-key
  ([filename]
   (-> (io/reader filename)
       org.bouncycastle.openssl.PEMReader.
       .readObject))
  ([filename pass-phrase]
   (-> (io/reader filename)
       (org.bouncycastle.openssl.PEMReader. (password-finder pass-phrase))
       .readObject)))

(defn rsa-private-key
  ([filename]
   (-> filename rsa-key .getPrivate))
  ([filename pass-phrase]
   (.getPrivate (rsa-key filename pass-phrase))))

(defn rsa-public-key
  ([filename]
   (-> filename rsa-key .getPublic))
  ([filename pass-phrase]
   (.getPublic (rsa-key filename pass-phrase))
   )
  )
