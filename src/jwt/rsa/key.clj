(ns jwt.rsa.key
  (:require [clojure.java.io :as io]))

(defn- rsa-key [filename]
  (-> (io/reader filename)
      org.bouncycastle.openssl.PEMReader.
      .readObject))

(defn rsa-private-key
  [filename]
  (-> filename rsa-key .getPrivate))

(defn rsa-public-key
  [filename]
  (-> filename rsa-key .getPublic))
