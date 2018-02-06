(ns clj-jwt.json-key-fn
  (:require
    [clojure.string :as str]))

(def write-key name)

(defn read-key
  "don't keywordize keys with / or ."
  [x]
  (if (re-matches #".*[/.].*" x)
    x
    (keyword x)))


