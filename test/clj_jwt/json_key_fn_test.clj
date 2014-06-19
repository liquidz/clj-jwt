(ns clj-jwt.json-key-fn-test
  (:require
    [clj-jwt.json-key-fn :refer :all]
    [midje.sweet         :refer :all]))

(fact "write-key should work fine."
  (write-key :foo)  => "foo"
  (write-key "foo") => "\"foo\"")

(fact "read-key should work fine."
  (read-key "foo")     => :foo
  (read-key "\"foo\"") => "foo")
