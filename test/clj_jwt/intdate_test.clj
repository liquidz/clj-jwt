(ns clj-jwt.intdate-test
  (:require
    [clj-jwt.intdate :refer :all]
    [clj-time.core   :refer [date-time]]
    [midje.sweet     :refer :all]))

(fact "joda-time->intdate should work fine."
  (let [d (date-time 2000 1 2 3 4 5)]
    (joda-time->intdate d)   => 946782245
    (joda-time->intdate nil) => (throws AssertionError)))

(fact "intdate->joda-time should work fine."
  (let [d (date-time 2000 1 2 3 4 5)
        i (joda-time->intdate d)]
    (intdate->joda-time i)   => d
    (intdate->joda-time nil) => (throws AssertionError)))

