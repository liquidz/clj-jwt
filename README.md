# clj-jwt

A Clojure library for JSON Web Token(JWT)

## Usage

```clojure
(ns foo
  (:require
    [jwt.core      :refer :all]
    [jwt.rsa.key   :refer [rsa-private-key]]
    [clj-time.core :refer [now plus days]]))

(def claim
  {:iss "foo"
   :exp (plus (now) (days 1))
   :nbf (now)})

; plain JWT
(-> claim jwt to-str)

; HS256 signed JWT
(-> claim jwt (sign :HS256 "key") to-str)

; RS256 signed JWT
(let [prv-key (rsa-private-key "foo.pem")]
  (-> claim jwt (sign :RS256 prv-key) to-str))
```

## License

Copyright © 2013 [uochan](http://twitter.com/uochan)

Distributed under the Eclipse Public License, the same as Clojure.
