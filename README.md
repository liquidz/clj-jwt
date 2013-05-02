# clj-jwt

[![Build Status](https://travis-ci.org/liquidz/clj-jwt.png?branch=master)](https://travis-ci.org/liquidz/clj-jwt)

A Clojure library for JSON Web Token(JWT)

## Supporting algorithms
 * HS256, HS384, HS512
 * RS256, RS384, RS512

## Usage

### Leiningen
```
[clj-jwt "0.0.1"]
```

### Generate

```clojure
(ns foo
  (:require
    [clj-jwt.core    :refer :all]
    [clj-jwt.rsa.key :refer [rsa-private-key]]
    [clj-time.core   :refer [now plus days]]))

(def claim
  {:iss "foo"
   :exp (plus (now) (days 1))
   :nbf (now)})

(def prv-key (rsa-private-key "private.key" "pass phrase"))

; plain JWT
(-> claim jwt to-str)

; HMAC256 signed JWT
(-> claim jwt (sign :HS256 "secret") to-str)

; RSA256 signed JWT
(-> claim jwt (sign :RS256 prv-key) to-str)
```

### Verify

```clojure
(ns foo
  (:require
    [clj-jwt.core    :refer :all]
    [clj-jwt.rsa.key :refer [rsa-private-key rsa-public-key]]
    [clj-time.core   :refer [now plus days]]))

(def claim
  {:iss "foo"
   :exp (plus (now) (days 1))
   :nbf (now)})

(def prv-key (rsa-private-key "private.key" "pass phrase"))
(def pub-key (rsa-public-key  "public.key"))

(let [token (-> claim jwt to-str)]
  (-> token str->jwt verify))

(let [token (-> claim jwt (sign :HS256 "secret") to-str)]
  (-> token str->jwt (verify "secret")))

(let [token (-> claim jwt (sign :RS256 prv-key) to-str)]
  (-> token str->jwt (verify pub-key)))
```

## License

Copyright © 2013 [uochan](http://twitter.com/uochan)

Distributed under the Eclipse Public License, the same as Clojure.
