# clj-jwt

[![Build Status](https://travis-ci.org/liquidz/clj-jwt.png?branch=master)](https://travis-ci.org/liquidz/clj-jwt)

A Clojure library for JSON Web Token(JWT) [draft-jones-json-web-token-10](http://tools.ietf.org/html/draft-jones-json-web-token-10)

## Supporting algorithms
 * HS256, HS384, HS512
 * RS256, RS384, RS512

## Not supporting
 * JSON Web Encryption (JWE)

## Usage

### Leiningen
```
[clj-jwt "0.0.1"]
```

### Generate

```clojure
(ns foo
  (:require
    [clj-jwt.core  :refer :all]
    [clj-jwt.key   :refer [private-key]]
    [clj-time.core :refer [now plus days]]))

(def claim
  {:iss "foo"
   :exp (plus (now) (days 1))
   :nbf (now)})

(def rsa-prv-key (private-key "rsa/private.key" "pass phrase"))
(def ec-prv-key  (private-key "ec/private.key"))

; plain JWT
(-> claim jwt to-str)

; HMAC256 signed JWT
(-> claim jwt (sign :HS256 "secret") to-str)

; RSA256 signed JWT
(-> claim jwt (sign :RS256 rsa-prv-key) to-str)

; ECDSA256 signed JWT
(-> claim jwt (sign :ES256 ec-prv-key) to-str)
```

### Verify

```clojure
(ns foo
  (:require
    [clj-jwt.core  :refer :all]
    [clj-jwt.key   :refer [private-key public-key]]
    [clj-time.core :refer [now plus days]]))

(def claim
  {:iss "foo"
   :exp (plus (now) (days 1))
   :nbf (now)})

(def rsa-prv-key (private-key "rsa/private.key" "pass phrase"))
(def rsa-pub-key (public-key  "rsa/public.key"))
(def ec-prv-key  (private-key "ec/private.key"))
(def ec-pub-key  (public-key  "ec/public.key"))

(let [token (-> claim jwt to-str)]
  (-> token str->jwt verify))

(let [token (-> claim jwt (sign :HS256 "secret") to-str)]
  (-> token str->jwt (verify "secret")))

(let [token (-> claim jwt (sign :RS256 rsa-prv-key) to-str)]
  (-> token str->jwt (verify rsa-pub-key)))

(let [token (-> claim jwt (sign :ES256 ec-prv-key) to-str)]
  (-> token str->jwt (verify ec-pub-key)))
```

## License

Copyright © 2013 [uochan](http://twitter.com/uochan)

Distributed under the Eclipse Public License, the same as Clojure.
