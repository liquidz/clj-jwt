(defproject clj-jwt "0.0.3"
  :description  "Clojure library for JSON Web Token(JWT)"
  :url          "https://github.com/liquidz/clj-jwt"
  :license      {:name "Eclipse Public License"
                 :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.clojure/data.json "0.2.2"]
                 [org.clojure/data.codec "0.1.0"]
                 [org.bouncycastle/bcprov-jdk15 "1.46"]
                 [clj-time "0.5.0"]]

  :profiles {:dev {:dependencies [[midje "1.5.1"  :exclusions [org.clojure/clojure]]]}}
  :plugins  [[lein-midje "3.0.0"]])
