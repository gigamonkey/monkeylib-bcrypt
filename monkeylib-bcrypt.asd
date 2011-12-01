;;
;; Copyright (c) 2011, Peter Seibel All rights reserved.
;;

(defsystem monkeylib-bcrypt
  :description "Wrapper around bcrypt C library for hashing passwords."
  :components
  ((:file "packages")
   (:file "bcrypt" :depends-on ("packages")))
  :depends-on (:cffi))
