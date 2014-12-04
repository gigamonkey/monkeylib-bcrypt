;;
;; Copyright (c) 2011, Peter Seibel All rights reserved.
;;

(in-package :cl-user)
(defpackage :monkeylib-bcrypt-asd
  (:use :cl :asdf))
(in-package :monkeylib-bcrypt-asd)

(defsystem monkeylib-bcrypt
  :description "Wrapper around bcrypt C library for hashing passwords."
  :components
  ((:file "packages")
   (:file "bcrypt" :depends-on ("packages")))
  :depends-on (:cffi))
