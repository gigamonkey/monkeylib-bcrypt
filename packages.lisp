;;;
;;; Copyright (c) 2010, Jon Rosebaugh All rights reserved.
;;; Copyright (c) 2011, Peter Seibel All rights reserved.
;;;

(in-package :cl-user)

(defpackage :bcrypt
  (:use :common-lisp :cffi)
  (:export :hash 
           :password=
           :cost
           :version
           *default-cost*
           *random-bytes-function*))

