;;
;; Copyright (c) 2011, Peter Seibel All rights reserved.
;;

(defsystem cl-bcrypt
  :components
  ((:file "packages")
   (:file "bcrypt" :depends-on ("packages")))
  :depends-on (:cffi))
