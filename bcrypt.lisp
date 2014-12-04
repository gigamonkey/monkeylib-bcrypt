;;;
;;; Copyright (c) 2010, Jon Rosebaugh All rights reserved.
;;; Copyright (c) 2011, Peter Seibel All rights reserved.
;;;

(in-package :bcrypt)

(define-foreign-library libbcrypt
  (:darwin "libbcrypt.dylib")
  (:unix (:or "libbcrypt.so.1.0.4" "libbcrypt.so.1" "libbcrypt.so"))
  (t (:default "libbcrypt")))

(use-foreign-library libbcrypt)

(defcfun ("_crypt_gensalt_blowfish_rn" crypt-gensalt-rn) :pointer
  (count :ulong)
  (input :pointer)
  (input-size :int)
  (output :pointer)
  (output-size :int))

(defcfun ("_crypt_blowfish_rn" crypt-rn) :pointer
  (key :pointer)
  (settings :pointer)
  (output :pointer)
  (output-size :int))

;;; Public API

(defvar *random-bytes-function* nil
  "Set to a function taking a length and returning an array of random
  bytes to customize how random bytes are generated for the salt. If
  this variable is not set, we will first try to get bytes from
  /dev/urandom and if that doesn't work, using the Lisp's built in
  random number generator.")

(defparameter *default-cost* 10
  "The default value for the COST parameter to HASH.") 

(defun hash (password &optional cost)
  "Encode the given plaintext PASSWORD with the given COST (defaults
to 10). Increasing cost by one approximately doubles the amount of
work required to encode the password (and thus to check it.)"
  (with-foreign-pointer (salt 16 salt-size)
    (fill-with-random-bytes salt salt-size)
    (with-foreign-pointer (settings 30 settings-size)
      (zero-memory settings settings-size)
      (crypt-gensalt-rn (or cost *default-cost*) salt salt-size settings settings-size)
      (with-foreign-pointer-as-string ((data data-size) 61 :encoding :ascii)
	(zero-memory data data-size)
	(with-foreign-string (password-cstring password)
	  (crypt-rn password-cstring settings data data-size))))))

(defun password= (password hash)
  "Return true if the given plaintext PASSWORD hashes to HASH, a hash
returned by BCRYPT:HASH. The check extracts the appropriate cost
parameter and salt from HASH."
  (let ((rehash
         (with-foreign-pointer-as-string ((data data-size) 61 :encoding :ascii)
           (zero-memory data data-size)
           (with-foreign-strings ((password-cstring password) (encoded-cstring hash))
             (crypt-rn password-cstring encoded-cstring data data-size)))))

    (string= hash rehash)))

(defun cost (hash)
  "Extract the cost parameter used to produce HASH."
  (unless (char= #\$ (char hash 0))
    (error "Hash ~a doesn't start with '$'" hash))
  (let* ((start (1+ (position #\$ hash :start 1)))
         (end   (position #\$ hash :start start)))
    (or (parse-integer (subseq hash start end) :junk-allowed t)
        (error "No cost found in ~a" hash))))

(defun version (hash)
  "Extract the algorithm version from HASH."
  (unless (char= #\$ (char hash 0))
    (error "Hash ~a doesn't start with '$'" hash))
  (subseq hash 1 (position #\$ hash :start 1)))

;;; Utility code

(defun zero-memory (mem-pointer n)
  "Zero out N bytes of memory starting at MEM-POINTER."
  (loop repeat n
     for p = mem-pointer then (inc-pointer p 1)
     do (setf (mem-ref p :int) 0)))

(defun fill-with-random-bytes (mem-pointer n)
  "Fill the N bytes of memory starting at MEM-POINTER with random
bytes obtained via GET-RANDOM-BYTES."
  (loop for byte across (get-random-bytes n)
     for p = mem-pointer then (inc-pointer p 1)
     do (setf (mem-ref p :int) byte)))

(defun get-random-bytes (n)
  "Get a vector of N random bytes using *RANDOM-BYTES-FUNCTION* if it
is set, /dev/urandom if it works, or, if all else fails, Lisp's
built-in random number generator."
  (or
   (and *random-bytes-function* (funcall *random-bytes-function* n))
   (urandom n)
   (lisp-random n)))

(defun urandom (n)
  "Generate N random bytes by reading from /dev/urandom. Returns NIL
if /dev/urandom doesn't exist or an error occurs."
  (when (probe-file "/dev/urandom")
    (ignore-errors 
      (with-open-file (r "/dev/urandom" :element-type '(unsigned-byte 8))
        (let ((bytes (make-array n :element-type '(unsigned-byte 8))))
          (read-sequence bytes r)
          bytes)))))

(defun lisp-random (n)
  "Generate N random bytes using Lisp's built in random number generator."
  (map-into (make-array n :element-type '(unsigned-byte 8)) (lambda () (random #xff))))
