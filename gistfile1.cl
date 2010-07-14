(defpackage :cl-bcrypt
  (:export :encode :check)
  (:use :common-lisp :cffi))

(in-package :cl-bcrypt)

(define-foreign-library libbcrypt
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

(defun zero-memory (mem-pointer length)
  (dotimes (i length)
    (setf (mem-ref (inc-pointer mem-pointer i) :int) 0)))

(defun get-rand-bytes (mem-pointer length)
  (with-open-file (rand "/dev/urandom" :element-type '(unsigned-byte 8))
    (dotimes (i length)
      (setf (mem-ref (inc-pointer mem-pointer i) :int) (read-byte rand)))))

(defun encode (password &optional (strength 10))
  (with-foreign-pointer (salt 16 salt-size)
    (get-rand-bytes salt salt-size)
    (with-foreign-pointer (settings 30 settings-size)
      (zero-memory settings settings-size)
      (crypt-gensalt-rn strength salt salt-size settings settings-size)
      (with-foreign-pointer-as-string ((data data-size) 61 :encoding :ascii)
	(zero-memory data data-size)
	(with-foreign-string (password-cstring password)
	  (crypt-rn password-cstring settings data data-size))
	))))

(defun check (encoded password)
  (equal encoded (with-foreign-pointer-as-string ((data data-size) 61 :encoding :ascii)
     (zero-memory data data-size)
     (with-foreign-strings ((password-cstring password) (encoded-cstring encoded))
       (crypt-rn password-cstring encoded-cstring data data-size)))))