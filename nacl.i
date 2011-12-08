%module nacl

 /*
   Copyright 2011 Sean R. Lynch <seanl@literati.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

%{
  #include "crypto_box.h"
  #include "crypto_sign.h"
  #include "crypto_scalarmult_curve25519.h"
  #include "crypto_secretbox.h"
  #include "crypto_stream.h"
  #include "crypto_auth.h"
  #include "crypto_onetimeauth.h"
  #include "crypto_hash.h"
  #include "crypto_hash_sha256.h"
  #include "crypto_hash_sha512.h"
  #include "crypto_uint32.h"
  #include "randombytes.h"

  typedef struct {
    crypto_uint32 v[32];
  } fe25519;

  typedef struct {
    crypto_uint32 v[32];
  } sc25519;

  typedef struct {
    fe25519 x;
    fe25519 y;
    fe25519 z;
    fe25519 t;
  } ge25519;

  #define sc25519_from32bytes crypto_sign_edwards25519sha512batch_sc25519_from32bytes
  #define ge25519_pack crypto_sign_edwards25519sha512batch_ge25519_pack
  #define ge25519_scalarmult_base crypto_sign_edwards25519sha512batch_ge25519_scalarmult_base

  void ge25519_pack(unsigned char r[32], const ge25519 *p);
  void ge25519_scalarmult_base(ge25519 *r, const sc25519 *s);
  void sc25519_from32bytes(sc25519 *r, const unsigned char x[32]);

  int crypto_sign_keypair_fromseed(unsigned char *pk,
                                   unsigned char *sk,
                                   const unsigned char *seed,
                                   unsigned long long seedlen) {
    sc25519 scsk;
    ge25519 gepk;

    crypto_hash_sha512(sk, seed, seedlen);

    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    sc25519_from32bytes(&scsk, sk);

    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(pk, &gepk);
    return 0;
  }

%}

%include <typemaps.i>

%typemap(in) (const unsigned char *m, unsigned long long mlen) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $1 = (unsigned char *)PyString_AS_STRING($input);
  $2 = PyString_GET_SIZE($input);
}

%typemap(in, numinputs=0) unsigned char [ANY] {
  $result = PyString_FromStringAndSize(NULL, $1_dim0);
  $1 = (unsigned char *)PyString_AS_STRING($result);
}

// For some reason [ANY] doesn't work for multi-argument typemaps.
%typemap(in, numinputs=0) (unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                           unsigned char sk[crypto_sign_SECRETKEYBYTES])
                          (PyObject *temp1, PyObject *temp2),
                          (unsigned char pk[crypto_box_PUBLICKEYBYTES],
                           unsigned char sk[crypto_box_SECRETKEYBYTES])
                          (PyObject *temp1, PyObject *temp2) {
  temp1 = PyString_FromStringAndSize(NULL, $1_dim0);
  $1 = (unsigned char *)PyString_AS_STRING(temp1);
  temp2 = PyString_FromStringAndSize(NULL, $2_dim0);
  $2 = (unsigned char *)PyString_AS_STRING(temp2);
  $result = PyTuple_Pack(2, temp1, temp2);
  Py_DECREF(temp1);
  Py_DECREF(temp2);
}

%typemap(in) (const unsigned char *seed, unsigned long long seedlen) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $1 = (unsigned char *)PyString_AS_STRING($input);
  $2 = (unsigned long long)PyString_GET_SIZE($input);
}

%typemap(in) const unsigned char [ANY] {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  if (PyString_GET_SIZE($input) != $1_dim0) {
    PyErr_Format(PyExc_ValueError, "Expecting a string of length %d", $1_dim0);
    SWIG_fail;
  }
  $1 = (unsigned char *)PyString_AS_STRING($input);
}

%typemap(in)
  (unsigned char *sm, unsigned long long *smlen,
   const unsigned char *m, unsigned long long mlen)
     (unsigned long long temp) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $4 = PyString_GET_SIZE($input);
  $result = PyString_FromStringAndSize(NULL, $4 + crypto_sign_BYTES);
  $1 = (unsigned char *)PyString_AS_STRING($result);
  $2 = &temp;
  $3 = (unsigned char *)PyString_AS_STRING($input);
}

%typemap(in)
  (unsigned char *m, unsigned long long *mlen,
   const unsigned char *sm, unsigned long long smlen)
  (unsigned long long temp) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $4 = PyString_GET_SIZE($input);
  $result = PyString_FromStringAndSize(NULL, $4);
  $1 = (unsigned char *)PyString_AS_STRING($result);
  $2 = &temp;
  $3 = (unsigned char *)PyString_AS_STRING($input);
}

%typemap(argout) (unsigned char *sm, unsigned long long *smlen),
  (unsigned char *m, unsigned long long *mlen) {
  _PyString_Resize(&$result, *$2);
}

%typemap(in) (unsigned char *buffer, unsigned long long bytes),
             (unsigned char *c, unsigned long long clen) {
  $2 = PyLong_AsUnsignedLongLongMask($input);
  if ($2 == -1 && PyErr_Occurred() != NULL) {
    SWIG_fail;
  }
  $result = PyString_FromStringAndSize(NULL, $2);
  $1 = (unsigned char *)PyString_AS_STRING($result);
}

%typemap(in) (unsigned char *c, const unsigned char *in,
              unsigned long long clen) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $3 = PyString_GET_SIZE($input);
  $result = PyString_FromStringAndSize(NULL, $3);
  $1 = (unsigned char *)PyString_AS_STRING($result);
  $2 = (unsigned char *)PyString_AS_STRING($input);
}

%typemap(out) int {
  if ($1 != 0) {
    PyErr_Format(PyExc_ValueError, "Operation failed with error %d", $1);
    SWIG_fail;
  }
}

%typemap(out) void randombytes {}

/**
 * crypto_box typemaps. The dimensions on the arrays indicate padding.
 */
%typemap(in) (unsigned char out[crypto_box_BOXZEROBYTES],
              const unsigned char in[crypto_box_ZEROBYTES],
              unsigned long long mlen),
   (unsigned char out[crypto_box_ZEROBYTES],
    const unsigned char in[crypto_box_BOXZEROBYTES],
    unsigned long long mlen),
   (unsigned char out[crypto_secretbox_BOXZEROBYTES],
    const unsigned char in[crypto_secretbox_ZEROBYTES],
    unsigned long long mlen),
   (unsigned char out[crypto_secretbox_ZEROBYTES],
    const unsigned char in[crypto_secretbox_BOXZEROBYTES],
    unsigned long long mlen) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $3 = PyString_GET_SIZE($input) + $2_dim0;
  // Need to pad the beginning
  $1 = (unsigned char *)calloc($3 + $1_dim0, sizeof(unsigned char));
  $2 = (unsigned char *)calloc($3 + $2_dim0, sizeof(unsigned char));
  memcpy(&$2[$2_dim0], PyString_AS_STRING($input), $3);
}

%typemap(argout) (unsigned char out[crypto_box_BOXZEROBYTES],
                  const unsigned char in [crypto_box_ZEROBYTES],
                  unsigned long long mlen),
   (unsigned char out[crypto_box_ZEROBYTES],
    const unsigned char in[crypto_box_BOXZEROBYTES],
    unsigned long long mlen),
   (unsigned char out[crypto_secretbox_BOXZEROBYTES],
    const unsigned char in[crypto_secretbox_ZEROBYTES],
    unsigned long long mlen),
   (unsigned char out[crypto_secretbox_ZEROBYTES],
    const unsigned char in[crypto_secretbox_BOXZEROBYTES],
    unsigned long long mlen) {
  $result = PyString_FromStringAndSize((char *)&$1[$1_dim0], $3 - $1_dim0);
  free($1);
  free($2);
}

/**
 * Auth typemaps
 */
%typemap(out) int crypto_auth_verify, int crypto_onetimeauth_verify {
  if ($1 == 0) {
    $result = Py_True;
  } else {
    $result = Py_False;
  }
  Py_INCREF($result);
}


/**
 * Utilities
 */
void randombytes(unsigned char *buffer, unsigned long long bytes);

/**
 * Hash stuff
 */
%constant int crypto_hash_sha256_BYTES;
%constant char *crypto_hash_sha256_IMPLEMENTATION;
%constant char *crypto_hash_sha256_VERSION;
%constant int crypto_hash_sha512_BYTES;
%constant char *crypto_hash_sha512_IMPLEMENTATION;
%constant char *crypto_hash_sha512_VERSION;

int crypto_hash_sha256(unsigned char hash[32], const unsigned char *m,
                       unsigned long long mlen);
int crypto_hash_sha512(unsigned char hash[64], const unsigned char *m,
                       unsigned long long mlen);


/**
 * Authenticated public-key encryption
 */
%constant int crypto_box_PUBLICKEYBYTES;
%constant int crypto_box_SECRETKEYBYTES;
%constant int crypto_box_BEFORENMBYTES;
%constant int crypto_box_NONCEBYTES;
%constant int crypto_box_ZEROBYTES;
%constant int crypto_box_BOXZEROBYTES;
%constant char *crypto_box_PRIMITIVE;
%constant char *crypto_box_IMPLEMENTATION;
%constant char *crypto_box_VERSION;

int crypto_box(unsigned char out[crypto_box_BOXZEROBYTES],
               const unsigned char in[crypto_box_ZEROBYTES],
               unsigned long long mlen,
               const unsigned char n[crypto_box_NONCEBYTES],
               const unsigned char pk[crypto_box_PUBLICKEYBYTES],
               const unsigned char sk[crypto_box_SECRETKEYBYTES]);
int crypto_box_open(unsigned char out[crypto_box_ZEROBYTES],
                    const unsigned char in[crypto_box_BOXZEROBYTES],
                    unsigned long long mlen,
                    const unsigned char n[crypto_box_NONCEBYTES],
                    const unsigned char pk[crypto_box_PUBLICKEYBYTES],
                    const unsigned char sk[crypto_box_SECRETKEYBYTES]);
int crypto_box_keypair(unsigned char pk[crypto_box_PUBLICKEYBYTES],
                       unsigned char sk[crypto_box_SECRETKEYBYTES]);
int crypto_box_beforenm(unsigned char k[crypto_box_BEFORENMBYTES],
                        const unsigned char pk[crypto_box_PUBLICKEYBYTES],
                        const unsigned char sk[crypto_box_PUBLICKEYBYTES]);
int crypto_box_afternm(unsigned char out[crypto_box_BOXZEROBYTES],
                       const unsigned char in[crypto_box_ZEROBYTES],
                       unsigned long long mlen,
                       const unsigned char n[crypto_box_NONCEBYTES],
                       const unsigned char k[crypto_box_BEFORENMBYTES]);
int crypto_box_open_afternm(unsigned char out[crypto_box_ZEROBYTES],
                            const unsigned char in[crypto_box_BOXZEROBYTES],
                            unsigned long long mlen,
                            const unsigned char n[crypto_box_NONCEBYTES],
                            const unsigned char k[crypto_box_BEFORENMBYTES]);

/**
 * Scalar multiplication
 */
%constant int crypto_scalarmult_curve25519_SCALARBYTES;
%constant int crypto_scalarmult_curve25519_BYTES;

int crypto_scalarmult_curve25519(unsigned char q[crypto_scalarmult_curve25519_BYTES],
                                 const unsigned char n[crypto_scalarmult_curve25519_SCALARBYTES],
                                 const unsigned char p[crypto_scalarmult_curve25519_BYTES]);
int crypto_scalarmult_curve25519_base(unsigned char q[crypto_scalarmult_curve25519_BYTES],
                                      const unsigned char n[crypto_scalarmult_curve25519_SCALARBYTES]);


%pythoncode %{
crypto_scalarmult = crypto_scalarmult_curve25519
crypto_scalarmult_base = crypto_scalarmult_curve25519_base
%}

/**
 * Signatures
 */
%constant int crypto_sign_BYTES;
%constant int crypto_sign_PUBLICKEYBYTES;
%constant int crypto_sign_SECRETKEYBYTES;
%constant char *crypto_sign_PRIMITIVE;
%constant char *crypto_sign_IMPLEMENTATION;
%constant char *crypto_sign_VERSION;

int crypto_sign_keypair_fromseed(unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                                 unsigned char sk[crypto_sign_SECRETKEYBYTES],
                                 const unsigned char *seed,
                                 unsigned long long seedlen); // Custom
int crypto_sign_keypair(unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                        unsigned char sk[crypto_sign_SECRETKEYBYTES]);
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char sk[crypto_sign_SECRETKEYBYTES]);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char pk[crypto_sign_PUBLICKEYBYTES]);


/**
 * Authenticated secret-key encryption
 */
%constant int crypto_secretbox_KEYBYTES;
%constant int crypto_secretbox_NONCEBYTES;
%constant int crypto_secretbox_ZEROBYTES;
%constant int crypto_secretbox_BOXZEROBYTES;
%constant char *crypto_secretbox_PRIMITIVE;
%constant char *crypto_secretbox_IMPLEMENTATION;
%constant char *crypto_secretbox_VERSION;

int crypto_secretbox(unsigned char out[crypto_secretbox_BOXZEROBYTES],
                     const unsigned char in[crypto_secretbox_ZEROBYTES],
                     unsigned long long mlen,
                     const unsigned char n[crypto_secretbox_NONCEBYTES],
                     const unsigned char k[crypto_secretbox_KEYBYTES]);
int crypto_secretbox_open(unsigned char out[crypto_secretbox_ZEROBYTES],
                          const unsigned char in[crypto_secretbox_BOXZEROBYTES],
                          unsigned long long mlen,
                          const unsigned char n[crypto_secretbox_NONCEBYTES],
                          const unsigned char k[crypto_secretbox_KEYBYTES]);


/**
 * Secret-key encryption
 */
%constant int crypto_stream_KEYBYTES;
%constant int crypto_stream_NONCEBYTES;
%constant char *crypto_stream_PRIMITIVE;
%constant char *crypto_stream_IMPLEMENTATION;
%constant char *crypto_stream_VERSION;

int crypto_stream(unsigned char *c, unsigned long long clen,
                  const unsigned char n[crypto_stream_NONCEBYTES],
                  const unsigned char k[crypto_stream_KEYBYTES]);
int crypto_stream_xor(unsigned char *c, const unsigned char *in,
                      unsigned long long clen,
                      const unsigned char n[crypto_stream_NONCEBYTES],
                      const unsigned char k[crypto_stream_KEYBYTES]);


/**
 * Authentication
 */
%constant int crypto_auth_BYTES;
%constant int crypto_auth_KEYBYTES;
%constant char *crypto_auth_PRIMITIVE;
%constant char *crypto_auth_IMPLEMENTATION;
%constant char *crypto_auth_VERSION;

int crypto_auth(unsigned char a[crypto_auth_BYTES], const unsigned char *m,
                unsigned long long mlen,
                const unsigned char k[crypto_auth_KEYBYTES]);
int crypto_auth_verify(const unsigned char a[crypto_auth_BYTES],
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char k[crypto_auth_KEYBYTES]);


/**
 * One-time authentication
 */
%constant int crypto_onetimeauth_BYTES;
%constant int crypto_onetimeauth_KEYBYTES;
%constant char *crypto_onetimeauth_PRIMITIVE;
%constant char *crypto_onetimeauth_IMPLEMENTATION;
%constant char *crypto_onetimeauth_VERSION;

int crypto_onetimeauth(unsigned char a[crypto_onetimeauth_BYTES],
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char k[crypto_onetimeauth_KEYBYTES]);
int crypto_onetimeauth_verify(const unsigned char a[crypto_onetimeauth_BYTES],
                              const unsigned char *m, unsigned long long mlen,
                              const unsigned char k[crypto_onetimeauth_KEYBYTES]);
