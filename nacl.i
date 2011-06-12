%module nacl

%{
  #include "crypto_box.h"
  #include "crypto_scalarmult_curve25519.h"
  #include "crypto_sign.h"
  #include "crypto_secretbox.h"
  #include "crypto_stream.h"
  #include "crypto_auth.h"
  #include "crypto_onetimeauth.h"
  #include "crypto_hash.h"
  #include "crypto_hash_sha256.h"

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

  void crypto_sign_keypair_fromseed(unsigned char *pk,
                                    unsigned char *sk,
                                    unsigned char *seed,
                                    int seedlen) {
    sc25519 scsk;
    ge25519 gepk;

    crypto_hash_sha512(sk, seed, seedlen);

    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    sc25519_from32bytes(&scsk, sk);

    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(pk, &gepk);
  }

%}

%include <typemaps.i>

%typemap(in) (const unsigned char *m, unsigned long long mlen) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    return NULL;
  }
  $1 = (unsigned char *)PyString_AsString($input);
  $2 = PyString_Size($input);
}

%typemap(in, numinputs=0) unsigned char *sha256hash (unsigned char temp[32]) {
  $1 = temp;
}

%typemap(argout) unsigned char *sha256hash {
  $result = PyString_FromStringAndSize((char *)$1, 32);
}

int crypto_hash_sha256(unsigned char *sha256hash, const unsigned char *m,
                       unsigned long long mlen);

%typemap(in, numinputs=0) unsigned char *sha512hash (unsigned char temp[64]) {
  $1 = temp;
}

%typemap(argout) unsigned char *sha512hash {
  $result = PyString_FromStringAndSize((char *)$1, 64);
}

int crypto_hash_sha512(unsigned char *sha512hash, const unsigned char *m,
                       unsigned long long mlen);


%constant int crypto_sign_PUBLICKEYBYTES;
%constant int crypto_sign_SECRETKEYBYTES;

%typemap(in, numinputs=0) (unsigned char *pk, unsigned char *sk)
  (unsigned char temp1[crypto_sign_PUBLICKEYBYTES],
   unsigned char temp2[crypto_sign_SECRETKEYBYTES]) {
  $1 = temp1;
  $2 = temp2;
}

%typemap(argout) (unsigned char *pk, unsigned char *sk) {
  $result = PyList_New(2);
  PyList_SetItem($result, 0,
                 PyString_FromStringAndSize((char *)$1,
                                            crypto_sign_PUBLICKEYBYTES));
  PyList_SetItem($result, 1,
                 PyString_FromStringAndSize((char *)$2,
                                            crypto_sign_SECRETKEYBYTES));
}

%typemap(in) (unsigned char *seed, int seedlen) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    return NULL;
  }
  $1 = (unsigned char *)PyString_AsString($input);
  $2 = PyString_Size($input);
}

void crypto_sign_keypair_fromseed(unsigned char *pk, unsigned char *sk,
                                  unsigned char *seed, int seedlen);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

%typemap(in) unsigned char *pk {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    return NULL;
  }
  if (PyString_Size($input) != crypto_sign_PUBLICKEYBYTES) {
    PyErr_Format(PyExc_ValueError, "Expecting a string of length %d",
                 crypto_sign_PUBLICKEYBYTES);
    return NULL;
  }
  $1 = (unsigned char *)PyString_AsString($input);
}

%typemap(in) unsigned char *sk {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    return NULL;
  }
  if (PyString_Size($input) != crypto_sign_SECRETKEYBYTES) {
    PyErr_Format(PyExc_ValueError, "Expecting a string of length %d",
                 crypto_sign_SECRETKEYBYTES);
    return NULL;
  }
  $1 = (unsigned char *)PyString_AsString($input);
}

%typemap(in)
  (unsigned char *sm, unsigned long long *smlen,
   const unsigned char *m, unsigned long long mlen)
     (unsigned long long temp) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    return NULL;
  }
  $4 = PyString_Size($input);
  $result = PyString_FromStringAndSize(NULL, $4 + crypto_sign_BYTES);
  $1 = (unsigned char *)PyString_AsString($result);
  $2 = &temp;
  $3 = (unsigned char *)PyString_AsString($input);
}

%typemap(in)
  (unsigned char *m, unsigned long long *mlen,
   const unsigned char *sm, unsigned long long smlen)
  (unsigned long long temp) {
  if (!PyString_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    return NULL;
  }
  $4 = PyString_Size($input);
  $result = PyString_FromStringAndSize(NULL, $4);
  $1 = (unsigned char *)PyString_AsString($result);
  $2 = &temp;
  $3 = (unsigned char *)PyString_AsString($input);
}

%typemap(argout) (unsigned char *sm, unsigned long long *smlen),
  (unsigned char *m, unsigned long long *mlen) {
  _PyString_Resize(&$result, *$2);
}

%typemap(freearg) unsigned char *sm, unsigned char *m {
  free($1);
}

%typemap(out) int {
  if ($1 != 0) {
    PyErr_Format(PyExc_ValueError, "Operation failed with error %d", $1);
    return NULL;
  }
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     unsigned char *pk);


