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

  #if PY_MAJOR_VERSION > 2
  #define MAKEINT PyLong_AsUnsignedLongLong
  #else
  #define MAKEINT PyInt_AsUnsignedLongLongMask
  #endif

%}

%include <typemaps.i>

%typemap(in) (const unsigned char *m, unsigned long long mlen) {
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $1 = (unsigned char *)PyBytes_AS_STRING($input);
  $2 = PyBytes_GET_SIZE($input);
}

%typemap(in, numinputs=0) unsigned char [ANY] {
  $result = PyBytes_FromStringAndSize(NULL, $1_dim0);
  $1 = (unsigned char *)PyBytes_AS_STRING($result);
}

// For some reason [ANY] doesn't work for multi-argument typemaps.
%typemap(in, numinputs=0) (unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                           unsigned char sk[crypto_sign_SECRETKEYBYTES])
                          (PyObject *temp1, PyObject *temp2),
                          (unsigned char pk[crypto_box_PUBLICKEYBYTES],
                           unsigned char sk[crypto_box_SECRETKEYBYTES])
                          (PyObject *temp1, PyObject *temp2) {
  temp1 = PyBytes_FromStringAndSize(NULL, $1_dim0);
  $1 = (unsigned char *)PyBytes_AS_STRING(temp1);
  temp2 = PyBytes_FromStringAndSize(NULL, $2_dim0);
  $2 = (unsigned char *)PyBytes_AS_STRING(temp2);
  $result = PyTuple_Pack(2, temp1, temp2);
  Py_DECREF(temp1);
  Py_DECREF(temp2);
}

%typemap(in) (const unsigned char *seed, unsigned long long seedlen) {
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $1 = (unsigned char *)PyBytes_AS_STRING($input);
  $2 = (unsigned long long)PyBytes_GET_SIZE($input);
}

%typemap(in) const unsigned char [ANY] {
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  if (PyBytes_GET_SIZE($input) != $1_dim0) {
    PyErr_Format(PyExc_ValueError, "Expecting a string of length %d", $1_dim0);
    SWIG_fail;
  }
  $1 = (unsigned char *)PyBytes_AS_STRING($input);
}

%typemap(in)
  (unsigned char *sm, unsigned long long *smlen,
   const unsigned char *m, unsigned long long mlen)
     (unsigned long long temp) {
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $4 = PyBytes_GET_SIZE($input);
  $result = PyBytes_FromStringAndSize(NULL, $4 + crypto_sign_BYTES);
  $1 = (unsigned char *)PyBytes_AS_STRING($result);
  $2 = &temp;
  $3 = (unsigned char *)PyBytes_AS_STRING($input);
}

%typemap(in)
  (unsigned char *m, unsigned long long *mlen,
   const unsigned char *sm, unsigned long long smlen)
  (unsigned long long temp) {
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $4 = PyBytes_GET_SIZE($input);
  $result = PyBytes_FromStringAndSize(NULL, $4);
  $1 = (unsigned char *)PyBytes_AS_STRING($result);
  $2 = &temp;
  $3 = (unsigned char *)PyBytes_AS_STRING($input);
}

%typemap(argout) (unsigned char *sm, unsigned long long *smlen),
  (unsigned char *m, unsigned long long *mlen) {
  _PyBytes_Resize(&$result, *$2);
}

%typemap(in) (unsigned char *buffer, unsigned long long bytes),
             (unsigned char *c, unsigned long long clen) {
  $2 = MAKEINT($input);
  if ($2 == -1 && PyErr_Occurred() != NULL) {
    SWIG_fail;
  }
  $result = PyBytes_FromStringAndSize(NULL, $2);
  $1 = (unsigned char *)PyBytes_AS_STRING($result);
}

%typemap(in) (unsigned char *c, const unsigned char *in,
              unsigned long long clen) {
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $3 = PyBytes_GET_SIZE($input);
  $result = PyBytes_FromStringAndSize(NULL, $3);
  $1 = (unsigned char *)PyBytes_AS_STRING($result);
  $2 = (unsigned char *)PyBytes_AS_STRING($input);
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
  if (!PyBytes_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expecting a string");
    SWIG_fail;
  }
  $3 = PyBytes_GET_SIZE($input) + $2_dim0;
  // Need to pad the beginning
  $1 = (unsigned char *)calloc($3 + $1_dim0, sizeof(unsigned char));
  $2 = (unsigned char *)calloc($3 + $2_dim0, sizeof(unsigned char));
  memcpy(&$2[$2_dim0], PyBytes_AS_STRING($input), $3);
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
  $result = PyBytes_FromStringAndSize((char *)&$1[$1_dim0], $3 - $1_dim0);
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
%feature("docstring") {
randombytes(length) -> random bytestring

Produces a random bytestring of the desired length, by reading from
/dev/urandom.
}
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

%feature("docstring") {
crypto_hash_sha256(string) -> hash

Produces the 32-byte-long SHA256 hash of the input bytestring.
}
int crypto_hash_sha256(unsigned char hash[32], const unsigned char *m,
                       unsigned long long mlen);
%feature("docstring") {
crypto_hash_sha512(string) -> hash

Produces the 64-byte-long SHA512 hash of the input bytestring.
}
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

%feature("docstring") {
crypto_box(message, nonce, their_pubkey, my_privkey) -> encrypted

Encrypts+authenticates a message by combining a public and a private key
to generate a shared secret. Takes a unique nonce (a bytestring of
length nacl.crypto_box_NONCEBYTES) and two keys (as bytestrings of
length nacl.crypto_box_PUBLICKEYBYTES and crypto_box_SECRETKEYBYTES),
returns a boxed message (also a bytestring).
}
int crypto_box(unsigned char out[crypto_box_BOXZEROBYTES],
               const unsigned char in[crypto_box_ZEROBYTES],
               unsigned long long mlen,
               const unsigned char n[crypto_box_NONCEBYTES],
               const unsigned char pk[crypto_box_PUBLICKEYBYTES],
               const unsigned char sk[crypto_box_SECRETKEYBYTES]);
%feature("docstring") {
crypto_box_open(encrypted, nonce, their_pubkey, my_privkey) -> message

Decrypts+authenticates a boxed message from crypto_box(). Takes a unique
nonce (a bytestring of length nacl.crypto_box_NONCEBYTES) and two keys
(as bytestrings of length nacl.crypto_box_PUBLICKEYBYTES and
crypto_box_SECRETKEYBYTES), returns the decrypted message (also a
bytestring). If authentication fails, ValueError is raised.
}
int crypto_box_open(unsigned char out[crypto_box_ZEROBYTES],
                    const unsigned char in[crypto_box_BOXZEROBYTES],
                    unsigned long long mlen,
                    const unsigned char n[crypto_box_NONCEBYTES],
                    const unsigned char pk[crypto_box_PUBLICKEYBYTES],
                    const unsigned char sk[crypto_box_SECRETKEYBYTES]);
%feature("docstring") {
crypto_box_keypair() -> (pubkey, privkey)

Creates a keypair by reading /dev/urandom. Returns a tuple of bytestrings.
'pubkey' is the public key, of length  nacl.crypto_box_PUBLICKEYBYTES, and
'privkey' is the secret key, of length nacl.crypto_box_SECRETKEYBYTES.
}
int crypto_box_keypair(unsigned char pk[crypto_box_PUBLICKEYBYTES],
                       unsigned char sk[crypto_box_SECRETKEYBYTES]);
%feature("docstring") {
crypto_box_beforenm(pubkey, privkey) -> precomputed 'K' value

Precomputes the non-message-specific shared key. This can be used to
amortize multiple crypto_box() calls for the same sender/receiver pair.
Pass the generated K value into crypto_box_afternm() or
crypto_box_open_afternm().
}
int crypto_box_beforenm(unsigned char k[crypto_box_BEFORENMBYTES],
                        const unsigned char pk[crypto_box_PUBLICKEYBYTES],
                        const unsigned char sk[crypto_box_PUBLICKEYBYTES]);
%feature("docstring") {
crypto_box_afternm(message, nonce, K) -> encrypted

Like crypto_box(), but uses the precomputed K value from crypto_box_beforenm().
}
int crypto_box_afternm(unsigned char out[crypto_box_BOXZEROBYTES],
                       const unsigned char in[crypto_box_ZEROBYTES],
                       unsigned long long mlen,
                       const unsigned char n[crypto_box_NONCEBYTES],
                       const unsigned char k[crypto_box_BEFORENMBYTES]);
%feature("docstring") {
crypto_box_open_afternm(encrypted, nonce, K) -> message

Like crypto_box_open(), but uses the precomputed K value from
crypto_box_beforenm().
}
int crypto_box_open_afternm(unsigned char out[crypto_box_ZEROBYTES],
                            const unsigned char in[crypto_box_BOXZEROBYTES],
                            unsigned long long mlen,
                            const unsigned char n[crypto_box_NONCEBYTES],
                            const unsigned char k[crypto_box_BEFORENMBYTES]);


/**
 * Scalar multiplication
 */
%constant int crypto_scalarmult_curve25519_BYTES;
%constant int crypto_scalarmult_curve25519_SCALARBYTES;
%constant char *crypto_scalarmult_curve25519_IMPLEMENTATION;
%constant char *crypto_scalarmult_curve25519_VERSION;

%feature("docstring") {
crypto_scalarmult_curve25519(scalar, element) -> element

Performs Curve25519 multiplication of a scalar (a bytestring of length
crypto_scalarmult_curve25519_SCALARBYTES) and a group element (a
bytestring of length crypto_scalarmult_curve25519_BYTES), resulting in
another group element (again a bytestring). This is a one-way function:
it is hard to derive the scalar from the output group element (CDH: the
Computational Diffie-Hellman Problem). All strings represent at least
one group element.
}
int crypto_scalarmult_curve25519(unsigned char
                                   q[crypto_scalarmult_curve25519_BYTES],
                                 const unsigned char
                                   n[crypto_scalarmult_curve25519_SCALARBYTES],
                                 const unsigned char
                                   p[crypto_scalarmult_curve25519_BYTES]);
%feature("docstring") {
crypto_scalarmult_curve25519_base(scalar) -> element

Like crypto_scalarmult_curve25519(), but uses a standard "base" group
element (a generator). The scalar is a bytestring of length
crypto_scalarmult_curve25519_SCALARBYTES, and the output group element
is a bytestring of length crypto_scalarmult_curve25519_BYTES.
}
int crypto_scalarmult_curve25519_base(unsigned char
                                        q[crypto_scalarmult_curve25519_BYTES],
                                      const unsigned char
                                        n[crypto_scalarmult_curve25519_SCALARBYTES]);


/**
 * Signatures
 */
%constant int crypto_sign_BYTES;
%constant int crypto_sign_PUBLICKEYBYTES;
%constant int crypto_sign_SECRETKEYBYTES;
%constant char *crypto_sign_PRIMITIVE;
%constant char *crypto_sign_IMPLEMENTATION;
%constant char *crypto_sign_VERSION;

%feature("docstring") {
crypto_sign_keypair_fromseed(seed) -> (verifying_key, signing_key)

Generate a signature keypair from a secret seed. The verifying key will
be a bytestring of length crypto_sign_PUBLICKEYBYTES, and the signing
key will be of length crypto_sign_SECRETKEYBYTES. The seed can be a
bytestring of any length, but must have at least
crypto_sign_SECRETKEYBYTES of entropy to be secure.
}
int crypto_sign_keypair_fromseed(unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                                 unsigned char sk[crypto_sign_SECRETKEYBYTES],
                                 const unsigned char *seed,
                                 unsigned long long seedlen); // Custom
%feature("docstring") {
crypto_sign_keypair() -> (verifying_key, signing_key)

Generate a signature keypair by reading /dev/urandom. The verifying key
will be a bytestring of length crypto_sign_PUBLICKEYBYTES, and the
signing key will be of length crypto_sign_SECRETKEYBYTES.
}
int crypto_sign_keypair(unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                        unsigned char sk[crypto_sign_SECRETKEYBYTES]);
%feature("docstring") {
crypto_sign(message, signing_key) -> signed_message

Sign a message, using a private signing key (a bytestring of length
crypto_sign_SECRETKEYBYTES). The message can be a bytestring of any
length. The signed_message will be a bytestring that includes both the
message and the signature.
}
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char sk[crypto_sign_SECRETKEYBYTES]);
%feature("docstring") {
crypto_sign_open(signed_message, verifying_key) -> message

Verify a signed message, using a public verifying key (a bytestring of
length crypto_sign_PUBLICKEYBYTES). If the signature was correct, the
message is returned. If not, ValueError is raised.
}
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

%feature("docstring") {
crypto_secretbox(message, nonce, key) -> encrypted

Encrypts+authenticates a message using a (symmetric) secret key. Takes a
unique nonce (a bytestring of length nacl.crypto_secretbox_NONCEBYTES)
and one shared key (a bytestring of length
nacl.crypto_secretbox_KEYBYTES), returns a boxed message (also a
bytestring).
}
int crypto_secretbox(unsigned char out[crypto_secretbox_BOXZEROBYTES],
                     const unsigned char in[crypto_secretbox_ZEROBYTES],
                     unsigned long long mlen,
                     const unsigned char n[crypto_secretbox_NONCEBYTES],
                     const unsigned char k[crypto_secretbox_KEYBYTES]);
%feature("docstring") {
crypto_secretbox_open(encrypted, nonce, key) -> message

Decrypts+authenticates a boxed message from crypto_secretbox(). Takes a
unique nonce (a bytestring of length nacl.crypto_secretbox_NONCEBYTES)
and a key (bytestring of length nacl.crypto_secretbox_KEYBYTES), returns
the decrypted message (also a bytestring). If authentication fails,
ValueError is raised.
}
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

%feature("docstring") {
crypto_stream(length, nonce, key) -> keystream

Generate a pseudo-random stream, given a unique nonce and secret key.
This is a PRF (Pseudo-Random Function). The stream is a bytestring of
'length' bytes, the nonce is a bytestring of length
crypto_stream_NONCEBYTES, and the key is a bytestring of length
crypto_stream_KEYBYTES.
}
int crypto_stream(unsigned char *c, unsigned long long clen,
                  const unsigned char n[crypto_stream_NONCEBYTES],
                  const unsigned char k[crypto_stream_KEYBYTES]);
%feature("docstring") {
crypto_stream_xor(message, nonce, key) -> encrypted

Encrypts a message by XORing with the pseudo-random stream generated by
crypto_stream(), given a unique nonce and secret key. Does not provide
message authentication. Both the input message and the encrypted output
are bytestrings (of equal length). The nonce is a bytestring of length
crypto_stream_NONCEBYTES, and the key is a bytestring of length
crypto_stream_KEYBYTES.
}
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

%feature("docstring") {
crypto_auth(message, key) -> authenticator

Produces a message authentication code for the given message and secret
key, to be passed into crypto_auth_verify(). The key is a bytestring of
length crypto_auth_KEYBYTES, and the authenticator is a bytestring of
length crypto_auth_BYTES. It is safe to use the same key for multiple
messages.
}
int crypto_auth(unsigned char a[crypto_auth_BYTES], const unsigned char *m,
                unsigned long long mlen,
                const unsigned char k[crypto_auth_KEYBYTES]);
%feature("docstring") {
crypto_auth_verify(authenticator, message, key) -> None

Verifies the authenticator created by crypto_auth(), raising ValueError
if authentication fails (i.e. the message or authenticator differs from
what was given to crypto_auth()). The key is a bytestring of length
crypto_auth_KEYBYTES, and the authenticator is a bytestring of length
crypto_auth_BYTES.
}
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

%feature("docstring") {
crypto_onetimeauth(message, key) -> authenticator

Produces a message authentication code for a message and secret key, to
be passed into crypto_onetimeauth_verify(). The key must *only* be used
for a single message: authenticators for two messages under the same key
should be expected to reveal enough information to allow forgeries of
authenticators on other messages. This is generally 3x faster than the
safer crypto_auth() function, and meant primarily for use inside
crypto_box().

The key is a bytestring of length crypto_onetimeauth_KEYBYTES, and the
authenticator is a bytestring of length crypto_onetimeauth_BYTES.
}
int crypto_onetimeauth(unsigned char a[crypto_onetimeauth_BYTES],
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char k[crypto_onetimeauth_KEYBYTES]);
%feature("docstring") {
crypto_onetimeauth_verify(authenticator, message, key) -> None

Verifies the authenticator created by crypto_onetimeauth(), raising
ValueError if authentication fails (i.e. the message or authenticator
differs from what was given to crypto_auth()). The key is a bytestring
of length crypto_onetimeauth_KEYBYTES, and the authenticator is a
bytestring of length crypto_onetimeauth_BYTES.
}
int crypto_onetimeauth_verify(const unsigned char a[crypto_onetimeauth_BYTES],
                              const unsigned char *m, unsigned long long mlen,
                              const unsigned char k[crypto_onetimeauth_KEYBYTES]);
