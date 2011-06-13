#!/usr/bin/env python
import binascii
import unittest

import nacl

class RandomTestCase(unittest.TestCase):
    def test_random_10(self):
        r = nacl.randombytes(10)
        self.assertEqual(len(r), 10)
        s = nacl.randombytes(10)
        self.assertNotEqual(r, s)

    def test_random_1000(self):
        r = nacl.randombytes(1000)
        self.assertEqual(len(r), 1000)


class HashTestCase(unittest.TestCase):
    fox = "The quick brown fox jumps over the lazy dog."
    def check_hash(self, func, s, h):
        f = getattr(nacl, func)
        r = f(s)
        self.assertEqual(binascii.b2a_hex(r), h)

    def test_sha256_empty(self):
        self.check_hash("crypto_hash_sha256", "",
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca4959"
                        "91b7852b855")

    def test_sha256_fox(self):
        self.check_hash("crypto_hash_sha256", self.fox,
                        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b7654"
                        "48c8635fb6c")

    def test_sha512_empty(self):
        self.check_hash("crypto_hash_sha512", "",
                        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a"
                        "921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47"
                        "417a81a538327af927da3e")

    def test_sha512_fox(self):
        self.check_hash("crypto_hash_sha512", self.fox,
                        "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d128"
                        "90cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3"
                        "c463d481c7e586c39ac1ed")


class BoxTestCase(unittest.TestCase):
    msg = "The quick brown fox jumps over the lazy dog."
    def setUp(self):
        self.pk1, self.sk1 = nacl.crypto_box_keypair()
        self.pk2, self.sk2 = nacl.crypto_box_keypair()

    def test_key_sizes(self):
        self.assertEqual(len(self.pk1), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(self.sk1), nacl.crypto_box_SECRETKEYBYTES)

    def test_box(self):
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        c = nacl.crypto_box(self.msg, nonce, self.pk2, self.sk1)
        m = nacl.crypto_box_open(c, nonce, self.pk1, self.sk2)
        self.assertEqual(m, self.msg)

    def test_box_badsig(self):
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        c = nacl.crypto_box(self.msg, nonce, self.pk1, self.sk2)
        c1 = c[:-1] + chr((ord(c[-1]) + 1) % 256)
        self.assertRaises(ValueError, nacl.crypto_box_open, c1, nonce, self.pk2,
                          self.sk1)


class SecretBoxTestCase(unittest.TestCase):
    msg = "The quick brown fox jumps over the lazy dog."
    def setUp(self):
        self.k = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)

    def test_secretbox(self):
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        c = nacl.crypto_secretbox(self.msg, nonce, self.k)
        m = nacl.crypto_secretbox_open(c, nonce, self.k)
        self.assertEqual(m, self.msg)

    def test_secretbox_badsig(self):
        nonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        c = nacl.crypto_secretbox(self.msg, nonce, self.k)
        c1 = c[:-1] + chr((ord(c[-1]) + 1) % 256)
        self.assertRaises(ValueError, nacl.crypto_secretbox_open, c1, nonce,
                          self.k)


class SignTestCase(unittest.TestCase):
    msg = "The quick brown fox jumps over the lazy dog."

    def setUp(self):
        self.pk, self.sk = nacl.crypto_sign_keypair()
        self.pk1, self.sk1 = nacl.crypto_sign_keypair_fromseed("hello world")

    def test_keys_different(self):
        self.assertNotEqual(self.pk, self.pk1)
        self.assertNotEqual(self.sk, self.sk1)
        self.assertNotEqual(self.pk, self.sk)
        self.assertNotEqual(self.pk1, self.sk1)

    def test_key_length(self):
        self.assertEqual(len(self.pk), nacl.crypto_sign_PUBLICKEYBYTES)
        self.assertEqual(len(self.sk), nacl.crypto_sign_SECRETKEYBYTES)

    def test_seed(self):
        self.assertEqual(binascii.b2a_hex(self.pk1),
                         "683d8d0458ef6ec4cfef25157f5d88ce7a0bba334fd102fafc7e"
                         "2751410d5718")
        self.assertEqual(binascii.b2a_hex(self.sk1),
                         "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd"
                         "3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f"
                         "605dcf7dc5542e93ae9cd76f")

    def test_signature(self):
        sm = nacl.crypto_sign(self.msg, self.sk)
        r = nacl.crypto_sign_open(sm, self.pk)
        self.assertEqual(r, self.msg)

    def test_failed_signature(self):
        sm = nacl.crypto_sign(self.msg, self.sk)
        self.assertRaises(ValueError, nacl.crypto_sign_open, sm, self.pk1)


if __name__ == '__main__':
    unittest.main()
