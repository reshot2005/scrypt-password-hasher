import unittest

from scrypt_password_hasher import (
    hash_password,
    parse_record,
    verify_password,
)


class TestScryptPasswordHasher(unittest.TestCase):
    def test_hash_format(self):
        stored = hash_password("MyP@ss")

        self.assertTrue(stored.startswith("scrypt$v=1$n=16384$r=8$p=1$"))

        record = parse_record(stored)
        self.assertEqual(record.n, 16384)
        self.assertEqual(record.r, 8)
        self.assertEqual(record.p, 1)
        self.assertEqual(len(record.salt), 16)
        self.assertEqual(len(record.digest), 32)

    def test_password_verifies(self):
        stored = hash_password("correct horse battery staple")

        self.assertTrue(
            verify_password("correct horse battery staple", stored)
        )

    def test_wrong_password_does_not_verify(self):
        stored = hash_password("correct password")

        self.assertFalse(
            verify_password("incorrect password", stored)
        )

    def test_same_password_gets_different_salts(self):
        first = hash_password("same password")
        second = hash_password("same password")

        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("same password", first))
        self.assertTrue(verify_password("same password", second))

    def test_malformed_record_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_record("not-a-valid-record")

    def test_short_salt_is_rejected(self):
        stored = "scrypt$v=1$n=16384$r=8$p=1$0011$" + ("00" * 32)

        with self.assertRaises(ValueError):
            parse_record(stored)


if __name__ == "__main__":
    unittest.main()
