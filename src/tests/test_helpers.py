import unittest
import binascii

from six.moves import xrange

import six
import gmpy
import seccure

class TestHelpers(unittest.TestCase):
    def test_serialize_number_binary(self):
        for number, string in (
                    (1231234,       b'12c982'),
                    (0,             b''),
                    (255,           b'ff'),
                    (1231231231232, b'011eab19a500'),
                    (13371337,      b'cc07c9'),
                    (256,           b'0100')):
            self.assertEqual(binascii.hexlify(seccure.serialize_number(number)),
                                        string)
            self.assertEqual(binascii.hexlify(seccure.serialize_number(
                        gmpy.mpz(number))), string)
            self.assertEqual(seccure.deserialize_number(
                            binascii.unhexlify(string)), number)
        for number, string in (
                    (1231234,       b'0012c982'),
                    (0,             b'00000000'),
                    (255,           b'000000ff'),
                    (13371337,      b'00cc07c9'),
                    (256,           b'00000100')):
            self.assertEqual(binascii.hexlify(
                    seccure.serialize_number(number, outlen=4)), string)
            self.assertEqual(binascii.hexlify(
                    seccure.serialize_number(gmpy.mpz(number),
                                                outlen=4)), string)
            self.assertEqual(seccure.deserialize_number(
                            binascii.unhexlify(string)), number)
    def test_deserialize_number_compact_unicode(self):
        for number, string in (
                    (1231234,       '#c!E'),
                    (0,             ''),
                    (255,           '$p'),
                    (1231231231232, '$?Pvfdc'),
                    (13371337,      '5AkH'),
                    (90,            '#!'),
                    (89,            '~'),
                    (256,           '$q')):
            self.assertEqual(seccure.deserialize_number(
                            six.u(string), fmt=seccure.SER_COMPACT), number)

    def test_serialize_number_compact(self):
        for number, string in (
                    (1231234,       b'#c!E'),
                    (0,             b''),
                    (255,           b'$p'),
                    (1231231231232, b'$?Pvfdc'),
                    (13371337,      b'5AkH'),
                    (90,            b'#!'),
                    (89,            b'~'),
                    (256,           b'$q')):
            self.assertEqual(seccure.serialize_number(number,
                        fmt=seccure.SER_COMPACT), string)
            self.assertEqual(seccure.serialize_number(gmpy.mpz(number),
                        fmt=seccure.SER_COMPACT), string)
            self.assertEqual(seccure.deserialize_number(
                            string, fmt=seccure.SER_COMPACT), number)
        for number, string in (
                    (1231234,       b'!!!!!!#c!E'),
                    (0,             b'!!!!!!!!!!'),
                    (255,           b'!!!!!!!!$p'),
                    (1231231231232, b'!!!$?Pvfdc'),
                    (13371337,      b'!!!!!!5AkH'),
                    (90,            b'!!!!!!!!#!'),
                    (89,            b'!!!!!!!!!~'),
                    (256,           b'!!!!!!!!$q')):
            self.assertEqual(
                    seccure.serialize_number(number, outlen=10,
                            fmt=seccure.SER_COMPACT), string)
            self.assertEqual(seccure.deserialize_number(string,
                            fmt=seccure.SER_COMPACT), number)

    def test_mod_issquare(self):
        for p in (7, 37, 1489):
            p = gmpy.mpz(p)
            had = set()
            for n in xrange(p-1):
                sq = (n * n) % p
                if sq in had:
                    continue
                had.add(sq)
                self.assertTrue(seccure.mod_issquare(sq, p))
            for n in xrange(p-1):
                if n not in had:
                    self.assertFalse(seccure.mod_issquare(n, p))

    def test_mod_root(self):
        for p in (7, 37, 1489):
            p = gmpy.mpz(p)
            for n in xrange(p-1):
                if seccure.mod_issquare(n, p):
                    self.assertEqual((seccure.mod_root(n, p) ** 2) % p, n)

if __name__ == '__main__':
    unittest.main()
