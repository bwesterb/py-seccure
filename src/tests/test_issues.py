""" Tests for specific issues that were reported on Github.

    See https://github.com/bwesterb/py-seccure/issues """

import seccure

import unittest

import gmpy2


class TestIssues(unittest.TestCase):

    def test_issue5(self):
        self.assertEqual(repr(seccure.passphrase_to_pubkey(b'my private key')),
                         '<PubKey 8W;>i^H0qi|J&$coR5MFpR*Vn>')

    def test_issue10(self):
        for curvename in seccure.curves:
            curve = seccure.Curve.by_name(curvename)
            for pt in (curve.base, curve.base * gmpy2.mpz(1337)):
                self.assertEqual(pt + pt, pt * gmpy2.mpz(2))


if __name__ == '__main__':
    unittest.main()
