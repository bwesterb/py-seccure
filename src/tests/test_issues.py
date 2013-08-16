import seccure
import six

""" Tests for specific issues that were reported on Github.

    See https://github.com/bwesterb/py-seccure/issues """

import unittest

import seccure

class TestIssues(unittest.TestCase):
    def test_issue5(self):
        self.assertEqual(repr(seccure.passphrase_to_pubkey(b'my private key')),
                            '<PubKey 8W;>i^H0qi|J&$coR5MFpR*Vn>')

if __name__ == '__main__':
    unittest.main()
