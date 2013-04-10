import unittest

import seccure

class TestMain(unittest.TestCase):
    def test_passphrase_to_pubkey(self):
        self.assertEqual(str(seccure.passphrase_to_pubkey('test')),
                                '*jMVCU^[QC&q*v_8C1ZAFBAgD')
        self.assertEqual(str(seccure.passphrase_to_pubkey('my private key')),
                                '8W;>i^H0qi|J&$coR5MFpR*Vn')
    def test_encrypt(self):
        msg = 'My private message'
        pw = 'my private key'
        self.assertEqual(seccure.decrypt(seccure.encrypt(msg,
                        str(seccure.passphrase_to_pubkey(pw))),
                            'my private key'), msg)

if __name__ == '__main__':
    unittest.main()

