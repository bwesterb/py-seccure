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
    def test_verify(self):
        msg = 'This message will be signed\n'
        sig = '$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq'
        pubkey = '8W;>i^H0qi|J&$coR5MFpR*Vn'
        self.assertTrue(seccure.verify(msg, sig, pubkey))

if __name__ == '__main__':
    unittest.main()

