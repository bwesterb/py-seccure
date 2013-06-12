import unittest
import tempfile

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
    def test_sign(self):
        msg = 'This message will be signed\n'
        pw = 'my private key'
        self.assertEqual(seccure.sign(msg, pw),
                '$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq')

    def test_encrypt_file(self):
        msg = 'My private message'
        pw = 'my private key'
        pubkey = '8W;>i^H0qi|J&$coR5MFpR*Vn'

        in_file = tempfile.NamedTemporaryFile()
        in_file.write(msg)
        in_file.seek(0)

        encrypted_file = tempfile.NamedTemporaryFile()
        decrypted_file = tempfile.NamedTemporaryFile(delete=False)

        seccure.encrypt_file(in_file.name, encrypted_file.name,
                             pubkey)
        seccure.decrypt_file(encrypted_file.name, decrypted_file.name, pw)

        self.assertEqual(msg, decrypted_file.read())


if __name__ == '__main__':
    unittest.main()
