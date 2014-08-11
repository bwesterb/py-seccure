import unittest
import tempfile

import seccure
import six

class TestMain(unittest.TestCase):
    def test_passphrase_to_pubkey(self):
        self.assertEqual(str(seccure.passphrase_to_pubkey(b'test')),
                                '*jMVCU^[QC&q*v_8C1ZAFBAgD')
        self.assertEqual(str(seccure.passphrase_to_pubkey(b'my private key')),
                                '8W;>i^H0qi|J&$coR5MFpR*Vn')
        self.assertRaises(ValueError, seccure.passphrase_to_pubkey,
                            six.u('test'))
        for curvename in seccure.curves:
            seccure.passphrase_to_pubkey(b'test', curve=curvename)
    def test_encrypt(self):
        msg = b'My private message'
        pw = b'my private key'
        self.assertEqual(seccure.decrypt(seccure.encrypt(msg,
                        str(seccure.passphrase_to_pubkey(pw))),
                            b'my private key'), msg)
        for c in seccure.curves:
            self.assertEqual(seccure.decrypt(seccure.encrypt(msg,
                            str(seccure.passphrase_to_pubkey(pw, curve=c)),
                            curve=c), b'my private key', curve=c), msg)
    def test_verify(self):
        msg = b'This message will be signed\n'
        sig = b'$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq'
        pubkey = '8W;>i^H0qi|J&$coR5MFpR*Vn'
        self.assertTrue(seccure.verify(msg, sig, pubkey))
    def test_sign(self):
        msg = b'This message will be signed\n'
        pw = b'my private key'
        self.assertEqual(seccure.sign(msg, pw),
                b'$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq')
    def test_sign_and_verify(self):
        msg = b'This message will be signed\n'
        pw = b'my private key'
        for c in seccure.curves:
            pubkey = str(seccure.passphrase_to_pubkey(pw, curve=c))
            self.assertTrue(seccure.verify(msg, seccure.sign(msg, pw, curve=c),
                                    pubkey, curve=c))


    def test_encrypt_file_named(self):
        msg = b'My private message'
        pw = b'my private key'
        pubkey = '8W;>i^H0qi|J&$coR5MFpR*Vn'

        in_file = tempfile.NamedTemporaryFile()
        in_file.write(msg)
        in_file.flush()
        in_file.seek(0)

        encrypted_file = tempfile.NamedTemporaryFile()
        decrypted_file = tempfile.NamedTemporaryFile(delete=False)

        seccure.encrypt_file(in_file.name, encrypted_file.name,
                             pubkey)
        seccure.decrypt_file(encrypted_file.name, decrypted_file.name, pw)

        self.assertEqual(msg, decrypted_file.read())

    def test_encrypt_file(self):
        msg = b'My private message'
        pw = b'my private key'
        pubkey = '8W;>i^H0qi|J&$coR5MFpR*Vn'

        encrypted_file = tempfile.NamedTemporaryFile()
        decrypted_file = tempfile.NamedTemporaryFile(delete=False)

        with open(decrypted_file.name, 'wb') as fo:
            fo.write(msg)
        with open(decrypted_file.name, 'rb') as fi:
            with open(encrypted_file.name, 'wb') as fo:
                seccure.encrypt_file(fi, fo, pubkey)
        with open(decrypted_file.name, 'wb') as fo:
            with open(encrypted_file.name, 'rb') as fi:
                seccure.decrypt_file(fi, fo, pw)
        with open(decrypted_file.name, 'rb') as fi:
            self.assertEqual(msg, fi.read())

if __name__ == '__main__':
    unittest.main()
