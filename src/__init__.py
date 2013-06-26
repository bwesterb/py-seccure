""" Elliptic Curve cryptography compatible with SECCURE:
        http://point-at-infinity.org/seccure/ """

import sys
import hmac
import hashlib
import logging
import binascii
import contextlib
import collections

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

# PyCrypto
import Crypto.Util
import Crypto.Cipher.AES
import Crypto.Random.random

# gmpy
import gmpy

l = logging.getLogger(__name__)

class IntegrityError(ValueError):
    pass

# Serialization of numbers
# #########################################################
SER_COMPACT = 0
SER_BINARY  = 1

COMPACT_DIGITS = ('!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                          '[]^_abcdefghijklmnopqrstuvwxyz{|}~')
R_COMPACT_DIGITS = {}  # TODO is a tuple/list faster?
for i, c in enumerate(COMPACT_DIGITS):
    R_COMPACT_DIGITS[c] = i

def serialize_number(x, fmt=SER_BINARY, outlen=None):
    """ Serializes `x' to a string of length `outlen' in format `fmt' """
    ret = ''
    if fmt == SER_BINARY:
        while x:
            x, r = divmod(x, 256)
            ret = chr(r) + ret
        if outlen is not None:
            assert len(ret) <= outlen
            ret = ret.rjust(outlen, '\0')
        return ret
    assert fmt == SER_COMPACT
    while x:
        x, r = divmod(x, len(COMPACT_DIGITS))
        ret = COMPACT_DIGITS[r] + ret
    if outlen is not None:
        assert len(ret) <= outlen
        ret = ret.rjust(outlen, COMPACT_DIGITS[0])
    return ret

def deserialize_number(s, fmt=SER_BINARY):
    """ Deserializes a number from a string `s' in format `fmt' """
    ret = gmpy.mpz(0)
    if fmt == SER_BINARY:
        for c in s:
            ret *= 256
            ret += ord(c)
        return ret
    assert fmt == SER_COMPACT
    for c in s:
        ret *= len(COMPACT_DIGITS)
        ret += R_COMPACT_DIGITS[c]
    return ret

def get_serialized_number_len(x, fmt=SER_BINARY):
    if fmt == SER_BINARY:
        return (x.numdigits(2) + 7) / 8
    assert fmt == SER_COMPACT
    res = 0
    while x != 0:
        x = x / len(COMPACT_DIGITS)
        res += 1
    return res

# Some modular arithmetic
# #########################################################

def mod_issquare(a, p):
    """ Returns whether `a' is a square modulo p """
    if not a:
        return True
    p1 = p / 2
    p2 = pow(a, p1, p)
    return p2 == 1

def mod_root(a, p):
    """ Return a root of `a' modulo p """
    if a == 0:
        return 0
    if not mod_issquare(a, p):
        raise ValueError
    n = 2
    while mod_issquare(n, p):
        n += 1
    q = p - 1
    r = 0
    while not q.getbit(r):
        r += 1
    q = q >> r
    y = pow(n, q, p)
    h = q >> 1
    b = pow(a, h, p)
    x = (a * b) % p
    b = (b * x) % p
    while b != 1:
        h = (b * b) % p
        m = 1
        while h != 1:
            h = (h * h) % p
            m += 1
        h = 0
        h.setbit(r - m - 1)
        t = pow(y, h, p)
        y = (t * t) % p
        r = m
        x = (x * t) % p
        b = (b * y) % p
    return x

# Raw curve parameters
# #########################################################

raw_curve_parameters = collections.namedtuple('raw_curve_parameters',
            ('name', 'a', 'b', 'm', 'base_x', 'base_y', 'order', 'cofactor'))
RAW_CURVES = {
    18 : ("secp112r1",
        "db7c2abf62e35e668076bead2088", 
        "659ef8ba043916eede8911702b22", 
        "db7c2abf62e35e668076bead208b",
        "09487239995a5ee76b55f9c2f098",
        "a89ce5af8724c0a23e0e0ff77500", 
        "db7c2abf62e35e7628dfac6561c5", 1),
    20: ("secp128r1",
        "fffffffdfffffffffffffffffffffffc", 
        "e87579c11079f43dd824993c2cee5ed3", 
        "fffffffdffffffffffffffffffffffff",
        "161ff7528b899b2d0c28607ca52c5b86", 
        "cf5ac8395bafeb13c02da292dded7a83",
        "fffffffe0000000075a30d1b9038a115", 1),
    25: ("secp160r1", 
        "ffffffffffffffffffffffffffffffff7ffffffc",
        "1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
        "ffffffffffffffffffffffffffffffff7fffffff",
        "4a96b5688ef573284664698968c38bb913cbfc82",
        "23a628553168947d59dcc912042351377ac5fb32",
        "0100000000000000000001f4c8f927aed3ca752257", 1),
    30: ("secp192r1/nistp192",
        "fffffffffffffffffffffffffffffffefffffffffffffffc",
        "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 
        "fffffffffffffffffffffffffffffffeffffffffffffffff",
        "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
        "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
        "ffffffffffffffffffffffff99def836146bc9b1b4d22831", 1),
    35: ("secp224r1/nistp224",
        "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
        "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        "ffffffffffffffffffffffffffffffff000000000000000000000001",
        "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
        "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 1),
    40: ("secp256r1/nistp256",
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 1),
    60: ("secp384r1/nistp384",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"+
            "ffffffff0000000000000000fffffffc",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"+
            "c656398d8a2ed19d2a85c8edd3ec2aef", 
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"+
            "ffffffff0000000000000000ffffffff",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"+
            "5502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"+
            "0a60b1ce1d7e819d7a431d7c90ea0e5f", 
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"+
            "581a0db248b0a77aecec196accc52973", 1),
    81: ("secp521r1/nistp521",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            "fffffffc",
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"+
            "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd4"+
            "6b503f00",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            "ffffffff",
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"+
            "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31"+
            "c2e5bd66",
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"+
            "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be9476"+
            "9fd16650",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            "fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e"+
            "91386409", 1)
    }

# Arithmetic on elliptic curves
# #########################################################

class JacobianPoint(object):
    def __init__(self, x, y, z, curve):
        self.x = x
        self.y = y
        self.z = z
        self.curve = curve
    def to_affine(self):
        if self.z == 0:
            return AffinePoint(x=0, y=0, curve=self.curve)
        m = self.curve.m
        h = gmpy.invert(self.z, m)
        y = (h * h) % m
        x = (self.x * y) % m
        y = (y * h) % m
        y = (y * self.y) % m
        return AffinePoint(x=x, y=y, curve=self.curve)
    def double(self):
        if not self.z:
            return self
        if not self.y:
            return JacobianPoint(x=self.x, y=self.y, z=0, curve=self.curve)
        m = self.curve.m
        a = self.curve.a
        t1 = (self.x * self.x) % m
        t2 = (t1 + t1) % m
        t2 = (t2 + t1) % m
        t1 = (self.z * self.z) % m
        t1 = (t1 * t1) % m
        t1 = (t1 * a) % m
        t1 = (t1 + t2) % m
        z = (self.z * self.y) % m
        z = (z + z) % m
        y = (self.y * self.y) % m
        y = (y + y) % m
        t2 = (self.x * y) % m
        t2 = (t2 + t2) % m
        x = (t1 * t1) % m
        x = (x - t2) % m
        x = (x - t2) % m
        t2 = (t2 - x) % m
        t1 = (t1 * t2) % m
        t2 = (y * y) % m
        t2 = (t2 + t2) % m
        y = (t1 - t2) % m
        return JacobianPoint(x=x, y=y, z=z, curve=self.curve)
    def __add__(self, other):
        if not isinstance(other, AffinePoint):
            raise NotImplementedError
        if not other:
            return self
        if not self.z:
            return other.to_jacobian()
        m = self.curve.m
        t1 = (self.z * self.z) % m
        t2 = (t1 * other.x) % m
        t1 = (t1 * self.z) % m
        t1 = (t1 * other.y) % m
        if self.x == t2:
            if self.y == t1:
                return self.double()
            return JacobianPoint(x=self.x, y=self.y, z=0, curve=self.curve)
        x = (self.x - t2) % m
        y = (self.y - t1) % m
        z = (self.z * x) % m
        t3 = (x * x) % m
        t2 = (t2 * t3) % m
        t3 = (t3 * x) % m
        t1 = (t1 * t3) % m
        x = (y * y) % m
        x = (x - t3) % m
        x = (x - t2) % m
        x = (x - t2) % m
        t2 = (t2 - x) % m
        y = (y * t2) % m
        y = (y - t1) % m
        return JacobianPoint(x=x, y=y, z=z, curve=self.curve)
        
    def __repr__(self):
        return "<JacobianPoint (%s, %s, %s) of %s>" % (
                            self.x, self.y, self.z, self.curve.name)

class AffinePoint(object):
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    @property
    def on_curve(self):
        if not self:
            return True
        m = self.curve.m
        a = self.curve.a
        b = self.curve.b
        h1 = (self.x * self.x) % m
        h1 = (h1 + a) % m
        h1 = (h1 * self.x) % m
        h1 = (h1 + b) % m
        h2 = (self.y * self.y) % m
        return h1 == h2
    def to_jacobian(self):
        if not self:
            return JacobianPoint(x=0, y=0, z=0, curve=self.curve)
        return JacobianPoint(x=self.x, y=self.y, z=1, curve=self.curve)
    def __mul__(self, exp):
        n = exp.numdigits(2)
        r = JacobianPoint(x=0, y=0, z=0, curve=self.curve)
        while n:
            r = r.double()
            n -= 1
            if exp.getbit(n):
                r = r + self
        R = r.to_affine()
        assert R.on_curve
        return R
    def __add__(self, other):
        if not isinstance(other, AffinePoint):
            raise NotImplementedError
        if not other:
            return self
        if not self:
            return other
        if self.x == other.x:
            if self.y == other.y:
                return self.double()
            return AffinePoint(x=0, y=0, curve=self.curve)
        m = self.curve.m
        t = (self.y - other.y) % m
        y = (self.x - other.x) % m
        y = gmpy.invert(y, m)
        y = (t * y) % m
        t = (y * y) % m
        x = (self.x + other.x) % m
        x = (t - x) % m
        t = (other.x - x) % m
        y = (y * t) % m
        y = (y - other.y) % m
        return AffinePoint(x=x, y=y, curve=self.curve)

    def __nonzero__(self):
        return bool(self.x or self.y)
    def __repr__(self):
        return "<AffinePoint (%s, %s) of %s>" % (
                            self.x, self.y, self.curve.name)
    def __str__(self):
        return self.to_string(SER_COMPACT)
    def to_string(self, fmt=SER_BINARY):
        outlen = (self.curve.pk_len_compact if fmt == SER_COMPACT
                        else self.curve.pk_len_bin)
        if self._point_compress():
            return serialize_number(self.x + self.curve.m, fmt, outlen)
        return serialize_number(self.x, fmt, outlen)
    def _point_compress(self):
        return self.y.getbit(0) == 1
    def _ECIES_KDF(self, R):
        h = hashlib.sha512()
        h.update(serialize_number(self.x, SER_BINARY, self.curve.elem_len_bin))
        h.update(serialize_number(R.x, SER_BINARY,self.curve.elem_len_bin))
        h.update(serialize_number(R.y, SER_BINARY,self.curve.elem_len_bin))
        return h.digest()
    def _ECIES_encryption(self):
        while True:
            k = gmpy.mpz(Crypto.Random.random.randrange(0,
                            int(self.curve.order - 1)))
            R = self.curve.base * k
            k = k * self.curve.cofactor
            Z = self * k
            if Z:
                break
        return (Z._ECIES_KDF(R), R)
    def _ECIES_decryption(self, d):
        if isinstance(d, PrivKey):
            d = d.e
        e = d * self.curve.cofactor
        if not self.valid_embedded_key:
            raise ValueError
        Z = self * e
        if not Z:
            raise ValueError
        return Z._ECIES_KDF(self)
    def _ECDSA_verify(self, md, sig):
        order = self.curve.order
        s, r = divmod(sig, order)
        if s <= 0  or order <= s or r <= 0 or order <= r:
            return False
        e = deserialize_number(md, SER_BINARY) % order
        s = gmpy.invert(s, order)
        e = (e * s) % order
        X1 = self.curve.base * e
        e = (r * s) % order
        X2 = self * e
        X1 = X1 + X2
        if not X1:
            return False
        s = X1.x % order
        return s == r
    @property
    def valid_embedded_key(self):
        if (self.x < 0 or self.x >= self.curve.m or self.y < 0 or
                    self.y > self.curve.m):
            return False
        if not self:
            return False
        if not self.on_curve:
            return False
        return True

class PubKey(object):
    """ A public affine point """
    def __init__(self, p):
        self.p = p

    def verify(self, h, sig, sig_fmt=SER_BINARY):
        """ Verifies that `sig' is a signature for a message with
            SHA-512 hash `h'. """
        s = deserialize_number(sig, sig_fmt)
        return self.p._ECDSA_verify(h, s)

    @contextlib.contextmanager
    def encrypt_to(self, f, mac_bytes=10):
        """ Returns a file like object `ef'.  Anything written to `ef'
            will be encrypted for this pubkey and written to `f'. """
        ctx = EncryptionContext(f, self.p, mac_bytes)
        yield ctx
        ctx.finish()

    def encrypt(self, s, mac_bytes=10):
        """ Encrypt `s' for this pubkey. """
        out = StringIO()
        with self.encrypt_to(out, mac_bytes) as f:
            f.write(s)
        return out.getvalue()

    def to_string(self, fmt=SER_BINARY):
        return self.p.to_string(fmt)
    def __str__(self):
        return str(self.p)
    def __repr__(self):
        return "<PubKey %s>" % str(self)

class PrivKey(object):
    """ A secret exponent """
    def __init__(self, e, curve):
        self.e = e
        self.curve = curve
    @contextlib.contextmanager
    def decrypt_from(self, f, mac_bytes=10):
        """ Decrypts a message from f. """
        ctx = DecryptionContext(self.curve, f, self, mac_bytes)
        yield ctx
        ctx.read()
    def decrypt(self, s, mac_bytes=10):
        instream = StringIO(s)
        with self.decrypt_from(instream, mac_bytes) as f:
            return f.read()
    def sign(self, h, sig_format=SER_BINARY):
        """ Signs the message with SHA-512 hash `h' with this private key. """
        sig = self._ECDSA_sign(h)
        return serialize_number(sig, sig_format)
    def __repr__(self):
        return "<PrivKey %s>" % self.e
    def __str__(self):
        return str(self.e)
    def _ECDSA_sign(self, md):
        # Get the pseudo-random exponent from the messagedigest
        # and the private key.
        order = self.curve.order
        hmk = serialize_number(self.e, SER_BINARY, self.curve.order_len_bin)
        h = hmac.new(hmk, digestmod=hashlib.sha256)
        h.update(md)
        ctr = Crypto.Util.Counter.new(128, initial_value=0)
        cprng = Crypto.Cipher.AES.new(h.digest(),
                    Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        r = 0
        s = 0
        while s == 0:
            while r == 0:
                buf = cprng.encrypt('\0'*self.curve.order_len_bin)
                k = self.curve._buf_to_exponent(buf)
                p1 = self.curve.base * k
                r = p1.x % order
            e = deserialize_number(md, SER_BINARY)
            e = (e % order)
            s = (self.e * r) % order
            s = (s + e) % order
            e = gmpy.invert(k, order)
            s = (s * e) % order
        s = s * order
        s = s + r
        return s

# Encryption and decryption contexts
# #########################################################
class EncryptionContext(object):
    """ Holds state of encryption.  Use AffinePoint.encrypt_to """
    def __init__(self, f, p, mac_bytes=10):
        self.f = f
        self.mac_bytes = mac_bytes
        key, R = p._ECIES_encryption()
        self.h = hmac.new(key[32:], digestmod=hashlib.sha256)
        f.write(R.to_string(SER_BINARY))
        ctr = Crypto.Util.Counter.new(128, initial_value=0)
        self.cipher = Crypto.Cipher.AES.new(key[:32],
                Crypto.Cipher.AES.MODE_CTR, counter=ctr)
    def write(self, s):
        if not self.f:
            raise IOError("closed")
        ct = self.cipher.encrypt(s)
        self.f.write(ct)
        self.h.update(ct)
    def finish(self):
        if not self.f:
            raise IOError("closed")
        self.f.write(self.h.digest()[:self.mac_bytes])
        self.f = None
class DecryptionContext(object):
    """ Holds state of decryption.  Use Curve.decrypt_from """
    def __init__(self, curve, f, privkey, mac_bytes=10):
        self.f = f
        self.mac_bytes = mac_bytes
        R = curve.point_from_string(f.read(curve.pk_len_bin), SER_BINARY)
        key = R._ECIES_decryption(privkey)
        self.h = hmac.new(key[32:], digestmod=hashlib.sha256)
        ctr = Crypto.Util.Counter.new(128, initial_value=0)
        self.cipher = Crypto.Cipher.AES.new(key[:32],
                    Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        self.ahead = f.read(mac_bytes)
    def read(self, n=None):
        if not self.f:
            return ''
        if n is None:
            tmp = self.ahead + self.f.read()
        else:
            tmp = self.ahead + self.f.read(n)
        ct = tmp[:-self.mac_bytes]
        self.ahead = tmp[-self.mac_bytes:]
        self.h.update(ct)
        pt = self.cipher.decrypt(ct)
        if n is None or len(ct) < n:
            if self.h.digest()[:self.mac_bytes] != self.ahead:
                raise IntegrityError
            self.f = None
        return pt

# The main Curve objects
# #########################################################
class Curve(object):
    """ Represents a Elliptic Curve """

    @staticmethod
    def by_name(name):
        for raw_curve in RAW_CURVES.itervalues():
            if raw_curve[0] == name:
                return Curve(raw_curve)
        raise KeyError
    @staticmethod
    def by_pk_len(pk_len):
        return Curve(RAW_CURVES[pk_len])

    def __init__(self, raw_curve_params):
        """ Initialize a new curve from raw curve parameters.

            Use `Curve.by_pk_len' instead """
        r = raw_curve_parameters(*raw_curve_params)
        
        # Store domain parameters
        self.name = r.name
        self.a = deserialize_number(binascii.unhexlify(r.a), SER_BINARY)
        self.b = deserialize_number(binascii.unhexlify(r.b), SER_BINARY)
        self.m = deserialize_number(binascii.unhexlify(r.m), SER_BINARY)
        self.order = deserialize_number(binascii.unhexlify(r.order), SER_BINARY)
        self.base = AffinePoint(curve=self,
                x=deserialize_number(binascii.unhexlify(r.base_x), SER_BINARY),
                y=deserialize_number(binascii.unhexlify(r.base_y), SER_BINARY))
        self.cofactor = r.cofactor

        # Calculate some other parameters
        self.pk_len_bin = get_serialized_number_len(
                                (2 * self.m) - 1, SER_BINARY)
        self.pk_len_compact = get_serialized_number_len(
                                (2 * self.m) - 1, SER_COMPACT)
        self.sig_len_bin = get_serialized_number_len(
                                (self.order * self.order) - 1, SER_BINARY)
        self.sig_len_compact = get_serialized_number_len(
                                (self.order * self.order) - 1, SER_COMPACT)
        self.dh_len_bin = min((self.order.numdigits(2) / 2 + 7) / 8, 32)
        self.dh_len_compact = get_serialized_number_len(
                                2 ** self.dh_len_bin - 1, SER_COMPACT)
        self.elem_len_bin = get_serialized_number_len(self.m, SER_BINARY)
        self.order_len_bin = get_serialized_number_len(self.order, SER_BINARY)

    @property
    def key_bytes(self):
        """ The approximate number of bytes of information in a key. """
        return self.pk_len_bin

    def __repr__(self):
        return "<Curve %s>" % self.name

    def point_from_string(self, s, fmt=SER_BINARY):
        x = deserialize_number(s, fmt)
        yflag = x >= self.m
        if yflag:
            x = x - self.m
        assert 0 < x and x <= self.m
        return self._point_decompress(x, yflag)
    def pubkey_from_string(self, s, fmt=SER_BINARY):
        return PubKey(self.point_from_string(s, fmt))
    def _point_decompress(self, x, yflag):
        m = self.m
        h = (x * x) % m
        h = (h + self.a) % m
        h = (h * x) % m
        h = (h + self.b) % m
        y = mod_root(h, m)
        if y or not yflag:
            if bool(y.getbit(0)) == yflag:
                return AffinePoint(x=x, y=y, curve=self)
            return AffinePoint(x=x, y=m - y, curve=self)
    def hash_to_exponent(self, h):
        """ Converts a 32 byte hash to an exponent """
        ctr = Crypto.Util.Counter.new(128, initial_value=0)
        cipher = Crypto.Cipher.AES.new(h,
                    Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        buf = cipher.encrypt('\0' * self.order_len_bin)
        return self._buf_to_exponent(buf)
    def _buf_to_exponent(self, buf):
        a = deserialize_number(buf, SER_BINARY)
        a = (a % (self.order - 1)) + 1
        return a
    def passphrase_to_pubkey(self, passphrase):
        return PubKey(self.base * self.passphrase_to_privkey(passphrase).e)
    def passphrase_to_privkey(self, passphrase):
        h = _passphrase_to_hash(passphrase)
        return PrivKey(self.hash_to_exponent(h), self)
    @contextlib.contextmanager
    def decrypt_from(self, f, privkey, mac_bytes=10):
        ctx = DecryptionContext(self, f, privkey, mac_bytes)
        yield ctx
        ctx.read()
    def decrypt(self, s, privkey, mac_bytes=10):
        instream = StringIO(s)
        with self.decrypt_from(instream, privkey, mac_bytes) as f:
            return f.read()

# Helpers
# #########################################################
def _passphrase_to_hash(passphrase):
    """ Converts a passphrase to a hash. """
    return hashlib.sha256(passphrase).digest()

def encrypt(s, pk, pk_format=SER_COMPACT, mac_bytes=10):
    """ Encrypts `s' for public key `pk' """
    curve = Curve.by_pk_len(len(pk))
    p = curve.pubkey_from_string(pk, pk_format)
    return p.encrypt(s, mac_bytes)

def decrypt(s, passphrase, curve='secp160r1', mac_bytes=10):
    """ Decrypts `s' with passphrase `passphrase' """
    curve = Curve.by_name(curve)
    privkey = curve.passphrase_to_privkey(passphrase)
    return privkey.decrypt(s, mac_bytes)

def encrypt_file(in_path_or_file, out_path_or_file, pk, pk_format=SER_COMPACT,
                 mac_bytes=10, chunk_size=4096):
    """ Encrypts `in_file' to `out_file' for pubkey `pk' """
    close_in, close_out = False, False
    in_file, out_file = in_path_or_file, out_path_or_file
    try:
        if isinstance(in_path_or_file, basestring):
            in_file = open(in_path_or_file, 'rb')
            close_in = True
        if isinstance(out_path_or_file, basestring):
            out_file = open(out_path_or_file, 'wb')
            close_out = True
        _encrypt_file(in_file, out_file, pk, pk_format, mac_bytes, chunk_size)
    finally:
        if close_out: out_file.close()
        if close_in: in_file.close()

def decrypt_file(in_path_or_file, out_path_or_file, passphrase,
                 curve='secp160r1', mac_bytes=10, chunk_size=4096):
    """ Decrypts `in_file' to `out_file' with passphrase `passphrase' """
    close_in, close_out = False, False
    in_file, out_file = in_path_or_file, out_path_or_file
    try:
        if isinstance(in_path_or_file, basestring):
            in_file = open(in_path_or_file, 'rb')
            close_in = True
        if isinstance(out_path_or_file, basestring):
            out_file = open(out_path_or_file, 'wb')
            close_out = True
        _decrypt_file(in_file, out_file, passphrase, curve, mac_bytes,
                      chunk_size)
    finally:
        if close_out: out_file.close()
        if close_in: in_file.close()

def _encrypt_file(in_file, out_file, pk, pk_format=SER_COMPACT,
                 mac_bytes=10, chunk_size=4096):
    curve = Curve.by_pk_len(len(pk))
    p = curve.pubkey_from_string(pk, pk_format)
    with p.encrypt_to(out_file, mac_bytes) as encrypted_out:
        while True:
            buff = in_file.read(chunk_size)
            if not buff:
                break
            encrypted_out.write(buff)

def _decrypt_file(in_file, out_file, passphrase, curve='secp160r1',
                 mac_bytes=10, chunk_size=4096):
    curve = Curve.by_name(curve)
    privkey = curve.passphrase_to_privkey(passphrase)
    with privkey.decrypt_from(in_file, mac_bytes) as decrypted_in:
        while True:
            buff = decrypted_in.read(chunk_size)
            if not buff:
                break
            out_file.write(buff)

def verify(s, sig, pk, sig_format=SER_COMPACT, pk_format=SER_COMPACT):
    """ Verifies that `sig' is a signature of pubkey `pk' for the
        message `s'. """
    curve = Curve.by_pk_len(len(pk))
    p = curve.pubkey_from_string(pk, pk_format)
    return p.verify(hashlib.sha512(s).digest(), sig, sig_format)

def sign(s, passphrase, sig_format=SER_COMPACT, curve='secp160r1'):
    """ Signs `s' with passphrase `passphrase' """
    curve = Curve.by_name(curve)
    privkey = curve.passphrase_to_privkey(passphrase)
    return privkey.sign(hashlib.sha512(s).digest(), sig_format)

def passphrase_to_pubkey(passphrase, curve='secp160r1'):
    curve = Curve.by_name(curve)
    return curve.passphrase_to_pubkey(passphrase)
