""" Elliptic Curve cryptography compatible with SECCURE:
        http://point-at-infinity.org/seccure/ """

import sys
import hmac
import hashlib
import logging
import binascii
import contextlib
import collections

# six
import six

# TODO replace with six.byte2int, when it is released
if six.PY3:
    from io import BytesIO as BytesIO
    def byte2int(b): return b
    def stringlike(x): return isinstance(x, (str, bytes))
else:
    from cStringIO import StringIO as BytesIO
    def byte2int(b): return ord(b)
    def stringlike(x): return isinstance(x, basestring)

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

COMPACT_DIGITS = (b'!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                          b'[]^_abcdefghijklmnopqrstuvwxyz{|}~')
R_COMPACT_DIGITS = {}  # TODO is a tuple/list faster?
for i, c in enumerate(COMPACT_DIGITS):
    R_COMPACT_DIGITS[c] = i

def serialize_number(x, fmt=SER_BINARY, outlen=None):
    """ Serializes `x' to a string of length `outlen' in format `fmt' """
    ret = b''
    if fmt == SER_BINARY:
        while x:
            x, r = divmod(x, 256)
            ret = six.int2byte(int(r)) + ret
        if outlen is not None:
            assert len(ret) <= outlen
            ret = ret.rjust(outlen, b'\0')
        return ret
    assert fmt == SER_COMPACT
    while x:
        x, r = divmod(x, len(COMPACT_DIGITS))
        ret = COMPACT_DIGITS[r:r+1] + ret
    if outlen is not None:
        assert len(ret) <= outlen
        ret = ret.rjust(outlen, COMPACT_DIGITS[0:1])
    return ret

def deserialize_number(s, fmt=SER_BINARY):
    """ Deserializes a number from a string `s' in format `fmt' """
    ret = gmpy.mpz(0)
    if fmt == SER_BINARY:
        if isinstance(s, six.text_type):
            raise ValueError("Encode `s` to a bytestring yourself to"+
                         " prevent problems with different default encodings")
        for c in s:
            ret *= 256
            ret += byte2int(c)
        return ret
    assert fmt == SER_COMPACT
    if isinstance(s, six.text_type):
        s = s.encode('ascii')
    for c in s:
        ret *= len(COMPACT_DIGITS)
        ret += R_COMPACT_DIGITS[c]
    return ret

def get_serialized_number_len(x, fmt=SER_BINARY):
    if fmt == SER_BINARY:
        return (x.numdigits(2) + 7) // 8
    assert fmt == SER_COMPACT
    res = 0
    while x != 0:
        x = x // len(COMPACT_DIGITS)
        res += 1
    return res

# Some modular arithmetic
# #########################################################

def mod_issquare(a, p):
    """ Returns whether `a' is a square modulo p """
    if not a:
        return True
    p1 = p // 2
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
        h = gmpy.mpz(0)
        h = h.setbit(r - m - 1)
        t = pow(y, h, p)
        y = (t * t) % p
        r = m
        x = (x * t) % p
        b = (b * y) % p
    return x

# Raw curve parameters
# #########################################################

raw_curve_parameters = collections.namedtuple('raw_curve_parameters',
            ('name', 'a', 'b', 'm', 'base_x', 'base_y', 'order', 'cofactor',
                        'pk_len_compact'))
RAW_CURVES = (
       ("secp112r1",
        b"db7c2abf62e35e668076bead2088",
        b"659ef8ba043916eede8911702b22",
        b"db7c2abf62e35e668076bead208b",
        b"09487239995a5ee76b55f9c2f098",
        b"a89ce5af8724c0a23e0e0ff77500",
        b"db7c2abf62e35e7628dfac6561c5", 1, 18),
       ("secp128r1",
        b"fffffffdfffffffffffffffffffffffc",
        b"e87579c11079f43dd824993c2cee5ed3",
        b"fffffffdffffffffffffffffffffffff",
        b"161ff7528b899b2d0c28607ca52c5b86",
        b"cf5ac8395bafeb13c02da292dded7a83",
        b"fffffffe0000000075a30d1b9038a115", 1, 20),
       ("secp160r1",
        b"ffffffffffffffffffffffffffffffff7ffffffc",
        b"1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
        b"ffffffffffffffffffffffffffffffff7fffffff",
        b"4a96b5688ef573284664698968c38bb913cbfc82",
        b"23a628553168947d59dcc912042351377ac5fb32",
        b"0100000000000000000001f4c8f927aed3ca752257", 1, 25),
       ("secp192r1/nistp192",
        b"fffffffffffffffffffffffffffffffefffffffffffffffc",
        b"64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
        b"fffffffffffffffffffffffffffffffeffffffffffffffff",
        b"188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
        b"07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
        b"ffffffffffffffffffffffff99def836146bc9b1b4d22831", 1, 30),
       ("secp224r1/nistp224",
        b"fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
        b"b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        b"ffffffffffffffffffffffffffffffff000000000000000000000001",
        b"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        b"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
        b"ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 1, 35),
       ("secp256r1/nistp256",
        b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            1, 40),
       ("secp384r1/nistp384",
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"+
            b"ffffffff0000000000000000fffffffc",
        b"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"+
            b"c656398d8a2ed19d2a85c8edd3ec2aef",
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"+
            b"ffffffff0000000000000000ffffffff",
        b"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"+
            b"5502f25dbf55296c3a545e3872760ab7",
        b"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"+
            b"0a60b1ce1d7e819d7a431d7c90ea0e5f",
        b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"+
            b"581a0db248b0a77aecec196accc52973", 1, 60),
       ("secp521r1/nistp521",
        b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            b"fffffffc",
        b"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"+
            b"09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd4"+
            b"6b503f00",
        b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            b"ffffffff",
        b"00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"+
            b"3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31"+
            b"c2e5bd66",
        b"011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"+
            b"662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be9476"+
            b"9fd16650",
        b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"+
            b"fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e"+
            b"91386409", 1, 81),
       ("brainpoolp160r1",
        b"340e7be2a280eb74e2be61bada745d97e8f7c300",
        b"1e589a8595423412134faa2dbdec95c8d8675e58",
        b"e95e4a5f737059dc60dfc7ad95b3d8139515620f",
        b"bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
        b"1667cb477a1a8ec338f94741669c976316da6321",
        b"e95e4a5f737059dc60df5991d45029409e60fc09", 1, 25),
       ("brainpoolp192r1",
        b"6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
        b"469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
        b"c302f41d932a36cda7a3463093d18db78fce476de1a86297",
        b"c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
        b"14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
        b"c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 1, 30 ),
       ("brainpoolp224r1",
        b"68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
        b"2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
        b"d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
        b"0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
        b"58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
        b"d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
            1, 35 ),
       ("brainpoolp256r1",
        b"7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        b"26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        b"a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        b"8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
        b"547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
        b"a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
            1, 40 ),
       ("brainpoolp320r1",
        b"3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f49"+
            b"2f375a97d860eb4",
        b"520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816"+
            b"f5eb4ac8fb1f1a6",
        b"d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28f"+
            b"cd412b1f1b32e27",
        b"43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c71"+
            b"0af8d0d39e20611",
        b"14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d"+
            b"35245d1692e8ee1",
        b"d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98"+
            b"691555b44c59311", 1, 50),
       ("brainpoolp384r1",
        b"7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8"+
            b"aa5814a503ad4eb04a8c7dd22ce2826",
        b"04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57"+
            b"cb4390295dbc9943ab78696fa504c11",
        b"8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123a"+
            b"cd3a729901d1a71874700133107ec53",
        b"1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e"+
            b"826e03436d646aaef87b2e247d4af1e",
        b"8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280"+
            b"e4646217791811142820341263c5315",
        b"8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7c"+
            b"f3ab6af6b7fc3103b883202e9046565", 1, 60),
       ("brainpoolp512r1",
        b"7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2"+
            b"ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94"+
            b"ca",
        b"3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72"+
            b"bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f7"+
            b"23",
        b"aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717"+
            b"d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48"+
            b"f3",
        b"81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098ef"+
            b"f3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8"+
            b"22",
        b"7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b"+
            b"2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad808"+
            b"92",
        b"aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308705"+
            b"53e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca900"+
            b"69",
        1, 79),
    )
curves = [r[0] for r in RAW_CURVES]

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
    __bool__ = __nonzero__

    def __repr__(self):
        return "<AffinePoint (%s, %s) of %s>" % (
                            self.x, self.y, self.curve.name)
    def __eq__(self, other):
        if not isinstance(other, AffinePoint):
            return False
        return self.x == other.x and self.y == other.y
    def __ne__(self, other):
        return not (self == other)
    def __str__(self):
        return self.to_string(SER_COMPACT)
    def to_bytes(self, fmt=SER_BINARY):
        outlen = (self.curve.pk_len_compact if fmt == SER_COMPACT
                        else self.curve.pk_len_bin)
        if self._point_compress():
            return serialize_number(self.x + self.curve.m, fmt, outlen)
        return serialize_number(self.x, fmt, outlen)
    def to_string(self, fmt=SER_BINARY):
        return self.to_bytes(fmt).decode()
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
        if isinstance(s, six.text_type):
            raise ValueError("Encode `s` to a bytestring yourself to"+
                         " prevent problems with different default encodings")
        out = BytesIO()
        with self.encrypt_to(out, mac_bytes) as f:
            f.write(s)
        return out.getvalue()

    def to_bytes(self, fmt=SER_BINARY):
        return self.p.to_bytes(fmt)
    def to_string(self, fmt=SER_BINARY):
        return self.p.to_string(fmt)
    def __str__(self):
        return self.to_string(SER_COMPACT)
    def __repr__(self):
        return "<PubKey %s>" % self

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
        if isinstance(s, six.text_type):
            raise ValueError("s should be bytes")
        instream = BytesIO(s)
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
                buf = cprng.encrypt(b'\0'*self.curve.order_len_bin)
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
        f.write(R.to_bytes(SER_BINARY))
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
    def by_name_substring(substring):
        substring = substring.lower()
        candidates = []
        for raw_curve in RAW_CURVES:
            if substring in raw_curve[0]:
                candidates.append(raw_curve)
        if len(candidates) != 1:
            raise KeyError
        return Curve(candidates[0])

    @staticmethod
    def by_name(name):
        for raw_curve in RAW_CURVES:
            if raw_curve[0] == name:
                return Curve(raw_curve)
        raise KeyError
    @staticmethod
    def by_pk_len(pk_len):
        for raw_curve in RAW_CURVES:
            if raw_curve[8] == pk_len:
                return Curve(raw_curve)
        raise KeyError

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
        assert self.pk_len_compact == r.pk_len_compact
        self.sig_len_bin = get_serialized_number_len(
                                (self.order * self.order) - 1, SER_BINARY)
        self.sig_len_compact = get_serialized_number_len(
                                (self.order * self.order) - 1, SER_COMPACT)
        self.dh_len_bin = min((self.order.numdigits(2) // 2 + 7) // 8, 32)
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
        buf = cipher.encrypt(b'\0' * self.order_len_bin)
        return self._buf_to_exponent(buf)
    def _buf_to_exponent(self, buf):
        a = deserialize_number(buf, SER_BINARY)
        a = (a % (self.order - 1)) + 1
        return a
    def passphrase_to_pubkey(self, passphrase):
        return PubKey(self.base * self.passphrase_to_privkey(passphrase).e)
    def passphrase_to_privkey(self, passphrase):
        if isinstance(passphrase, six.text_type):
            raise ValueError("Encode `passphrase` to a bytestring yourself to"+
                         " prevent problems with different default encodings")
        h = _passphrase_to_hash(passphrase)
        return PrivKey(self.hash_to_exponent(h), self)
    @contextlib.contextmanager
    def decrypt_from(self, f, privkey, mac_bytes=10):
        ctx = DecryptionContext(self, f, privkey, mac_bytes)
        yield ctx
        ctx.read()
    def decrypt(self, s, privkey, mac_bytes=10):
        instream = BytesIO(s)
        with self.decrypt_from(instream, privkey, mac_bytes) as f:
            return f.read()

# Helpers
# #########################################################
def _passphrase_to_hash(passphrase):
    """ Converts a passphrase to a hash. """
    return hashlib.sha256(passphrase).digest()

def encrypt(s, pk, pk_format=SER_COMPACT, mac_bytes=10, curve=None):
    """ Encrypts `s' for public key `pk' """
    curve = (Curve.by_pk_len(len(pk)) if curve is None
                else Curve.by_name(curve))
    p = curve.pubkey_from_string(pk, pk_format)
    return p.encrypt(s, mac_bytes)

def decrypt(s, passphrase, curve='secp160r1', mac_bytes=10):
    """ Decrypts `s' with passphrase `passphrase' """
    curve = Curve.by_name(curve)
    privkey = curve.passphrase_to_privkey(passphrase)
    return privkey.decrypt(s, mac_bytes)

def encrypt_file(in_path_or_file, out_path_or_file, pk, pk_format=SER_COMPACT,
                 mac_bytes=10, chunk_size=4096, curve=None):
    """ Encrypts `in_file' to `out_file' for pubkey `pk' """
    close_in, close_out = False, False
    in_file, out_file = in_path_or_file, out_path_or_file
    try:
        if stringlike(in_path_or_file):
            in_file = open(in_path_or_file, 'rb')
            close_in = True
        if stringlike(out_path_or_file):
            out_file = open(out_path_or_file, 'wb')
            close_out = True
        _encrypt_file(in_file, out_file, pk, pk_format, mac_bytes, chunk_size,
                                curve)
    finally:
        if close_out: out_file.close()
        if close_in: in_file.close()

def decrypt_file(in_path_or_file, out_path_or_file, passphrase,
                 curve='secp160r1', mac_bytes=10, chunk_size=4096):
    """ Decrypts `in_file' to `out_file' with passphrase `passphrase' """
    close_in, close_out = False, False
    in_file, out_file = in_path_or_file, out_path_or_file
    try:
        if stringlike(in_path_or_file):
            in_file = open(in_path_or_file, 'rb')
            close_in = True
        if stringlike(out_path_or_file):
            out_file = open(out_path_or_file, 'wb')
            close_out = True
        _decrypt_file(in_file, out_file, passphrase, curve, mac_bytes,
                      chunk_size)
    finally:
        if close_out: out_file.close()
        if close_in: in_file.close()

def _encrypt_file(in_file, out_file, pk, pk_format=SER_COMPACT,
                 mac_bytes=10, chunk_size=4096, curve=None):
    curve = (Curve.by_pk_len(len(pk)) if curve is None
                else Curve.by_name(curve))
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

def verify(s, sig, pk, sig_format=SER_COMPACT, pk_format=SER_COMPACT,
                        curve=None):
    """ Verifies that `sig' is a signature of pubkey `pk' for the
        message `s'. """
    if isinstance(s, six.text_type):
        raise ValueError("Encode `s` to a bytestring yourself to"+
                     " prevent problems with different default encodings")
    curve = (Curve.by_pk_len(len(pk)) if curve is None
                    else Curve.by_name(curve))
    p = curve.pubkey_from_string(pk, pk_format)
    return p.verify(hashlib.sha512(s).digest(), sig, sig_format)

def sign(s, passphrase, sig_format=SER_COMPACT, curve='secp160r1'):
    """ Signs `s' with passphrase `passphrase' """
    if isinstance(s, six.text_type):
        raise ValueError("Encode `s` to a bytestring yourself to"+
                     " prevent problems with different default encodings")
    curve = Curve.by_name(curve)
    privkey = curve.passphrase_to_privkey(passphrase)
    return privkey.sign(hashlib.sha512(s).digest(), sig_format)

def passphrase_to_pubkey(passphrase, curve='secp160r1'):
    curve = Curve.by_name(curve)
    return curve.passphrase_to_pubkey(passphrase)
