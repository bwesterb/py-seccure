py-seccure
==========

Simple Elliptic Curve Cryptography for Python compatible with the
excellent [SECCURE](http://point-at-infinity.org/seccure/) command
line utility.

Usage
-----

### Public key from private

To get the public key from the private, you can use the original
commandline utility:

```
$ seccure-key
Assuming curve p160.
Enter private key: my private key
The public key is: 8W;>i^H0qi|J&$coR5MFpR*Vn
```

In Python:

```python
>>> import seccure
>>> str(seccure.passphrase_to_pubkey('my private key'))
'8W;>i^H0qi|J&$coR5MFpR*Vn'
```

### Encrypting a string

To encrypt for a public key, one would use the original commandline
utility as follows.

```
$ seccure-encrypt -o private.msg '8W;>i^H0qi|J&$coR5MFpR*Vn'  
Assuming MAC length of 80 bits.
Go ahead and type your message ...
This is a very very secret message!
^D
```

In Python:

```python
>>> ciphertext = seccure.encrypt('This is a very secret message\n', '8W;>i^H0qi|J&$coR5MFpR*Vn')
>>> ciphertext
'\x00\x146\x17\xe9\xc1\x1a\x7fkX\xec\xa0n,h\xb4\xd0\x98\xeaO[\xf8\xfa\x85\xaa\xb37!\xf0j\x0e\xd4\xd0\x8b\xfe}\x8a\xd2+\xf2\xceu\x07\x90K2E\x12\x1d\xf1\xd8\x8f\xc6\x91\t<w\x99\x1b9\x98'
```

There is a shorthand to encrypt a file:

```python
>>> seccure.encrypt_file('/path/to/file',  '/path/to/file.enc', '8W;>i^H0qi|J&$coR5MFpR*Vn')
'/path/to/file.enc'
```

### Decrypting
To decrypt the message with the original utility:

```
$ seccure-decrypt -i private.msg
Assuming MAC length of 80 bits.
Assuming curve p160.
Enter private key: my private key
This is a very very secret message!
Integrity check successful, message unforged!
```

In Python:

```python
>>> seccure.decrypt(ciphertext, 'my private key')
'This is a very secret message\n'
```

And to decrypt a file:

```python
>>> seccure.decrypt_file('/path/to/file.enc',  '/path/to/file', 'my private key')
'/path/to/file'
''
```

### Creating a signature
To create a signature:

```
$ seccure-sign
Assuming curve p160.
Enter private key: my private key
Go ahead and type your message ...
This message will be signed
^D
Signature: $HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq
```

In Python:

```python
>>> seccure.sign('This message will be signed\n', 'my private key')
'$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq'
```

### Verifying a signature
To verify a signature:

```
$ seccure-verify '8W;>i^H0qi|J&$coR5MFpR*Vn' '$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq'  
Go ahead and type your message ...
This message will be signed
^D
Signature successfully verified!
```

In Python:

```python
>>> seccure.verify('This message will be signed\n', '$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq', '8W;>i^H0qi|J&$coR5MFpR*Vn')
True
```

Installation
------------

### On Debian Wheezy

    $ apt-get install libgmp3-dev build-essential python-dev python-pip
    $ pip install seccure

### On Ubuntu

    $ apt-get install libgmp-dev build-essential python-dev python-pip
    $ pip install seccure

### On Mac with MacPorts

    $ port install gmp
    $ pip install seccure

Please contribute!
------------------

To help out, you could:

1.  Test and report any bugs or other difficulties.
2.  Implement missing features, such as `seccure-dh`, `seccure-veridec`
            and `seccure-signcrypt`.
3.  Package py-seccure (or the original SECCURE itself) for your platform.
4.  Write more unit tests.


[![Build Status](https://travis-ci.org/bwesterb/py-seccure.png)](
   https://travis-ci.org/py-seccure/pol)
      
<!-- vim: set shiftwidth=4:tabstop=4:expandtab: -->
