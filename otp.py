#!/usr/bin/env python
"""This program encrypts and decrypts Unicode strings using OTP.

The main challenge in this assignment is not the encryption, but the
encoding: The plaintext is a unicode string in the usual UTF-8
encoding. The ciphertext and the key are bytes. Therefore you have to
make sure that you convert from UTF-8 to bytes before encrypion and
from bytes to UTF-8 after decryption.

You get 2 points for your encryption function and 2 points for your
decryption function.
"""

from typing import Tuple
import Crypto.Random as Rand


#################
# Global Settings
################
encoding = 'utf-8'


def byte_xor(b1: bytes, b2: bytes) -> bytes:
    ####################
    # Helper Class
    # ByteString to Bytearray to XOR-Bytes
    ####################
    output = bytearray(len(b1))
    # Fix edge case shorter Key
    if len(b2) < len(b1):
        b2 = b2 + b2[:(len(b1) - len(b2))]

    for i in range(len(b1)):
        output[i] = b1[i] ^ b2[i % len(b1)]
    return bytes(output)


def encrypt(plaintext: str) -> Tuple[bytes, bytes]:
    ##################
    # Plaintext to bytes
    # Create Key of same length
    # Create XOR
    ##################
    bytetext = bytes(plaintext, encoding)
    key = b''.join([Rand.get_random_bytes(len(bytetext))])
    ciphertext = byte_xor(bytetext, key)
    # List back to bytestring
    return (ciphertext, key)


def decrypt(ciphertext: bytes, key: bytes) -> str:
    ##################
    # Create XOR of Cipher and Key
    # Encode to Plaintext
    ##################
    bytetext = byte_xor(ciphertext, key)
    plaintext = str(bytetext, encoding)
    return plaintext


def test_encryption_decryption(text: str) -> None:
    (ciphertext, key) = encrypt(plaintext=text)
    assert (text == decrypt(ciphertext=ciphertext, key=key))
    print(f'Successfully matched "{text}" to "{ciphertext}"!')


if __name__ == '__main__':
    test_encryption_decryption('Hello, world!')
    test_encryption_decryption('مرحبا بالعالم!')
    test_encryption_decryption('สวัสดีชาวโลก!')
    ciphertext = b'\x1d\x00"\x17\xbb\xf7\xb0H\xf8\xc7w\x1fn\\\xca'
    key = b'\xfe\x81\xb1\xf49dS\xc9S$\xf6\xbe\x8d\xdde'
    assert (decrypt(ciphertext=ciphertext, key=key) == 'こんにちは')
