#!/usr/bin/env python3

from typing import List

DEBUG = False
#DEBUG = True


# We are going to use the following keys and plaintexts.
# Note that your program will be tested on different keys and plaintext for grading!
plaintext0: int = 0x02468ACEECA86420
plaintext1: int = 0x12468ACEECA86420
key0: int       = 0x08C73A08514436F2E150A865EB75443F904396E66638E182170C1CA1CB6C1062
key1: int       = 0x18C73A08514436F2E150A865EB75443F904396E66638E182170C1CA1CB6C1062

# 	GOST R 34.12-2015 S-Box
sboxes: List[List[int]] = [
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2]
]

# This week's assignment is to meausure the avalanche effect in GOST,
# both for changes in the plaintext and in the key. As you can see,
# the two plaintexts and the two keys differ in 1 bit, respectively.
#
# In order to measure the avalanche effect for differences in the
# plaintext, you encrypt both plaintext0 and plaintext1 with
# key0. After each round of encryption, you measure how many bits of
# the intermediate ciphertexts differ.
#
# In order to measure the avalanche effect for difference in the key,
# you encrypt plaintext0 both with key0 and with key1. Again, you
# measure how many bits of the intermediate ciphertexts differ.
#
# In order to complete this assignment, you have to write your own
# implementation of GOST. You can use function testGost() to check
# if your implementation is correct. Even if your implementation does
# not encrypt to the same ciphertext as in the example, please carry
# on and measure the avalanche effects for your implementation.


def gost(text: int, key: int, encrypt: bool = True, rounds:int = 32) -> int:
##################
# YOUR CODE HERE #
##################
    # get left and right part of the 64 Bit Block
    left = text >> 32
    right = text & 0xffffffff

    # get 32bit subkeys from key
    subkeys = key_to_subkey(key)

    # Create key schedule
    key_schedule = {key: (key % 8) if key < 24 else (7 - key % 8) for key in range(32)}

    # create cypher
    for rnd in range(rounds):
        # calculate right + Subkey
        subright = right + subkeys[key_schedule[rnd]]
        # use s-Box
        boxsubright = s_box(subright)
        # rotate left 11 bits
        rotboxsubright = rotate_left(boxsubright, 11)
        # xor left and cypher of right
        new_right = left ^ rotboxsubright
        # flip left and right
        left = right
        # cypher as new right value
        right = new_right


    # return ciphertext
    return (left << 32) & right


# You will probably need a number of utility functions to implement
# gostEncrypt.

def rotate_left(value:int, rotations: int) -> int:
    bitsize = 32
    return ((value << rotations) & ((1 << bitsize) - 1)) |(value >> (bitsize - rotations))


def s_box(value:int)-> int:
    # make chunks from given value
    chunks = key_to_chunks(value)
    boxed_value = 0
    # use 4 to 16 decoder on the chunks
    for i in range(8):
        boxed_value |= sboxes[i][chunks[i]] << (i * 4)
    return boxed_value

def key_to_chunks(key: int)-> int:
    chunks = []
    for i in range(8):
        # take last 4bit and shift 4bit right
        chunks.append((key >> (i*4)) & 0xf)
    return chunks


def key_to_subkey(key: int) -> [int]:
##################
# YOUR CODE HERE #
##################
    # 256 bit key to subkeys of 32bit length
    subkeys = []
    for i in range(8):
        # take last 32bit and shift 32bit right
        subkeys.append((key >> (i*32)) & 0xffffffff)
    # reverse list to get back left to right order of the key
    subkeys.reverse()
    return subkeys


def bitDifference(a: int, b: int) -> int:
    """Return number of bits different between a and b."""
    pass
    #pass
##################
# YOUR CODE HERE #
##################


def testGost() -> None:
    ciphertext = gost(text=plaintext0, key=key0, encrypt=True)
    assert(ciphertext == 0xB3196C3940160B06)
    deciphered = gost(text=ciphertext,
                      key=key0, encrypt=False)
    assert(plaintext0 == deciphered)

    # Since it is notoriously hard to get bit ordering in crypto
    # algorithms right, here are the temporary values for the first
    # four rounds of encryption. You can also find a complete
    # example in appendix A.4 of RFC 89891, available at
    # https://tools.ietf.org/html/rfc8891
    #
    # Round:             1
    # Left:              0x02468ACE
    # Right:             0xECA86420
    # Round Key:         0x08C73A08
    # R + Round Key:     0xF56F9E28
    # S-Box Application: 0x29CC062E
    # Shift Left:        0x6031714E
    # Round:             2
    # Left:              0xECA86420
    # Right:             0x6277FB80
    # Round Key:         0x514436F2
    # R + Round Key:     0xB3BC3272
    # S-Box Application: 0x651B15C6
    # Shift Left:        0xD8AE3328
    # Round:             3
    # Left:              0x6277FB80
    # Right:             0x34065708
    # Round Key:         0xE150A865
    # R + Round Key:     0x1556FF6D
    # S-Box Application: 0x7926B053
    # Shift Left:        0x35829BC9
    # Round:             4
    # Left:              0x34065708
    # Right:             0x57F56049
    # Round Key:         0xEB75443F
    # R + Round Key:     0x436AA488
    # S-Box Application: 0x05C3A21E
    # Shift Left:        0x1D10F02E


def plaintextAvalanche() -> None:
    print('\nAvalanche effect for changes in plaintext.')
    print('Original difference: %d' %
          bitDifference(plaintext0, plaintext1))
    for rounds in range(32+1):
        c0 = gost(text=plaintext0, key=key0, rounds=rounds, encrypt=True)
        c1 = gost(text=plaintext1, key=key0, rounds=rounds, encrypt=True)
        print('Round: %02d Delta: %d' % (rounds, bitDifference(c0, c1)))


def keyAvalanche() -> None:
    print('\nAvalanche effect for changes in key.')
    print('Original difference: %d' %
          bitDifference(plaintext0, plaintext0))
    for rounds in range(32+1):
        c0 = gost(text=plaintext0, key=key0, rounds=rounds, encrypt=True)
        c1 = gost(text=plaintext0, key=key1, rounds=rounds, encrypt=True)
        print('Round: %02d Delta: %d' % (rounds, bitDifference(c0, c1)))


if __name__ == '__main__':
    testGost()
    plaintextAvalanche()
    keyAvalanche()
