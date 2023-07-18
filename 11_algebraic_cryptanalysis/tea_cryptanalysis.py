#!/usr/bin/env python3
"""Algebraic Cryptanalysis of TEA."""

import z3  # type: ignore
import tea
import hashlib



DEBUG = False
# This week, you break TEA, the Tiny Encryption Algorithm, reduced to
# 2 or 4 rounds (1 or 2 cycles).

# Your first assignment is to write a function that translates TEA the
# cycle function of TEA Z3 formulas and uses Z3 to check if 2 rounds
# (1 cycle) TEA encryption is valid. The function gets a plaintext, a
# ciphertext, and a key as input and returns sat if ciphertext is a
# valid encryption of plaintext with key and unsat if not. Remember
# that here TEA is reduced to 2 rounds (1 cycle)! You must translate
# TEA into Z3 formula. Using tea.encipher for encrpytion of one cycle
# and using Z3 to compare the result to the expected result is not
# acceptable!
#
# Here are some hints:
#
# You will want to split the plaintext into a right and a left half
# and assign Z3 variables to the halves. This can be achieved by code
# like
#
# left_input = z3.BitVec('left_input', 32)
# right_input = z3.BitVec('right_input', 32)
# s.add(left_input == plaintext >> 32)
# s.add(right_input == plaintext & 0xFFFFFFFF)
#
# In a similar way, the result of the cycle should match the ciphertext.
#
# Most likely, your code will not be correct on the first try. In
# order to debug your program, assign Z3 variables to the intermediate
# values of the calculation, and remove constraints until you get a
# satisfiable model. Once you got a satisfiable model,
#
# print(s.model())
#
# gives you all variable assignments of the model. Use the Python
# implementation tea.py to compare the (intermediate) values in your
# model to the expected values. For example, when I designed this
# assignment, I modeled the "lower path" of the first round as
#
# s.add(tmp == (right_input >> 5 + k_1))
#
# Z3 could not find a model for this. After removing the constraint
# that the result must match the ciphertext, Z3 generated the model,
# but in this model, tmp and the ciphertext did not match the expected
# value. After some research, I found out that the correct cacluation
# is
#
# s.add(tmp == (z3.LShR(right_input, 5) + k_1))
#
# with this, the model generated the correct values.

# 4 Points
def check_one_cycle(key, plaintext, ciphertext):
    s = z3.Solver()

    # Define key parts
    k0 = z3.BitVecVal((key >> 96) & 0xFFFFFFFF, 32)
    k1 = z3.BitVecVal((key >> 64) & 0xFFFFFFFF, 32)
    k2 = z3.BitVecVal((key >> 32) & 0xFFFFFFFF, 32)
    k3 = z3.BitVecVal(key & 0xFFFFFFFF, 32)

    # Define plaintext parts
    v0 = z3.BitVecVal(plaintext >> 32, 32)
    v1 = z3.BitVecVal(plaintext & 0xFFFFFFFF, 32)

    # TEA constants
    delta = 0x9E3779B9
    sum = 0

    # Define cipher text parts
    c0 = z3.BitVec('c0', 32)
    c1 = z3.BitVec('c1', 32)
    s.add(c0 == ciphertext >> 32)
    s.add(c1 == ciphertext & 0xFFFFFFFF)

    # First cycle (two rounds) of TEA
    # Instead of adding every step, add whole calculation to Solver
    sum += delta
    v0 +=((v1 << 4) + k0) ^ (v1 + sum) ^ (z3.LShR(v1, 5) + k1)
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ (z3.LShR(v0, 5) + k3)


    if DEBUG:
        print(f'v0 = {z3.simplify(v0)}')
        print(f'v1 = {z3.simplify(v1)}')
        s.check()
        try:
            print(s.model())
        except:
            pass

    # Constrain
    s.add(c0 == v0)
    s.add(c1 == v1)


    return s.check() == z3.sat


# Now you shall compute a key for a given plaintext-ciphertext pair
# encrypted with 1 cycle (2 rounds) of TEA.  Beware that for each key,
# there are three equivalent keys. Also, since we operate on one
# plaintext-icphertext pair only, there will be multiple keys for this
# pair. Therefore you can not expect exactly the same key that you
# used for generating the ciphertext, but the key you compute will
# behave identical to the original key.
#
# If there is no key generating the ciphertext from the plaintext, the
# function shall return None.

# 2 Points
def retrieve_key_one_cycle(plaintext, ciphertext):
    # Create a Solver instance
    s = z3.Solver()

    # Define plaintext parts
    v0 = z3.BitVecVal(plaintext >> 32, 32)
    v1 = z3.BitVecVal(plaintext & 0xFFFFFFFF, 32)

    # TEA constants
    delta = 0x9E3779B9
    sum = 0

    # Define cipher text parts
    c0 = z3.BitVec('c0', 32)
    c1 = z3.BitVec('c1', 32)
    s.add(c0 == ciphertext >> 32)
    s.add(c1 == ciphertext & 0xFFFFFFFF)

    # Define key parts as variables
    k0 = z3.BitVec('k0', 32)
    k1 = z3.BitVec('k1', 32)
    k2 = z3.BitVec('k2', 32)
    k3 = z3.BitVec('k3', 32)

    sum += delta
    v0 +=((v1 << 4) + k0) ^ (v1 + sum) ^ (z3.LShR(v1, 5) + k1)
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ (z3.LShR(v0, 5) + k3)

    s.add(v0 == c0)
    s.add(v1 == c1)

    if s.check() == z3.sat:
        m = s.model()
        return (m[k0].as_long() << 96) + (m[k1].as_long() << 64) + (m[k2].as_long() << 32) + m[k3].as_long()
    else:
        return None


# The following function takes a list of plaintext-ciphertext
# pairs. All messages have been encrypted with 4 rounds (2 cycles) of
# TEA and the same key.
#
# The function shall return the key. Remember that now we use 4 rounds (2
# cycles) of TEA!

# 2 Points
def retrieve_key(plain_cipher_pairs):
    # Create a Solver instance
    s = z3.Solver()

    # Define key parts as variables
    k0 = z3.BitVec('k0', 32)
    k1 = z3.BitVec('k1', 32)
    k2 = z3.BitVec('k2', 32)
    k3 = z3.BitVec('k3', 32)

    # Define delta
    delta = 0x9E3779B9
    v0 = [0] * len(plain_cipher_pairs)
    v1 = [0] * len(plain_cipher_pairs)
    c0 = [0] * len(plain_cipher_pairs)
    c1 = [0] * len(plain_cipher_pairs)

    # Loop over plain-cipher pairs
    for num,pair in enumerate(plain_cipher_pairs):
        plaintext, ciphertext = pair


        # Define plaintext parts
        v0[num] = z3.BitVecVal(plaintext >> 32, 32)
        v1[num] = z3.BitVecVal(plaintext & 0xFFFFFFFF, 32)

        sum = 0

        # Define cipher text parts
        c0[num] = z3.BitVec(f'c0_{num}', 32)
        c1[num] = z3.BitVec(f'c1_{num}', 32)
        s.add(c0[num] == ciphertext >> 32)
        s.add(c1[num] == ciphertext & 0xFFFFFFFF)

        # Generate tea as long calculation for Solver
        for _ in range(2):
            sum += delta
            v0[num] +=((v1[num] << 4) + k0) ^ (v1[num] + sum) ^ (z3.LShR(v1[num], 5) + k1)
            v1[num] += ((v0[num] << 4) + k2) ^ (v0[num] + sum) ^ (z3.LShR(v0[num], 5) + k3)
        
        # Add constraint
        s.add(v0[num] == c0[num])
        s.add(v1[num] == c1[num])


    if s.check() == z3.sat:
        m = s.model()
        return (m[k0].as_long() << 96) + (m[k1].as_long() << 64) + (m[k2].as_long() << 32) + m[k3].as_long()
    else:
        return None

def test_check_one_cycle():
    key = 0x2BD6459F82C5B300952C49104881FF48
    plaintext = 0xEA024714AD5C4D84
    ciphertext = 0xAC3A96A20CA0BE1A
    assert(check_one_cycle(key=key,
                           plaintext=plaintext,
                           ciphertext=ciphertext))
    assert(not check_one_cycle(key=key-1,
                               plaintext=plaintext,
                               ciphertext=ciphertext))


def test_retrieve_key_one_cycle():
    plaintext = 0xEA024714AD5C4D84
    ciphertext = 0xAC3A96A20CA0BE1A
    key_calculated = retrieve_key_one_cycle(plaintext=plaintext,
                                            ciphertext=ciphertext)
    assert(tea.encipher(plaintext=plaintext, key=key_calculated, rounds=2)
           == ciphertext)

def test_retrieve_key():
    # You have received the following message:
    secret_message = 0xE93160683E397DFC
    # You know that it has been encrypted with TEA reduced to 4 rounds.
    # You also know that the folowing plaintext-ciphertext pairs
    # have been encrypted with the same key:
    plain_cipher_pairs = [
        [0x9BE6A8EA7F8EC4C2, 0x0B4303CF0C025055],
        [0xF362B708C15C71BF, 0x8475569ED7571332],
        [0x2D1AA9EA64D8F363, 0x4256791B652C1274],
        [0x60383FA01FE2A062, 0x8B5B337627887A36],
        [0x7EF85D5BD5A25C02, 0x4437870336BF9B28],
        [0x81B584EBFA6B594E, 0x1E5540D8DA17C86E],
        [0x2E8D0BB3933D9D81, 0x5D0BC0262D836B1E],
        [0xD6CF23C00FB87E07, 0x1491A5CCAE001103],
        [0xB37EE754AA032032, 0xC8277D6C387D44F3],
        [0xC7E6C9711484CF3F, 0xAAE1E08D18984E1D]
    ]
    # Decrypt the secret message!
    # Note: There is no "meaning" in the message; it is just a sequence
    # of bytes.
    key_calculated = retrieve_key(plain_cipher_pairs=plain_cipher_pairs)
    decrypted = tea.decipher(key=key_calculated,
                             ciphertext=secret_message,
                             rounds=4)
    assert(hashlib.sha256(hex(decrypted).encode('ascii')).hexdigest() ==
           '0c0676b9ae9872fd4b54ffacc6f12d7247af09a4e8ef712d7e7876670aaa2b9f')


if __name__ == '__main__':
    test_check_one_cycle()
    test_retrieve_key_one_cycle()
    test_retrieve_key()
    print("Fin")
