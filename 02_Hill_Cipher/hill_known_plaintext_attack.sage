#!/usr/bin/env sage
"""Here you implement a known plaintext attack on a 2x2 Hill cipher."""

R = IntegerModRing(26)
key_dim = 2
KeyMatrix = MatrixSpace(R, key_dim, key_dim)

# Here is some test data. Each entry in the list has the following format:
# Key, plaintexts, ciphertexts
#
# In your previous assignment you developed a linear equation system
# for 2x2 Hill cipher with 2 plaintext-ciphertext pairs. One would
# assume that such an equation system allows to compute the key.
# However, since all computations are modulo 26, there may be multiple
# solutions with just 2 pairs (but most of them could not be used as a
# key, because they do not have an inverse matrix). In order to
# guarantee unique solutions for each example, 6 plaintext-ciphertext
# pairs are given.
test_data = [
    [[1, 12, 4, 5],
     [(13, 10), (1, 11), (21, 12), (1, 15), (12, 3), (25, 17)],
     [(3, 24), (3, 7), (9, 14), (25, 1), (22, 11), (21, 3)]],
    [[14, 25, 21, 2],
     [(13, 5), (13, 24), (13, 20), (9, 1), (18, 10), (24, 9)],
     [(21, 23), (2, 9), (6, 1), (21, 9), (8, 8), (15, 2)]],
    [[24, 7, 7, 1],
     [(7, 6), (3, 7), (12, 7), (7, 20), (10, 2), (12, 12)],
     [(2, 3), (17, 2), (25, 13), (22, 17), (20, 20), (8, 18)]],
    [[13, 7, 5, 18],
     [(7, 2), (14, 2), (22, 7), (19, 23), (11, 19), (12, 17)],
     [(1, 19), (14, 2), (23, 2), (18, 15), (16, 7), (15, 2)]],
    [[19, 0, 16, 15],
     [(13, 2), (19, 9), (8, 13), (4, 13), (6, 20), (0, 3)],
     [(13, 4), (23, 23), (22, 11), (24, 25), (10, 6), (0, 19)]],
    [[14, 21, 1, 16],
     [(19, 10), (2, 1), (16, 19), (1, 18), (4, 12), (16, 6)],
     [(8, 23), (23, 18), (25, 8), (2, 3), (22, 14), (12, 8)]],
    [[3, 15, 15, 0],
     [(0, 17), (25, 12), (4, 16), (18, 3), (24, 19), (12, 13)],
     [(21, 0), (21, 11), (18, 8), (21, 10), (19, 22), (23, 24)]],
    [[23, 7, 22, 21],
     [(18, 0), (11, 18), (8, 9), (9, 11), (1, 19), (4, 6)],
     [(24, 6), (15, 22), (13, 1), (24, 13), (0, 5), (4, 6)]],
    [[19, 15, 0, 1],
     [(7, 4), (8, 9), (8, 11), (24, 15), (3, 16), (5, 7)],
     [(11, 4), (1, 9), (5, 11), (5, 15), (11, 16), (18, 7)]],
    [[8, 11, 23, 16],
     [(3, 2), (13, 1), (8, 4), (5, 13), (23, 25), (9, 3)],
     [(20, 23), (11, 3), (4, 14), (1, 11), (17, 19), (1, 21)]],
]


def kpa(plaintexts, ciphertexts):
    """This function takes a list of plaintexts, and a list of
    corresponding ciphertexts. It returns the encryption key by
    solving the linear equation system of the Hill cipher.
    """
##################
# YOUR CODE HERE #
# Find first invertible 2x2 matrix from Plaintext
# save invertible plaintext matrix + corresponding cipher
# invert + mod 26 plaintext matrix
# multiply with corresponding cipher to key matrix
# return key if no error occurs
##################
    # find invertible 2x2 plaintext matrix
    plaintext_matrix = ""
    for i in range(len(plaintexts)):
        for j in range(len(plaintexts)):
            if i != j and KeyMatrix.matrix(list(plaintexts[i]+plaintexts[j])).transpose().is_invertible():
                plaintext_matrix = KeyMatrix.matrix(plaintexts[i]+plaintexts[j]).transpose()
                cipher_matrix = KeyMatrix.matrix(ciphertexts[i]+ciphertexts[j]).transpose()

    #print(f'Invertible plaintext Matrix found: {plaintext_matrix} with cipher: {cipher_matrix}')

    # invert plaintext and calculate modulo over ring
    plain_inv_mod = ~plaintext_matrix.mod(26)

    # multiply inverted plaintext matrix with ciphertext to keymatrix
    try:
        key_recovered = cipher_matrix * plain_inv_mod
        #print(f'Key {key_recovered} recovered for plaintext {plaintext_matrix}')
    except:
        print(f'Error on key recovery with cipher: {cipher_matrix} and plain_inv_mod: {plain_inv_mod}')
        key_recovered = KeyMatrix.matrix(0,0,0,0)

    return key_recovered


def sanity_check():
    # A little sanity check: Make sure that the test data set is correct.
    for (k, ps, cs) in test_data:
        for (p, c) in zip(ps, cs):
            assert(KeyMatrix(k).inverse() * vector(c) == vector(p))


def test():
    # Let's break stuff now!
    i = 0
    for (_, ps, cs) in test_data:
        key_recovered = kpa(ps, cs)
        for (p, c) in zip(ps, cs):
            assert(KeyMatrix(key_recovered).inverse() * vector(c) == vector(p))
        i += 1
        print(f'{i}/{len(test_data)} keys successfully recovered.')

if __name__ == '__main__':
    sanity_check()
    test()
