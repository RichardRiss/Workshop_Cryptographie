#!/usr/bin/env sage
# -*- coding: utf-8 -*-

# Implement the Simplified AES algorithm as described in Stalling's
# book and the specification as given in the class materials on the
# Moodle server. You also find a walk-through of an encryption and a
# decryption operation in the class materials.


# S-box
S_BOX = [
    [0x9, 0x4, 0xa, 0xb],
    [0xd, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xc, 0xe, 0xf, 0x7]
]




def xor(a, b):
    def h(x,y):
        if(x==y):
            return(0)
        else:
            return(1)
    return(list(map(lambda x, y: h(x, y), a, b)))


def int2blist(n, length):
    b = bin(n)
    l = string2blist(b[2:])
    return([0]*(length-len(l)) + l)

def string2blist(s):
    return(list(map(int, list(s))))

def pp(b):
    """Pretty print bit lists"""
    t = "".join(map(str, b))
    r = ""
    for i in range(0, len(t), 4):
        r += t[i:i+4] + ' '
    return(r)

# Since the mix column operations are tricky, the following
# implementations are provided for your convenience.

def mix_col(d, inv=False):
    L.<a> = GF(2^4);
    if inv:
        MixColumns_matrix = Matrix(L, [[a^3+1,a],[a,a^3+1]])
    else:
        MixColumns_matrix = Matrix(L, [[1,a^2],[a^2,1]])
    d0 = d[0:4]
    d0.reverse()
    d1 = d[4:8]
    d1.reverse()
    d2 = d[8:12]
    d2.reverse()
    d3 = d[12:16]
    d3.reverse()
    dMatrix = Matrix(L, [[d0, d2],
                         [d1, d3]])
    matrixProduct = MixColumns_matrix*dMatrix
    r = []
    for j in range(2):
        for i in range(2):
            r += int2blist(int(matrixProduct[i][j]._int_repr()), 4)
    return(r)

def inv_mix_col(d):
    return(mix_col(d=d, inv=True))

# You probably want to define more utility functions

##################
# YOUR CODE HERE #
##################
def initial_round(plaintext, key):
    # Get Round key
    round_key = key [:7]

    # XOR the first 8 bits of the input with the key
    xored_input = [a ^ b for a, b in zip(plaintext[:8], round_key)]

    # Substitute the input using the S-box
    substituted_input = [S_BOX[row][col] for row, col in zip(xored_input[:4], xored_input[4:])]
    
    # Shift the substituted input to the left by one bit
    shifted_input = substituted_input[1:] + substituted_input[:1]

    
    # XOR the shifted input with the second 8 bits of the key  
    r1_text = [a ^ b for a, b in zip(shifted_input, key[8:])]
    return r1_text




# 2 Points
def saes_encrypt(plaintext, key):
    ##################
    # YOUR CODE HERE #
    ##################
    r1_text = initial_round(plaintext, key)
    print(r1_text)
    pass


# 2 Points
def saes_decrypt(ciphertext, key):
    pass
##################
# YOUR CODE HERE #
##################

def test():
    for (plaintext, key, ciphertext) in [
         (# Stallings, Exercise 5.10 / 5.12 / 5.14
          '0110111101101011',
          '1010011100111011',
          '0000011100111000')
        ,(# Gordon
          '1101011100101000',
          '0100101011110101',
          '0010010011101100')
        ,(# Holden
          '0110111101101011',
          '1010011100111011',
          '0000011100111000')
        ]:
        plaintext = string2blist(plaintext)
        ciphertext = string2blist(ciphertext)
        key = string2blist(key)
        saes_encrypt(plaintext=plaintext, key=key)
        #assert(saes_encrypt(plaintext=plaintext, key=key)
        #       == ciphertext)
        #assert(saes_decrypt(ciphertext=ciphertext, key=key)
        #       == plaintext)

if __name__ == '__main__':
    test()
