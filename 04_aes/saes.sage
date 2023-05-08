#!/usr/bin/env sage
# -*- coding: utf-8 -*-

# Implement the Simplified AES algorithm as described in Stalling's
# book and the specification as given in the class materials on the
# Moodle server. You also find a walk-through of an encryption and a
# decryption operation in the class materials.


# S-box
S_BOX = {
    0b0000: 0b1001, 0b1000: 0b0110,
    0b0001: 0b0100, 0b1001: 0b0010,
    0b0010: 0b1010, 0b1010: 0b0000,
    0b0011: 0b1011, 0b1011: 0b0011,
    0b0100: 0b1101, 0b1100: 0b1100,
    0b0101: 0b0001, 0b1101: 0b1110,
    0b0110: 0b1000, 0b1110: 0b1111,
    0b0111: 0b0101, 0b1111: 0b0111
}

# Round constant
R_CON = [0b00000000,0b10000000, 0b00110000]



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

def listtoint(bin):
    return sum(val*(2**idx) for idx, val in enumerate(reversed(bin)))

##################
# YOUR CODE HERE #
##################
def key_expansion(key:int):
    
    # split key
    left = key[:8]
    right = key [8:]

    # first sub-key is just input key
    keyDict = {0:key}

    for i in range(1,3):
        # Create nibbles from right side
        N0 = right[:4]
        N1 = right[4:]

        # Rotate word
        N0, N1 = N1, N0

        # S-Box on nibbles
        N0_new = S_BOX[listtoint(N0)]
        N1_new = S_BOX[listtoint(N1)]

        # Xor with RoundKey and recombine to G
        G = int2blist((N0_new << 4 & N1_new) ^ R_CON[i], 8)
        
        # recombine to new Subkey-words
        left = xor(left,G)
        right = xor(right, left)

        # Add to key dictionary
        keyDict[i] = left + right
    
    return keyDict


# 2 Points
def saes_encrypt(plaintext, key):
    ##################
    # YOUR CODE HERE #
    ##################
    # expand key
    keyDict = key_expansion(key)
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

