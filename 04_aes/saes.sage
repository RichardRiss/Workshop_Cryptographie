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

# Invert S-Box for decryption
S_BOX_INV = {v: k for k, v in S_BOX.items()}

# Round constant
R_CON = [
    [0,0,0,0,0,0,0,0],
    [1,0,0,0,0,0,0,0],
    [0,0,1,1,0,0,0,0]
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

def listtoint(bin):
    return sum(val*(2**idx) for idx, val in enumerate(reversed(bin)))

##################
# YOUR CODE HERE #
##################
def key_expansion(key:int):
    
    # split key
    w0 = key[:8]
    w1 = key [8:]


    # first sub-key is just input key
    keyDict = {0:key}

    for i in range(1,3):
        # Create nibbles from first word
        N0 = w1[:4]
        N1 = w1[4:]

        # Rotate word
        N0, N1 = N1, N0

        # S-Box on nibbles
        N0_new = S_BOX[listtoint(N0)]
        N1_new = S_BOX[listtoint(N1)]
        
        # Xor with RoundKey and recombine to G
        G = xor(int2blist((N0_new << 4 | N1_new),8),R_CON[i])

        # recombine to new Subkey-words
        w0 = xor(w0,G)
        w1 = xor(w1, w0)

        # Add to key dictionary
        keyDict[i] = w0 + w1

    return keyDict

def sbox_nibbles(ciphertext, inv=False):
    # split list in nibbles -> sbox -> add back to list of nibbles
    if inv:
        retval = [int2blist(S_BOX_INV[listtoint(ciphertext[i*4:(i*4+4)])],4) for i in range(4)]
    else:
        retval = [int2blist(S_BOX[listtoint(ciphertext[i*4:(i*4+4)])],4) for i in range(4)]
    return retval


# 2 Points
def saes_encrypt(plaintext, key):
    ##################
    # YOUR CODE HERE #
    ##################
    # expand key
    keyDict = key_expansion(key)

    # add first round key
    ciphertext = xor(plaintext, keyDict[0])

    ##########
    # Round 1
    ##########
    # substitute nibbles
    sboxed_nibbles = sbox_nibbles(ciphertext)

    # shift rows
    sboxed_nibbles[1],sboxed_nibbles[3] = sboxed_nibbles[3], sboxed_nibbles[1]

    # add back together
    state = [item for nibble in sboxed_nibbles for item in nibble]
    
    # Mix columns
    mixed_state = mix_col(state)
    
    # Add Round key
    ciphertext = xor(mixed_state, keyDict[1])
    
    ##########
    # Round 2
    ##########
    # substitute nibbles
    sboxed_nibbles = sbox_nibbles(ciphertext)

    # shift rows
    sboxed_nibbles[1],sboxed_nibbles[3] = sboxed_nibbles[3], sboxed_nibbles[1]

    # add back together
    state = [item for nibble in sboxed_nibbles for item in nibble]

    # Add Round key
    ciphertext = xor(state, keyDict[2])

    return ciphertext


# 2 Points
def saes_decrypt(ciphertext, key):
    ##################
    # YOUR CODE HERE #
    ##################
    # expand key
    keyDict = key_expansion(key)
    
    # add last round key
    plaintext = xor(ciphertext, keyDict[2])

    ##########
    # Round 1
    ##########
    # inverse shift row
    plaintext[4:8],plaintext[12:16] = plaintext[12:16], plaintext[4:8]

    #substitute inverse nibble
    sboxed_nibbles = sbox_nibbles(plaintext, inv=True)

    # add back together
    state = [item for nibble in sboxed_nibbles for item in nibble]

    # Add Round key
    round_state = xor(state, keyDict[1])

    # inverse mix cols
    plaintext = mix_col(round_state, inv=True)


    ##########
    # Round 2
    ##########
    # inverse shift row
    plaintext[4:8],plaintext[12:16] = plaintext[12:16], plaintext[4:8]

    #substitute inverse nibble
    sboxed_nibbles = sbox_nibbles(plaintext, inv=True)

    # add back together
    state = [item for nibble in sboxed_nibbles for item in nibble]

    # Add Round key
    plaintext = xor(state, keyDict[0])

    return plaintext




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

        assert(saes_encrypt(plaintext=plaintext, key=key)
               == ciphertext)
        assert(saes_decrypt(ciphertext=ciphertext, key=key)
               == plaintext)

if __name__ == '__main__':
    test()

