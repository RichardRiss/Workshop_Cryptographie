#!/usr/bin/env sage
"""Elliptic Curve Diffie-Hellman Key Exchange"""

import Cryptodome.Random.random
import hashlib

# In this exercise you will implement Diffie-Hellman key exchange
# over elliptic curves.

# Implement a Sage function that takes the curve parameters a, b, q, alpha,
# and n as inputs. E_q(a;b) defines an elliptic curve, alpha is the
# generator, and n is the order of alpha. Your function shall return a
# public and a private ECDH key.


def generateKey(a, b, q, alpha, n):
##################
# YOUR CODE HERE #
##################
    E = EllipticCurve(IntegerModRing(q), [a,b])

    # Create Point on Curve with coordinates of alpha
    P = E.point(alpha)

    # Generate a random private key
    private = randint(0, n-1)

    # Generate orresponding public key
    public = P * private

    return(public, private)


def computeSharedSecret(othersPublicKey, myPrivateKey):
    sK = othersPublicKey * myPrivateKey
    return sK
##################
# YOUR CODE HERE #
##################

# Simulate DH key exchange. In the following function, add code that
# calculates the shared keys of user A and of user B. The result
# of user A's shared key calculation shall be stored in variable
# sharedSecretCalculationA, and the value of user B's shared key
# calculation shall be stored in variable sharedSecretCalculationB.


def keyExchangeSimulation(a, b, q, alpha, n):
    (publicA, privateA) = generateKey(a, b, q, alpha, n)
    (publicB, privateB) = generateKey(a, b, q, alpha, n)
##################
# YOUR CODE HERE #
##################
    sharedSecretCalculationA = computeSharedSecret(publicB, privateA)
    sharedSecretCalculationB = computeSharedSecret(publicA, privateB)
    assert(sharedSecretCalculationA == sharedSecretCalculationB)


def aliceAndBobExchangeKeys():
    # NOTE: I will _not_ run this function with different parameters
    # (well, it doesn't take parameters). Just make sure that none of the
    # assertions fails.
    #
    # Alice and Bob use the ECDH key exchange technique with the
    # following parameters:
    a = 8
    b = 12
    q = 23
    n = 28
    alpha = (4, 19)

    # Get the encryption Group G
    E = EllipticCurve(IntegerModRing(q), [a,b])
    G = E(alpha[0], alpha[1])
    
    # If Alice's private key is 21, what is her public key?
    privateA = 21
    publicA = G * privateA
##################
# YOUR CODE HERE #
##################
    assert(hashlib.sha256(repr(publicA).encode('utf8')).hexdigest()
           == '724a40af786ddbb382dc18560050e4fdf40667d0bcfbb010ac159371af3a304b')
    # If Bob's private key is 11, what is his public key?
    privateB = 11
    publicB = G * privateB
##################
# YOUR CODE HERE #
##################
    assert(hashlib.sha256(repr(publicB).encode('utf8')).hexdigest()
           == '53a4d60817d4ee031e9de0e78acec22ab991112efc69736e95d6ccee95f1fdde')
    # What is their shared secret?
##################
# YOUR CODE HERE #
##################
    sharedSecretA = computeSharedSecret(publicB, privateA)
    sharedSecretB = computeSharedSecret(publicA, privateB)
    assert(hashlib.sha256(repr(sharedSecretA).encode('utf8')).hexdigest()
           == '9f5e207726b38a058ca863f9f0eafad11dbf0c031a359b5e2caaf13104ebb901')
    assert(sharedSecretA == sharedSecretB)


if __name__ == "__main__":
    for _ in range(0x100):
        keyExchangeSimulation(a=1, b=1, q=23, alpha=(9, 7), n=28)
    aliceAndBobExchangeKeys()