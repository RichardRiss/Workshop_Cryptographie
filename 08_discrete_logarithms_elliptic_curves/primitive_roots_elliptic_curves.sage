#!/usr/bin/env sage
"""In this assignment you do some calculations on primitive roots and
elliptic curves."""

import Cryptodome.Random.random

# Primitive roots (3 points)
# Write a function that returns a set of all primitive roots for a
# given n. You must not use Sage's function is_primitive_root()!
def primitiveRoots(n):
    pass
    ##################
    # YOUR CODE HERE #
    ##################
    roots = set()
    eulerVal = euler_phi(n)
    isRoot = True
    for a in range(2, n):
        isRoot = True
        for x in range(1, eulerVal+1):
            if (a**x) % n == 1 and x < eulerVal:
                isRoot = False
                break
            if x == eulerVal and (a**x) % n != 1:
                isRoot = False
        if isRoot:
            roots.add(a)
    return roots


# Encoding (3 points)
# Research and implement a scheme to encode natural numbers into elliptic
# curves. We only use elliptic curves over prime fields here.
# Your scheme should be able to encode natural numbers in the range
# 0 < i < 2**(log(p,2)/2).

def int2point(i, a, b, p):
    ##################
    # YOUR CODE HERE #
    # Kolbitz's method
    # Try x-coordinates x=1000*i, 1000*i+1, ..., 1000*i+999
    # Try to construct a point on the curve with this x-coordinate
    # If the point is not on the curve, continue
    ##################
    assert 0 < i < 2**(p.nbits()//2)
    assert 0 < i < (p/1000 - 1)


    E = EllipticCurve(GF(p), [a, b])
    for j in range(1000):
        x = 1000*i + j
        try:
            y = pow(mod(x**3 + a*x + b,p), (p + 1) // 4, p)
            if E.is_on_curve(x,y):    
                return (x,y)

        except:            
            print(f'Error calculating POW for {x}.')

    raise ValueError("Failed to encode the integer as point on the given elliptic curve")


def point2int(x, y, a, b, p):
    ##################
    # YOUR CODE HERE #
    # Define the elliptic curve
    # Construct the point with the given x and y coordinates
    # Compute the integer i that was encoded as this point
    ##################
    #E = EllipticCurve(GF(p) , [a, b])     
    #point = E(x, y)
    #i = point[0] // 1000

    return x // 1000



# Curve brainpoolP512r1
p = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
a = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
b = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723


def test():
    assert(primitiveRoots(25) == set([2, 3, 8, 12, 13, 17, 22, 23]))
    E = EllipticCurve(IntegerModRing(p), [a, b])
    for _ in range(10):
        i = Cryptodome.Random.random.randint(int(0), int(2**256))
        (x, y) = int2point(i, a, b, p)
        assert(E((x, y)))
        assert(point2int(x, y, a, b, p) == i)

if __name__ == '__main__':
    test()

