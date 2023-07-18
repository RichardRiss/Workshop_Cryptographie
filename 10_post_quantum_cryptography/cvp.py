#!/usr/bin/env python3
#
# In this assignment, you write a program that brute-forces the
# closest vector problem (CVP) as shown in Chapter 7 (Lattices).
# You implement the scenario shown in Figures 2 to 4:
#
# - We operate on a two-dimensional Cartesian coordinate system
# - Distance is measured as Euclidean distance In difference to
# - Figures 2 to 4, the values for s1 and s2 are in the range
#   [-10, ..., 10]


def squared_distance(p0, p1):  # 1 point
    # Calculate the squared Euclidean distance between p0 and p1.
##################
# YOUR CODE HERE #
##################
    return sum((x - y) ** 2 for x, y in zip(p0, p1))


def scale_and_sum_vectors(vectors, scale):  # 1 point
    # Each element of the list of vectors is multiplied by the
    # corresponding scalar in list scale. The scaled vectors are
    # summed up.
##################
# YOUR CODE HERE #
##################
    scaled_vectors = [[s*v for v in vec] for s, vec in zip(scale, vectors)]
    
    sum_vector = [sum(x) for x in zip(*scaled_vectors)]
    return sum_vector


def closest_vector_point(basis, target):  # 3 points
    # Given a list of two basis vectors a1 and a2 and a target vector
    # t, return scalars s1 and s2 such that s1*a1+s2*a2 is the lattice
    # element closest to t.
    #
    # Note that s1 and s2 can be in the range [-10, ..., 10].
##################
# YOUR CODE HERE #
##################
    a1, a2 = basis
    closest_point = None
    s1, s2 = None, None
    r = range(-10,11)
    closest_dist = 20

    # Brute Force Combinations of s1 s2
    for i in r:
        for j in r:
            # get s1*a1 + s2*a2
            point = [i * a + j * b for a, b in zip(a1, a2)]
            dist = squared_distance(target, point) 

            # Save closest found distance
            if dist < closest_dist:
                closest_dist = dist
                s1, s2 = i, j
                closest_point = point

    return (s1, s2, closest_point)


def test():
    assert(squared_distance(p0=[0, 0], p1=[0, 0]) == 0)
    assert(squared_distance(p0=[1, 0], p1=[0, 1]) == 2)
    assert(squared_distance(p0=[1, 0], p1=[1, 1]) == 1)
    assert(squared_distance(p0=[0, 0], p1=[2, 3]) == 13)
    assert(scale_and_sum_vectors(vectors=[[1, 1]], scale=[1]) == [1, 1])
    assert(scale_and_sum_vectors(vectors=[[1, 2], [3, 4]], scale=[5, 6])
           == [23, 34])
    assert(closest_vector_point(basis=[[1, 0], [0, 1]], target=[3, 5])
           == (3, 5, [3, 5]))
    assert(closest_vector_point(basis=[[1, 0], [0, -1]], target=[3, 5])
           == (3, -5, [3, 5]))
    assert(closest_vector_point(basis=[[1, 3], [4, 2]], target=[3, 5])
           == (2, 0, [2, 6]))
    assert(closest_vector_point(basis=[[-7, 2], [8, 5]], target=[3, 5])
           == (1, 1, [1, 7]))


if __name__ == '__main__':
    test()
