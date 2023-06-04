#!/usr/bin/env python3

"""FIPS 140-2: RNG Power-Up Tests"""

# Asses the quality of your TRNG by running the statistical random
# number generator tests from Chapter 4.9.1 (Power-Up Tests) of "FIPS
# PUB 140-2 - SECURITY REQUIREMENTS FOR CRYPTOGRAPHIC MODULES". The
# document is available on the handout server.

import functools
import typing

FILENAME = 'random.dat'


def readRandomBits(filename: str) -> typing.List[int]:
    """Read file and return it as list of bits."""
    rnFile: typing.IO = open(filename, 'rb')
    rn: bytes = rnFile.read()
    rnFile.close()
    return(functools.reduce(lambda x, y: x+int2bin(y, 8), rn, []))


def int2bin(x: int, n: int) -> typing.List[int]:
    """Convert integer to array of bits.

    x : integer
    n : length of bit array"""
    b: typing.List[int] = list(map(lambda x: ord(x)-ord('0'), list(bin(x)[2:])))
    return([0]*(n-len(b)) + b)


def bin2int(b: typing.List[int]) -> int:
    """Convert array of bits to integer."""
    return(int("".join(map(lambda x: chr(x+ord('0')), b)), 2))


def testRandomNumbers(randomBits: typing.List[int]) -> None:
    print('Monobit Test:   %s' % repr(monobitTest(randomBits)))
    print('Poker Test:     %s' % repr(pokerTest(randomBits)))
    print('Runs Test:      %s' % repr(runsTest(randomBits)))
    print('Long Runs Test: %s' % repr(longRunsTest(randomBits)))


def monobitTest(randomBits: typing.List[int]) -> bool:
    """FIPS 140-2 monobit test"""
    # Count the number of ones in the 20,000 bit stream. Denote this
    # quantity by x.
    #
    # The test is passed if 9725 < x < 10275
    ##################
    # YOUR CODE HERE #
    ##################
    return 9725 < sum(randomBits) < 10275


def pokerTest(randomBits: typing.List[int]) -> bool:
    """FIPS 140-2 poker test"""
    # Divide the 20000 bit stream into 5000 contiguous 4 bit
    # segments. Count and store the number of occurrences of the 16
    # possible 4 bit values. Denote f[i] as the number of each 4 bit
    # value i where 0 < i < 15.
    #
    # Evaluate the following:
    #                   15
    #                   --
    # x = (16/5000) * ( \  f[i]^2 ) - 5000
    #                   /
    #                   --
    #                  i=0
    #
    # The test is passed if 2.16 < x < 46.17
    #
    # See fips_140_2.pdf, page 39-40
    ##################
    # YOUR CODE HERE #
    ##################
    counts = [0] * 16
    for i in range(0, len(randomBits), 4):
        value = 8 * randomBits[i] + 4 * randomBits[i+1] + 2 * randomBits[i+2] + randomBits[i+3]
        counts[value] += 1

    x = (16/5000) * sum(count**2 for count in counts) - 5000
    return 2.16 < x < 46.17

def wald_wolfowitz_test(randomBits):
    """Wald-Wolfowitz runs test"""
    n = len(randomBits)
    runs = 1
    for i in range(1, n):
        if randomBits[i] != randomBits[i-1]:
            runs += 1
    expected_runs = (2 * n - 1) / 3
    variance = (16 * n - 29) / 90
    z = (runs - expected_runs) / variance**0.5
    return abs(z) < 1.96

def runsTest(randomBits: typing.List[int]) -> bool:
    """FIPS 140-2 runs test"""
    # A run is defined as a maximal sequence of consecutive bits of
    # either all ones or all zeros that is part of the 20000 bit
    # sample stream. The incidences of runs (for both consecutive
    # zeros and consecutive ones) of all lengths (>= 1) in the
    # sample stream should be counted and stored.
    #
    # The test is passed if the runs that occur (of lengths 1 through
    # 6) are each within the corresponding interval specified in the
    # table below. This must hold for both the zeros and ones (i.e.,
    # all 12 counts must lie in the specified interval). For the
    # purposes of this test, runs of greater than 6 are considered to
    # be of length 6.
    #
    # Length      Required Interval
    # of Run
    # 1           2343 - 2657
    # 2           1135 - 1365
    # 3            542 -  708
    # 4            251 -  373
    # 5            111 -  201
    # 6+           111 -  201
    
    dictBits = count_consecutive_bits(randomBits)

    intervals = {
        1:(2343, 2657),
        2:(1135, 1365),
        3:(542, 708),
        4:(251, 373),
        5:(111, 201),
        6:(111, 201)
        }
    for type in dictBits.values():
        for k,v in type.items():
            interval = intervals.get(k)
            if not (interval[0] < v < interval[1]):
                return False
    return True


def count_consecutive_bits(bits) -> dict:
    """Count consecutive bits"""
    ones_counts = {}
    zeros_counts = {}
    current_run = None
    run_length = 0

    for bit in bits:
        if current_run is None:
            current_run = bit
            run_length = 1
        elif current_run == bit:
            run_length += 1
        else:
            if current_run == 1:
                if run_length > 6:
                    run_length = 6
                if run_length in ones_counts:
                    ones_counts[run_length] += 1
                else:
                    ones_counts[run_length] = 1
            else:
                if run_length > 6:
                    run_length = 6
                if run_length in zeros_counts:
                    zeros_counts[run_length] += 1
                else:
                    zeros_counts[run_length] = 1
            current_run = bit
            run_length = 1

    if current_run == 1:
        if run_length > 6:
            run_length = 6
        if run_length in ones_counts:
            ones_counts[run_length] += 1
        else:
            ones_counts[run_length] = 1
    else:
        if run_length > 6:
            run_length = 6
        if run_length in zeros_counts:
            zeros_counts[run_length] += 1
        else:
            zeros_counts[run_length] = 1

    return {'ones': ones_counts, 'zeros': zeros_counts}


def longRunsTest(randomBits: typing.List[int]) -> bool:
    """FIPS 140-2 long runs test"""
    # A long run is defined to be a run of length 26 or more (of
    # either zeros or ones). On the sample of 20000 bits, the test is
    # passed if there are no long runs.
    #
    # See fips_140_2.pdf, page 40
    ##################
    # YOUR CODE HERE #
    ##################
    ones_runs = 0
    zeros_runs = 0
    for bit in randomBits:
        if bit == 1:
            ones_runs += 1
            zeros_runs = 0
        else:
            zeros_runs += 1
            ones_runs = 0
        if ones_runs >= 26 or zeros_runs >= 26:
            return False
    return True


if __name__ == "__main__":
    randomBits: typing.List[int] = readRandomBits(filename=FILENAME)
    testRandomNumbers(randomBits=randomBits)

