#!/usr/bin/env python3
import requests
import hashlib
import random

"""True Random Number Generator"""

# Write a true random number generator. In order to do so, you have to
# identify a source of true randomness. Creative sources of randomness
# are appreciated. If you cannot use Python/Sage for this assignment,
# e.g. because you want to access low-level functionality not
# available in Python/Sage, you may also submit C code for this
# assignment.
#
# Your function shall output 20000 random bits as byte values,
# i.e. it should write a file of 2500 random bytes.

import typing

FILENAME: str = 'random.dat'
N: int = 2500


def get_seed_from_data(data):
    # concatenate the string representations of the values
    s = ''.join(str(v) for v in data.values())
    return s

def trng(filename: str, n: int) -> None:
    ##################
    # YOUR CODE HERE #
    ##################
    # Base data for https://www.swpc.noaa.gov/products/real-time-solar-wind
    url = "https://services.swpc.noaa.gov/json/enlil_time_series.json"
    print("Querying for solar wind data. Please be patient, sometimes the site is a bit slow with its responses.")
    response = requests.get(url)
    data = None
    buffer = []

    if response.status_code == 200:
        data = response.json()
        for i in range(n):
            act_value = data[-1]
            data = data[:-1]
            
            random.seed(get_seed_from_data(act_value))

            val = random.randbytes(1)
            buffer.append(val)

    else:
        print("Error: could not retrieve data")

    if data is not None:
        with open(filename, 'wb') as f:
            for i in buffer:
                f.write(i)
    

if __name__ == "__main__":
    trng(filename=FILENAME, n=N)
    print("Done")
