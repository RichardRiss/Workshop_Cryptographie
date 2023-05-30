#!/usr/bin/env python3

import sha256
import Crypto.Random.random as r

# This weeks program assignment is to implement a message extension
# attack against SHA-256. Since this requires changing internal values
# of the SHA-256 function, a pure Python implementation of SHA-256 is
# supplied in sha256.py.
#
# This assignment is split in two parts:
#
# In the first part, you have to implement function
# set_hashing_state(). This function reconstructs the internal state
# of the SHA-256 hashing function from the digest value.
#
# In the second part, you implement message_extension_attack(). The tricky
# part is that you have to take care of the padding of the original
# message. The SHA-256 sum, i.e. the result of digest(), is not simply
# calculated over key+msg, but over key+msg+padding. This is also the
# reason why you can no longer call update() in Sha256 once you have
# called digest(): The message has already been padded.
#
# For the message extension attack, you will update the hashing object
# anyway. Therefore you are calculating the hash over
# key+msg+padding+extension.
#
# Hints:
#
# The test functions use random byte sequences for key, message, and
# extension. For debugging purposes I recommend you use short, fixed
# byte sequences instead.
#
# Numbers in SHA-256 are 4 bytes in big-endian encoding. You can
# convert integer variable x into this format with
#
# b = x.to_bytes(4, 'big')
#
# You can convert these four bytes bag into an integer with
#
# int.from_bytes(b, 'big')
#
# When you are operating on lists, remember that in Python lists
# are call-by-reference, not call-by-value:
#
# >>> foo = [1,2,3]
# >>> bar = foo
# >>> bar[1] = 5
# >>> print(foo)
# [1, 5, 3]
#
# If you want an actual copy of a list, use index "[:]":
#
# >>> foo = [1,2,3]
# >>> bar = foo[:]
# >>> bar[1] = 5
# >>> print(foo)
# [1, 2, 3]


def get_random_bytes(a: int, b: int) -> bytes:
    # Returns between a and b random bytes
    return b"".join([bytes([r.getrandbits(8)])
                     for _ in range(r.randint(a, b))])


def set_hashing_state(msg_digest: bytes, msg_length: int) -> sha256.Sha256:
    # This function takes a message digest and the length of the
    # message processed and returns a hashing object with the given
    # state, i.e. when method digest() of the object instance returned
    # is called, its return value is identical to msg_digest. Also,
    # the instance variable mlen must be set, because when we are
    # extending the message, this value is used in the padding
    # method. mlen is the length of the message (msg_length) after
    # padding!
    #
    # Note: Since msg_digest has been calculated by calling the
    # digest() method of a hashing instance, the state of the hashing
    # object returned by this function should be the state of a
    # hashing object for which digest() has been called at least once.
    
    ##################
    # YOUR CODE HERE #
    ##################
        
    # Create an empty sha256 object
    sha = sha256.Sha256(b"")
    
    # Set the message length of the sha256 object
    sha.mlen = msg_length + len(sha.pad(msg_length))

    # set digested value and "fake" already digested object
    sha.fin = True
    sha.digest_value = msg_digest
    
    # split digest into list of 4 byte sized blocks
    sha.h = [int.from_bytes(msg_digest[i:i+4],'big') for i in range(0, len(msg_digest), 4)]
    

    return sha

def test_set_hashing_state() -> None:
    for _ in range(100):
        msg: bytes = get_random_bytes(1, 200)
        hash0: sha256.Sha256 = sha256.Sha256(msg)
        digest0: bytes = hash0.digest()
        hash1: sha256.Sha256 = set_hashing_state(digest0, len(msg))
        digest1: bytes = hash1.digest()
        assert(digest0 == digest1)
        assert(hash0.mlen == hash1.mlen)
    


def message_extension_attack(original_msg: bytes, key_length: int,
                             original_mac: bytes,
                             extension: bytes) -> tuple[bytes, bytes]:
    ##################
    # YOUR CODE HERE #
    ##################
    # length of original message
    orig_len = len(original_msg)

    # create new sha256 object with state of original mac and length of key + msg 
    hash0 = set_hashing_state(original_mac, key_length + orig_len)
    
    # update with extension message
    hash0.fin = False
    hash0.update(extension)
    

    # get the padding string to return as part of the extended msg
    padding = sha256.Sha256().pad(orig_len+key_length)
    
    # update the Hash with the original message and padding
    #hash0.fin = False
    #hash0.update(original_msg + padding)
    #hash0.update(padding)
    
    # use the provided mac to create a new sha256 object and extend with extension message
    #hash1 = set_hashing_state(hash0.digest(), orig_len + key_length)
    #hash1.fin=False
    #hash1.update(extension)

    # calculate the new mac and extended message 
    # without knowledge of the key
    extended_mac = hash0.digest()

    extended_msg = original_msg + padding + extension


    return (extended_msg, extended_mac)


def test_message_extension_attack() -> None:
    for _ in range(100):
        key: bytes = get_random_bytes(16, 16)
        msg: bytes = get_random_bytes(1, 200)
        extension: bytes = get_random_bytes(1, 200)
        key_msg: bytes = key + msg
        original_mac: bytes = sha256.Sha256(key_msg).digest()
        (extended_msg, extended_mac) = message_extension_attack(msg, len(key),
                                                                original_mac,
                                                                extension)
        # Check if the original message has been extended
        assert(extended_msg[:len(msg)] == msg)
        assert(extended_msg[-len(extension):] == extension)
        # Check MAC of extended message
        assert(sha256.Sha256(key + extended_msg).digest() == extended_mac)


if __name__ == '__main__':
    test_set_hashing_state()
    test_message_extension_attack()
