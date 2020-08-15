import hashlib
from itertools import product
from string import ascii_letters, digits # it's usually this charset, but you can import printable if it doesn't work

charset = ascii_letters + digits
# use this function if you are given the hash and asked for a small chunk of tha plaintext
# example :
# (XXXX + hagGte854de84j) = b1946ac92492d2347c6235b4d2611184
# find XXXX
def proof(alg, known, target, length):
    for t in product(charset, repeat=length):
        proof = (''.join(t) + known).encode()
        if hashlib.__dict__[alg](proof).hexdigest() == target:
            return ''.join(t)


# use this if you have a subset of the hash but nothing of the plaintext
# example:
# give X such that len(X) = 20 and hash(X)[-6:]=b194ac

def proof(alg, known_chunk, length, index):
    for t in product(charset, repeat=length):
        proof = ''.join(t).encode()
        if hashlib.__dict__[alg](proof).hexdigest()[-index:] == known_chunk:
            return ''.join(t)
