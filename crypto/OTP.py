#!/usr/bin/env python

from pwn import xor

def updatep1(new_guess):
    global p1, p2, p1xp2
    p1 += new_guess
    p2 = xor(p1xp2[:len(p1)], p1)
    print('added %s to p1 and updated p2 accordingly' % new_guess)
    print('p1: %s' % p1)
    print('p2: %s' % p2)

def updatep2(new_guess):
    global p1, p2, p1xp2
    p2 += new_guess
    p1 = xor(p1xp2[:len(p2)], p2)
    print('added %s to p2 and updated p1 accordingly' % new_guess)
    print('p1: %s' % p1)
    print('p2: %s' % p2)


c1 = bytes.fromhex('213c234c2322282057730b32492e720b35732b2124553d354c22352224237f1826283d7b0651')
c2 = bytes.fromhex('3b3b463829225b3632630b542623767f39674431343b353435412223243b7f162028397a103e')

p1xp2 = xor(c1, c2)

# guess the first bytes of the key
k = b'utflag{'
# take a peek at plaintext
p1 = xor(c1[:len(k)], k)

# and guess a byte and see if it makes sense with p1 and p2
updatep1(b'T')
updatep2(b'EST')
updatep1(b'F')
updatep1(b' ')
updatep2(b'NE ')
updatep1(b'EGORY ')
updatep2(b'ARY EXPLOITATION')

k = xor(c1, p1)
print(k)
