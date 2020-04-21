#!/usr/bin/env python

from string import ascii_letters, digits, punctuation

alpha = ascii_letters + digits + '_{}' + punctuation
flag = 'flag{'

while flag[-1] != '}':
    found = False
    for cand in alpha:
        payload = ...
        print("sending payload %s" % payload)

        if b'true' in res:
            found = True
            flag += cand
            print("update! flag: %s" % flag)
            break

    if not found:
        print("something's wrong")
        break

